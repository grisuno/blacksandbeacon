# Subsystem: include (page 1 of 2)
Pages: [KB_include.md](KB_include.md), [KB_include_p2.md](KB_include_p2.md)

## include/aes.c
- Doc: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Layer: utility
- Language: c
- Symbols:
  - `__attribute__` (function, line 11) `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)`
  - `__attribute__` (function, line 35) `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)`
  - `__attribute__` (function, line 59) `static __attribute__((unused)) uint8_t Td0(int x)`
  - `__attribute__` (function, line 63) `static __attribute__((unused)) uint8_t Td1(int x)`
  - `__attribute__` (function, line 67) `static __attribute__((unused)) uint8_t Td2(int x)`
  - `__attribute__` (function, line 71) `static __attribute__((unused)) uint8_t Td3(int x)`
  - `__attribute__` (function, line 75) `static __attribute__((unused)) uint8_t Td4(int x)`
  - `KeyExpansion` (function, line 181) `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)`
  - `AES_init_ctx` (function, line 254) `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)`
  - `AES_init_ctx_iv` (function, line 259) `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)`
  - `AES_ctx_set_iv` (function, line 264) `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)`
  - `AddRoundKey` (function, line 272) `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)`
  - `SubBytes` (function, line 286) `static void SubBytes(state_t *state)`
  - `ShiftRows` (function, line 301) `static void ShiftRows(state_t *state)`
  - `xtime` (function, line 329) `static uint8_t xtime(uint8_t x)`
  - `MixColumns` (function, line 335) `static void MixColumns(state_t *state)`
  - `Multiply` (function, line 363) `static uint8_t Multiply(uint8_t x, uint8_t y)`
  - `InvMixColumns` (function, line 389) `static void InvMixColumns(state_t *state)`
  - `InvSubBytes` (function, line 413) `static void InvSubBytes(state_t *state)`
  - `InvShiftRows` (function, line 425) `static void InvShiftRows(state_t *state)`
  - `Cipher` (function, line 455) `static void Cipher(state_t *state, const uint8_t *RoundKey)`
  - `InvCipher` (function, line 482) `static void InvCipher(state_t *state, const uint8_t *RoundKey)`
  - `AES_ECB_encrypt` (function, line 512) `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)`
  - `AES_ECB_decrypt` (function, line 518) `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)`
  - `XorWithIv` (function, line 528) `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)`
  - `AES_CBC_encrypt_buffer` (function, line 537) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
  - `AES_CBC_decrypt_buffer` (function, line 552) `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
  - `AES_CTR_xcrypt_buffer` (function, line 572) `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
  - `Nb` (macro, line 5) `#define Nb`
  - `KEYLEN_256` (macro, line 7) `#define KEYLEN_256`
  - `RKLENGTH` (macro, line 8) `#define RKLENGTH`
  - `BLOCKLEN` (macro, line 9) `#define BLOCKLEN`
  - `Nb` (macro, line 84) `#define Nb`
  - `Nk` (macro, line 87) `#define Nk`
  - `Nr` (macro, line 88) `#define Nr`
  - `Nk` (macro, line 90) `#define Nk`
  - `Nr` (macro, line 91) `#define Nr`
  - `Nk` (macro, line 93) `#define Nk`
  - `Nr` (macro, line 94) `#define Nr`
  - `MULTIPLY_AS_A_FUNCTION` (macro, line 101) `#define MULTIPLY_AS_A_FUNCTION`
  - `getSBoxValue` (macro, line 177) `#define getSBoxValue(num)`
  - `Multiply` (macro, line 371) `#define Multiply(x, y)`
  - `getSBoxInvert` (macro, line 384) `#define getSBoxInvert(num)`
- Depends on: `include/aes.h`

## include/aes.h
- Doc: #define the macros below to 1/0 to enable/disable the mode of operation.
- Layer: utility
- Language: h
- Symbols:
  - `AES_ctx` (struct, line 33)
  - `AES_init_ctx` (function, line 41) `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);`
  - `AES_init_ctx_iv` (function, line 43) `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);`
  - `AES_ctx_set_iv` (function, line 44) `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);`
  - `AES_ECB_encrypt` (function, line 48) `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);`
  - `AES_ECB_decrypt` (function, line 49) `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);`
  - `AES_CBC_encrypt_buffer` (function, line 53) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);`
  - `AES_CBC_decrypt_buffer` (function, line 54) `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);`
  - `AES_CTR_xcrypt_buffer` (function, line 58) `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);`
  - `_AES_H_` (macro, line 2) `#define _AES_H_`
  - `CBC` (macro, line 9) `#define CBC`
  - `ECB` (macro, line 12) `#define ECB`
  - `CTR` (macro, line 15) `#define CTR`
  - `AES256` (macro, line 18) `#define AES256`
  - `AES_BLOCKLEN` (macro, line 20) `#define AES_BLOCKLEN`
  - `AES_KEYLEN` (macro, line 23) `#define AES_KEYLEN`
  - `AES_keyExpSize` (macro, line 24) `#define AES_keyExpSize`
  - `AES_KEYLEN` (macro, line 26) `#define AES_KEYLEN`
  - `AES_keyExpSize` (macro, line 27) `#define AES_keyExpSize`
  - `AES_KEYLEN` (macro, line 29) `#define AES_KEYLEN`
  - `AES_keyExpSize` (macro, line 30) `#define AES_keyExpSize`
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

## include/aes_cfb.c
- Doc: aes256_cfb_encrypt_replay: Encrypt with replay protection: prepends counter (8 bytes LE) and...
- Layer: utility
- Language: c
- Symbols:
  - `aes256_cfb_encrypt` (function, line 21) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 55) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_encrypt_replay` (function, line 94) `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv,
     ...`
  - `aes256_cfb_decrypt_replay` (function, line 126) `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv,
     ...`
- Depends on: `include/aes.h`, `include/aes_cfb.h`

## include/aes_cfb.h
- Layer: utility
- Language: h
- Symbols:
  - `aes256_cfb_encrypt` (function, line 9) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...`
  - `aes256_cfb_decrypt` (function, line 11) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...`
  - `BSB_AES_CFB_H` (macro, line 5) `#define BSB_AES_CFB_H`
- Imported by: `include/aes_cfb.c`, `mutants/tests/crypto_harness.c`, `tests/crypto_harness.c`

## include/async_i_o_for_beacon.h
- Layer: utility
- Language: h
- Symbols:
  - `async_i_o_for_beacon_process` (function, line 4) `bool async_i_o_for_beacon_process(void);`
  - `ASYNC_I_O_FOR_BEACON_H` (macro, line 2) `#define ASYNC_I_O_FOR_BEACON_H`
- Imported by: `mutants/src/async_i_o_for_beacon.c`, `src/async_i_o_for_beacon.c`

## include/beacon.h
- Doc: Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)
- Layer: utility
- Language: h
- Symbols:
  - `datap` (struct, line 14)
  - `BeaconDataParse` (function, line 22) `void BeaconDataParse(datap *parser, char *buffer, int size);`
  - `BeaconDataPtr` (function, line 23) `char *BeaconDataPtr(datap *parser, int size);`
  - `BeaconDataInt` (function, line 24) `int BeaconDataInt(datap *parser);`
  - `BeaconDataShort` (function, line 25) `short BeaconDataShort(datap *parser);`
  - `BeaconDataLength` (function, line 26) `int BeaconDataLength(datap *parser);`
  - `BeaconDataExtract` (function, line 27) `char *BeaconDataExtract(datap *parser, int *size);`
  - `BeaconPrintf` (function, line 28) `void BeaconPrintf(int type, const char *fmt, ...);`
  - `BeaconOutput` (function, line 29) `void BeaconOutput(int type, const char *data, int len);`
  - `BEACON_API_H` (macro, line 3) `#define BEACON_API_H`
  - `CALLBACK_OUTPUT` (macro, line 9) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 10) `#define CALLBACK_ERROR`
  - `CALLBACK_OUTPUT_OEM` (macro, line 11) `#define CALLBACK_OUTPUT_OEM`

## include/beacon_common.c
- Doc: MemoryStruct: size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8; TrampolineCache *tmp...
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 297)
  - `bsb_output_meta_t` (struct, line 43)
  - `bsb_output_init` (function, line 109) `int bsb_output_init(size_t capacity)`
  - `bsb_output_cleanup` (function, line 135) `void bsb_output_cleanup(void)`
  - `bsb_output_reset` (function, line 149) `void bsb_output_reset(void)`
  - `BeaconPrintf` (function, line 159) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 175) `void BeaconOutput(int type, const char *data, int len)`
  - `mmap_near` (function, line 193) `static void *mmap_near(void *near_hint, size_t len, int prot)`
  - `create_trampoline` (function, line 211) `void *create_trampoline(void *target, void *near_hint)`
  - `cleanup_trampolines` (function, line 249) `void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 266) `void *get_or_create_trampoline(void *target, void *near_hint)`
  - `WriteMemoryCallback` (function, line 303) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `bsb_curl_pin_format` (function, line 330) `static void bsb_curl_pin_format(const char *in, char *out, size_t outsz)`
  - `https_request` (function, line 367) `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method,
     ...`
  - `base64_encode` (function, line 443) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 460) `unsigned char *base64_decode(const char *input, int *len)`
  - `bsb_generate_secure_iv` (function, line 490) `int bsb_generate_secure_iv(unsigned char *iv_out)`
  - `_is_unreserved` (function, line 515) `static int _is_unreserved(unsigned char c)`
  - `url_encode` (function, line 521) `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
  - `parse_cmd_to_argv` (function, line 553) `static char **parse_cmd_to_argv(const char *cmd, int *out_argc)`
  - `free_argv` (function, line 629) `static void free_argv(char **argv)`
  - `exec_cmd` (function, line 640) `char *exec_cmd(const char *cmd, int *out_len)`
  - `bsb_backoff_init` (function, line 781) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)`
  - `bsb_backoff_next` (function, line 788) `int bsb_backoff_next(bsb_backoff_t *bo)`
  - `bsb_backoff_reset` (function, line 799) `void bsb_backoff_reset(bsb_backoff_t *bo)`
  - `get_local_ips` (function, line 805) `char *get_local_ips(void)`
  - `download_bof` (function, line 840) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)`
  - `init_function_pointers` (function, line 872) `static void init_function_pointers(void)`
  - `page_align` (function, line 922) `static size_t page_align(size_t size)`
  - `bof_crash_exit` (function, line 930) `static void bof_crash_exit(int sig)`
  - `__attribute__` (function, line 935) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `RunELF` (function, line 961) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `run_bof_and_capture` (function, line 1263) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `fault` (function, line 941) `* fault (SIGSEGV inside BeaconPrintf). We save the original %rsp in * a scratch slot we own below the current stack...`
  - `_GNU_SOURCE` (macro, line 9) `#define _GNU_SOURCE`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

## include/beacon_common.c_extraction.h
- Layer: utility
- Language: h
- Symbols:
  - `BEACON_COMMON` (macro, line 2) `#define BEACON_COMMON`
- Imported by: `mutants/src/beacon_common.c_extraction.c`, `src/beacon_common.c_extraction.c`

## include/beacon_common.h
- Doc: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead...
- Layer: utility
- Language: h
- Symbols:
  - `http_response_t` (struct, line 33)
  - `Trampoline` (struct, line 41)
  - `SymbolResolver` (struct, line 51)
  - `TrampolineCache` (struct, line 58)
  - `bsb_backoff_t` (struct, line 182)
  - `bsb_output_init` (function, line 96) `int bsb_output_init(size_t capacity);`
  - `bsb_output_cleanup` (function, line 99) `void bsb_output_cleanup(void);`
  - `bsb_output_reset` (function, line 102) `void bsb_output_reset(void);`
  - `BeaconPrintf` (function, line 105) `void BeaconPrintf(int type, const char *fmt, ...);`
  - `BeaconOutput` (function, line 108) `void BeaconOutput(int type, const char *data, int len);`
  - `create_trampoline` (function, line 111) `void *create_trampoline(void *target, void *near_hint);`
  - `cleanup_trampolines` (function, line 112) `void cleanup_trampolines(void);`
  - `get_or_create_trampoline` (function, line 113) `void *get_or_create_trampoline(void *target, void *near_hint);`
  - `https_request` (function, line 119) `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);`
  - `base64_encode` (function, line 123) `char *base64_encode(const unsigned char *input, int len);`
  - `base64_decode` (function, line 124) `unsigned char *base64_decode(const char *input, int *len);`
  - `url_encode` (function, line 127) `char *url_encode(const char *in, size_t in_len, size_t *out_len);`
  - `bsb_generate_secure_iv` (function, line 131) `int bsb_generate_secure_iv(unsigned char *iv_out);`
  - `aes256_cfb_encrypt` (function, line 134) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...`
  - `aes256_cfb_decrypt` (function, line 136) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...`
  - `aes256_cfb_encrypt_replay` (function, line 142) `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...`
  - `aes256_cfb_decrypt_replay` (function, line 150) `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...`
  - `buffer` (function, line 156) `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);`
  - `RunELF` (function, line 164) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...`
  - `download_bof` (function, line 169) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);`
  - `run_bof_and_capture` (function, line 173) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);`
  - `get_local_ips` (function, line 178) `char *get_local_ips(void);`
  - `bsb_backoff_init` (function, line 189) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);`
  - `bsb_backoff_next` (function, line 190) `int bsb_backoff_next(bsb_backoff_t *bo);`
  - `bsb_backoff_reset` (function, line 191) `void bsb_backoff_reset(bsb_backoff_t *bo);`
  - `g_beacon_output` (variable, line 65) `extern char *g_beacon_output;`
  - `g_printf_ptr` (variable, line 68) `extern void *g_printf_ptr;`
  - `g_strlen_ptr` (variable, line 69) `extern void *g_strlen_ptr;`
  - `g_memcpy_ptr` (variable, line 70) `extern void *g_memcpy_ptr;`
  - `g_memset_ptr` (variable, line 71) `extern void *g_memset_ptr;`
  - `g_exit_ptr` (variable, line 72) `extern void *g_exit_ptr;`
  - `g_dlsym_ptr` (variable, line 73) `extern void *g_dlsym_ptr;`
  - `g_dlerror_ptr` (variable, line 74) `extern void *g_dlerror_ptr;`
  - `g_dlopen_ptr` (variable, line 75) `extern void *g_dlopen_ptr;`
  - `g_dlclose_ptr` (variable, line 76) `extern void *g_dlclose_ptr;`
  - `g_write_ptr` (variable, line 77) `extern void *g_write_ptr;`
  - `g_mmap_ptr` (variable, line 78) `extern void *g_mmap_ptr;`
  - `g_munmap_ptr` (variable, line 79) `extern void *g_munmap_ptr;`
  - `g_BeaconPrintf_ptr` (variable, line 80) `extern void *g_BeaconPrintf_ptr;`
  - `g_BeaconOutput_ptr` (variable, line 81) `extern void *g_BeaconOutput_ptr;`
  - `g_socket_ptr` (variable, line 82) `extern void *g_socket_ptr;`
  - `g_connect_ptr` (variable, line 83) `extern void *g_connect_ptr;`
  - `g_inet_addr_ptr` (variable, line 84) `extern void *g_inet_addr_ptr;`
  - `g_htons_ptr` (variable, line 85) `extern void *g_htons_ptr;`
  - `g_send_ptr` (variable, line 86) `extern void *g_send_ptr;`
  - `g_recv_ptr` (variable, line 87) `extern void *g_recv_ptr;`
  - `g_close_ptr` (variable, line 88) `extern void *g_close_ptr;`
  - `g_getaddrinfo_ptr` (variable, line 89) `extern void *g_getaddrinfo_ptr;`
  - `g_freeaddrinfo_ptr` (variable, line 90) `extern void *g_freeaddrinfo_ptr;`
  - `BEACON_COMMON_H` (macro, line 13) `#define BEACON_COMMON_H`
  - `_GNU_SOURCE` (macro, line 15) `#define _GNU_SOURCE`
  - `BSB_OUTPUT_BUFFER_DEFAULT` (macro, line 26) `#define BSB_OUTPUT_BUFFER_DEFAULT`
  - `BSB_OUTPUT_TRUNCATION_MARKER` (macro, line 27) `#define BSB_OUTPUT_TRUNCATION_MARKER`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`, `tests/test_iv_generation_c.c`

## include/beacon_heartbeat___health_endpoint.h
- Layer: presentation
- Language: h
- Symbols:
  - `beacon_heartbeat___health_endpoint_process` (function, line 4) `bool beacon_heartbeat___health_endpoint_process(void);`
  - `BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` (macro, line 2) `#define BEACON_HEARTBEAT___HEALTH_ENDPOINT_H`
- Imported by: `mutants/src/beacon_heartbeat___health_endpoint.c`, `src/beacon_heartbeat___health_endpoint.c`

## include/bof_api_versioning.h
- Layer: presentation
- Language: h
- Symbols:
  - `bof_api_versioning_process` (function, line 4) `bool bof_api_versioning_process(void);`
  - `BOF_API_VERSIONING_H` (macro, line 2) `#define BOF_API_VERSIONING_H`
- Imported by: `mutants/src/bof_api_versioning.c`, `src/bof_api_versioning.c`

## include/bof_path_traversal_hardening.h
- Layer: utility
- Language: h
- Symbols:
  - `bof_path_traversal_hardening_process` (function, line 4) `bool bof_path_traversal_hardening_process(void);`
  - `BOF_PATH_TRAVERSAL_HARDENING_H` (macro, line 2) `#define BOF_PATH_TRAVERSAL_HARDENING_H`
- Imported by: `mutants/src/bof_path_traversal_hardening.c`, `src/bof_path_traversal_hardening.c`

## include/bof_streaming_(large_outputs).h
- Layer: utility
- Language: h
- Symbols:
  - `bof_streaming_` (function, line 4) `bool bof_streaming_(large_outputs)_process(void);`
  - `BOF_STREAMING_` (macro, line 2) `#define BOF_STREAMING_(LARGE_OUTPUTS)`
- Imported by: `mutants/src/bof_streaming_(large_outputs).c`, `src/bof_streaming_(large_outputs).c`

## include/c2_rest_api.h
- Layer: presentation
- Language: h
- Symbols:
  - `c2_rest_api_process` (function, line 4) `bool c2_rest_api_process(void);`
  - `C2_REST_API_H` (macro, line 2) `#define C2_REST_API_H`
- Imported by: `mutants/src/c2_rest_api.c`, `src/c2_rest_api.c`

## include/cJSON.c
- Doc: case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible...
- Layer: utility
- Language: c
- Symbols:
  - `internal_hooks` (struct, line 158)
  - `error` (struct, line 89)
  - `parse_buffer` (struct, line 292)
  - `printbuffer` (struct, line 485)
  - `CJSON_PUBLIC` (function, line 96) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
  - `CJSON_PUBLIC` (function, line 101) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 111) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 126) `CJSON_PUBLIC(const char *) cJSON_Version(void)`
  - `case_insensitive_strcmp` (function, line 135) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
  - `internal_malloc` (function, line 167) `static void *CJSON_CDECL internal_malloc(size_t size)`
  - `internal_free` (function, line 171) `static void CJSON_CDECL internal_free(void *pointer)`
  - `internal_realloc` (function, line 175) `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)`
  - `cJSON_strdup` (function, line 190) `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)`
  - `CJSON_PUBLIC` (function, line 211) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)`
  - `cJSON_New_Item` (function, line 243) `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)`
  - `get_decimal_point` (function, line 282) `static unsigned char get_decimal_point(void)`
  - `parse_number` (function, line 311) `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)`
  - `ensure` (function, line 497) `static unsigned char *ensure(printbuffer *const p, size_t needed)`
  - `update_offset` (function, line 583) `static void update_offset(printbuffer *const buffer)`
  - `compare_double` (function, line 596) `static cJSON_bool compare_double(double a, double b)`
  - `print_number` (function, line 603) `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)`
  - `parse_hex4` (function, line 673) `static unsigned parse_hex4(const unsigned char *const input)`
  - `utf16_literal_to_utf8` (function, line 710) `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,
            ...`
  - `parse_string` (function, line 832) `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)`
  - `print_string_ptr` (function, line 964) `static cJSON_bool print_string_ptr(const unsigned char *const input,
                            ...`
  - `print_string` (function, line 1087) `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)`
  - `buffer_skip_whitespace` (function, line 1101) `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)`
  - `skip_utf8_bom` (function, line 1127) `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)`
  - `CJSON_PUBLIC` (function, line 1143) `CJSON_PUBLIC(cJSON *)
cJSON_ParseWithOpts(const char *value, const char **return_parse_end,
     ...`
  - `CJSON_PUBLIC` (function, line 1251) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
  - `print` (function, line 1258) `static unsigned char *print(const cJSON *const item, cJSON_bool format,
                         ...`
  - `CJSON_PUBLIC` (function, line 1333) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
  - `CJSON_PUBLIC` (function, line 1338) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
  - `CJSON_PUBLIC` (function, line 1369) `CJSON_PUBLIC(cJSON_bool)
cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
  - `parse_value` (function, line 1390) `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)`
  - `print_value` (function, line 1450) `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)`
  - `parse_array` (function, line 1524) `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)`
  - `print_array` (function, line 1621) `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)`
  - `parse_object` (function, line 1683) `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)`
  - `print_object` (function, line 1801) `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)`
  - `get_array_item` (function, line 1937) `static cJSON *get_array_item(const cJSON *array, size_t index)`
  - `CJSON_PUBLIC` (function, line 1956) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
  - `get_object_item` (function, line 1966) `static cJSON *get_object_item(const cJSON *const object, const char *const name,
                ...`
  - `CJSON_PUBLIC` (function, line 2003) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)`
  - `CJSON_PUBLIC` (function, line 2008) `CJSON_PUBLIC(cJSON *)
cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...`
  - `CJSON_PUBLIC` (function, line 2014) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
  - `suffix_object` (function, line 2020) `static void suffix_object(cJSON *prev, cJSON *item)`
  - `create_reference` (function, line 2027) `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)`
  - `add_item_to_array` (function, line 2048) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
  - `cast_away_const` (function, line 2095) `static void *cast_away_const(const void *string)`
  - `add_item_to_object` (function, line 2104) `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,
             ...`
  - `CJSON_PUBLIC` (function, line 2143) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2154) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2164) `CJSON_PUBLIC(cJSON_bool)
cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
  - `CJSON_PUBLIC` (function, line 2176) `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)`
  - `CJSON_PUBLIC` (function, line 2188) `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)`
  - `CJSON_PUBLIC` (function, line 2200) `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)`
  - `CJSON_PUBLIC` (function, line 2212) `CJSON_PUBLIC(cJSON *)
cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...`
  - `CJSON_PUBLIC` (function, line 2225) `CJSON_PUBLIC(cJSON *)
cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...`
  - `CJSON_PUBLIC` (function, line 2238) `CJSON_PUBLIC(cJSON *)
cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...`
  - `CJSON_PUBLIC` (function, line 2251) `CJSON_PUBLIC(cJSON *)
cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...`
  - `CJSON_PUBLIC` (function, line 2264) `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)`
  - `CJSON_PUBLIC` (function, line 2276) `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)`
  - `CJSON_PUBLIC` (function, line 2288) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 2324) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2334) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2339) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2346) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2353) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2358) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2400) `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...`
  - `CJSON_PUBLIC` (function, line 2451) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
  - `replace_item_in_object` (function, line 2461) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,
 ...`
  - `CJSON_PUBLIC` (function, line 2486) `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
  - `CJSON_PUBLIC` (function, line 2492) `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
  - `CJSON_PUBLIC` (function, line 2510) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
  - `CJSON_PUBLIC` (function, line 2521) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
  - `CJSON_PUBLIC` (function, line 2532) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
  - `CJSON_PUBLIC` (function, line 2543) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
  - `CJSON_PUBLIC` (function, line 2568) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
  - `CJSON_PUBLIC` (function, line 2585) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
  - `CJSON_PUBLIC` (function, line 2597) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2609) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2621) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
  - `CJSON_PUBLIC` (function, line 2638) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
  - `CJSON_PUBLIC` (function, line 2649) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
  - `CJSON_PUBLIC` (function, line 2702) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2743) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2784) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
  - `cJSON_Duplicate_rec` (function, line 2832) `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
  - `skip_oneline_comment` (function, line 2923) `static void skip_oneline_comment(char **input)`
  - `skip_multiline_comment` (function, line 2937) `static void skip_multiline_comment(char **input)`
  - `minify_string` (function, line 2951) `static void minify_string(char **input, char **output)`
  - `CJSON_PUBLIC` (function, line 2977) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
  - `CJSON_PUBLIC` (function, line 3027) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3037) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3047) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3057) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3067) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3077) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3087) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3097) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3107) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3117) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)`
  - `CJSON_PUBLIC` (function, line 3127) `CJSON_PUBLIC(cJSON_bool)
cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...`
  - `cJSON_ArrayForEach` (function, line 3214) `cJSON_ArrayForEach(a_element, a)`
  - `cJSON_ArrayForEach` (function, line 3230) `cJSON_ArrayForEach(b_element, b)`
  - `CJSON_PUBLIC` (function, line 3251) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
  - `CJSON_PUBLIC` (function, line 3256) `CJSON_PUBLIC(void) cJSON_free(void *object)`
  - `_CRT_SECURE_NO_DEPRECATE` (macro, line 28) `#define _CRT_SECURE_NO_DEPRECATE`
  - `true` (macro, line 65) `#define true`
  - `false` (macro, line 70) `#define false`
  - `isinf` (macro, line 75) `#define isinf(d)`
  - `isnan` (macro, line 78) `#define isnan(d)`
  - `NAN` (macro, line 83) `#define NAN`
  - `NAN` (macro, line 85) `#define NAN`
  - `internal_malloc` (macro, line 180) `#define internal_malloc`
  - `internal_free` (macro, line 181) `#define internal_free`
  - `internal_realloc` (macro, line 182) `#define internal_realloc`
  - `static_strlen` (macro, line 186) `#define static_strlen(string_literal)`
  - `can_read` (macro, line 302) `#define can_read(buffer, size)`
  - `can_access_at_index` (macro, line 304) `#define can_access_at_index(buffer, index)`
  - `cannot_access_at_index` (macro, line 306) `#define cannot_access_at_index(buffer, index)`
  - `buffer_at_offset` (macro, line 308) `#define buffer_at_offset(buffer)`
  - `cjson_min` (macro, line 1256) `#define cjson_min(a, b)`
- Depends on: `include/cJSON.h`

## include/cJSON.h
- Doc: cJSON: #define cJSON_Invalid (0) #define cJSON_False (1 << 0) #define cJSON_True (1 << 1)...
- Layer: utility
- Language: h
- Symbols:
  - `cJSON` (struct, line 98)
  - `cJSON_Hooks` (struct, line 123)
  - `cJSON_bool` (type_alias, line 130) `typedef int cJSON_bool;`
  - `cJSON_Parse` (function, line 152) `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...`
  - `cJSON_GetErrorPtr` (function, line 161) `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...`
  - `that` (function, line 247) `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...`
  - `sensitive` (function, line 286) `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...`
  - `next` (variable, line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) ||...`
  - `cJSON__h` (macro, line 24) `#define cJSON__h`
  - `__WINDOWS__` (macro, line 33) `#define __WINDOWS__`
  - `CJSON_CDECL` (macro, line 49) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 50) `#define CJSON_STDCALL`
  - `CJSON_EXPORT_SYMBOLS` (macro, line 54) `#define CJSON_EXPORT_SYMBOLS`
  - `CJSON_PUBLIC` (macro, line 58) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 60) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 62) `#define CJSON_PUBLIC(type)`
  - `CJSON_CDECL` (macro, line 65) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 66) `#define CJSON_STDCALL`
  - `CJSON_PUBLIC` (macro, line 70) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 72) `#define CJSON_PUBLIC(type)`
  - `CJSON_VERSION_MAJOR` (macro, line 77) `#define CJSON_VERSION_MAJOR`
  - `CJSON_VERSION_MINOR` (macro, line 78) `#define CJSON_VERSION_MINOR`
  - `CJSON_VERSION_PATCH` (macro, line 79) `#define CJSON_VERSION_PATCH`
  - `cJSON_Invalid` (macro, line 84) `#define cJSON_Invalid`
  - `cJSON_False` (macro, line 85) `#define cJSON_False`
  - `cJSON_True` (macro, line 86) `#define cJSON_True`
  - `cJSON_NULL` (macro, line 87) `#define cJSON_NULL`
  - `cJSON_Number` (macro, line 88) `#define cJSON_Number`
  - `cJSON_String` (macro, line 89) `#define cJSON_String`
  - `cJSON_Array` (macro, line 90) `#define cJSON_Array`
  - `cJSON_Object` (macro, line 91) `#define cJSON_Object`
  - `cJSON_Raw` (macro, line 92) `#define cJSON_Raw`
  - `cJSON_IsReference` (macro, line 94) `#define cJSON_IsReference`
  - `cJSON_StringIsConst` (macro, line 95) `#define cJSON_StringIsConst`
  - `CJSON_NESTING_LIMIT` (macro, line 136) `#define CJSON_NESTING_LIMIT`
  - `CJSON_CIRCULAR_LIMIT` (macro, line 142) `#define CJSON_CIRCULAR_LIMIT`
  - `cJSON_SetIntValue` (macro, line 312) `#define cJSON_SetIntValue(object, number)`
  - `cJSON_SetNumberValue` (macro, line 316) `#define cJSON_SetNumberValue(object, number)`
  - `cJSON_SetBoolValue` (macro, line 324) `#define cJSON_SetBoolValue(object, boolValue)`
  - `cJSON_ArrayForEach` (macro, line 331) `#define cJSON_ArrayForEach(element, array)`
- Imported by: `include/beacon_common.c`, `include/cJSON.c`

## include/certificate_pinning___tofu.h
- Layer: utility
- Language: h
- Symbols:
  - `certificate_pinning___tofu_process` (function, line 4) `bool certificate_pinning___tofu_process(void);`
  - `CERTIFICATE_PINNING___TOFU_H` (macro, line 2) `#define CERTIFICATE_PINNING___TOFU_H`
- Imported by: `mutants/src/certificate_pinning___tofu.c`, `src/certificate_pinning___tofu.c`


Next: [KB_include_p2.md](KB_include_p2.md)
