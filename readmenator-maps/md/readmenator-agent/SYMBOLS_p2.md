# Symbols (page 2 of 4)
Previous: [SYMBOLS.md](SYMBOLS.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_ECB_encrypt` | function | `include/aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_KEYLEN` | macro | `include/aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `include/aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `include/aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);` |
| `AES_init_ctx` | function | `include/aes.h:41` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);` |
| `AES_init_ctx_iv` | function | `include/aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` |
| `AES_keyExpSize` | macro | `include/aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `include/aes.h:9` | `#define CBC` |
| `CTR` | macro | `include/aes.h:15` | `#define CTR` |
| `ECB` | macro | `include/aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `include/aes.h:2` | `#define _AES_H_` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.c:55` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_decrypt_replay` | function | `include/aes_cfb.c:126` | `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv,      ...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.c:21` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt_replay` | function | `include/aes_cfb.c:94` | `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv,      ...` |
| `BSB_AES_CFB_H` | macro | `include/aes_cfb.h:5` | `#define BSB_AES_CFB_H` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.h:11` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.h:9` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` |
| `ASYNC_I_O_FOR_BEACON_H` | macro | `include/async_i_o_for_beacon.h:2` | `#define ASYNC_I_O_FOR_BEACON_H` |
| `async_i_o_for_beacon_process` | function | `include/async_i_o_for_beacon.h:4` | `bool async_i_o_for_beacon_process(void);` |
| `BEACON_API_H` | macro | `include/beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `include/beacon.h:27` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `include/beacon.h:24` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `include/beacon.h:26` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `include/beacon.h:22` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `include/beacon.h:23` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `include/beacon.h:25` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `include/beacon.h:29` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon.h:28` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `include/beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `include/beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `include/beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `include/beacon.h:14` | `` |
| `BeaconOutput` | function | `include/beacon_common.c:175` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `include/beacon_common.c:159` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `MemoryStruct` | struct | `include/beacon_common.c:297` | `` |
| `RunELF` | function | `include/beacon_common.c:961` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `WriteMemoryCallback` | function | `include/beacon_common.c:303` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `include/beacon_common.c:9` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `include/beacon_common.c:935` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `_is_unreserved` | function | `include/beacon_common.c:515` | `static int _is_unreserved(unsigned char c)` |
| `base64_decode` | function | `include/beacon_common.c:460` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `include/beacon_common.c:443` | `char *base64_encode(const unsigned char *input, int len)` |
| `bof_crash_exit` | function | `include/beacon_common.c:930` | `static void bof_crash_exit(int sig)` |
| `bsb_backoff_init` | function | `include/beacon_common.c:781` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` |
| `bsb_backoff_next` | function | `include/beacon_common.c:788` | `int bsb_backoff_next(bsb_backoff_t *bo)` |
| `bsb_backoff_reset` | function | `include/beacon_common.c:799` | `void bsb_backoff_reset(bsb_backoff_t *bo)` |
| `bsb_curl_pin_format` | function | `include/beacon_common.c:330` | `static void bsb_curl_pin_format(const char *in, char *out, size_t outsz)` |
| `bsb_generate_secure_iv` | function | `include/beacon_common.c:490` | `int bsb_generate_secure_iv(unsigned char *iv_out)` |
| `bsb_output_cleanup` | function | `include/beacon_common.c:135` | `void bsb_output_cleanup(void)` |
| `bsb_output_init` | function | `include/beacon_common.c:109` | `int bsb_output_init(size_t capacity)` |
| `bsb_output_meta_t` | struct | `include/beacon_common.c:43` | `` |
| `bsb_output_reset` | function | `include/beacon_common.c:149` | `void bsb_output_reset(void)` |
| `cleanup_trampolines` | function | `include/beacon_common.c:249` | `void cleanup_trampolines(void)` |
| `create_trampoline` | function | `include/beacon_common.c:211` | `void *create_trampoline(void *target, void *near_hint)` |
| `download_bof` | function | `include/beacon_common.c:840` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` |
| `exec_cmd` | function | `include/beacon_common.c:640` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `fault` | function | `include/beacon_common.c:941` | `* fault (SIGSEGV inside BeaconPrintf). We save the original %rsp in * a scratch slot we own below the current stack...` |
| `free_argv` | function | `include/beacon_common.c:629` | `static void free_argv(char **argv)` |
| `get_local_ips` | function | `include/beacon_common.c:805` | `char *get_local_ips(void)` |
| `get_or_create_trampoline` | function | `include/beacon_common.c:266` | `void *get_or_create_trampoline(void *target, void *near_hint)` |
| `https_request` | function | `include/beacon_common.c:367` | `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method,      ...` |
| `init_function_pointers` | function | `include/beacon_common.c:872` | `static void init_function_pointers(void)` |
| `mmap_near` | function | `include/beacon_common.c:193` | `static void *mmap_near(void *near_hint, size_t len, int prot)` |
| `page_align` | function | `include/beacon_common.c:922` | `static size_t page_align(size_t size)` |
| `parse_cmd_to_argv` | function | `include/beacon_common.c:553` | `static char **parse_cmd_to_argv(const char *cmd, int *out_argc)` |
| `run_bof_and_capture` | function | `include/beacon_common.c:1263` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `url_encode` | function | `include/beacon_common.c:521` | `char *url_encode(const char *in, size_t in_len, size_t *out_len)` |
| `BEACON_COMMON` | macro | `include/beacon_common.c_extraction.h:2` | `#define BEACON_COMMON` |
| `BEACON_COMMON_H` | macro | `include/beacon_common.h:13` | `#define BEACON_COMMON_H` |
| `BSB_OUTPUT_BUFFER_DEFAULT` | macro | `include/beacon_common.h:26` | `#define BSB_OUTPUT_BUFFER_DEFAULT` |
| `BSB_OUTPUT_TRUNCATION_MARKER` | macro | `include/beacon_common.h:27` | `#define BSB_OUTPUT_TRUNCATION_MARKER` |
| `BeaconOutput` | function | `include/beacon_common.h:108` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon_common.h:105` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `RunELF` | function | `include/beacon_common.h:164` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...` |
| `SymbolResolver` | struct | `include/beacon_common.h:51` | `` |
| `Trampoline` | struct | `include/beacon_common.h:41` | `` |
| `TrampolineCache` | struct | `include/beacon_common.h:58` | `` |
| `_GNU_SOURCE` | macro | `include/beacon_common.h:15` | `#define _GNU_SOURCE` |
| `aes256_cfb_decrypt` | function | `include/beacon_common.h:136` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_decrypt_replay` | function | `include/beacon_common.h:150` | `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_encrypt` | function | `include/beacon_common.h:134` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` |
| `aes256_cfb_encrypt_replay` | function | `include/beacon_common.h:142` | `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `base64_decode` | function | `include/beacon_common.h:124` | `unsigned char *base64_decode(const char *input, int *len);` |
| `base64_encode` | function | `include/beacon_common.h:123` | `char *base64_encode(const unsigned char *input, int len);` |
| `bsb_backoff_init` | function | `include/beacon_common.h:189` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);` |
| `bsb_backoff_next` | function | `include/beacon_common.h:190` | `int bsb_backoff_next(bsb_backoff_t *bo);` |
| `bsb_backoff_reset` | function | `include/beacon_common.h:191` | `void bsb_backoff_reset(bsb_backoff_t *bo);` |
| `bsb_backoff_t` | struct | `include/beacon_common.h:182` | `` |
| `bsb_generate_secure_iv` | function | `include/beacon_common.h:131` | `int bsb_generate_secure_iv(unsigned char *iv_out);` |
| `bsb_output_cleanup` | function | `include/beacon_common.h:99` | `void bsb_output_cleanup(void);` |
| `bsb_output_init` | function | `include/beacon_common.h:96` | `int bsb_output_init(size_t capacity);` |
| `bsb_output_reset` | function | `include/beacon_common.h:102` | `void bsb_output_reset(void);` |
| `buffer` | function | `include/beacon_common.h:156` | `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);` |
| `cleanup_trampolines` | function | `include/beacon_common.h:112` | `void cleanup_trampolines(void);` |
| `create_trampoline` | function | `include/beacon_common.h:111` | `void *create_trampoline(void *target, void *near_hint);` |
| `download_bof` | function | `include/beacon_common.h:169` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` |
| `g_BeaconOutput_ptr` | variable | `include/beacon_common.h:81` | `extern void *g_BeaconOutput_ptr;` |
| `g_BeaconPrintf_ptr` | variable | `include/beacon_common.h:80` | `extern void *g_BeaconPrintf_ptr;` |
| `g_beacon_output` | variable | `include/beacon_common.h:65` | `extern char *g_beacon_output;` |
| `g_close_ptr` | variable | `include/beacon_common.h:88` | `extern void *g_close_ptr;` |
| `g_connect_ptr` | variable | `include/beacon_common.h:83` | `extern void *g_connect_ptr;` |
| `g_dlclose_ptr` | variable | `include/beacon_common.h:76` | `extern void *g_dlclose_ptr;` |
| `g_dlerror_ptr` | variable | `include/beacon_common.h:74` | `extern void *g_dlerror_ptr;` |
| `g_dlopen_ptr` | variable | `include/beacon_common.h:75` | `extern void *g_dlopen_ptr;` |
| `g_dlsym_ptr` | variable | `include/beacon_common.h:73` | `extern void *g_dlsym_ptr;` |
| `g_exit_ptr` | variable | `include/beacon_common.h:72` | `extern void *g_exit_ptr;` |
| `g_freeaddrinfo_ptr` | variable | `include/beacon_common.h:90` | `extern void *g_freeaddrinfo_ptr;` |
| `g_getaddrinfo_ptr` | variable | `include/beacon_common.h:89` | `extern void *g_getaddrinfo_ptr;` |
| `g_htons_ptr` | variable | `include/beacon_common.h:85` | `extern void *g_htons_ptr;` |
| `g_inet_addr_ptr` | variable | `include/beacon_common.h:84` | `extern void *g_inet_addr_ptr;` |
| `g_memcpy_ptr` | variable | `include/beacon_common.h:70` | `extern void *g_memcpy_ptr;` |
| `g_memset_ptr` | variable | `include/beacon_common.h:71` | `extern void *g_memset_ptr;` |
| `g_mmap_ptr` | variable | `include/beacon_common.h:78` | `extern void *g_mmap_ptr;` |
| `g_munmap_ptr` | variable | `include/beacon_common.h:79` | `extern void *g_munmap_ptr;` |
| `g_printf_ptr` | variable | `include/beacon_common.h:68` | `extern void *g_printf_ptr;` |
| `g_recv_ptr` | variable | `include/beacon_common.h:87` | `extern void *g_recv_ptr;` |
| `g_send_ptr` | variable | `include/beacon_common.h:86` | `extern void *g_send_ptr;` |
| `g_socket_ptr` | variable | `include/beacon_common.h:82` | `extern void *g_socket_ptr;` |
| `g_strlen_ptr` | variable | `include/beacon_common.h:69` | `extern void *g_strlen_ptr;` |
| `g_write_ptr` | variable | `include/beacon_common.h:77` | `extern void *g_write_ptr;` |
| `get_local_ips` | function | `include/beacon_common.h:178` | `char *get_local_ips(void);` |
| `get_or_create_trampoline` | function | `include/beacon_common.h:113` | `void *get_or_create_trampoline(void *target, void *near_hint);` |
| `http_response_t` | struct | `include/beacon_common.h:33` | `` |
| `https_request` | function | `include/beacon_common.h:119` | `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` |
| `run_bof_and_capture` | function | `include/beacon_common.h:173` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` |
| `url_encode` | function | `include/beacon_common.h:127` | `char *url_encode(const char *in, size_t in_len, size_t *out_len);` |
| `BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` | macro | `include/beacon_heartbeat___health_endpoint.h:2` | `#define BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` |
| `beacon_heartbeat___health_endpoint_process` | function | `include/beacon_heartbeat___health_endpoint.h:4` | `bool beacon_heartbeat___health_endpoint_process(void);` |
| `BOF_API_VERSIONING_H` | macro | `include/bof_api_versioning.h:2` | `#define BOF_API_VERSIONING_H` |
| `bof_api_versioning_process` | function | `include/bof_api_versioning.h:4` | `bool bof_api_versioning_process(void);` |
| `BOF_PATH_TRAVERSAL_HARDENING_H` | macro | `include/bof_path_traversal_hardening.h:2` | `#define BOF_PATH_TRAVERSAL_HARDENING_H` |
| `bof_path_traversal_hardening_process` | function | `include/bof_path_traversal_hardening.h:4` | `bool bof_path_traversal_hardening_process(void);` |
| `BOF_STREAMING_` | macro | `include/bof_streaming_(large_outputs).h:2` | `#define BOF_STREAMING_(LARGE_OUTPUTS)` |
| `bof_streaming_` | function | `include/bof_streaming_(large_outputs).h:4` | `bool bof_streaming_(large_outputs)_process(void);` |
| `C2_REST_API_H` | macro | `include/c2_rest_api.h:2` | `#define C2_REST_API_H` |
| `c2_rest_api_process` | function | `include/c2_rest_api.h:4` | `bool c2_rest_api_process(void);` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:96` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:101` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:111` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:126` | `CJSON_PUBLIC(const char *) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:211` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1143` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end,      ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1251` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1333` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1338` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1369` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1956` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2003` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2008` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2014` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2143` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2154` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2164` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2176` | `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2188` | `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2200` | `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2212` | `CJSON_PUBLIC(cJSON *) cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2225` | `CJSON_PUBLIC(cJSON *) cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2238` | `CJSON_PUBLIC(cJSON *) cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2264` | `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2276` | `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2288` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2324` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2334` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2339` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2346` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2353` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2358` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2400` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2486` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2492` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2510` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2521` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2532` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2568` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2585` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2597` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2609` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2621` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2638` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2649` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2702` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2743` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2784` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2977` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3027` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3037` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3047` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3057` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3067` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3077` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3087` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3097` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3107` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3117` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3127` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3251` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3256` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `include/cJSON.c:83` | `#define NAN` |
| `NAN` | macro | `include/cJSON.c:85` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `include/cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `include/cJSON.c:2048` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `include/cJSON.c:2104` | `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,              ...` |
| `buffer_at_offset` | macro | `include/cJSON.c:308` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `include/cJSON.c:1101` | `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3214` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3230` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `include/cJSON.c:2832` | `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `include/cJSON.c:243` | `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` |
| `cJSON_strdup` | function | `include/cJSON.c:190` | `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)` |
| `can_access_at_index` | macro | `include/cJSON.c:304` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `include/cJSON.c:302` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `include/cJSON.c:306` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `include/cJSON.c:135` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `include/cJSON.c:2095` | `static void *cast_away_const(const void *string)` |
| `cjson_min` | macro | `include/cJSON.c:1256` | `#define cjson_min(a, b)` |
| `compare_double` | function | `include/cJSON.c:596` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `include/cJSON.c:2027` | `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` |
| `ensure` | function | `include/cJSON.c:497` | `static unsigned char *ensure(printbuffer *const p, size_t needed)` |
| `error` | struct | `include/cJSON.c:89` | `` |
| `false` | macro | `include/cJSON.c:70` | `#define false` |
| `get_array_item` | function | `include/cJSON.c:1937` | `static cJSON *get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `include/cJSON.c:282` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `include/cJSON.c:1966` | `static cJSON *get_object_item(const cJSON *const object, const char *const name,                 ...` |
| `internal_free` | function | `include/cJSON.c:171` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `include/cJSON.c:181` | `#define internal_free` |
| `internal_hooks` | struct | `include/cJSON.c:158` | `` |
| `internal_malloc` | function | `include/cJSON.c:167` | `static void *CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `include/cJSON.c:180` | `#define internal_malloc` |
| `internal_realloc` | function | `include/cJSON.c:175` | `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `include/cJSON.c:182` | `#define internal_realloc` |
| `isinf` | macro | `include/cJSON.c:75` | `#define isinf(d)` |
| `isnan` | macro | `include/cJSON.c:78` | `#define isnan(d)` |
| `minify_string` | function | `include/cJSON.c:2951` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `include/cJSON.c:1524` | `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_buffer` | struct | `include/cJSON.c:292` | `` |
| `parse_hex4` | function | `include/cJSON.c:673` | `static unsigned parse_hex4(const unsigned char *const input)` |
| `parse_number` | function | `include/cJSON.c:311` | `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_object` | function | `include/cJSON.c:1683` | `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_string` | function | `include/cJSON.c:832` | `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_value` | function | `include/cJSON.c:1390` | `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` |
| `print` | function | `include/cJSON.c:1258` | `static unsigned char *print(const cJSON *const item, cJSON_bool format,                          ...` |
| `print_array` | function | `include/cJSON.c:1621` | `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_number` | function | `include/cJSON.c:603` | `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_object` | function | `include/cJSON.c:1801` | `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_string` | function | `include/cJSON.c:1087` | `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` |
| `print_string_ptr` | function | `include/cJSON.c:964` | `static cJSON_bool print_string_ptr(const unsigned char *const input,                             ...` |
| `print_value` | function | `include/cJSON.c:1450` | `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` |
| `printbuffer` | struct | `include/cJSON.c:485` | `` |
| `replace_item_in_object` | function | `include/cJSON.c:2461` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,  ...` |
| `skip_multiline_comment` | function | `include/cJSON.c:2937` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `include/cJSON.c:2923` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `include/cJSON.c:1127` | `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` |
| `static_strlen` | macro | `include/cJSON.c:186` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `include/cJSON.c:2020` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `include/cJSON.c:65` | `#define true` |
| `update_offset` | function | `include/cJSON.c:583` | `static void update_offset(printbuffer *const buffer)` |
| `utf16_literal_to_utf8` | function | `include/cJSON.c:710` | `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,             ...` |
| `CJSON_CDECL` | macro | `include/cJSON.h:49` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `include/cJSON.h:65` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `include/cJSON.h:142` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `include/cJSON.h:54` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `include/cJSON.h:136` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:58` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:60` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:62` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:70` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:72` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:50` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:66` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `include/cJSON.h:77` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `include/cJSON.h:78` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `include/cJSON.h:79` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `include/cJSON.h:33` | `#define __WINDOWS__` |
| `cJSON` | struct | `include/cJSON.h:98` | `` |
| `cJSON_Array` | macro | `include/cJSON.h:90` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `include/cJSON.h:331` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `include/cJSON.h:85` | `#define cJSON_False` |
| `cJSON_GetErrorPtr` | function | `include/cJSON.h:161` | `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...` |
| `cJSON_Hooks` | struct | `include/cJSON.h:123` | `` |
| `cJSON_Invalid` | macro | `include/cJSON.h:84` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `include/cJSON.h:94` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `include/cJSON.h:87` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `include/cJSON.h:88` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `include/cJSON.h:91` | `#define cJSON_Object` |
| `cJSON_Parse` | function | `include/cJSON.h:152` | `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...` |
| `cJSON_Raw` | macro | `include/cJSON.h:92` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `include/cJSON.h:324` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `include/cJSON.h:312` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `include/cJSON.h:316` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `include/cJSON.h:89` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `include/cJSON.h:95` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `include/cJSON.h:86` | `#define cJSON_True` |
| `cJSON__h` | macro | `include/cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `include/cJSON.h:130` | `typedef int cJSON_bool;` |
| `next` | variable | `include/cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `include/cJSON.h:286` | `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...` |
| `that` | function | `include/cJSON.h:247` | `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...` |
| `CERTIFICATE_PINNING___TOFU_H` | macro | `include/certificate_pinning___tofu.h:2` | `#define CERTIFICATE_PINNING___TOFU_H` |
| `certificate_pinning___tofu_process` | function | `include/certificate_pinning___tofu.h:4` | `bool certificate_pinning___tofu_process(void);` |
| `COMMAND_EXECUTION_VIA_EXECVE_H` | macro | `include/command_execution_via_execve.h:2` | `#define COMMAND_EXECUTION_VIA_EXECVE_H` |
| `command_execution_via_execve_process` | function | `include/command_execution_via_execve.h:4` | `bool command_execution_via_execve_process(void);` |
| `HKDF_INFO_ENC` | macro | `include/config.c:289` | `#define HKDF_INFO_ENC` |
| `HKDF_INFO_HMAC` | macro | `include/config.c:290` | `#define HKDF_INFO_HMAC` |
| `HKDF_SALT` | macro | `include/config.c:288` | `#define HKDF_SALT` |
| `_POSIX_C_SOURCE` | macro | `include/config.c:13` | `#define _POSIX_C_SOURCE` |
| `binary_dir` | function | `include/config.c:798` | `static const char *binary_dir(char *out, size_t outsz)` |
| `bsb_config_load` | function | `include/config.c:655` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_load_default` | function | `include/config.c:820` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_sleep_seconds` | function | `include/config.c:853` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg)` |
| `derive_keys_from_master` | function | `include/config.c:345` | `static void derive_keys_from_master(bsb_config_t *cfg)` |
| `expect` | function | `include/config.c:156` | `static int expect(const char **pp, const char *end, char c)` |
| `find_matching_brace` | function | `include/config.c:167` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `hex_to_bytes` | function | `include/config.c:269` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `hkdf_expand` | function | `include/config.c:305` | `static void hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,...` |
| `hkdf_extract` | function | `include/config.c:299` | `static void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len...` |
| `hkdf_sha256` | function | `include/config.c:337` | `static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,...` |
| `hmac_sha256` | function | `include/config.c:292` | `static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,...` |
| `parse_backoff` | function | `include/config.c:620` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config.c:586` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config.c:375` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config.c:419` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config.c:518` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config.c:474` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config.c:137` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config.c:113` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config.c:66` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config.c:203` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config.c:56` | `static const char *skip_ws(const char *p, const char *end)` |
| `slurp` | function | `include/config.c:24` | `static char *slurp(const char *path, size_t *out_len)` |
| `BSB_AES_KEY_BYTES` | macro | `include/config.h:25` | `#define BSB_AES_KEY_BYTES` |
| `BSB_AES_KEY_HEX_LEN` | macro | `include/config.h:24` | `#define BSB_AES_KEY_HEX_LEN` |
| `BSB_CONFIG_H` | macro | `include/config.h:14` | `#define BSB_CONFIG_H` |
| `BSB_CONFIG_PATH_DEFAULT` | macro | `include/config.h:19` | `#define BSB_CONFIG_PATH_DEFAULT` |
| `BSB_CONFIG_PATH_ENV` | macro | `include/config.h:20` | `#define BSB_CONFIG_PATH_ENV` |
| `BSB_MAX_CLIENT_ID` | macro | `include/config.h:23` | `#define BSB_MAX_CLIENT_ID` |
| `BSB_MAX_URI` | macro | `include/config.h:22` | `#define BSB_MAX_URI` |
| `BSB_MAX_URL` | macro | `include/config.h:21` | `#define BSB_MAX_URL` |
| `BSB_MAX_USER_AGENTS` | macro | `include/config.h:26` | `#define BSB_MAX_USER_AGENTS` |
| `BSB_REPORT_URI_DEFAULT` | macro | `include/config.h:28` | `#define BSB_REPORT_URI_DEFAULT` |
| `BSB_USER_AGENT_LEN` | macro | `include/config.h:27` | `#define BSB_USER_AGENT_LEN` |
| `bsb_backoff_config_t` | struct | `include/config.h:70` | `` |
| `bsb_bof_t` | struct | `include/config.h:64` | `` |
| `bsb_c2_t` | struct | `include/config.h:30` | `` |
| `bsb_config_load` | function | `include/config.h:89` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_load_default` | function | `include/config.h:92` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_sleep_seconds` | function | `include/config.h:95` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` |
| `bsb_config_t` | struct | `include/config.h:76` | `` |
| `bsb_crypto_t` | struct | `include/config.h:38` | `` |
| `bsb_network_t` | struct | `include/config.h:56` | `` |
| `bsb_timing_t` | struct | `include/config.h:48` | `` |
| `_POSIX_C_SOURCE` | macro | `include/config_autogen.c:5` | `#define _POSIX_C_SOURCE` |
| `bsb_config_load` | function | `include/config_autogen.c:375` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `expect` | function | `include/config_autogen.c:93` | `static int expect(const char **pp, const char *end, char c)` |
| `find_matching_brace` | function | `include/config_autogen.c:101` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `hex_to_bytes` | function | `include/config_autogen.c:165` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `parse_backoff` | function | `include/config_autogen.c:325` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config_autogen.c:300` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config_autogen.c:177` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config_autogen.c:206` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config_autogen.c:260` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_server` | function | `include/config_autogen.c:350` | `static void parse_server(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config_autogen.c:227` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config_autogen.c:85` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config_autogen.c:68` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config_autogen.c:40` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config_autogen.c:123` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config_autogen.c:34` | `static const char *skip_ws(const char *p, const char *end)` |
| `slurp` | function | `include/config_autogen.c:16` | `static char *slurp(const char *path, size_t *out_len)` |
| `BSB_CONFIG_AUTOGEN_H` | macro | `include/config_autogen.h:6` | `#define BSB_CONFIG_AUTOGEN_H` |
| `bsb_backoff_t` | struct | `include/config_autogen.h:47` | `` |
| `bsb_bof_t` | struct | `include/config_autogen.h:42` | `` |
| `bsb_c2_t` | struct | `include/config_autogen.h:11` | `` |
| `bsb_config_load` | function | `include/config_autogen.h:69` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_load_default` | function | `include/config_autogen.h:72` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_sleep_seconds` | function | `include/config_autogen.h:75` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` |
| `bsb_config_t` | struct | `include/config_autogen.h:57` | `` |
| `bsb_crypto_t` | struct | `include/config_autogen.h:21` | `` |
| `bsb_network_t` | struct | `include/config_autogen.h:35` | `` |
| `bsb_server_t` | struct | `include/config_autogen.h:52` | `` |
| `bsb_timing_t` | struct | `include/config_autogen.h:28` | `` |
| `_deep_merge` | function | `include/config_py.py:84` | `def _deep_merge(base, overlay)` |
| `_derive_keys` | function | `include/config_py.py:65` | `def _derive_keys(master_key_bytes)` |
| `load_config` | function | `include/config_py.py:94` | `def load_config(path)` |
| `_deep_merge` | function | `include/config_py_autogen.py:80` | `def _deep_merge(base, overlay)` |
| `_derive_keys` | function | `include/config_py_autogen.py:59` | `def _derive_keys(master_key_bytes)` |
| `load_config` | function | `include/config_py_autogen.py:89` | `def load_config(path)` |
| `CONTAINERIZED_BUILD_` | macro | `include/containerized_build_+_sbom.h:2` | `#define CONTAINERIZED_BUILD_` |
| `HKDF_KEY_DERIVATION_H` | macro | `include/hkdf_key_derivation.h:2` | `#define HKDF_KEY_DERIVATION_H` |
| `hkdf_key_derivation_process` | function | `include/hkdf_key_derivation.h:4` | `bool hkdf_key_derivation_process(void);` |
| `IV_GENERATION_WITH_ENTROPY_VERIFICATION_H` | macro | `include/iv_generation_with_entropy_verification.h:2` | `#define IV_GENERATION_WITH_ENTROPY_VERIFICATION_H` |
| `iv_generation_with_entropy_verification_process` | function | `include/iv_generation_with_entropy_verification.h:4` | `bool iv_generation_with_entropy_verification_process(void);` |
| `MUTATION_TESTING_INTEGRATION_H` | macro | `include/mutation_testing_integration.h:2` | `#define MUTATION_TESTING_INTEGRATION_H` |
| `mutation_testing_integration_process` | function | `include/mutation_testing_integration.h:4` | `bool mutation_testing_integration_process(void);` |
| `PRE` | macro | `include/pre-commit_+_ci_hardening.h:2` | `#define PRE` |
| `REPLAY_PROTECTION_H` | macro | `include/replay_protection.h:2` | `#define REPLAY_PROTECTION_H` |
| `replay_protection_process` | function | `include/replay_protection.h:4` | `bool replay_protection_process(void);` |
| `SOCKS5___HTTP_PROXY_SUPPORT_H` | macro | `include/socks5___http_proxy_support.h:2` | `#define SOCKS5___HTTP_PROXY_SUPPORT_H` |
| `socks5___http_proxy_support_process` | function | `include/socks5___http_proxy_support.h:4` | `bool socks5___http_proxy_support_process(void);` |
| `STRUCTURED_JSONL_LOGGING_H` | macro | `include/structured_jsonl_logging.h:2` | `#define STRUCTURED_JSONL_LOGGING_H` |
| `structured_jsonl_logging_process` | function | `include/structured_jsonl_logging.h:4` | `bool structured_jsonl_logging_process(void);` |
| `TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H` | macro | `include/tls_client_certificate_authentication.h:2` | `#define TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H` |
| `tls_client_certificate_authentication_process` | function | `include/tls_client_certificate_authentication.h:4` | `bool tls_client_certificate_authentication_process(void);` |
| `UNIFIED_CONFIG_SCHEMA_H` | macro | `include/unified_config_schema.h:2` | `#define UNIFIED_CONFIG_SCHEMA_H` |
| `unified_config_schema_process` | function | `include/unified_config_schema.h:4` | `bool unified_config_schema_process(void);` |
| `AT_FDCWD` | macro | `issudo.c:19` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `issudo.c:11` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `issudo.c:10` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `issudo.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `issudo.c:2` | `#define NULL` |
| `SYS_close` | macro | `issudo.c:16` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `issudo.c:18` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `issudo.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `issudo.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `issudo.c:15` | `#define SYS_read` |
| `get_username_from_uid` | function | `issudo.c:51` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `issudo.c:121` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `issudo.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `issudo.c:7` | `typedef long ssize_t;` |
| `strcmp` | function | `issudo.c:40` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `issudo.c:32` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `issudo.c:22` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `BeaconOutput` | function | `legacy/beacon3.c:213` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/beacon3.c:196` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `legacy/beacon3.c:33` | `#define C2_URL` |
| `CLIENT_ID` | macro | `legacy/beacon3.c:34` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `legacy/beacon3.c:35` | `#define MALEABLE` |
| `MemoryStruct` | struct | `legacy/beacon3.c:52` | `` |
| `RunELF` | function | `legacy/beacon3.c:584` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/beacon3.c:69` | `` |
| `Trampoline` | struct | `legacy/beacon3.c:60` | `` |
| `TrampolineCache` | struct | `legacy/beacon3.c:76` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/beacon3.c:36` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/beacon3.c:324` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/beacon3.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/beacon3.c:145` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `legacy/beacon3.c:514` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/beacon3.c:480` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/beacon3.c:454` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/beacon3.c:436` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/beacon3.c:268` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/beacon3.c:227` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/beacon3.c:1118` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `legacy/beacon3.c:550` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/beacon3.c:1083` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/beacon3.c:286` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `legacy/beacon3.c:342` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `legacy/beacon3.c:1187` | `int main()` |
| `page_align` | function | `legacy/beacon3.c:576` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `legacy/beacon3.c:1141` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BeaconOutput` | function | `legacy/beacon5.c:256` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/beacon5.c:239` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `legacy/beacon5.c:42` | `#define C2_URL` |
| `CLIENT_ID` | macro | `legacy/beacon5.c:43` | `#define CLIENT_ID` |
| `DISCOVERY_INTERVAL` | macro | `legacy/beacon5.c:38` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `legacy/beacon5.c:37` | `#define DISCOVERY_PORT` |
| `MALEABLE` | macro | `legacy/beacon5.c:44` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `legacy/beacon5.c:36` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `legacy/beacon5.c:39` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `legacy/beacon5.c:40` | `#define MESH_MSG_SIZE` |
| `MemoryStruct` | struct | `legacy/beacon5.c:61` | `` |
| `RunELF` | function | `legacy/beacon5.c:627` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/beacon5.c:111` | `` |
| `Trampoline` | struct | `legacy/beacon5.c:102` | `` |
| `TrampolineCache` | struct | `legacy/beacon5.c:118` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/beacon5.c:45` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/beacon5.c:367` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/beacon5.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/beacon5.c:188` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `legacy/beacon5.c:557` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/beacon5.c:523` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/beacon5.c:497` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/beacon5.c:479` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/beacon5.c:311` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/beacon5.c:270` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/beacon5.c:1161` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `legacy/beacon5.c:593` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/beacon5.c:1126` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/beacon5.c:329` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `legacy/beacon5.c:385` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `legacy/beacon5.c:1702` | `int main(int argc, char **argv)` |
| `mesh_add_peer` | function | `legacy/beacon5.c:1255` | `void mesh_add_peer(const char *ip, int port)` |
| `mesh_cleanup_peers` | function | `legacy/beacon5.c:1283` | `void mesh_cleanup_peers()` |
| `mesh_discovery_thread` | function | `legacy/beacon5.c:1356` | `void *mesh_discovery_thread(void *arg)` |
| `mesh_is_seen` | function | `legacy/beacon5.c:1240` | `int mesh_is_seen(const char *msg_id)` |

Next: [SYMBOLS_p3.md](SYMBOLS_p3.md)
