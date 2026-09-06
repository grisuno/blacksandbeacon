# Subsystem: root

## aes.c
- Layer: utility
- Doc: aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h>  define Nb 4    define KEYLE
- Language: c
- Symbols:
  - `getSBoxValue` (function, line 12) `static uint8_t getSBoxValue(uint8_t num)`
  - `getSBoxInvert` (function, line 34) `static uint8_t getSBoxInvert(uint8_t num)`
  - `Td0` (function, line 56) `static uint8_t Td0(int x)`
  - `Td1` (function, line 58) `static uint8_t Td1(int x)`
  - `Td2` (function, line 59) `static uint8_t Td2(int x)`
  - `Td3` (function, line 60) `static uint8_t Td3(int x)`
  - `Td4` (function, line 61) `static uint8_t Td4(int x)`
  - `KeyExpansion` (function, line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
  - `AES_init_ctx` (function, line 238) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
  - `AES_init_ctx_iv` (function, line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
  - `AES_ctx_set_iv` (function, line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
  - `AddRoundKey` (function, line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
  - `SubBytes` (function, line 271) `static void SubBytes(state_t* state)`
  - `ShiftRows` (function, line 286) `static void ShiftRows(state_t* state)`
  - `xtime` (function, line 313) `static uint8_t xtime(uint8_t x)`
  - `MixColumns` (function, line 320) `static void MixColumns(state_t* state)`
  - `Multiply` (function, line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)`
  - `InvMixColumns` (function, line 370) `static void InvMixColumns(state_t* state)`
  - `InvSubBytes` (function, line 391) `static void InvSubBytes(state_t* state)`
  - `InvShiftRows` (function, line 402) `static void InvShiftRows(state_t* state)`
  - `Cipher` (function, line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
  - `InvCipher` (function, line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
  - `AES_ECB_encrypt` (function, line 488) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
  - `AES_ECB_decrypt` (function, line 495) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
  - `XorWithIv` (function, line 510) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
  - `AES_CBC_encrypt_buffer` (function, line 520) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
  - `AES_CBC_decrypt_buffer` (function, line 535) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
  - `AES_CTR_xcrypt_buffer` (function, line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
  - `Nb` (macro, line 4)
  - `KEYLEN_256` (macro, line 6)
  - `RKLENGTH` (macro, line 10)
  - `BLOCKLEN` (macro, line 11)
  - `Nb` (macro, line 67)
  - `Nk` (macro, line 70)
  - `Nr` (macro, line 71)
  - `Nk` (macro, line 73)
  - `Nr` (macro, line 74)
  - `Nk` (macro, line 76)
  - `Nr` (macro, line 77)
  - `MULTIPLY_AS_A_FUNCTION` (macro, line 84)
  - `getSBoxValue` (macro, line 163)
  - `Multiply` (macro, line 349)
  - `getSBoxInvert` (macro, line 365)

## aes.h
- Layer: utility
- Doc: ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable 
- Language: h
- Symbols:
  - `AES_ctx` (struct, line 33)
  - `_AES_H_` (macro, line 2)
  - `CBC` (macro, line 9)
  - `ECB` (macro, line 12)
  - `CTR` (macro, line 15)
  - `AES256` (macro, line 17)
  - `AES_BLOCKLEN` (macro, line 19)
  - `AES_KEYLEN` (macro, line 23)
  - `AES_keyExpSize` (macro, line 24)
  - `AES_KEYLEN` (macro, line 26)
  - `AES_keyExpSize` (macro, line 27)
  - `AES_KEYLEN` (macro, line 29)
  - `AES_keyExpSize` (macro, line 30)

## app.py
- Layer: utility
- Doc: _*_ coding: utf8 _*_
- Language: py

## beacon.h
- Layer: utility
- Doc: beacon_api.h ifndef BEACON_API_H define BEACON_API_H  include <stdint.h> include <stdarg.h>  Tipos de callback define CA
- Language: h
- Symbols:
  - `BEACON_API_H` (macro, line 3)
  - `CALLBACK_OUTPUT` (macro, line 9)
  - `CALLBACK_ERROR` (macro, line 10)
  - `CALLBACK_OUTPUT_OEM` (macro, line 11)

## beacon3.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 50)
  - `__attribute__` (function, line 140) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 193) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 205) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 217) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 253) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 268) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 300) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 317) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 406) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 422) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 446) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 473) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 504) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 525) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 530) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 912) `char* get_local_ips()`
  - `download_bof` (function, line 941) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 963) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 1007) `int main()`
  - `_GNU_SOURCE` (macro, line 1)
  - `C2_URL` (macro, line 32)
  - `CLIENT_ID` (macro, line 34)
  - `MALEABLE` (macro, line 35)
  - `USER_AGENTS_COUNT` (macro, line 36)

## beacon5.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 61)
  - `__attribute__` (function, line 182) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 235) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 247) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 259) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 295) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 310) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 342) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 359) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 448) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 464) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 488) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 515) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 546) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 567) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 572) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 954) `char* get_local_ips()`
  - `download_bof` (function, line 983) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 1005) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `mesh_mark_seen` (function, line 1049) `void mesh_mark_seen(const char *msg_id)`
  - `mesh_is_seen` (function, line 1057) `int mesh_is_seen(const char *msg_id)`
  - `mesh_add_peer` (function, line 1069) `void mesh_add_peer(const char *ip, int port)`
  - `mesh_cleanup_peers` (function, line 1094) `void mesh_cleanup_peers()`
  - `mesh_send_to_peer` (function, line 1108) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
  - `mesh_propagate` (function, line 1130) `void mesh_propagate(const char *command)`
  - `mesh_discovery_thread` (function, line 1157) `void *mesh_discovery_thread(void *arg)`
  - `mesh_listener_thread` (function, line 1240) `void *mesh_listener_thread(void *arg)`
  - `mesh_send_message` (function, line 1416) `void mesh_send_message(int type, const char* target, const char* payload)`
  - `main` (function, line 1444) `int main(int argc, char **argv)`
  - `_GNU_SOURCE` (macro, line 1)
  - `MAX_PEERS` (macro, line 35)
  - `DISCOVERY_PORT` (macro, line 38)
  - `DISCOVERY_INTERVAL` (macro, line 39)
  - `MAX_TTL` (macro, line 40)
  - `MESH_MSG_SIZE` (macro, line 41)
  - `C2_URL` (macro, line 42)
  - `CLIENT_ID` (macro, line 45)
  - `MALEABLE` (macro, line 46)
  - `USER_AGENTS_COUNT` (macro, line 47)

## beacon6.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 52)
  - `__attribute__` (function, line 142) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `delay_ms` (function, line 195) `static void delay_ms(int ms)`
  - `is_prime` (function, line 202) `static unsigned int is_prime(unsigned int x)`
  - `get_nth_prime_limited` (function, line 218) `static unsigned int get_nth_prime_limited(unsigned int n)`
  - `portable_rand_19k_29k` (function, line 242) `static unsigned int portable_rand_19k_29k(void)`
  - `BeaconPrintf` (function, line 255) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 267) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 279) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 315) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 330) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 362) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 379) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 468) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 484) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 508) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 535) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 566) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 587) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 592) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 974) `char* get_local_ips()`
  - `download_bof` (function, line 1003) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 1025) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 1069) `int main()`
  - `_GNU_SOURCE` (macro, line 1)
  - `C2_URL` (macro, line 34)
  - `CLIENT_ID` (macro, line 36)
  - `MALEABLE` (macro, line 37)
  - `USER_AGENTS_COUNT` (macro, line 38)

## beacon_p2p.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 549)
  - `BeaconDataParse` (function, line 91) `void BeaconDataParse(datap *parser, char *buffer, int size)`
  - `BeaconDataPtr` (function, line 96) `char *BeaconDataPtr(datap *parser, int size)`
  - `BeaconDataInt` (function, line 104) `int BeaconDataInt(datap *parser)`
  - `BeaconDataShort` (function, line 110) `short BeaconDataShort(datap *parser)`
  - `BeaconDataLength` (function, line 116) `int BeaconDataLength(datap *parser)`
  - `BeaconDataExtract` (function, line 120) `char *BeaconDataExtract(datap *parser, int *size)`
  - `BeaconPrintf` (function, line 128) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 141) `void BeaconOutput(int type, const char *data, int len)`
  - `__attribute__` (function, line 228) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `create_trampoline` (function, line 258) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 283) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 296) `static void* get_or_create_trampoline(void* target)`
  - `page_align` (function, line 317) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 323) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
  - `WriteMemoryCallback` (function, line 554) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 574) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 624) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 640) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 653) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 680) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 712) `char* exec_cmd(const char* cmd, int* out_len)`
  - `get_local_ips` (function, line 728) `char* get_local_ips()`
  - `download_bof` (function, line 756) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 765) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `add_peer` (function, line 783) `void add_peer(struct in_addr ip, int port, const char *id)`
  - `peer_discovery_thread` (function, line 806) `void *peer_discovery_thread(void *arg)`
  - `handle_peer_connection` (function, line 845) `void *handle_peer_connection(void *arg)`
  - `peer_server_thread` (function, line 915) `void *peer_server_thread(void *arg)`
  - `send_to_peer` (function, line 934) `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
  - `send_to_c2_or_peer` (function, line 967) `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
  - `execute_generic_command` (function, line 996) `char* execute_generic_command(const char *cmd, int *out_len)`
  - `main` (function, line 1031) `int main()`
  - `_GNU_SOURCE` (macro, line 1)
  - `C2_URL` (macro, line 37)
  - `CLIENT_ID` (macro, line 38)
  - `MALEABLE` (macro, line 39)
  - `USER_AGENTS_COUNT` (macro, line 40)
  - `PEER_DISCOVERY_PORT` (macro, line 41)
  - `PEER_TCP_PORT` (macro, line 43)
  - `PEER_MAGIC` (macro, line 44)
  - `PEER_VERSION` (macro, line 45)
  - `BROADCAST_INTERVAL` (macro, line 46)
  - `MAX_PEERS` (macro, line 47)

## bof.c
- Layer: utility
- Doc: bof.c include "beacon.h"  // ← Incluir la API
- Language: c
- Symbols:
  - `__attribute__` (function, line 3) `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)`

## cJSON.c
- Layer: utility
- Language: c
- Symbols:
  - `internal_hooks` (struct, line 157)
  - `CJSON_PUBLIC` (function, line 94) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
  - `CJSON_PUBLIC` (function, line 99) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 109) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 124) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
  - `case_insensitive_strcmp` (function, line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
  - `internal_malloc` (function, line 166) `static void * CJSON_CDECL internal_malloc(size_t size)`
  - `internal_free` (function, line 170) `static void CJSON_CDECL internal_free(void *pointer)`
  - `internal_realloc` (function, line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
  - `cJSON_strdup` (function, line 188) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
  - `CJSON_PUBLIC` (function, line 209) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
  - `cJSON_New_Item` (function, line 242) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
  - `get_decimal_point` (function, line 281) `static unsigned char get_decimal_point(void)`
  - `parse_number` (function, line 309) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
  - `ensure` (function, line 494) `static unsigned char* ensure(printbuffer * const p, size_t needed)`
  - `update_offset` (function, line 579) `static void update_offset(printbuffer * const buffer)`
  - `compare_double` (function, line 592) `static cJSON_bool compare_double(double a, double b)`
  - `print_number` (function, line 599) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
  - `parse_hex4` (function, line 669) `static unsigned parse_hex4(const unsigned char * const input)`
  - `utf16_literal_to_utf8` (function, line 706) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
  - `parse_string` (function, line 827) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_string_ptr` (function, line 957) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
  - `print_string` (function, line 1079) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
  - `buffer_skip_whitespace` (function, line 1093) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
  - `skip_utf8_bom` (function, line 1119) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
  - `CJSON_PUBLIC` (function, line 1133) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
  - `CJSON_PUBLIC` (function, line 1235) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
  - `print` (function, line 1242) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
  - `CJSON_PUBLIC` (function, line 1315) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
  - `CJSON_PUBLIC` (function, line 1320) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
  - `CJSON_PUBLIC` (function, line 1351) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
  - `parse_value` (function, line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_value` (function, line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
  - `parse_array` (function, line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_array` (function, line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
  - `parse_object` (function, line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_object` (function, line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
  - `get_array_item` (function, line 1915) `static cJSON* get_array_item(const cJSON *array, size_t index)`
  - `CJSON_PUBLIC` (function, line 1934) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
  - `get_object_item` (function, line 1944) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
  - `CJSON_PUBLIC` (function, line 1976) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
  - `CJSON_PUBLIC` (function, line 1981) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
  - `CJSON_PUBLIC` (function, line 1986) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
  - `suffix_object` (function, line 1993) `static void suffix_object(cJSON *prev, cJSON *item)`
  - `create_reference` (function, line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
  - `add_item_to_array` (function, line 2020) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
  - `cast_away_const` (function, line 2066) `static void* cast_away_const(const void* string)`
  - `add_item_to_object` (function, line 2073) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
  - `CJSON_PUBLIC` (function, line 2111) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2122) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2132) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
  - `CJSON_PUBLIC` (function, line 2142) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2154) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2166) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2178) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
  - `CJSON_PUBLIC` (function, line 2190) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
  - `CJSON_PUBLIC` (function, line 2202) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
  - `CJSON_PUBLIC` (function, line 2214) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
  - `CJSON_PUBLIC` (function, line 2226) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2238) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2250) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2286) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2296) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2301) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2308) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2315) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2320) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2362) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
  - `CJSON_PUBLIC` (function, line 2412) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
  - `replace_item_in_object` (function, line 2422) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
  - `CJSON_PUBLIC` (function, line 2445) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
  - `CJSON_PUBLIC` (function, line 2450) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
  - `CJSON_PUBLIC` (function, line 2467) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
  - `CJSON_PUBLIC` (function, line 2478) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
  - `CJSON_PUBLIC` (function, line 2489) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
  - `CJSON_PUBLIC` (function, line 2500) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
  - `CJSON_PUBLIC` (function, line 2525) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
  - `CJSON_PUBLIC` (function, line 2542) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
  - `CJSON_PUBLIC` (function, line 2554) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2566) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2578) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
  - `CJSON_PUBLIC` (function, line 2595) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
  - `CJSON_PUBLIC` (function, line 2606) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
  - `CJSON_PUBLIC` (function, line 2658) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2698) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2738) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
  - `cJSON_Duplicate_rec` (function, line 2785) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
  - `skip_oneline_comment` (function, line 2872) `static void skip_oneline_comment(char **input)`
  - `skip_multiline_comment` (function, line 2885) `static void skip_multiline_comment(char **input)`
  - `minify_string` (function, line 2899) `static void minify_string(char **input, char **output)`
  - `CJSON_PUBLIC` (function, line 2921) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
  - `CJSON_PUBLIC` (function, line 2971) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2981) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2991) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3001) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3011) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3021) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3031) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3041) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3051) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3061) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3071) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
  - `cJSON_ArrayForEach` (function, line 3157) `cJSON_ArrayForEach(a_element, a)`
  - `cJSON_ArrayForEach` (function, line 3173) `cJSON_ArrayForEach(b_element, b)`
  - `CJSON_PUBLIC` (function, line 3193) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
  - `CJSON_PUBLIC` (function, line 3198) `CJSON_PUBLIC(void) cJSON_free(void *object)`
  - `_CRT_SECURE_NO_DEPRECATE` (macro, line 28)
  - `true` (macro, line 65)
  - `false` (macro, line 70)
  - `isinf` (macro, line 74)
  - `isnan` (macro, line 77)
  - `NAN` (macro, line 82)
  - `NAN` (macro, line 84)
  - `internal_malloc` (macro, line 179)
  - `internal_free` (macro, line 180)
  - `internal_realloc` (macro, line 181)
  - `static_strlen` (macro, line 185)
  - `can_read` (macro, line 301)
  - `can_access_at_index` (macro, line 303)
  - `cannot_access_at_index` (macro, line 304)
  - `buffer_at_offset` (macro, line 306)
  - `cjson_min` (macro, line 1240)

## cJSON.h
- Layer: utility
- Language: h
- Symbols:
  - `cJSON` (struct, line 92)
  - `cJSON_Hooks` (struct, line 114)
  - `cJSON__h` (macro, line 24)
  - `__WINDOWS__` (macro, line 32)
  - `CJSON_CDECL` (macro, line 43)
  - `CJSON_STDCALL` (macro, line 45)
  - `CJSON_EXPORT_SYMBOLS` (macro, line 49)
  - `CJSON_PUBLIC` (macro, line 53)
  - `CJSON_PUBLIC` (macro, line 55)
  - `CJSON_PUBLIC` (macro, line 57)
  - `CJSON_CDECL` (macro, line 60)
  - `CJSON_STDCALL` (macro, line 61)
  - `CJSON_PUBLIC` (macro, line 64)
  - `CJSON_PUBLIC` (macro, line 66)
  - `CJSON_VERSION_MAJOR` (macro, line 71)
  - `CJSON_VERSION_MINOR` (macro, line 72)
  - `CJSON_VERSION_PATCH` (macro, line 73)
  - `cJSON_Invalid` (macro, line 78)
  - `cJSON_False` (macro, line 79)
  - `cJSON_True` (macro, line 80)
  - `cJSON_NULL` (macro, line 81)
  - `cJSON_Number` (macro, line 82)
  - `cJSON_String` (macro, line 83)
  - `cJSON_Array` (macro, line 84)
  - `cJSON_Object` (macro, line 85)
  - `cJSON_Raw` (macro, line 86)
  - `cJSON_IsReference` (macro, line 87)
  - `cJSON_StringIsConst` (macro, line 89)
  - `CJSON_NESTING_LIMIT` (macro, line 126)
  - `CJSON_CIRCULAR_LIMIT` (macro, line 132)
  - `cJSON_SetIntValue` (macro, line 270)
  - `cJSON_SetNumberValue` (macro, line 273)
  - `cJSON_SetBoolValue` (macro, line 278)
  - `cJSON_ArrayForEach` (macro, line 285)

## gopher_beacon.c
- Layer: utility
- Doc: define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 47)
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
  - `_GNU_SOURCE` (macro, line 1)
  - `C2` (macro, line 29)
  - `CLIENT_ID` (macro, line 31)
  - `MALEABLE` (macro, line 32)
  - `USER_AGENTS_COUNT` (macro, line 33)

## gopher_c2.py
- Layer: utility
- Language: py
- Symbols:
  - `encrypt_data` (function, line 28) `def encrypt_data(data)`
  - `decrypt_data` (function, line 37) `def decrypt_data(b64_data)`
  - `handle_client` (function, line 45) `def handle_client(conn, addr)`
  - `main` (function, line 127) `def main()`
  - `command_injector` (function, line 136) `def command_injector()`

## install.sh
- Layer: utility
- Doc: install.sh - Install build deps and build everything.  Idempotent: safe to run on a fresh checkout. Tested on Debian 12 
- Language: sh

## issudo.c
- Layer: utility
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos
- Language: c
- Symbols:
  - `syscall3` (function, line 22) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 31) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 43) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 52) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 107) `void go(char *args, int alen)`
  - `NULL` (macro, line 2)
  - `CALLBACK_OUTPUT` (macro, line 3)
  - `SYS_openat` (macro, line 14)
  - `SYS_read` (macro, line 15)
  - `SYS_close` (macro, line 16)
  - `SYS_getuid` (macro, line 17)
  - `SYS_getpwuid_r` (macro, line 18)
  - `AT_FDCWD` (macro, line 19)
