# Subsystem: root

## aes.c
- Layer: utility
- Doc: aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Language: c
- Symbols:
  - `getSBoxValue` (function, line 13) `static uint8_t getSBoxValue(uint8_t num)`
  - `getSBoxInvert` (function, line 35) `static uint8_t getSBoxInvert(uint8_t num)`
  - `Td0` (function, line 57) `static uint8_t Td0(int x)`
  - `Td1` (function, line 58) `static uint8_t Td1(int x)`
  - `Td2` (function, line 59) `static uint8_t Td2(int x)`
  - `Td3` (function, line 60) `static uint8_t Td3(int x)`
  - `Td4` (function, line 61) `static uint8_t Td4(int x)`
  - `KeyExpansion` (function, line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
  - `AES_init_ctx` (function, line 239) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
  - `AES_init_ctx_iv` (function, line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
  - `AES_ctx_set_iv` (function, line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
  - `AddRoundKey` (function, line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
  - `SubBytes` (function, line 271) `static void SubBytes(state_t* state)`
  - `ShiftRows` (function, line 286) `static void ShiftRows(state_t* state)`
  - `xtime` (function, line 314) `static uint8_t xtime(uint8_t x)`
  - `MixColumns` (function, line 320) `static void MixColumns(state_t* state)`
  - `Multiply` (function, line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)`
  - `InvMixColumns` (function, line 370) `static void InvMixColumns(state_t* state)`
  - `InvSubBytes` (function, line 391) `static void InvSubBytes(state_t* state)`
  - `InvShiftRows` (function, line 403) `static void InvShiftRows(state_t* state)`
  - `Cipher` (function, line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
  - `InvCipher` (function, line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
  - `AES_ECB_encrypt` (function, line 490) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
  - `AES_ECB_decrypt` (function, line 496) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
  - `XorWithIv` (function, line 512) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
  - `AES_CBC_encrypt_buffer` (function, line 521) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
  - `AES_CBC_decrypt_buffer` (function, line 536) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
  - `AES_CTR_xcrypt_buffer` (function, line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
  - `Nb` (macro, line 5) `#define Nb`
  - `KEYLEN_256` (macro, line 9) `#define KEYLEN_256`
  - `RKLENGTH` (macro, line 10) `#define RKLENGTH`
  - `BLOCKLEN` (macro, line 11) `#define BLOCKLEN`
  - `Nb` (macro, line 67) `#define Nb`
  - `Nk` (macro, line 70) `#define Nk`
  - `Nr` (macro, line 71) `#define Nr`
  - `Nk` (macro, line 73) `#define Nk`
  - `Nr` (macro, line 74) `#define Nr`
  - `Nk` (macro, line 76) `#define Nk`
  - `Nr` (macro, line 77) `#define Nr`
  - `MULTIPLY_AS_A_FUNCTION` (macro, line 84) `#define MULTIPLY_AS_A_FUNCTION`
  - `getSBoxValue` (macro, line 163) `#define getSBoxValue(num)`
  - `Multiply` (macro, line 349) `#define Multiply(x, y)`
  - `getSBoxInvert` (macro, line 365) `#define getSBoxInvert(num)`
- Depends on: `aes.h`

## aes.h
- Layer: utility
- Doc: #define the macros below to 1/0 to enable/disable the mode of operation.
- Language: h
- Symbols:
  - `AES_ctx` (struct, line 33)
  - `AES_init_ctx` (function, line 41) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
  - `AES_init_ctx_iv` (function, line 43) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);`
  - `AES_ctx_set_iv` (function, line 44) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
  - `AES_ECB_encrypt` (function, line 48) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);`
  - `AES_ECB_decrypt` (function, line 49) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
  - `AES_CBC_encrypt_buffer` (function, line 53) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
  - `AES_CBC_decrypt_buffer` (function, line 54) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
  - `AES_CTR_xcrypt_buffer` (function, line 58) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
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
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

## app.py
- Layer: utility
- Doc: app.py  Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licenci
- Language: py

## beacon.h
- Layer: utility
- Doc: beacon_api.h   Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)
- Language: h
- Symbols:
  - `datap` (struct, line 14)
  - `BeaconDataParse` (function, line 21) `void BeaconDataParse(datap *parser, char *buffer, int size);`
  - `BeaconDataPtr` (function, line 22) `char *BeaconDataPtr(datap *parser, int size);`
  - `BeaconDataInt` (function, line 23) `int BeaconDataInt(datap *parser);`
  - `BeaconDataShort` (function, line 24) `short BeaconDataShort(datap *parser);`
  - `BeaconDataLength` (function, line 25) `int BeaconDataLength(datap *parser);`
  - `BeaconDataExtract` (function, line 26) `char *BeaconDataExtract(datap *parser, int *size);`
  - `BeaconPrintf` (function, line 27) `void BeaconPrintf(int type, const char *fmt, ...);`
  - `BeaconOutput` (function, line 28) `void BeaconOutput(int type, const char *data, int len);`
  - `BEACON_API_H` (macro, line 3) `#define BEACON_API_H`
  - `CALLBACK_OUTPUT` (macro, line 9) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 10) `#define CALLBACK_ERROR`
  - `CALLBACK_OUTPUT_OEM` (macro, line 11) `#define CALLBACK_OUTPUT_OEM`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

## beacon3.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 50)
  - `Trampoline` (struct, line 57)
  - `SymbolResolver` (struct, line 65)
  - `TrampolineCache` (struct, line 71)
  - `__attribute__` (function, line 140) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 193) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 206) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 217) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 253) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 269) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 300) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 317) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 406) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 423) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 446) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 474) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 504) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 525) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 531) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 912) `char* get_local_ips()`
  - `download_bof` (function, line 941) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 963) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 1007) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 33) `#define C2_URL`
  - `CLIENT_ID` (macro, line 34) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 35) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 36) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon5.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 61)
  - `peer_t` (struct, line 68)
  - `mesh_msg_t` (struct, line 75)
  - `Trampoline` (struct, line 98)
  - `SymbolResolver` (struct, line 106)
  - `TrampolineCache` (struct, line 112)
  - `__attribute__` (function, line 182) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 235) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 248) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 259) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 295) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 311) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 342) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 359) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 448) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 465) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 488) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 516) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 546) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 567) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 573) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 954) `char* get_local_ips()`
  - `download_bof` (function, line 983) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 1005) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `mesh_mark_seen` (function, line 1050) `void mesh_mark_seen(const char *msg_id)`
  - `mesh_is_seen` (function, line 1058) `int mesh_is_seen(const char *msg_id)`
  - `mesh_add_peer` (function, line 1070) `void mesh_add_peer(const char *ip, int port)`
  - `mesh_cleanup_peers` (function, line 1095) `void mesh_cleanup_peers()`
  - `mesh_send_to_peer` (function, line 1109) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
  - `mesh_propagate` (function, line 1131) `void mesh_propagate(const char *command)`
  - `mesh_discovery_thread` (function, line 1158) `void *mesh_discovery_thread(void *arg)`
  - `mesh_listener_thread` (function, line 1241) `void *mesh_listener_thread(void *arg)`
  - `mesh_send_message` (function, line 1417) `void mesh_send_message(int type, const char* target, const char* payload)`
  - `main` (function, line 1444) `int main(int argc, char **argv)`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 37) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 38) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 39) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 40) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 41) `#define MESH_MSG_SIZE`
  - `C2_URL` (macro, line 44) `#define C2_URL`
  - `CLIENT_ID` (macro, line 45) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 46) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 47) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon6.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 52)
  - `Trampoline` (struct, line 59)
  - `SymbolResolver` (struct, line 67)
  - `TrampolineCache` (struct, line 73)
  - `__attribute__` (function, line 142) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `delay_ms` (function, line 195) `static void delay_ms(int ms)`
  - `is_prime` (function, line 202) `static unsigned int is_prime(unsigned int x)`
  - `get_nth_prime_limited` (function, line 218) `static unsigned int get_nth_prime_limited(unsigned int n)`
  - `portable_rand_19k_29k` (function, line 243) `static unsigned int portable_rand_19k_29k(void)`
  - `BeaconPrintf` (function, line 255) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 268) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 279) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 315) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 331) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 362) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 379) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 468) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 485) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 508) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 536) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 566) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 587) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 593) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 974) `char* get_local_ips()`
  - `download_bof` (function, line 1003) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 1025) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 1069) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 35) `#define C2_URL`
  - `CLIENT_ID` (macro, line 36) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 37) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 38) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon_p2p.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 549)
  - `peer_t` (struct, line 59)
  - `p2p_header_t` (struct, line 72)
  - `Trampoline` (struct, line 155)
  - `SymbolResolver` (struct, line 161)
  - `TrampolineCache` (struct, line 170)
  - `BeaconDataParse` (function, line 91) `void BeaconDataParse(datap *parser, char *buffer, int size)`
  - `BeaconDataPtr` (function, line 97) `char *BeaconDataPtr(datap *parser, int size)`
  - `BeaconDataInt` (function, line 105) `int BeaconDataInt(datap *parser)`
  - `BeaconDataShort` (function, line 111) `short BeaconDataShort(datap *parser)`
  - `BeaconDataLength` (function, line 117) `int BeaconDataLength(datap *parser)`
  - `BeaconDataExtract` (function, line 121) `char *BeaconDataExtract(datap *parser, int *size)`
  - `BeaconPrintf` (function, line 129) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 142) `void BeaconOutput(int type, const char *data, int len)`
  - `__attribute__` (function, line 229) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `create_trampoline` (function, line 259) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 284) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 297) `static void* get_or_create_trampoline(void* target)`
  - `page_align` (function, line 318) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 324) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
  - `WriteMemoryCallback` (function, line 555) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 575) `char* https_request(const char* url, const char* method, const char* post_data)`
  - `base64_encode` (function, line 625) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 641) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 654) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 681) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 712) `char* exec_cmd(const char* cmd, int* out_len)`
  - `get_local_ips` (function, line 729) `char* get_local_ips()`
  - `download_bof` (function, line 757) `unsigned char* download_bof(const char* url, size_t* out_size)`
  - `run_bof_and_capture` (function, line 766) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `add_peer` (function, line 783) `void add_peer(struct in_addr ip, int port, const char *id)`
  - `peer_discovery_thread` (function, line 807) `void *peer_discovery_thread(void *arg)`
  - `handle_peer_connection` (function, line 846) `void *handle_peer_connection(void *arg)`
  - `peer_server_thread` (function, line 916) `void *peer_server_thread(void *arg)`
  - `send_to_peer` (function, line 935) `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
  - `send_to_c2_or_peer` (function, line 968) `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
  - `execute_generic_command` (function, line 996) `char* execute_generic_command(const char *cmd, int *out_len)`
  - `main` (function, line 1031) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 37) `#define C2_URL`
  - `CLIENT_ID` (macro, line 38) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 39) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 40) `#define USER_AGENTS_COUNT`
  - `PEER_DISCOVERY_PORT` (macro, line 42) `#define PEER_DISCOVERY_PORT`
  - `PEER_TCP_PORT` (macro, line 43) `#define PEER_TCP_PORT`
  - `PEER_MAGIC` (macro, line 44) `#define PEER_MAGIC`
  - `PEER_VERSION` (macro, line 45) `#define PEER_VERSION`
  - `BROADCAST_INTERVAL` (macro, line 46) `#define BROADCAST_INTERVAL`
  - `MAX_PEERS` (macro, line 47) `#define MAX_PEERS`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## bof.c
- Layer: utility
- Doc: bof.c
- Language: c
- Symbols:
  - `__attribute__` (function, line 4) `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)`
- Depends on: `beacon.h`

## cJSON.c
- Layer: utility
- Language: c
- Symbols:
  - `internal_hooks` (struct, line 157)
  - `error` (struct, line 88)
  - `parse_buffer` (struct, line 291)
  - `printbuffer` (struct, line 482)
  - `CJSON_PUBLIC` (function, line 95) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
  - `CJSON_PUBLIC` (function, line 100) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 110) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 125) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
  - `case_insensitive_strcmp` (function, line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
  - `internal_malloc` (function, line 166) `static void * CJSON_CDECL internal_malloc(size_t size)`
  - `internal_free` (function, line 170) `static void CJSON_CDECL internal_free(void *pointer)`
  - `internal_realloc` (function, line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
  - `cJSON_strdup` (function, line 189) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
  - `CJSON_PUBLIC` (function, line 210) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
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
  - `CJSON_PUBLIC` (function, line 1134) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
  - `CJSON_PUBLIC` (function, line 1236) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
  - `print` (function, line 1243) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
  - `CJSON_PUBLIC` (function, line 1316) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
  - `CJSON_PUBLIC` (function, line 1321) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
  - `CJSON_PUBLIC` (function, line 1352) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
  - `parse_value` (function, line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_value` (function, line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
  - `parse_array` (function, line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_array` (function, line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
  - `parse_object` (function, line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
  - `print_object` (function, line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
  - `get_array_item` (function, line 1916) `static cJSON* get_array_item(const cJSON *array, size_t index)`
  - `CJSON_PUBLIC` (function, line 1935) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
  - `get_object_item` (function, line 1945) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
  - `CJSON_PUBLIC` (function, line 1977) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
  - `CJSON_PUBLIC` (function, line 1982) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
  - `CJSON_PUBLIC` (function, line 1987) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
  - `suffix_object` (function, line 1993) `static void suffix_object(cJSON *prev, cJSON *item)`
  - `create_reference` (function, line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
  - `add_item_to_array` (function, line 2021) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
  - `cast_away_const` (function, line 2066) `static void* cast_away_const(const void* string)`
  - `add_item_to_object` (function, line 2075) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
  - `CJSON_PUBLIC` (function, line 2112) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2123) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
  - `CJSON_PUBLIC` (function, line 2133) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
  - `CJSON_PUBLIC` (function, line 2143) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2155) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2167) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2179) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
  - `CJSON_PUBLIC` (function, line 2191) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
  - `CJSON_PUBLIC` (function, line 2203) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
  - `CJSON_PUBLIC` (function, line 2215) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
  - `CJSON_PUBLIC` (function, line 2227) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2239) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
  - `CJSON_PUBLIC` (function, line 2251) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2287) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2297) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
  - `CJSON_PUBLIC` (function, line 2302) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2309) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2316) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2321) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
  - `CJSON_PUBLIC` (function, line 2363) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
  - `CJSON_PUBLIC` (function, line 2413) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
  - `replace_item_in_object` (function, line 2423) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
  - `CJSON_PUBLIC` (function, line 2446) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
  - `CJSON_PUBLIC` (function, line 2451) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
  - `CJSON_PUBLIC` (function, line 2468) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
  - `CJSON_PUBLIC` (function, line 2479) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
  - `CJSON_PUBLIC` (function, line 2490) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
  - `CJSON_PUBLIC` (function, line 2501) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
  - `CJSON_PUBLIC` (function, line 2526) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
  - `CJSON_PUBLIC` (function, line 2543) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
  - `CJSON_PUBLIC` (function, line 2555) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2567) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
  - `CJSON_PUBLIC` (function, line 2579) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
  - `CJSON_PUBLIC` (function, line 2596) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
  - `CJSON_PUBLIC` (function, line 2607) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
  - `CJSON_PUBLIC` (function, line 2659) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2699) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
  - `CJSON_PUBLIC` (function, line 2739) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
  - `cJSON_Duplicate_rec` (function, line 2786) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
  - `skip_oneline_comment` (function, line 2873) `static void skip_oneline_comment(char **input)`
  - `skip_multiline_comment` (function, line 2886) `static void skip_multiline_comment(char **input)`
  - `minify_string` (function, line 2900) `static void minify_string(char **input, char **output)`
  - `CJSON_PUBLIC` (function, line 2922) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
  - `CJSON_PUBLIC` (function, line 2972) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2982) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 2992) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3002) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3012) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3022) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3032) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3042) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3052) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3062) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
  - `CJSON_PUBLIC` (function, line 3072) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
  - `cJSON_ArrayForEach` (function, line 3157) `cJSON_ArrayForEach(a_element, a)`
  - `cJSON_ArrayForEach` (function, line 3173) `cJSON_ArrayForEach(b_element, b)`
  - `CJSON_PUBLIC` (function, line 3194) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
  - `CJSON_PUBLIC` (function, line 3199) `CJSON_PUBLIC(void) cJSON_free(void *object)`
  - `_CRT_SECURE_NO_DEPRECATE` (macro, line 28) `#define _CRT_SECURE_NO_DEPRECATE`
  - `true` (macro, line 65) `#define true`
  - `false` (macro, line 70) `#define false`
  - `isinf` (macro, line 74) `#define isinf(d)`
  - `isnan` (macro, line 77) `#define isnan(d)`
  - `NAN` (macro, line 82) `#define NAN`
  - `NAN` (macro, line 84) `#define NAN`
  - `internal_malloc` (macro, line 179) `#define internal_malloc`
  - `internal_free` (macro, line 180) `#define internal_free`
  - `internal_realloc` (macro, line 181) `#define internal_realloc`
  - `static_strlen` (macro, line 185) `#define static_strlen(string_literal)`
  - `can_read` (macro, line 301) `#define can_read(buffer, size)`
  - `can_access_at_index` (macro, line 303) `#define can_access_at_index(buffer, index)`
  - `cannot_access_at_index` (macro, line 304) `#define cannot_access_at_index(buffer, index)`
  - `buffer_at_offset` (macro, line 306) `#define buffer_at_offset(buffer)`
  - `cjson_min` (macro, line 1241) `#define cjson_min(a, b)`
- Depends on: `cJSON.h`

## cJSON.h
- Layer: utility
- Language: h
- Symbols:
  - `cJSON` (struct, line 92)
  - `cJSON_Hooks` (struct, line 114)
  - `cJSON_bool` (type_alias, line 120) `typedef int cJSON_bool;`
  - `sensitive` (function, line 249) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
  - `next` (variable, line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for windows,`
  - `cJSON__h` (macro, line 24) `#define cJSON__h`
  - `__WINDOWS__` (macro, line 32) `#define __WINDOWS__`
  - `CJSON_CDECL` (macro, line 44) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 45) `#define CJSON_STDCALL`
  - `CJSON_EXPORT_SYMBOLS` (macro, line 49) `#define CJSON_EXPORT_SYMBOLS`
  - `CJSON_PUBLIC` (macro, line 53) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 55) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 57) `#define CJSON_PUBLIC(type)`
  - `CJSON_CDECL` (macro, line 60) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 61) `#define CJSON_STDCALL`
  - `CJSON_PUBLIC` (macro, line 64) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 66) `#define CJSON_PUBLIC(type)`
  - `CJSON_VERSION_MAJOR` (macro, line 71) `#define CJSON_VERSION_MAJOR`
  - `CJSON_VERSION_MINOR` (macro, line 72) `#define CJSON_VERSION_MINOR`
  - `CJSON_VERSION_PATCH` (macro, line 73) `#define CJSON_VERSION_PATCH`
  - `cJSON_Invalid` (macro, line 78) `#define cJSON_Invalid`
  - `cJSON_False` (macro, line 79) `#define cJSON_False`
  - `cJSON_True` (macro, line 80) `#define cJSON_True`
  - `cJSON_NULL` (macro, line 81) `#define cJSON_NULL`
  - `cJSON_Number` (macro, line 82) `#define cJSON_Number`
  - `cJSON_String` (macro, line 83) `#define cJSON_String`
  - `cJSON_Array` (macro, line 84) `#define cJSON_Array`
  - `cJSON_Object` (macro, line 85) `#define cJSON_Object`
  - `cJSON_Raw` (macro, line 86) `#define cJSON_Raw`
  - `cJSON_IsReference` (macro, line 88) `#define cJSON_IsReference`
  - `cJSON_StringIsConst` (macro, line 89) `#define cJSON_StringIsConst`
  - `CJSON_NESTING_LIMIT` (macro, line 126) `#define CJSON_NESTING_LIMIT`
  - `CJSON_CIRCULAR_LIMIT` (macro, line 132) `#define CJSON_CIRCULAR_LIMIT`
  - `cJSON_SetIntValue` (macro, line 270) `#define cJSON_SetIntValue(object, number)`
  - `cJSON_SetNumberValue` (macro, line 273) `#define cJSON_SetNumberValue(object, number)`
  - `cJSON_SetBoolValue` (macro, line 278) `#define cJSON_SetBoolValue(object, boolValue)`
  - `cJSON_ArrayForEach` (macro, line 285) `#define cJSON_ArrayForEach(element, array)`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `cJSON.c`, `gopher_beacon.c`

## gopher_beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 47)
  - `Trampoline` (struct, line 54)
  - `SymbolResolver` (struct, line 62)
  - `TrampolineCache` (struct, line 68)
  - `__attribute__` (function, line 137) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 190) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 203) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 214) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 250) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 266) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 297) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `gopher_request` (function, line 314) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
  - `base64_encode` (function, line 377) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 394) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 417) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 445) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 475) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 506) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 512) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 893) `char* get_local_ips()`
  - `download_bof` (function, line 922) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
  - `run_bof_and_capture` (function, line 950) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 994) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2` (macro, line 30) `#define C2`
  - `CLIENT_ID` (macro, line 31) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 32) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 33) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

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
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64)  Tipos
- Language: c
- Symbols:
  - `size_t` (type_alias, line 6) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 7) `typedef long ssize_t;`
  - `syscall3` (function, line 22) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 32) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 43) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 52) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 108) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 10) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 11) `extern void BeaconOutput(int, const char*, int);`
  - `NULL` (macro, line 2) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 3) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 14) `#define SYS_openat`
  - `SYS_read` (macro, line 15) `#define SYS_read`
  - `SYS_close` (macro, line 16) `#define SYS_close`
  - `SYS_getuid` (macro, line 17) `#define SYS_getuid`
  - `SYS_getpwuid_r` (macro, line 18) `#define SYS_getpwuid_r`
  - `AT_FDCWD` (macro, line 19) `#define AT_FDCWD`
