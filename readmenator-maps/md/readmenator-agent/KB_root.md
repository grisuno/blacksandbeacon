# Subsystem: root (page 1 of 2)
Pages: [KB_root.md](KB_root.md), [KB_root_p2.md](KB_root_p2.md)

## aes.c
- Doc: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Layer: utility
- Language: c
- Symbols:
  - `getSBoxValue` (function, line 11) `static uint8_t getSBoxValue(uint8_t num)`
  - `getSBoxInvert` (function, line 35) `static uint8_t getSBoxInvert(uint8_t num)`
  - `Td0` (function, line 59) `static uint8_t Td0(int x)`
  - `Td1` (function, line 63) `static uint8_t Td1(int x)`
  - `Td2` (function, line 67) `static uint8_t Td2(int x)`
  - `Td3` (function, line 71) `static uint8_t Td3(int x)`
  - `Td4` (function, line 75) `static uint8_t Td4(int x)`
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
- Depends on: `aes.h`

## aes.h
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
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

## app.py
- Doc: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación...
- Layer: utility
- Language: py

## beacon.h
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
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

## beacon3.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 52)
  - `Trampoline` (struct, line 60)
  - `SymbolResolver` (struct, line 69)
  - `TrampolineCache` (struct, line 76)
  - `__attribute__` (function, line 145) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 196) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 213) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 227) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 268) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 286) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 324) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 342) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 436) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 454) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 480) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 514) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 550) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 576) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 584) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1083) `char *get_local_ips()`
  - `download_bof` (function, line 1118) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1141) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1187) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 33) `#define C2_URL`
  - `CLIENT_ID` (macro, line 34) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 35) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 36) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon5.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 61)
  - `peer_t` (struct, line 69)
  - `mesh_msg_t` (struct, line 77)
  - `Trampoline` (struct, line 102)
  - `SymbolResolver` (struct, line 111)
  - `TrampolineCache` (struct, line 118)
  - `__attribute__` (function, line 188) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 239) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 256) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 270) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 311) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 329) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 367) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 385) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 479) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 497) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 523) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 557) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 593) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 619) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 627) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1126) `char *get_local_ips()`
  - `download_bof` (function, line 1161) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1184) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `mesh_mark_seen` (function, line 1231) `void mesh_mark_seen(const char *msg_id)`
  - `mesh_is_seen` (function, line 1240) `int mesh_is_seen(const char *msg_id)`
  - `mesh_add_peer` (function, line 1255) `void mesh_add_peer(const char *ip, int port)`
  - `mesh_cleanup_peers` (function, line 1283) `void mesh_cleanup_peers()`
  - `mesh_send_to_peer` (function, line 1300) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
  - `mesh_propagate` (function, line 1324) `void mesh_propagate(const char *command)`
  - `mesh_discovery_thread` (function, line 1356) `void *mesh_discovery_thread(void *arg)`
  - `mesh_listener_thread` (function, line 1447) `void *mesh_listener_thread(void *arg)`
  - `mesh_send_message` (function, line 1667) `void mesh_send_message(int type, const char *target, const char *payload)`
  - `main` (function, line 1702) `int main(int argc, char **argv)`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 36) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 37) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 38) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 39) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 40) `#define MESH_MSG_SIZE`
  - `C2_URL` (macro, line 42) `#define C2_URL`
  - `CLIENT_ID` (macro, line 43) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 44) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 45) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon6.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 53)
  - `Trampoline` (struct, line 61)
  - `SymbolResolver` (struct, line 70)
  - `TrampolineCache` (struct, line 77)
  - `__attribute__` (function, line 146) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `delay_ms` (function, line 197) `static void delay_ms(int ms)`
  - `is_prime` (function, line 204) `static unsigned int is_prime(unsigned int x)`
  - `get_nth_prime_limited` (function, line 224) `static unsigned int get_nth_prime_limited(unsigned int n)`
  - `portable_rand_19k_29k` (function, line 253) `static unsigned int portable_rand_19k_29k(void)`
  - `BeaconPrintf` (function, line 266) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 283) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 297) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 338) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 356) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 394) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 412) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 506) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 524) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 550) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 584) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 620) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 646) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 654) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1153) `char *get_local_ips()`
  - `download_bof` (function, line 1188) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1211) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1257) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 34) `#define C2_URL`
  - `CLIENT_ID` (macro, line 35) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 36) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 37) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon_p2p.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 676)
  - `peer_t` (struct, line 59)
  - `p2p_header_t` (struct, line 73)
  - `Trampoline` (struct, line 175)
  - `SymbolResolver` (struct, line 182)
  - `TrampolineCache` (struct, line 192)
  - `BeaconDataParse` (function, line 93) `void BeaconDataParse(datap *parser, char *buffer, int size)`
  - `BeaconDataPtr` (function, line 100) `char *BeaconDataPtr(datap *parser, int size)`
  - `BeaconDataInt` (function, line 110) `int BeaconDataInt(datap *parser)`
  - `BeaconDataShort` (function, line 118) `short BeaconDataShort(datap *parser)`
  - `BeaconDataLength` (function, line 126) `int BeaconDataLength(datap *parser)`
  - `BeaconDataExtract` (function, line 131) `char *BeaconDataExtract(datap *parser, int *size)`
  - `BeaconPrintf` (function, line 142) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 159) `void BeaconOutput(int type, const char *data, int len)`
  - `__attribute__` (function, line 250) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `create_trampoline` (function, line 278) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 309) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 323) `static void *get_or_create_trampoline(void *target)`
  - `page_align` (function, line 350) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 358) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `WriteMemoryCallback` (function, line 683) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 707) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 763) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 780) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 802) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 832) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 866) `char *exec_cmd(const char *cmd, int *out_len)`
  - `get_local_ips` (function, line 891) `char *get_local_ips()`
  - `download_bof` (function, line 925) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 939) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `add_peer` (function, line 965) `void add_peer(struct in_addr ip, int port, const char *id)`
  - `peer_discovery_thread` (function, line 992) `void *peer_discovery_thread(void *arg)`
  - `handle_peer_connection` (function, line 1032) `void *handle_peer_connection(void *arg)`
  - `peer_server_thread` (function, line 1130) `void *peer_server_thread(void *arg)`
  - `send_to_peer` (function, line 1153) `char *send_to_peer(peer_t *peer, const char *data, int *out_len)`
  - `send_to_c2_or_peer` (function, line 1197) `char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
  - `execute_generic_command` (function, line 1231) `char *execute_generic_command(const char *cmd, int *out_len)`
  - `main` (function, line 1276) `int main()`
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
- Language: c
- Symbols:
  - `__attribute__` (function, line 4) `__attribute__((used)) __attribute__((visibility("default"))) void go(char *args, int alen)`
- Depends on: `beacon.h`

## cJSON.c
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
- Depends on: `cJSON.h`


Next: [KB_root_p2.md](KB_root_p2.md)
