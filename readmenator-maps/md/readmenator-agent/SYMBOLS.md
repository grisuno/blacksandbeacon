# Symbols (page 1 of 4)
Pages: [SYMBOLS.md](SYMBOLS.md), [SYMBOLS_p2.md](SYMBOLS_p2.md), [SYMBOLS_p3.md](SYMBOLS_p3.md), [SYMBOLS_p4.md](SYMBOLS_p4.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_CBC_decrypt_buffer` | function | `aes.c:552` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:537` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:572` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:518` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ECB_encrypt` | function | `aes.c:512` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ctx_set_iv` | function | `aes.c:264` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)` |
| `AES_init_ctx` | function | `aes.c:254` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)` |
| `AES_init_ctx_iv` | function | `aes.c:259` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` |
| `AddRoundKey` | function | `aes.c:272` | `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:9` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:455` | `static void Cipher(state_t *state, const uint8_t *RoundKey)` |
| `InvCipher` | function | `aes.c:482` | `static void InvCipher(state_t *state, const uint8_t *RoundKey)` |
| `InvMixColumns` | function | `aes.c:389` | `static void InvMixColumns(state_t *state)` |
| `InvShiftRows` | function | `aes.c:425` | `static void InvShiftRows(state_t *state)` |
| `InvSubBytes` | function | `aes.c:413` | `static void InvSubBytes(state_t *state)` |
| `KEYLEN_256` | macro | `aes.c:7` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:181` | `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:101` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:335` | `static void MixColumns(state_t *state)` |
| `Multiply` | function | `aes.c:363` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:371` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:5` | `#define Nb` |
| `Nb` | macro | `aes.c:84` | `#define Nb` |
| `Nk` | macro | `aes.c:87` | `#define Nk` |
| `Nk` | macro | `aes.c:90` | `#define Nk` |
| `Nk` | macro | `aes.c:93` | `#define Nk` |
| `Nr` | macro | `aes.c:88` | `#define Nr` |
| `Nr` | macro | `aes.c:91` | `#define Nr` |
| `Nr` | macro | `aes.c:94` | `#define Nr` |
| `RKLENGTH` | macro | `aes.c:8` | `#define RKLENGTH` |
| `ShiftRows` | function | `aes.c:301` | `static void ShiftRows(state_t *state)` |
| `SubBytes` | function | `aes.c:286` | `static void SubBytes(state_t *state)` |
| `Td0` | function | `aes.c:59` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:63` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:67` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:71` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:75` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:528` | `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)` |
| `getSBoxInvert` | function | `aes.c:35` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:384` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:11` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:177` | `#define getSBoxValue(num)` |
| `xtime` | function | `aes.c:329` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:18` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:20` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_ECB_decrypt` | function | `aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_ECB_encrypt` | function | `aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_KEYLEN` | macro | `aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);` |
| `AES_init_ctx` | function | `aes.h:41` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);` |
| `AES_init_ctx_iv` | function | `aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` |
| `AES_keyExpSize` | macro | `aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `aes.h:9` | `#define CBC` |
| `CTR` | macro | `aes.h:15` | `#define CTR` |
| `ECB` | macro | `aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `aes.h:2` | `#define _AES_H_` |
| `BEACON_API_H` | macro | `beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `beacon.h:27` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `beacon.h:24` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `beacon.h:26` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `beacon.h:22` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `beacon.h:23` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `beacon.h:25` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `beacon.h:29` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `beacon.h:28` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `beacon.h:14` | `` |
| `BeaconOutput` | function | `beacon3.c:213` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon3.c:196` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon3.c:33` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon3.c:34` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon3.c:35` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon3.c:52` | `` |
| `RunELF` | function | `beacon3.c:584` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacon3.c:69` | `` |
| `Trampoline` | struct | `beacon3.c:60` | `` |
| `TrampolineCache` | struct | `beacon3.c:76` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon3.c:36` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon3.c:324` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon3.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon3.c:145` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `beacon3.c:514` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon3.c:480` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `beacon3.c:454` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `beacon3.c:436` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `beacon3.c:268` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon3.c:227` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `beacon3.c:1118` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `beacon3.c:550` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacon3.c:1083` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon3.c:286` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `beacon3.c:342` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `beacon3.c:1187` | `int main()` |
| `page_align` | function | `beacon3.c:576` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `beacon3.c:1141` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BeaconOutput` | function | `beacon5.c:256` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon5.c:239` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon5.c:42` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon5.c:43` | `#define CLIENT_ID` |
| `DISCOVERY_INTERVAL` | macro | `beacon5.c:38` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacon5.c:37` | `#define DISCOVERY_PORT` |
| `MALEABLE` | macro | `beacon5.c:44` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon5.c:36` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacon5.c:39` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacon5.c:40` | `#define MESH_MSG_SIZE` |
| `MemoryStruct` | struct | `beacon5.c:61` | `` |
| `RunELF` | function | `beacon5.c:627` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacon5.c:111` | `` |
| `Trampoline` | struct | `beacon5.c:102` | `` |
| `TrampolineCache` | struct | `beacon5.c:118` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon5.c:45` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon5.c:367` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon5.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon5.c:188` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `beacon5.c:557` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon5.c:523` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `beacon5.c:497` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `beacon5.c:479` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `beacon5.c:311` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon5.c:270` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `beacon5.c:1161` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `beacon5.c:593` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacon5.c:1126` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon5.c:329` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `beacon5.c:385` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `beacon5.c:1702` | `int main(int argc, char **argv)` |
| `mesh_add_peer` | function | `beacon5.c:1255` | `void mesh_add_peer(const char *ip, int port)` |
| `mesh_cleanup_peers` | function | `beacon5.c:1283` | `void mesh_cleanup_peers()` |
| `mesh_discovery_thread` | function | `beacon5.c:1356` | `void *mesh_discovery_thread(void *arg)` |
| `mesh_is_seen` | function | `beacon5.c:1240` | `int mesh_is_seen(const char *msg_id)` |
| `mesh_listener_thread` | function | `beacon5.c:1447` | `void *mesh_listener_thread(void *arg)` |
| `mesh_mark_seen` | function | `beacon5.c:1231` | `void mesh_mark_seen(const char *msg_id)` |
| `mesh_msg_t` | struct | `beacon5.c:77` | `` |
| `mesh_propagate` | function | `beacon5.c:1324` | `void mesh_propagate(const char *command)` |
| `mesh_send_message` | function | `beacon5.c:1667` | `void mesh_send_message(int type, const char *target, const char *payload)` |
| `mesh_send_to_peer` | function | `beacon5.c:1300` | `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)` |
| `page_align` | function | `beacon5.c:619` | `static size_t page_align(size_t size)` |
| `peer_t` | struct | `beacon5.c:69` | `` |
| `run_bof_and_capture` | function | `beacon5.c:1184` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BeaconOutput` | function | `beacon6.c:283` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon6.c:266` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon6.c:34` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon6.c:35` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon6.c:36` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon6.c:53` | `` |
| `RunELF` | function | `beacon6.c:654` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacon6.c:70` | `` |
| `Trampoline` | struct | `beacon6.c:61` | `` |
| `TrampolineCache` | struct | `beacon6.c:77` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon6.c:37` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon6.c:394` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon6.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon6.c:146` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `beacon6.c:584` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon6.c:550` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `beacon6.c:524` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `beacon6.c:506` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `beacon6.c:338` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon6.c:297` | `static void *create_trampoline(void *target)` |
| `delay_ms` | function | `beacon6.c:197` | `static void delay_ms(int ms)` |
| `download_bof` | function | `beacon6.c:1188` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `beacon6.c:620` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacon6.c:1153` | `char *get_local_ips()` |
| `get_nth_prime_limited` | function | `beacon6.c:224` | `static unsigned int get_nth_prime_limited(unsigned int n)` |
| `get_or_create_trampoline` | function | `beacon6.c:356` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `beacon6.c:412` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `is_prime` | function | `beacon6.c:204` | `static unsigned int is_prime(unsigned int x)` |
| `main` | function | `beacon6.c:1257` | `int main()` |
| `page_align` | function | `beacon6.c:646` | `static size_t page_align(size_t size)` |
| `portable_rand_19k_29k` | function | `beacon6.c:253` | `static unsigned int portable_rand_19k_29k(void)` |
| `run_bof_and_capture` | function | `beacon6.c:1211` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BROADCAST_INTERVAL` | macro | `beacon_p2p.c:46` | `#define BROADCAST_INTERVAL` |
| `BeaconDataExtract` | function | `beacon_p2p.c:131` | `char *BeaconDataExtract(datap *parser, int *size)` |
| `BeaconDataInt` | function | `beacon_p2p.c:110` | `int BeaconDataInt(datap *parser)` |
| `BeaconDataLength` | function | `beacon_p2p.c:126` | `int BeaconDataLength(datap *parser)` |
| `BeaconDataParse` | function | `beacon_p2p.c:93` | `void BeaconDataParse(datap *parser, char *buffer, int size)` |
| `BeaconDataPtr` | function | `beacon_p2p.c:100` | `char *BeaconDataPtr(datap *parser, int size)` |
| `BeaconDataShort` | function | `beacon_p2p.c:118` | `short BeaconDataShort(datap *parser)` |
| `BeaconOutput` | function | `beacon_p2p.c:159` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon_p2p.c:142` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon_p2p.c:37` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon_p2p.c:38` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon_p2p.c:39` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon_p2p.c:47` | `#define MAX_PEERS` |
| `MemoryStruct` | struct | `beacon_p2p.c:676` | `` |
| `PEER_DISCOVERY_PORT` | macro | `beacon_p2p.c:42` | `#define PEER_DISCOVERY_PORT` |
| `PEER_MAGIC` | macro | `beacon_p2p.c:44` | `#define PEER_MAGIC` |
| `PEER_TCP_PORT` | macro | `beacon_p2p.c:43` | `#define PEER_TCP_PORT` |
| `PEER_VERSION` | macro | `beacon_p2p.c:45` | `#define PEER_VERSION` |
| `RunELF` | function | `beacon_p2p.c:358` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacon_p2p.c:182` | `` |
| `Trampoline` | struct | `beacon_p2p.c:175` | `` |
| `TrampolineCache` | struct | `beacon_p2p.c:192` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon_p2p.c:40` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon_p2p.c:683` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon_p2p.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon_p2p.c:250` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `add_peer` | function | `beacon_p2p.c:965` | `void add_peer(struct in_addr ip, int port, const char *id)` |
| `aes256_cfb_decrypt` | function | `beacon_p2p.c:832` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon_p2p.c:802` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `beacon_p2p.c:780` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `beacon_p2p.c:763` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `beacon_p2p.c:309` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon_p2p.c:278` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `beacon_p2p.c:925` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `beacon_p2p.c:866` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `execute_generic_command` | function | `beacon_p2p.c:1231` | `char *execute_generic_command(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacon_p2p.c:891` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon_p2p.c:323` | `static void *get_or_create_trampoline(void *target)` |
| `handle_peer_connection` | function | `beacon_p2p.c:1032` | `void *handle_peer_connection(void *arg)` |
| `https_request` | function | `beacon_p2p.c:707` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `beacon_p2p.c:1276` | `int main()` |
| `p2p_header_t` | struct | `beacon_p2p.c:73` | `` |
| `page_align` | function | `beacon_p2p.c:350` | `static size_t page_align(size_t size)` |
| `peer_discovery_thread` | function | `beacon_p2p.c:992` | `void *peer_discovery_thread(void *arg)` |
| `peer_server_thread` | function | `beacon_p2p.c:1130` | `void *peer_server_thread(void *arg)` |
| `peer_t` | struct | `beacon_p2p.c:59` | `` |
| `run_bof_and_capture` | function | `beacon_p2p.c:939` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `send_to_c2_or_peer` | function | `beacon_p2p.c:1197` | `char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)` |
| `send_to_peer` | function | `beacon_p2p.c:1153` | `char *send_to_peer(peer_t *peer, const char *data, int *out_len)` |
| `_GNU_SOURCE` | macro | `beacons/v1/beacon.c:13` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v1/beacon.c:104` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v1/beacon.c:167` | `int main(void)` |
| `report_result` | function | `beacons/v1/beacon.c:24` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `BeaconOutput` | function | `beacons/v1/gopher_beacon.c:210` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacons/v1/gopher_beacon.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `beacons/v1/gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `beacons/v1/gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacons/v1/gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacons/v1/gopher_beacon.c:49` | `` |
| `RunELF` | function | `beacons/v1/gopher_beacon.c:581` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacons/v1/gopher_beacon.c:66` | `` |
| `Trampoline` | struct | `beacons/v1/gopher_beacon.c:57` | `` |
| `TrampolineCache` | struct | `beacons/v1/gopher_beacon.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `beacons/v1/gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacons/v1/gopher_beacon.c:321` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacons/v1/gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacons/v1/gopher_beacon.c:142` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `beacons/v1/gopher_beacon.c:500` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacons/v1/gopher_beacon.c:466` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `beacons/v1/gopher_beacon.c:440` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `beacons/v1/gopher_beacon.c:422` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `beacons/v1/gopher_beacon.c:265` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacons/v1/gopher_beacon.c:224` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `beacons/v1/gopher_beacon.c:1115` | `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` |
| `exec_cmd` | function | `beacons/v1/gopher_beacon.c:536` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacons/v1/gopher_beacon.c:1080` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `beacons/v1/gopher_beacon.c:283` | `static void *get_or_create_trampoline(void *target)` |
| `gopher_request` | function | `beacons/v1/gopher_beacon.c:339` | `char *gopher_request(const char *host, int port, const char *selector, const char *method,       ...` |
| `main` | function | `beacons/v1/gopher_beacon.c:1193` | `int main()` |
| `page_align` | function | `beacons/v1/gopher_beacon.c:573` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `beacons/v1/gopher_beacon.c:1147` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `DISCOVERY_INTERVAL` | macro | `beacons/v2/beacon.c:29` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacons/v2/beacon.c:28` | `#define DISCOVERY_PORT` |
| `MAX_PEERS` | macro | `beacons/v2/beacon.c:27` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacons/v2/beacon.c:30` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacons/v2/beacon.c:31` | `#define MESH_MSG_SIZE` |
| `_GNU_SOURCE` | macro | `beacons/v2/beacon.c:12` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v2/beacon.c:149` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v2/beacon.c:212` | `int main(void)` |
| `mesh_msg_t` | struct | `beacons/v2/beacon.c:41` | `` |
| `peer_t` | struct | `beacons/v2/beacon.c:33` | `` |
| `report_result` | function | `beacons/v2/beacon.c:69` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `_GNU_SOURCE` | macro | `beacons/v3/beacon.c:12` | `#define _GNU_SOURCE` |
| `compute_primes` | function | `beacons/v3/beacon.c:42` | `static int compute_primes(int count)` |
| `evasive_sleep` | function | `beacons/v3/beacon.c:55` | `static void evasive_sleep(int seconds)` |
| `execute_command` | function | `beacons/v3/beacon.c:142` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `infrastructure` | function | `beacons/v3/beacon.c:8` | `*  * All shared infrastructure (HTTP client, crypto, BOF loader)  * lives in beacon_common.c. Thi...` |
| `main` | function | `beacons/v3/beacon.c:205` | `int main(void)` |
| `report_result` | function | `beacons/v3/beacon.c:62` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `__attribute__` | function | `bof.c:4` | `__attribute__((used)) __attribute__((visibility("default"))) void go(char *args, int alen)` |
| `go` | function | `bof/cat/bof.c:15` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/cat/cat.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/cat/cat.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/cat/cat.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/cat/cat.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/cat/cat.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/cat/cat.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/cat/cat.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/cat/cat.c:16` | `#define SYS_read` |
| `go` | function | `bof/cat/cat.c:31` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/cat/cat.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/cat/cat.c:8` | `typedef long ssize_t;` |
| `syscall3` | function | `bof/cat/cat.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `BSB_BOF_BEACON_API_H` | macro | `bof/include/beacon_api.h:17` | `#define BSB_BOF_BEACON_API_H` |
| `BeaconDataExtract` | function | `bof/include/beacon_api.h:42` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `bof/include/beacon_api.h:39` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `bof/include/beacon_api.h:41` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `bof/include/beacon_api.h:37` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `bof/include/beacon_api.h:38` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `bof/include/beacon_api.h:40` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `bof/include/beacon_api.h:48` | `void BeaconOutput(int type, const char *data, int len);` |
| `CALLBACK_ERROR` | macro | `bof/include/beacon_api.h:25` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/include/beacon_api.h:24` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `bof/include/beacon_api.h:26` | `#define CALLBACK_OUTPUT_OEM` |
| `buffer` | function | `bof/include/beacon_api.h:45` | `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */...` |
| `datap` | struct | `bof/include/beacon_api.h:30` | `` |
| `go` | function | `bof/include/beacon_api.h:10` | `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);` |
| `AT_FDCWD` | macro | `bof/include/syscalls.h:47` | `#define AT_FDCWD` |
| `BSB_BOF_SYSCALLS_H` | macro | `bof/include/syscalls.h:12` | `#define BSB_BOF_SYSCALLS_H` |
| `SYS_access` | macro | `bof/include/syscalls.h:28` | `#define SYS_access` |
| `SYS_brk` | macro | `bof/include/syscalls.h:26` | `#define SYS_brk` |
| `SYS_clone` | macro | `bof/include/syscalls.h:44` | `#define SYS_clone` |
| `SYS_close` | macro | `bof/include/syscalls.h:20` | `#define SYS_close` |
| `SYS_dup2` | macro | `bof/include/syscalls.h:30` | `#define SYS_dup2` |
| `SYS_execve` | macro | `bof/include/syscalls.h:32` | `#define SYS_execve` |
| `SYS_exit` | macro | `bof/include/syscalls.h:33` | `#define SYS_exit` |
| `SYS_fork` | macro | `bof/include/syscalls.h:31` | `#define SYS_fork` |
| `SYS_fstat` | macro | `bof/include/syscalls.h:22` | `#define SYS_fstat` |
| `SYS_getegid` | macro | `bof/include/syscalls.h:38` | `#define SYS_getegid` |
| `SYS_geteuid` | macro | `bof/include/syscalls.h:37` | `#define SYS_geteuid` |
| `SYS_getgid` | macro | `bof/include/syscalls.h:36` | `#define SYS_getgid` |
| `SYS_getpid` | macro | `bof/include/syscalls.h:39` | `#define SYS_getpid` |
| `SYS_getppid` | macro | `bof/include/syscalls.h:40` | `#define SYS_getppid` |
| `SYS_getpwnam_r` | macro | `bof/include/syscalls.h:41` | `#define SYS_getpwnam_r` |
| `SYS_getpwuid_r` | macro | `bof/include/syscalls.h:42` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `bof/include/syscalls.h:35` | `#define SYS_getuid` |
| `SYS_ioctl` | macro | `bof/include/syscalls.h:27` | `#define SYS_ioctl` |
| `SYS_lseek` | macro | `bof/include/syscalls.h:23` | `#define SYS_lseek` |
| `SYS_mmap` | macro | `bof/include/syscalls.h:24` | `#define SYS_mmap` |
| `SYS_munmap` | macro | `bof/include/syscalls.h:25` | `#define SYS_munmap` |
| `SYS_open` | macro | `bof/include/syscalls.h:19` | `#define SYS_open` |
| `SYS_openat` | macro | `bof/include/syscalls.h:43` | `#define SYS_openat` |
| `SYS_pipe` | macro | `bof/include/syscalls.h:29` | `#define SYS_pipe` |
| `SYS_read` | macro | `bof/include/syscalls.h:17` | `#define SYS_read` |
| `SYS_stat` | macro | `bof/include/syscalls.h:21` | `#define SYS_stat` |
| `SYS_wait4` | macro | `bof/include/syscalls.h:34` | `#define SYS_wait4` |
| `SYS_write` | macro | `bof/include/syscalls.h:18` | `#define SYS_write` |
| `bsf_memcmp` | function | `bof/include/syscalls.h:112` | `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` |
| `bsf_strcmp` | function | `bof/include/syscalls.h:101` | `static inline int bsf_strcmp(const char *a, const char *b)` |
| `bsf_strlen` | function | `bof/include/syscalls.h:92` | `static inline size_t bsf_strlen(const char *s)` |
| `syscall0` | function | `bof/include/syscalls.h:49` | `static inline long syscall0(long n)` |
| `syscall1` | function | `bof/include/syscalls.h:56` | `static inline long syscall1(long n, long a1)` |
| `syscall2` | function | `bof/include/syscalls.h:63` | `static inline long syscall2(long n, long a1, long a2)` |
| `syscall3` | function | `bof/include/syscalls.h:70` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `syscall4` | function | `bof/include/syscalls.h:80` | `static inline long syscall4(long n, long a1, long a2, long a3, long a4)` |
| `go` | function | `bof/is_sudo/bof.c:74` | `void go(char *args, int alen)` |
| `user_in_group` | function | `bof/is_sudo/bof.c:15` | `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)` |
| `AT_FDCWD` | macro | `bof/is_sudo/is_sudo.c:20` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/is_sudo/is_sudo.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/is_sudo/is_sudo.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/is_sudo/is_sudo.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/is_sudo/is_sudo.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/is_sudo/is_sudo.c:17` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `bof/is_sudo/is_sudo.c:19` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `bof/is_sudo/is_sudo.c:18` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/is_sudo/is_sudo.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/is_sudo/is_sudo.c:16` | `#define SYS_read` |
| `get_username_from_uid` | function | `bof/is_sudo/is_sudo.c:52` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `bof/is_sudo/is_sudo.c:122` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/is_sudo/is_sudo.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/is_sudo/is_sudo.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/is_sudo/is_sudo.c:41` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `bof/is_sudo/is_sudo.c:33` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/is_sudo/is_sudo.c:23` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `DT_DIR` | macro | `bof/suid_enum/bof.c:31` | `#define DT_DIR` |
| `DT_LNK` | macro | `bof/suid_enum/bof.c:32` | `#define DT_LNK` |
| `DT_UNKNOWN` | macro | `bof/suid_enum/bof.c:30` | `#define DT_UNKNOWN` |
| `SYS_getdents64` | macro | `bof/suid_enum/bof.c:26` | `#define SYS_getdents64` |
| `SYS_lstat` | macro | `bof/suid_enum/bof.c:27` | `#define SYS_lstat` |
| `emit` | function | `bof/suid_enum/bof.c:87` | `static void emit(const char *s)` |
| `flush_output` | function | `bof/suid_enum/bof.c:78` | `static void flush_output(void)` |
| `format_mode` | function | `bof/suid_enum/bof.c:114` | `static void format_mode(unsigned int mode, char *out)` |
| `go` | function | `bof/suid_enum/bof.c:298` | `void go(char *args, int alen)` |
| `linux_dirent64` | struct | `bof/suid_enum/bof.c:59` | `` |
| `linux_stat` | struct | `bof/suid_enum/bof.c:35` | `` |
| `path_append` | function | `bof/suid_enum/bof.c:148` | `static void path_append(const char *name)` |
| `path_reset` | function | `bof/suid_enum/bof.c:137` | `static void path_reset(const char *root)` |
| `path_trim_to` | function | `bof/suid_enum/bof.c:166` | `static void path_trim_to(int len)` |
| `walk` | function | `bof/suid_enum/bof.c:178` | `static void walk(int depth)` |
| `go` | function | `bof/userenum/bof.c:89` | `void go(char *args, int alen)` |
| `user_in_member_list` | function | `bof/userenum/bof.c:67` | `static int user_in_member_list(const char *username, const char *members)` |
| `AT_FDCWD` | macro | `bof/userenum/userenum.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/userenum/userenum.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/userenum/userenum.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/userenum/userenum.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/userenum/userenum.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/userenum/userenum.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/userenum/userenum.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/userenum/userenum.c:16` | `#define SYS_read` |
| `go` | function | `bof/userenum/userenum.c:42` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/userenum/userenum.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/userenum/userenum.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/userenum/userenum.c:32` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall3` | function | `bof/userenum/userenum.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `go` | function | `bof/whoami/bof.c:19` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/whoami/whoami.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/whoami/whoami.c:11` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/whoami/whoami.c:10` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/whoami/whoami.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/whoami/whoami.c:2` | `#define NULL` |
| `SYS_close` | macro | `bof/whoami/whoami.c:16` | `#define SYS_close` |
| `SYS_getuid` | macro | `bof/whoami/whoami.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/whoami/whoami.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/whoami/whoami.c:15` | `#define SYS_read` |
| `go` | function | `bof/whoami/whoami.c:38` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/whoami/whoami.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/whoami/whoami.c:7` | `typedef long ssize_t;` |
| `syscall1` | function | `bof/whoami/whoami.c:31` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/whoami/whoami.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `C2State` | class | `c2/server.py:271` | `class C2State` |
| `__init__` | method | `c2/server.py:274` | `def __init__(self, cfg)` |
| `_http_response` | function | `c2/server.py:555` | `def _http_response(body, status)` |
| `_is_http_line` | function | `c2/server.py:490` | `def _is_http_line(line)` |
| `_is_http_request` | function | `c2/server.py:496` | `def _is_http_request(raw)` |
| `_read_request` | function | `c2/server.py:507` | `def _read_request(conn)` |
| `command_injector` | function | `c2/server.py:619` | `def command_injector(state)` |
| `compute_hmac` | function | `c2/server.py:110` | `def compute_hmac(key, data)` |
| `decrypt_data` | function | `c2/server.py:178` | `def decrypt_data(b64_data, key, hmac_key, use_hmac)` |
| `decrypt_data_replay` | function | `c2/server.py:201` | `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds, last_seen_counter, client_id)` |
| `encrypt_data` | function | `c2/server.py:121` | `def encrypt_data(data, key, hmac_key, use_hmac)` |
| `encrypt_data_replay` | function | `c2/server.py:144` | `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)` |
| `handle_bof` | function | `c2/server.py:401` | `def handle_bof(state, name)` |
| `handle_get_command` | function | `c2/server.py:287` | `def handle_get_command(state, selector)` |
| `handle_report` | function | `c2/server.py:311` | `def handle_report(state, b64_payload)` |
| `handle_request` | function | `c2/server.py:439` | `def handle_request(state, selector)` |
| `load_runtime_config` | function | `c2/server.py:62` | `def load_runtime_config()` |
| `main` | function | `c2/server.py:642` | `def main()` |
| `serve` | function | `c2/server.py:595` | `def serve(cfg, state)` |
| `serve_client` | function | `c2/server.py:567` | `def serve_client(state, conn, addr)` |
| `verify_hmac` | function | `c2/server.py:115` | `def verify_hmac(key, data, signature)` |
| `CJSON_PUBLIC` | function | `cJSON.c:96` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:101` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:111` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:126` | `CJSON_PUBLIC(const char *) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:211` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1143` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end,      ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1251` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1333` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1338` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1369` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1956` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2003` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2008` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2014` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2143` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2154` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2164` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2176` | `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2188` | `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2200` | `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2212` | `CJSON_PUBLIC(cJSON *) cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2225` | `CJSON_PUBLIC(cJSON *) cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2238` | `CJSON_PUBLIC(cJSON *) cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2264` | `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2276` | `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2288` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2324` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2334` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2339` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2346` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2353` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2358` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2400` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2486` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2492` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2510` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2521` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2532` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2568` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2585` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2597` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2609` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2621` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2638` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2649` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2702` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2743` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2784` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2977` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3027` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3037` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3047` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3057` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3067` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3077` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3087` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3097` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3107` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3117` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)` |

Next: [SYMBOLS_p2.md](SYMBOLS_p2.md)
