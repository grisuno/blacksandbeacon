# Symbols (page 1 of 3)
Pages: [SYMBOLS.md](SYMBOLS.md), [SYMBOLS_p2.md](SYMBOLS_p2.md), [SYMBOLS_p3.md](SYMBOLS_p3.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_CBC_decrypt_buffer` | function | `aes.c:536` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:521` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:496` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `aes.c:490` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `aes.c:239` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `aes.c:403` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `aes.c:9` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:5` | `#define Nb` |
| `Nb` | macro | `aes.c:67` | `#define Nb` |
| `Nk` | macro | `aes.c:70` | `#define Nk` |
| `Nk` | macro | `aes.c:73` | `#define Nk` |
| `Nk` | macro | `aes.c:76` | `#define Nk` |
| `Nr` | macro | `aes.c:71` | `#define Nr` |
| `Nr` | macro | `aes.c:74` | `#define Nr` |
| `Nr` | macro | `aes.c:77` | `#define Nr` |
| `RKLENGTH` | macro | `aes.c:10` | `#define RKLENGTH` |
| `ShiftRows` | function | `aes.c:286` | `static void ShiftRows(state_t* state)` |
| `SubBytes` | function | `aes.c:271` | `static void SubBytes(state_t* state)` |
| `Td0` | function | `aes.c:57` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:58` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:59` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:60` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:61` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:512` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `getSBoxInvert` | function | `aes.c:35` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:13` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:163` | `#define getSBoxValue(num)` |
| `xtime` | function | `aes.c:314` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:18` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:20` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_ECB_decrypt` | function | `aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_ECB_encrypt` | function | `aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_KEYLEN` | macro | `aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);` |
| `AES_init_ctx` | function | `aes.h:41` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
| `AES_init_ctx_iv` | function | `aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` |
| `AES_keyExpSize` | macro | `aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `aes.h:9` | `#define CBC` |
| `CTR` | macro | `aes.h:15` | `#define CTR` |
| `ECB` | macro | `aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `aes.h:2` | `#define _AES_H_` |
| `BEACON_API_H` | macro | `beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `beacon.h:26` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `beacon.h:23` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `beacon.h:25` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `beacon.h:21` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `beacon.h:22` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `beacon.h:24` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `beacon.h:28` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `beacon.h:27` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `beacon.h:14` | `` |
| `BeaconOutput` | function | `beacon3.c:206` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon3.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon3.c:33` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon3.c:34` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon3.c:35` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon3.c:50` | `` |
| `RunELF` | function | `beacon3.c:531` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,             unsi...` |
| `SymbolResolver` | struct | `beacon3.c:65` | `` |
| `Trampoline` | struct | `beacon3.c:57` | `` |
| `TrampolineCache` | struct | `beacon3.c:71` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon3.c:36` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon3.c:300` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon3.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon3.c:140` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon3.c:474` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon3.c:446` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `beacon3.c:423` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon3.c:406` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `beacon3.c:253` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon3.c:217` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `beacon3.c:941` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon3.c:504` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `beacon3.c:912` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon3.c:269` | `static void* get_or_create_trampoline(void* target)` |
| `https_request` | function | `beacon3.c:317` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `main` | function | `beacon3.c:1007` | `int main()` |
| `page_align` | function | `beacon3.c:525` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `beacon3.c:963` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `BeaconOutput` | function | `beacon5.c:248` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon5.c:235` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon5.c:44` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon5.c:45` | `#define CLIENT_ID` |
| `DISCOVERY_INTERVAL` | macro | `beacon5.c:39` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacon5.c:38` | `#define DISCOVERY_PORT` |
| `MALEABLE` | macro | `beacon5.c:46` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon5.c:37` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacon5.c:40` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacon5.c:41` | `#define MESH_MSG_SIZE` |
| `MemoryStruct` | struct | `beacon5.c:61` | `` |
| `RunELF` | function | `beacon5.c:573` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,             unsi...` |
| `SymbolResolver` | struct | `beacon5.c:106` | `` |
| `Trampoline` | struct | `beacon5.c:98` | `` |
| `TrampolineCache` | struct | `beacon5.c:112` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon5.c:47` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon5.c:342` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon5.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon5.c:182` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon5.c:516` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon5.c:488` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `beacon5.c:465` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon5.c:448` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `beacon5.c:295` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon5.c:259` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `beacon5.c:983` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon5.c:546` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `beacon5.c:954` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon5.c:311` | `static void* get_or_create_trampoline(void* target)` |
| `https_request` | function | `beacon5.c:359` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `main` | function | `beacon5.c:1444` | `int main(int argc, char **argv)` |
| `mesh_add_peer` | function | `beacon5.c:1070` | `void mesh_add_peer(const char *ip, int port)` |
| `mesh_cleanup_peers` | function | `beacon5.c:1095` | `void mesh_cleanup_peers()` |
| `mesh_discovery_thread` | function | `beacon5.c:1158` | `void *mesh_discovery_thread(void *arg)` |
| `mesh_is_seen` | function | `beacon5.c:1058` | `int mesh_is_seen(const char *msg_id)` |
| `mesh_listener_thread` | function | `beacon5.c:1241` | `void *mesh_listener_thread(void *arg)` |
| `mesh_mark_seen` | function | `beacon5.c:1050` | `void mesh_mark_seen(const char *msg_id)` |
| `mesh_msg_t` | struct | `beacon5.c:75` | `` |
| `mesh_propagate` | function | `beacon5.c:1131` | `void mesh_propagate(const char *command)` |
| `mesh_send_message` | function | `beacon5.c:1417` | `void mesh_send_message(int type, const char* target, const char* payload)` |
| `mesh_send_to_peer` | function | `beacon5.c:1109` | `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)` |
| `page_align` | function | `beacon5.c:567` | `static size_t page_align(size_t size)` |
| `peer_t` | struct | `beacon5.c:68` | `` |
| `run_bof_and_capture` | function | `beacon5.c:1005` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `BeaconOutput` | function | `beacon6.c:268` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon6.c:255` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon6.c:35` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon6.c:36` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon6.c:37` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon6.c:52` | `` |
| `RunELF` | function | `beacon6.c:593` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,             unsi...` |
| `SymbolResolver` | struct | `beacon6.c:67` | `` |
| `Trampoline` | struct | `beacon6.c:59` | `` |
| `TrampolineCache` | struct | `beacon6.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon6.c:38` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon6.c:362` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon6.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon6.c:142` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon6.c:536` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon6.c:508` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `beacon6.c:485` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon6.c:468` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `beacon6.c:315` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon6.c:279` | `static void* create_trampoline(void* target)` |
| `delay_ms` | function | `beacon6.c:195` | `static void delay_ms(int ms)` |
| `download_bof` | function | `beacon6.c:1003` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon6.c:566` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `beacon6.c:974` | `char* get_local_ips()` |
| `get_nth_prime_limited` | function | `beacon6.c:218` | `static unsigned int get_nth_prime_limited(unsigned int n)` |
| `get_or_create_trampoline` | function | `beacon6.c:331` | `static void* get_or_create_trampoline(void* target)` |
| `https_request` | function | `beacon6.c:379` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `is_prime` | function | `beacon6.c:202` | `static unsigned int is_prime(unsigned int x)` |
| `main` | function | `beacon6.c:1069` | `int main()` |
| `page_align` | function | `beacon6.c:587` | `static size_t page_align(size_t size)` |
| `portable_rand_19k_29k` | function | `beacon6.c:243` | `static unsigned int portable_rand_19k_29k(void)` |
| `run_bof_and_capture` | function | `beacon6.c:1025` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `BROADCAST_INTERVAL` | macro | `beacon_p2p.c:46` | `#define BROADCAST_INTERVAL` |
| `BeaconDataExtract` | function | `beacon_p2p.c:121` | `char *BeaconDataExtract(datap *parser, int *size)` |
| `BeaconDataInt` | function | `beacon_p2p.c:105` | `int BeaconDataInt(datap *parser)` |
| `BeaconDataLength` | function | `beacon_p2p.c:117` | `int BeaconDataLength(datap *parser)` |
| `BeaconDataParse` | function | `beacon_p2p.c:91` | `void BeaconDataParse(datap *parser, char *buffer, int size)` |
| `BeaconDataPtr` | function | `beacon_p2p.c:97` | `char *BeaconDataPtr(datap *parser, int size)` |
| `BeaconDataShort` | function | `beacon_p2p.c:111` | `short BeaconDataShort(datap *parser)` |
| `BeaconOutput` | function | `beacon_p2p.c:142` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon_p2p.c:129` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon_p2p.c:37` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon_p2p.c:38` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon_p2p.c:39` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon_p2p.c:47` | `#define MAX_PEERS` |
| `MemoryStruct` | struct | `beacon_p2p.c:549` | `` |
| `PEER_DISCOVERY_PORT` | macro | `beacon_p2p.c:42` | `#define PEER_DISCOVERY_PORT` |
| `PEER_MAGIC` | macro | `beacon_p2p.c:44` | `#define PEER_MAGIC` |
| `PEER_TCP_PORT` | macro | `beacon_p2p.c:43` | `#define PEER_TCP_PORT` |
| `PEER_VERSION` | macro | `beacon_p2p.c:45` | `#define PEER_VERSION` |
| `RunELF` | function | `beacon_p2p.c:324` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `beacon_p2p.c:161` | `` |
| `Trampoline` | struct | `beacon_p2p.c:155` | `` |
| `TrampolineCache` | struct | `beacon_p2p.c:170` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon_p2p.c:40` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon_p2p.c:555` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon_p2p.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon_p2p.c:229` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `add_peer` | function | `beacon_p2p.c:783` | `void add_peer(struct in_addr ip, int port, const char *id)` |
| `aes256_cfb_decrypt` | function | `beacon_p2p.c:681` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacon_p2p.c:654` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `beacon_p2p.c:641` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon_p2p.c:625` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `beacon_p2p.c:284` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacon_p2p.c:259` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `beacon_p2p.c:757` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon_p2p.c:712` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `execute_generic_command` | function | `beacon_p2p.c:996` | `char* execute_generic_command(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `beacon_p2p.c:729` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon_p2p.c:297` | `static void* get_or_create_trampoline(void* target)` |
| `handle_peer_connection` | function | `beacon_p2p.c:846` | `void *handle_peer_connection(void *arg)` |
| `https_request` | function | `beacon_p2p.c:575` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `main` | function | `beacon_p2p.c:1031` | `int main()` |
| `p2p_header_t` | struct | `beacon_p2p.c:72` | `` |
| `page_align` | function | `beacon_p2p.c:318` | `static size_t page_align(size_t size)` |
| `peer_discovery_thread` | function | `beacon_p2p.c:807` | `void *peer_discovery_thread(void *arg)` |
| `peer_server_thread` | function | `beacon_p2p.c:916` | `void *peer_server_thread(void *arg)` |
| `peer_t` | struct | `beacon_p2p.c:59` | `` |
| `run_bof_and_capture` | function | `beacon_p2p.c:766` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `send_to_c2_or_peer` | function | `beacon_p2p.c:968` | `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)` |
| `send_to_peer` | function | `beacon_p2p.c:935` | `char* send_to_peer(peer_t *peer, const char *data, int *out_len)` |
| `_GNU_SOURCE` | macro | `beacons/v1/beacon.c:13` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v1/beacon.c:97` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v1/beacon.c:146` | `int main(void)` |
| `report_result` | function | `beacons/v1/beacon.c:24` | `static void report_result(const bsb_config_t *cfg,                            const char *command...` |
| `BeaconOutput` | function | `beacons/v1/gopher_beacon.c:203` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacons/v1/gopher_beacon.c:190` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `beacons/v1/gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `beacons/v1/gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacons/v1/gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacons/v1/gopher_beacon.c:47` | `` |
| `RunELF` | function | `beacons/v1/gopher_beacon.c:512` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,             unsi...` |
| `SymbolResolver` | struct | `beacons/v1/gopher_beacon.c:62` | `` |
| `Trampoline` | struct | `beacons/v1/gopher_beacon.c:54` | `` |
| `TrampolineCache` | struct | `beacons/v1/gopher_beacon.c:68` | `` |
| `USER_AGENTS_COUNT` | macro | `beacons/v1/gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacons/v1/gopher_beacon.c:297` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacons/v1/gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacons/v1/gopher_beacon.c:137` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacons/v1/gopher_beacon.c:445` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `beacons/v1/gopher_beacon.c:417` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `beacons/v1/gopher_beacon.c:394` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacons/v1/gopher_beacon.c:377` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `beacons/v1/gopher_beacon.c:250` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `beacons/v1/gopher_beacon.c:214` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `beacons/v1/gopher_beacon.c:922` | `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` |
| `exec_cmd` | function | `beacons/v1/gopher_beacon.c:475` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `beacons/v1/gopher_beacon.c:893` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacons/v1/gopher_beacon.c:266` | `static void* get_or_create_trampoline(void* target)` |
| `gopher_request` | function | `beacons/v1/gopher_beacon.c:314` | `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` |
| `main` | function | `beacons/v1/gopher_beacon.c:994` | `int main()` |
| `page_align` | function | `beacons/v1/gopher_beacon.c:506` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `beacons/v1/gopher_beacon.c:950` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `DISCOVERY_INTERVAL` | macro | `beacons/v2/beacon.c:29` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacons/v2/beacon.c:28` | `#define DISCOVERY_PORT` |
| `MAX_PEERS` | macro | `beacons/v2/beacon.c:27` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacons/v2/beacon.c:30` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacons/v2/beacon.c:31` | `#define MESH_MSG_SIZE` |
| `_GNU_SOURCE` | macro | `beacons/v2/beacon.c:12` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v2/beacon.c:139` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v2/beacon.c:188` | `int main(void)` |
| `mesh_msg_t` | struct | `beacons/v2/beacon.c:40` | `` |
| `peer_t` | struct | `beacons/v2/beacon.c:33` | `` |
| `report_result` | function | `beacons/v2/beacon.c:66` | `static void report_result(const bsb_config_t *cfg,                            const char *command...` |
| `_GNU_SOURCE` | macro | `beacons/v3/beacon.c:12` | `#define _GNU_SOURCE` |
| `compute_primes` | function | `beacons/v3/beacon.c:36` | `static int compute_primes(int count)` |
| `evasive_sleep` | function | `beacons/v3/beacon.c:46` | `static void evasive_sleep(int seconds)` |
| `execute_command` | function | `beacons/v3/beacon.c:125` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `infrastructure` | function | `beacons/v3/beacon.c:8` | `*  * All shared infrastructure (HTTP client, crypto, BOF loader)  * lives in beacon_common.c. Thi...` |
| `main` | function | `beacons/v3/beacon.c:174` | `int main(void)` |
| `report_result` | function | `beacons/v3/beacon.c:52` | `static void report_result(const bsb_config_t *cfg,                            const char *command...` |
| `__attribute__` | function | `bof.c:4` | `__attribute__((used)) __attribute__((visibility("default"))) void go(char *args, int alen)` |
| `go` | function | `bof/cat/bof.c:15` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/cat/cat.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/cat/cat.c:12` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/cat/cat.c:11` | `extern void BeaconPrintf(int, const char*, ...);` |
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
| `BeaconDataExtract` | function | `bof/include/beacon_api.h:41` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `bof/include/beacon_api.h:38` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `bof/include/beacon_api.h:40` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `bof/include/beacon_api.h:36` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `bof/include/beacon_api.h:37` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `bof/include/beacon_api.h:39` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `bof/include/beacon_api.h:47` | `void BeaconOutput(int type, const char *data, int len);` |
| `CALLBACK_ERROR` | macro | `bof/include/beacon_api.h:25` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/include/beacon_api.h:24` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `bof/include/beacon_api.h:26` | `#define CALLBACK_OUTPUT_OEM` |
| `buffer` | function | `bof/include/beacon_api.h:44` | `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */...` |
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
| `bsf_memcmp` | function | `bof/include/syscalls.h:119` | `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` |
| `bsf_strcmp` | function | `bof/include/syscalls.h:113` | `static inline int bsf_strcmp(const char *a, const char *b)` |
| `bsf_strlen` | function | `bof/include/syscalls.h:106` | `static inline size_t bsf_strlen(const char *s)` |
| `syscall0` | function | `bof/include/syscalls.h:49` | `static inline long syscall0(long n)` |
| `syscall1` | function | `bof/include/syscalls.h:60` | `static inline long syscall1(long n, long a1)` |
| `syscall2` | function | `bof/include/syscalls.h:71` | `static inline long syscall2(long n, long a1, long a2)` |
| `syscall3` | function | `bof/include/syscalls.h:82` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `syscall4` | function | `bof/include/syscalls.h:93` | `static inline long syscall4(long n, long a1, long a2, long a3, long a4)` |
| `go` | function | `bof/is_sudo/bof.c:57` | `void go(char *args, int alen)` |
| `user_in_group` | function | `bof/is_sudo/bof.c:15` | `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)` |
| `AT_FDCWD` | macro | `bof/is_sudo/is_sudo.c:20` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/is_sudo/is_sudo.c:12` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/is_sudo/is_sudo.c:11` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/is_sudo/is_sudo.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/is_sudo/is_sudo.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/is_sudo/is_sudo.c:17` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `bof/is_sudo/is_sudo.c:19` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `bof/is_sudo/is_sudo.c:18` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/is_sudo/is_sudo.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/is_sudo/is_sudo.c:16` | `#define SYS_read` |
| `get_username_from_uid` | function | `bof/is_sudo/is_sudo.c:53` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `bof/is_sudo/is_sudo.c:109` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/is_sudo/is_sudo.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/is_sudo/is_sudo.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/is_sudo/is_sudo.c:44` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `bof/is_sudo/is_sudo.c:33` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/is_sudo/is_sudo.c:23` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `DT_DIR` | macro | `bof/suid_enum/bof.c:31` | `#define DT_DIR` |
| `DT_LNK` | macro | `bof/suid_enum/bof.c:32` | `#define DT_LNK` |
| `DT_UNKNOWN` | macro | `bof/suid_enum/bof.c:30` | `#define DT_UNKNOWN` |
| `SYS_getdents64` | macro | `bof/suid_enum/bof.c:26` | `#define SYS_getdents64` |
| `SYS_lstat` | macro | `bof/suid_enum/bof.c:27` | `#define SYS_lstat` |
| `emit` | function | `bof/suid_enum/bof.c:83` | `static void emit(const char *s)` |
| `flush_output` | function | `bof/suid_enum/bof.c:76` | `static void flush_output(void)` |
| `format_mode` | function | `bof/suid_enum/bof.c:105` | `static void format_mode(unsigned int mode, char *out)` |
| `go` | function | `bof/suid_enum/bof.c:247` | `void go(char *args, int alen)` |
| `linux_dirent64` | struct | `bof/suid_enum/bof.c:58` | `` |
| `linux_stat` | struct | `bof/suid_enum/bof.c:35` | `` |
| `path_append` | function | `bof/suid_enum/bof.c:135` | `static void path_append(const char *name)` |
| `path_reset` | function | `bof/suid_enum/bof.c:126` | `static void path_reset(const char *root)` |
| `path_trim_to` | function | `bof/suid_enum/bof.c:149` | `static void path_trim_to(int len)` |
| `walk` | function | `bof/suid_enum/bof.c:158` | `static void walk(int depth)` |
| `go` | function | `bof/userenum/bof.c:68` | `void go(char *args, int alen)` |
| `user_in_member_list` | function | `bof/userenum/bof.c:52` | `static int user_in_member_list(const char *username, const char *members)` |
| `AT_FDCWD` | macro | `bof/userenum/userenum.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/userenum/userenum.c:12` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/userenum/userenum.c:11` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/userenum/userenum.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/userenum/userenum.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/userenum/userenum.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/userenum/userenum.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/userenum/userenum.c:16` | `#define SYS_read` |
| `go` | function | `bof/userenum/userenum.c:41` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/userenum/userenum.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/userenum/userenum.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/userenum/userenum.c:33` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall3` | function | `bof/userenum/userenum.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `go` | function | `bof/whoami/bof.c:19` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/whoami/whoami.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/whoami/whoami.c:11` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/whoami/whoami.c:10` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/whoami/whoami.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/whoami/whoami.c:2` | `#define NULL` |
| `SYS_close` | macro | `bof/whoami/whoami.c:16` | `#define SYS_close` |
| `SYS_getuid` | macro | `bof/whoami/whoami.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/whoami/whoami.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/whoami/whoami.c:15` | `#define SYS_read` |
| `go` | function | `bof/whoami/whoami.c:41` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/whoami/whoami.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/whoami/whoami.c:7` | `typedef long ssize_t;` |
| `syscall1` | function | `bof/whoami/whoami.c:31` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/whoami/whoami.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `C2State` | class | `c2/server.py:136` | `class C2State` |
| `__init__` | method | `c2/server.py:139` | `def __init__(self, cfg)` |
| `command_injector` | method | `c2/server.py:294` | `def command_injector(state)` |
| `compute_hmac` | function | `c2/server.py:86` | `def compute_hmac(key, data)` |
| `decrypt_data` | function | `c2/server.py:117` | `def decrypt_data(b64_data, key, use_hmac)` |
| `encrypt_data` | function | `c2/server.py:97` | `def encrypt_data(data, key, use_hmac)` |
| `handle_bof` | method | `c2/server.py:229` | `def handle_bof(state, name)` |
| `handle_get_command` | method | `c2/server.py:150` | `def handle_get_command(state, selector)` |
| `handle_report` | method | `c2/server.py:173` | `def handle_report(state, b64_payload)` |
| `handle_request` | method | `c2/server.py:239` | `def handle_request(state, selector)` |
| `load_runtime_config` | function | `c2/server.py:59` | `def load_runtime_config()` |
| `main` | method | `c2/server.py:317` | `def main()` |
| `serve_client` | method | `c2/server.py:272` | `def serve_client(state, conn, addr)` |
| `verify_hmac` | function | `c2/server.py:91` | `def verify_hmac(key, data, signature)` |
| `CJSON_PUBLIC` | function | `cJSON.c:95` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:100` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:110` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:125` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:210` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1134` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1236` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1316` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1321` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1352` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1935` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1977` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1982` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1987` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2112` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2123` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2133` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2143` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2155` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2167` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2179` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2191` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2203` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2215` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2227` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2239` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2287` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2297` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2302` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2309` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2316` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2321` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2363` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2413` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2446` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2468` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2479` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2490` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2501` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2526` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2555` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2567` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2579` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2596` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2607` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2659` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2699` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2739` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2922` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2972` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2982` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2992` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3002` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3012` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3022` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3032` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3042` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3052` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3062` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3072` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3194` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3199` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2021` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |

Next: [SYMBOLS_p2.md](SYMBOLS_p2.md)
