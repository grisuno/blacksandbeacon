# API (page 1 of 2)
Pages: [API.md](API.md), [API_p2.md](API_p2.md)

## aes.c
Depends on: `aes.h`
- `getSBoxValue` (function) `aes.c:13` `static uint8_t getSBoxValue(uint8_t num)`
- `getSBoxInvert` (function) `aes.c:35` `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (function) `aes.c:57` `static uint8_t Td0(int x)`
- `Td1` (function) `aes.c:58` `static uint8_t Td1(int x)`
- `Td2` (function) `aes.c:59` `static uint8_t Td2(int x)`
- `Td3` (function) `aes.c:60` `static uint8_t Td3(int x)`
- `Td4` (function) `aes.c:61` `static uint8_t Td4(int x)`
- `KeyExpansion` (function) `aes.c:166` `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` -- This function produces Nb(Nr+1) round keys.
- `AES_init_ctx` (function) `aes.c:239` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (function) `aes.c:244` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.c:249` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (function) `aes.c:257` `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` -- This function adds the round key to state.
- `SubBytes` (function) `aes.c:271` `static void SubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function) `aes.c:286` `static void ShiftRows(state_t* state)` -- The ShiftRows() function shifts the rows in the state to the left.
- `xtime` (function) `aes.c:314` `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function) `aes.c:320` `static void MixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix
- `Multiply` (function) `aes.c:340` `static uint8_t Multiply(uint8_t x, uint8_t y)` -- Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends...
- `InvMixColumns` (function) `aes.c:370` `static void InvMixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix.
- `InvSubBytes` (function) `aes.c:391` `static void InvSubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `InvShiftRows` (function) `aes.c:403` `static void InvShiftRows(state_t* state)`
- `Cipher` (function) `aes.c:433` `static void Cipher(state_t* state, const uint8_t* RoundKey)` -- Cipher is the main function that encrypts the PlainText.
- `InvCipher` (function) `aes.c:459` `static void InvCipher(state_t* state, const uint8_t* RoundKey)` -- if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- `AES_ECB_encrypt` (function) `aes.c:490` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `AES_ECB_decrypt` (function) `aes.c:496` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (function) `aes.c:512` `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- `AES_CBC_encrypt_buffer` (function) `aes.c:521` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (function) `aes.c:536` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (function) `aes.c:558` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` -- XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if...

## aes.h
Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`
- `AES_init_ctx` (function) `aes.h:41` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- `AES_init_ctx_iv` (function) `aes.h:43` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.h:44` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- `AES_ECB_encrypt` (function) `aes.h:48` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` -- if defined(ECB) && (ECB == 1)
- `AES_ECB_decrypt` (function) `aes.h:49` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- `AES_CBC_encrypt_buffer` (function) `aes.h:53` `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CBC) && (CBC == 1)
- `AES_CBC_decrypt_buffer` (function) `aes.h:54` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (function) `aes.h:58` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CTR) && (CTR == 1)

## beacon.h
Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`
- `BeaconDataParse` (function) `beacon.h:21` `void BeaconDataParse(datap *parser, char *buffer, int size);` -- === API para BOFs ===
- `BeaconDataPtr` (function) `beacon.h:22` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `beacon.h:23` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `beacon.h:24` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `beacon.h:25` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `beacon.h:26` `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (function) `beacon.h:27` `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (function) `beacon.h:28` `void BeaconOutput(int type, const char *data, int len);`

## beacon3.c
Depends on: `aes.h`, `beacon.h`, `cJSON.h`
- `BeaconPrintf` (function) `beacon3.c:193` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `beacon3.c:206` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `beacon3.c:217` `static void* create_trampoline(void* target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `beacon3.c:253` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `beacon3.c:269` `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (function) `beacon3.c:300` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `beacon3.c:317` `char* https_request(const char* url, const char* method, const char* post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `beacon3.c:406` `char* base64_encode(const unsigned char* input, int len)` -- === BASE64 ===
- `base64_decode` (function) `beacon3.c:423` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `beacon3.c:446` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `beacon3.c:474` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `beacon3.c:504` `char* exec_cmd(const char* cmd, int* out_len)` -- === EXEC CMD ===
- `page_align` (function) `beacon3.c:525` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `beacon3.c:531` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (function) `beacon3.c:912` `char* get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `beacon3.c:941` `unsigned char* download_bof(const char* url, size_t* out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `beacon3.c:963` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `beacon3.c:1007` `int main()` -- === MAIN ===

## beacon5.c
Depends on: `aes.h`, `beacon.h`, `cJSON.h`
- `BeaconPrintf` (function) `beacon5.c:235` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `beacon5.c:248` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `beacon5.c:259` `static void* create_trampoline(void* target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `beacon5.c:295` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `beacon5.c:311` `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (function) `beacon5.c:342` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `beacon5.c:359` `char* https_request(const char* url, const char* method, const char* post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `beacon5.c:448` `char* base64_encode(const unsigned char* input, int len)` -- === BASE64 ===
- `base64_decode` (function) `beacon5.c:465` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `beacon5.c:488` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `beacon5.c:516` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `beacon5.c:546` `char* exec_cmd(const char* cmd, int* out_len)` -- === EXEC CMD ===
- `page_align` (function) `beacon5.c:567` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `beacon5.c:573` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (function) `beacon5.c:954` `char* get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `beacon5.c:983` `unsigned char* download_bof(const char* url, size_t* out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `beacon5.c:1005` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` -- === RUN BOF AND CAPTURE ===
- `mesh_mark_seen` (function) `beacon5.c:1050` `void mesh_mark_seen(const char *msg_id)`
- `mesh_is_seen` (function) `beacon5.c:1058` `int mesh_is_seen(const char *msg_id)`
- `mesh_add_peer` (function) `beacon5.c:1070` `void mesh_add_peer(const char *ip, int port)`
- `mesh_cleanup_peers` (function) `beacon5.c:1095` `void mesh_cleanup_peers()`
- `mesh_send_to_peer` (function) `beacon5.c:1109` `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
- `mesh_propagate` (function) `beacon5.c:1131` `void mesh_propagate(const char *command)`
- `mesh_discovery_thread` (function) `beacon5.c:1158` `void *mesh_discovery_thread(void *arg)`
- `mesh_listener_thread` (function) `beacon5.c:1241` `void *mesh_listener_thread(void *arg)`
- `mesh_send_message` (function) `beacon5.c:1417` `void mesh_send_message(int type, const char* target, const char* payload)`
- `main` (function) `beacon5.c:1444` `int main(int argc, char **argv)` -- === MAIN ===

## beacon6.c
Depends on: `aes.h`, `beacon.h`, `cJSON.h`
- `delay_ms` (function) `beacon6.c:195` `static void delay_ms(int ms)` -- sleep ofuscated using poll
- `is_prime` (function) `beacon6.c:202` `static unsigned int is_prime(unsigned int x)` -- -- Lógica de números primos (sin cambios esenciales) ---
- `get_nth_prime_limited` (function) `beacon6.c:218` `static unsigned int get_nth_prime_limited(unsigned int n)` -- if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d...
- `portable_rand_19k_29k` (function) `beacon6.c:243` `static unsigned int portable_rand_19k_29k(void)`
- `BeaconPrintf` (function) `beacon6.c:255` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `beacon6.c:268` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `beacon6.c:279` `static void* create_trampoline(void* target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `beacon6.c:315` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `beacon6.c:331` `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (function) `beacon6.c:362` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `beacon6.c:379` `char* https_request(const char* url, const char* method, const char* post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `beacon6.c:468` `char* base64_encode(const unsigned char* input, int len)` -- === BASE64 ===
- `base64_decode` (function) `beacon6.c:485` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `beacon6.c:508` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `beacon6.c:536` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `beacon6.c:566` `char* exec_cmd(const char* cmd, int* out_len)` -- === EXEC CMD ===
- `page_align` (function) `beacon6.c:587` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `beacon6.c:593` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (function) `beacon6.c:974` `char* get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `beacon6.c:1003` `unsigned char* download_bof(const char* url, size_t* out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `beacon6.c:1025` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `beacon6.c:1069` `int main()` -- === MAIN ===

## beacon_p2p.c
Depends on: `aes.h`, `beacon.h`, `cJSON.h`
- `BeaconDataParse` (function) `beacon_p2p.c:91` `void BeaconDataParse(datap *parser, char *buffer, int size)`
- `BeaconDataPtr` (function) `beacon_p2p.c:97` `char *BeaconDataPtr(datap *parser, int size)`
- `BeaconDataInt` (function) `beacon_p2p.c:105` `int BeaconDataInt(datap *parser)`
- `BeaconDataShort` (function) `beacon_p2p.c:111` `short BeaconDataShort(datap *parser)`
- `BeaconDataLength` (function) `beacon_p2p.c:117` `int BeaconDataLength(datap *parser)`
- `BeaconDataExtract` (function) `beacon_p2p.c:121` `char *BeaconDataExtract(datap *parser, int *size)`
- `BeaconPrintf` (function) `beacon_p2p.c:129` `void BeaconPrintf(int type, const char *fmt, ...)`
- `BeaconOutput` (function) `beacon_p2p.c:142` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `beacon_p2p.c:259` `static void* create_trampoline(void* target)`
- `cleanup_trampolines` (function) `beacon_p2p.c:284` `static void cleanup_trampolines(void)`
- `get_or_create_trampoline` (function) `beacon_p2p.c:297` `static void* get_or_create_trampoline(void* target)`
- `page_align` (function) `beacon_p2p.c:318` `static size_t page_align(size_t size)`
- `RunELF` (function) `beacon_p2p.c:324` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
- `WriteMemoryCallback` (function) `beacon_p2p.c:555` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `https_request` (function) `beacon_p2p.c:575` `char* https_request(const char* url, const char* method, const char* post_data)`
- `base64_encode` (function) `beacon_p2p.c:625` `char* base64_encode(const unsigned char* input, int len)`
- `base64_decode` (function) `beacon_p2p.c:641` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `beacon_p2p.c:654` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `aes256_cfb_decrypt` (function) `beacon_p2p.c:681` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `beacon_p2p.c:712` `char* exec_cmd(const char* cmd, int* out_len)`
- `get_local_ips` (function) `beacon_p2p.c:729` `char* get_local_ips()`
- `download_bof` (function) `beacon_p2p.c:757` `unsigned char* download_bof(const char* url, size_t* out_size)`
- `run_bof_and_capture` (function) `beacon_p2p.c:766` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- `add_peer` (function) `beacon_p2p.c:783` `void add_peer(struct in_addr ip, int port, const char *id)`
- `peer_discovery_thread` (function) `beacon_p2p.c:807` `void *peer_discovery_thread(void *arg)`
- `handle_peer_connection` (function) `beacon_p2p.c:846` `void *handle_peer_connection(void *arg)`
- `peer_server_thread` (function) `beacon_p2p.c:916` `void *peer_server_thread(void *arg)`
- `send_to_peer` (function) `beacon_p2p.c:935` `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
- `send_to_c2_or_peer` (function) `beacon_p2p.c:968` `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
- `execute_generic_command` (function) `beacon_p2p.c:996` `char* execute_generic_command(const char *cmd, int *out_len)`
- `main` (function) `beacon_p2p.c:1031` `int main()`

## beacons/v1/beacon.c
Depends on: `include/beacon_common.h`
- `report_result` (function) `beacons/v1/beacon.c:24` `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- `execute_command` (function) `beacons/v1/beacon.c:97` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v1/beacon.c:146` `int main(void)`

## beacons/v1/gopher_beacon.c
- `BeaconPrintf` (function) `beacons/v1/gopher_beacon.c:190` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `beacons/v1/gopher_beacon.c:203` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `beacons/v1/gopher_beacon.c:214` `static void* create_trampoline(void* target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `beacons/v1/gopher_beacon.c:250` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `beacons/v1/gopher_beacon.c:266` `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (function) `beacons/v1/gopher_beacon.c:297` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `gopher_request` (function) `beacons/v1/gopher_beacon.c:314` `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` -- === GOPHER REQUEST () ===
- `base64_encode` (function) `beacons/v1/gopher_beacon.c:377` `char* base64_encode(const unsigned char* input, int len)` -- === BASE64 ===
- `base64_decode` (function) `beacons/v1/gopher_beacon.c:394` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `beacons/v1/gopher_beacon.c:417` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `beacons/v1/gopher_beacon.c:445` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `beacons/v1/gopher_beacon.c:475` `char* exec_cmd(const char* cmd, int* out_len)` -- === EXEC CMD ===
- `page_align` (function) `beacons/v1/gopher_beacon.c:506` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `beacons/v1/gopher_beacon.c:512` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (function) `beacons/v1/gopher_beacon.c:893` `char* get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `beacons/v1/gopher_beacon.c:922` `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `beacons/v1/gopher_beacon.c:950` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `beacons/v1/gopher_beacon.c:994` `int main()` -- === MAIN ===

## beacons/v2/beacon.c
Depends on: `include/beacon_common.h`
- `report_result` (function) `beacons/v2/beacon.c:66` `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- `execute_command` (function) `beacons/v2/beacon.c:139` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v2/beacon.c:188` `int main(void)`

## beacons/v3/beacon.c
Depends on: `include/beacon_common.h`
- `infrastructure` (function) `beacons/v3/beacon.c:8` `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
- `compute_primes` (function) `beacons/v3/beacon.c:36` `static int compute_primes(int count)`
- `evasive_sleep` (function) `beacons/v3/beacon.c:46` `static void evasive_sleep(int seconds)`
- `report_result` (function) `beacons/v3/beacon.c:52` `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- `execute_command` (function) `beacons/v3/beacon.c:125` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v3/beacon.c:174` `int main(void)`

## bof/cat/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `go` (function) `bof/cat/bof.c:15` `void go(char *args, int alen)`

## bof/cat/cat.c
- `BeaconPrintf` (function) `bof/cat/cat.c:11` `extern void BeaconPrintf(int, const char*, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/cat/cat.c:12` `extern void BeaconOutput(int, const char*, int);`
- `syscall3` (function) `bof/cat/cat.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers (copiados de tus ejemplos)
- `go` (function) `bof/cat/cat.c:31` `void go(char *args, int alen)`

## bof/include/beacon_api.h
Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`
- `go` (function) `bof/include/beacon_api.h:10` `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);`
- `BeaconDataParse` (function) `bof/include/beacon_api.h:36` `void BeaconDataParse(datap *parser, char *buffer, int size);`
- `BeaconDataPtr` (function) `bof/include/beacon_api.h:37` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `bof/include/beacon_api.h:38` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `bof/include/beacon_api.h:39` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `bof/include/beacon_api.h:40` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `bof/include/beacon_api.h:41` `char *BeaconDataExtract(datap *parser, int *size);`
- `buffer` (function) `bof/include/beacon_api.h:44` `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */...`
- `BeaconOutput` (function) `bof/include/beacon_api.h:47` `void BeaconOutput(int type, const char *data, int len);`

## bof/include/syscalls.h
Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`
- `syscall0` (function) `bof/include/syscalls.h:49` `static inline long syscall0(long n)`
- `syscall1` (function) `bof/include/syscalls.h:60` `static inline long syscall1(long n, long a1)`
- `syscall2` (function) `bof/include/syscalls.h:71` `static inline long syscall2(long n, long a1, long a2)`
- `syscall3` (function) `bof/include/syscalls.h:82` `static inline long syscall3(long n, long a1, long a2, long a3)`
- `syscall4` (function) `bof/include/syscalls.h:93` `static inline long syscall4(long n, long a1, long a2, long a3, long a4)`
- `bsf_strlen` (function) `bof/include/syscalls.h:106` `static inline size_t bsf_strlen(const char *s)` -- static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10")...
- `bsf_strcmp` (function) `bof/include/syscalls.h:113` `static inline int bsf_strcmp(const char *a, const char *b)` -- : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; } /* strlen - libc is not...
- `bsf_memcmp` (function) `bof/include/syscalls.h:119` `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` -- /* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++...

## bof/is_sudo/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `user_in_group` (function) `bof/is_sudo/bof.c:15` `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
- `go` (function) `bof/is_sudo/bof.c:57` `void go(char *args, int alen)`

## bof/is_sudo/is_sudo.c
- `BeaconPrintf` (function) `bof/is_sudo/is_sudo.c:11` `extern void BeaconPrintf(int, const char*, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/is_sudo/is_sudo.c:12` `extern void BeaconOutput(int, const char*, int);`
- `syscall3` (function) `bof/is_sudo/is_sudo.c:23` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `syscall1` (function) `bof/is_sudo/is_sudo.c:33` `static inline long syscall1(long n, long a1)`
- `strcmp` (function) `bof/is_sudo/is_sudo.c:44` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function) `bof/is_sudo/is_sudo.c:53` `static int get_username_from_uid(long uid, char *buf, int buf_size)` -- Obtener username desde /etc/passwd (sin libc)
- `go` (function) `bof/is_sudo/is_sudo.c:109` `void go(char *args, int alen)`

## bof/suid_enum/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `flush_output` (function) `bof/suid_enum/bof.c:76` `static void flush_output(void)`
- `emit` (function) `bof/suid_enum/bof.c:83` `static void emit(const char *s)`
- `format_mode` (function) `bof/suid_enum/bof.c:105` `static void format_mode(unsigned int mode, char *out)` -- Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.
- `path_reset` (function) `bof/suid_enum/bof.c:126` `static void path_reset(const char *root)`
- `path_append` (function) `bof/suid_enum/bof.c:135` `static void path_append(const char *name)`
- `path_trim_to` (function) `bof/suid_enum/bof.c:149` `static void path_trim_to(int len)`
- `walk` (function) `bof/suid_enum/bof.c:158` `static void walk(int depth)` -- Walk one directory, recursing into subdirectories.
- `go` (function) `bof/suid_enum/bof.c:247` `void go(char *args, int alen)`

## bof/userenum/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `user_in_member_list` (function) `bof/userenum/bof.c:52` `static int user_in_member_list(const char *username, const char *members)`
- `go` (function) `bof/userenum/bof.c:68` `void go(char *args, int alen)`

## bof/userenum/userenum.c
- `BeaconPrintf` (function) `bof/userenum/userenum.c:11` `extern void BeaconPrintf(int, const char*, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/userenum/userenum.c:12` `extern void BeaconOutput(int, const char*, int);`
- `syscall3` (function) `bof/userenum/userenum.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `strcmp` (function) `bof/userenum/userenum.c:33` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `go` (function) `bof/userenum/userenum.c:41` `void go(char *args, int alen)`

## bof/whoami/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `go` (function) `bof/whoami/bof.c:19` `void go(char *args, int alen)`

## bof/whoami/whoami.c
- `BeaconPrintf` (function) `bof/whoami/whoami.c:10` `extern void BeaconPrintf(int, const char*, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/whoami/whoami.c:11` `extern void BeaconOutput(int, const char*, int);`
- `syscall3` (function) `bof/whoami/whoami.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Syscall wrappers
- `syscall1` (function) `bof/whoami/whoami.c:31` `static inline long syscall1(long n, long a1)`
- `go` (function) `bof/whoami/whoami.c:41` `void go(char *args, int alen)`

## c2/server.py
Depends on: `include/config_py.py`
Imported by: `tests/test_c2_server.py`
- `load_runtime_config` (function) `c2/server.py:59` `def load_runtime_config()` -- Load configuration from JSON file or use defaults.
- `compute_hmac` (function) `c2/server.py:86` `def compute_hmac(key, data)` -- Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function) `c2/server.py:91` `def verify_hmac(key, data, signature)` -- Verify HMAC-SHA256 signature.
- `encrypt_data` (function) `c2/server.py:97` `def encrypt_data(data, key, use_hmac)` -- Encrypt data with AES-256-CFB and optional HMAC.
- `decrypt_data` (function) `c2/server.py:117` `def decrypt_data(b64_data, key, use_hmac)` -- Decrypt AES-256-CFB data with optional HMAC verification.
- `C2State.__init__` (method) `c2/server.py:139` `def __init__(self, cfg)`
- `C2State.handle_get_command` (method) `c2/server.py:150` `def handle_get_command(state, selector)` -- Dispatch beacon's polling GET request.
- `C2State.handle_report` (method) `c2/server.py:173` `def handle_report(state, b64_payload)` -- Process beacon result report.
- `C2State.handle_bof` (method) `c2/server.py:229` `def handle_bof(state, name)` -- Serve BOF file from upload directory.
- `C2State.handle_request` (method) `c2/server.py:239` `def handle_request(state, selector)` -- Route request to appropriate handler.
- `C2State.serve_client` (method) `c2/server.py:272` `def serve_client(state, conn, addr)` -- Handle individual client connection.
- `C2State.command_injector` (method) `c2/server.py:294` `def command_injector(state)` -- Interactive command injection REPL.
- `C2State.main` (method) `c2/server.py:317` `def main()` -- Start C2 server.

## cJSON.c
Depends on: `cJSON.h`
- `CJSON_PUBLIC` (function) `cJSON.c:95` `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:100` `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:110` `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:125` `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- `case_insensitive_strcmp` (function) `cJSON.c:134` `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` -- /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR...
- `internal_malloc` (function) `cJSON.c:166` `static void * CJSON_CDECL internal_malloc(size_t size)` -- } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL...
- `internal_free` (function) `cJSON.c:170` `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (function) `cJSON.c:174` `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (function) `cJSON.c:189` `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (function) `cJSON.c:210` `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (function) `cJSON.c:242` `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` -- if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and...
- `get_decimal_point` (function) `cJSON.c:281` `static unsigned char get_decimal_point(void)` -- item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {...
- `parse_number` (function) `cJSON.c:309` `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` -- size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset....
- `ensure` (function) `cJSON.c:494` `static unsigned char* ensure(printbuffer * const p, size_t needed)` -- } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for...
- `update_offset` (function) `cJSON.c:579` `static void update_offset(printbuffer * const buffer)` -- p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); }...
- `compare_double` (function) `cJSON.c:592` `static cJSON_bool compare_double(double a, double b)` -- /* calculate the new length of the string in a printbuffer and update the offset static void...
- `print_number` (function) `cJSON.c:599` `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` -- } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /*...
- `parse_hex4` (function) `cJSON.c:669` `static unsigned parse_hex4(const unsigned char * const input)` -- output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'...
- `utf16_literal_to_utf8` (function) `cJSON.c:706` `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` -- converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- `parse_string` (function) `cJSON.c:827` `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` -- else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return...
- `print_string_ptr` (function) `cJSON.c:957` `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` -- { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset =...
- `print_string` (function) `cJSON.c:1079` `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` -- /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer +=...
- `buffer_skip_whitespace` (function) `cJSON.c:1093` `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` -- static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned...
- `skip_utf8_bom` (function) `cJSON.c:1119` `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` -- while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if...
- `CJSON_PUBLIC` (function) `cJSON.c:1134` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (function) `cJSON.c:1236` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (function) `cJSON.c:1243` `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- `CJSON_PUBLIC` (function) `cJSON.c:1316` `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:1321` `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (function) `cJSON.c:1352` `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (function) `cJSON.c:1372` `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` -- return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true...
- `print_value` (function) `cJSON.c:1427` `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` -- if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item...
- `parse_array` (function) `cJSON.c:1501` `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` -- return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case...
- `print_array` (function) `cJSON.c:1599` `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `parse_object` (function) `cJSON.c:1661` `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` -- output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'...
- `print_object` (function) `cJSON.c:1780` `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `get_array_item` (function) `cJSON.c:1916` `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (function) `cJSON.c:1935` `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (function) `cJSON.c:1945` `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (function) `cJSON.c:1977` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (function) `cJSON.c:1982` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (function) `cJSON.c:1987` `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (function) `cJSON.c:1993` `static void suffix_object(cJSON *prev, cJSON *item)` -- return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON...
- `create_reference` (function) `cJSON.c:2000` `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` -- CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return...
- `add_item_to_array` (function) `cJSON.c:2021` `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (function) `cJSON.c:2066` `static void* cast_away_const(const void* string)` -- /* Add item to array/object.
- `add_item_to_object` (function) `cJSON.c:2075` `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- `CJSON_PUBLIC` (function) `cJSON.c:2112` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2123` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2133` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2143` `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2155` `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2167` `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2179` `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (function) `cJSON.c:2191` `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `cJSON.c:2203` `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `cJSON.c:2215` `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (function) `cJSON.c:2227` `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2239` `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2251` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2287` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2297` `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2302` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2309` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2316` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2321` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2363` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2413` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (function) `cJSON.c:2423` `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (function) `cJSON.c:2446` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (function) `cJSON.c:2451` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (function) `cJSON.c:2468` `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2479` `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2490` `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (function) `cJSON.c:2501` `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (function) `cJSON.c:2526` `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2543` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2555` `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2567` `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2579` `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (function) `cJSON.c:2596` `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2607` `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2659` `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2699` `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2739` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (function) `cJSON.c:2786` `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (function) `cJSON.c:2873` `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (function) `cJSON.c:2886` `static void skip_multiline_comment(char **input)`
- `minify_string` (function) `cJSON.c:2900` `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (function) `cJSON.c:2922` `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (function) `cJSON.c:2972` `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2982` `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2992` `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3002` `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3012` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3022` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3032` `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3042` `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3052` `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3062` `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3072` `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (function) `cJSON.c:3157` `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (function) `cJSON.c:3173` `cJSON_ArrayForEach(b_element, b)` -- doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this...
- `CJSON_PUBLIC` (function) `cJSON.c:3194` `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (function) `cJSON.c:3199` `CJSON_PUBLIC(void) cJSON_free(void *object)`

## cJSON.h
Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `cJSON.c`, `gopher_beacon.c`
- `sensitive` (function) `cJSON.h:249` `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */...`

## gopher_beacon.c
Depends on: `aes.h`, `beacon.h`, `cJSON.h`
- `BeaconPrintf` (function) `gopher_beacon.c:190` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `gopher_beacon.c:203` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `gopher_beacon.c:214` `static void* create_trampoline(void* target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `gopher_beacon.c:250` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `gopher_beacon.c:266` `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (function) `gopher_beacon.c:297` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `gopher_request` (function) `gopher_beacon.c:314` `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` -- === GOPHER REQUEST () ===
- `base64_encode` (function) `gopher_beacon.c:377` `char* base64_encode(const unsigned char* input, int len)` -- === BASE64 ===
- `base64_decode` (function) `gopher_beacon.c:394` `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (function) `gopher_beacon.c:417` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `gopher_beacon.c:445` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (function) `gopher_beacon.c:475` `char* exec_cmd(const char* cmd, int* out_len)` -- === EXEC CMD ===
- `page_align` (function) `gopher_beacon.c:506` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `gopher_beacon.c:512` `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (function) `gopher_beacon.c:893` `char* get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `gopher_beacon.c:922` `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `gopher_beacon.c:950` `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `gopher_beacon.c:994` `int main()` -- === MAIN ===

## gopher_c2.py
- `encrypt_data` (function) `gopher_c2.py:28` `def encrypt_data(data)`
- `decrypt_data` (function) `gopher_c2.py:37` `def decrypt_data(b64_data)`
- `handle_client` (function) `gopher_c2.py:45` `def handle_client(conn, addr)`
- `main` (function) `gopher_c2.py:127` `def main()`
- `command_injector` (function) `gopher_c2.py:136` `def command_injector()`

## include/aes.c
Depends on: `include/aes.h`
- `KeyExpansion` (function) `include/aes.c:166` `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` -- This function produces Nb(Nr+1) round keys.
- `AES_init_ctx` (function) `include/aes.c:239` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (function) `include/aes.c:244` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `include/aes.c:249` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (function) `include/aes.c:257` `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` -- This function adds the round key to state.
- `SubBytes` (function) `include/aes.c:271` `static void SubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function) `include/aes.c:286` `static void ShiftRows(state_t* state)` -- The ShiftRows() function shifts the rows in the state to the left.
- `xtime` (function) `include/aes.c:314` `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function) `include/aes.c:320` `static void MixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix
- `Multiply` (function) `include/aes.c:340` `static uint8_t Multiply(uint8_t x, uint8_t y)` -- Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends...
- `InvMixColumns` (function) `include/aes.c:370` `static void InvMixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix.
- `InvSubBytes` (function) `include/aes.c:391` `static void InvSubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `InvShiftRows` (function) `include/aes.c:403` `static void InvShiftRows(state_t* state)`
- `Cipher` (function) `include/aes.c:433` `static void Cipher(state_t* state, const uint8_t* RoundKey)` -- Cipher is the main function that encrypts the PlainText.
- `InvCipher` (function) `include/aes.c:459` `static void InvCipher(state_t* state, const uint8_t* RoundKey)` -- if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- `AES_ECB_encrypt` (function) `include/aes.c:490` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `AES_ECB_decrypt` (function) `include/aes.c:496` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (function) `include/aes.c:512` `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- `AES_CBC_encrypt_buffer` (function) `include/aes.c:521` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (function) `include/aes.c:536` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (function) `include/aes.c:558` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` -- XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if...


Next: [API_p2.md](API_p2.md)
