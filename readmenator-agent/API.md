# API

## aes.c

### getSBoxValue `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16

### getSBoxInvert `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:34`

### Td0 `static uint8_t Td0(int x)`
- Defined: `aes.c:56`

### Td1 `static uint8_t Td1(int x)`
- Defined: `aes.c:58`

### Td2 `static uint8_t Td2(int x)`
- Defined: `aes.c:59`

### Td3 `static uint8_t Td3(int x)`
- Defined: `aes.c:60`

### Td4 `static uint8_t Td4(int x)`
- Defined: `aes.c:61`

### KeyExpansion `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.

### AES_init_ctx `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `aes.c:238`

### AES_init_ctx_iv `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

### AES_ctx_set_iv `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `aes.c:249`

### AddRoundKey `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.

### SubBytes `static void SubBytes(state_t* state)`
- Defined: `aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### ShiftRows `static void ShiftRows(state_t* state)`
- Defined: `aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R

### xtime `static uint8_t xtime(uint8_t x)`
- Defined: `aes.c:313`

### MixColumns `static void MixColumns(state_t* state)`
- Defined: `aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix

### Multiply `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 

### InvMixColumns `static void InvMixColumns(state_t* state)`
- Defined: `aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo

### InvSubBytes `static void InvSubBytes(state_t* state)`
- Defined: `aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### InvShiftRows `static void InvShiftRows(state_t* state)`
- Defined: `aes.c:402`

### Cipher `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.

### InvCipher `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

### AES_ECB_encrypt `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&

### AES_ECB_decrypt `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:495`

### XorWithIv `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)

### AES_CBC_encrypt_buffer `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:520`

### AES_CBC_decrypt_buffer `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:535`

### AES_CTR_xcrypt_buffer `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)

## beacon3.c

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon3.c:140`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon3.c:193`
- Doc: === BEACON API ===

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon3.c:205`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `beacon3.c:217`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `beacon3.c:253`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon3.c:268`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon3.c:300`
- Doc: === CURL WRITE CALLBACK ===

### https_request `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon3.c:317`
- Doc: === HTTPS REQUEST ===

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon3.c:406`
- Doc: === BASE64 ===

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon3.c:422`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon3.c:446`
- Doc: === AES CFB ===

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon3.c:473`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon3.c:504`
- Doc: === EXEC CMD ===

### page_align `static size_t page_align(size_t size)`
- Defined: `beacon3.c:525`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon3.c:530`

### get_local_ips `char* get_local_ips()`
- Defined: `beacon3.c:912`
- Doc: === GET LOCAL IPs ===

### download_bof `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon3.c:941`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon3.c:963`
- Doc: === RUN BOF AND CAPTURE ===

### main `int main()`
- Defined: `beacon3.c:1007`
- Doc: === MAIN ===

## beacon5.c

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon5.c:182`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon5.c:235`
- Doc: === BEACON API ===

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon5.c:247`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `beacon5.c:259`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `beacon5.c:295`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon5.c:310`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon5.c:342`
- Doc: === CURL WRITE CALLBACK ===

### https_request `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon5.c:359`
- Doc: === HTTPS REQUEST ===

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon5.c:448`
- Doc: === BASE64 ===

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon5.c:464`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon5.c:488`
- Doc: === AES CFB ===

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon5.c:515`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon5.c:546`
- Doc: === EXEC CMD ===

### page_align `static size_t page_align(size_t size)`
- Defined: `beacon5.c:567`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon5.c:572`

### get_local_ips `char* get_local_ips()`
- Defined: `beacon5.c:954`
- Doc: === GET LOCAL IPs ===

### download_bof `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon5.c:983`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon5.c:1005`
- Doc: === RUN BOF AND CAPTURE ===

### mesh_mark_seen `void mesh_mark_seen(const char *msg_id)`
- Defined: `beacon5.c:1049`
- Doc: ========== UTILIDADES MESH ==========

### mesh_is_seen `int mesh_is_seen(const char *msg_id)`
- Defined: `beacon5.c:1057`

### mesh_add_peer `void mesh_add_peer(const char *ip, int port)`
- Defined: `beacon5.c:1069`

### mesh_cleanup_peers `void mesh_cleanup_peers()`
- Defined: `beacon5.c:1094`

### mesh_send_to_peer `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
- Defined: `beacon5.c:1108`
- Doc: ========== PROPAGACIÓN MESH ==========

### mesh_propagate `void mesh_propagate(const char *command)`
- Defined: `beacon5.c:1130`

### mesh_discovery_thread `void *mesh_discovery_thread(void *arg)`
- Defined: `beacon5.c:1157`
- Doc: ========== DISCOVERY THREAD ==========

### mesh_listener_thread `void *mesh_listener_thread(void *arg)`
- Defined: `beacon5.c:1240`
- Doc: ========== MESH LISTENER THREAD ==========

### mesh_send_message `void mesh_send_message(int type, const char* target, const char* payload)`
- Defined: `beacon5.c:1416`

### main `int main(int argc, char **argv)`
- Defined: `beacon5.c:1444`
- Doc: === MAIN ===

## beacon6.c

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon6.c:142`

### delay_ms `static void delay_ms(int ms)`
- Defined: `beacon6.c:195`
- Doc: sleep ofuscated using poll

### is_prime `static unsigned int is_prime(unsigned int x)`
- Defined: `beacon6.c:202`
- Doc: -- Lógica de números primos (sin cambios esenciales) ---

### get_nth_prime_limited `static unsigned int get_nth_prime_limited(unsigned int n)`
- Defined: `beacon6.c:218`
- Doc: if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d <= x

### portable_rand_19k_29k `static unsigned int portable_rand_19k_29k(void)`
- Defined: `beacon6.c:242`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon6.c:255`
- Doc: === BEACON API ===

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon6.c:267`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `beacon6.c:279`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `beacon6.c:315`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon6.c:330`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon6.c:362`
- Doc: === CURL WRITE CALLBACK ===

### https_request `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon6.c:379`
- Doc: === HTTPS REQUEST ===

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon6.c:468`
- Doc: === BASE64 ===

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon6.c:484`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon6.c:508`
- Doc: === AES CFB ===

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon6.c:535`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon6.c:566`
- Doc: === EXEC CMD ===

### page_align `static size_t page_align(size_t size)`
- Defined: `beacon6.c:587`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon6.c:592`

### get_local_ips `char* get_local_ips()`
- Defined: `beacon6.c:974`
- Doc: === GET LOCAL IPs ===

### download_bof `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon6.c:1003`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon6.c:1025`
- Doc: === RUN BOF AND CAPTURE ===

### main `int main()`
- Defined: `beacon6.c:1069`
- Doc: === MAIN ===

## beacon_p2p.c

### BeaconDataParse `void BeaconDataParse(datap *parser, char *buffer, int size)`
- Defined: `beacon_p2p.c:91`
- Doc: ======================================================================= FUNCIONES DE LA API DE BEACON (para BOFs) ======

### BeaconDataPtr `char *BeaconDataPtr(datap *parser, int size)`
- Defined: `beacon_p2p.c:96`

### BeaconDataInt `int BeaconDataInt(datap *parser)`
- Defined: `beacon_p2p.c:104`

### BeaconDataShort `short BeaconDataShort(datap *parser)`
- Defined: `beacon_p2p.c:110`

### BeaconDataLength `int BeaconDataLength(datap *parser)`
- Defined: `beacon_p2p.c:116`

### BeaconDataExtract `char *BeaconDataExtract(datap *parser, int *size)`
- Defined: `beacon_p2p.c:120`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon_p2p.c:128`

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon_p2p.c:141`

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon_p2p.c:228`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `beacon_p2p.c:258`

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `beacon_p2p.c:283`

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon_p2p.c:296`

### page_align `static size_t page_align(size_t size)`
- Defined: `beacon_p2p.c:317`

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
- Defined: `beacon_p2p.c:323`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon_p2p.c:554`

### https_request `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon_p2p.c:574`

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon_p2p.c:624`

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon_p2p.c:640`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon_p2p.c:653`

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon_p2p.c:680`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon_p2p.c:712`
- Doc: ======================================================================= UTILIDADES: ejecutar comandos shell, obtener IPs

### get_local_ips `char* get_local_ips()`
- Defined: `beacon_p2p.c:728`

### download_bof `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon_p2p.c:756`

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon_p2p.c:765`

### add_peer `void add_peer(struct in_addr ip, int port, const char *id)`
- Defined: `beacon_p2p.c:783`
- Doc: ======================================================================= FUNCIONES P2P ==================================

### peer_discovery_thread `void *peer_discovery_thread(void *arg)`
- Defined: `beacon_p2p.c:806`

### handle_peer_connection `void *handle_peer_connection(void *arg)`
- Defined: `beacon_p2p.c:845`

### peer_server_thread `void *peer_server_thread(void *arg)`
- Defined: `beacon_p2p.c:915`

### send_to_peer `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
- Defined: `beacon_p2p.c:934`

### send_to_c2_or_peer `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
- Defined: `beacon_p2p.c:967`

### execute_generic_command `char* execute_generic_command(const char *cmd, int *out_len)`
- Defined: `beacon_p2p.c:996`
- Doc: ======================================================================= EJECUTOR DE COMANDOS (unificado para shell y BOF

### main `int main()`
- Defined: `beacon_p2p.c:1031`
- Doc: ======================================================================= MAIN ===========================================

## beacons/v1/beacon.c

### report_result `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v1/beacon.c:23`
- Doc: This beacon uses exponential backoff on failures to reduce noise when the C2 is unreachable. The backoff resets on the f

### execute_command `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v1/beacon.c:96`

### main `int main(void)`
- Defined: `beacons/v1/beacon.c:145`

## beacons/v1/gopher_beacon.c

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacons/v1/gopher_beacon.c:137`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacons/v1/gopher_beacon.c:190`
- Doc: === BEACON API ===

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacons/v1/gopher_beacon.c:202`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `beacons/v1/gopher_beacon.c:214`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `beacons/v1/gopher_beacon.c:250`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `beacons/v1/gopher_beacon.c:265`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacons/v1/gopher_beacon.c:297`
- Doc: === CURL WRITE CALLBACK ===

### gopher_request `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
- Defined: `beacons/v1/gopher_beacon.c:314`
- Doc: === GOPHER REQUEST () ===

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacons/v1/gopher_beacon.c:377`
- Doc: === BASE64 ===

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacons/v1/gopher_beacon.c:393`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacons/v1/gopher_beacon.c:417`
- Doc: === AES CFB ===

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacons/v1/gopher_beacon.c:444`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacons/v1/gopher_beacon.c:475`
- Doc: === EXEC CMD ===

### page_align `static size_t page_align(size_t size)`
- Defined: `beacons/v1/gopher_beacon.c:506`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacons/v1/gopher_beacon.c:511`

### get_local_ips `char* get_local_ips()`
- Defined: `beacons/v1/gopher_beacon.c:893`
- Doc: === GET LOCAL IPs ===

### download_bof `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
- Defined: `beacons/v1/gopher_beacon.c:922`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacons/v1/gopher_beacon.c:950`
- Doc: === RUN BOF AND CAPTURE ===

### main `int main()`
- Defined: `beacons/v1/gopher_beacon.c:994`
- Doc: === MAIN ===

## beacons/v2/beacon.c

### report_result `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v2/beacon.c:65`
- Doc: Mesh functions would be implemented here, but for this refactor we keep the same structure as v1 with mesh stubs. A prod

### execute_command `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v2/beacon.c:138`

### main `int main(void)`
- Defined: `beacons/v2/beacon.c:187`

## beacons/v3/beacon.c

### infrastructure `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
- Defined: `beacons/v3/beacon.c:7`

### compute_primes `static int compute_primes(int count)`
- Defined: `beacons/v3/beacon.c:35`

### evasive_sleep `static void evasive_sleep(int seconds)`
- Defined: `beacons/v3/beacon.c:45`

### report_result `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v3/beacon.c:51`

### execute_command `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v3/beacon.c:124`

### main `int main(void)`
- Defined: `beacons/v3/beacon.c:173`

## bof.c

### __attribute__ `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)`
- Defined: `bof.c:3`
- Doc: bof.c include "beacon.h"  // ← Incluir la API

## bof/cat/bof.c

### go `void go(char *args, int alen)`
- Defined: `bof/cat/bof.c:14`
- Doc: bof/cat/bof.c  Read a file from disk and stream it back through the beacon.  args/alen: a NUL-terminated path string. Th

## bof/cat/cat.c

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/cat/cat.c:21`
- Doc: Wrappers (copiados de tus ejemplos)

### go `void go(char *args, int alen)`
- Defined: `bof/cat/cat.c:30`

## bof/include/syscalls.h

### syscall0 `static inline long syscall0(long n)`
- Defined: `bof/include/syscalls.h:48`
- Doc: #define SYS_wait4      61 #define SYS_getuid     102 #define SYS_getgid     104 #define SYS_geteuid    107 #define SYS_g

### syscall1 `static inline long syscall1(long n, long a1)`
- Defined: `bof/include/syscalls.h:59`

### syscall2 `static inline long syscall2(long n, long a1, long a2)`
- Defined: `bof/include/syscalls.h:70`

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/include/syscalls.h:81`

### syscall4 `static inline long syscall4(long n, long a1, long a2, long a3, long a4)`
- Defined: `bof/include/syscalls.h:92`

### bsf_strlen `static inline size_t bsf_strlen(const char *s)`
- Defined: `bof/include/syscalls.h:106`
- Doc: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a

### bsf_strcmp `static inline int bsf_strcmp(const char *a, const char *b)`
- Defined: `bof/include/syscalls.h:113`
- Doc: : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; } /* strlen - libc is not linked. 

### bsf_memcmp `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)`
- Defined: `bof/include/syscalls.h:119`
- Doc: /* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; retu

## bof/is_sudo/bof.c

### user_in_group `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
- Defined: `bof/is_sudo/bof.c:14`
- Doc: bof/is_sudo/bof.c  Check whether the current user is in the sudo or wheel group.  Reads /etc/group, looks for the user's

### go `void go(char *args, int alen)`
- Defined: `bof/is_sudo/bof.c:56`

## bof/is_sudo/is_sudo.c

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/is_sudo/is_sudo.c:23`
- Doc: Wrappers

### syscall1 `static inline long syscall1(long n, long a1)`
- Defined: `bof/is_sudo/is_sudo.c:32`

### strcmp `static int strcmp(const char *s1, const char *s2)`
- Defined: `bof/is_sudo/is_sudo.c:44`
- Doc: strcmp mínimo (necesario para comparar strings)

### get_username_from_uid `static int get_username_from_uid(long uid, char *buf, int buf_size)`
- Defined: `bof/is_sudo/is_sudo.c:53`
- Doc: Obtener username desde /etc/passwd (sin libc)

### go `void go(char *args, int alen)`
- Defined: `bof/is_sudo/is_sudo.c:108`

## bof/suid_enum/bof.c

### flush_output `static void flush_output(void)`
- Defined: `bof/suid_enum/bof.c:75`

### emit `static void emit(const char *s)`
- Defined: `bof/suid_enum/bof.c:82`

### format_mode `static void format_mode(unsigned int mode, char *out)`
- Defined: `bof/suid_enum/bof.c:105`
- Doc: Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.

### path_reset `static void path_reset(const char *root)`
- Defined: `bof/suid_enum/bof.c:125`

### path_append `static void path_append(const char *name)`
- Defined: `bof/suid_enum/bof.c:134`

### path_trim_to `static void path_trim_to(int len)`
- Defined: `bof/suid_enum/bof.c:148`

### walk `static void walk(int depth)`
- Defined: `bof/suid_enum/bof.c:158`
- Doc: Walk one directory, recursing into subdirectories. `depth` * bounds the recursion so a symlink loop cannot blow the stac

### go `void go(char *args, int alen)`
- Defined: `bof/suid_enum/bof.c:246`

## bof/userenum/bof.c

### user_in_member_list `static int user_in_member_list(const char *username, const char *members)`
- Defined: `bof/userenum/bof.c:51`

### go `void go(char *args, int alen)`
- Defined: `bof/userenum/bof.c:67`

## bof/userenum/userenum.c

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/userenum/userenum.c:21`
- Doc: Wrappers

### strcmp `static int strcmp(const char *s1, const char *s2)`
- Defined: `bof/userenum/userenum.c:33`
- Doc: strcmp mínimo (necesario para comparar strings)

### go `void go(char *args, int alen)`
- Defined: `bof/userenum/userenum.c:40`

## bof/whoami/bof.c

### go `void go(char *args, int alen)`
- Defined: `bof/whoami/bof.c:18`
- Doc: BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the * beacon's loader resolves by symbol name.

## bof/whoami/whoami.c

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/whoami/whoami.c:21`
- Doc: Syscall wrappers

### syscall1 `static inline long syscall1(long n, long a1)`
- Defined: `bof/whoami/whoami.c:30`

### go `void go(char *args, int alen)`
- Defined: `bof/whoami/whoami.c:40`

## c2/server.py

### load_runtime_config `def load_runtime_config()`
- Defined: `c2/server.py:59`
- Doc: Load configuration from JSON file or use defaults.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### compute_hmac `def compute_hmac(key, data)`
- Defined: `c2/server.py:86`
- Doc: Compute HMAC-SHA256 for message authentication.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### verify_hmac `def verify_hmac(key, data, signature)`
- Defined: `c2/server.py:91`
- Doc: Verify HMAC-SHA256 signature.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### encrypt_data `def encrypt_data(data, key, use_hmac)`
- Defined: `c2/server.py:97`
- Doc: Encrypt data with AES-256-CFB and optional HMAC.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### decrypt_data `def decrypt_data(b64_data, key, use_hmac)`
- Defined: `c2/server.py:117`
- Doc: Decrypt AES-256-CFB data with optional HMAC verification.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_get_command `def handle_get_command(state, selector)`
- Defined: `c2/server.py:150`
- Doc: Dispatch beacon's polling GET request.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_report `def handle_report(state, b64_payload)`
- Defined: `c2/server.py:173`
- Doc: Process beacon result report.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_bof `def handle_bof(state, name)`
- Defined: `c2/server.py:229`
- Doc: Serve BOF file from upload directory.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_request `def handle_request(state, selector)`
- Defined: `c2/server.py:239`
- Doc: Route request to appropriate handler.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### serve_client `def serve_client(state, conn, addr)`
- Defined: `c2/server.py:272`
- Doc: Handle individual client connection.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### command_injector `def command_injector(state)`
- Defined: `c2/server.py:294`
- Doc: Interactive command injection REPL.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### main `def main()`
- Defined: `c2/server.py:317`
- Doc: Start C2 server.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### __init__ `def __init__(self, cfg)`
- Defined: `c2/server.py:139`
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

## cJSON.c

### CJSON_PUBLIC `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:94`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:99`

### CJSON_PUBLIC `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:109`

### CJSON_PUBLIC `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 

### case_insensitive_strcmp `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)

### internal_malloc `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s

### internal_free `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `cJSON.c:170`

### internal_realloc `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `cJSON.c:174`

### cJSON_strdup `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `cJSON.c:188`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:209`

### cJSON_New_Item `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar

### get_decimal_point `static unsigned char get_decimal_point(void)`
- Defined: `cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate

### parse_number `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks

### ensure `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form

### update_offset `static void update_offset(printbuffer * const buffer)`
- Defined: `cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt

### compare_double `static cJSON_bool compare_double(double a, double b)`
- Defined: `cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *

### print_number `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely

### parse_hex4 `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of

### utf16_literal_to_utf8 `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX

### parse_string `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length

### print_string_ptr `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(

### print_string `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b

### buffer_skip_whitespace `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char

### skip_utf8_bom `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `cJSON.c:1133`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1235`

### print `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1315`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1351`

### parse_value `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =

### print_value `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input

### parse_array `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 

### print_array `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 

### parse_object `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_

### print_object `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object

### get_array_item `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `cJSON.c:1915`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1934`

### get_object_item `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1944`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1976`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1986`

### suffix_object `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co

### create_reference `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec

### add_item_to_array `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2020`

### cast_away_const `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_

### add_item_to_object `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2111`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2122`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2132`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2142`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2154`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2166`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2178`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2190`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2202`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2214`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2226`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2238`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2250`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2286`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2296`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2301`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2308`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2315`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2362`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2412`

### replace_item_in_object `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2422`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2445`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2450`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2467`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2478`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2489`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2500`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2525`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2542`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2554`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2566`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2578`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2595`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2606`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2658`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2698`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2738`

### cJSON_Duplicate_rec `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2785`

### skip_oneline_comment `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2872`

### skip_multiline_comment `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2885`

### minify_string `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2899`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2921`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2971`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2991`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3001`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3011`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3021`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3031`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3041`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3051`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3061`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3071`

### cJSON_ArrayForEach `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`

### cJSON_ArrayForEach `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju

### CJSON_PUBLIC `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3193`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3198`

## gopher_beacon.c

### __attribute__ `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `gopher_beacon.c:137`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `gopher_beacon.c:190`
- Doc: === BEACON API ===

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `gopher_beacon.c:202`

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `gopher_beacon.c:214`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines `static void cleanup_trampolines(void)`
- Defined: `gopher_beacon.c:250`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline `static void* get_or_create_trampoline(void* target)`
- Defined: `gopher_beacon.c:265`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `gopher_beacon.c:297`
- Doc: === CURL WRITE CALLBACK ===

### gopher_request `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
- Defined: `gopher_beacon.c:314`
- Doc: === GOPHER REQUEST () ===

### base64_encode `char* base64_encode(const unsigned char* input, int len)`
- Defined: `gopher_beacon.c:377`
- Doc: === BASE64 ===

### base64_decode `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `gopher_beacon.c:393`

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `gopher_beacon.c:417`
- Doc: === AES CFB ===

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `gopher_beacon.c:444`

### exec_cmd `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `gopher_beacon.c:475`
- Doc: === EXEC CMD ===

### page_align `static size_t page_align(size_t size)`
- Defined: `gopher_beacon.c:506`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `gopher_beacon.c:511`

### get_local_ips `char* get_local_ips()`
- Defined: `gopher_beacon.c:893`
- Doc: === GET LOCAL IPs ===

### download_bof `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
- Defined: `gopher_beacon.c:922`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `gopher_beacon.c:950`
- Doc: === RUN BOF AND CAPTURE ===

### main `int main()`
- Defined: `gopher_beacon.c:994`
- Doc: === MAIN ===

## gopher_c2.py

### encrypt_data `def encrypt_data(data)`
- Defined: `gopher_c2.py:28`

### decrypt_data `def decrypt_data(b64_data)`
- Defined: `gopher_c2.py:37`

### handle_client `def handle_client(conn, addr)`
- Defined: `gopher_c2.py:45`

### main `def main()`
- Defined: `gopher_c2.py:127`

### command_injector `def command_injector()`
- Defined: `gopher_c2.py:136`

## include/aes.c

### __attribute__ `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)`
- Defined: `include/aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16

### __attribute__ `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)`
- Defined: `include/aes.c:34`

### __attribute__ `static __attribute__((unused)) uint8_t Td0(int x)`
- Defined: `include/aes.c:56`

### __attribute__ `static __attribute__((unused)) uint8_t Td1(int x)`
- Defined: `include/aes.c:58`

### __attribute__ `static __attribute__((unused)) uint8_t Td2(int x)`
- Defined: `include/aes.c:59`

### __attribute__ `static __attribute__((unused)) uint8_t Td3(int x)`
- Defined: `include/aes.c:60`

### __attribute__ `static __attribute__((unused)) uint8_t Td4(int x)`
- Defined: `include/aes.c:61`

### KeyExpansion `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `include/aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.

### AES_init_ctx `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `include/aes.c:238`

### AES_init_ctx_iv `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `include/aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

### AES_ctx_set_iv `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `include/aes.c:249`

### AddRoundKey `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.

### SubBytes `static void SubBytes(state_t* state)`
- Defined: `include/aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### ShiftRows `static void ShiftRows(state_t* state)`
- Defined: `include/aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R

### xtime `static uint8_t xtime(uint8_t x)`
- Defined: `include/aes.c:313`

### MixColumns `static void MixColumns(state_t* state)`
- Defined: `include/aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix

### Multiply `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `include/aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 

### InvMixColumns `static void InvMixColumns(state_t* state)`
- Defined: `include/aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo

### InvSubBytes `static void InvSubBytes(state_t* state)`
- Defined: `include/aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### InvShiftRows `static void InvShiftRows(state_t* state)`
- Defined: `include/aes.c:402`

### Cipher `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.

### InvCipher `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

### AES_ECB_encrypt `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `include/aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&

### AES_ECB_decrypt `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `include/aes.c:495`

### XorWithIv `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `include/aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)

### AES_CBC_encrypt_buffer `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:520`

### AES_CBC_decrypt_buffer `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:535`

### AES_CTR_xcrypt_buffer `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)

## include/aes_cfb.c

### aes256_cfb_encrypt `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `include/aes_cfb.c:19`
- Doc: This is the same algorithm the v1 beacon uses to wrap C2 commands and results. The C2 server in c2/server.py implements 

### aes256_cfb_decrypt `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `include/aes_cfb.c:47`

## include/beacon_common.c

### bsb_output_init `int bsb_output_init(size_t capacity)`
- Defined: `include/beacon_common.c:100`
- Doc: { "BeaconOutput",   &g_BeaconOutput_ptr }, { "socket",         &g_socket_ptr }, { "connect",        &g_connect_ptr }, { 

### bsb_output_cleanup `void bsb_output_cleanup(void)`
- Defined: `include/beacon_common.c:109`

### bsb_output_reset `void bsb_output_reset(void)`
- Defined: `include/beacon_common.c:116`

### BeaconPrintf `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `include/beacon_common.c:125`
- Doc: free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; } void bsb_output_reset(void) { 

### BeaconOutput `void BeaconOutput(int type, const char *data, int len)`
- Defined: `include/beacon_common.c:137`

### create_trampoline `void *create_trampoline(void *target)`
- Defined: `include/beacon_common.c:151`
- Doc: void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data) return; 

### cleanup_trampolines `void cleanup_trampolines(void)`
- Defined: `include/beacon_common.c:180`

### get_or_create_trampoline `void *get_or_create_trampoline(void *target)`
- Defined: `include/beacon_common.c:195`

### WriteMemoryCallback `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `include/beacon_common.c:224`

### https_request `http_response_t https_request(const bsb_config_t *cfg, const char *url,
                         ...`
- Defined: `include/beacon_common.c:236`

### base64_encode `char *base64_encode(const unsigned char *input, int len)`
- Defined: `include/beacon_common.c:291`
- Doc: curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

### base64_decode `unsigned char *base64_decode(const char *input, int *len)`
- Defined: `include/beacon_common.c:306`

### _is_unreserved `static int _is_unreserved(unsigned char c)`
- Defined: `include/beacon_common.c:329`
- Doc: if (!buffer) { BIO_free_all(b64); return NULL; } len = BIO_read(b64, buffer, input_len); BIO_free_all(b64); if (*len <= 

### url_encode `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
- Defined: `include/beacon_common.c:334`

### exec_cmd `char *exec_cmd(const char *cmd, int *out_len)`
- Defined: `include/beacon_common.c:358`
- Doc: static const char hex[] = "0123456789ABCDEF"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c & 0xF]; }

### bsb_backoff_init `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)`
- Defined: `include/beacon_common.c:385`
- Doc: if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; } } pc

### bsb_backoff_next `int bsb_backoff_next(bsb_backoff_t *bo)`
- Defined: `include/beacon_common.c:390`

### bsb_backoff_reset `void bsb_backoff_reset(bsb_backoff_t *bo)`
- Defined: `include/beacon_common.c:399`

### get_local_ips `char *get_local_ips(void)`
- Defined: `include/beacon_common.c:405`
- Doc: int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if (bo->current_secon

### download_bof `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)`
- Defined: `include/beacon_common.c:434`
- Doc: for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family == 

### init_function_pointers `static void init_function_pointers(void)`
- Defined: `include/beacon_common.c:446`
- Doc: /* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) { http_r

### page_align `static size_t page_align(size_t size)`
- Defined: `include/beacon_common.c:471`

### __attribute__ `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar...`
- Defined: `include/beacon_common.c:477`

### RunELF `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- Defined: `include/beacon_common.c:506`

### run_bof_and_capture `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           ...`
- Defined: `include/beacon_common.c:710`

## include/cJSON.c

### CJSON_PUBLIC `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `include/cJSON.c:94`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `include/cJSON.c:99`

### CJSON_PUBLIC `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `include/cJSON.c:109`

### CJSON_PUBLIC `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `include/cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 

### case_insensitive_strcmp `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `include/cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)

### internal_malloc `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `include/cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s

### internal_free `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `include/cJSON.c:170`

### internal_realloc `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `include/cJSON.c:174`

### cJSON_strdup `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:188`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `include/cJSON.c:209`

### cJSON_New_Item `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar

### get_decimal_point `static unsigned char get_decimal_point(void)`
- Defined: `include/cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate

### parse_number `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks

### ensure `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `include/cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form

### update_offset `static void update_offset(printbuffer * const buffer)`
- Defined: `include/cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt

### compare_double `static cJSON_bool compare_double(double a, double b)`
- Defined: `include/cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *

### print_number `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely

### parse_hex4 `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `include/cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of

### utf16_literal_to_utf8 `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `include/cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX

### parse_string `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length

### print_string_ptr `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `include/cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(

### print_string `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `include/cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b

### buffer_skip_whitespace `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `include/cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char

### skip_utf8_bom `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `include/cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `include/cJSON.c:1133`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `include/cJSON.c:1235`

### print `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `include/cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `include/cJSON.c:1315`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `include/cJSON.c:1320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `include/cJSON.c:1351`

### parse_value `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =

### print_value `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input

### parse_array `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 

### print_array `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 

### parse_object `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_

### print_object `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object

### get_array_item `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `include/cJSON.c:1915`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `include/cJSON.c:1934`

### get_object_item `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `include/cJSON.c:1944`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `include/cJSON.c:1976`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `include/cJSON.c:1981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `include/cJSON.c:1986`

### suffix_object `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `include/cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co

### create_reference `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec

### add_item_to_array `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `include/cJSON.c:2020`

### cast_away_const `static void* cast_away_const(const void* string)`
- Defined: `include/cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_

### add_item_to_object `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `include/cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `include/cJSON.c:2111`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `include/cJSON.c:2122`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `include/cJSON.c:2132`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2142`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2154`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2166`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `include/cJSON.c:2178`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `include/cJSON.c:2190`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `include/cJSON.c:2202`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `include/cJSON.c:2214`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2226`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2238`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `include/cJSON.c:2250`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `include/cJSON.c:2286`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `include/cJSON.c:2296`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2301`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2308`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2315`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `include/cJSON.c:2362`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `include/cJSON.c:2412`

### replace_item_in_object `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `include/cJSON.c:2422`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `include/cJSON.c:2445`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `include/cJSON.c:2450`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `include/cJSON.c:2467`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `include/cJSON.c:2478`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `include/cJSON.c:2489`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `include/cJSON.c:2500`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `include/cJSON.c:2525`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `include/cJSON.c:2542`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `include/cJSON.c:2554`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `include/cJSON.c:2566`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `include/cJSON.c:2578`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `include/cJSON.c:2595`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `include/cJSON.c:2606`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `include/cJSON.c:2658`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `include/cJSON.c:2698`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `include/cJSON.c:2738`

### cJSON_Duplicate_rec `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `include/cJSON.c:2785`

### skip_oneline_comment `static void skip_oneline_comment(char **input)`
- Defined: `include/cJSON.c:2872`

### skip_multiline_comment `static void skip_multiline_comment(char **input)`
- Defined: `include/cJSON.c:2885`

### minify_string `static void minify_string(char **input, char **output)`
- Defined: `include/cJSON.c:2899`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `include/cJSON.c:2921`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `include/cJSON.c:2971`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `include/cJSON.c:2981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `include/cJSON.c:2991`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `include/cJSON.c:3001`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `include/cJSON.c:3011`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `include/cJSON.c:3021`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `include/cJSON.c:3031`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `include/cJSON.c:3041`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `include/cJSON.c:3051`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `include/cJSON.c:3061`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `include/cJSON.c:3071`

### cJSON_ArrayForEach `cJSON_ArrayForEach(a_element, a)`
- Defined: `include/cJSON.c:3157`

### cJSON_ArrayForEach `cJSON_ArrayForEach(b_element, b)`
- Defined: `include/cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju

### CJSON_PUBLIC `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `include/cJSON.c:3193`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `include/cJSON.c:3198`

## include/config.c

### slurp `static char *slurp(const char *path, size_t *out_len)`
- Defined: `include/config.c:24`
- Doc: declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #define _POSIX_C_SOURCE 

### skip_ws `static const char *skip_ws(const char *p, const char *end)`
- Defined: `include/config.c:41`
- Doc: fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf = (cha

### read_string `static int read_string(const char **pp, const char *end, char *out, size_t outsz)`
- Defined: `include/config.c:49`
- Doc: Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string into out (NUL termina

### read_int `static int read_int(const char **pp, const char *end, int *out)`
- Defined: `include/config.c:75`

### read_bool `static int read_bool(const char **pp, const char *end, int *out)`
- Defined: `include/config.c:91`

### expect `static int expect(const char **pp, const char *end, char c)`
- Defined: `include/config.c:100`
- Doc: } out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *end, int *out) { cons

### find_matching_brace `static const char *find_matching_brace(const char *p, const char *end)`
- Defined: `include/config.c:109`
- Doc: Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and escape rules.

### skip_value `static const char *skip_value(const char *p, const char *end)`
- Defined: `include/config.c:132`
- Doc: Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or NUL

### hex_to_bytes `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)`
- Defined: `include/config.c:174`
- Doc: else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if (c =

### parse_c2 `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:186`
- Doc: /* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen = strlen(hex);

### parse_crypto `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:208`

### parse_timing `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:229`

### parse_network `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:252`

### parse_bof `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:288`

### parse_backoff `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:307`

### bsb_config_load `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)`
- Defined: `include/config.c:328`
- Doc: if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end, &cfg->backoff.base_seconds

### binary_dir `static const char *binary_dir(char *out, size_t outsz)`
- Defined: `include/config.c:420`
- Doc: Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without /proc/self/

### bsb_config_load_default `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- Defined: `include/config.c:437`

### bsb_config_sleep_seconds `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
- Defined: `include/config.c:465`

## include/config_py.py

### _deep_merge `def _deep_merge(base, overlay)`
- Defined: `include/config_py.py:55`
- Doc: Recursively merge overlay into base; overlay wins.
- Imported by: `c2/server.py`

### load_config `def load_config(path)`
- Defined: `include/config_py.py:65`
- Doc: Load and validate a BSB config file.
- Imported by: `c2/server.py`

## issudo.c

### syscall3 `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `issudo.c:22`
- Doc: Wrappers

### syscall1 `static inline long syscall1(long n, long a1)`
- Defined: `issudo.c:31`

### strcmp `static int strcmp(const char *s1, const char *s2)`
- Defined: `issudo.c:43`
- Doc: strcmp mínimo (necesario para comparar strings)

### get_username_from_uid `static int get_username_from_uid(long uid, char *buf, int buf_size)`
- Defined: `issudo.c:52`
- Doc: Obtener username desde /etc/passwd (sin libc)

### go `void go(char *args, int alen)`
- Defined: `issudo.c:107`

## tests/config_harness.c

### main `int main(void)`
- Defined: `tests/config_harness.c:21`

## tests/crypto_harness.c

### hex_to_bytes `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)`
- Defined: `tests/crypto_harness.c:11`
- Doc: crypto_harness.c - Roundtrip test harness for AES-256-CFB.  Used by tests/test_crypto.py to validate the AES path the be

### main `int main(int argc, char **argv)`
- Defined: `tests/crypto_harness.c:22`

## tests/test_beacon_build.py

### have_headers `def have_headers()`
- Defined: `tests/test_beacon_build.py:20`
- Doc: Return True if openssl and curl headers are present.

### compile_beacon `def compile_beacon()`
- Defined: `tests/test_beacon_build.py:34`

### inspect_binary `def inspect_binary()`
- Defined: `tests/test_beacon_build.py:50`

### test_beacon_compiles_and_links `def test_beacon_compiles_and_links()`
- Defined: `tests/test_beacon_build.py:55`

### test_beacon_exposes_bof_api `def test_beacon_exposes_bof_api()`
- Defined: `tests/test_beacon_build.py:64`

### test_beacon_exposes_elf_loader `def test_beacon_exposes_elf_loader()`
- Defined: `tests/test_beacon_build.py:85`

### main `def main()`
- Defined: `tests/test_beacon_build.py:96`

## tests/test_bof_compile.py

### compile_bof `def compile_bof(name)`
- Defined: `tests/test_bof_compile.py:21`

### inspect_symbols `def inspect_symbols(obj_path)`
- Defined: `tests/test_bof_compile.py:35`

### test_compile_all `def test_compile_all()`
- Defined: `tests/test_bof_compile.py:53`

### test_export_go `def test_export_go()`
- Defined: `tests/test_bof_compile.py:60`

### test_unresolved_beacon_api `def test_unresolved_beacon_api()`
- Defined: `tests/test_bof_compile.py:68`

### test_no_libc_leak `def test_no_libc_leak()`
- Defined: `tests/test_bof_compile.py:80`
- Doc: Make sure we did not pull in glibc symbols by accident.

### main `def main()`
- Defined: `tests/test_bof_compile.py:91`

## tests/test_c2_http_e2e.py

### _free_port `def _free_port()`
- Defined: `tests/test_c2_http_e2e.py:43`

### _recv_response `def _recv_response(sock, timeout)`
- Defined: `tests/test_c2_http_e2e.py:51`

### test_http_get_poll_returns_encrypted_command `def test_http_get_poll_returns_encrypted_command()`
- Defined: `tests/test_c2_http_e2e.py:65`
- Doc: Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64

### test_http_post_report_writes_log `def test_http_post_report_writes_log()`
- Defined: `tests/test_c2_http_e2e.py:115`
- Doc: Beacon-style HTTP/1.1 POST /report/<b64> must reach the

### test_gopher_legacy_still_works `def test_gopher_legacy_still_works()`
- Defined: `tests/test_c2_http_e2e.py:183`
- Doc: The old Gopher-style selector (single line, CRLF) must

### test_http_post_with_url_encoded_b64_payload `def test_http_post_with_url_encoded_b64_payload()`
- Defined: `tests/test_c2_http_e2e.py:233`
- Doc: The beacon percent-encodes the base64 payload before

### test_fragmented_post_is_dispatched_as_http `def test_fragmented_post_is_dispatched_as_http()`
- Defined: `tests/test_c2_http_e2e.py:326`
- Doc: When the client sends a long POST URL that crosses a TCP

### main `def main()`
- Defined: `tests/test_c2_http_e2e.py:399`

### encode `def encode(s)`
- Defined: `tests/test_c2_http_e2e.py:274`

## tests/test_c2_server.py

### make_state `def make_state(tmp)`
- Defined: `tests/test_c2_server.py:39`
- Depends on: `c2/server.py`

### test_get_command_empty `def test_get_command_empty()`
- Defined: `tests/test_c2_server.py:46`
- Depends on: `c2/server.py`

### test_get_command_queued `def test_get_command_queued()`
- Defined: `tests/test_c2_server.py:58`
- Depends on: `c2/server.py`

### test_report_writes_log `def test_report_writes_log()`
- Defined: `tests/test_c2_server.py:69`
- Depends on: `c2/server.py`

### test_bof_not_found `def test_bof_not_found()`
- Defined: `tests/test_c2_server.py:85`
- Depends on: `c2/server.py`

### test_bof_serves_existing_file `def test_bof_serves_existing_file()`
- Defined: `tests/test_c2_server.py:92`
- Depends on: `c2/server.py`

### test_unknown_selector `def test_unknown_selector()`
- Defined: `tests/test_c2_server.py:104`
- Depends on: `c2/server.py`

### test_path_traversal_in_bof_name `def test_path_traversal_in_bof_name()`
- Defined: `tests/test_c2_server.py:111`
- Doc: Path-traversal in /bof/ should be neutralised by os.path.basename.
- Depends on: `c2/server.py`

### test_roundtrip_empty `def test_roundtrip_empty()`
- Defined: `tests/test_c2_server.py:120`
- Doc: encrypt then decrypt empty payload must yield single NUL byte.
- Depends on: `c2/server.py`

### test_roundtrip_text `def test_roundtrip_text()`
- Defined: `tests/test_c2_server.py:127`
- Depends on: `c2/server.py`

### main `def main()`
- Defined: `tests/test_c2_server.py:134`
- Depends on: `c2/server.py`

## tests/test_config.py

### compile_harness `def compile_harness()`
- Defined: `tests/test_config.py:24`
- Doc: Build the test harness against config.c.

### run_harness `def run_harness(config_text)`
- Defined: `tests/test_config.py:38`
- Doc: Write a config file, run the harness, return parsed output.

### test_default_load `def test_default_load()`
- Defined: `tests/test_config.py:55`

### test_overrides `def test_overrides()`
- Defined: `tests/test_config.py:73`

### test_missing_file `def test_missing_file()`
- Defined: `tests/test_config.py:90`

### test_search_order_env_wins `def test_search_order_env_wins()`
- Defined: `tests/test_config.py:98`
- Doc: $BSB_CONFIG must take precedence over the binary-relative path.

### test_search_order_falls_back_to_cwd_default `def test_search_order_falls_back_to_cwd_default()`
- Defined: `tests/test_config.py:115`
- Doc: With BSB_CONFIG unset, the harness resolves to ./config.json

### test_bad_hex_key `def test_bad_hex_key()`
- Defined: `tests/test_config.py:141`

### main `def main()`
- Defined: `tests/test_config.py:156`

## tests/test_crypto.py

### compile_harness `def compile_harness()`
- Defined: `tests/test_crypto.py:18`

### run `def run(plaintext, key_hex)`
- Defined: `tests/test_crypto.py:32`

### test_short `def test_short()`
- Defined: `tests/test_crypto.py:40`

### test_block_boundary `def test_block_boundary()`
- Defined: `tests/test_crypto.py:44`

### test_longer_than_block `def test_longer_than_block()`
- Defined: `tests/test_crypto.py:49`

### test_known_ciphertext `def test_known_ciphertext()`
- Defined: `tests/test_crypto.py:55`

### test_python_can_decrypt_c_ciphertext `def test_python_can_decrypt_c_ciphertext()`
- Defined: `tests/test_crypto.py:74`
- Doc: The Python C2 server must be able to decrypt C-encrypted

### main `def main()`
- Defined: `tests/test_crypto.py:107`

## tests/test_install_deploy.py

### make_all `def make_all()`
- Defined: `tests/test_install_deploy.py:23`
- Doc: Clean and build everything, return nothing.

### run_beacon `def run_beacon(binary, cwd)`
- Defined: `tests/test_install_deploy.py:29`

### test_build_beacon_lands_alongside_config `def test_build_beacon_lands_alongside_config()`
- Defined: `tests/test_install_deploy.py:42`
- Doc: The point of this whole iteration: `make beacon` leaves

### test_staged_files_have_correct_modes `def test_staged_files_have_correct_modes()`
- Defined: `tests/test_install_deploy.py:53`

### test_staged_beacon_runs_from_any_cwd `def test_staged_beacon_runs_from_any_cwd()`
- Defined: `tests/test_install_deploy.py:61`
- Doc: Drop the operator in /tmp; the staged beacon should still

### test_staged_bofs_are_present `def test_staged_bofs_are_present()`
- Defined: `tests/test_install_deploy.py:74`

### test_clean_removes_everything `def test_clean_removes_everything()`
- Defined: `tests/test_install_deploy.py:82`
- Doc: make clean must wipe build/ — including the staged config.json —

### main `def main()`
- Defined: `tests/test_install_deploy.py:104`
