# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_CBC_decrypt_buffer` | function | `aes.c:535` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:520` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:495` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `aes.c:488` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `aes.c:238` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `aes.c:402` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `aes.c:6` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:4` | `#define Nb` |
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
| `Td0` | function | `aes.c:56` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:58` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:59` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:60` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:61` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:510` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `getSBoxInvert` | function | `aes.c:34` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:12` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:163` | `#define getSBoxValue(num)` |
| `memcpy` | function | `aes.c:247` | `memcpy (ctx->Iv, iv, AES_BLOCKLEN);` |
| `xtime` | function | `aes.c:313` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:17` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:19` | `#define AES_BLOCKLEN` |
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
| `AES_init_ctx` | function | `aes.h:40` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
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
| `AES_ECB_encrypt` | function | `beacon3.c:457` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `beacon3.c:449` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `beacon3.c:414` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `beacon3.c:419` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `beacon3.c:415` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `beacon3.c:412` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `beacon3.c:413` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `beacon3.c:205` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon3.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon3.c:32` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon3.c:34` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon3.c:35` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon3.c:50` | `` |
| `RAND_bytes` | function | `beacon3.c:1158` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `beacon3.c:530` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...` |
| `SymbolResolver` | struct | `beacon3.c:65` | `` |
| `Trampoline` | struct | `beacon3.c:57` | `` |
| `TrampolineCache` | struct | `beacon3.c:71` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon3.c:36` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon3.c:300` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon3.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon3.c:140` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon3.c:473` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacon3.c:446` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacon3.c:422` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon3.c:406` | `char* base64_encode(const unsigned char* input, int len)` |
| `cJSON_AddNullToObject` | function | `beacon3.c:1138` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacon3.c:1133` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacon3.c:1130` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacon3.c:1142` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `beacon3.c:897` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `beacon3.c:253` | `static void cleanup_trampolines(void)` |
| `close` | function | `beacon3.c:920` | `close(sockfd);` |
| `create_trampoline` | function | `beacon3.c:217` | `static void* create_trampoline(void* target)` |
| `curl_easy_cleanup` | function | `beacon3.c:380` | `curl_easy_cleanup(curl);` |
| `curl_easy_setopt` | function | `beacon3.c:335` | `curl_easy_setopt(curl, CURLOPT_URL, url);` |
| `download_bof` | function | `beacon3.c:941` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon3.c:504` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `fflush` | function | `beacon3.c:321` | `fflush(stderr);` |
| `fprintf` | function | `beacon3.c:224` | `fprintf(stderr, "[!] Trampolín: mmap falló\n");` |
| `free` | function | `beacon3.c:257` | `free(g_trampolines);` |
| `get_local_ips` | function | `beacon3.c:912` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon3.c:268` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `beacon3.c:1122` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `https_request` | function | `beacon3.c:317` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `inet_ntop` | function | `beacon3.c:931` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `main` | function | `beacon3.c:1007` | `int main()` |
| `memcpy` | function | `beacon3.c:211` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `beacon3.c:466` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `munmap` | function | `beacon3.c:240` | `munmap(code, code_size);` |
| `page_align` | function | `beacon3.c:525` | `static size_t page_align(size_t size)` |
| `pclose` | function | `beacon3.c:509` | `pclose(fp);` |
| `perror` | function | `beacon3.c:701` | `perror("calloc");` |
| `printf` | function | `beacon3.c:952` | `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);` |
| `run_bof_and_capture` | function | `beacon3.c:963` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `sleep` | function | `beacon3.c:1030` | `sleep(6);` |
| `snprintf` | function | `beacon3.c:1017` | `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);` |
| `srand` | function | `beacon3.c:1009` | `srand(time(NULL));` |
| `sscanf` | function | `beacon3.c:1013` | `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);` |
| `strcat` | function | `beacon3.c:933` | `strcat(result, ip);` |
| `strdup` | function | `beacon3.c:921` | `return strdup("127.0.0.1");` |
| `strlen` | function | `beacon3.c:937` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `va_end` | function | `beacon3.c:200` | `va_end(args);` |
| `va_start` | function | `beacon3.c:196` | `va_start(args, fmt);` |
| `void` | function | `beacon3.c:63` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `beacon3.c:146` | `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %` |
| `AES_ECB_encrypt` | function | `beacon5.c:499` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `beacon5.c:491` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `beacon5.c:456` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `beacon5.c:461` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `beacon5.c:457` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `beacon5.c:454` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `beacon5.c:455` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `beacon5.c:247` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon5.c:235` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon5.c:42` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon5.c:45` | `#define CLIENT_ID` |
| `DISCOVERY_INTERVAL` | macro | `beacon5.c:39` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacon5.c:38` | `#define DISCOVERY_PORT` |
| `FD_SET` | function | `beacon5.c:1190` | `FD_SET(sock, &readfds);` |
| `FD_ZERO` | function | `beacon5.c:1188` | `FD_ZERO(&readfds);` |
| `MALEABLE` | macro | `beacon5.c:46` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon5.c:35` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacon5.c:40` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacon5.c:41` | `#define MESH_MSG_SIZE` |
| `MemoryStruct` | struct | `beacon5.c:61` | `` |
| `RAND_bytes` | function | `beacon5.c:1627` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `beacon5.c:572` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...` |
| `SymbolResolver` | struct | `beacon5.c:106` | `` |
| `Trampoline` | struct | `beacon5.c:98` | `` |
| `TrampolineCache` | struct | `beacon5.c:112` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon5.c:47` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon5.c:342` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon5.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon5.c:182` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon5.c:515` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacon5.c:488` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacon5.c:464` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon5.c:448` | `char* base64_encode(const unsigned char* input, int len)` |
| `cJSON_AddNullToObject` | function | `beacon5.c:1607` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacon5.c:1602` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacon5.c:1599` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacon5.c:1611` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `beacon5.c:939` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `beacon5.c:295` | `static void cleanup_trampolines(void)` |
| `close` | function | `beacon5.c:962` | `close(sockfd);` |
| `create_trampoline` | function | `beacon5.c:259` | `static void* create_trampoline(void* target)` |
| `curl_easy_cleanup` | function | `beacon5.c:422` | `curl_easy_cleanup(curl);` |
| `curl_easy_setopt` | function | `beacon5.c:377` | `curl_easy_setopt(curl, CURLOPT_URL, url);` |
| `download_bof` | function | `beacon5.c:983` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon5.c:546` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `fflush` | function | `beacon5.c:363` | `fflush(stderr);` |
| `fprintf` | function | `beacon5.c:266` | `fprintf(stderr, "[!] Trampolín: mmap falló\n");` |
| `free` | function | `beacon5.c:299` | `free(g_trampolines);` |
| `get_local_ips` | function | `beacon5.c:954` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon5.c:310` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `beacon5.c:1591` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `https_request` | function | `beacon5.c:359` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `inet_ntop` | function | `beacon5.c:973` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `inet_pton` | function | `beacon5.c:1117` | `inet_pton(AF_INET, ip, &addr.sin_addr);` |
| `listen` | function | `beacon5.c:1257` | `listen(server_sock, 10);` |
| `main` | function | `beacon5.c:1444` | `int main(int argc, char **argv)` |
| `memcpy` | function | `beacon5.c:253` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `beacon5.c:508` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `mesh_add_peer` | function | `beacon5.c:1069` | `void mesh_add_peer(const char *ip, int port)` |
| `mesh_cleanup_peers` | function | `beacon5.c:1094` | `void mesh_cleanup_peers()` |
| `mesh_discovery_thread` | function | `beacon5.c:1157` | `void *mesh_discovery_thread(void *arg)` |
| `mesh_is_seen` | function | `beacon5.c:1057` | `int mesh_is_seen(const char *msg_id)` |
| `mesh_listener_thread` | function | `beacon5.c:1240` | `void *mesh_listener_thread(void *arg)` |
| `mesh_mark_seen` | function | `beacon5.c:1049` | `void mesh_mark_seen(const char *msg_id)` |
| `mesh_msg_t` | struct | `beacon5.c:75` | `` |
| `mesh_propagate` | function | `beacon5.c:1130` | `void mesh_propagate(const char *command)` |
| `mesh_send_message` | function | `beacon5.c:1416` | `void mesh_send_message(int type, const char* target, const char* payload)` |
| `mesh_send_to_peer` | function | `beacon5.c:1108` | `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)` |
| `munmap` | function | `beacon5.c:282` | `munmap(code, code_size);` |
| `page_align` | function | `beacon5.c:567` | `static size_t page_align(size_t size)` |
| `pclose` | function | `beacon5.c:551` | `pclose(fp);` |
| `peer_t` | struct | `beacon5.c:68` | `` |
| `perror` | function | `beacon5.c:743` | `perror("calloc");` |
| `printf` | function | `beacon5.c:994` | `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);` |
| `pthread_detach` | function | `beacon5.c:1468` | `pthread_detach(tid_discovery);` |
| `pthread_mutex_init` | function | `beacon5.c:1460` | `pthread_mutex_init(&g_mesh.peers_mutex, NULL);` |
| `pthread_mutex_lock` | function | `beacon5.c:1051` | `pthread_mutex_lock(&g_mesh.seen_mutex);` |
| `pthread_mutex_unlock` | function | `beacon5.c:1055` | `pthread_mutex_unlock(&g_mesh.seen_mutex);` |
| `run_bof_and_capture` | function | `beacon5.c:1005` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `send` | function | `beacon5.c:1126` | `send(sock, buffer, len, 0);` |
| `sendto` | function | `beacon5.c:1200` | `sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&bcast, sizeof(bcast));` |
| `setsockopt` | function | `beacon5.c:1113` | `setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));` |
| `sleep` | function | `beacon5.c:1494` | `sleep(6);` |
| `snprintf` | function | `beacon5.c:1134` | `snprintf(msg.msg_id, sizeof(msg.msg_id), "%lx-%lx", (unsigned long)time(NULL), (unsigned long)rand());` |
| `srand` | function | `beacon5.c:1473` | `srand(time(NULL));` |
| `sscanf` | function | `beacon5.c:1477` | `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);` |
| `strcat` | function | `beacon5.c:975` | `strcat(result, ip);` |
| `strdup` | function | `beacon5.c:963` | `return strdup("127.0.0.1");` |
| `strlen` | function | `beacon5.c:979` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `strncpy` | function | `beacon5.c:1053` | `strncpy(g_mesh.seen_msgs[idx], msg_id, 63);` |
| `va_end` | function | `beacon5.c:242` | `va_end(args);` |
| `va_start` | function | `beacon5.c:238` | `va_start(args, fmt);` |
| `void` | function | `beacon5.c:104` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `beacon5.c:188` | `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %` |
| `AES_ECB_encrypt` | function | `beacon6.c:519` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `beacon6.c:511` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `beacon6.c:476` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `beacon6.c:481` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `beacon6.c:477` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `beacon6.c:474` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `beacon6.c:475` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `beacon6.c:267` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon6.c:255` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon6.c:34` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon6.c:36` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon6.c:37` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacon6.c:52` | `` |
| `RAND_bytes` | function | `beacon6.c:1228` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `beacon6.c:592` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...` |
| `SymbolResolver` | struct | `beacon6.c:67` | `` |
| `Trampoline` | struct | `beacon6.c:59` | `` |
| `TrampolineCache` | struct | `beacon6.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon6.c:38` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon6.c:362` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon6.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon6.c:142` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacon6.c:535` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacon6.c:508` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacon6.c:484` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon6.c:468` | `char* base64_encode(const unsigned char* input, int len)` |
| `cJSON_AddNullToObject` | function | `beacon6.c:1207` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacon6.c:1202` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacon6.c:1199` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacon6.c:1211` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `beacon6.c:959` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `beacon6.c:315` | `static void cleanup_trampolines(void)` |
| `close` | function | `beacon6.c:982` | `close(sockfd);` |
| `create_trampoline` | function | `beacon6.c:279` | `static void* create_trampoline(void* target)` |
| `curl_easy_cleanup` | function | `beacon6.c:442` | `curl_easy_cleanup(curl);` |
| `curl_easy_setopt` | function | `beacon6.c:397` | `curl_easy_setopt(curl, CURLOPT_URL, url);` |
| `delay_ms` | function | `beacon6.c:195` | `static void delay_ms(int ms)` |
| `download_bof` | function | `beacon6.c:1003` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon6.c:566` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `fflush` | function | `beacon6.c:383` | `fflush(stderr);` |
| `fprintf` | function | `beacon6.c:286` | `fprintf(stderr, "[!] Trampolín: mmap falló\n");` |
| `free` | function | `beacon6.c:319` | `free(g_trampolines);` |
| `get_local_ips` | function | `beacon6.c:974` | `char* get_local_ips()` |
| `get_nth_prime_limited` | function | `beacon6.c:218` | `static unsigned int get_nth_prime_limited(unsigned int n)` |
| `get_or_create_trampoline` | function | `beacon6.c:330` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `beacon6.c:1191` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `https_request` | function | `beacon6.c:379` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `inet_ntop` | function | `beacon6.c:993` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `is_prime` | function | `beacon6.c:202` | `static unsigned int is_prime(unsigned int x)` |
| `main` | function | `beacon6.c:1069` | `int main()` |
| `memcpy` | function | `beacon6.c:273` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `beacon6.c:528` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `munmap` | function | `beacon6.c:302` | `munmap(code, code_size);` |
| `page_align` | function | `beacon6.c:587` | `static size_t page_align(size_t size)` |
| `pclose` | function | `beacon6.c:571` | `pclose(fp);` |
| `perror` | function | `beacon6.c:763` | `perror("calloc");` |
| `poll` | function | `beacon6.c:197` | `poll(&p, 0, ms);` |
| `portable_rand_19k_29k` | function | `beacon6.c:242` | `static unsigned int portable_rand_19k_29k(void)` |
| `printf` | function | `beacon6.c:1014` | `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);` |
| `run_bof_and_capture` | function | `beacon6.c:1025` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `snprintf` | function | `beacon6.c:1082` | `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);` |
| `srand` | function | `beacon6.c:247` | `srand((unsigned int)time(NULL));` |
| `sscanf` | function | `beacon6.c:1075` | `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);` |
| `strcat` | function | `beacon6.c:995` | `strcat(result, ip);` |
| `strdup` | function | `beacon6.c:983` | `return strdup("127.0.0.1");` |
| `strlen` | function | `beacon6.c:999` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `va_end` | function | `beacon6.c:262` | `va_end(args);` |
| `va_start` | function | `beacon6.c:258` | `va_start(args, fmt);` |
| `void` | function | `beacon6.c:65` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `beacon6.c:148` | `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %` |
| `AES_ECB_encrypt` | function | `beacon_p2p.c:665` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `beacon_p2p.c:657` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `beacon_p2p.c:631` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `beacon_p2p.c:637` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `beacon_p2p.c:633` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `beacon_p2p.c:629` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `beacon_p2p.c:630` | `BIO_write(b64, input, len);` |
| `BROADCAST_INTERVAL` | macro | `beacon_p2p.c:46` | `#define BROADCAST_INTERVAL` |
| `BeaconDataExtract` | function | `beacon_p2p.c:120` | `char *BeaconDataExtract(datap *parser, int *size)` |
| `BeaconDataInt` | function | `beacon_p2p.c:104` | `int BeaconDataInt(datap *parser)` |
| `BeaconDataLength` | function | `beacon_p2p.c:116` | `int BeaconDataLength(datap *parser)` |
| `BeaconDataParse` | function | `beacon_p2p.c:91` | `void BeaconDataParse(datap *parser, char *buffer, int size)` |
| `BeaconDataPtr` | function | `beacon_p2p.c:96` | `char *BeaconDataPtr(datap *parser, int size)` |
| `BeaconDataShort` | function | `beacon_p2p.c:110` | `short BeaconDataShort(datap *parser)` |
| `BeaconOutput` | function | `beacon_p2p.c:141` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacon_p2p.c:128` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `beacon_p2p.c:37` | `#define C2_URL` |
| `CLIENT_ID` | macro | `beacon_p2p.c:38` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacon_p2p.c:39` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `beacon_p2p.c:47` | `#define MAX_PEERS` |
| `MemoryStruct` | struct | `beacon_p2p.c:549` | `` |
| `PEER_DISCOVERY_PORT` | macro | `beacon_p2p.c:41` | `#define PEER_DISCOVERY_PORT` |
| `PEER_MAGIC` | macro | `beacon_p2p.c:44` | `#define PEER_MAGIC` |
| `PEER_TCP_PORT` | macro | `beacon_p2p.c:43` | `#define PEER_TCP_PORT` |
| `PEER_VERSION` | macro | `beacon_p2p.c:45` | `#define PEER_VERSION` |
| `RAND_bytes` | function | `beacon_p2p.c:871` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `beacon_p2p.c:323` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...` |
| `SymbolResolver` | struct | `beacon_p2p.c:161` | `` |
| `Trampoline` | struct | `beacon_p2p.c:155` | `` |
| `TrampolineCache` | struct | `beacon_p2p.c:170` | `` |
| `USER_AGENTS_COUNT` | macro | `beacon_p2p.c:40` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacon_p2p.c:554` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacon_p2p.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacon_p2p.c:228` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `add_peer` | function | `beacon_p2p.c:783` | `void add_peer(struct in_addr ip, int port, const char *id)` |
| `aes256_cfb_decrypt` | function | `beacon_p2p.c:680` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacon_p2p.c:653` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacon_p2p.c:640` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacon_p2p.c:624` | `char* base64_encode(const unsigned char* input, int len)` |
| `bind` | function | `beacon_p2p.c:825` | `bind(udp_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));` |
| `cJSON_AddNullToObject` | function | `beacon_p2p.c:1105` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacon_p2p.c:1100` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacon_p2p.c:1097` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacon_p2p.c:1108` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `beacon_p2p.c:534` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `beacon_p2p.c:283` | `static void cleanup_trampolines(void)` |
| `close` | function | `beacon_p2p.c:737` | `close(sockfd);` |
| `create_trampoline` | function | `beacon_p2p.c:258` | `static void* create_trampoline(void* target)` |
| `curl_easy_cleanup` | function | `beacon_p2p.c:606` | `curl_easy_cleanup(curl);` |
| `curl_easy_setopt` | function | `beacon_p2p.c:579` | `curl_easy_setopt(curl, CURLOPT_URL, url);` |
| `download_bof` | function | `beacon_p2p.c:756` | `unsigned char* download_bof(const char* url, size_t* out_size)` |
| `exec_cmd` | function | `beacon_p2p.c:712` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `execute_generic_command` | function | `beacon_p2p.c:996` | `char* execute_generic_command(const char *cmd, int *out_len)` |
| `free` | function | `beacon_p2p.c:287` | `free(g_trampolines);` |
| `get_local_ips` | function | `beacon_p2p.c:728` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacon_p2p.c:296` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `beacon_p2p.c:817` | `gethostname(my_id, sizeof(my_id)-1);` |
| `handle_peer_connection` | function | `beacon_p2p.c:845` | `void *handle_peer_connection(void *arg)` |
| `https_request` | function | `beacon_p2p.c:574` | `char* https_request(const char* url, const char* method, const char* post_data)` |
| `inet_ntop` | function | `beacon_p2p.c:748` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `listen` | function | `beacon_p2p.c:922` | `listen(listen_fd, 10);` |
| `main` | function | `beacon_p2p.c:1031` | `int main()` |
| `memcpy` | function | `beacon_p2p.c:147` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `beacon_p2p.c:673` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `munmap` | function | `beacon_p2p.c:286` | `munmap(g_trampolines[i].addr, g_trampolines[i].size);` |
| `p2p_header_t` | struct | `beacon_p2p.c:72` | `` |
| `page_align` | function | `beacon_p2p.c:317` | `static size_t page_align(size_t size)` |
| `pclose` | function | `beacon_p2p.c:723` | `pclose(fp);` |
| `peer_discovery_thread` | function | `beacon_p2p.c:806` | `void *peer_discovery_thread(void *arg)` |
| `peer_server_thread` | function | `beacon_p2p.c:915` | `void *peer_server_thread(void *arg)` |
| `peer_t` | struct | `beacon_p2p.c:59` | `` |
| `printf` | function | `beacon_p2p.c:1032` | `printf("[*] Beacon P2P starting...\n");` |
| `pthread_create` | function | `beacon_p2p.c:929` | `pthread_create(&tid, NULL, handle_peer_connection, (void*)(intptr_t)client_fd);` |
| `pthread_detach` | function | `beacon_p2p.c:930` | `pthread_detach(tid);` |
| `pthread_mutex_lock` | function | `beacon_p2p.c:784` | `pthread_mutex_lock(&g_peer_lock);` |
| `pthread_mutex_unlock` | function | `beacon_p2p.c:789` | `pthread_mutex_unlock(&g_peer_lock);` |
| `read` | function | `beacon_p2p.c:959` | `read(peer->fd, cipher, resp_hdr.payload_len);` |
| `run_bof_and_capture` | function | `beacon_p2p.c:765` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `send_to_c2_or_peer` | function | `beacon_p2p.c:967` | `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)` |
| `send_to_peer` | function | `beacon_p2p.c:934` | `char* send_to_peer(peer_t *peer, const char *data, int *out_len)` |
| `sendto` | function | `beacon_p2p.c:828` | `sendto(udp_sock, my_id, strlen(my_id), 0, (struct sockaddr*)&bc_addr, sizeof(bc_addr));` |
| `setsockopt` | function | `beacon_p2p.c:810` | `setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));` |
| `sleep` | function | `beacon_p2p.c:838` | `sleep(BROADCAST_INTERVAL);` |
| `snprintf` | function | `beacon_p2p.c:818` | `snprintf(my_id + strlen(my_id), sizeof(my_id)-strlen(my_id), ":%d", getpid());` |
| `srand` | function | `beacon_p2p.c:1033` | `srand(time(NULL));` |
| `sscanf` | function | `beacon_p2p.c:1037` | `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);` |
| `strcat` | function | `beacon_p2p.c:750` | `strcat(result, ip);` |
| `strdup` | function | `beacon_p2p.c:738` | `return strdup("127.0.0.1");` |
| `strlen` | function | `beacon_p2p.c:754` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `strncpy` | function | `beacon_p2p.c:800` | `strncpy(g_peers[g_peer_count].id, id, sizeof(g_peers[g_peer_count].id)-1);` |
| `va_end` | function | `beacon_p2p.c:136` | `va_end(args);` |
| `va_start` | function | `beacon_p2p.c:132` | `va_start(args, fmt);` |
| `void` | function | `beacon_p2p.c:159` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `beacon_p2p.c:231` | `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t` |
| `write` | function | `beacon_p2p.c:864` | `write(fd, &resp_hdr, sizeof(resp_hdr));` |
| `RAND_bytes` | function | `beacons/v1/beacon.c:57` | `RAND_bytes(iv_out, 16);` |
| `_GNU_SOURCE` | macro | `beacons/v1/beacon.c:13` | `#define _GNU_SOURCE` |
| `bsb_backoff_init` | function | `beacons/v1/beacon.c:163` | `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);` |
| `bsb_backoff_reset` | function | `beacons/v1/beacon.c:200` | `bsb_backoff_reset(&backoff);` |
| `bsb_output_cleanup` | function | `beacons/v1/beacon.c:211` | `bsb_output_cleanup();` |
| `cJSON_AddNullToObject` | function | `beacons/v1/beacon.c:44` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacons/v1/beacon.c:39` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacons/v1/beacon.c:36` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacons/v1/beacon.c:48` | `cJSON_Delete(root);` |
| `execute_command` | function | `beacons/v1/beacon.c:96` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `fprintf` | function | `beacons/v1/beacon.c:152` | `fprintf(stderr, "config error: %s\n", cfg_err);` |
| `free` | function | `beacons/v1/beacon.c:51` | `free(ips);` |
| `gethostname` | function | `beacons/v1/beacon.c:28` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `main` | function | `beacons/v1/beacon.c:145` | `int main(void)` |
| `memcpy` | function | `beacons/v1/beacon.c:67` | `memcpy(full_enc, iv_out, 16);` |
| `report_result` | function | `beacons/v1/beacon.c:23` | `static void report_result(const bsb_config_t *cfg,
                           const char *command...` |
| `sleep` | function | `beacons/v1/beacon.c:173` | `sleep(bsb_backoff_next(&backoff));` |
| `snprintf` | function | `beacons/v1/beacon.c:73` | `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);` |
| `srand` | function | `beacons/v1/beacon.c:147` | `srand(time(NULL));` |
| `AES_ECB_encrypt` | function | `beacons/v1/gopher_beacon.c:428` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `beacons/v1/gopher_beacon.c:420` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `beacons/v1/gopher_beacon.c:385` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `beacons/v1/gopher_beacon.c:390` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `beacons/v1/gopher_beacon.c:386` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `beacons/v1/gopher_beacon.c:383` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `beacons/v1/gopher_beacon.c:384` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `beacons/v1/gopher_beacon.c:202` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `beacons/v1/gopher_beacon.c:190` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `beacons/v1/gopher_beacon.c:29` | `#define C2` |
| `CLIENT_ID` | macro | `beacons/v1/gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `beacons/v1/gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `beacons/v1/gopher_beacon.c:47` | `` |
| `RAND_bytes` | function | `beacons/v1/gopher_beacon.c:1148` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `beacons/v1/gopher_beacon.c:511` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...` |
| `SymbolResolver` | struct | `beacons/v1/gopher_beacon.c:62` | `` |
| `Trampoline` | struct | `beacons/v1/gopher_beacon.c:54` | `` |
| `TrampolineCache` | struct | `beacons/v1/gopher_beacon.c:68` | `` |
| `USER_AGENTS_COUNT` | macro | `beacons/v1/gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `beacons/v1/gopher_beacon.c:297` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `beacons/v1/gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `beacons/v1/gopher_beacon.c:137` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `beacons/v1/gopher_beacon.c:444` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `beacons/v1/gopher_beacon.c:417` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `beacons/v1/gopher_beacon.c:393` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `beacons/v1/gopher_beacon.c:377` | `char* base64_encode(const unsigned char* input, int len)` |
| `cJSON_AddNullToObject` | function | `beacons/v1/gopher_beacon.c:1138` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacons/v1/gopher_beacon.c:1133` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacons/v1/gopher_beacon.c:1130` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacons/v1/gopher_beacon.c:1142` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `beacons/v1/gopher_beacon.c:878` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `beacons/v1/gopher_beacon.c:250` | `static void cleanup_trampolines(void)` |
| `close` | function | `beacons/v1/gopher_beacon.c:345` | `close(sockfd);` |
| `create_trampoline` | function | `beacons/v1/gopher_beacon.c:214` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `beacons/v1/gopher_beacon.c:922` | `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` |
| `exec_cmd` | function | `beacons/v1/gopher_beacon.c:475` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `fflush` | function | `beacons/v1/gopher_beacon.c:319` | `fflush(stdout);` |
| `fprintf` | function | `beacons/v1/gopher_beacon.c:221` | `fprintf(stderr, "[!] Trampolín: mmap falló\n");` |
| `free` | function | `beacons/v1/gopher_beacon.c:254` | `free(g_trampolines);` |
| `get_local_ips` | function | `beacons/v1/gopher_beacon.c:893` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `beacons/v1/gopher_beacon.c:265` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `beacons/v1/gopher_beacon.c:1122` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `gopher_request` | function | `beacons/v1/gopher_beacon.c:314` | `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` |
| `inet_ntop` | function | `beacons/v1/gopher_beacon.c:912` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `main` | function | `beacons/v1/gopher_beacon.c:994` | `int main()` |
| `memcpy` | function | `beacons/v1/gopher_beacon.c:208` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `beacons/v1/gopher_beacon.c:437` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `munmap` | function | `beacons/v1/gopher_beacon.c:237` | `munmap(code, code_size);` |
| `page_align` | function | `beacons/v1/gopher_beacon.c:506` | `static size_t page_align(size_t size)` |
| `pclose` | function | `beacons/v1/gopher_beacon.c:488` | `pclose(fp);` |
| `perror` | function | `beacons/v1/gopher_beacon.c:682` | `perror("calloc");` |
| `printf` | function | `beacons/v1/gopher_beacon.c:998` | `printf("[*] Beacon starting...\n");` |
| `run_bof_and_capture` | function | `beacons/v1/gopher_beacon.c:950` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `send` | function | `beacons/v1/gopher_beacon.c:350` | `send(sockfd, req, strlen(req), 0);` |
| `setvbuf` | function | `beacons/v1/gopher_beacon.c:996` | `setvbuf(stdout, NULL, _IOLBF, 0);` |
| `sleep` | function | `beacons/v1/gopher_beacon.c:1028` | `sleep(6);` |
| `snprintf` | function | `beacons/v1/gopher_beacon.c:326` | `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);` |
| `srand` | function | `beacons/v1/gopher_beacon.c:1001` | `srand(time(NULL));` |
| `strcat` | function | `beacons/v1/gopher_beacon.c:914` | `strcat(result, ip);` |
| `strdup` | function | `beacons/v1/gopher_beacon.c:478` | `return strdup("[!] Empty command");` |
| `strlen` | function | `beacons/v1/gopher_beacon.c:918` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `va_end` | function | `beacons/v1/gopher_beacon.c:197` | `va_end(args);` |
| `va_start` | function | `beacons/v1/gopher_beacon.c:193` | `va_start(args, fmt);` |
| `void` | function | `beacons/v1/gopher_beacon.c:60` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `beacons/v1/gopher_beacon.c:143` | `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %` |
| `DISCOVERY_INTERVAL` | macro | `beacons/v2/beacon.c:29` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacons/v2/beacon.c:28` | `#define DISCOVERY_PORT` |
| `MAX_PEERS` | macro | `beacons/v2/beacon.c:26` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacons/v2/beacon.c:30` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacons/v2/beacon.c:31` | `#define MESH_MSG_SIZE` |
| `RAND_bytes` | function | `beacons/v2/beacon.c:99` | `RAND_bytes(iv_out, 16);` |
| `_GNU_SOURCE` | macro | `beacons/v2/beacon.c:12` | `#define _GNU_SOURCE` |
| `bsb_backoff_init` | function | `beacons/v2/beacon.c:209` | `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);` |
| `bsb_backoff_reset` | function | `beacons/v2/beacon.c:246` | `bsb_backoff_reset(&backoff);` |
| `bsb_output_cleanup` | function | `beacons/v2/beacon.c:257` | `bsb_output_cleanup();` |
| `cJSON_AddNullToObject` | function | `beacons/v2/beacon.c:86` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacons/v2/beacon.c:81` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacons/v2/beacon.c:78` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacons/v2/beacon.c:90` | `cJSON_Delete(root);` |
| `execute_command` | function | `beacons/v2/beacon.c:138` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `fprintf` | function | `beacons/v2/beacon.c:194` | `fprintf(stderr, "config error: %s\n", cfg_err);` |
| `free` | function | `beacons/v2/beacon.c:93` | `free(ips);` |
| `gethostname` | function | `beacons/v2/beacon.c:70` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `main` | function | `beacons/v2/beacon.c:187` | `int main(void)` |
| `memcpy` | function | `beacons/v2/beacon.c:109` | `memcpy(full_enc, iv_out, 16);` |
| `mesh_msg_t` | struct | `beacons/v2/beacon.c:40` | `` |
| `peer_t` | struct | `beacons/v2/beacon.c:33` | `` |
| `pthread_mutex_destroy` | function | `beacons/v2/beacon.c:259` | `pthread_mutex_destroy(&g_mesh.peers_mutex);` |
| `pthread_mutex_init` | function | `beacons/v2/beacon.c:203` | `pthread_mutex_init(&g_mesh.peers_mutex, NULL);` |
| `report_result` | function | `beacons/v2/beacon.c:65` | `static void report_result(const bsb_config_t *cfg,
                           const char *command...` |
| `sleep` | function | `beacons/v2/beacon.c:219` | `sleep(bsb_backoff_next(&backoff));` |
| `snprintf` | function | `beacons/v2/beacon.c:115` | `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);` |
| `srand` | function | `beacons/v2/beacon.c:189` | `srand(time(NULL));` |
| `RAND_bytes` | function | `beacons/v3/beacon.c:85` | `RAND_bytes(iv_out, 16);` |
| `_GNU_SOURCE` | macro | `beacons/v3/beacon.c:12` | `#define _GNU_SOURCE` |
| `bsb_backoff_init` | function | `beacons/v3/beacon.c:191` | `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);` |
| `bsb_backoff_reset` | function | `beacons/v3/beacon.c:230` | `bsb_backoff_reset(&backoff);` |
| `bsb_output_cleanup` | function | `beacons/v3/beacon.c:241` | `bsb_output_cleanup();` |
| `cJSON_AddNullToObject` | function | `beacons/v3/beacon.c:72` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `beacons/v3/beacon.c:67` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `beacons/v3/beacon.c:64` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `beacons/v3/beacon.c:76` | `cJSON_Delete(root);` |
| `compute_primes` | function | `beacons/v3/beacon.c:35` | `static int compute_primes(int count)` |
| `evasive_sleep` | function | `beacons/v3/beacon.c:45` | `static void evasive_sleep(int seconds)` |
| `execute_command` | function | `beacons/v3/beacon.c:124` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `fprintf` | function | `beacons/v3/beacon.c:180` | `fprintf(stderr, "config error: %s\n", cfg_err);` |
| `free` | function | `beacons/v3/beacon.c:79` | `free(ips);` |
| `gethostname` | function | `beacons/v3/beacon.c:56` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `infrastructure` | function | `beacons/v3/beacon.c:7` | `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...` |
| `main` | function | `beacons/v3/beacon.c:173` | `int main(void)` |
| `memcpy` | function | `beacons/v3/beacon.c:95` | `memcpy(full_enc, iv_out, 16);` |
| `report_result` | function | `beacons/v3/beacon.c:51` | `static void report_result(const bsb_config_t *cfg,
                           const char *command...` |
| `sleep` | function | `beacons/v3/beacon.c:49` | `sleep(seconds);` |
| `snprintf` | function | `beacons/v3/beacon.c:101` | `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);` |
| `srand` | function | `beacons/v3/beacon.c:175` | `srand(time(NULL));` |
| `BeaconPrintf` | function | `bof.c:7` | `BeaconPrintf(CALLBACK_OUTPUT, "[TEST BOF] Somehow, I'm still alive. Args=%.*s\n", alen, args);` |
| `__attribute__` | function | `bof.c:3` | `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)` |
| `BeaconOutput` | function | `bof/cat/bof.c:34` | `BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);` |
| `BeaconPrintf` | function | `bof/cat/bof.c:17` | `BeaconPrintf(CALLBACK_OUTPUT, "[cat] missing path argument\n");` |
| `go` | function | `bof/cat/bof.c:14` | `void go(char *args, int alen)` |
| `syscall1` | function | `bof/cat/bof.c:37` | `syscall1(SYS_close, fd);` |
| `AT_FDCWD` | macro | `bof/cat/cat.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/cat/cat.c:12` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/cat/cat.c:11` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/cat/cat.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/cat/cat.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/cat/cat.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/cat/cat.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/cat/cat.c:16` | `#define SYS_read` |
| `go` | function | `bof/cat/cat.c:30` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/cat/cat.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/cat/cat.c:8` | `typedef long ssize_t;` |
| `syscall3` | function | `bof/cat/cat.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `volatile` | function | `bof/cat/cat.c:23` | `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );` |
| `BSB_BOF_BEACON_API_H` | macro | `bof/include/beacon_api.h:17` | `#define BSB_BOF_BEACON_API_H` |
| `BeaconDataExtract` | function | `bof/include/beacon_api.h:41` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `bof/include/beacon_api.h:38` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `bof/include/beacon_api.h:40` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `bof/include/beacon_api.h:35` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `bof/include/beacon_api.h:37` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `bof/include/beacon_api.h:39` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `bof/include/beacon_api.h:47` | `void BeaconOutput(int type, const char *data, int len);` |
| `CALLBACK_ERROR` | macro | `bof/include/beacon_api.h:25` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/include/beacon_api.h:24` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `bof/include/beacon_api.h:26` | `#define CALLBACK_OUTPUT_OEM` |
| `buffer` | function | `bof/include/beacon_api.h:44` | `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void` |
| `datap` | struct | `bof/include/beacon_api.h:30` | `` |
| `go` | function | `bof/include/beacon_api.h:7` | `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);` |
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
| `syscall0` | function | `bof/include/syscalls.h:48` | `static inline long syscall0(long n)` |
| `syscall1` | function | `bof/include/syscalls.h:59` | `static inline long syscall1(long n, long a1)` |
| `syscall2` | function | `bof/include/syscalls.h:70` | `static inline long syscall2(long n, long a1, long a2)` |
| `syscall3` | function | `bof/include/syscalls.h:81` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `syscall4` | function | `bof/include/syscalls.h:92` | `static inline long syscall4(long n, long a1, long a2, long a3, long a4)` |
| `volatile` | function | `bof/include/syscalls.h:51` | `__asm__ volatile ( "syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory" );` |
| `BeaconOutput` | function | `bof/is_sudo/bof.c:69` | `BeaconOutput(CALLBACK_OUTPUT, "yes", 0);` |
| `BeaconPrintf` | function | `bof/is_sudo/bof.c:68` | `BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] uid=0 (root)\n");` |
| `go` | function | `bof/is_sudo/bof.c:56` | `void go(char *args, int alen)` |
| `syscall1` | function | `bof/is_sudo/bof.c:96` | `syscall1(SYS_close, fd);` |
| `user_in_group` | function | `bof/is_sudo/bof.c:14` | `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)` |
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
| `go` | function | `bof/is_sudo/is_sudo.c:108` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/is_sudo/is_sudo.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/is_sudo/is_sudo.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/is_sudo/is_sudo.c:44` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `bof/is_sudo/is_sudo.c:32` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/is_sudo/is_sudo.c:23` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `volatile` | function | `bof/is_sudo/is_sudo.c:25` | `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );` |
| `BeaconOutput` | function | `bof/suid_enum/bof.c:78` | `BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);` |
| `BeaconPrintf` | function | `bof/suid_enum/bof.c:259` | `BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] scanning %s\n", root);` |
| `DT_DIR` | macro | `bof/suid_enum/bof.c:31` | `#define DT_DIR` |
| `DT_LNK` | macro | `bof/suid_enum/bof.c:32` | `#define DT_LNK` |
| `DT_UNKNOWN` | macro | `bof/suid_enum/bof.c:30` | `#define DT_UNKNOWN` |
| `SYS_getdents64` | macro | `bof/suid_enum/bof.c:26` | `#define SYS_getdents64` |
| `SYS_lstat` | macro | `bof/suid_enum/bof.c:27` | `#define SYS_lstat` |
| `emit` | function | `bof/suid_enum/bof.c:82` | `static void emit(const char *s)` |
| `flush_output` | function | `bof/suid_enum/bof.c:75` | `static void flush_output(void)` |
| `format_mode` | function | `bof/suid_enum/bof.c:105` | `static void format_mode(unsigned int mode, char *out)` |
| `go` | function | `bof/suid_enum/bof.c:246` | `void go(char *args, int alen)` |
| `linux_dirent64` | struct | `bof/suid_enum/bof.c:58` | `` |
| `linux_stat` | struct | `bof/suid_enum/bof.c:35` | `` |
| `path_append` | function | `bof/suid_enum/bof.c:134` | `static void path_append(const char *name)` |
| `path_reset` | function | `bof/suid_enum/bof.c:125` | `static void path_reset(const char *root)` |
| `path_trim_to` | function | `bof/suid_enum/bof.c:148` | `static void path_trim_to(int len)` |
| `syscall1` | function | `bof/suid_enum/bof.c:244` | `syscall1(SYS_close, fd);` |
| `walk` | function | `bof/suid_enum/bof.c:158` | `static void walk(int depth)` |
| `BeaconPrintf` | function | `bof/userenum/bof.c:93` | `BeaconPrintf(CALLBACK_OUTPUT, "[userenum] cannot open /etc/passwd\n");` |
| `copy_group_members` | function | `bof/userenum/bof.c:87` | `copy_group_members("sudo", gbuf, total, sudo_members, sizeof(sudo_members));` |
| `go` | function | `bof/userenum/bof.c:67` | `void go(char *args, int alen)` |
| `syscall1` | function | `bof/userenum/bof.c:86` | `syscall1(SYS_close, fd);` |
| `user_in_member_list` | function | `bof/userenum/bof.c:51` | `static int user_in_member_list(const char *username, const char *members)` |
| `AT_FDCWD` | macro | `bof/userenum/userenum.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/userenum/userenum.c:12` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/userenum/userenum.c:11` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/userenum/userenum.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/userenum/userenum.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/userenum/userenum.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/userenum/userenum.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/userenum/userenum.c:16` | `#define SYS_read` |
| `go` | function | `bof/userenum/userenum.c:40` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/userenum/userenum.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/userenum/userenum.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/userenum/userenum.c:33` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall3` | function | `bof/userenum/userenum.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `volatile` | function | `bof/userenum/userenum.c:23` | `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );` |
| `BeaconOutput` | function | `bof/whoami/bof.c:31` | `BeaconOutput(CALLBACK_OUTPUT, "root", 0);` |
| `BeaconPrintf` | function | `bof/whoami/bof.c:30` | `BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=0 (root)\n");` |
| `go` | function | `bof/whoami/bof.c:18` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/whoami/whoami.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/whoami/whoami.c:11` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `bof/whoami/whoami.c:10` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/whoami/whoami.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/whoami/whoami.c:2` | `#define NULL` |
| `SYS_close` | macro | `bof/whoami/whoami.c:16` | `#define SYS_close` |
| `SYS_getuid` | macro | `bof/whoami/whoami.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/whoami/whoami.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/whoami/whoami.c:15` | `#define SYS_read` |
| `go` | function | `bof/whoami/whoami.c:40` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/whoami/whoami.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/whoami/whoami.c:7` | `typedef long ssize_t;` |
| `syscall1` | function | `bof/whoami/whoami.c:30` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/whoami/whoami.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `volatile` | function | `bof/whoami/whoami.c:23` | `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );` |
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
| `CJSON_PUBLIC` | function | `cJSON.c:94` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:99` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:109` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:124` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:209` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1133` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1235` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1315` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1320` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1351` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1934` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1976` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1981` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1986` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2111` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2122` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2132` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2142` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2154` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2166` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2178` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2190` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2202` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2214` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2226` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2238` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2250` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2286` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2296` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2301` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2308` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2315` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2320` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2362` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2412` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2445` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2450` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2467` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2478` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2489` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2500` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2525` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2542` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2554` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2566` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2578` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2595` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2606` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2658` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2698` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2738` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2921` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2971` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2981` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2991` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3001` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3011` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3021` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3031` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3041` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3051` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3061` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3071` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3193` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3198` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2020` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `cJSON.c:2073` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Delete` | function | `cJSON.c:262` | `cJSON_Delete(item->child);` |
| `cJSON_DetachItemViaPointer` | function | `cJSON.c:2293` | `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2785` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_ParseWithLengthOpts` | function | `cJSON.c:1145` | `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);` |
| `cJSON_ParseWithOpts` | function | `cJSON.c:1233` | `return cJSON_ParseWithOpts(value, 0, 0);` |
| `cJSON_ReplaceItemViaPointer` | function | `cJSON.c:2419` | `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);` |
| `cJSON_free` | function | `cJSON.c:475` | `cJSON_free(object->valuestring);` |
| `cJSON_strdup` | function | `cJSON.c:188` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `cJSON.c:1240` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `cJSON.c:88` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `free` | function | `cJSON.c:172` | `free(pointer);` |
| `get_array_item` | function | `cJSON.c:1915` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1944` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:157` | `` |
| `internal_malloc` | function | `cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:77` | `#define isnan(d)` |
| `malloc` | function | `cJSON.c:168` | `return malloc(size);` |
| `memcpy` | function | `cJSON.c:205` | `memcpy(copy, string, length);` |
| `memset` | function | `cJSON.c:247` | `memset(node, '\0', sizeof(cJSON));` |
| `minify_string` | function | `cJSON.c:2899` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:291` | `` |
| `parse_hex4` | function | `cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `cJSON.c:1242` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:482` | `` |
| `realloc` | function | `cJSON.c:176` | `return realloc(pointer, size);` |
| `replace_item_in_object` | function | `cJSON.c:2422` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `cJSON.c:2885` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2872` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `sprintf` | function | `cJSON.c:128` | `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);` |
| `static_strlen` | macro | `cJSON.c:185` | `#define static_strlen(string_literal)` |
| `strcpy` | function | `cJSON.c:464` | `strcpy(object->valuestring, valuestring);` |
| `suffix_object` | function | `cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `tolower` | function | `cJSON.c:153` | `return tolower(*string1) - tolower(*string2);` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `void` | function | `cJSON.c:160` | `void (CJSON_CDECL *deallocate)(void *pointer);` |
| `CJSON_CDECL` | macro | `cJSON.h:43` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `cJSON.h:60` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `cJSON.h:132` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `cJSON.h:49` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `cJSON.h:126` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `cJSON.h:53` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:55` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:57` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:64` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:66` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `cJSON.h:45` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `cJSON.h:61` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `cJSON.h:71` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `cJSON.h:72` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `cJSON.h:73` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `cJSON.h:32` | `#define __WINDOWS__` |
| `cJSON` | struct | `cJSON.h:92` | `` |
| `cJSON_Array` | macro | `cJSON.h:84` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `cJSON.h:285` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `cJSON.h:79` | `#define cJSON_False` |
| `cJSON_Hooks` | struct | `cJSON.h:114` | `` |
| `cJSON_Invalid` | macro | `cJSON.h:78` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `cJSON.h:87` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `cJSON.h:81` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `cJSON.h:82` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `cJSON.h:85` | `#define cJSON_Object` |
| `cJSON_Raw` | macro | `cJSON.h:86` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `cJSON.h:278` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `cJSON.h:270` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `cJSON.h:273` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `cJSON.h:83` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `cJSON.h:89` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `cJSON.h:80` | `#define cJSON_True` |
| `cJSON__h` | macro | `cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `cJSON.h:120` | `typedef int cJSON_bool;` |
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\| defined` |
| `sensitive` | function | `cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_` |
| `void` | function | `cJSON.h:118` | `void (CJSON_CDECL *free_fn)(void *ptr);` |
| `AES_ECB_encrypt` | function | `gopher_beacon.c:428` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `gopher_beacon.c:420` | `AES_init_ctx(&ctx, key);` |
| `BIO_flush` | function | `gopher_beacon.c:385` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `gopher_beacon.c:390` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `gopher_beacon.c:386` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `gopher_beacon.c:383` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `gopher_beacon.c:384` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `gopher_beacon.c:202` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `gopher_beacon.c:190` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `gopher_beacon.c:29` | `#define C2` |
| `CLIENT_ID` | macro | `gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `gopher_beacon.c:47` | `` |
| `RAND_bytes` | function | `gopher_beacon.c:1148` | `RAND_bytes(iv_out, 16);` |
| `RunELF` | function | `gopher_beacon.c:511` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...` |
| `SymbolResolver` | struct | `gopher_beacon.c:62` | `` |
| `Trampoline` | struct | `gopher_beacon.c:54` | `` |
| `TrampolineCache` | struct | `gopher_beacon.c:68` | `` |
| `USER_AGENTS_COUNT` | macro | `gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `gopher_beacon.c:297` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `gopher_beacon.c:137` | `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `gopher_beacon.c:444` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `gopher_beacon.c:417` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `base64_decode` | function | `gopher_beacon.c:393` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `gopher_beacon.c:377` | `char* base64_encode(const unsigned char* input, int len)` |
| `cJSON_AddNullToObject` | function | `gopher_beacon.c:1138` | `cJSON_AddNullToObject(root, "result_portscan");` |
| `cJSON_AddNumberToObject` | function | `gopher_beacon.c:1133` | `cJSON_AddNumberToObject(root, "pid", (double)getpid());` |
| `cJSON_AddStringToObject` | function | `gopher_beacon.c:1130` | `cJSON_AddStringToObject(root, "output", output);` |
| `cJSON_Delete` | function | `gopher_beacon.c:1142` | `cJSON_Delete(root);` |
| `call_bof_isolated` | function | `gopher_beacon.c:878` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `gopher_beacon.c:250` | `static void cleanup_trampolines(void)` |
| `close` | function | `gopher_beacon.c:345` | `close(sockfd);` |
| `create_trampoline` | function | `gopher_beacon.c:214` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `gopher_beacon.c:922` | `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` |
| `exec_cmd` | function | `gopher_beacon.c:475` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `fflush` | function | `gopher_beacon.c:319` | `fflush(stdout);` |
| `fprintf` | function | `gopher_beacon.c:221` | `fprintf(stderr, "[!] Trampolín: mmap falló\n");` |
| `free` | function | `gopher_beacon.c:254` | `free(g_trampolines);` |
| `get_local_ips` | function | `gopher_beacon.c:893` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `gopher_beacon.c:265` | `static void* get_or_create_trampoline(void* target)` |
| `gethostname` | function | `gopher_beacon.c:1122` | `gethostname(hostname, sizeof(hostname) - 1);` |
| `gopher_request` | function | `gopher_beacon.c:314` | `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` |
| `inet_ntop` | function | `gopher_beacon.c:912` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `main` | function | `gopher_beacon.c:994` | `int main()` |
| `memcpy` | function | `gopher_beacon.c:208` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `gopher_beacon.c:437` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `munmap` | function | `gopher_beacon.c:237` | `munmap(code, code_size);` |
| `page_align` | function | `gopher_beacon.c:506` | `static size_t page_align(size_t size)` |
| `pclose` | function | `gopher_beacon.c:488` | `pclose(fp);` |
| `perror` | function | `gopher_beacon.c:682` | `perror("calloc");` |
| `printf` | function | `gopher_beacon.c:998` | `printf("[*] Beacon starting...\n");` |
| `run_bof_and_capture` | function | `gopher_beacon.c:950` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` |
| `send` | function | `gopher_beacon.c:350` | `send(sockfd, req, strlen(req), 0);` |
| `setvbuf` | function | `gopher_beacon.c:996` | `setvbuf(stdout, NULL, _IOLBF, 0);` |
| `sleep` | function | `gopher_beacon.c:1028` | `sleep(6);` |
| `snprintf` | function | `gopher_beacon.c:326` | `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);` |
| `srand` | function | `gopher_beacon.c:1001` | `srand(time(NULL));` |
| `strcat` | function | `gopher_beacon.c:914` | `strcat(result, ip);` |
| `strdup` | function | `gopher_beacon.c:478` | `return strdup("[!] Empty command");` |
| `strlen` | function | `gopher_beacon.c:918` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `va_end` | function | `gopher_beacon.c:197` | `va_end(args);` |
| `va_start` | function | `gopher_beacon.c:193` | `va_start(args, fmt);` |
| `void` | function | `gopher_beacon.c:60` | `typedef void (*bof_func_t)(char*, int);` |
| `volatile` | function | `gopher_beacon.c:143` | `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %` |
| `command_injector` | function | `gopher_c2.py:136` | `def command_injector()` |
| `decrypt_data` | function | `gopher_c2.py:37` | `def decrypt_data(b64_data)` |
| `encrypt_data` | function | `gopher_c2.py:28` | `def encrypt_data(data)` |
| `handle_client` | function | `gopher_c2.py:45` | `def handle_client(conn, addr)` |
| `main` | function | `gopher_c2.py:127` | `def main()` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.c:535` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.c:520` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `include/aes.c:495` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `include/aes.c:488` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `include/aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `include/aes.c:238` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `include/aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `include/aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `include/aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `include/aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `include/aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `include/aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `include/aes.c:402` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `include/aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `include/aes.c:6` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `include/aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `include/aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `include/aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `include/aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `include/aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `include/aes.c:4` | `#define Nb` |
| `Nb` | macro | `include/aes.c:67` | `#define Nb` |
| `Nk` | macro | `include/aes.c:70` | `#define Nk` |
| `Nk` | macro | `include/aes.c:73` | `#define Nk` |
| `Nk` | macro | `include/aes.c:76` | `#define Nk` |
| `Nr` | macro | `include/aes.c:71` | `#define Nr` |
| `Nr` | macro | `include/aes.c:74` | `#define Nr` |
| `Nr` | macro | `include/aes.c:77` | `#define Nr` |
| `RKLENGTH` | macro | `include/aes.c:10` | `#define RKLENGTH` |
| `ShiftRows` | function | `include/aes.c:286` | `static void ShiftRows(state_t* state)` |
| `SubBytes` | function | `include/aes.c:271` | `static void SubBytes(state_t* state)` |
| `XorWithIv` | function | `include/aes.c:510` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `__attribute__` | function | `include/aes.c:12` | `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:34` | `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:56` | `static __attribute__((unused)) uint8_t Td0(int x)` |
| `__attribute__` | function | `include/aes.c:58` | `static __attribute__((unused)) uint8_t Td1(int x)` |
| `__attribute__` | function | `include/aes.c:59` | `static __attribute__((unused)) uint8_t Td2(int x)` |
| `__attribute__` | function | `include/aes.c:60` | `static __attribute__((unused)) uint8_t Td3(int x)` |
| `__attribute__` | function | `include/aes.c:61` | `static __attribute__((unused)) uint8_t Td4(int x)` |
| `getSBoxInvert` | macro | `include/aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | macro | `include/aes.c:163` | `#define getSBoxValue(num)` |
| `memcpy` | function | `include/aes.c:247` | `memcpy (ctx->Iv, iv, AES_BLOCKLEN);` |
| `xtime` | function | `include/aes.c:313` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `include/aes.h:17` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `include/aes.h:19` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_ECB_decrypt` | function | `include/aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_ECB_encrypt` | function | `include/aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_KEYLEN` | macro | `include/aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `include/aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `include/aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);` |
| `AES_init_ctx` | function | `include/aes.h:40` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
| `AES_init_ctx_iv` | function | `include/aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` |
| `AES_keyExpSize` | macro | `include/aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `include/aes.h:9` | `#define CBC` |
| `CTR` | macro | `include/aes.h:15` | `#define CTR` |
| `ECB` | macro | `include/aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `include/aes.h:2` | `#define _AES_H_` |
| `AES_ECB_encrypt` | function | `include/aes_cfb.c:31` | `AES_ECB_encrypt(&ctx, encrypted_iv);` |
| `AES_init_ctx` | function | `include/aes_cfb.c:23` | `AES_init_ctx(&ctx, key);` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.c:47` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.c:19` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` |
| `memcpy` | function | `include/aes_cfb.c:26` | `memcpy(iv_buf, iv, 16);` |
| `memset` | function | `include/aes_cfb.c:40` | `memset(iv_buf + block_size, 0, 16 - block_size);` |
| `BSB_AES_CFB_H` | macro | `include/aes_cfb.h:5` | `#define BSB_AES_CFB_H` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.h:11` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, si` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.h:8` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, siz` |
| `BEACON_API_H` | macro | `include/beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `include/beacon.h:26` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `include/beacon.h:23` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `include/beacon.h:25` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `include/beacon.h:21` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `include/beacon.h:22` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `include/beacon.h:24` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `include/beacon.h:28` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon.h:27` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `include/beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `include/beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `include/beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `include/beacon.h:14` | `` |
| `BIO_flush` | function | `include/beacon_common.c:297` | `BIO_flush(b64);` |
| `BIO_free_all` | function | `include/beacon_common.c:303` | `BIO_free_all(b64);` |
| `BIO_get_mem_ptr` | function | `include/beacon_common.c:299` | `BIO_get_mem_ptr(b64, &bptr);` |
| `BIO_set_flags` | function | `include/beacon_common.c:295` | `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);` |
| `BIO_write` | function | `include/beacon_common.c:296` | `BIO_write(b64, input, len);` |
| `BeaconOutput` | function | `include/beacon_common.c:137` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `include/beacon_common.c:125` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `MemoryStruct` | struct | `include/beacon_common.c:220` | `` |
| `RunELF` | function | `include/beacon_common.c:506` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...` |
| `WriteMemoryCallback` | function | `include/beacon_common.c:224` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `include/beacon_common.c:9` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `include/beacon_common.c:477` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar...` |
| `_exit` | function | `include/beacon_common.c:693` | `_exit(0);` |
| `_is_unreserved` | function | `include/beacon_common.c:329` | `static int _is_unreserved(unsigned char c)` |
| `base64_decode` | function | `include/beacon_common.c:306` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `include/beacon_common.c:291` | `char *base64_encode(const unsigned char *input, int len)` |
| `bsb_backoff_init` | function | `include/beacon_common.c:385` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` |
| `bsb_backoff_next` | function | `include/beacon_common.c:390` | `int bsb_backoff_next(bsb_backoff_t *bo)` |
| `bsb_backoff_reset` | function | `include/beacon_common.c:399` | `void bsb_backoff_reset(bsb_backoff_t *bo)` |
| `bsb_output_cleanup` | function | `include/beacon_common.c:109` | `void bsb_output_cleanup(void)` |
| `bsb_output_init` | function | `include/beacon_common.c:100` | `int bsb_output_init(size_t capacity)` |
| `bsb_output_reset` | function | `include/beacon_common.c:116` | `void bsb_output_reset(void)` |
| `call_bof_isolated` | function | `include/beacon_common.c:690` | `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);` |
| `cleanup_trampolines` | function | `include/beacon_common.c:180` | `void cleanup_trampolines(void)` |
| `close` | function | `include/beacon_common.c:413` | `close(sockfd);` |
| `create_trampoline` | function | `include/beacon_common.c:151` | `void *create_trampoline(void *target)` |
| `curl_easy_cleanup` | function | `include/beacon_common.c:277` | `curl_easy_cleanup(curl);` |
| `curl_easy_getinfo` | function | `include/beacon_common.c:282` | `curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);` |
| `curl_easy_setopt` | function | `include/beacon_common.c:244` | `curl_easy_setopt(curl, CURLOPT_URL, url);` |
| `download_bof` | function | `include/beacon_common.c:434` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` |
| `exec_cmd` | function | `include/beacon_common.c:358` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `free` | function | `include/beacon_common.c:111` | `free(g_beacon_output);` |
| `get_local_ips` | function | `include/beacon_common.c:405` | `char *get_local_ips(void)` |
| `get_or_create_trampoline` | function | `include/beacon_common.c:195` | `void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `include/beacon_common.c:236` | `http_response_t https_request(const bsb_config_t *cfg, const char *url,
                         ...` |
| `inet_ntop` | function | `include/beacon_common.c:424` | `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);` |
| `init_function_pointers` | function | `include/beacon_common.c:446` | `static void init_function_pointers(void)` |
| `memcpy` | function | `include/beacon_common.c:145` | `memcpy(g_beacon_output + g_output_len, data, len);` |
| `memset` | function | `include/beacon_common.c:594` | `memset(addr, 0, aligned_size);` |
| `munmap` | function | `include/beacon_common.c:169` | `munmap(code, code_size);` |
| `page_align` | function | `include/beacon_common.c:471` | `static size_t page_align(size_t size)` |
| `pclose` | function | `include/beacon_common.c:363` | `pclose(fp);` |
| `run_bof_and_capture` | function | `include/beacon_common.c:710` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           ...` |
| `strcat` | function | `include/beacon_common.c:426` | `strcat(result, ip);` |
| `strdup` | function | `include/beacon_common.c:414` | `return strdup("127.0.0.1");` |
| `strlen` | function | `include/beacon_common.c:430` | `return strlen(result) > 0 ? result : strdup("127.0.0.1");` |
| `url_encode` | function | `include/beacon_common.c:334` | `char *url_encode(const char *in, size_t in_len, size_t *out_len)` |
| `va_end` | function | `include/beacon_common.c:132` | `va_end(args);` |
| `va_start` | function | `include/beacon_common.c:129` | `va_start(args, fmt);` |
| `volatile` | function | `include/beacon_common.c:479` | `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t` |
| `waitpid` | function | `include/beacon_common.c:696` | `waitpid(pid, &status, 0);` |
| `BEACON_COMMON_H` | macro | `include/beacon_common.h:13` | `#define BEACON_COMMON_H` |
| `BSB_OUTPUT_BUFFER_DEFAULT` | macro | `include/beacon_common.h:26` | `#define BSB_OUTPUT_BUFFER_DEFAULT` |
| `BSB_OUTPUT_TRUNCATION_MARKER` | macro | `include/beacon_common.h:27` | `#define BSB_OUTPUT_TRUNCATION_MARKER` |
| `BeaconOutput` | function | `include/beacon_common.h:105` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon_common.h:102` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `RunELF` | function | `include/beacon_common.h:147` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int argume` |
| `SymbolResolver` | struct | `include/beacon_common.h:48` | `` |
| `Trampoline` | struct | `include/beacon_common.h:39` | `` |
| `TrampolineCache` | struct | `include/beacon_common.h:54` | `` |
| `_GNU_SOURCE` | macro | `include/beacon_common.h:14` | `#define _GNU_SOURCE` |
| `aes256_cfb_decrypt` | function | `include/beacon_common.h:133` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, si` |
| `aes256_cfb_encrypt` | function | `include/beacon_common.h:129` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, siz` |
| `base64_decode` | function | `include/beacon_common.h:123` | `unsigned char *base64_decode(const char *input, int *len);` |
| `base64_encode` | function | `include/beacon_common.h:122` | `char *base64_encode(const unsigned char *input, int len);` |
| `bsb_backoff_init` | function | `include/beacon_common.h:178` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);` |
| `bsb_backoff_next` | function | `include/beacon_common.h:180` | `int bsb_backoff_next(bsb_backoff_t *bo);` |
| `bsb_backoff_reset` | function | `include/beacon_common.h:181` | `void bsb_backoff_reset(bsb_backoff_t *bo);` |
| `bsb_backoff_t` | struct | `include/beacon_common.h:173` | `` |
| `bsb_output_cleanup` | function | `include/beacon_common.h:96` | `void bsb_output_cleanup(void);` |
| `bsb_output_init` | function | `include/beacon_common.h:93` | `int bsb_output_init(size_t capacity);` |
| `bsb_output_reset` | function | `include/beacon_common.h:99` | `void bsb_output_reset(void);` |
| `buffer` | function | `include/beacon_common.h:139` | `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);` |
| `cleanup_trampolines` | function | `include/beacon_common.h:109` | `void cleanup_trampolines(void);` |
| `create_trampoline` | function | `include/beacon_common.h:108` | `void *create_trampoline(void *target);` |
| `download_bof` | function | `include/beacon_common.h:155` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` |
| `g_BeaconOutput_ptr` | variable | `include/beacon_common.h:78` | `extern void *g_BeaconOutput_ptr;` |
| `g_BeaconPrintf_ptr` | variable | `include/beacon_common.h:77` | `extern void *g_BeaconPrintf_ptr;` |
| `g_beacon_output` | variable | `include/beacon_common.h:60` | `extern char *g_beacon_output;` |
| `g_close_ptr` | variable | `include/beacon_common.h:85` | `extern void *g_close_ptr;` |
| `g_connect_ptr` | variable | `include/beacon_common.h:80` | `extern void *g_connect_ptr;` |
| `g_dlclose_ptr` | variable | `include/beacon_common.h:73` | `extern void *g_dlclose_ptr;` |
| `g_dlerror_ptr` | variable | `include/beacon_common.h:71` | `extern void *g_dlerror_ptr;` |
| `g_dlopen_ptr` | variable | `include/beacon_common.h:72` | `extern void *g_dlopen_ptr;` |
| `g_dlsym_ptr` | variable | `include/beacon_common.h:70` | `extern void *g_dlsym_ptr;` |
| `g_exit_ptr` | variable | `include/beacon_common.h:69` | `extern void *g_exit_ptr;` |
| `g_freeaddrinfo_ptr` | variable | `include/beacon_common.h:87` | `extern void *g_freeaddrinfo_ptr;` |
| `g_getaddrinfo_ptr` | variable | `include/beacon_common.h:86` | `extern void *g_getaddrinfo_ptr;` |
| `g_htons_ptr` | variable | `include/beacon_common.h:82` | `extern void *g_htons_ptr;` |
| `g_inet_addr_ptr` | variable | `include/beacon_common.h:81` | `extern void *g_inet_addr_ptr;` |
| `g_memcpy_ptr` | variable | `include/beacon_common.h:67` | `extern void *g_memcpy_ptr;` |
| `g_memset_ptr` | variable | `include/beacon_common.h:68` | `extern void *g_memset_ptr;` |
| `g_mmap_ptr` | variable | `include/beacon_common.h:75` | `extern void *g_mmap_ptr;` |
| `g_munmap_ptr` | variable | `include/beacon_common.h:76` | `extern void *g_munmap_ptr;` |
| `g_output_capacity` | variable | `include/beacon_common.h:62` | `extern size_t g_output_capacity;` |
| `g_output_len` | variable | `include/beacon_common.h:61` | `extern size_t g_output_len;` |
| `g_printf_ptr` | variable | `include/beacon_common.h:65` | `extern void *g_printf_ptr;` |
| `g_recv_ptr` | variable | `include/beacon_common.h:84` | `extern void *g_recv_ptr;` |
| `g_send_ptr` | variable | `include/beacon_common.h:83` | `extern void *g_send_ptr;` |
| `g_socket_ptr` | variable | `include/beacon_common.h:79` | `extern void *g_socket_ptr;` |
| `g_strlen_ptr` | variable | `include/beacon_common.h:66` | `extern void *g_strlen_ptr;` |
| `g_write_ptr` | variable | `include/beacon_common.h:74` | `extern void *g_write_ptr;` |
| `get_local_ips` | function | `include/beacon_common.h:169` | `char *get_local_ips(void);` |
| `get_or_create_trampoline` | function | `include/beacon_common.h:110` | `void *get_or_create_trampoline(void *target);` |
| `http_response_t` | struct | `include/beacon_common.h:32` | `` |
| `https_request` | function | `include/beacon_common.h:116` | `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` |
| `run_bof_and_capture` | function | `include/beacon_common.h:161` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` |
| `url_encode` | function | `include/beacon_common.h:126` | `char *url_encode(const char *in, size_t in_len, size_t *out_len);` |
| `void` | function | `include/beacon_common.h:45` | `typedef void (*bof_func_t)(char*, int);` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:94` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:99` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:109` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:124` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:209` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1133` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1235` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1315` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1320` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1351` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1934` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1976` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1981` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1986` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2111` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2122` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2132` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2142` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2154` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2166` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2178` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2190` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2202` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2214` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2226` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2238` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2250` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2286` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2296` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2301` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2308` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2315` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2320` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2362` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2412` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2445` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2450` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2467` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2478` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2489` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2500` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2525` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2542` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2554` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2566` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2578` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2595` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2606` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2658` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2698` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2738` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2921` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2971` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2981` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2991` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3001` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3011` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3021` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3031` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3041` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3051` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3061` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3071` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3193` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3198` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `include/cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `include/cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `include/cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `include/cJSON.c:2020` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `include/cJSON.c:2073` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `include/cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `include/cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Delete` | function | `include/cJSON.c:262` | `cJSON_Delete(item->child);` |
| `cJSON_DetachItemViaPointer` | function | `include/cJSON.c:2293` | `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));` |
| `cJSON_Duplicate_rec` | function | `include/cJSON.c:2785` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `include/cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_ParseWithLengthOpts` | function | `include/cJSON.c:1145` | `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);` |
| `cJSON_ParseWithOpts` | function | `include/cJSON.c:1233` | `return cJSON_ParseWithOpts(value, 0, 0);` |
| `cJSON_ReplaceItemViaPointer` | function | `include/cJSON.c:2419` | `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);` |
| `cJSON_free` | function | `include/cJSON.c:475` | `cJSON_free(object->valuestring);` |
| `cJSON_strdup` | function | `include/cJSON.c:188` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `include/cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `include/cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `include/cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `include/cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `include/cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `include/cJSON.c:1240` | `#define cjson_min(a, b)` |
| `compare_double` | function | `include/cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `include/cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `include/cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `include/cJSON.c:88` | `` |
| `false` | macro | `include/cJSON.c:70` | `#define false` |
| `free` | function | `include/cJSON.c:172` | `free(pointer);` |
| `get_array_item` | function | `include/cJSON.c:1915` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `include/cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `include/cJSON.c:1944` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `include/cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `include/cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `include/cJSON.c:157` | `` |
| `internal_malloc` | function | `include/cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `include/cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `include/cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `include/cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `include/cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `include/cJSON.c:77` | `#define isnan(d)` |
| `malloc` | function | `include/cJSON.c:168` | `return malloc(size);` |
| `memcpy` | function | `include/cJSON.c:205` | `memcpy(copy, string, length);` |
| `memset` | function | `include/cJSON.c:247` | `memset(node, '\0', sizeof(cJSON));` |
| `minify_string` | function | `include/cJSON.c:2899` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `include/cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `include/cJSON.c:291` | `` |
| `parse_hex4` | function | `include/cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `include/cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `include/cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `include/cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `include/cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `include/cJSON.c:1242` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `include/cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `include/cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `include/cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `include/cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `include/cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `include/cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `include/cJSON.c:482` | `` |
| `realloc` | function | `include/cJSON.c:176` | `return realloc(pointer, size);` |
| `replace_item_in_object` | function | `include/cJSON.c:2422` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `include/cJSON.c:2885` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `include/cJSON.c:2872` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `include/cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `sprintf` | function | `include/cJSON.c:128` | `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);` |
| `static_strlen` | macro | `include/cJSON.c:185` | `#define static_strlen(string_literal)` |
| `strcpy` | function | `include/cJSON.c:464` | `strcpy(object->valuestring, valuestring);` |
| `suffix_object` | function | `include/cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `tolower` | function | `include/cJSON.c:153` | `return tolower(*string1) - tolower(*string2);` |
| `true` | macro | `include/cJSON.c:65` | `#define true` |
| `update_offset` | function | `include/cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `include/cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `void` | function | `include/cJSON.c:160` | `void (CJSON_CDECL *deallocate)(void *pointer);` |
| `CJSON_CDECL` | macro | `include/cJSON.h:43` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `include/cJSON.h:60` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `include/cJSON.h:132` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `include/cJSON.h:49` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `include/cJSON.h:126` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:53` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:55` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:57` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:64` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:66` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:45` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:61` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `include/cJSON.h:71` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `include/cJSON.h:72` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `include/cJSON.h:73` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `include/cJSON.h:32` | `#define __WINDOWS__` |
| `cJSON` | struct | `include/cJSON.h:92` | `` |
| `cJSON_Array` | macro | `include/cJSON.h:84` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `include/cJSON.h:285` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `include/cJSON.h:79` | `#define cJSON_False` |
| `cJSON_Hooks` | struct | `include/cJSON.h:114` | `` |
| `cJSON_Invalid` | macro | `include/cJSON.h:78` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `include/cJSON.h:87` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `include/cJSON.h:81` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `include/cJSON.h:82` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `include/cJSON.h:85` | `#define cJSON_Object` |
| `cJSON_Raw` | macro | `include/cJSON.h:86` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `include/cJSON.h:278` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `include/cJSON.h:270` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `include/cJSON.h:273` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `include/cJSON.h:83` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `include/cJSON.h:89` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `include/cJSON.h:80` | `#define cJSON_True` |
| `cJSON__h` | macro | `include/cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `include/cJSON.h:120` | `typedef int cJSON_bool;` |
| `next` | variable | `include/cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\| defined` |
| `sensitive` | function | `include/cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_` |
| `void` | function | `include/cJSON.h:118` | `void (CJSON_CDECL *free_fn)(void *ptr);` |
| `_POSIX_C_SOURCE` | macro | `include/config.c:13` | `#define _POSIX_C_SOURCE` |
| `binary_dir` | function | `include/config.c:420` | `static const char *binary_dir(char *out, size_t outsz)` |
| `bsb_config_load` | function | `include/config.c:328` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_load_default` | function | `include/config.c:437` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_sleep_seconds` | function | `include/config.c:465` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg)` |
| `expect` | function | `include/config.c:100` | `static int expect(const char **pp, const char *end, char c)` |
| `fclose` | function | `include/config.c:35` | `fclose(f);` |
| `find_matching_brace` | function | `include/config.c:109` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `free` | function | `include/config.c:365` | `free(buf);` |
| `fseek` | function | `include/config.c:27` | `fseek(f, 0, SEEK_END);` |
| `hex_to_bytes` | function | `include/config.c:174` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `memset` | function | `include/config.c:330` | `memset(cfg, 0, sizeof(*cfg));` |
| `parse_backoff` | function | `include/config.c:307` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config.c:288` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config.c:186` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config.c:208` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config.c:252` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config.c:229` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config.c:91` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config.c:75` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config.c:49` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config.c:132` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config.c:41` | `static const char *skip_ws(const char *p, const char *end)` |
| `slurp` | function | `include/config.c:24` | `static char *slurp(const char *path, size_t *out_len)` |
| `snprintf` | function | `include/config.c:331` | `snprintf(cfg->path, sizeof(cfg->path), "%s", path);` |
| `BSB_AES_KEY_BYTES` | macro | `include/config.h:25` | `#define BSB_AES_KEY_BYTES` |
| `BSB_AES_KEY_HEX_LEN` | macro | `include/config.h:24` | `#define BSB_AES_KEY_HEX_LEN` |
| `BSB_CONFIG_H` | macro | `include/config.h:14` | `#define BSB_CONFIG_H` |
| `BSB_CONFIG_PATH_DEFAULT` | macro | `include/config.h:18` | `#define BSB_CONFIG_PATH_DEFAULT` |
| `BSB_CONFIG_PATH_ENV` | macro | `include/config.h:20` | `#define BSB_CONFIG_PATH_ENV` |
| `BSB_MAX_CLIENT_ID` | macro | `include/config.h:23` | `#define BSB_MAX_CLIENT_ID` |
| `BSB_MAX_URI` | macro | `include/config.h:22` | `#define BSB_MAX_URI` |
| `BSB_MAX_URL` | macro | `include/config.h:21` | `#define BSB_MAX_URL` |
| `BSB_MAX_USER_AGENTS` | macro | `include/config.h:26` | `#define BSB_MAX_USER_AGENTS` |
| `BSB_REPORT_URI_DEFAULT` | macro | `include/config.h:28` | `#define BSB_REPORT_URI_DEFAULT` |
| `BSB_USER_AGENT_LEN` | macro | `include/config.h:27` | `#define BSB_USER_AGENT_LEN` |
| `bsb_backoff_config_t` | struct | `include/config.h:60` | `` |
| `bsb_bof_t` | struct | `include/config.h:55` | `` |
| `bsb_c2_t` | struct | `include/config.h:30` | `` |
| `bsb_config_load` | function | `include/config.h:77` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_load_default` | function | `include/config.h:80` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_sleep_seconds` | function | `include/config.h:83` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` |
| `bsb_config_t` | struct | `include/config.h:65` | `` |
| `bsb_crypto_t` | struct | `include/config.h:37` | `` |
| `bsb_network_t` | struct | `include/config.h:49` | `` |
| `bsb_timing_t` | struct | `include/config.h:42` | `` |
| `_deep_merge` | function | `include/config_py.py:55` | `def _deep_merge(base, overlay)` |
| `load_config` | function | `include/config_py.py:65` | `def load_config(path)` |
| `AT_FDCWD` | macro | `issudo.c:19` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `issudo.c:11` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `issudo.c:10` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `issudo.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `issudo.c:2` | `#define NULL` |
| `SYS_close` | macro | `issudo.c:16` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `issudo.c:18` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `issudo.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `issudo.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `issudo.c:15` | `#define SYS_read` |
| `get_username_from_uid` | function | `issudo.c:52` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `issudo.c:107` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `issudo.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `issudo.c:7` | `typedef long ssize_t;` |
| `strcmp` | function | `issudo.c:43` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `issudo.c:31` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `issudo.c:22` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `volatile` | function | `issudo.c:24` | `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );` |
| `fprintf` | function | `tests/config_harness.c:26` | `fprintf(stderr, "config error: %s\n", err);` |
| `hex_encode` | function | `tests/config_harness.c:31` | `hex_encode(cfg.crypto.key, BSB_AES_KEY_BYTES, key_hex);` |
| `main` | function | `tests/config_harness.c:21` | `int main(void)` |
| `printf` | function | `tests/config_harness.c:32` | `printf("c2.url=%s\n", cfg.c2.url);` |
| `fprintf` | function | `tests/crypto_harness.c:31` | `fprintf(stderr, "usage: %s --key <64hex> --plain <text>\n", argv[0]);` |
| `free` | function | `tests/crypto_harness.c:50` | `free(cipher);` |
| `hex_to_bytes` | function | `tests/crypto_harness.c:11` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `tests/crypto_harness.c:22` | `int main(int argc, char **argv)` |
| `printf` | function | `tests/crypto_harness.c:37` | `printf("FAIL:bad-key\n");` |
| `snprintf` | function | `tests/crypto_harness.c:68` | `snprintf(hex + i*2, 3, "%02x", cipher[i]);` |
| `compile_beacon` | function | `tests/test_beacon_build.py:34` | `def compile_beacon()` |
| `have_headers` | function | `tests/test_beacon_build.py:20` | `def have_headers()` |
| `inspect_binary` | function | `tests/test_beacon_build.py:50` | `def inspect_binary()` |
| `main` | function | `tests/test_beacon_build.py:96` | `def main()` |
| `test_beacon_compiles_and_links` | function | `tests/test_beacon_build.py:55` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `tests/test_beacon_build.py:64` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `tests/test_beacon_build.py:85` | `def test_beacon_exposes_elf_loader()` |
| `compile_bof` | function | `tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `tests/test_bof_compile.py:35` | `def inspect_symbols(obj_path)` |
| `main` | function | `tests/test_bof_compile.py:91` | `def main()` |
| `test_compile_all` | function | `tests/test_bof_compile.py:53` | `def test_compile_all()` |
| `test_export_go` | function | `tests/test_bof_compile.py:60` | `def test_export_go()` |
| `test_no_libc_leak` | function | `tests/test_bof_compile.py:80` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `tests/test_bof_compile.py:68` | `def test_unresolved_beacon_api()` |
| `_free_port` | function | `tests/test_c2_http_e2e.py:43` | `def _free_port()` |
| `_recv_response` | function | `tests/test_c2_http_e2e.py:51` | `def _recv_response(sock, timeout)` |
| `encode` | function | `tests/test_c2_http_e2e.py:274` | `def encode(s)` |
| `main` | function | `tests/test_c2_http_e2e.py:399` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `tests/test_c2_http_e2e.py:326` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `tests/test_c2_http_e2e.py:183` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `tests/test_c2_http_e2e.py:65` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `tests/test_c2_http_e2e.py:115` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `tests/test_c2_http_e2e.py:233` | `def test_http_post_with_url_encoded_b64_payload()` |
| `main` | function | `tests/test_c2_server.py:134` | `def main()` |
| `make_state` | function | `tests/test_c2_server.py:39` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `tests/test_c2_server.py:85` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `tests/test_c2_server.py:92` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `tests/test_c2_server.py:46` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `tests/test_c2_server.py:58` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `tests/test_c2_server.py:111` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `tests/test_c2_server.py:69` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `tests/test_c2_server.py:120` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `tests/test_c2_server.py:127` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `tests/test_c2_server.py:104` | `def test_unknown_selector()` |
| `compile_harness` | function | `tests/test_config.py:24` | `def compile_harness()` |
| `main` | function | `tests/test_config.py:156` | `def main()` |
| `run_harness` | function | `tests/test_config.py:38` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `tests/test_config.py:141` | `def test_bad_hex_key()` |
| `test_default_load` | function | `tests/test_config.py:55` | `def test_default_load()` |
| `test_missing_file` | function | `tests/test_config.py:90` | `def test_missing_file()` |
| `test_overrides` | function | `tests/test_config.py:73` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `tests/test_config.py:98` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `tests/test_config.py:115` | `def test_search_order_falls_back_to_cwd_default()` |
| `compile_harness` | function | `tests/test_crypto.py:18` | `def compile_harness()` |
| `main` | function | `tests/test_crypto.py:107` | `def main()` |
| `run` | function | `tests/test_crypto.py:32` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `tests/test_crypto.py:44` | `def test_block_boundary()` |
| `test_known_ciphertext` | function | `tests/test_crypto.py:55` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `tests/test_crypto.py:49` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `tests/test_crypto.py:74` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `tests/test_crypto.py:40` | `def test_short()` |
| `main` | function | `tests/test_install_deploy.py:104` | `def main()` |
| `make_all` | function | `tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `tests/test_install_deploy.py:42` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `tests/test_install_deploy.py:82` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `tests/test_install_deploy.py:61` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `tests/test_install_deploy.py:74` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `tests/test_install_deploy.py:53` | `def test_staged_files_have_correct_modes()` |
