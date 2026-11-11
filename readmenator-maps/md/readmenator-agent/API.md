# API (page 1 of 3)
Pages: [API.md](API.md), [API_p2.md](API_p2.md), [API_p3.md](API_p3.md)

## aes.c
Depends on: `aes.h`
- `getSBoxValue` (function) `aes.c:11` `static uint8_t getSBoxValue(uint8_t num)`
- `getSBoxInvert` (function) `aes.c:35` `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (function) `aes.c:59` `static uint8_t Td0(int x)`
- `Td1` (function) `aes.c:63` `static uint8_t Td1(int x)`
- `Td2` (function) `aes.c:67` `static uint8_t Td2(int x)`
- `Td3` (function) `aes.c:71` `static uint8_t Td3(int x)`
- `Td4` (function) `aes.c:75` `static uint8_t Td4(int x)`
- `KeyExpansion` (function) `aes.c:181` `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` -- This function produces Nb(Nr+1) round keys.
- `AES_init_ctx` (function) `aes.c:254` `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)`
- `AES_init_ctx_iv` (function) `aes.c:259` `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.c:264` `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)`
- `AddRoundKey` (function) `aes.c:272` `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` -- This function adds the round key to state.
- `SubBytes` (function) `aes.c:286` `static void SubBytes(state_t *state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function) `aes.c:301` `static void ShiftRows(state_t *state)` -- The ShiftRows() function shifts the rows in the state to the left.
- `xtime` (function) `aes.c:329` `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function) `aes.c:335` `static void MixColumns(state_t *state)` -- MixColumns function mixes the columns of the state matrix
- `Multiply` (function) `aes.c:363` `static uint8_t Multiply(uint8_t x, uint8_t y)` -- Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends...
- `InvMixColumns` (function) `aes.c:389` `static void InvMixColumns(state_t *state)` -- MixColumns function mixes the columns of the state matrix.
- `InvSubBytes` (function) `aes.c:413` `static void InvSubBytes(state_t *state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `InvShiftRows` (function) `aes.c:425` `static void InvShiftRows(state_t *state)`
- `Cipher` (function) `aes.c:455` `static void Cipher(state_t *state, const uint8_t *RoundKey)` -- Cipher is the main function that encrypts the PlainText.
- `InvCipher` (function) `aes.c:482` `static void InvCipher(state_t *state, const uint8_t *RoundKey)` -- if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- `AES_ECB_encrypt` (function) `aes.c:512` `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)`
- `AES_ECB_decrypt` (function) `aes.c:518` `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)`
- `XorWithIv` (function) `aes.c:528` `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)`
- `AES_CBC_encrypt_buffer` (function) `aes.c:537` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
- `AES_CBC_decrypt_buffer` (function) `aes.c:552` `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (function) `aes.c:572` `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` -- Symmetrical operation: same function for encrypting as for decrypting.

## aes.h
Imported by: `aes.c`
- `AES_init_ctx` (function) `aes.h:41` `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);`
- `AES_init_ctx_iv` (function) `aes.h:43` `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.h:44` `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);`
- `AES_ECB_encrypt` (function) `aes.h:48` `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` -- if defined(ECB) && (ECB == 1)
- `AES_ECB_decrypt` (function) `aes.h:49` `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);`
- `AES_CBC_encrypt_buffer` (function) `aes.h:53` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` -- if defined(CBC) && (CBC == 1)
- `AES_CBC_decrypt_buffer` (function) `aes.h:54` `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (function) `aes.h:58` `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` -- if defined(CTR) && (CTR == 1)

## beacon.h
Imported by: `bof.c`
- `BeaconDataParse` (function) `beacon.h:22` `void BeaconDataParse(datap *parser, char *buffer, int size);` -- === API para BOFs ===
- `BeaconDataPtr` (function) `beacon.h:23` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `beacon.h:24` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `beacon.h:25` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `beacon.h:26` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `beacon.h:27` `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (function) `beacon.h:28` `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (function) `beacon.h:29` `void BeaconOutput(int type, const char *data, int len);`

## beacons/v1/beacon.c
Depends on: `include/beacon_common.h`
- `report_result` (function) `beacons/v1/beacon.c:24` `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
- `execute_command` (function) `beacons/v1/beacon.c:104` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v1/beacon.c:167` `int main(void)`

## beacons/v2/beacon.c
Depends on: `include/beacon_common.h`
- `report_result` (function) `beacons/v2/beacon.c:69` `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
- `execute_command` (function) `beacons/v2/beacon.c:149` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v2/beacon.c:212` `int main(void)`

## beacons/v3/beacon.c
Depends on: `include/beacon_common.h`
- `infrastructure` (function) `beacons/v3/beacon.c:8` `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
- `compute_primes` (function) `beacons/v3/beacon.c:42` `static int compute_primes(int count)`
- `evasive_sleep` (function) `beacons/v3/beacon.c:55` `static void evasive_sleep(int seconds)`
- `report_result` (function) `beacons/v3/beacon.c:62` `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
- `execute_command` (function) `beacons/v3/beacon.c:142` `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function) `beacons/v3/beacon.c:205` `int main(void)`

## bof/cat/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `go` (function) `bof/cat/bof.c:15` `void go(char *args, int alen)`

## bof/cat/cat.c
- `BeaconPrintf` (function) `bof/cat/cat.c:11` `extern void BeaconPrintf(int, const char *, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/cat/cat.c:12` `extern void BeaconOutput(int, const char *, int);`
- `syscall3` (function) `bof/cat/cat.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers (copiados de tus ejemplos)
- `go` (function) `bof/cat/cat.c:31` `void go(char *args, int alen)`

## bof/include/beacon_api.h
Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`
- `go` (function) `bof/include/beacon_api.h:10` `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);`
- `BeaconDataParse` (function) `bof/include/beacon_api.h:37` `void BeaconDataParse(datap *parser, char *buffer, int size);`
- `BeaconDataPtr` (function) `bof/include/beacon_api.h:38` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `bof/include/beacon_api.h:39` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `bof/include/beacon_api.h:40` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `bof/include/beacon_api.h:41` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `bof/include/beacon_api.h:42` `char *BeaconDataExtract(datap *parser, int *size);`
- `buffer` (function) `bof/include/beacon_api.h:45` `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */...`
- `BeaconOutput` (function) `bof/include/beacon_api.h:48` `void BeaconOutput(int type, const char *data, int len);`

## bof/include/syscalls.h
Imported by: `bof/cat/bof.c`, `bof/is_sudo/bof.c`, `bof/suid_enum/bof.c`, `bof/userenum/bof.c`, `bof/whoami/bof.c`
- `syscall0` (function) `bof/include/syscalls.h:49` `static inline long syscall0(long n)`
- `syscall1` (function) `bof/include/syscalls.h:56` `static inline long syscall1(long n, long a1)`
- `syscall2` (function) `bof/include/syscalls.h:63` `static inline long syscall2(long n, long a1, long a2)`
- `syscall3` (function) `bof/include/syscalls.h:70` `static inline long syscall3(long n, long a1, long a2, long a3)`
- `syscall4` (function) `bof/include/syscalls.h:80` `static inline long syscall4(long n, long a1, long a2, long a3, long a4)`
- `bsf_strlen` (function) `bof/include/syscalls.h:92` `static inline size_t bsf_strlen(const char *s)` -- } static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10...
- `bsf_strcmp` (function) `bof/include/syscalls.h:101` `static inline int bsf_strcmp(const char *a, const char *b)` -- : "rcx", "r11", "memory"); return ret; } /* strlen - libc is not linked. static inline size_t bsf_strlen(const char...
- `bsf_memcmp` (function) `bof/include/syscalls.h:112` `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` -- } /* strcmp - libc is not linked.

## bof/is_sudo/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `user_in_group` (function) `bof/is_sudo/bof.c:15` `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
- `go` (function) `bof/is_sudo/bof.c:74` `void go(char *args, int alen)`

## bof/is_sudo/is_sudo.c
- `BeaconPrintf` (function) `bof/is_sudo/is_sudo.c:11` `extern void BeaconPrintf(int, const char *, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/is_sudo/is_sudo.c:12` `extern void BeaconOutput(int, const char *, int);`
- `syscall3` (function) `bof/is_sudo/is_sudo.c:23` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `syscall1` (function) `bof/is_sudo/is_sudo.c:33` `static inline long syscall1(long n, long a1)`
- `strcmp` (function) `bof/is_sudo/is_sudo.c:41` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function) `bof/is_sudo/is_sudo.c:52` `static int get_username_from_uid(long uid, char *buf, int buf_size)` -- Obtener username desde /etc/passwd (sin libc)
- `go` (function) `bof/is_sudo/is_sudo.c:122` `void go(char *args, int alen)`

## bof/suid_enum/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `flush_output` (function) `bof/suid_enum/bof.c:78` `static void flush_output(void)`
- `emit` (function) `bof/suid_enum/bof.c:87` `static void emit(const char *s)`
- `format_mode` (function) `bof/suid_enum/bof.c:114` `static void format_mode(unsigned int mode, char *out)` -- Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.
- `path_reset` (function) `bof/suid_enum/bof.c:137` `static void path_reset(const char *root)`
- `path_append` (function) `bof/suid_enum/bof.c:148` `static void path_append(const char *name)`
- `path_trim_to` (function) `bof/suid_enum/bof.c:166` `static void path_trim_to(int len)`
- `walk` (function) `bof/suid_enum/bof.c:178` `static void walk(int depth)` -- Walk one directory, recursing into subdirectories.
- `go` (function) `bof/suid_enum/bof.c:298` `void go(char *args, int alen)`

## bof/userenum/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `user_in_member_list` (function) `bof/userenum/bof.c:67` `static int user_in_member_list(const char *username, const char *members)`
- `go` (function) `bof/userenum/bof.c:89` `void go(char *args, int alen)`

## bof/userenum/userenum.c
- `BeaconPrintf` (function) `bof/userenum/userenum.c:11` `extern void BeaconPrintf(int, const char *, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/userenum/userenum.c:12` `extern void BeaconOutput(int, const char *, int);`
- `syscall3` (function) `bof/userenum/userenum.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `strcmp` (function) `bof/userenum/userenum.c:32` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `go` (function) `bof/userenum/userenum.c:42` `void go(char *args, int alen)`

## bof/whoami/bof.c
Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`
- `go` (function) `bof/whoami/bof.c:19` `void go(char *args, int alen)`

## bof/whoami/whoami.c
- `BeaconPrintf` (function) `bof/whoami/whoami.c:10` `extern void BeaconPrintf(int, const char *, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `bof/whoami/whoami.c:11` `extern void BeaconOutput(int, const char *, int);`
- `syscall3` (function) `bof/whoami/whoami.c:21` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Syscall wrappers
- `syscall1` (function) `bof/whoami/whoami.c:31` `static inline long syscall1(long n, long a1)`
- `go` (function) `bof/whoami/whoami.c:38` `void go(char *args, int alen)`

## c2/server.py
Depends on: `include/config_py.py`
Imported by: `mutants/tests/test_c2_server.py`, `tests/test_bof_path_traversal.py`, `tests/test_c2_beacon_bof_integration.py`, `tests/test_c2_http_e2e.py`, `tests/test_c2_server.py`, `tests/test_certificate_pinning.py`, `tests/test_crypto.py`, `tests/test_iv_generation.py`, `tests/test_replay_protection.py`
- `load_runtime_config` (function) `c2/server.py:62` `def load_runtime_config()` -- Load configuration from JSON file or use defaults.
- `compute_hmac` (function) `c2/server.py:110` `def compute_hmac(key, data)` -- Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function) `c2/server.py:115` `def verify_hmac(key, data, signature)` -- Verify HMAC-SHA256 signature.
- `encrypt_data` (function) `c2/server.py:121` `def encrypt_data(data, key, hmac_key, use_hmac)` -- Encrypt data with AES-256-CFB and optional HMAC (legacy format without replay protection).
- `encrypt_data_replay` (function) `c2/server.py:144` `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)` -- Encrypt data with AES-256-CFB and replay protection (counter + timestamp).
- `decrypt_data` (function) `c2/server.py:178` `def decrypt_data(b64_data, key, hmac_key, use_hmac)` -- Decrypt AES-256-CFB data with optional HMAC verification.
- `decrypt_data_replay` (function) `c2/server.py:201` `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds, last_seen_counter, client_id)` -- Decrypt AES-256-CFB data with replay protection (counter + timestamp).
- `C2State.__init__` (method) `c2/server.py:274` `def __init__(self, cfg)`
- `handle_get_command` (function) `c2/server.py:287` `def handle_get_command(state, selector)` -- Dispatch beacon's polling GET request.
- `handle_report` (function) `c2/server.py:311` `def handle_report(state, b64_payload)` -- Process beacon result report.
- `handle_bof` (function) `c2/server.py:401` `def handle_bof(state, name)` -- Serve BOF file from upload directory with path traversal protection.
- `handle_request` (function) `c2/server.py:439` `def handle_request(state, selector)` -- Route request to appropriate handler.
- `serve_client` (function) `c2/server.py:567` `def serve_client(state, conn, addr)` -- Handle individual client connection.
- `serve` (function) `c2/server.py:595` `def serve(cfg, state)` -- Bind and accept loop.
- `command_injector` (function) `c2/server.py:619` `def command_injector(state)` -- Interactive command injection REPL.
- `main` (function) `c2/server.py:642` `def main()` -- Start C2 server.

## cJSON.c
Depends on: `cJSON.h`
- `CJSON_PUBLIC` (function) `cJSON.c:96` `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:101` `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:111` `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:126` `CJSON_PUBLIC(const char *) cJSON_Version(void)`
- `case_insensitive_strcmp` (function) `cJSON.c:135` `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` -- /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR...
- `internal_malloc` (function) `cJSON.c:167` `static void *CJSON_CDECL internal_malloc(size_t size)` -- } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL...
- `internal_free` (function) `cJSON.c:171` `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (function) `cJSON.c:175` `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (function) `cJSON.c:190` `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)`
- `CJSON_PUBLIC` (function) `cJSON.c:211` `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)`
- `cJSON_New_Item` (function) `cJSON.c:243` `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` -- if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and...
- `get_decimal_point` (function) `cJSON.c:282` `static unsigned char get_decimal_point(void)` -- item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {...
- `parse_number` (function) `cJSON.c:311` `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` -- size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; }...
- `ensure` (function) `cJSON.c:497` `static unsigned char *ensure(printbuffer *const p, size_t needed)` -- } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for...
- `update_offset` (function) `cJSON.c:583` `static void update_offset(printbuffer *const buffer)` -- p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); }...
- `compare_double` (function) `cJSON.c:596` `static cJSON_bool compare_double(double a, double b)` -- /* calculate the new length of the string in a printbuffer and update the offset static void...
- `print_number` (function) `cJSON.c:603` `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` -- } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char *)buffer_pointer); } /*...
- `parse_hex4` (function) `cJSON.c:673` `static unsigned parse_hex4(const unsigned char *const input)` -- output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'...
- `utf16_literal_to_utf8` (function) `cJSON.c:710` `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,
            ...` -- converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- `parse_string` (function) `cJSON.c:832` `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` -- else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return...
- `print_string_ptr` (function) `cJSON.c:964` `static cJSON_bool print_string_ptr(const unsigned char *const input,
                            ...` -- { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset =...
- `print_string` (function) `cJSON.c:1087` `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` -- /* escape and print as unicode codepoint sprintf((char *)output_pointer, "u%04x", *input_pointer); output_pointer +=...
- `buffer_skip_whitespace` (function) `cJSON.c:1101` `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` -- static cJSON_bool print_string(const cJSON *const item, printbuffer *const p) { return print_string_ptr((unsigned...
- `skip_utf8_bom` (function) `cJSON.c:1127` `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` -- while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if...
- `CJSON_PUBLIC` (function) `cJSON.c:1143` `CJSON_PUBLIC(cJSON *)
cJSON_ParseWithOpts(const char *value, const char **return_parse_end,
     ...`
- `CJSON_PUBLIC` (function) `cJSON.c:1251` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (function) `cJSON.c:1258` `static unsigned char *print(const cJSON *const item, cJSON_bool format,
                         ...`
- `CJSON_PUBLIC` (function) `cJSON.c:1333` `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:1338` `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (function) `cJSON.c:1369` `CJSON_PUBLIC(cJSON_bool)
cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (function) `cJSON.c:1390` `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` -- return false; } p.buffer = (unsigned char *)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true...
- `print_value` (function) `cJSON.c:1450` `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` -- if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item...
- `parse_array` (function) `cJSON.c:1524` `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` -- return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case...
- `print_array` (function) `cJSON.c:1621` `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `parse_object` (function) `cJSON.c:1683` `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` -- output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'...
- `print_object` (function) `cJSON.c:1801` `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `get_array_item` (function) `cJSON.c:1937` `static cJSON *get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (function) `cJSON.c:1956` `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (function) `cJSON.c:1966` `static cJSON *get_object_item(const cJSON *const object, const char *const name,
                ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2003` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2008` `CJSON_PUBLIC(cJSON *)
cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...`
- `CJSON_PUBLIC` (function) `cJSON.c:2014` `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (function) `cJSON.c:2020` `static void suffix_object(cJSON *prev, cJSON *item)` -- } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *const string) {...
- `create_reference` (function) `cJSON.c:2027` `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` -- CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return...
- `add_item_to_array` (function) `cJSON.c:2048` `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (function) `cJSON.c:2095` `static void *cast_away_const(const void *string)` -- /* Add item to array/object.
- `add_item_to_object` (function) `cJSON.c:2104` `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,
             ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2143` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2154` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2164` `CJSON_PUBLIC(cJSON_bool)
cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2176` `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2188` `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2200` `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2212` `CJSON_PUBLIC(cJSON *)
cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2225` `CJSON_PUBLIC(cJSON *)
cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2238` `CJSON_PUBLIC(cJSON *)
cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2251` `CJSON_PUBLIC(cJSON *)
cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...`
- `CJSON_PUBLIC` (function) `cJSON.c:2264` `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2276` `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2288` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2324` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2334` `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2339` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2346` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2353` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2358` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2400` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...`
- `CJSON_PUBLIC` (function) `cJSON.c:2451` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (function) `cJSON.c:2461` `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,
 ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2486` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (function) `cJSON.c:2492` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (function) `cJSON.c:2510` `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2521` `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2532` `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (function) `cJSON.c:2543` `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (function) `cJSON.c:2568` `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2585` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2597` `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2609` `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2621` `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (function) `cJSON.c:2638` `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2649` `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2702` `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2743` `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2784` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (function) `cJSON.c:2832` `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (function) `cJSON.c:2923` `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (function) `cJSON.c:2937` `static void skip_multiline_comment(char **input)`
- `minify_string` (function) `cJSON.c:2951` `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (function) `cJSON.c:2977` `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (function) `cJSON.c:3027` `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3037` `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3047` `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3057` `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3067` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3077` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3087` `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3097` `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3107` `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3117` `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3127` `CJSON_PUBLIC(cJSON_bool)
cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...`
- `cJSON_ArrayForEach` (function) `cJSON.c:3214` `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (function) `cJSON.c:3230` `cJSON_ArrayForEach(b_element, b)` -- doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this...
- `CJSON_PUBLIC` (function) `cJSON.c:3251` `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (function) `cJSON.c:3256` `CJSON_PUBLIC(void) cJSON_free(void *object)`

## cJSON.h
Imported by: `cJSON.c`
- `cJSON_Parse` (function) `cJSON.h:152` `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...`
- `cJSON_GetErrorPtr` (function) `cJSON.h:161` `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...`
- `that` (function) `cJSON.h:247` `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...`
- `sensitive` (function) `cJSON.h:286` `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...`

## config/generate_parsers.py
- `load_schema` (function) `config/generate_parsers.py:25` `def load_schema()`
- `c_type_from_schema` (function) `config/generate_parsers.py:30` `def c_type_from_schema(prop, required)` -- Map JSON Schema type to C type.
- `c_field_name` (function) `config/generate_parsers.py:48` `def c_field_name(json_name)` -- Convert JSON field name to C field name (snake_case).
- `generate_c_structs` (function) `config/generate_parsers.py:53` `def generate_c_structs(schema)` -- Generate C struct definitions from schema.
- `generate_c_parser` (function) `config/generate_parsers.py:136` `def generate_c_parser(schema)` -- Generate C parser implementation from schema.
- `generate_python_loader` (function) `config/generate_parsers.py:465` `def generate_python_loader(schema)` -- Generate Python config loader from schema.
- `main` (function) `config/generate_parsers.py:615` `def main()`

## contract_agent.py
- `run_cmd` (function) `contract_agent.py:23` `def run_cmd(cmd, cwd)` -- Run a command and return (exit_code, stdout, stderr).
- `ensure_dir` (function) `contract_agent.py:29` `def ensure_dir(path)`
- `git` (function) `contract_agent.py:33` `def git()`
- `make_target` (function) `contract_agent.py:37` `def make_target(target)`
- `extract_contracts` (function) `contract_agent.py:41` `def extract_contracts(claude_content)` -- Extract contracts from CLAUDE.md (## Contract: Name headings).
- `write_spec` (function) `contract_agent.py:62` `def write_spec(contract_name, body)` -- Write spec/<contract_name>.md with SDD template.
- `write_python_test` (function) `contract_agent.py:96` `def write_python_test(contract_name, body)` -- Write a failing pytest test for the contract.
- `write_c_test` (function) `contract_agent.py:141` `def write_c_test(contract_name, body)` -- Write a failing CMocka test for C components.
- `write_implementation_stub` (function) `contract_agent.py:179` `def write_implementation_stub(contract_name)` -- Write minimal C implementation stub.
- `run_python_tests` (function) `contract_agent.py:213` `def run_python_tests()` -- Run pytest and return True if all pass.
- `run_c_tests` (function) `contract_agent.py:223` `def run_c_tests()` -- Run C tests via make test (assumes Makefile has C test targets).
- `run_mutation_testing` (function) `contract_agent.py:233` `def run_mutation_testing()` -- Run mutation testing with mutmut (Python) and custom (C).
- `run_asan` (function) `contract_agent.py:256` `def run_asan()` -- Run AddressSanitizer build and tests.
- `run_qa` (function) `contract_agent.py:266` `def run_qa()` -- Run static analysis (cppcheck).
- `git_commit_and_branch` (function) `contract_agent.py:275` `def git_commit_and_branch(contract_name)` -- Create a new branch, add changes, commit.
- `process_contract` (function) `contract_agent.py:289` `def process_contract(contract_name, body)` -- Execute the full SDD+TDD+BDD workflow for a single contract.
- `main` (function) `contract_agent.py:316` `def main()`

## gopher_c2.py
- `encrypt_data` (function) `gopher_c2.py:30` `def encrypt_data(data)`
- `decrypt_data` (function) `gopher_c2.py:40` `def decrypt_data(b64_data)`
- `handle_client` (function) `gopher_c2.py:49` `def handle_client(conn, addr)`
- `main` (function) `gopher_c2.py:143` `def main()`
- `command_injector` (function) `gopher_c2.py:152` `def command_injector()`

## include/aes.c
Depends on: `include/aes.h`
- `KeyExpansion` (function) `include/aes.c:181` `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` -- This function produces Nb(Nr+1) round keys.
- `AES_init_ctx` (function) `include/aes.c:254` `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)`
- `AES_init_ctx_iv` (function) `include/aes.c:259` `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `include/aes.c:264` `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)`
- `AddRoundKey` (function) `include/aes.c:272` `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` -- This function adds the round key to state.
- `SubBytes` (function) `include/aes.c:286` `static void SubBytes(state_t *state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function) `include/aes.c:301` `static void ShiftRows(state_t *state)` -- The ShiftRows() function shifts the rows in the state to the left.
- `xtime` (function) `include/aes.c:329` `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function) `include/aes.c:335` `static void MixColumns(state_t *state)` -- MixColumns function mixes the columns of the state matrix
- `Multiply` (function) `include/aes.c:363` `static uint8_t Multiply(uint8_t x, uint8_t y)` -- Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends...
- `InvMixColumns` (function) `include/aes.c:389` `static void InvMixColumns(state_t *state)` -- MixColumns function mixes the columns of the state matrix.
- `InvSubBytes` (function) `include/aes.c:413` `static void InvSubBytes(state_t *state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `InvShiftRows` (function) `include/aes.c:425` `static void InvShiftRows(state_t *state)`
- `Cipher` (function) `include/aes.c:455` `static void Cipher(state_t *state, const uint8_t *RoundKey)` -- Cipher is the main function that encrypts the PlainText.
- `InvCipher` (function) `include/aes.c:482` `static void InvCipher(state_t *state, const uint8_t *RoundKey)` -- if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- `AES_ECB_encrypt` (function) `include/aes.c:512` `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)`
- `AES_ECB_decrypt` (function) `include/aes.c:518` `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)`
- `XorWithIv` (function) `include/aes.c:528` `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)`
- `AES_CBC_encrypt_buffer` (function) `include/aes.c:537` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
- `AES_CBC_decrypt_buffer` (function) `include/aes.c:552` `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (function) `include/aes.c:572` `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` -- Symmetrical operation: same function for encrypting as for decrypting.

## include/aes.h
Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`
- `AES_init_ctx` (function) `include/aes.h:41` `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);`
- `AES_init_ctx_iv` (function) `include/aes.h:43` `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `include/aes.h:44` `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);`
- `AES_ECB_encrypt` (function) `include/aes.h:48` `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` -- if defined(ECB) && (ECB == 1)
- `AES_ECB_decrypt` (function) `include/aes.h:49` `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);`
- `AES_CBC_encrypt_buffer` (function) `include/aes.h:53` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` -- if defined(CBC) && (CBC == 1)
- `AES_CBC_decrypt_buffer` (function) `include/aes.h:54` `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (function) `include/aes.h:58` `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` -- if defined(CTR) && (CTR == 1)

## include/aes_cfb.c
Depends on: `include/aes.h`, `include/aes_cfb.h`
- `aes256_cfb_encrypt` (function) `include/aes_cfb.c:21` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `aes256_cfb_decrypt` (function) `include/aes_cfb.c:55` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `aes256_cfb_encrypt_replay` (function) `include/aes_cfb.c:94` `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv,
     ...` -- Encrypt with replay protection: prepends counter (8 bytes LE) and timestamp (8 bytes LE) * to plaintext before...
- `aes256_cfb_decrypt_replay` (function) `include/aes_cfb.c:126` `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv,
     ...` -- Decrypt with replay protection: decrypts ciphertext, extracts counter and timestamp.

## include/aes_cfb.h
Imported by: `include/aes_cfb.c`, `mutants/tests/crypto_harness.c`, `tests/crypto_harness.c`
- `aes256_cfb_encrypt` (function) `include/aes_cfb.h:9` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...`
- `aes256_cfb_decrypt` (function) `include/aes_cfb.h:11` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...`

## include/async_i_o_for_beacon.h
Imported by: `mutants/src/async_i_o_for_beacon.c`, `src/async_i_o_for_beacon.c`
- `async_i_o_for_beacon_process` (function) `include/async_i_o_for_beacon.h:4` `bool async_i_o_for_beacon_process(void);`

## include/beacon.h
- `BeaconDataParse` (function) `include/beacon.h:22` `void BeaconDataParse(datap *parser, char *buffer, int size);` -- === API para BOFs ===
- `BeaconDataPtr` (function) `include/beacon.h:23` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `include/beacon.h:24` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `include/beacon.h:25` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `include/beacon.h:26` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `include/beacon.h:27` `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (function) `include/beacon.h:28` `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (function) `include/beacon.h:29` `void BeaconOutput(int type, const char *data, int len);`

## include/beacon_common.c
Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`
- `bsb_output_init` (function) `include/beacon_common.c:109` `int bsb_output_init(size_t capacity)` -- {"BeaconPrintf", &g_BeaconPrintf_ptr}, {"BeaconOutput", &g_BeaconOutput_ptr}, {"socket", &g_socket_ptr}, {"connect"...
- `bsb_output_cleanup` (function) `include/beacon_common.c:135` `void bsb_output_cleanup(void)`
- `bsb_output_reset` (function) `include/beacon_common.c:149` `void bsb_output_reset(void)`
- `BeaconPrintf` (function) `include/beacon_common.c:159` `void BeaconPrintf(int type, const char *fmt, ...)` -- g_beacon_output = NULL; g_out_meta = NULL; } void bsb_output_reset(void) { if (g_beacon_output && g_out_meta) {...
- `BeaconOutput` (function) `include/beacon_common.c:175` `void BeaconOutput(int type, const char *data, int len)`
- `mmap_near` (function) `include/beacon_common.c:193` `static void *mmap_near(void *near_hint, size_t len, int prot)` -- mmap a code page near `near_hint` so PC32 relocations stay within the * +-2GB displacement range; falls back to an...
- `create_trampoline` (function) `include/beacon_common.c:211` `void *create_trampoline(void *target, void *near_hint)`
- `cleanup_trampolines` (function) `include/beacon_common.c:249` `void cleanup_trampolines(void)`
- `get_or_create_trampoline` (function) `include/beacon_common.c:266` `void *get_or_create_trampoline(void *target, void *near_hint)`
- `WriteMemoryCallback` (function) `include/beacon_common.c:303` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `bsb_curl_pin_format` (function) `include/beacon_common.c:330` `static void bsb_curl_pin_format(const char *in, char *out, size_t outsz)`
- `https_request` (function) `include/beacon_common.c:367` `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method,
     ...`
- `base64_encode` (function) `include/beacon_common.c:443` `char *base64_encode(const unsigned char *input, int len)` -- curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE...
- `base64_decode` (function) `include/beacon_common.c:460` `unsigned char *base64_decode(const char *input, int *len)`
- `bsb_generate_secure_iv` (function) `include/beacon_common.c:490` `int bsb_generate_secure_iv(unsigned char *iv_out)` -- Generates a cryptographically secure 16-byte IV.
- `url_encode` (function) `include/beacon_common.c:521` `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
- `parse_cmd_to_argv` (function) `include/beacon_common.c:553` `static char **parse_cmd_to_argv(const char *cmd, int *out_argc)` -- Parse command string into argv array.
- `free_argv` (function) `include/beacon_common.c:629` `static void free_argv(char **argv)`
- `exec_cmd` (function) `include/beacon_common.c:640` `char *exec_cmd(const char *cmd, int *out_len)` -- Execute command via execve (no shell) and capture stdout+stderr.
- `bsb_backoff_init` (function) `include/beacon_common.c:781` `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` -- if (total == 0) { free(buffer); out_len = 0; return strdup(""); } buffer[total] = '\0'; out_len = (int)total; return...
- `bsb_backoff_next` (function) `include/beacon_common.c:788` `int bsb_backoff_next(bsb_backoff_t *bo)`
- `bsb_backoff_reset` (function) `include/beacon_common.c:799` `void bsb_backoff_reset(bsb_backoff_t *bo)`
- `get_local_ips` (function) `include/beacon_common.c:805` `char *get_local_ips(void)` -- bo->current_seconds *= 2; if (bo->current_seconds > bo->max_seconds) { bo->current_seconds = bo->max_seconds; }...
- `download_bof` (function) `include/beacon_common.c:840` `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` -- if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, "lo") != 0) { char ip[INET_ADDRSTRLEN]...
- `init_function_pointers` (function) `include/beacon_common.c:872` `static void init_function_pointers(void)` -- int decoded_len = 0; unsigned char *decoded = base64_decode(resp.data, &decoded_len); free(resp.data); if (!decoded...
- `page_align` (function) `include/beacon_common.c:922` `static size_t page_align(size_t size)`
- `bof_crash_exit` (function) `include/beacon_common.c:930` `static void bof_crash_exit(int sig)`
- `fault` (function) `include/beacon_common.c:941` `* fault (SIGSEGV inside BeaconPrintf). We save the original %rsp in * a scratch slot we own below the current stack...`
- `RunELF` (function) `include/beacon_common.c:961` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `run_bof_and_capture` (function) `include/beacon_common.c:1263` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`

## include/beacon_common.h
Depends on: `include/config.h`
Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`, `tests/test_iv_generation_c.c`
- `bsb_output_init` (function) `include/beacon_common.h:96` `int bsb_output_init(size_t capacity);` -- Initialize the output buffer.
- `bsb_output_cleanup` (function) `include/beacon_common.h:99` `void bsb_output_cleanup(void);` -- Initialize the output buffer.
- `bsb_output_reset` (function) `include/beacon_common.h:102` `void bsb_output_reset(void);` -- Initialize the output buffer.
- `BeaconPrintf` (function) `include/beacon_common.h:105` `void BeaconPrintf(int type, const char *fmt, ...);` -- Initialize the output buffer.
- `BeaconOutput` (function) `include/beacon_common.h:108` `void BeaconOutput(int type, const char *data, int len);` -- Initialize the output buffer.
- `create_trampoline` (function) `include/beacon_common.h:111` `void *create_trampoline(void *target, void *near_hint);` -- /* Free the output buffer.
- `cleanup_trampolines` (function) `include/beacon_common.h:112` `void cleanup_trampolines(void);`
- `get_or_create_trampoline` (function) `include/beacon_common.h:113` `void *get_or_create_trampoline(void *target, void *near_hint);`
- `https_request` (function) `include/beacon_common.h:119` `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` -- HTTP client: performs GET or POST request.
- `base64_encode` (function) `include/beacon_common.h:123` `char *base64_encode(const unsigned char *input, int len);` -- HTTP client: performs GET or POST request.
- `base64_decode` (function) `include/beacon_common.h:124` `unsigned char *base64_decode(const char *input, int *len);`
- `url_encode` (function) `include/beacon_common.h:127` `char *url_encode(const char *in, size_t in_len, size_t *out_len);` -- HTTP client: performs GET or POST request.
- `bsb_generate_secure_iv` (function) `include/beacon_common.h:131` `int bsb_generate_secure_iv(unsigned char *iv_out);` -- Secure IV generation: tries RAND_bytes, falls back to getrandom(2). * Returns 1 on success, 0 on failure (fail-closed).
- `aes256_cfb_encrypt` (function) `include/beacon_common.h:134` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` -- Secure IV generation: tries RAND_bytes, falls back to getrandom(2). * Returns 1 on success, 0 on failure...
- `aes256_cfb_decrypt` (function) `include/beacon_common.h:136` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...`
- `aes256_cfb_encrypt_replay` (function) `include/beacon_common.h:142` `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` -- Replay-protected encryption: prepends counter (8 bytes LE) and timestamp (8 bytes LE) to plaintext before AES-CFB...
- `aes256_cfb_decrypt_replay` (function) `include/beacon_common.h:150` `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` -- Replay-protected decryption: decrypts ciphertext, extracts counter and timestamp.
- `buffer` (function) `include/beacon_common.h:156` `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);`
- `RunELF` (function) `include/beacon_common.h:164` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...` -- ELF BOF loader.
- `download_bof` (function) `include/beacon_common.h:169` `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` -- Download a BOF from the C2 server.
- `run_bof_and_capture` (function) `include/beacon_common.h:173` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` -- Execute a BOF and capture its output.
- `get_local_ips` (function) `include/beacon_common.h:178` `char *get_local_ips(void);` -- Get local IP addresses as a comma-separated string.
- `bsb_backoff_init` (function) `include/beacon_common.h:189` `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);`
- `bsb_backoff_next` (function) `include/beacon_common.h:190` `int bsb_backoff_next(bsb_backoff_t *bo);`
- `bsb_backoff_reset` (function) `include/beacon_common.h:191` `void bsb_backoff_reset(bsb_backoff_t *bo);`

## include/beacon_heartbeat___health_endpoint.h
Imported by: `mutants/src/beacon_heartbeat___health_endpoint.c`, `src/beacon_heartbeat___health_endpoint.c`
- `beacon_heartbeat___health_endpoint_process` (function) `include/beacon_heartbeat___health_endpoint.h:4` `bool beacon_heartbeat___health_endpoint_process(void);`

## include/bof_api_versioning.h
Imported by: `mutants/src/bof_api_versioning.c`, `src/bof_api_versioning.c`
- `bof_api_versioning_process` (function) `include/bof_api_versioning.h:4` `bool bof_api_versioning_process(void);`

## include/bof_path_traversal_hardening.h
Imported by: `mutants/src/bof_path_traversal_hardening.c`, `src/bof_path_traversal_hardening.c`
- `bof_path_traversal_hardening_process` (function) `include/bof_path_traversal_hardening.h:4` `bool bof_path_traversal_hardening_process(void);`

## include/bof_streaming_(large_outputs).h
Imported by: `mutants/src/bof_streaming_(large_outputs).c`, `src/bof_streaming_(large_outputs).c`
- `bof_streaming_` (function) `include/bof_streaming_(large_outputs).h:4` `bool bof_streaming_(large_outputs)_process(void);`


Next: [API_p2.md](API_p2.md)
