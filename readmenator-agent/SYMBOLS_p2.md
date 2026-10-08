# Symbols (page 2 of 3)
Previous: [SYMBOLS.md](SYMBOLS.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `add_item_to_object` | function | `cJSON.c:2075` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2786` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_strdup` | function | `cJSON.c:189` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `cJSON.c:1241` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `cJSON.c:88` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `get_array_item` | function | `cJSON.c:1916` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1945` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:157` | `` |
| `internal_malloc` | function | `cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:77` | `#define isnan(d)` |
| `minify_string` | function | `cJSON.c:2900` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:291` | `` |
| `parse_hex4` | function | `cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `cJSON.c:1243` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:482` | `` |
| `replace_item_in_object` | function | `cJSON.c:2423` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `cJSON.c:2886` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2873` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `static_strlen` | macro | `cJSON.c:185` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `CJSON_CDECL` | macro | `cJSON.h:44` | `#define CJSON_CDECL` |
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
| `cJSON_IsReference` | macro | `cJSON.h:88` | `#define cJSON_IsReference` |
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
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */...` |
| `BeaconOutput` | function | `gopher_beacon.c:203` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `gopher_beacon.c:190` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `gopher_beacon.c:47` | `` |
| `RunELF` | function | `gopher_beacon.c:512` | `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,             unsi...` |
| `SymbolResolver` | struct | `gopher_beacon.c:62` | `` |
| `Trampoline` | struct | `gopher_beacon.c:54` | `` |
| `TrampolineCache` | struct | `gopher_beacon.c:68` | `` |
| `USER_AGENTS_COUNT` | macro | `gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `gopher_beacon.c:297` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `gopher_beacon.c:137` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...` |
| `aes256_cfb_decrypt` | function | `gopher_beacon.c:445` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `gopher_beacon.c:417` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `base64_decode` | function | `gopher_beacon.c:394` | `unsigned char* base64_decode(const char* input, int* len)` |
| `base64_encode` | function | `gopher_beacon.c:377` | `char* base64_encode(const unsigned char* input, int len)` |
| `cleanup_trampolines` | function | `gopher_beacon.c:250` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `gopher_beacon.c:214` | `static void* create_trampoline(void* target)` |
| `download_bof` | function | `gopher_beacon.c:922` | `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` |
| `exec_cmd` | function | `gopher_beacon.c:475` | `char* exec_cmd(const char* cmd, int* out_len)` |
| `get_local_ips` | function | `gopher_beacon.c:893` | `char* get_local_ips()` |
| `get_or_create_trampoline` | function | `gopher_beacon.c:266` | `static void* get_or_create_trampoline(void* target)` |
| `gopher_request` | function | `gopher_beacon.c:314` | `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` |
| `main` | function | `gopher_beacon.c:994` | `int main()` |
| `page_align` | function | `gopher_beacon.c:506` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `gopher_beacon.c:950` | `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,                           c...` |
| `command_injector` | function | `gopher_c2.py:136` | `def command_injector()` |
| `decrypt_data` | function | `gopher_c2.py:37` | `def decrypt_data(b64_data)` |
| `encrypt_data` | function | `gopher_c2.py:28` | `def encrypt_data(data)` |
| `handle_client` | function | `gopher_c2.py:45` | `def handle_client(conn, addr)` |
| `main` | function | `gopher_c2.py:127` | `def main()` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.c:536` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.c:521` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `include/aes.c:496` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `include/aes.c:490` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `include/aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `include/aes.c:239` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `include/aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `include/aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `include/aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `include/aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `include/aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `include/aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `include/aes.c:403` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `include/aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `include/aes.c:9` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `include/aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `include/aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `include/aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `include/aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `include/aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `include/aes.c:5` | `#define Nb` |
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
| `XorWithIv` | function | `include/aes.c:512` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `__attribute__` | function | `include/aes.c:13` | `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:35` | `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:57` | `static __attribute__((unused)) uint8_t Td0(int x)` |
| `__attribute__` | function | `include/aes.c:58` | `static __attribute__((unused)) uint8_t Td1(int x)` |
| `__attribute__` | function | `include/aes.c:59` | `static __attribute__((unused)) uint8_t Td2(int x)` |
| `__attribute__` | function | `include/aes.c:60` | `static __attribute__((unused)) uint8_t Td3(int x)` |
| `__attribute__` | function | `include/aes.c:61` | `static __attribute__((unused)) uint8_t Td4(int x)` |
| `getSBoxInvert` | macro | `include/aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | macro | `include/aes.c:163` | `#define getSBoxValue(num)` |
| `xtime` | function | `include/aes.c:314` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `include/aes.h:18` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `include/aes.h:20` | `#define AES_BLOCKLEN` |
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
| `AES_init_ctx` | function | `include/aes.h:41` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
| `AES_init_ctx_iv` | function | `include/aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` |
| `AES_keyExpSize` | macro | `include/aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `include/aes.h:9` | `#define CBC` |
| `CTR` | macro | `include/aes.h:15` | `#define CTR` |
| `ECB` | macro | `include/aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `include/aes.h:2` | `#define _AES_H_` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.c:48` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.c:20` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,             ...` |
| `BSB_AES_CFB_H` | macro | `include/aes_cfb.h:5` | `#define BSB_AES_CFB_H` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.h:11` | `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char*...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.h:9` | `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext...` |
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
| `BeaconOutput` | function | `include/beacon_common.c:138` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `include/beacon_common.c:125` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `MemoryStruct` | struct | `include/beacon_common.c:220` | `` |
| `RunELF` | function | `include/beacon_common.c:507` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `WriteMemoryCallback` | function | `include/beacon_common.c:225` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `include/beacon_common.c:9` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `include/beacon_common.c:478` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar...` |
| `_is_unreserved` | function | `include/beacon_common.c:329` | `static int _is_unreserved(unsigned char c)` |
| `base64_decode` | function | `include/beacon_common.c:307` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `include/beacon_common.c:291` | `char *base64_encode(const unsigned char *input, int len)` |
| `bsb_backoff_init` | function | `include/beacon_common.c:385` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` |
| `bsb_backoff_next` | function | `include/beacon_common.c:391` | `int bsb_backoff_next(bsb_backoff_t *bo)` |
| `bsb_backoff_reset` | function | `include/beacon_common.c:400` | `void bsb_backoff_reset(bsb_backoff_t *bo)` |
| `bsb_output_cleanup` | function | `include/beacon_common.c:110` | `void bsb_output_cleanup(void)` |
| `bsb_output_init` | function | `include/beacon_common.c:100` | `int bsb_output_init(size_t capacity)` |
| `bsb_output_reset` | function | `include/beacon_common.c:117` | `void bsb_output_reset(void)` |
| `cleanup_trampolines` | function | `include/beacon_common.c:181` | `void cleanup_trampolines(void)` |
| `create_trampoline` | function | `include/beacon_common.c:151` | `void *create_trampoline(void *target)` |
| `download_bof` | function | `include/beacon_common.c:434` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` |
| `exec_cmd` | function | `include/beacon_common.c:358` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `include/beacon_common.c:405` | `char *get_local_ips(void)` |
| `get_or_create_trampoline` | function | `include/beacon_common.c:196` | `void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `include/beacon_common.c:237` | `http_response_t https_request(const bsb_config_t *cfg, const char *url,                          ...` |
| `init_function_pointers` | function | `include/beacon_common.c:446` | `static void init_function_pointers(void)` |
| `page_align` | function | `include/beacon_common.c:472` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `include/beacon_common.c:711` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,                            ...` |
| `url_encode` | function | `include/beacon_common.c:335` | `char *url_encode(const char *in, size_t in_len, size_t *out_len)` |
| `BEACON_COMMON_H` | macro | `include/beacon_common.h:13` | `#define BEACON_COMMON_H` |
| `BSB_OUTPUT_BUFFER_DEFAULT` | macro | `include/beacon_common.h:26` | `#define BSB_OUTPUT_BUFFER_DEFAULT` |
| `BSB_OUTPUT_TRUNCATION_MARKER` | macro | `include/beacon_common.h:27` | `#define BSB_OUTPUT_TRUNCATION_MARKER` |
| `BeaconOutput` | function | `include/beacon_common.h:105` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon_common.h:102` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `RunELF` | function | `include/beacon_common.h:147` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...` |
| `SymbolResolver` | struct | `include/beacon_common.h:48` | `` |
| `Trampoline` | struct | `include/beacon_common.h:39` | `` |
| `TrampolineCache` | struct | `include/beacon_common.h:54` | `` |
| `_GNU_SOURCE` | macro | `include/beacon_common.h:15` | `#define _GNU_SOURCE` |
| `aes256_cfb_decrypt` | function | `include/beacon_common.h:133` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_encrypt` | function | `include/beacon_common.h:129` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` |
| `base64_decode` | function | `include/beacon_common.h:123` | `unsigned char *base64_decode(const char *input, int *len);` |
| `base64_encode` | function | `include/beacon_common.h:122` | `char *base64_encode(const unsigned char *input, int len);` |
| `bsb_backoff_init` | function | `include/beacon_common.h:179` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);` |
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
| `CJSON_PUBLIC` | function | `include/cJSON.c:95` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:100` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:110` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:125` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:210` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1134` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1236` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1316` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1321` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1352` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1935` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1977` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1982` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1987` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2112` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2123` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2133` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2143` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2155` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2167` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2179` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2191` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2203` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2215` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2227` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2239` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2287` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2297` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2302` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2309` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2316` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2321` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2363` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2413` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2446` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2468` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2479` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2490` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2501` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2526` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2555` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2567` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2579` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2596` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2607` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2659` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2699` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2739` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2922` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2972` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2982` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2992` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3002` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3012` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3022` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3032` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3042` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3052` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3062` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3072` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3194` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3199` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `include/cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `include/cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `include/cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `include/cJSON.c:2021` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `include/cJSON.c:2075` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `include/cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `include/cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `include/cJSON.c:2786` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `include/cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_strdup` | function | `include/cJSON.c:189` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `include/cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `include/cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `include/cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `include/cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `include/cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `include/cJSON.c:1241` | `#define cjson_min(a, b)` |
| `compare_double` | function | `include/cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `include/cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `include/cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `include/cJSON.c:88` | `` |
| `false` | macro | `include/cJSON.c:70` | `#define false` |
| `get_array_item` | function | `include/cJSON.c:1916` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `include/cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `include/cJSON.c:1945` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `include/cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `include/cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `include/cJSON.c:157` | `` |
| `internal_malloc` | function | `include/cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `include/cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `include/cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `include/cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `include/cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `include/cJSON.c:77` | `#define isnan(d)` |
| `minify_string` | function | `include/cJSON.c:2900` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `include/cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `include/cJSON.c:291` | `` |
| `parse_hex4` | function | `include/cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `include/cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `include/cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `include/cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `include/cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `include/cJSON.c:1243` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `include/cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `include/cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `include/cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `include/cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `include/cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `include/cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `include/cJSON.c:482` | `` |
| `replace_item_in_object` | function | `include/cJSON.c:2423` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `include/cJSON.c:2886` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `include/cJSON.c:2873` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `include/cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `static_strlen` | macro | `include/cJSON.c:185` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `include/cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `include/cJSON.c:65` | `#define true` |
| `update_offset` | function | `include/cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `include/cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `CJSON_CDECL` | macro | `include/cJSON.h:44` | `#define CJSON_CDECL` |
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
| `cJSON_IsReference` | macro | `include/cJSON.h:88` | `#define cJSON_IsReference` |
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
| `next` | variable | `include/cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `include/cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */...` |
| `_POSIX_C_SOURCE` | macro | `include/config.c:13` | `#define _POSIX_C_SOURCE` |
| `binary_dir` | function | `include/config.c:420` | `static const char *binary_dir(char *out, size_t outsz)` |
| `bsb_config_load` | function | `include/config.c:328` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_load_default` | function | `include/config.c:438` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_sleep_seconds` | function | `include/config.c:466` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg)` |
| `expect` | function | `include/config.c:100` | `static int expect(const char **pp, const char *end, char c)` |
| `find_matching_brace` | function | `include/config.c:109` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `hex_to_bytes` | function | `include/config.c:174` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `parse_backoff` | function | `include/config.c:308` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config.c:289` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config.c:186` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config.c:209` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config.c:253` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config.c:230` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config.c:92` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config.c:76` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config.c:49` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config.c:132` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config.c:41` | `static const char *skip_ws(const char *p, const char *end)` |
| `slurp` | function | `include/config.c:24` | `static char *slurp(const char *path, size_t *out_len)` |
| `BSB_AES_KEY_BYTES` | macro | `include/config.h:25` | `#define BSB_AES_KEY_BYTES` |
| `BSB_AES_KEY_HEX_LEN` | macro | `include/config.h:24` | `#define BSB_AES_KEY_HEX_LEN` |
| `BSB_CONFIG_H` | macro | `include/config.h:14` | `#define BSB_CONFIG_H` |
| `BSB_CONFIG_PATH_DEFAULT` | macro | `include/config.h:19` | `#define BSB_CONFIG_PATH_DEFAULT` |
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

Next: [SYMBOLS_p3.md](SYMBOLS_p3.md)
