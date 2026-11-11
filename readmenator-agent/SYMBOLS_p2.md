# Symbols (page 2 of 4)
Previous: [SYMBOLS.md](SYMBOLS.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `CJSON_PUBLIC` | function | `cJSON.c:3127` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3251` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3256` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:83` | `#define NAN` |
| `NAN` | macro | `cJSON.c:85` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2048` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `cJSON.c:2104` | `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,              ...` |
| `buffer_at_offset` | macro | `cJSON.c:308` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1101` | `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3214` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3230` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2832` | `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:243` | `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` |
| `cJSON_strdup` | function | `cJSON.c:190` | `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:304` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:302` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:306` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:135` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2095` | `static void *cast_away_const(const void *string)` |
| `cjson_min` | macro | `cJSON.c:1256` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:596` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2027` | `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` |
| `ensure` | function | `cJSON.c:497` | `static unsigned char *ensure(printbuffer *const p, size_t needed)` |
| `error` | struct | `cJSON.c:89` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `get_array_item` | function | `cJSON.c:1937` | `static cJSON *get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:282` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1966` | `static cJSON *get_object_item(const cJSON *const object, const char *const name,                 ...` |
| `internal_free` | function | `cJSON.c:171` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:181` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:158` | `` |
| `internal_malloc` | function | `cJSON.c:167` | `static void *CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:180` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:175` | `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:182` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:75` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:78` | `#define isnan(d)` |
| `minify_string` | function | `cJSON.c:2951` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1524` | `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:292` | `` |
| `parse_hex4` | function | `cJSON.c:673` | `static unsigned parse_hex4(const unsigned char *const input)` |
| `parse_number` | function | `cJSON.c:311` | `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_object` | function | `cJSON.c:1683` | `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_string` | function | `cJSON.c:832` | `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_value` | function | `cJSON.c:1390` | `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` |
| `print` | function | `cJSON.c:1258` | `static unsigned char *print(const cJSON *const item, cJSON_bool format,                          ...` |
| `print_array` | function | `cJSON.c:1621` | `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_number` | function | `cJSON.c:603` | `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_object` | function | `cJSON.c:1801` | `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_string` | function | `cJSON.c:1087` | `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` |
| `print_string_ptr` | function | `cJSON.c:964` | `static cJSON_bool print_string_ptr(const unsigned char *const input,                             ...` |
| `print_value` | function | `cJSON.c:1450` | `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:485` | `` |
| `replace_item_in_object` | function | `cJSON.c:2461` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,  ...` |
| `skip_multiline_comment` | function | `cJSON.c:2937` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2923` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1127` | `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` |
| `static_strlen` | macro | `cJSON.c:186` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `cJSON.c:2020` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:583` | `static void update_offset(printbuffer *const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:710` | `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,             ...` |
| `CJSON_CDECL` | macro | `cJSON.h:49` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `cJSON.h:65` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `cJSON.h:142` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `cJSON.h:54` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `cJSON.h:136` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `cJSON.h:58` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:60` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:62` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:70` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:72` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `cJSON.h:50` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `cJSON.h:66` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `cJSON.h:77` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `cJSON.h:78` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `cJSON.h:79` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `cJSON.h:33` | `#define __WINDOWS__` |
| `cJSON` | struct | `cJSON.h:98` | `` |
| `cJSON_Array` | macro | `cJSON.h:90` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `cJSON.h:331` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `cJSON.h:85` | `#define cJSON_False` |
| `cJSON_GetErrorPtr` | function | `cJSON.h:161` | `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...` |
| `cJSON_Hooks` | struct | `cJSON.h:123` | `` |
| `cJSON_Invalid` | macro | `cJSON.h:84` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `cJSON.h:94` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `cJSON.h:87` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `cJSON.h:88` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `cJSON.h:91` | `#define cJSON_Object` |
| `cJSON_Parse` | function | `cJSON.h:152` | `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...` |
| `cJSON_Raw` | macro | `cJSON.h:92` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `cJSON.h:324` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `cJSON.h:312` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `cJSON.h:316` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `cJSON.h:89` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `cJSON.h:95` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `cJSON.h:86` | `#define cJSON_True` |
| `cJSON__h` | macro | `cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `cJSON.h:130` | `typedef int cJSON_bool;` |
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `cJSON.h:286` | `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...` |
| `that` | function | `cJSON.h:247` | `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...` |
| `c_field_name` | function | `config/generate_parsers.py:48` | `def c_field_name(json_name)` |
| `c_type_from_schema` | function | `config/generate_parsers.py:30` | `def c_type_from_schema(prop, required)` |
| `generate_c_parser` | function | `config/generate_parsers.py:136` | `def generate_c_parser(schema)` |
| `generate_c_structs` | function | `config/generate_parsers.py:53` | `def generate_c_structs(schema)` |
| `generate_python_loader` | function | `config/generate_parsers.py:465` | `def generate_python_loader(schema)` |
| `load_schema` | function | `config/generate_parsers.py:25` | `def load_schema()` |
| `main` | function | `config/generate_parsers.py:615` | `def main()` |
| `ensure_dir` | function | `contract_agent.py:29` | `def ensure_dir(path)` |
| `extract_contracts` | function | `contract_agent.py:41` | `def extract_contracts(claude_content)` |
| `git` | function | `contract_agent.py:33` | `def git()` |
| `git_commit_and_branch` | function | `contract_agent.py:275` | `def git_commit_and_branch(contract_name)` |
| `main` | function | `contract_agent.py:316` | `def main()` |
| `make_target` | function | `contract_agent.py:37` | `def make_target(target)` |
| `process_contract` | function | `contract_agent.py:289` | `def process_contract(contract_name, body)` |
| `run_asan` | function | `contract_agent.py:256` | `def run_asan()` |
| `run_c_tests` | function | `contract_agent.py:223` | `def run_c_tests()` |
| `run_cmd` | function | `contract_agent.py:23` | `def run_cmd(cmd, cwd)` |
| `run_mutation_testing` | function | `contract_agent.py:233` | `def run_mutation_testing()` |
| `run_python_tests` | function | `contract_agent.py:213` | `def run_python_tests()` |
| `run_qa` | function | `contract_agent.py:266` | `def run_qa()` |
| `write_c_test` | function | `contract_agent.py:141` | `def write_c_test(contract_name, body)` |
| `write_implementation_stub` | function | `contract_agent.py:179` | `def write_implementation_stub(contract_name)` |
| `write_python_test` | function | `contract_agent.py:96` | `def write_python_test(contract_name, body)` |
| `write_spec` | function | `contract_agent.py:62` | `def write_spec(contract_name, body)` |
| `BeaconOutput` | function | `gopher_beacon.c:210` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `gopher_beacon.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `gopher_beacon.c:49` | `` |
| `RunELF` | function | `gopher_beacon.c:581` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `gopher_beacon.c:66` | `` |
| `Trampoline` | struct | `gopher_beacon.c:57` | `` |
| `TrampolineCache` | struct | `gopher_beacon.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `gopher_beacon.c:321` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `gopher_beacon.c:142` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `gopher_beacon.c:500` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `gopher_beacon.c:466` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `gopher_beacon.c:440` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `gopher_beacon.c:422` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `gopher_beacon.c:265` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `gopher_beacon.c:224` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `gopher_beacon.c:1115` | `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` |
| `exec_cmd` | function | `gopher_beacon.c:536` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `gopher_beacon.c:1080` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `gopher_beacon.c:283` | `static void *get_or_create_trampoline(void *target)` |
| `gopher_request` | function | `gopher_beacon.c:339` | `char *gopher_request(const char *host, int port, const char *selector, const char *method,       ...` |
| `main` | function | `gopher_beacon.c:1193` | `int main()` |
| `page_align` | function | `gopher_beacon.c:573` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `gopher_beacon.c:1147` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `command_injector` | function | `gopher_c2.py:152` | `def command_injector()` |
| `decrypt_data` | function | `gopher_c2.py:40` | `def decrypt_data(b64_data)` |
| `encrypt_data` | function | `gopher_c2.py:30` | `def encrypt_data(data)` |
| `handle_client` | function | `gopher_c2.py:49` | `def handle_client(conn, addr)` |
| `main` | function | `gopher_c2.py:143` | `def main()` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.c:552` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.c:537` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.c:572` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_ECB_decrypt` | function | `include/aes.c:518` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ECB_encrypt` | function | `include/aes.c:512` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ctx_set_iv` | function | `include/aes.c:264` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)` |
| `AES_init_ctx` | function | `include/aes.c:254` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)` |
| `AES_init_ctx_iv` | function | `include/aes.c:259` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` |
| `AddRoundKey` | function | `include/aes.c:272` | `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` |
| `BLOCKLEN` | macro | `include/aes.c:9` | `#define BLOCKLEN` |
| `Cipher` | function | `include/aes.c:455` | `static void Cipher(state_t *state, const uint8_t *RoundKey)` |
| `InvCipher` | function | `include/aes.c:482` | `static void InvCipher(state_t *state, const uint8_t *RoundKey)` |
| `InvMixColumns` | function | `include/aes.c:389` | `static void InvMixColumns(state_t *state)` |
| `InvShiftRows` | function | `include/aes.c:425` | `static void InvShiftRows(state_t *state)` |
| `InvSubBytes` | function | `include/aes.c:413` | `static void InvSubBytes(state_t *state)` |
| `KEYLEN_256` | macro | `include/aes.c:7` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `include/aes.c:181` | `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `include/aes.c:101` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `include/aes.c:335` | `static void MixColumns(state_t *state)` |
| `Multiply` | function | `include/aes.c:363` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `include/aes.c:371` | `#define Multiply(x, y)` |
| `Nb` | macro | `include/aes.c:5` | `#define Nb` |
| `Nb` | macro | `include/aes.c:84` | `#define Nb` |
| `Nk` | macro | `include/aes.c:87` | `#define Nk` |
| `Nk` | macro | `include/aes.c:90` | `#define Nk` |
| `Nk` | macro | `include/aes.c:93` | `#define Nk` |
| `Nr` | macro | `include/aes.c:88` | `#define Nr` |
| `Nr` | macro | `include/aes.c:91` | `#define Nr` |
| `Nr` | macro | `include/aes.c:94` | `#define Nr` |
| `RKLENGTH` | macro | `include/aes.c:8` | `#define RKLENGTH` |
| `ShiftRows` | function | `include/aes.c:301` | `static void ShiftRows(state_t *state)` |
| `SubBytes` | function | `include/aes.c:286` | `static void SubBytes(state_t *state)` |
| `XorWithIv` | function | `include/aes.c:528` | `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)` |
| `__attribute__` | function | `include/aes.c:11` | `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:35` | `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:59` | `static __attribute__((unused)) uint8_t Td0(int x)` |
| `__attribute__` | function | `include/aes.c:63` | `static __attribute__((unused)) uint8_t Td1(int x)` |
| `__attribute__` | function | `include/aes.c:67` | `static __attribute__((unused)) uint8_t Td2(int x)` |
| `__attribute__` | function | `include/aes.c:71` | `static __attribute__((unused)) uint8_t Td3(int x)` |
| `__attribute__` | function | `include/aes.c:75` | `static __attribute__((unused)) uint8_t Td4(int x)` |
| `getSBoxInvert` | macro | `include/aes.c:384` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | macro | `include/aes.c:177` | `#define getSBoxValue(num)` |
| `xtime` | function | `include/aes.c:329` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `include/aes.h:18` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `include/aes.h:20` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_ECB_decrypt` | function | `include/aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_ECB_encrypt` | function | `include/aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_KEYLEN` | macro | `include/aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `include/aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `include/aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `include/aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);` |
| `AES_init_ctx` | function | `include/aes.h:41` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);` |
| `AES_init_ctx_iv` | function | `include/aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` |
| `AES_keyExpSize` | macro | `include/aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `include/aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `include/aes.h:9` | `#define CBC` |
| `CTR` | macro | `include/aes.h:15` | `#define CTR` |
| `ECB` | macro | `include/aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `include/aes.h:2` | `#define _AES_H_` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.c:55` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_decrypt_replay` | function | `include/aes_cfb.c:126` | `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv,      ...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.c:21` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt_replay` | function | `include/aes_cfb.c:94` | `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv,      ...` |
| `BSB_AES_CFB_H` | macro | `include/aes_cfb.h:5` | `#define BSB_AES_CFB_H` |
| `aes256_cfb_decrypt` | function | `include/aes_cfb.h:11` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_encrypt` | function | `include/aes_cfb.h:9` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` |
| `ASYNC_I_O_FOR_BEACON_H` | macro | `include/async_i_o_for_beacon.h:2` | `#define ASYNC_I_O_FOR_BEACON_H` |
| `async_i_o_for_beacon_process` | function | `include/async_i_o_for_beacon.h:4` | `bool async_i_o_for_beacon_process(void);` |
| `BEACON_API_H` | macro | `include/beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `include/beacon.h:27` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `include/beacon.h:24` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `include/beacon.h:26` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `include/beacon.h:22` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `include/beacon.h:23` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `include/beacon.h:25` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `include/beacon.h:29` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon.h:28` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `include/beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `include/beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `include/beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `include/beacon.h:14` | `` |
| `BeaconOutput` | function | `include/beacon_common.c:175` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `include/beacon_common.c:159` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `MemoryStruct` | struct | `include/beacon_common.c:291` | `` |
| `RunELF` | function | `include/beacon_common.c:872` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `WriteMemoryCallback` | function | `include/beacon_common.c:297` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `include/beacon_common.c:9` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `include/beacon_common.c:855` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `_is_unreserved` | function | `include/beacon_common.c:453` | `static int _is_unreserved(unsigned char c)` |
| `base64_decode` | function | `include/beacon_common.c:398` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `include/beacon_common.c:381` | `char *base64_encode(const unsigned char *input, int len)` |
| `bof_crash_exit` | function | `include/beacon_common.c:850` | `static void bof_crash_exit(int sig)` |
| `bsb_backoff_init` | function | `include/beacon_common.c:719` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` |
| `bsb_backoff_next` | function | `include/beacon_common.c:726` | `int bsb_backoff_next(bsb_backoff_t *bo)` |
| `bsb_backoff_reset` | function | `include/beacon_common.c:737` | `void bsb_backoff_reset(bsb_backoff_t *bo)` |
| `bsb_generate_secure_iv` | function | `include/beacon_common.c:428` | `int bsb_generate_secure_iv(unsigned char *iv_out)` |
| `bsb_output_cleanup` | function | `include/beacon_common.c:135` | `void bsb_output_cleanup(void)` |
| `bsb_output_init` | function | `include/beacon_common.c:109` | `int bsb_output_init(size_t capacity)` |
| `bsb_output_meta_t` | struct | `include/beacon_common.c:43` | `` |
| `bsb_output_reset` | function | `include/beacon_common.c:149` | `void bsb_output_reset(void)` |
| `cleanup_trampolines` | function | `include/beacon_common.c:243` | `void cleanup_trampolines(void)` |
| `create_trampoline` | function | `include/beacon_common.c:211` | `void *create_trampoline(void *target, void *near_hint)` |
| `download_bof` | function | `include/beacon_common.c:778` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` |
| `exec_cmd` | function | `include/beacon_common.c:578` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `free_argv` | function | `include/beacon_common.c:567` | `static void free_argv(char **argv)` |
| `get_local_ips` | function | `include/beacon_common.c:743` | `char *get_local_ips(void)` |
| `get_or_create_trampoline` | function | `include/beacon_common.c:260` | `void *get_or_create_trampoline(void *target, void *near_hint)` |
| `https_request` | function | `include/beacon_common.c:311` | `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method,      ...` |
| `init_function_pointers` | function | `include/beacon_common.c:792` | `static void init_function_pointers(void)` |
| `mmap_near` | function | `include/beacon_common.c:193` | `static void *mmap_near(void *near_hint, size_t len, int prot)` |
| `page_align` | function | `include/beacon_common.c:842` | `static size_t page_align(size_t size)` |
| `parse_cmd_to_argv` | function | `include/beacon_common.c:491` | `static char **parse_cmd_to_argv(const char *cmd, int *out_argc)` |
| `run_bof_and_capture` | function | `include/beacon_common.c:1174` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `url_encode` | function | `include/beacon_common.c:459` | `char *url_encode(const char *in, size_t in_len, size_t *out_len)` |
| `BEACON_COMMON` | macro | `include/beacon_common.c_extraction.h:2` | `#define BEACON_COMMON` |
| `BEACON_COMMON_H` | macro | `include/beacon_common.h:13` | `#define BEACON_COMMON_H` |
| `BSB_OUTPUT_BUFFER_DEFAULT` | macro | `include/beacon_common.h:26` | `#define BSB_OUTPUT_BUFFER_DEFAULT` |
| `BSB_OUTPUT_TRUNCATION_MARKER` | macro | `include/beacon_common.h:27` | `#define BSB_OUTPUT_TRUNCATION_MARKER` |
| `BeaconOutput` | function | `include/beacon_common.h:108` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `include/beacon_common.h:105` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `RunELF` | function | `include/beacon_common.h:164` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...` |
| `SymbolResolver` | struct | `include/beacon_common.h:51` | `` |
| `Trampoline` | struct | `include/beacon_common.h:41` | `` |
| `TrampolineCache` | struct | `include/beacon_common.h:58` | `` |
| `_GNU_SOURCE` | macro | `include/beacon_common.h:15` | `#define _GNU_SOURCE` |
| `aes256_cfb_decrypt` | function | `include/beacon_common.h:136` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_decrypt_replay` | function | `include/beacon_common.h:150` | `unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `aes256_cfb_encrypt` | function | `include/beacon_common.h:134` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` |
| `aes256_cfb_encrypt_replay` | function | `include/beacon_common.h:142` | `unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv, const unsigned char...` |
| `base64_decode` | function | `include/beacon_common.h:124` | `unsigned char *base64_decode(const char *input, int *len);` |
| `base64_encode` | function | `include/beacon_common.h:123` | `char *base64_encode(const unsigned char *input, int len);` |
| `bsb_backoff_init` | function | `include/beacon_common.h:189` | `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);` |
| `bsb_backoff_next` | function | `include/beacon_common.h:190` | `int bsb_backoff_next(bsb_backoff_t *bo);` |
| `bsb_backoff_reset` | function | `include/beacon_common.h:191` | `void bsb_backoff_reset(bsb_backoff_t *bo);` |
| `bsb_backoff_t` | struct | `include/beacon_common.h:182` | `` |
| `bsb_generate_secure_iv` | function | `include/beacon_common.h:131` | `int bsb_generate_secure_iv(unsigned char *iv_out);` |
| `bsb_output_cleanup` | function | `include/beacon_common.h:99` | `void bsb_output_cleanup(void);` |
| `bsb_output_init` | function | `include/beacon_common.h:96` | `int bsb_output_init(size_t capacity);` |
| `bsb_output_reset` | function | `include/beacon_common.h:102` | `void bsb_output_reset(void);` |
| `buffer` | function | `include/beacon_common.h:156` | `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);` |
| `cleanup_trampolines` | function | `include/beacon_common.h:112` | `void cleanup_trampolines(void);` |
| `create_trampoline` | function | `include/beacon_common.h:111` | `void *create_trampoline(void *target, void *near_hint);` |
| `download_bof` | function | `include/beacon_common.h:169` | `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` |
| `g_BeaconOutput_ptr` | variable | `include/beacon_common.h:81` | `extern void *g_BeaconOutput_ptr;` |
| `g_BeaconPrintf_ptr` | variable | `include/beacon_common.h:80` | `extern void *g_BeaconPrintf_ptr;` |
| `g_beacon_output` | variable | `include/beacon_common.h:65` | `extern char *g_beacon_output;` |
| `g_close_ptr` | variable | `include/beacon_common.h:88` | `extern void *g_close_ptr;` |
| `g_connect_ptr` | variable | `include/beacon_common.h:83` | `extern void *g_connect_ptr;` |
| `g_dlclose_ptr` | variable | `include/beacon_common.h:76` | `extern void *g_dlclose_ptr;` |
| `g_dlerror_ptr` | variable | `include/beacon_common.h:74` | `extern void *g_dlerror_ptr;` |
| `g_dlopen_ptr` | variable | `include/beacon_common.h:75` | `extern void *g_dlopen_ptr;` |
| `g_dlsym_ptr` | variable | `include/beacon_common.h:73` | `extern void *g_dlsym_ptr;` |
| `g_exit_ptr` | variable | `include/beacon_common.h:72` | `extern void *g_exit_ptr;` |
| `g_freeaddrinfo_ptr` | variable | `include/beacon_common.h:90` | `extern void *g_freeaddrinfo_ptr;` |
| `g_getaddrinfo_ptr` | variable | `include/beacon_common.h:89` | `extern void *g_getaddrinfo_ptr;` |
| `g_htons_ptr` | variable | `include/beacon_common.h:85` | `extern void *g_htons_ptr;` |
| `g_inet_addr_ptr` | variable | `include/beacon_common.h:84` | `extern void *g_inet_addr_ptr;` |
| `g_memcpy_ptr` | variable | `include/beacon_common.h:70` | `extern void *g_memcpy_ptr;` |
| `g_memset_ptr` | variable | `include/beacon_common.h:71` | `extern void *g_memset_ptr;` |
| `g_mmap_ptr` | variable | `include/beacon_common.h:78` | `extern void *g_mmap_ptr;` |
| `g_munmap_ptr` | variable | `include/beacon_common.h:79` | `extern void *g_munmap_ptr;` |
| `g_printf_ptr` | variable | `include/beacon_common.h:68` | `extern void *g_printf_ptr;` |
| `g_recv_ptr` | variable | `include/beacon_common.h:87` | `extern void *g_recv_ptr;` |
| `g_send_ptr` | variable | `include/beacon_common.h:86` | `extern void *g_send_ptr;` |
| `g_socket_ptr` | variable | `include/beacon_common.h:82` | `extern void *g_socket_ptr;` |
| `g_strlen_ptr` | variable | `include/beacon_common.h:69` | `extern void *g_strlen_ptr;` |
| `g_write_ptr` | variable | `include/beacon_common.h:77` | `extern void *g_write_ptr;` |
| `get_local_ips` | function | `include/beacon_common.h:178` | `char *get_local_ips(void);` |
| `get_or_create_trampoline` | function | `include/beacon_common.h:113` | `void *get_or_create_trampoline(void *target, void *near_hint);` |
| `http_response_t` | struct | `include/beacon_common.h:33` | `` |
| `https_request` | function | `include/beacon_common.h:119` | `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` |
| `run_bof_and_capture` | function | `include/beacon_common.h:173` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` |
| `url_encode` | function | `include/beacon_common.h:127` | `char *url_encode(const char *in, size_t in_len, size_t *out_len);` |
| `BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` | macro | `include/beacon_heartbeat___health_endpoint.h:2` | `#define BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` |
| `beacon_heartbeat___health_endpoint_process` | function | `include/beacon_heartbeat___health_endpoint.h:4` | `bool beacon_heartbeat___health_endpoint_process(void);` |
| `BOF_API_VERSIONING_H` | macro | `include/bof_api_versioning.h:2` | `#define BOF_API_VERSIONING_H` |
| `bof_api_versioning_process` | function | `include/bof_api_versioning.h:4` | `bool bof_api_versioning_process(void);` |
| `BOF_PATH_TRAVERSAL_HARDENING_H` | macro | `include/bof_path_traversal_hardening.h:2` | `#define BOF_PATH_TRAVERSAL_HARDENING_H` |
| `bof_path_traversal_hardening_process` | function | `include/bof_path_traversal_hardening.h:4` | `bool bof_path_traversal_hardening_process(void);` |
| `BOF_STREAMING_` | macro | `include/bof_streaming_(large_outputs).h:2` | `#define BOF_STREAMING_(LARGE_OUTPUTS)` |
| `bof_streaming_` | function | `include/bof_streaming_(large_outputs).h:4` | `bool bof_streaming_(large_outputs)_process(void);` |
| `C2_REST_API_H` | macro | `include/c2_rest_api.h:2` | `#define C2_REST_API_H` |
| `c2_rest_api_process` | function | `include/c2_rest_api.h:4` | `bool c2_rest_api_process(void);` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:96` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:101` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:111` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:126` | `CJSON_PUBLIC(const char *) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:211` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1143` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end,      ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1251` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1333` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1338` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1369` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:1956` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2003` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2008` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2014` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2143` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2154` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2164` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2176` | `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2188` | `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2200` | `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2212` | `CJSON_PUBLIC(cJSON *) cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2225` | `CJSON_PUBLIC(cJSON *) cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2238` | `CJSON_PUBLIC(cJSON *) cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2264` | `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2276` | `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2288` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2324` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2334` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2339` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2346` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2353` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2358` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2400` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2486` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2492` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2510` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2521` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2532` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2568` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2585` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2597` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2609` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2621` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2638` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2649` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2702` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2743` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2784` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:2977` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3027` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3037` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3047` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3057` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3067` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3077` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3087` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3097` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3107` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3117` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3127` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3251` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `include/cJSON.c:3256` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `include/cJSON.c:83` | `#define NAN` |
| `NAN` | macro | `include/cJSON.c:85` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `include/cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `include/cJSON.c:2048` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `include/cJSON.c:2104` | `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,              ...` |
| `buffer_at_offset` | macro | `include/cJSON.c:308` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `include/cJSON.c:1101` | `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3214` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `include/cJSON.c:3230` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `include/cJSON.c:2832` | `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `include/cJSON.c:243` | `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` |
| `cJSON_strdup` | function | `include/cJSON.c:190` | `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)` |
| `can_access_at_index` | macro | `include/cJSON.c:304` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `include/cJSON.c:302` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `include/cJSON.c:306` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `include/cJSON.c:135` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `include/cJSON.c:2095` | `static void *cast_away_const(const void *string)` |
| `cjson_min` | macro | `include/cJSON.c:1256` | `#define cjson_min(a, b)` |
| `compare_double` | function | `include/cJSON.c:596` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `include/cJSON.c:2027` | `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` |
| `ensure` | function | `include/cJSON.c:497` | `static unsigned char *ensure(printbuffer *const p, size_t needed)` |
| `error` | struct | `include/cJSON.c:89` | `` |
| `false` | macro | `include/cJSON.c:70` | `#define false` |
| `get_array_item` | function | `include/cJSON.c:1937` | `static cJSON *get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `include/cJSON.c:282` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `include/cJSON.c:1966` | `static cJSON *get_object_item(const cJSON *const object, const char *const name,                 ...` |
| `internal_free` | function | `include/cJSON.c:171` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `include/cJSON.c:181` | `#define internal_free` |
| `internal_hooks` | struct | `include/cJSON.c:158` | `` |
| `internal_malloc` | function | `include/cJSON.c:167` | `static void *CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `include/cJSON.c:180` | `#define internal_malloc` |
| `internal_realloc` | function | `include/cJSON.c:175` | `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `include/cJSON.c:182` | `#define internal_realloc` |
| `isinf` | macro | `include/cJSON.c:75` | `#define isinf(d)` |
| `isnan` | macro | `include/cJSON.c:78` | `#define isnan(d)` |
| `minify_string` | function | `include/cJSON.c:2951` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `include/cJSON.c:1524` | `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_buffer` | struct | `include/cJSON.c:292` | `` |
| `parse_hex4` | function | `include/cJSON.c:673` | `static unsigned parse_hex4(const unsigned char *const input)` |
| `parse_number` | function | `include/cJSON.c:311` | `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_object` | function | `include/cJSON.c:1683` | `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_string` | function | `include/cJSON.c:832` | `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_value` | function | `include/cJSON.c:1390` | `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` |
| `print` | function | `include/cJSON.c:1258` | `static unsigned char *print(const cJSON *const item, cJSON_bool format,                          ...` |
| `print_array` | function | `include/cJSON.c:1621` | `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_number` | function | `include/cJSON.c:603` | `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_object` | function | `include/cJSON.c:1801` | `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_string` | function | `include/cJSON.c:1087` | `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` |
| `print_string_ptr` | function | `include/cJSON.c:964` | `static cJSON_bool print_string_ptr(const unsigned char *const input,                             ...` |
| `print_value` | function | `include/cJSON.c:1450` | `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` |
| `printbuffer` | struct | `include/cJSON.c:485` | `` |
| `replace_item_in_object` | function | `include/cJSON.c:2461` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,  ...` |
| `skip_multiline_comment` | function | `include/cJSON.c:2937` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `include/cJSON.c:2923` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `include/cJSON.c:1127` | `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` |
| `static_strlen` | macro | `include/cJSON.c:186` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `include/cJSON.c:2020` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `include/cJSON.c:65` | `#define true` |
| `update_offset` | function | `include/cJSON.c:583` | `static void update_offset(printbuffer *const buffer)` |
| `utf16_literal_to_utf8` | function | `include/cJSON.c:710` | `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,             ...` |
| `CJSON_CDECL` | macro | `include/cJSON.h:49` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `include/cJSON.h:65` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `include/cJSON.h:142` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `include/cJSON.h:54` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `include/cJSON.h:136` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:58` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:60` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:62` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:70` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `include/cJSON.h:72` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:50` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `include/cJSON.h:66` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `include/cJSON.h:77` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `include/cJSON.h:78` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `include/cJSON.h:79` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `include/cJSON.h:33` | `#define __WINDOWS__` |
| `cJSON` | struct | `include/cJSON.h:98` | `` |
| `cJSON_Array` | macro | `include/cJSON.h:90` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `include/cJSON.h:331` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `include/cJSON.h:85` | `#define cJSON_False` |

Next: [SYMBOLS_p3.md](SYMBOLS_p3.md)
