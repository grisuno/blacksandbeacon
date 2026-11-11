# Subsystem: root

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
- Imported by: `aes.c`

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
- Imported by: `bof.c`

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

## cJSON.h
- Doc: cJSON: #define cJSON_Invalid (0) #define cJSON_False (1 << 0) #define cJSON_True (1 << 1)...
- Layer: utility
- Language: h
- Symbols:
  - `cJSON` (struct, line 98)
  - `cJSON_Hooks` (struct, line 123)
  - `cJSON_bool` (type_alias, line 130) `typedef int cJSON_bool;`
  - `cJSON_Parse` (function, line 152) `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...`
  - `cJSON_GetErrorPtr` (function, line 161) `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...`
  - `that` (function, line 247) `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...`
  - `sensitive` (function, line 286) `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...`
  - `next` (variable, line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) ||...`
  - `cJSON__h` (macro, line 24) `#define cJSON__h`
  - `__WINDOWS__` (macro, line 33) `#define __WINDOWS__`
  - `CJSON_CDECL` (macro, line 49) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 50) `#define CJSON_STDCALL`
  - `CJSON_EXPORT_SYMBOLS` (macro, line 54) `#define CJSON_EXPORT_SYMBOLS`
  - `CJSON_PUBLIC` (macro, line 58) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 60) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 62) `#define CJSON_PUBLIC(type)`
  - `CJSON_CDECL` (macro, line 65) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 66) `#define CJSON_STDCALL`
  - `CJSON_PUBLIC` (macro, line 70) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 72) `#define CJSON_PUBLIC(type)`
  - `CJSON_VERSION_MAJOR` (macro, line 77) `#define CJSON_VERSION_MAJOR`
  - `CJSON_VERSION_MINOR` (macro, line 78) `#define CJSON_VERSION_MINOR`
  - `CJSON_VERSION_PATCH` (macro, line 79) `#define CJSON_VERSION_PATCH`
  - `cJSON_Invalid` (macro, line 84) `#define cJSON_Invalid`
  - `cJSON_False` (macro, line 85) `#define cJSON_False`
  - `cJSON_True` (macro, line 86) `#define cJSON_True`
  - `cJSON_NULL` (macro, line 87) `#define cJSON_NULL`
  - `cJSON_Number` (macro, line 88) `#define cJSON_Number`
  - `cJSON_String` (macro, line 89) `#define cJSON_String`
  - `cJSON_Array` (macro, line 90) `#define cJSON_Array`
  - `cJSON_Object` (macro, line 91) `#define cJSON_Object`
  - `cJSON_Raw` (macro, line 92) `#define cJSON_Raw`
  - `cJSON_IsReference` (macro, line 94) `#define cJSON_IsReference`
  - `cJSON_StringIsConst` (macro, line 95) `#define cJSON_StringIsConst`
  - `CJSON_NESTING_LIMIT` (macro, line 136) `#define CJSON_NESTING_LIMIT`
  - `CJSON_CIRCULAR_LIMIT` (macro, line 142) `#define CJSON_CIRCULAR_LIMIT`
  - `cJSON_SetIntValue` (macro, line 312) `#define cJSON_SetIntValue(object, number)`
  - `cJSON_SetNumberValue` (macro, line 316) `#define cJSON_SetNumberValue(object, number)`
  - `cJSON_SetBoolValue` (macro, line 324) `#define cJSON_SetBoolValue(object, boolValue)`
  - `cJSON_ArrayForEach` (macro, line 331) `#define cJSON_ArrayForEach(element, array)`
- Imported by: `cJSON.c`

## contract_agent.py
- Doc: Contract Driven Agent - SDD/TDD/BDD workflow for Black Sand Beacon v2.
- Layer: utility
- Language: py
- Symbols:
  - `run_cmd` (function, line 23) `def run_cmd(cmd, cwd)`
  - `ensure_dir` (function, line 29) `def ensure_dir(path)`
  - `git` (function, line 33) `def git()`
  - `make_target` (function, line 37) `def make_target(target)`
  - `extract_contracts` (function, line 41) `def extract_contracts(claude_content)`
  - `write_spec` (function, line 62) `def write_spec(contract_name, body)`
  - `write_python_test` (function, line 96) `def write_python_test(contract_name, body)`
  - `write_c_test` (function, line 141) `def write_c_test(contract_name, body)`
  - `write_implementation_stub` (function, line 179) `def write_implementation_stub(contract_name)`
  - `run_python_tests` (function, line 213) `def run_python_tests()`
  - `run_c_tests` (function, line 223) `def run_c_tests()`
  - `run_mutation_testing` (function, line 233) `def run_mutation_testing()`
  - `run_asan` (function, line 256) `def run_asan()`
  - `run_qa` (function, line 266) `def run_qa()`
  - `git_commit_and_branch` (function, line 275) `def git_commit_and_branch(contract_name)`
  - `process_contract` (function, line 289) `def process_contract(contract_name, body)`
  - `main` (function, line 316) `def main()`

## gopher_c2.py
- Layer: utility
- Language: py
- Symbols:
  - `encrypt_data` (function, line 30) `def encrypt_data(data)`
  - `decrypt_data` (function, line 40) `def decrypt_data(b64_data)`
  - `handle_client` (function, line 49) `def handle_client(conn, addr)`
  - `main` (function, line 143) `def main()`
  - `command_injector` (function, line 152) `def command_injector()`

## install.sh
- Doc: Install build deps and build everything.
- Layer: utility
- Language: sh

## issudo.c
- Doc: — LazyOwn RedTeam BOF (Linux/x64)  Tipos
- Layer: utility
- Language: c
- Symbols:
  - `size_t` (type_alias, line 6) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 7) `typedef long ssize_t;`
  - `syscall3` (function, line 22) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 32) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 40) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 51) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 121) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 10) `extern void BeaconPrintf(int, const char *, ...);`
  - `BeaconOutput` (function, line 11) `extern void BeaconOutput(int, const char *, int);`
  - `NULL` (macro, line 2) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 3) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 14) `#define SYS_openat`
  - `SYS_read` (macro, line 15) `#define SYS_read`
  - `SYS_close` (macro, line 16) `#define SYS_close`
  - `SYS_getuid` (macro, line 17) `#define SYS_getuid`
  - `SYS_getpwuid_r` (macro, line 18) `#define SYS_getpwuid_r`
  - `AT_FDCWD` (macro, line 19) `#define AT_FDCWD`

## mutmut_config.py
- Layer: infrastructure
- Language: py
