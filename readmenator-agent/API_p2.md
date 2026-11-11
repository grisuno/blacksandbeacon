# API (page 2 of 3)
Previous: [API.md](API.md)

## include/c2_rest_api.h
Imported by: `mutants/src/c2_rest_api.c`, `src/c2_rest_api.c`
- `c2_rest_api_process` (function) `include/c2_rest_api.h:4` `bool c2_rest_api_process(void);`

## include/cJSON.c
Depends on: `include/cJSON.h`
- `CJSON_PUBLIC` (function) `include/cJSON.c:96` `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:101` `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:111` `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:126` `CJSON_PUBLIC(const char *) cJSON_Version(void)`
- `case_insensitive_strcmp` (function) `include/cJSON.c:135` `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` -- /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR...
- `internal_malloc` (function) `include/cJSON.c:167` `static void *CJSON_CDECL internal_malloc(size_t size)` -- } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL...
- `internal_free` (function) `include/cJSON.c:171` `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (function) `include/cJSON.c:175` `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (function) `include/cJSON.c:190` `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:211` `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)`
- `cJSON_New_Item` (function) `include/cJSON.c:243` `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` -- if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and...
- `get_decimal_point` (function) `include/cJSON.c:282` `static unsigned char get_decimal_point(void)` -- item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {...
- `parse_number` (function) `include/cJSON.c:311` `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` -- size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; }...
- `ensure` (function) `include/cJSON.c:497` `static unsigned char *ensure(printbuffer *const p, size_t needed)` -- } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for...
- `update_offset` (function) `include/cJSON.c:583` `static void update_offset(printbuffer *const buffer)` -- p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); }...
- `compare_double` (function) `include/cJSON.c:596` `static cJSON_bool compare_double(double a, double b)` -- /* calculate the new length of the string in a printbuffer and update the offset static void...
- `print_number` (function) `include/cJSON.c:603` `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` -- } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char *)buffer_pointer); } /*...
- `parse_hex4` (function) `include/cJSON.c:673` `static unsigned parse_hex4(const unsigned char *const input)` -- output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'...
- `utf16_literal_to_utf8` (function) `include/cJSON.c:710` `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,
            ...` -- converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- `parse_string` (function) `include/cJSON.c:832` `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` -- else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return...
- `print_string_ptr` (function) `include/cJSON.c:964` `static cJSON_bool print_string_ptr(const unsigned char *const input,
                            ...` -- { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset =...
- `print_string` (function) `include/cJSON.c:1087` `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` -- /* escape and print as unicode codepoint sprintf((char *)output_pointer, "u%04x", *input_pointer); output_pointer +=...
- `buffer_skip_whitespace` (function) `include/cJSON.c:1101` `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` -- static cJSON_bool print_string(const cJSON *const item, printbuffer *const p) { return print_string_ptr((unsigned...
- `skip_utf8_bom` (function) `include/cJSON.c:1127` `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` -- while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if...
- `CJSON_PUBLIC` (function) `include/cJSON.c:1143` `CJSON_PUBLIC(cJSON *)
cJSON_ParseWithOpts(const char *value, const char **return_parse_end,
     ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1251` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (function) `include/cJSON.c:1258` `static unsigned char *print(const cJSON *const item, cJSON_bool format,
                         ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1333` `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1338` `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1369` `CJSON_PUBLIC(cJSON_bool)
cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (function) `include/cJSON.c:1390` `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` -- return false; } p.buffer = (unsigned char *)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true...
- `print_value` (function) `include/cJSON.c:1450` `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` -- if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item...
- `parse_array` (function) `include/cJSON.c:1524` `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` -- return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case...
- `print_array` (function) `include/cJSON.c:1621` `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `parse_object` (function) `include/cJSON.c:1683` `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` -- output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'...
- `print_object` (function) `include/cJSON.c:1801` `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `get_array_item` (function) `include/cJSON.c:1937` `static cJSON *get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1956` `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (function) `include/cJSON.c:1966` `static cJSON *get_object_item(const cJSON *const object, const char *const name,
                ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2003` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2008` `CJSON_PUBLIC(cJSON *)
cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2014` `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (function) `include/cJSON.c:2020` `static void suffix_object(cJSON *prev, cJSON *item)` -- } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *const string) {...
- `create_reference` (function) `include/cJSON.c:2027` `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` -- CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return...
- `add_item_to_array` (function) `include/cJSON.c:2048` `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (function) `include/cJSON.c:2095` `static void *cast_away_const(const void *string)` -- /* Add item to array/object.
- `add_item_to_object` (function) `include/cJSON.c:2104` `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,
             ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2143` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2154` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2164` `CJSON_PUBLIC(cJSON_bool)
cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2176` `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2188` `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2200` `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2212` `CJSON_PUBLIC(cJSON *)
cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2225` `CJSON_PUBLIC(cJSON *)
cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2238` `CJSON_PUBLIC(cJSON *)
cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2251` `CJSON_PUBLIC(cJSON *)
cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2264` `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2276` `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2288` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2324` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2334` `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2339` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2346` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2353` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2358` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2400` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2451` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (function) `include/cJSON.c:2461` `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,
 ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2486` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2492` `CJSON_PUBLIC(cJSON_bool)
cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2510` `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2521` `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2532` `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2543` `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2568` `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2585` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2597` `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2609` `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2621` `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2638` `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2649` `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2702` `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2743` `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2784` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (function) `include/cJSON.c:2832` `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (function) `include/cJSON.c:2923` `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (function) `include/cJSON.c:2937` `static void skip_multiline_comment(char **input)`
- `minify_string` (function) `include/cJSON.c:2951` `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2977` `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3027` `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3037` `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3047` `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3057` `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3067` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3077` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3087` `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3097` `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3107` `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3117` `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3127` `CJSON_PUBLIC(cJSON_bool)
cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...`
- `cJSON_ArrayForEach` (function) `include/cJSON.c:3214` `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (function) `include/cJSON.c:3230` `cJSON_ArrayForEach(b_element, b)` -- doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this...
- `CJSON_PUBLIC` (function) `include/cJSON.c:3251` `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3256` `CJSON_PUBLIC(void) cJSON_free(void *object)`

## include/cJSON.h
Imported by: `include/beacon_common.c`, `include/cJSON.c`
- `cJSON_Parse` (function) `include/cJSON.h:152` `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...`
- `cJSON_GetErrorPtr` (function) `include/cJSON.h:161` `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...`
- `that` (function) `include/cJSON.h:247` `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...`
- `sensitive` (function) `include/cJSON.h:286` `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...`

## include/certificate_pinning___tofu.h
Imported by: `mutants/src/certificate_pinning___tofu.c`, `src/certificate_pinning___tofu.c`
- `certificate_pinning___tofu_process` (function) `include/certificate_pinning___tofu.h:4` `bool certificate_pinning___tofu_process(void);`

## include/command_execution_via_execve.h
Imported by: `mutants/src/command_execution_via_execve.c`, `src/command_execution_via_execve.c`
- `command_execution_via_execve_process` (function) `include/command_execution_via_execve.h:4` `bool command_execution_via_execve_process(void);`

## include/config.c
Depends on: `include/config.h`
- `slurp` (function) `include/config.c:24` `static char *slurp(const char *path, size_t *out_len)` -- declared in the schema.
- `skip_ws` (function) `include/config.c:56` `static const char *skip_ws(const char *p, const char *end)` -- } if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; } buf[n] = '\0'; fclose(f)...
- `read_string` (function) `include/config.c:66` `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` -- Read a JSON string starting at *pp (which must point at ").
- `read_int` (function) `include/config.c:113` `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function) `include/config.c:137` `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function) `include/config.c:156` `static int expect(const char **pp, const char *end, char c)` -- out = 1; pp = p + 4; return 1; } if ((end - p) >= 5 && !memcmp(p, "false", 5)) { out = 0; pp = p + 5; return 1; }...
- `find_matching_brace` (function) `include/config.c:167` `static const char *find_matching_brace(const char *p, const char *end)` -- Find the byte position of the matching closing brace for the * opening { at *pp.
- `skip_value` (function) `include/config.c:203` `static const char *skip_value(const char *p, const char *end)` -- Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or...
- `hex_to_bytes` (function) `include/config.c:269` `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` -- if (c == 't') return p + 4; if (c == 'f') return p + 5; if (c == 'n') return p + 4; /* number while (p < end && (*p...
- `hmac_sha256` (function) `include/config.c:292` `static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,...`
- `hkdf_extract` (function) `include/config.c:299` `static void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len...`
- `hkdf_expand` (function) `include/config.c:305` `static void hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,...`
- `hkdf_sha256` (function) `include/config.c:337` `static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,...`
- `derive_keys_from_master` (function) `include/config.c:345` `static void derive_keys_from_master(bsb_config_t *cfg)`
- `parse_c2` (function) `include/config.c:375` `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` -- } uint8_t salt[] = HKDF_SALT; uint8_t info_enc[] = HKDF_INFO_ENC; uint8_t info_hmac[] = HKDF_INFO_HMAC...
- `parse_crypto` (function) `include/config.c:419` `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function) `include/config.c:474` `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function) `include/config.c:518` `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function) `include/config.c:586` `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function) `include/config.c:620` `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function) `include/config.c:655` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` -- } else { p = skip_value(p, end); if (!p) return; } p = skip_ws(p, end); if (p < end && *p == ',') p++; } } /*...
- `binary_dir` (function) `include/config.c:798` `static const char *binary_dir(char *out, size_t outsz)` -- Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without...
- `bsb_config_load_default` (function) `include/config.c:820` `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- `bsb_config_sleep_seconds` (function) `include/config.c:853` `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`

## include/config.h
Imported by: `include/beacon_common.h`, `include/config.c`, `mutants/tests/config_harness.c`, `tests/config_harness.c`, `tests/test_certificate_pinning_c.c`, `tests/test_hkdf_key_derivation_c.c`
- `bsb_config_load` (function) `include/config.h:89` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` -- Load config from path.
- `bsb_config_load_default` (function) `include/config.h:92` `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` -- Load config from path.
- `bsb_config_sleep_seconds` (function) `include/config.h:95` `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` -- Load config from path.

## include/config_autogen.c
Depends on: `include/config_autogen.h`
- `slurp` (function) `include/config_autogen.c:16` `static char *slurp(const char *path, size_t *out_len)` -- Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to...
- `skip_ws` (function) `include/config_autogen.c:34` `static const char *skip_ws(const char *p, const char *end)` -- fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf =...
- `read_string` (function) `include/config_autogen.c:40` `static int read_string(const char **pp, const char *end, char *out, size_t outsz)`
- `read_int` (function) `include/config_autogen.c:68` `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function) `include/config_autogen.c:85` `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function) `include/config_autogen.c:93` `static int expect(const char **pp, const char *end, char c)`
- `find_matching_brace` (function) `include/config_autogen.c:101` `static const char *find_matching_brace(const char *p, const char *end)`
- `skip_value` (function) `include/config_autogen.c:123` `static const char *skip_value(const char *p, const char *end)`
- `hex_to_bytes` (function) `include/config_autogen.c:165` `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` -- if (ch == '[') depth++; else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c...
- `parse_c2` (function) `include/config_autogen.c:177` `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_crypto` (function) `include/config_autogen.c:206` `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function) `include/config_autogen.c:227` `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function) `include/config_autogen.c:260` `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function) `include/config_autogen.c:300` `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function) `include/config_autogen.c:325` `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_server` (function) `include/config_autogen.c:350` `static void parse_server(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function) `include/config_autogen.c:375` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)`

## include/config_autogen.h
Imported by: `include/config_autogen.c`
- `bsb_config_load` (function) `include/config_autogen.h:69` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` -- } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network...
- `bsb_config_load_default` (function) `include/config_autogen.h:72` `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` -- bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff...
- `bsb_config_sleep_seconds` (function) `include/config_autogen.h:75` `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` -- bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff; bsb_server_t server; char path[512]; } bsb_config_t; /*...

## include/config_py.py
Imported by: `c2/server.py`, `mutants/tests/test_certificate_pinning.py`, `tests/test_c2_beacon_bof_integration.py`, `tests/test_certificate_pinning.py`, `tests/test_hkdf_key_derivation.py`, `tests/test_iv_generation.py`, `tests/test_replay_protection.py`
- `load_config` (function) `include/config_py.py:94` `def load_config(path)` -- Load and validate a BSB config file.

## include/config_py_autogen.py
- `load_config` (function) `include/config_py_autogen.py:89` `def load_config(path)` -- Load and validate a BSB config file.

## include/hkdf_key_derivation.h
Imported by: `mutants/src/hkdf_key_derivation.c`, `src/hkdf_key_derivation.c`
- `hkdf_key_derivation_process` (function) `include/hkdf_key_derivation.h:4` `bool hkdf_key_derivation_process(void);`

## include/iv_generation_with_entropy_verification.h
Imported by: `mutants/src/iv_generation_with_entropy_verification.c`, `src/iv_generation_with_entropy_verification.c`
- `iv_generation_with_entropy_verification_process` (function) `include/iv_generation_with_entropy_verification.h:4` `bool iv_generation_with_entropy_verification_process(void);`

## include/replay_protection.h
Imported by: `mutants/src/replay_protection.c`, `src/replay_protection.c`
- `replay_protection_process` (function) `include/replay_protection.h:4` `bool replay_protection_process(void);`

## include/socks5___http_proxy_support.h
Imported by: `mutants/src/socks5___http_proxy_support.c`, `src/socks5___http_proxy_support.c`
- `socks5___http_proxy_support_process` (function) `include/socks5___http_proxy_support.h:4` `bool socks5___http_proxy_support_process(void);`

## include/structured_jsonl_logging.h
Imported by: `mutants/src/structured_jsonl_logging.c`, `src/structured_jsonl_logging.c`
- `structured_jsonl_logging_process` (function) `include/structured_jsonl_logging.h:4` `bool structured_jsonl_logging_process(void);`

## include/tls_client_certificate_authentication.h
Imported by: `mutants/src/tls_client_certificate_authentication.c`, `src/tls_client_certificate_authentication.c`
- `tls_client_certificate_authentication_process` (function) `include/tls_client_certificate_authentication.h:4` `bool tls_client_certificate_authentication_process(void);`

## include/unified_config_schema.h
Imported by: `mutants/src/unified_config_schema.c`, `src/unified_config_schema.c`
- `unified_config_schema_process` (function) `include/unified_config_schema.h:4` `bool unified_config_schema_process(void);`

## issudo.c
- `BeaconPrintf` (function) `issudo.c:10` `extern void BeaconPrintf(int, const char *, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `issudo.c:11` `extern void BeaconOutput(int, const char *, int);`
- `syscall3` (function) `issudo.c:22` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `syscall1` (function) `issudo.c:32` `static inline long syscall1(long n, long a1)`
- `strcmp` (function) `issudo.c:40` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function) `issudo.c:51` `static int get_username_from_uid(long uid, char *buf, int buf_size)` -- Obtener username desde /etc/passwd (sin libc)
- `go` (function) `issudo.c:121` `void go(char *args, int alen)`

## legacy/beacon3.c
- `BeaconPrintf` (function) `legacy/beacon3.c:196` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `legacy/beacon3.c:213` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/beacon3.c:227` `static void *create_trampoline(void *target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `legacy/beacon3.c:268` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `legacy/beacon3.c:286` `static void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `legacy/beacon3.c:324` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `legacy/beacon3.c:342` `char *https_request(const char *url, const char *method, const char *post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `legacy/beacon3.c:436` `char *base64_encode(const unsigned char *input, int len)` -- === BASE64 ===
- `base64_decode` (function) `legacy/beacon3.c:454` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/beacon3.c:480` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `legacy/beacon3.c:514` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/beacon3.c:550` `char *exec_cmd(const char *cmd, int *out_len)` -- === EXEC CMD ===
- `page_align` (function) `legacy/beacon3.c:576` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `legacy/beacon3.c:584` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `get_local_ips` (function) `legacy/beacon3.c:1083` `char *get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `legacy/beacon3.c:1118` `unsigned char *download_bof(const char *url, size_t *out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `legacy/beacon3.c:1141` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `legacy/beacon3.c:1187` `int main()` -- === MAIN ===

## legacy/beacon5.c
- `BeaconPrintf` (function) `legacy/beacon5.c:239` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `legacy/beacon5.c:256` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/beacon5.c:270` `static void *create_trampoline(void *target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `legacy/beacon5.c:311` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `legacy/beacon5.c:329` `static void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `legacy/beacon5.c:367` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `legacy/beacon5.c:385` `char *https_request(const char *url, const char *method, const char *post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `legacy/beacon5.c:479` `char *base64_encode(const unsigned char *input, int len)` -- === BASE64 ===
- `base64_decode` (function) `legacy/beacon5.c:497` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/beacon5.c:523` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `legacy/beacon5.c:557` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/beacon5.c:593` `char *exec_cmd(const char *cmd, int *out_len)` -- === EXEC CMD ===
- `page_align` (function) `legacy/beacon5.c:619` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `legacy/beacon5.c:627` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `get_local_ips` (function) `legacy/beacon5.c:1126` `char *get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `legacy/beacon5.c:1161` `unsigned char *download_bof(const char *url, size_t *out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `legacy/beacon5.c:1184` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...` -- === RUN BOF AND CAPTURE ===
- `mesh_mark_seen` (function) `legacy/beacon5.c:1231` `void mesh_mark_seen(const char *msg_id)`
- `mesh_is_seen` (function) `legacy/beacon5.c:1240` `int mesh_is_seen(const char *msg_id)`
- `mesh_add_peer` (function) `legacy/beacon5.c:1255` `void mesh_add_peer(const char *ip, int port)`
- `mesh_cleanup_peers` (function) `legacy/beacon5.c:1283` `void mesh_cleanup_peers()`
- `mesh_send_to_peer` (function) `legacy/beacon5.c:1300` `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
- `mesh_propagate` (function) `legacy/beacon5.c:1324` `void mesh_propagate(const char *command)`
- `mesh_discovery_thread` (function) `legacy/beacon5.c:1356` `void *mesh_discovery_thread(void *arg)`
- `mesh_listener_thread` (function) `legacy/beacon5.c:1447` `void *mesh_listener_thread(void *arg)`
- `mesh_send_message` (function) `legacy/beacon5.c:1667` `void mesh_send_message(int type, const char *target, const char *payload)`
- `main` (function) `legacy/beacon5.c:1702` `int main(int argc, char **argv)` -- === MAIN ===

## legacy/beacon6.c
- `delay_ms` (function) `legacy/beacon6.c:197` `static void delay_ms(int ms)` -- sleep ofuscated using poll
- `is_prime` (function) `legacy/beacon6.c:204` `static unsigned int is_prime(unsigned int x)` -- -- Lógica de números primos (sin cambios esenciales) ---
- `get_nth_prime_limited` (function) `legacy/beacon6.c:224` `static unsigned int get_nth_prime_limited(unsigned int n)` -- if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d <= x) { if (x % d == 0) return 0; d += 2; }...
- `portable_rand_19k_29k` (function) `legacy/beacon6.c:253` `static unsigned int portable_rand_19k_29k(void)`
- `BeaconPrintf` (function) `legacy/beacon6.c:266` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `legacy/beacon6.c:283` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/beacon6.c:297` `static void *create_trampoline(void *target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `legacy/beacon6.c:338` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `legacy/beacon6.c:356` `static void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `legacy/beacon6.c:394` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `https_request` (function) `legacy/beacon6.c:412` `char *https_request(const char *url, const char *method, const char *post_data)` -- === HTTPS REQUEST ===
- `base64_encode` (function) `legacy/beacon6.c:506` `char *base64_encode(const unsigned char *input, int len)` -- === BASE64 ===
- `base64_decode` (function) `legacy/beacon6.c:524` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/beacon6.c:550` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `legacy/beacon6.c:584` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/beacon6.c:620` `char *exec_cmd(const char *cmd, int *out_len)` -- === EXEC CMD ===
- `page_align` (function) `legacy/beacon6.c:646` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `legacy/beacon6.c:654` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `get_local_ips` (function) `legacy/beacon6.c:1153` `char *get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `legacy/beacon6.c:1188` `unsigned char *download_bof(const char *url, size_t *out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `legacy/beacon6.c:1211` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `legacy/beacon6.c:1257` `int main()` -- === MAIN ===

## legacy/beacon_p2p.c
- `BeaconDataParse` (function) `legacy/beacon_p2p.c:93` `void BeaconDataParse(datap *parser, char *buffer, int size)`
- `BeaconDataPtr` (function) `legacy/beacon_p2p.c:100` `char *BeaconDataPtr(datap *parser, int size)`
- `BeaconDataInt` (function) `legacy/beacon_p2p.c:110` `int BeaconDataInt(datap *parser)`
- `BeaconDataShort` (function) `legacy/beacon_p2p.c:118` `short BeaconDataShort(datap *parser)`
- `BeaconDataLength` (function) `legacy/beacon_p2p.c:126` `int BeaconDataLength(datap *parser)`
- `BeaconDataExtract` (function) `legacy/beacon_p2p.c:131` `char *BeaconDataExtract(datap *parser, int *size)`
- `BeaconPrintf` (function) `legacy/beacon_p2p.c:142` `void BeaconPrintf(int type, const char *fmt, ...)`
- `BeaconOutput` (function) `legacy/beacon_p2p.c:159` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/beacon_p2p.c:278` `static void *create_trampoline(void *target)`
- `cleanup_trampolines` (function) `legacy/beacon_p2p.c:309` `static void cleanup_trampolines(void)`
- `get_or_create_trampoline` (function) `legacy/beacon_p2p.c:323` `static void *get_or_create_trampoline(void *target)`
- `page_align` (function) `legacy/beacon_p2p.c:350` `static size_t page_align(size_t size)`
- `RunELF` (function) `legacy/beacon_p2p.c:358` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `WriteMemoryCallback` (function) `legacy/beacon_p2p.c:683` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `https_request` (function) `legacy/beacon_p2p.c:707` `char *https_request(const char *url, const char *method, const char *post_data)`
- `base64_encode` (function) `legacy/beacon_p2p.c:763` `char *base64_encode(const unsigned char *input, int len)`
- `base64_decode` (function) `legacy/beacon_p2p.c:780` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/beacon_p2p.c:802` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `aes256_cfb_decrypt` (function) `legacy/beacon_p2p.c:832` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/beacon_p2p.c:866` `char *exec_cmd(const char *cmd, int *out_len)`
- `get_local_ips` (function) `legacy/beacon_p2p.c:891` `char *get_local_ips()`
- `download_bof` (function) `legacy/beacon_p2p.c:925` `unsigned char *download_bof(const char *url, size_t *out_size)`
- `run_bof_and_capture` (function) `legacy/beacon_p2p.c:939` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
- `add_peer` (function) `legacy/beacon_p2p.c:965` `void add_peer(struct in_addr ip, int port, const char *id)`
- `peer_discovery_thread` (function) `legacy/beacon_p2p.c:992` `void *peer_discovery_thread(void *arg)`
- `handle_peer_connection` (function) `legacy/beacon_p2p.c:1032` `void *handle_peer_connection(void *arg)`
- `peer_server_thread` (function) `legacy/beacon_p2p.c:1130` `void *peer_server_thread(void *arg)`
- `send_to_peer` (function) `legacy/beacon_p2p.c:1153` `char *send_to_peer(peer_t *peer, const char *data, int *out_len)`
- `send_to_c2_or_peer` (function) `legacy/beacon_p2p.c:1197` `char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
- `execute_generic_command` (function) `legacy/beacon_p2p.c:1231` `char *execute_generic_command(const char *cmd, int *out_len)`
- `main` (function) `legacy/beacon_p2p.c:1276` `int main()`

## legacy/gopher_beacon.c
- `BeaconPrintf` (function) `legacy/gopher_beacon.c:193` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `legacy/gopher_beacon.c:210` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/gopher_beacon.c:224` `static void *create_trampoline(void *target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `legacy/gopher_beacon.c:265` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `legacy/gopher_beacon.c:283` `static void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `legacy/gopher_beacon.c:321` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `gopher_request` (function) `legacy/gopher_beacon.c:339` `char *gopher_request(const char *host, int port, const char *selector, const char *method,
      ...` -- === GOPHER REQUEST () ===
- `base64_encode` (function) `legacy/gopher_beacon.c:422` `char *base64_encode(const unsigned char *input, int len)` -- === BASE64 ===
- `base64_decode` (function) `legacy/gopher_beacon.c:440` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/gopher_beacon.c:466` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `legacy/gopher_beacon.c:500` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/gopher_beacon.c:536` `char *exec_cmd(const char *cmd, int *out_len)` -- === EXEC CMD ===
- `page_align` (function) `legacy/gopher_beacon.c:573` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `legacy/gopher_beacon.c:581` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `get_local_ips` (function) `legacy/gopher_beacon.c:1080` `char *get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `legacy/gopher_beacon.c:1115` `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `legacy/gopher_beacon.c:1147` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `legacy/gopher_beacon.c:1193` `int main()` -- === MAIN ===

## legacy/v1_gopher_beacon.c
- `BeaconPrintf` (function) `legacy/v1_gopher_beacon.c:193` `void BeaconPrintf(int type, const char *fmt, ...)` -- === BEACON API ===
- `BeaconOutput` (function) `legacy/v1_gopher_beacon.c:210` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `legacy/v1_gopher_beacon.c:224` `static void *create_trampoline(void *target)` -- === CRATE TRAPOLINE ===
- `cleanup_trampolines` (function) `legacy/v1_gopher_beacon.c:265` `static void cleanup_trampolines(void)` -- === CLEAN TRAMPOLINE ===
- `get_or_create_trampoline` (function) `legacy/v1_gopher_beacon.c:283` `static void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `legacy/v1_gopher_beacon.c:321` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` -- === CURL WRITE CALLBACK ===
- `gopher_request` (function) `legacy/v1_gopher_beacon.c:339` `char *gopher_request(const char *host, int port, const char *selector, const char *method,
      ...` -- === GOPHER REQUEST () ===
- `base64_encode` (function) `legacy/v1_gopher_beacon.c:422` `char *base64_encode(const unsigned char *input, int len)` -- === BASE64 ===
- `base64_decode` (function) `legacy/v1_gopher_beacon.c:440` `unsigned char *base64_decode(const char *input, int *len)`
- `aes256_cfb_encrypt` (function) `legacy/v1_gopher_beacon.c:466` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...` -- === AES CFB ===
- `aes256_cfb_decrypt` (function) `legacy/v1_gopher_beacon.c:500` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
- `exec_cmd` (function) `legacy/v1_gopher_beacon.c:536` `char *exec_cmd(const char *cmd, int *out_len)` -- === EXEC CMD ===
- `page_align` (function) `legacy/v1_gopher_beacon.c:573` `static size_t page_align(size_t size)` -- === Función auxiliar: alinear al tamaño de página ===
- `RunELF` (function) `legacy/v1_gopher_beacon.c:581` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `get_local_ips` (function) `legacy/v1_gopher_beacon.c:1080` `char *get_local_ips()` -- === GET LOCAL IPs ===
- `download_bof` (function) `legacy/v1_gopher_beacon.c:1115` `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` -- === DOWNLOAD BOF ===
- `run_bof_and_capture` (function) `legacy/v1_gopher_beacon.c:1147` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...` -- === RUN BOF AND CAPTURE ===
- `main` (function) `legacy/v1_gopher_beacon.c:1193` `int main()` -- === MAIN ===

## mutants/src/async_i_o_for_beacon.c
Depends on: `include/async_i_o_for_beacon.h`
- `async_i_o_for_beacon_process` (function) `mutants/src/async_i_o_for_beacon.c:6` `bool async_i_o_for_beacon_process(void)`

## mutants/src/beacon_heartbeat___health_endpoint.c
Depends on: `include/beacon_heartbeat___health_endpoint.h`
- `beacon_heartbeat___health_endpoint_process` (function) `mutants/src/beacon_heartbeat___health_endpoint.c:6` `bool beacon_heartbeat___health_endpoint_process(void)`

## mutants/src/bof_api_versioning.c
Depends on: `include/bof_api_versioning.h`
- `bof_api_versioning_process` (function) `mutants/src/bof_api_versioning.c:6` `bool bof_api_versioning_process(void)`

## mutants/src/bof_path_traversal_hardening.c
Depends on: `include/bof_path_traversal_hardening.h`
- `bof_path_traversal_hardening_process` (function) `mutants/src/bof_path_traversal_hardening.c:6` `bool bof_path_traversal_hardening_process(void)`

## mutants/src/bof_streaming_(large_outputs).c
Depends on: `include/bof_streaming_(large_outputs).h`
- `bof_streaming_` (function) `mutants/src/bof_streaming_(large_outputs).c:6` `bool bof_streaming_(large_outputs)_process(void)`

## mutants/src/c2_rest_api.c
Depends on: `include/c2_rest_api.h`
- `c2_rest_api_process` (function) `mutants/src/c2_rest_api.c:6` `bool c2_rest_api_process(void)`

## mutants/src/certificate_pinning___tofu.c
Depends on: `include/certificate_pinning___tofu.h`
- `certificate_pinning___tofu_process` (function) `mutants/src/certificate_pinning___tofu.c:6` `bool certificate_pinning___tofu_process(void)`

## mutants/src/command_execution_via_execve.c
Depends on: `include/command_execution_via_execve.h`
- `command_execution_via_execve_process` (function) `mutants/src/command_execution_via_execve.c:6` `bool command_execution_via_execve_process(void)`

## mutants/src/hkdf_key_derivation.c
Depends on: `include/hkdf_key_derivation.h`
- `hkdf_key_derivation_process` (function) `mutants/src/hkdf_key_derivation.c:6` `bool hkdf_key_derivation_process(void)`

## mutants/src/iv_generation_with_entropy_verification.c
Depends on: `include/iv_generation_with_entropy_verification.h`
- `iv_generation_with_entropy_verification_process` (function) `mutants/src/iv_generation_with_entropy_verification.c:6` `bool iv_generation_with_entropy_verification_process(void)`

## mutants/src/replay_protection.c
Depends on: `include/replay_protection.h`
- `replay_protection_process` (function) `mutants/src/replay_protection.c:6` `bool replay_protection_process(void)`

## mutants/src/socks5___http_proxy_support.c
Depends on: `include/socks5___http_proxy_support.h`
- `socks5___http_proxy_support_process` (function) `mutants/src/socks5___http_proxy_support.c:6` `bool socks5___http_proxy_support_process(void)`

## mutants/src/structured_jsonl_logging.c
Depends on: `include/structured_jsonl_logging.h`
- `structured_jsonl_logging_process` (function) `mutants/src/structured_jsonl_logging.c:6` `bool structured_jsonl_logging_process(void)`

## mutants/src/tls_client_certificate_authentication.c
Depends on: `include/tls_client_certificate_authentication.h`
- `tls_client_certificate_authentication_process` (function) `mutants/src/tls_client_certificate_authentication.c:6` `bool tls_client_certificate_authentication_process(void)`

## mutants/src/unified_config_schema.c
Depends on: `include/unified_config_schema.h`
- `unified_config_schema_process` (function) `mutants/src/unified_config_schema.c:6` `bool unified_config_schema_process(void)`

## mutants/tests/config_harness.c
Depends on: `include/config.h`
- `main` (function) `mutants/tests/config_harness.c:22` `int main(void)`

## src/async_i_o_for_beacon.c
Depends on: `include/async_i_o_for_beacon.h`
- `async_i_o_for_beacon_process` (function) `src/async_i_o_for_beacon.c:6` `bool async_i_o_for_beacon_process(void)`

## src/beacon_heartbeat___health_endpoint.c
Depends on: `include/beacon_heartbeat___health_endpoint.h`
- `beacon_heartbeat___health_endpoint_process` (function) `src/beacon_heartbeat___health_endpoint.c:6` `bool beacon_heartbeat___health_endpoint_process(void)`


Next: [API_p3.md](API_p3.md)
