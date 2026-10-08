# API (page 2 of 2)
Previous: [API.md](API.md)

## include/aes.h
Imported by: `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c`
- `AES_init_ctx` (function) `include/aes.h:41` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- `AES_init_ctx_iv` (function) `include/aes.h:43` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `include/aes.h:44` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- `AES_ECB_encrypt` (function) `include/aes.h:48` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` -- if defined(ECB) && (ECB == 1)
- `AES_ECB_decrypt` (function) `include/aes.h:49` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- `AES_CBC_encrypt_buffer` (function) `include/aes.h:53` `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CBC) && (CBC == 1)
- `AES_CBC_decrypt_buffer` (function) `include/aes.h:54` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (function) `include/aes.h:58` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CTR) && (CTR == 1)

## include/aes_cfb.c
Depends on: `include/aes.h`
- `aes256_cfb_encrypt` (function) `include/aes_cfb.c:20` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `aes256_cfb_decrypt` (function) `include/aes_cfb.c:48` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`

## include/aes_cfb.h
Imported by: `tests/crypto_harness.c`
- `aes256_cfb_encrypt` (function) `include/aes_cfb.h:9` `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext...`
- `aes256_cfb_decrypt` (function) `include/aes_cfb.h:11` `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char*...`

## include/beacon.h
- `BeaconDataParse` (function) `include/beacon.h:21` `void BeaconDataParse(datap *parser, char *buffer, int size);` -- === API para BOFs ===
- `BeaconDataPtr` (function) `include/beacon.h:22` `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function) `include/beacon.h:23` `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function) `include/beacon.h:24` `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function) `include/beacon.h:25` `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function) `include/beacon.h:26` `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (function) `include/beacon.h:27` `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (function) `include/beacon.h:28` `void BeaconOutput(int type, const char *data, int len);`

## include/beacon_common.c
Depends on: `include/aes.h`, `include/beacon_common.h`, `include/cJSON.h`
- `bsb_output_init` (function) `include/beacon_common.c:100` `int bsb_output_init(size_t capacity)` -- { "BeaconOutput",   &g_BeaconOutput_ptr }, { "socket",         &g_socket_ptr }, { "connect",        &g_connect_ptr...
- `bsb_output_cleanup` (function) `include/beacon_common.c:110` `void bsb_output_cleanup(void)`
- `bsb_output_reset` (function) `include/beacon_common.c:117` `void bsb_output_reset(void)`
- `BeaconPrintf` (function) `include/beacon_common.c:125` `void BeaconPrintf(int type, const char *fmt, ...)` -- free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; } void...
- `BeaconOutput` (function) `include/beacon_common.c:138` `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (function) `include/beacon_common.c:151` `void *create_trampoline(void *target)` -- void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data)...
- `cleanup_trampolines` (function) `include/beacon_common.c:181` `void cleanup_trampolines(void)`
- `get_or_create_trampoline` (function) `include/beacon_common.c:196` `void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (function) `include/beacon_common.c:225` `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `https_request` (function) `include/beacon_common.c:237` `http_response_t https_request(const bsb_config_t *cfg, const char *url,
                         ...`
- `base64_encode` (function) `include/beacon_common.c:291` `char *base64_encode(const unsigned char *input, int len)` -- curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE...
- `base64_decode` (function) `include/beacon_common.c:307` `unsigned char *base64_decode(const char *input, int *len)`
- `url_encode` (function) `include/beacon_common.c:335` `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
- `exec_cmd` (function) `include/beacon_common.c:358` `char *exec_cmd(const char *cmd, int *out_len)` -- static const char hex[] = "0123456789ABCDEF"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c &...
- `bsb_backoff_init` (function) `include/beacon_common.c:385` `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` -- if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; }...
- `bsb_backoff_next` (function) `include/beacon_common.c:391` `int bsb_backoff_next(bsb_backoff_t *bo)`
- `bsb_backoff_reset` (function) `include/beacon_common.c:400` `void bsb_backoff_reset(bsb_backoff_t *bo)`
- `get_local_ips` (function) `include/beacon_common.c:405` `char *get_local_ips(void)` -- int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if...
- `download_bof` (function) `include/beacon_common.c:434` `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` -- for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family...
- `init_function_pointers` (function) `include/beacon_common.c:446` `static void init_function_pointers(void)` -- /* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) {...
- `page_align` (function) `include/beacon_common.c:472` `static size_t page_align(size_t size)`
- `RunELF` (function) `include/beacon_common.c:507` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `run_bof_and_capture` (function) `include/beacon_common.c:711` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           ...`

## include/beacon_common.h
Depends on: `include/config.h`
Imported by: `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`
- `bsb_output_init` (function) `include/beacon_common.h:93` `int bsb_output_init(size_t capacity);` -- Initialize the output buffer.
- `bsb_output_cleanup` (function) `include/beacon_common.h:96` `void bsb_output_cleanup(void);` -- Initialize the output buffer.
- `bsb_output_reset` (function) `include/beacon_common.h:99` `void bsb_output_reset(void);` -- Initialize the output buffer.
- `BeaconPrintf` (function) `include/beacon_common.h:102` `void BeaconPrintf(int type, const char *fmt, ...);` -- Initialize the output buffer.
- `BeaconOutput` (function) `include/beacon_common.h:105` `void BeaconOutput(int type, const char *data, int len);` -- Initialize the output buffer.
- `create_trampoline` (function) `include/beacon_common.h:108` `void *create_trampoline(void *target);` -- /* Free the output buffer.
- `cleanup_trampolines` (function) `include/beacon_common.h:109` `void cleanup_trampolines(void);`
- `get_or_create_trampoline` (function) `include/beacon_common.h:110` `void *get_or_create_trampoline(void *target);`
- `https_request` (function) `include/beacon_common.h:116` `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` -- HTTP client: performs GET or POST request.
- `base64_encode` (function) `include/beacon_common.h:122` `char *base64_encode(const unsigned char *input, int len);` -- HTTP client: performs GET or POST request.
- `base64_decode` (function) `include/beacon_common.h:123` `unsigned char *base64_decode(const char *input, int *len);`
- `url_encode` (function) `include/beacon_common.h:126` `char *url_encode(const char *in, size_t in_len, size_t *out_len);` -- HTTP client: performs GET or POST request.
- `aes256_cfb_encrypt` (function) `include/beacon_common.h:129` `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext...` -- Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg...
- `aes256_cfb_decrypt` (function) `include/beacon_common.h:133` `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char...`
- `buffer` (function) `include/beacon_common.h:139` `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);`
- `RunELF` (function) `include/beacon_common.h:147` `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int...` -- ELF BOF loader.
- `download_bof` (function) `include/beacon_common.h:155` `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` -- Download a BOF from the C2 server.
- `run_bof_and_capture` (function) `include/beacon_common.h:161` `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` -- Execute a BOF and capture its output.
- `get_local_ips` (function) `include/beacon_common.h:169` `char *get_local_ips(void);` -- Get local IP addresses as a comma-separated string.
- `bsb_backoff_init` (function) `include/beacon_common.h:179` `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);`
- `bsb_backoff_next` (function) `include/beacon_common.h:180` `int bsb_backoff_next(bsb_backoff_t *bo);`
- `bsb_backoff_reset` (function) `include/beacon_common.h:181` `void bsb_backoff_reset(bsb_backoff_t *bo);`

## include/cJSON.c
Depends on: `include/cJSON.h`
- `CJSON_PUBLIC` (function) `include/cJSON.c:95` `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:100` `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:110` `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:125` `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- `case_insensitive_strcmp` (function) `include/cJSON.c:134` `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` -- /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR...
- `internal_malloc` (function) `include/cJSON.c:166` `static void * CJSON_CDECL internal_malloc(size_t size)` -- } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL...
- `internal_free` (function) `include/cJSON.c:170` `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (function) `include/cJSON.c:174` `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (function) `include/cJSON.c:189` `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:210` `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (function) `include/cJSON.c:242` `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` -- if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and...
- `get_decimal_point` (function) `include/cJSON.c:281` `static unsigned char get_decimal_point(void)` -- item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {...
- `parse_number` (function) `include/cJSON.c:309` `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` -- size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset....
- `ensure` (function) `include/cJSON.c:494` `static unsigned char* ensure(printbuffer * const p, size_t needed)` -- } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for...
- `update_offset` (function) `include/cJSON.c:579` `static void update_offset(printbuffer * const buffer)` -- p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); }...
- `compare_double` (function) `include/cJSON.c:592` `static cJSON_bool compare_double(double a, double b)` -- /* calculate the new length of the string in a printbuffer and update the offset static void...
- `print_number` (function) `include/cJSON.c:599` `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` -- } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /*...
- `parse_hex4` (function) `include/cJSON.c:669` `static unsigned parse_hex4(const unsigned char * const input)` -- output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'...
- `utf16_literal_to_utf8` (function) `include/cJSON.c:706` `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` -- converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- `parse_string` (function) `include/cJSON.c:827` `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` -- else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return...
- `print_string_ptr` (function) `include/cJSON.c:957` `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` -- { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset =...
- `print_string` (function) `include/cJSON.c:1079` `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` -- /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer +=...
- `buffer_skip_whitespace` (function) `include/cJSON.c:1093` `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` -- static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned...
- `skip_utf8_bom` (function) `include/cJSON.c:1119` `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` -- while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if...
- `CJSON_PUBLIC` (function) `include/cJSON.c:1134` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1236` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (function) `include/cJSON.c:1243` `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1316` `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1321` `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1352` `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (function) `include/cJSON.c:1372` `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` -- return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true...
- `print_value` (function) `include/cJSON.c:1427` `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` -- if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item...
- `parse_array` (function) `include/cJSON.c:1501` `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` -- return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case...
- `print_array` (function) `include/cJSON.c:1599` `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `parse_object` (function) `include/cJSON.c:1661` `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` -- output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'...
- `print_object` (function) `include/cJSON.c:1780` `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `get_array_item` (function) `include/cJSON.c:1916` `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1935` `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (function) `include/cJSON.c:1945` `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1977` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1982` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:1987` `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (function) `include/cJSON.c:1993` `static void suffix_object(cJSON *prev, cJSON *item)` -- return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON...
- `create_reference` (function) `include/cJSON.c:2000` `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` -- CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return...
- `add_item_to_array` (function) `include/cJSON.c:2021` `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (function) `include/cJSON.c:2066` `static void* cast_away_const(const void* string)` -- /* Add item to array/object.
- `add_item_to_object` (function) `include/cJSON.c:2075` `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2112` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2123` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2133` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2143` `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2155` `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2167` `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2179` `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2191` `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2203` `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2215` `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2227` `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2239` `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2251` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2287` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2297` `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2302` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2309` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2316` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2321` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2363` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2413` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (function) `include/cJSON.c:2423` `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2446` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2451` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2468` `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2479` `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2490` `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2501` `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2526` `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2543` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2555` `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2567` `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2579` `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2596` `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2607` `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2659` `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2699` `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2739` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (function) `include/cJSON.c:2786` `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (function) `include/cJSON.c:2873` `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (function) `include/cJSON.c:2886` `static void skip_multiline_comment(char **input)`
- `minify_string` (function) `include/cJSON.c:2900` `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2922` `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2972` `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2982` `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:2992` `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3002` `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3012` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3022` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3032` `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3042` `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3052` `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3062` `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3072` `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (function) `include/cJSON.c:3157` `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (function) `include/cJSON.c:3173` `cJSON_ArrayForEach(b_element, b)` -- doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this...
- `CJSON_PUBLIC` (function) `include/cJSON.c:3194` `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (function) `include/cJSON.c:3199` `CJSON_PUBLIC(void) cJSON_free(void *object)`

## include/cJSON.h
Imported by: `include/beacon_common.c`, `include/cJSON.c`
- `sensitive` (function) `include/cJSON.h:249` `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */...`

## include/config.c
Depends on: `include/config.h`
- `slurp` (function) `include/config.c:24` `static char *slurp(const char *path, size_t *out_len)` -- declared in the schema.
- `skip_ws` (function) `include/config.c:41` `static const char *skip_ws(const char *p, const char *end)` -- fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf =...
- `read_string` (function) `include/config.c:49` `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` -- Read a JSON string starting at *pp (which must point at ").
- `read_int` (function) `include/config.c:76` `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function) `include/config.c:92` `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function) `include/config.c:100` `static int expect(const char **pp, const char *end, char c)` -- } out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *end, int *out) {...
- `find_matching_brace` (function) `include/config.c:109` `static const char *find_matching_brace(const char *p, const char *end)` -- Find the byte position of the matching closing brace for the * opening { at *pp.
- `skip_value` (function) `include/config.c:132` `static const char *skip_value(const char *p, const char *end)` -- Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or...
- `hex_to_bytes` (function) `include/config.c:174` `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` -- else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if...
- `parse_c2` (function) `include/config.c:186` `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` -- /* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen =...
- `parse_crypto` (function) `include/config.c:209` `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function) `include/config.c:230` `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function) `include/config.c:253` `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function) `include/config.c:289` `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function) `include/config.c:308` `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function) `include/config.c:328` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` -- if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end...
- `binary_dir` (function) `include/config.c:420` `static const char *binary_dir(char *out, size_t outsz)` -- Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without...
- `bsb_config_load_default` (function) `include/config.c:438` `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- `bsb_config_sleep_seconds` (function) `include/config.c:466` `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`

## include/config.h
Imported by: `include/beacon_common.h`, `include/config.c`, `tests/config_harness.c`
- `bsb_config_load` (function) `include/config.h:77` `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` -- Load config from path.
- `bsb_config_load_default` (function) `include/config.h:80` `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` -- Load config from path.
- `bsb_config_sleep_seconds` (function) `include/config.h:83` `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` -- Load config from path.

## include/config_py.py
Imported by: `c2/server.py`
- `load_config` (function) `include/config_py.py:65` `def load_config(path)` -- Load and validate a BSB config file.

## issudo.c
- `BeaconPrintf` (function) `issudo.c:10` `extern void BeaconPrintf(int, const char*, ...);` -- Símbolos del beacon
- `BeaconOutput` (function) `issudo.c:11` `extern void BeaconOutput(int, const char*, int);`
- `syscall3` (function) `issudo.c:22` `static inline long syscall3(long n, long a1, long a2, long a3)` -- Wrappers
- `syscall1` (function) `issudo.c:32` `static inline long syscall1(long n, long a1)`
- `strcmp` (function) `issudo.c:43` `static int strcmp(const char *s1, const char *s2)` -- strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function) `issudo.c:52` `static int get_username_from_uid(long uid, char *buf, int buf_size)` -- Obtener username desde /etc/passwd (sin libc)
- `go` (function) `issudo.c:108` `void go(char *args, int alen)`

## tests/config_harness.c
Depends on: `include/config.h`
- `main` (function) `tests/config_harness.c:22` `int main(void)`

