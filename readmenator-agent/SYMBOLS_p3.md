# Symbols (page 3 of 4)
Previous: [SYMBOLS_p2.md](SYMBOLS_p2.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `cJSON_GetErrorPtr` | function | `include/cJSON.h:161` | `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...` |
| `cJSON_Hooks` | struct | `include/cJSON.h:123` | `` |
| `cJSON_Invalid` | macro | `include/cJSON.h:84` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `include/cJSON.h:94` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `include/cJSON.h:87` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `include/cJSON.h:88` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `include/cJSON.h:91` | `#define cJSON_Object` |
| `cJSON_Parse` | function | `include/cJSON.h:152` | `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...` |
| `cJSON_Raw` | macro | `include/cJSON.h:92` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `include/cJSON.h:324` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `include/cJSON.h:312` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `include/cJSON.h:316` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `include/cJSON.h:89` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `include/cJSON.h:95` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `include/cJSON.h:86` | `#define cJSON_True` |
| `cJSON__h` | macro | `include/cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `include/cJSON.h:130` | `typedef int cJSON_bool;` |
| `next` | variable | `include/cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `include/cJSON.h:286` | `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...` |
| `that` | function | `include/cJSON.h:247` | `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...` |
| `CERTIFICATE_PINNING___TOFU_H` | macro | `include/certificate_pinning___tofu.h:2` | `#define CERTIFICATE_PINNING___TOFU_H` |
| `certificate_pinning___tofu_process` | function | `include/certificate_pinning___tofu.h:4` | `bool certificate_pinning___tofu_process(void);` |
| `COMMAND_EXECUTION_VIA_EXECVE_H` | macro | `include/command_execution_via_execve.h:2` | `#define COMMAND_EXECUTION_VIA_EXECVE_H` |
| `command_execution_via_execve_process` | function | `include/command_execution_via_execve.h:4` | `bool command_execution_via_execve_process(void);` |
| `HKDF_INFO_ENC` | macro | `include/config.c:289` | `#define HKDF_INFO_ENC` |
| `HKDF_INFO_HMAC` | macro | `include/config.c:290` | `#define HKDF_INFO_HMAC` |
| `HKDF_SALT` | macro | `include/config.c:288` | `#define HKDF_SALT` |
| `_POSIX_C_SOURCE` | macro | `include/config.c:13` | `#define _POSIX_C_SOURCE` |
| `binary_dir` | function | `include/config.c:798` | `static const char *binary_dir(char *out, size_t outsz)` |
| `bsb_config_load` | function | `include/config.c:655` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_load_default` | function | `include/config.c:820` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)` |
| `bsb_config_sleep_seconds` | function | `include/config.c:853` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg)` |
| `derive_keys_from_master` | function | `include/config.c:345` | `static void derive_keys_from_master(bsb_config_t *cfg)` |
| `expect` | function | `include/config.c:156` | `static int expect(const char **pp, const char *end, char c)` |
| `find_matching_brace` | function | `include/config.c:167` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `hex_to_bytes` | function | `include/config.c:269` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `hkdf_expand` | function | `include/config.c:305` | `static void hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,...` |
| `hkdf_extract` | function | `include/config.c:299` | `static void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len...` |
| `hkdf_sha256` | function | `include/config.c:337` | `static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,...` |
| `hmac_sha256` | function | `include/config.c:292` | `static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,...` |
| `parse_backoff` | function | `include/config.c:620` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config.c:586` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config.c:375` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config.c:419` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config.c:518` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config.c:474` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config.c:137` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config.c:113` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config.c:66` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config.c:203` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config.c:56` | `static const char *skip_ws(const char *p, const char *end)` |
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
| `bsb_backoff_config_t` | struct | `include/config.h:70` | `` |
| `bsb_bof_t` | struct | `include/config.h:64` | `` |
| `bsb_c2_t` | struct | `include/config.h:30` | `` |
| `bsb_config_load` | function | `include/config.h:89` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_load_default` | function | `include/config.h:92` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_sleep_seconds` | function | `include/config.h:95` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` |
| `bsb_config_t` | struct | `include/config.h:76` | `` |
| `bsb_crypto_t` | struct | `include/config.h:38` | `` |
| `bsb_network_t` | struct | `include/config.h:56` | `` |
| `bsb_timing_t` | struct | `include/config.h:48` | `` |
| `_POSIX_C_SOURCE` | macro | `include/config_autogen.c:5` | `#define _POSIX_C_SOURCE` |
| `bsb_config_load` | function | `include/config_autogen.c:375` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` |
| `expect` | function | `include/config_autogen.c:93` | `static int expect(const char **pp, const char *end, char c)` |
| `find_matching_brace` | function | `include/config_autogen.c:101` | `static const char *find_matching_brace(const char *p, const char *end)` |
| `hex_to_bytes` | function | `include/config_autogen.c:165` | `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` |
| `parse_backoff` | function | `include/config_autogen.c:325` | `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_bof` | function | `include/config_autogen.c:300` | `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_c2` | function | `include/config_autogen.c:177` | `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_crypto` | function | `include/config_autogen.c:206` | `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_network` | function | `include/config_autogen.c:260` | `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_server` | function | `include/config_autogen.c:350` | `static void parse_server(const char *p, const char *end, bsb_config_t *cfg)` |
| `parse_timing` | function | `include/config_autogen.c:227` | `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)` |
| `read_bool` | function | `include/config_autogen.c:85` | `static int read_bool(const char **pp, const char *end, int *out)` |
| `read_int` | function | `include/config_autogen.c:68` | `static int read_int(const char **pp, const char *end, int *out)` |
| `read_string` | function | `include/config_autogen.c:40` | `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` |
| `skip_value` | function | `include/config_autogen.c:123` | `static const char *skip_value(const char *p, const char *end)` |
| `skip_ws` | function | `include/config_autogen.c:34` | `static const char *skip_ws(const char *p, const char *end)` |
| `slurp` | function | `include/config_autogen.c:16` | `static char *slurp(const char *path, size_t *out_len)` |
| `BSB_CONFIG_AUTOGEN_H` | macro | `include/config_autogen.h:6` | `#define BSB_CONFIG_AUTOGEN_H` |
| `bsb_backoff_t` | struct | `include/config_autogen.h:47` | `` |
| `bsb_bof_t` | struct | `include/config_autogen.h:42` | `` |
| `bsb_c2_t` | struct | `include/config_autogen.h:11` | `` |
| `bsb_config_load` | function | `include/config_autogen.h:69` | `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_load_default` | function | `include/config_autogen.h:72` | `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` |
| `bsb_config_sleep_seconds` | function | `include/config_autogen.h:75` | `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` |
| `bsb_config_t` | struct | `include/config_autogen.h:57` | `` |
| `bsb_crypto_t` | struct | `include/config_autogen.h:21` | `` |
| `bsb_network_t` | struct | `include/config_autogen.h:35` | `` |
| `bsb_server_t` | struct | `include/config_autogen.h:52` | `` |
| `bsb_timing_t` | struct | `include/config_autogen.h:28` | `` |
| `_deep_merge` | function | `include/config_py.py:84` | `def _deep_merge(base, overlay)` |
| `_derive_keys` | function | `include/config_py.py:65` | `def _derive_keys(master_key_bytes)` |
| `load_config` | function | `include/config_py.py:94` | `def load_config(path)` |
| `_deep_merge` | function | `include/config_py_autogen.py:80` | `def _deep_merge(base, overlay)` |
| `_derive_keys` | function | `include/config_py_autogen.py:59` | `def _derive_keys(master_key_bytes)` |
| `load_config` | function | `include/config_py_autogen.py:89` | `def load_config(path)` |
| `CONTAINERIZED_BUILD_` | macro | `include/containerized_build_+_sbom.h:2` | `#define CONTAINERIZED_BUILD_` |
| `HKDF_KEY_DERIVATION_H` | macro | `include/hkdf_key_derivation.h:2` | `#define HKDF_KEY_DERIVATION_H` |
| `hkdf_key_derivation_process` | function | `include/hkdf_key_derivation.h:4` | `bool hkdf_key_derivation_process(void);` |
| `IV_GENERATION_WITH_ENTROPY_VERIFICATION_H` | macro | `include/iv_generation_with_entropy_verification.h:2` | `#define IV_GENERATION_WITH_ENTROPY_VERIFICATION_H` |
| `iv_generation_with_entropy_verification_process` | function | `include/iv_generation_with_entropy_verification.h:4` | `bool iv_generation_with_entropy_verification_process(void);` |
| `MUTATION_TESTING_INTEGRATION_H` | macro | `include/mutation_testing_integration.h:2` | `#define MUTATION_TESTING_INTEGRATION_H` |
| `mutation_testing_integration_process` | function | `include/mutation_testing_integration.h:4` | `bool mutation_testing_integration_process(void);` |
| `PRE` | macro | `include/pre-commit_+_ci_hardening.h:2` | `#define PRE` |
| `REPLAY_PROTECTION_H` | macro | `include/replay_protection.h:2` | `#define REPLAY_PROTECTION_H` |
| `replay_protection_process` | function | `include/replay_protection.h:4` | `bool replay_protection_process(void);` |
| `SOCKS5___HTTP_PROXY_SUPPORT_H` | macro | `include/socks5___http_proxy_support.h:2` | `#define SOCKS5___HTTP_PROXY_SUPPORT_H` |
| `socks5___http_proxy_support_process` | function | `include/socks5___http_proxy_support.h:4` | `bool socks5___http_proxy_support_process(void);` |
| `STRUCTURED_JSONL_LOGGING_H` | macro | `include/structured_jsonl_logging.h:2` | `#define STRUCTURED_JSONL_LOGGING_H` |
| `structured_jsonl_logging_process` | function | `include/structured_jsonl_logging.h:4` | `bool structured_jsonl_logging_process(void);` |
| `TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H` | macro | `include/tls_client_certificate_authentication.h:2` | `#define TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H` |
| `tls_client_certificate_authentication_process` | function | `include/tls_client_certificate_authentication.h:4` | `bool tls_client_certificate_authentication_process(void);` |
| `UNIFIED_CONFIG_SCHEMA_H` | macro | `include/unified_config_schema.h:2` | `#define UNIFIED_CONFIG_SCHEMA_H` |
| `unified_config_schema_process` | function | `include/unified_config_schema.h:4` | `bool unified_config_schema_process(void);` |
| `AT_FDCWD` | macro | `issudo.c:19` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `issudo.c:11` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `issudo.c:10` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `issudo.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `issudo.c:2` | `#define NULL` |
| `SYS_close` | macro | `issudo.c:16` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `issudo.c:18` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `issudo.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `issudo.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `issudo.c:15` | `#define SYS_read` |
| `get_username_from_uid` | function | `issudo.c:51` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `issudo.c:121` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `issudo.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `issudo.c:7` | `typedef long ssize_t;` |
| `strcmp` | function | `issudo.c:40` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `issudo.c:32` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `issudo.c:22` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `async_i_o_for_beacon_process` | function | `mutants/src/async_i_o_for_beacon.c:6` | `bool async_i_o_for_beacon_process(void)` |
| `beacon_heartbeat___health_endpoint_process` | function | `mutants/src/beacon_heartbeat___health_endpoint.c:6` | `bool beacon_heartbeat___health_endpoint_process(void)` |
| `bof_api_versioning_process` | function | `mutants/src/bof_api_versioning.c:6` | `bool bof_api_versioning_process(void)` |
| `bof_path_traversal_hardening_process` | function | `mutants/src/bof_path_traversal_hardening.c:6` | `bool bof_path_traversal_hardening_process(void)` |
| `bof_streaming_` | function | `mutants/src/bof_streaming_(large_outputs).c:6` | `bool bof_streaming_(large_outputs)_process(void)` |
| `c2_rest_api_process` | function | `mutants/src/c2_rest_api.c:6` | `bool c2_rest_api_process(void)` |
| `certificate_pinning___tofu_process` | function | `mutants/src/certificate_pinning___tofu.c:6` | `bool certificate_pinning___tofu_process(void)` |
| `command_execution_via_execve_process` | function | `mutants/src/command_execution_via_execve.c:6` | `bool command_execution_via_execve_process(void)` |
| `hkdf_key_derivation_process` | function | `mutants/src/hkdf_key_derivation.c:6` | `bool hkdf_key_derivation_process(void)` |
| `iv_generation_with_entropy_verification_process` | function | `mutants/src/iv_generation_with_entropy_verification.c:6` | `bool iv_generation_with_entropy_verification_process(void)` |
| `mutation_testing_integration_process` | function | `mutants/src/mutation_testing_integration.c:6` | `bool mutation_testing_integration_process(void)` |
| `replay_protection_process` | function | `mutants/src/replay_protection.c:6` | `bool replay_protection_process(void)` |
| `socks5___http_proxy_support_process` | function | `mutants/src/socks5___http_proxy_support.c:6` | `bool socks5___http_proxy_support_process(void)` |
| `structured_jsonl_logging_process` | function | `mutants/src/structured_jsonl_logging.c:6` | `bool structured_jsonl_logging_process(void)` |
| `tls_client_certificate_authentication_process` | function | `mutants/src/tls_client_certificate_authentication.c:6` | `bool tls_client_certificate_authentication_process(void)` |
| `unified_config_schema_process` | function | `mutants/src/unified_config_schema.c:6` | `bool unified_config_schema_process(void)` |
| `main` | function | `mutants/tests/config_harness.c:22` | `int main(void)` |
| `hex_to_bytes` | function | `mutants/tests/crypto_harness.c:12` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `mutants/tests/crypto_harness.c:23` | `int main(int argc, char **argv)` |
| `TestAsyncIOforBeacon` | class | `mutants/tests/test_async_i_o_for_beacon.py:18` | `class TestAsyncIOforBeacon` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_async_i_o_for_beacon.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_async_i_o_for_beacon_c.c:21` | `int main(void)` |
| `test_async_i_o_for_beacon_placeholder` | function | `mutants/tests/test_async_i_o_for_beacon_c.c:14` | `static void test_async_i_o_for_beacon_placeholder(void **state)` |
| `compile_beacon` | function | `mutants/tests/test_beacon_build.py:43` | `def compile_beacon()` |
| `ensure_beacon` | function | `mutants/tests/test_beacon_build.py:70` | `def ensure_beacon()` |
| `have_headers` | function | `mutants/tests/test_beacon_build.py:29` | `def have_headers()` |
| `inspect_binary` | function | `mutants/tests/test_beacon_build.py:65` | `def inspect_binary()` |
| `main` | function | `mutants/tests/test_beacon_build.py:123` | `def main()` |
| `test_beacon_compiles_and_links` | function | `mutants/tests/test_beacon_build.py:84` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `mutants/tests/test_beacon_build.py:93` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `mutants/tests/test_beacon_build.py:113` | `def test_beacon_exposes_elf_loader()` |
| `main` | function | `mutants/tests/test_beacon_common.c_extraction_c.c:21` | `int main(void)` |
| `TestBeaconHeartbeatHealthEndpoint` | class | `mutants/tests/test_beacon_heartbeat___health_endpoint.py:18` | `class TestBeaconHeartbeatHealthEndpoint` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_beacon_heartbeat___health_endpoint.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c:21` | `int main(void)` |
| `test_beacon_heartbeat___health_endpoint_placeholder` | function | `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c:14` | `static void test_beacon_heartbeat___health_endpoint_placeholder(void **state)` |
| `TestBOFAPIVersioning` | class | `mutants/tests/test_bof_api_versioning.py:18` | `class TestBOFAPIVersioning` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_api_versioning.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_api_versioning_c.c:21` | `int main(void)` |
| `test_bof_api_versioning_placeholder` | function | `mutants/tests/test_bof_api_versioning_c.c:14` | `static void test_bof_api_versioning_placeholder(void **state)` |
| `compile_bof` | function | `mutants/tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `mutants/tests/test_bof_compile.py:35` | `def inspect_symbols(obj_path)` |
| `main` | function | `mutants/tests/test_bof_compile.py:91` | `def main()` |
| `test_compile_all` | function | `mutants/tests/test_bof_compile.py:53` | `def test_compile_all()` |
| `test_export_go` | function | `mutants/tests/test_bof_compile.py:60` | `def test_export_go()` |
| `test_no_libc_leak` | function | `mutants/tests/test_bof_compile.py:80` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `mutants/tests/test_bof_compile.py:68` | `def test_unresolved_beacon_api()` |
| `TestBOFPathTraversalHardening` | class | `mutants/tests/test_bof_path_traversal_hardening.py:18` | `class TestBOFPathTraversalHardening` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_path_traversal_hardening.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_path_traversal_hardening_c.c:21` | `int main(void)` |
| `test_bof_path_traversal_hardening_placeholder` | function | `mutants/tests/test_bof_path_traversal_hardening_c.c:14` | `static void test_bof_path_traversal_hardening_placeholder(void **state)` |
| `TestBOFStreaming` | class | `mutants/tests/test_bof_streaming_(large_outputs).py:18` | `class TestBOFStreaming(LargeOutputs)` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_streaming_(large_outputs).py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_streaming_(large_outputs)_c.c:21` | `int main(void)` |
| `test_bof_streaming_` | function | `mutants/tests/test_bof_streaming_(large_outputs)_c.c:14` | `static void test_bof_streaming_(large_outputs)_placeholder(void **state)` |
| `_free_port` | function | `mutants/tests/test_c2_http_e2e.py:43` | `def _free_port()` |
| `_recv_response` | function | `mutants/tests/test_c2_http_e2e.py:51` | `def _recv_response(sock, timeout)` |
| `encode` | function | `mutants/tests/test_c2_http_e2e.py:274` | `def encode(s)` |
| `main` | function | `mutants/tests/test_c2_http_e2e.py:399` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `mutants/tests/test_c2_http_e2e.py:326` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `mutants/tests/test_c2_http_e2e.py:183` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `mutants/tests/test_c2_http_e2e.py:65` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `mutants/tests/test_c2_http_e2e.py:115` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `mutants/tests/test_c2_http_e2e.py:233` | `def test_http_post_with_url_encoded_b64_payload()` |
| `TestC2RESTAPI` | class | `mutants/tests/test_c2_rest_api.py:18` | `class TestC2RESTAPI` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_c2_rest_api.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_c2_rest_api_c.c:21` | `int main(void)` |
| `test_c2_rest_api_placeholder` | function | `mutants/tests/test_c2_rest_api_c.c:14` | `static void test_c2_rest_api_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_c2_server.py:134` | `def main()` |
| `make_state` | function | `mutants/tests/test_c2_server.py:39` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `mutants/tests/test_c2_server.py:85` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `mutants/tests/test_c2_server.py:92` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `mutants/tests/test_c2_server.py:46` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `mutants/tests/test_c2_server.py:58` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `mutants/tests/test_c2_server.py:111` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `mutants/tests/test_c2_server.py:69` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `mutants/tests/test_c2_server.py:120` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `mutants/tests/test_c2_server.py:127` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `mutants/tests/test_c2_server.py:104` | `def test_unknown_selector()` |
| `TestCertificatePinningCConfig` | class | `mutants/tests/test_certificate_pinning.py:86` | `class TestCertificatePinningCConfig` |
| `TestCertificatePinningConfig` | class | `mutants/tests/test_certificate_pinning.py:23` | `class TestCertificatePinningConfig` |
| `TestCertificatePinningIntegration` | class | `mutants/tests/test_certificate_pinning.py:96` | `class TestCertificatePinningIntegration` |
| `TestCertificatePinningMutationResistance` | class | `mutants/tests/test_certificate_pinning.py:126` | `class TestCertificatePinningMutationResistance` |
| `test_beacon_rejects_mismatched_certificate` | method | `mutants/tests/test_certificate_pinning.py:109` | `def test_beacon_rejects_mismatched_certificate(self)` |
| `test_beacon_verifies_pinned_certificate` | method | `mutants/tests/test_certificate_pinning.py:99` | `def test_beacon_verifies_pinned_certificate(self)` |
| `test_c_config_parses_fingerprint_field` | method | `mutants/tests/test_certificate_pinning.py:89` | `def test_c_config_parses_fingerprint_field(self)` |
| `test_config_defaults_to_empty_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:73` | `def test_config_defaults_to_empty_fingerprint(self)` |
| `test_config_loads_empty_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:26` | `def test_config_loads_empty_fingerprint(self)` |
| `test_config_loads_valid_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:38` | `def test_config_loads_valid_fingerprint(self)` |
| `test_config_rejects_invalid_fingerprint_length` | method | `mutants/tests/test_certificate_pinning.py:51` | `def test_config_rejects_invalid_fingerprint_length(self)` |
| `test_config_rejects_non_hex_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:62` | `def test_config_rejects_non_hex_fingerprint(self)` |
| `test_fingerprint_empty_check_not_mutated_to_always_true` | method | `mutants/tests/test_certificate_pinning.py:129` | `def test_fingerprint_empty_check_not_mutated_to_always_true(self)` |
| `test_fingerprint_hex_validation_not_mutated` | method | `mutants/tests/test_certificate_pinning.py:139` | `def test_fingerprint_hex_validation_not_mutated(self)` |
| `test_pin_option_set_only_when_fingerprint_present` | method | `mutants/tests/test_certificate_pinning.py:151` | `def test_pin_option_set_only_when_fingerprint_present(self)` |
| `test_tofu_first_connection_stores_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:117` | `def test_tofu_first_connection_stores_fingerprint(self)` |
| `TestCertificatePinningTOFU` | class | `mutants/tests/test_certificate_pinning___tofu.py:18` | `class TestCertificatePinningTOFU` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_certificate_pinning___tofu.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_certificate_pinning___tofu_c.c:21` | `int main(void)` |
| `test_certificate_pinning___tofu_placeholder` | function | `mutants/tests/test_certificate_pinning___tofu_c.c:14` | `static void test_certificate_pinning___tofu_placeholder(void **state)` |
| `TestCommandExecutionviaexecve` | class | `mutants/tests/test_command_execution_via_execve.py:18` | `class TestCommandExecutionviaexecve` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_command_execution_via_execve.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_command_execution_via_execve_c.c:21` | `int main(void)` |
| `test_command_execution_via_execve_placeholder` | function | `mutants/tests/test_command_execution_via_execve_c.c:14` | `static void test_command_execution_via_execve_placeholder(void **state)` |
| `compile_harness` | function | `mutants/tests/test_config.py:24` | `def compile_harness()` |
| `main` | function | `mutants/tests/test_config.py:156` | `def main()` |
| `run_harness` | function | `mutants/tests/test_config.py:38` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `mutants/tests/test_config.py:141` | `def test_bad_hex_key()` |
| `test_default_load` | function | `mutants/tests/test_config.py:55` | `def test_default_load()` |
| `test_missing_file` | function | `mutants/tests/test_config.py:90` | `def test_missing_file()` |
| `test_overrides` | function | `mutants/tests/test_config.py:73` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `mutants/tests/test_config.py:98` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `mutants/tests/test_config.py:115` | `def test_search_order_falls_back_to_cwd_default()` |
| `main` | function | `mutants/tests/test_containerized_build_+_sbom_c.c:21` | `int main(void)` |
| `compile_harness` | function | `mutants/tests/test_crypto.py:27` | `def compile_harness()` |
| `main` | function | `mutants/tests/test_crypto.py:126` | `def main()` |
| `run` | function | `mutants/tests/test_crypto.py:50` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `mutants/tests/test_crypto.py:63` | `def test_block_boundary()` |
| `test_known_ciphertext` | function | `mutants/tests/test_crypto.py:74` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `mutants/tests/test_crypto.py:68` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `mutants/tests/test_crypto.py:93` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `mutants/tests/test_crypto.py:59` | `def test_short()` |
| `TestHKDFKeyDerivation` | class | `mutants/tests/test_hkdf_key_derivation.py:18` | `class TestHKDFKeyDerivation` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_hkdf_key_derivation.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_hkdf_key_derivation_c.c:21` | `int main(void)` |
| `test_hkdf_key_derivation_placeholder` | function | `mutants/tests/test_hkdf_key_derivation_c.c:14` | `static void test_hkdf_key_derivation_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_install_deploy.py:120` | `def main()` |
| `make_all` | function | `mutants/tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `mutants/tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `mutants/tests/test_install_deploy.py:56` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `mutants/tests/test_install_deploy.py:98` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `mutants/tests/test_install_deploy.py:75` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `mutants/tests/test_install_deploy.py:90` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `mutants/tests/test_install_deploy.py:67` | `def test_staged_files_have_correct_modes()` |
| `TestIVGenerationwithEntropyVerification` | class | `mutants/tests/test_iv_generation_with_entropy_verification.py:18` | `class TestIVGenerationwithEntropyVerification` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_iv_generation_with_entropy_verification.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_iv_generation_with_entropy_verification_c.c:21` | `int main(void)` |
| `test_iv_generation_with_entropy_verification_placeholder` | function | `mutants/tests/test_iv_generation_with_entropy_verification_c.c:14` | `static void test_iv_generation_with_entropy_verification_placeholder(void **state)` |
| `TestMutationTestingIntegration` | class | `mutants/tests/test_mutation_testing_integration.py:18` | `class TestMutationTestingIntegration` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_mutation_testing_integration.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_mutation_testing_integration_c.c:21` | `int main(void)` |
| `test_mutation_testing_integration_placeholder` | function | `mutants/tests/test_mutation_testing_integration_c.c:14` | `static void test_mutation_testing_integration_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_pre-commit_+_ci_hardening_c.c:21` | `int main(void)` |
| `TestReplayProtection` | class | `mutants/tests/test_replay_protection.py:18` | `class TestReplayProtection` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_replay_protection.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_replay_protection_c.c:21` | `int main(void)` |
| `test_replay_protection_placeholder` | function | `mutants/tests/test_replay_protection_c.c:14` | `static void test_replay_protection_placeholder(void **state)` |
| `TestSOCKS5HTTPProxySupport` | class | `mutants/tests/test_socks5___http_proxy_support.py:18` | `class TestSOCKS5HTTPProxySupport` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_socks5___http_proxy_support.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_socks5___http_proxy_support_c.c:21` | `int main(void)` |
| `test_socks5___http_proxy_support_placeholder` | function | `mutants/tests/test_socks5___http_proxy_support_c.c:14` | `static void test_socks5___http_proxy_support_placeholder(void **state)` |
| `TestStructuredJSONLLogging` | class | `mutants/tests/test_structured_jsonl_logging.py:18` | `class TestStructuredJSONLLogging` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_structured_jsonl_logging.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_structured_jsonl_logging_c.c:21` | `int main(void)` |
| `test_structured_jsonl_logging_placeholder` | function | `mutants/tests/test_structured_jsonl_logging_c.c:14` | `static void test_structured_jsonl_logging_placeholder(void **state)` |
| `TestTLSClientCertificateAuthentication` | class | `mutants/tests/test_tls_client_certificate_authentication.py:18` | `class TestTLSClientCertificateAuthentication` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_tls_client_certificate_authentication.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_tls_client_certificate_authentication_c.c:21` | `int main(void)` |
| `test_tls_client_certificate_authentication_placeholder` | function | `mutants/tests/test_tls_client_certificate_authentication_c.c:14` | `static void test_tls_client_certificate_authentication_placeholder(void **state)` |
| `TestUnifiedConfigSchema` | class | `mutants/tests/test_unified_config_schema.py:18` | `class TestUnifiedConfigSchema` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_unified_config_schema.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_unified_config_schema_c.c:21` | `int main(void)` |
| `test_unified_config_schema_placeholder` | function | `mutants/tests/test_unified_config_schema_c.c:14` | `static void test_unified_config_schema_placeholder(void **state)` |
| `apply_mutation` | function | `scripts/mutation_test_c.py:103` | `def apply_mutation(content, line_num, mutated_line)` |
| `compile_and_test` | function | `scripts/mutation_test_c.py:111` | `def compile_and_test(mutant_dir, test_name)` |
| `find_mutable_lines` | function | `scripts/mutation_test_c.py:82` | `def find_mutable_lines(content)` |
| `main` | function | `scripts/mutation_test_c.py:222` | `def main()` |
| `run_mutation_test` | function | `scripts/mutation_test_c.py:136` | `def run_mutation_test()` |
| `should_mutate` | function | `scripts/mutation_test_c.py:73` | `def should_mutate(filepath)` |
| `async_i_o_for_beacon_process` | function | `src/async_i_o_for_beacon.c:6` | `bool async_i_o_for_beacon_process(void)` |
| `beacon_heartbeat___health_endpoint_process` | function | `src/beacon_heartbeat___health_endpoint.c:6` | `bool beacon_heartbeat___health_endpoint_process(void)` |
| `bof_api_versioning_process` | function | `src/bof_api_versioning.c:6` | `bool bof_api_versioning_process(void)` |
| `bof_path_traversal_hardening_process` | function | `src/bof_path_traversal_hardening.c:6` | `bool bof_path_traversal_hardening_process(void)` |
| `bof_streaming_` | function | `src/bof_streaming_(large_outputs).c:6` | `bool bof_streaming_(large_outputs)_process(void)` |
| `c2_rest_api_process` | function | `src/c2_rest_api.c:6` | `bool c2_rest_api_process(void)` |
| `certificate_pinning___tofu_process` | function | `src/certificate_pinning___tofu.c:6` | `bool certificate_pinning___tofu_process(void)` |
| `command_execution_via_execve_process` | function | `src/command_execution_via_execve.c:6` | `bool command_execution_via_execve_process(void)` |
| `hkdf_key_derivation_process` | function | `src/hkdf_key_derivation.c:6` | `bool hkdf_key_derivation_process(void)` |
| `iv_generation_with_entropy_verification_process` | function | `src/iv_generation_with_entropy_verification.c:6` | `bool iv_generation_with_entropy_verification_process(void)` |
| `mutation_testing_integration_process` | function | `src/mutation_testing_integration.c:6` | `bool mutation_testing_integration_process(void)` |
| `replay_protection_process` | function | `src/replay_protection.c:6` | `bool replay_protection_process(void)` |
| `socks5___http_proxy_support_process` | function | `src/socks5___http_proxy_support.c:6` | `bool socks5___http_proxy_support_process(void)` |
| `structured_jsonl_logging_process` | function | `src/structured_jsonl_logging.c:6` | `bool structured_jsonl_logging_process(void)` |
| `tls_client_certificate_authentication_process` | function | `src/tls_client_certificate_authentication.c:6` | `bool tls_client_certificate_authentication_process(void)` |
| `unified_config_schema_process` | function | `src/unified_config_schema.c:6` | `bool unified_config_schema_process(void)` |
| `main` | function | `tests/config_harness.c:24` | `int main(void)` |
| `hex_to_bytes` | function | `tests/crypto_harness.c:12` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `tests/crypto_harness.c:27` | `int main(int argc, char **argv)` |
| `compile_beacon` | function | `tests/test_beacon_build.py:43` | `def compile_beacon()` |
| `ensure_beacon` | function | `tests/test_beacon_build.py:79` | `def ensure_beacon()` |
| `have_headers` | function | `tests/test_beacon_build.py:29` | `def have_headers()` |
| `inspect_binary` | function | `tests/test_beacon_build.py:74` | `def inspect_binary()` |
| `main` | function | `tests/test_beacon_build.py:132` | `def main()` |
| `test_beacon_compiles_and_links` | function | `tests/test_beacon_build.py:93` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `tests/test_beacon_build.py:102` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `tests/test_beacon_build.py:122` | `def test_beacon_exposes_elf_loader()` |
| `compile_bof` | function | `tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `tests/test_bof_compile.py:44` | `def inspect_symbols(obj_path)` |
| `main` | function | `tests/test_bof_compile.py:118` | `def main()` |
| `test_compile_all` | function | `tests/test_bof_compile.py:62` | `def test_compile_all()` |
| `test_export_go` | function | `tests/test_bof_compile.py:71` | `def test_export_go()` |
| `test_no_libc_leak` | function | `tests/test_bof_compile.py:97` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `tests/test_bof_compile.py:79` | `def test_unresolved_beacon_api()` |
| `TestBOFPathTraversalConfig` | class | `tests/test_bof_path_traversal.py:25` | `class TestBOFPathTraversalConfig` |
| `TestBOFPathTraversalMutationResistance` | class | `tests/test_bof_path_traversal.py:175` | `class TestBOFPathTraversalMutationResistance` |
| `TestBOFPathTraversalServer` | class | `tests/test_bof_path_traversal.py:36` | `class TestBOFPathTraversalServer` |
| `test_absolute_path_rejected` | method | `tests/test_bof_path_traversal.py:89` | `def test_absolute_path_rejected(self)` |
| `test_basename_not_sufficient_protection` | method | `tests/test_bof_path_traversal.py:178` | `def test_basename_not_sufficient_protection(self)` |
| `test_case_sensitivity_on_linux` | method | `tests/test_bof_path_traversal.py:216` | `def test_case_sensitivity_on_linux(self)` |
| `test_double_url_encoded_traversal_rejected` | method | `tests/test_bof_path_traversal.py:114` | `def test_double_url_encoded_traversal_rejected(self)` |
| `test_normal_bof_name_served` | method | `tests/test_bof_path_traversal.py:39` | `def test_normal_bof_name_served(self)` |
| `test_null_byte_injection_rejected` | method | `tests/test_bof_path_traversal.py:126` | `def test_null_byte_injection_rejected(self)` |
| `test_path_traversal_multiple_parent_dirs_rejected` | method | `tests/test_bof_path_traversal.py:65` | `def test_path_traversal_multiple_parent_dirs_rejected(self)` |
| `test_path_traversal_parent_dir_rejected` | method | `tests/test_bof_path_traversal.py:53` | `def test_path_traversal_parent_dir_rejected(self)` |
| `test_path_traversal_with_subdir_rejected` | method | `tests/test_bof_path_traversal.py:77` | `def test_path_traversal_with_subdir_rejected(self)` |
| `test_realpath_prefix_check_not_mutated` | method | `tests/test_bof_path_traversal.py:186` | `def test_realpath_prefix_check_not_mutated(self)` |
| `test_symlink_outside_upload_dir_rejected` | method | `tests/test_bof_path_traversal.py:156` | `def test_symlink_outside_upload_dir_rejected(self)` |
| `test_unicode_normalization_not_mutated` | method | `tests/test_bof_path_traversal.py:234` | `def test_unicode_normalization_not_mutated(self)` |
| `test_upload_dir_config_exists` | method | `tests/test_bof_path_traversal.py:28` | `def test_upload_dir_config_exists(self)` |
| `test_upload_dir_symlink_escape_prevented` | method | `tests/test_bof_path_traversal.py:138` | `def test_upload_dir_symlink_escape_prevented(self)` |
| `test_url_encoded_traversal_rejected` | method | `tests/test_bof_path_traversal.py:101` | `def test_url_encoded_traversal_rejected(self)` |
| `TestC2BeaconBOFIntegration` | class | `tests/test_c2_beacon_bof_integration.py:34` | `class TestC2BeaconBOFIntegration` |
| `_free_port` | method | `tests/test_c2_beacon_bof_integration.py:76` | `def _free_port(self)` |
| `_run_server` | method | `tests/test_c2_beacon_bof_integration.py:275` | `def _run_server(self, cfg, state)` |
| `_wait_for_bof_result` | method | `tests/test_c2_beacon_bof_integration.py:98` | `def _wait_for_bof_result(self, state, client_id, timeout)` |
| `_wait_for_server_ready` | method | `tests/test_c2_beacon_bof_integration.py:84` | `def _wait_for_server_ready(self, host, port, timeout)` |
| `_wait_for_server_ready` | method | `tests/test_c2_beacon_bof_integration.py:278` | `def _wait_for_server_ready(self, host, port, timeout)` |
| `setup_method` | method | `tests/test_c2_beacon_bof_integration.py:37` | `def setup_method(self)` |
| `teardown_method` | method | `tests/test_c2_beacon_bof_integration.py:71` | `def teardown_method(self)` |
| `test_beacon_executes_whoami_bof` | method | `tests/test_c2_beacon_bof_integration.py:118` | `def test_beacon_executes_whoami_bof(self)` |
| `test_c2_beacon_bof_integration` | function | `tests/test_c2_beacon_bof_integration.py:292` | `def test_c2_beacon_bof_integration()` |
| `_free_port` | function | `tests/test_c2_http_e2e.py:45` | `def _free_port()` |
| `_recv_response` | function | `tests/test_c2_http_e2e.py:53` | `def _recv_response(sock, timeout)` |
| `encode` | function | `tests/test_c2_http_e2e.py:288` | `def encode(s)` |
| `main` | function | `tests/test_c2_http_e2e.py:422` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `tests/test_c2_http_e2e.py:347` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `tests/test_c2_http_e2e.py:192` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `tests/test_c2_http_e2e.py:67` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `tests/test_c2_http_e2e.py:122` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `tests/test_c2_http_e2e.py:246` | `def test_http_post_with_url_encoded_b64_payload()` |
| `main` | function | `tests/test_c2_server.py:145` | `def main()` |
| `make_state` | function | `tests/test_c2_server.py:41` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `tests/test_c2_server.py:96` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `tests/test_c2_server.py:103` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `tests/test_c2_server.py:48` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `tests/test_c2_server.py:60` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `tests/test_c2_server.py:122` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `tests/test_c2_server.py:71` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `tests/test_c2_server.py:131` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `tests/test_c2_server.py:138` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `tests/test_c2_server.py:115` | `def test_unknown_selector()` |
| `TestCertificatePinningCConfig` | class | `tests/test_certificate_pinning.py:86` | `class TestCertificatePinningCConfig` |
| `TestCertificatePinningConfig` | class | `tests/test_certificate_pinning.py:23` | `class TestCertificatePinningConfig` |
| `TestCertificatePinningIntegration` | class | `tests/test_certificate_pinning.py:96` | `class TestCertificatePinningIntegration` |
| `TestCertificatePinningMutationResistance` | class | `tests/test_certificate_pinning.py:126` | `class TestCertificatePinningMutationResistance` |
| `test_beacon_rejects_mismatched_certificate` | method | `tests/test_certificate_pinning.py:109` | `def test_beacon_rejects_mismatched_certificate(self)` |
| `test_beacon_verifies_pinned_certificate` | method | `tests/test_certificate_pinning.py:99` | `def test_beacon_verifies_pinned_certificate(self)` |
| `test_c_config_parses_fingerprint_field` | method | `tests/test_certificate_pinning.py:89` | `def test_c_config_parses_fingerprint_field(self)` |
| `test_config_defaults_to_empty_fingerprint` | method | `tests/test_certificate_pinning.py:73` | `def test_config_defaults_to_empty_fingerprint(self)` |
| `test_config_loads_empty_fingerprint` | method | `tests/test_certificate_pinning.py:26` | `def test_config_loads_empty_fingerprint(self)` |
| `test_config_loads_valid_fingerprint` | method | `tests/test_certificate_pinning.py:38` | `def test_config_loads_valid_fingerprint(self)` |
| `test_config_rejects_invalid_fingerprint_length` | method | `tests/test_certificate_pinning.py:51` | `def test_config_rejects_invalid_fingerprint_length(self)` |
| `test_config_rejects_non_hex_fingerprint` | method | `tests/test_certificate_pinning.py:62` | `def test_config_rejects_non_hex_fingerprint(self)` |
| `test_fingerprint_empty_check_not_mutated_to_always_true` | method | `tests/test_certificate_pinning.py:129` | `def test_fingerprint_empty_check_not_mutated_to_always_true(self)` |
| `test_fingerprint_hex_validation_not_mutated` | method | `tests/test_certificate_pinning.py:139` | `def test_fingerprint_hex_validation_not_mutated(self)` |
| `test_pin_option_set_only_when_fingerprint_present` | method | `tests/test_certificate_pinning.py:151` | `def test_pin_option_set_only_when_fingerprint_present(self)` |
| `test_tofu_first_connection_stores_fingerprint` | method | `tests/test_certificate_pinning.py:117` | `def test_tofu_first_connection_stores_fingerprint(self)` |
| `main` | function | `tests/test_certificate_pinning_c.c:90` | `int main(void)` |
| `test_cert_fingerprint_defaults_to_empty` | function | `tests/test_certificate_pinning_c.c:19` | `static void test_cert_fingerprint_defaults_to_empty(void **state)` |
| `test_cert_fingerprint_invalid_length_fails` | function | `tests/test_certificate_pinning_c.c:55` | `static void test_cert_fingerprint_invalid_length_fails(void **state)` |
| `test_cert_fingerprint_loads_from_config` | function | `tests/test_certificate_pinning_c.c:29` | `static void test_cert_fingerprint_loads_from_config(void **state)` |
| `test_network_struct_has_fingerprint_field` | function | `tests/test_certificate_pinning_c.c:82` | `static void test_network_struct_has_fingerprint_field(void **state)` |
| `compile_harness` | function | `tests/test_config.py:25` | `def compile_harness()` |
| `main` | function | `tests/test_config.py:187` | `def main()` |
| `run_harness` | function | `tests/test_config.py:46` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `tests/test_config.py:172` | `def test_bad_hex_key()` |
| `test_default_load` | function | `tests/test_config.py:63` | `def test_default_load()` |
| `test_missing_file` | function | `tests/test_config.py:104` | `def test_missing_file()` |
| `test_overrides` | function | `tests/test_config.py:81` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `tests/test_config.py:112` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `tests/test_config.py:137` | `def test_search_order_falls_back_to_cwd_default()` |
| `compile_harness` | function | `tests/test_crypto.py:27` | `def compile_harness()` |
| `main` | function | `tests/test_crypto.py:167` | `def main()` |
| `run` | function | `tests/test_crypto.py:59` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `tests/test_crypto.py:72` | `def test_block_boundary()` |
| `test_c_replay_encrypt_python_decrypt` | function | `tests/test_crypto.py:136` | `def test_c_replay_encrypt_python_decrypt()` |
| `test_known_ciphertext` | function | `tests/test_crypto.py:83` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `tests/test_crypto.py:77` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `tests/test_crypto.py:104` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `tests/test_crypto.py:68` | `def test_short()` |
| `TestExecveCommandExecution` | class | `tests/test_execve_command.py:25` | `class TestExecveCommandExecution` |
| `TestExecveMutationResistance` | class | `tests/test_execve_command.py:57` | `class TestExecveMutationResistance` |
| `test_argv_array_not_string` | method | `tests/test_execve_command.py:71` | `def test_argv_array_not_string(self)` |
| `test_command_with_arguments` | method | `tests/test_execve_command.py:34` | `def test_command_with_arguments(self)` |
| `test_no_popen_call` | method | `tests/test_execve_command.py:67` | `def test_no_popen_call(self)` |
| `test_no_system_call` | method | `tests/test_execve_command.py:60` | `def test_no_system_call(self)` |
| `test_non_existent_command` | method | `tests/test_execve_command.py:42` | `def test_non_existent_command(self)` |
| `test_quoted_arguments` | method | `tests/test_execve_command.py:38` | `def test_quoted_arguments(self)` |
| `test_shell_metacharacters_escaped` | method | `tests/test_execve_command.py:77` | `def test_shell_metacharacters_escaped(self)` |
| `test_shell_metacharacters_not_interpreted` | method | `tests/test_execve_command.py:50` | `def test_shell_metacharacters_not_interpreted(self)` |
| `test_simple_command_execution` | method | `tests/test_execve_command.py:28` | `def test_simple_command_execution(self)` |
| `test_stderr_capture` | method | `tests/test_execve_command.py:46` | `def test_stderr_capture(self)` |
| `TestHKDFConfigIntegration` | class | `tests/test_hkdf_key_derivation.py:159` | `class TestHKDFConfigIntegration` |
| `TestHKDFDerivation` | class | `tests/test_hkdf_key_derivation.py:87` | `class TestHKDFDerivation` |
| `TestHKDFKeyDerivationConfig` | class | `tests/test_hkdf_key_derivation.py:24` | `class TestHKDFKeyDerivationConfig` |
| `TestHKDFMutationResistance` | class | `tests/test_hkdf_key_derivation.py:220` | `class TestHKDFMutationResistance` |
| `test_c_and_python_derive_same_keys` | method | `tests/test_hkdf_key_derivation.py:196` | `def test_c_and_python_derive_same_keys(self)` |
| `test_config_loads_aes_key_hex_backward_compat` | method | `tests/test_hkdf_key_derivation.py:40` | `def test_config_loads_aes_key_hex_backward_compat(self)` |
| `test_config_loads_master_key_hex` | method | `tests/test_hkdf_key_derivation.py:27` | `def test_config_loads_master_key_hex(self)` |
| `test_config_rejects_missing_both_keys` | method | `tests/test_hkdf_key_derivation.py:53` | `def test_config_rejects_missing_both_keys(self)` |
| `test_config_validates_master_key_hex_hex_chars` | method | `tests/test_hkdf_key_derivation.py:75` | `def test_config_validates_master_key_hex_hex_chars(self)` |
| `test_config_validates_master_key_hex_length` | method | `tests/test_hkdf_key_derivation.py:64` | `def test_config_validates_master_key_hex_length(self)` |
| `test_hkdf_derives_encryption_and_hmac_keys` | method | `tests/test_hkdf_key_derivation.py:90` | `def test_hkdf_derives_encryption_and_hmac_keys(self)` |
| `test_hkdf_deterministic` | method | `tests/test_hkdf_key_derivation.py:123` | `def test_hkdf_deterministic(self)` |
| `test_hkdf_different_info_produces_different_keys` | method | `tests/test_hkdf_key_derivation.py:137` | `def test_hkdf_different_info_produces_different_keys(self)` |
| `test_info_strings_are_enc_and_hmac_not_mutated` | method | `tests/test_hkdf_key_derivation.py:238` | `def test_info_strings_are_enc_and_hmac_not_mutated(self)` |
| `test_key_length_is_32_bytes_not_mutated` | method | `tests/test_hkdf_key_derivation.py:263` | `def test_key_length_is_32_bytes_not_mutated(self)` |
| `test_load_config_derives_from_aes_key_when_no_master_key` | method | `tests/test_hkdf_key_derivation.py:180` | `def test_load_config_derives_from_aes_key_when_no_master_key(self)` |
| `test_load_config_returns_derived_keys_when_master_key_present` | method | `tests/test_hkdf_key_derivation.py:162` | `def test_load_config_returns_derived_keys_when_master_key_present(self)` |
| `test_salt_is_constant_not_mutated` | method | `tests/test_hkdf_key_derivation.py:223` | `def test_salt_is_constant_not_mutated(self)` |
| `test_sha256_not_mutated_to_sha1_or_md5` | method | `tests/test_hkdf_key_derivation.py:277` | `def test_sha256_not_mutated_to_sha1_or_md5(self)` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:207` | `assert_memory_equal(crypto.master_key, (uint8_t[BSB_AES_KEY_BYTES])` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:208` | `assert_memory_equal(crypto.encryption_key, (uint8_t[BSB_AES_KEY_BYTES])` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:209` | `assert_memory_equal(crypto.hmac_key, (uint8_t[BSB_AES_KEY_BYTES])` |
| `main` | function | `tests/test_hkdf_key_derivation_c.c:212` | `int main(void)` |
| `test_aes_key_hex_backward_compat` | function | `tests/test_hkdf_key_derivation_c.c:55` | `static void test_aes_key_hex_backward_compat(void **state)` |
| `test_crypto_struct_has_new_fields` | function | `tests/test_hkdf_key_derivation_c.c:200` | `static void test_crypto_struct_has_new_fields(void **state)` |
| `test_deterministic_derivation` | function | `tests/test_hkdf_key_derivation_c.c:165` | `static void test_deterministic_derivation(void **state)` |
| `test_invalid_master_key_hex_length_fails` | function | `tests/test_hkdf_key_derivation_c.c:115` | `static void test_invalid_master_key_hex_length_fails(void **state)` |
| `test_key_separation` | function | `tests/test_hkdf_key_derivation_c.c:139` | `static void test_key_separation(void **state)` |
| `test_master_key_hex_loads_from_config` | function | `tests/test_hkdf_key_derivation_c.c:19` | `static void test_master_key_hex_loads_from_config(void **state)` |
| `test_missing_both_keys_fails` | function | `tests/test_hkdf_key_derivation_c.c:90` | `static void test_missing_both_keys_fails(void **state)` |
| `main` | function | `tests/test_install_deploy.py:129` | `def main()` |
| `make_all` | function | `tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `tests/test_install_deploy.py:56` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `tests/test_install_deploy.py:103` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `tests/test_install_deploy.py:75` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `tests/test_install_deploy.py:90` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `tests/test_install_deploy.py:67` | `def test_staged_files_have_correct_modes()` |
| `TestIVGenerationCBehavior` | class | `tests/test_iv_generation.py:101` | `class TestIVGenerationCBehavior` |
| `TestIVGenerationConfig` | class | `tests/test_iv_generation.py:26` | `class TestIVGenerationConfig` |
| `TestIVGenerationPython` | class | `tests/test_iv_generation.py:42` | `class TestIVGenerationPython` |
| `TestIVMutationResistance` | class | `tests/test_iv_generation.py:128` | `class TestIVMutationResistance` |
| `test_config_defaults_include_iv_settings` | method | `tests/test_iv_generation.py:29` | `def test_config_defaults_include_iv_settings(self)` |
| `test_decrypt_data_handles_iv_correctly` | method | `tests/test_iv_generation.py:73` | `def test_decrypt_data_handles_iv_correctly(self)` |
| `test_encrypt_data_iv_is_16_bytes` | method | `tests/test_iv_generation.py:58` | `def test_encrypt_data_iv_is_16_bytes(self)` |
| `test_encrypt_data_uses_os_urandom_for_iv` | method | `tests/test_iv_generation.py:45` | `def test_encrypt_data_uses_os_urandom_for_iv(self)` |
| `test_encrypt_decrypt_roundtrip_with_different_ivs` | method | `tests/test_iv_generation.py:85` | `def test_encrypt_decrypt_roundtrip_with_different_ivs(self)` |
| `test_fail_closed_on_entropy_failure` | method | `tests/test_iv_generation.py:121` | `def test_fail_closed_on_entropy_failure(self)` |

Next: [SYMBOLS_p4.md](SYMBOLS_p4.md)
