# Subsystem: include (page 2 of 2)
Previous: [KB_include.md](KB_include.md)

## include/command_execution_via_execve.h
- Layer: utility
- Language: h
- Symbols:
  - `command_execution_via_execve_process` (function, line 4) `bool command_execution_via_execve_process(void);`
  - `COMMAND_EXECUTION_VIA_EXECVE_H` (macro, line 2) `#define COMMAND_EXECUTION_VIA_EXECVE_H`
- Imported by: `mutants/src/command_execution_via_execve.c`, `src/command_execution_via_execve.c`

## include/config.c
- Doc: slurp: declared in the schema.
- Layer: infrastructure
- Language: c
- Symbols:
  - `slurp` (function, line 24) `static char *slurp(const char *path, size_t *out_len)`
  - `skip_ws` (function, line 56) `static const char *skip_ws(const char *p, const char *end)`
  - `read_string` (function, line 66) `static int read_string(const char **pp, const char *end, char *out, size_t outsz)`
  - `read_int` (function, line 113) `static int read_int(const char **pp, const char *end, int *out)`
  - `read_bool` (function, line 137) `static int read_bool(const char **pp, const char *end, int *out)`
  - `expect` (function, line 156) `static int expect(const char **pp, const char *end, char c)`
  - `find_matching_brace` (function, line 167) `static const char *find_matching_brace(const char *p, const char *end)`
  - `skip_value` (function, line 203) `static const char *skip_value(const char *p, const char *end)`
  - `hex_to_bytes` (function, line 269) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)`
  - `hmac_sha256` (function, line 292) `static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,...`
  - `hkdf_extract` (function, line 299) `static void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len...`
  - `hkdf_expand` (function, line 305) `static void hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,...`
  - `hkdf_sha256` (function, line 337) `static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,...`
  - `derive_keys_from_master` (function, line 345) `static void derive_keys_from_master(bsb_config_t *cfg)`
  - `parse_c2` (function, line 375) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_crypto` (function, line 419) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_timing` (function, line 474) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_network` (function, line 518) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_bof` (function, line 586) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_backoff` (function, line 620) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
  - `bsb_config_load` (function, line 655) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)`
  - `binary_dir` (function, line 798) `static const char *binary_dir(char *out, size_t outsz)`
  - `bsb_config_load_default` (function, line 820) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
  - `bsb_config_sleep_seconds` (function, line 853) `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
  - `_POSIX_C_SOURCE` (macro, line 13) `#define _POSIX_C_SOURCE`
  - `HKDF_SALT` (macro, line 288) `#define HKDF_SALT`
  - `HKDF_INFO_ENC` (macro, line 289) `#define HKDF_INFO_ENC`
  - `HKDF_INFO_HMAC` (macro, line 290) `#define HKDF_INFO_HMAC`
- Depends on: `include/config.h`

## include/config.h
- Doc: bsb_config_load: Load config from path.
- Layer: infrastructure
- Language: h
- Symbols:
  - `bsb_c2_t` (struct, line 30)
  - `bsb_crypto_t` (struct, line 38)
  - `bsb_timing_t` (struct, line 48)
  - `bsb_network_t` (struct, line 56)
  - `bsb_bof_t` (struct, line 64)
  - `bsb_backoff_config_t` (struct, line 70)
  - `bsb_config_t` (struct, line 76)
  - `bsb_config_load` (function, line 89) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);`
  - `bsb_config_load_default` (function, line 92) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);`
  - `bsb_config_sleep_seconds` (function, line 95) `int bsb_config_sleep_seconds(const bsb_config_t *cfg);`
  - `BSB_CONFIG_H` (macro, line 14) `#define BSB_CONFIG_H`
  - `BSB_CONFIG_PATH_DEFAULT` (macro, line 19) `#define BSB_CONFIG_PATH_DEFAULT`
  - `BSB_CONFIG_PATH_ENV` (macro, line 20) `#define BSB_CONFIG_PATH_ENV`
  - `BSB_MAX_URL` (macro, line 21) `#define BSB_MAX_URL`
  - `BSB_MAX_URI` (macro, line 22) `#define BSB_MAX_URI`
  - `BSB_MAX_CLIENT_ID` (macro, line 23) `#define BSB_MAX_CLIENT_ID`
  - `BSB_AES_KEY_HEX_LEN` (macro, line 24) `#define BSB_AES_KEY_HEX_LEN`
  - `BSB_AES_KEY_BYTES` (macro, line 25) `#define BSB_AES_KEY_BYTES`
  - `BSB_MAX_USER_AGENTS` (macro, line 26) `#define BSB_MAX_USER_AGENTS`
  - `BSB_USER_AGENT_LEN` (macro, line 27) `#define BSB_USER_AGENT_LEN`
  - `BSB_REPORT_URI_DEFAULT` (macro, line 28) `#define BSB_REPORT_URI_DEFAULT`
- Imported by: `include/beacon_common.h`, `include/config.c`, `mutants/tests/config_harness.c`, `tests/config_harness.c`, `tests/test_certificate_pinning_c.c`, `tests/test_hkdf_key_derivation_c.c`

## include/config_autogen.c
- Doc: slurp: Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run...
- Layer: infrastructure
- Language: c
- Symbols:
  - `slurp` (function, line 16) `static char *slurp(const char *path, size_t *out_len)`
  - `skip_ws` (function, line 34) `static const char *skip_ws(const char *p, const char *end)`
  - `read_string` (function, line 40) `static int read_string(const char **pp, const char *end, char *out, size_t outsz)`
  - `read_int` (function, line 68) `static int read_int(const char **pp, const char *end, int *out)`
  - `read_bool` (function, line 85) `static int read_bool(const char **pp, const char *end, int *out)`
  - `expect` (function, line 93) `static int expect(const char **pp, const char *end, char c)`
  - `find_matching_brace` (function, line 101) `static const char *find_matching_brace(const char *p, const char *end)`
  - `skip_value` (function, line 123) `static const char *skip_value(const char *p, const char *end)`
  - `hex_to_bytes` (function, line 165) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)`
  - `parse_c2` (function, line 177) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_crypto` (function, line 206) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_timing` (function, line 227) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_network` (function, line 260) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_bof` (function, line 300) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_backoff` (function, line 325) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
  - `parse_server` (function, line 350) `static void parse_server(const char *p, const char *end, bsb_config_t *cfg)`
  - `bsb_config_load` (function, line 375) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)`
  - `_POSIX_C_SOURCE` (macro, line 5) `#define _POSIX_C_SOURCE`
- Depends on: `include/config_autogen.h`

## include/config_autogen.h
- Doc: bsb_config_load: } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t...
- Layer: infrastructure
- Language: h
- Symbols:
  - `bsb_c2_t` (struct, line 11)
  - `bsb_crypto_t` (struct, line 21)
  - `bsb_timing_t` (struct, line 28)
  - `bsb_network_t` (struct, line 35)
  - `bsb_bof_t` (struct, line 42)
  - `bsb_backoff_t` (struct, line 47)
  - `bsb_server_t` (struct, line 52)
  - `bsb_config_t` (struct, line 57)
  - `bsb_config_load` (function, line 69) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);`
  - `bsb_config_load_default` (function, line 72) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);`
  - `bsb_config_sleep_seconds` (function, line 75) `int bsb_config_sleep_seconds(const bsb_config_t *cfg);`
  - `BSB_CONFIG_AUTOGEN_H` (macro, line 6) `#define BSB_CONFIG_AUTOGEN_H`
- Imported by: `include/config_autogen.c`

## include/config_py.py
- Doc: Python loader for BSB JSON config files.
- Layer: infrastructure
- Language: py
- Symbols:
  - `_derive_keys` (function, line 65) `def _derive_keys(master_key_bytes)`
  - `_deep_merge` (function, line 84) `def _deep_merge(base, overlay)`
  - `load_config` (function, line 94) `def load_config(path)`
- Imported by: `c2/server.py`, `mutants/tests/test_certificate_pinning.py`, `tests/test_c2_beacon_bof_integration.py`, `tests/test_certificate_pinning.py`, `tests/test_hkdf_key_derivation.py`, `tests/test_iv_generation.py`, `tests/test_replay_protection.py`, `tests/test_runtime_random.py`

## include/config_py_autogen.py
- Doc: Auto-generated Python config loader from config/schema.json DO NOT EDIT MANUALLY - run...
- Layer: infrastructure
- Language: py
- Symbols:
  - `_derive_keys` (function, line 59) `def _derive_keys(master_key_bytes)`
  - `_deep_merge` (function, line 80) `def _deep_merge(base, overlay)`
  - `load_config` (function, line 89) `def load_config(path)`

## include/containerized_build_+_sbom.h
- Layer: infrastructure
- Language: h
- Symbols:
  - `CONTAINERIZED_BUILD_` (macro, line 2) `#define CONTAINERIZED_BUILD_`
- Imported by: `mutants/src/containerized_build_+_sbom.c`, `src/containerized_build_+_sbom.c`

## include/hkdf_key_derivation.h
- Layer: utility
- Language: h
- Symbols:
  - `hkdf_key_derivation_process` (function, line 4) `bool hkdf_key_derivation_process(void);`
  - `HKDF_KEY_DERIVATION_H` (macro, line 2) `#define HKDF_KEY_DERIVATION_H`
- Imported by: `mutants/src/hkdf_key_derivation.c`, `src/hkdf_key_derivation.c`

## include/iv_generation_with_entropy_verification.h
- Layer: utility
- Language: h
- Symbols:
  - `iv_generation_with_entropy_verification_process` (function, line 4) `bool iv_generation_with_entropy_verification_process(void);`
  - `IV_GENERATION_WITH_ENTROPY_VERIFICATION_H` (macro, line 2) `#define IV_GENERATION_WITH_ENTROPY_VERIFICATION_H`
- Imported by: `mutants/src/iv_generation_with_entropy_verification.c`, `src/iv_generation_with_entropy_verification.c`

## include/mutation_testing_integration.h
- Layer: testing
- Language: h
- Symbols:
  - `mutation_testing_integration_process` (function, line 4) `bool mutation_testing_integration_process(void);`
  - `MUTATION_TESTING_INTEGRATION_H` (macro, line 2) `#define MUTATION_TESTING_INTEGRATION_H`
- Imported by: `mutants/src/mutation_testing_integration.c`, `src/mutation_testing_integration.c`

## include/pre-commit_+_ci_hardening.h
- Layer: utility
- Language: h
- Symbols:
  - `PRE` (macro, line 2) `#define PRE`
- Imported by: `mutants/src/pre-commit_+_ci_hardening.c`, `src/pre-commit_+_ci_hardening.c`

## include/replay_protection.h
- Layer: utility
- Language: h
- Symbols:
  - `replay_protection_process` (function, line 4) `bool replay_protection_process(void);`
  - `REPLAY_PROTECTION_H` (macro, line 2) `#define REPLAY_PROTECTION_H`
- Imported by: `mutants/src/replay_protection.c`, `src/replay_protection.c`

## include/socks5___http_proxy_support.h
- Layer: presentation
- Language: h
- Symbols:
  - `socks5___http_proxy_support_process` (function, line 4) `bool socks5___http_proxy_support_process(void);`
  - `SOCKS5___HTTP_PROXY_SUPPORT_H` (macro, line 2) `#define SOCKS5___HTTP_PROXY_SUPPORT_H`
- Imported by: `mutants/src/socks5___http_proxy_support.c`, `src/socks5___http_proxy_support.c`

## include/structured_jsonl_logging.h
- Layer: infrastructure
- Language: h
- Symbols:
  - `structured_jsonl_logging_process` (function, line 4) `bool structured_jsonl_logging_process(void);`
  - `STRUCTURED_JSONL_LOGGING_H` (macro, line 2) `#define STRUCTURED_JSONL_LOGGING_H`
- Imported by: `mutants/src/structured_jsonl_logging.c`, `src/structured_jsonl_logging.c`

## include/tls_client_certificate_authentication.h
- Layer: infrastructure
- Language: h
- Symbols:
  - `tls_client_certificate_authentication_process` (function, line 4) `bool tls_client_certificate_authentication_process(void);`
  - `TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H` (macro, line 2) `#define TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H`
- Imported by: `mutants/src/tls_client_certificate_authentication.c`, `src/tls_client_certificate_authentication.c`

## include/unified_config_schema.h
- Layer: infrastructure
- Language: h
- Symbols:
  - `unified_config_schema_process` (function, line 4) `bool unified_config_schema_process(void);`
  - `UNIFIED_CONFIG_SCHEMA_H` (macro, line 2) `#define UNIFIED_CONFIG_SCHEMA_H`
- Imported by: `mutants/src/unified_config_schema.c`, `src/unified_config_schema.c`

