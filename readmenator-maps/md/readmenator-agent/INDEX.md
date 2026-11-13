# Index

| File | Purpose | Subsystem | Symbols | Used by |
|------|---------|-----------|---------|---------|
| `aes.c` | tiny-AES-c (https://github.com/kokke/tiny-AES-c) | root | 43 | 0 |
| `aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | root | 21 | 1 |
| `app.py` | Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación... | root | 0 | 0 |
| `beacon.h` | Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos) | root | 13 | 1 |
| `beacons/v1/beacon.c` | - | misc | 4 | 0 |
| `beacons/v2/beacon.c` | - | misc | 11 | 0 |
| `beacons/v3/beacon.c` | - | misc | 7 | 0 |
| `bof.c` | - | root | 1 | 0 |
| `bof/cat/bof.c` | - | cat | 1 | 0 |
| `bof/cat/cat.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos | cat | 12 | 0 |
| `bof/include/beacon_api.h` | datap: Argument parser. | bof_include | 14 | 5 |
| `bof/include/syscalls.h` | bsf_strlen: } static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long... | bof_include | 38 | 5 |
| `bof/is_sudo/bof.c` | - | is_sudo | 2 | 0 |
| `bof/is_sudo/is_sudo.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o  Tipos | is_sudo | 17 | 0 |
| `bof/suid_enum/bof.c` | linux_stat: #include "beacon_api.h" #include "syscalls.h" /* getdents64 syscall number (x86_64)... | misc | 15 | 0 |
| `bof/userenum/bof.c` | - | userenum | 2 | 0 |
| `bof/userenum/userenum.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o... | userenum | 13 | 0 |
| `bof/whoami/bof.c` | - | whoami | 1 | 0 |
| `bof/whoami/whoami.c` | — LazyOwn RedTeam BOF (Linux/x64)  Tipos | whoami | 14 | 0 |
| `c2/__init__.py` | - | c2 | 0 | 2 |
| `c2/server.py` | Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. | c2 | 33 | 11 |
| `c2/stage_oneliner.sh` | Black Sand Beacon diskless stager (Stage-0 one-liner). | c2 | 0 | 0 |
| `c2/stage_payload.py` | Black Sand Beacon diskless stager. | c2 | 3 | 0 |
| `cJSON.c` | case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible... | root | 125 | 0 |
| `cJSON.h` | cJSON: #define cJSON_Invalid (0) #define cJSON_False (1 << 0) #define cJSON_True (1 << 1)... | root | 40 | 1 |
| `config/generate_parsers.py` | Config Parser Generator for Black Sand Beacon  Reads config/schema.json (JSON Schema Draft 7)... | misc | 7 | 0 |
| `contract_agent.py` | Contract Driven Agent - SDD/TDD/BDD workflow for Black Sand Beacon v2. | root | 17 | 0 |
| `gopher_c2.py` | - | root | 5 | 0 |
| `include/aes.c` | tiny-AES-c (https://github.com/kokke/tiny-AES-c) | include | 43 | 0 |
| `include/aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | include | 21 | 3 |
| `include/aes_cfb.c` | aes256_cfb_encrypt_replay: Encrypt with replay protection: prepends counter (8 bytes LE) and... | include | 4 | 0 |
| `include/aes_cfb.h` | - | include | 3 | 3 |
| `include/async_i_o_for_beacon.h` | - | include | 2 | 2 |
| `include/beacon.h` | Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos) | include | 13 | 0 |
| `include/beacon_common.c` | MemoryStruct: size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8; TrampolineCache *tmp... | include | 36 | 0 |
| `include/beacon_common.c_extraction.h` | - | include | 1 | 2 |
| `include/beacon_common.h` | http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead... | include | 58 | 5 |
| `include/beacon_heartbeat___health_endpoint.h` | - | include | 2 | 2 |
| `include/bof_api_versioning.h` | - | include | 2 | 2 |
| `include/bof_path_traversal_hardening.h` | - | include | 2 | 2 |
| `include/bof_streaming_(large_outputs).h` | - | include | 2 | 2 |
| `include/c2_rest_api.h` | - | include | 2 | 2 |
| `include/cJSON.c` | case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible... | include | 125 | 0 |
| `include/cJSON.h` | cJSON: #define cJSON_Invalid (0) #define cJSON_False (1 << 0) #define cJSON_True (1 << 1)... | include | 40 | 2 |
| `include/certificate_pinning___tofu.h` | - | include | 2 | 2 |
| `include/command_execution_via_execve.h` | - | include | 2 | 2 |
| `include/config.c` | slurp: declared in the schema. | include | 28 | 0 |
| `include/config.h` | bsb_config_load: Load config from path. | include | 21 | 6 |
| `include/config_autogen.c` | slurp: Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run... | include | 18 | 0 |
| `include/config_autogen.h` | bsb_config_load: } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t... | include | 12 | 1 |
| `include/config_py.py` | Python loader for BSB JSON config files. | include | 3 | 8 |
| `include/config_py_autogen.py` | Auto-generated Python config loader from config/schema.json DO NOT EDIT MANUALLY - run... | include | 3 | 0 |
| `include/containerized_build_+_sbom.h` | - | include | 1 | 2 |
| `include/hkdf_key_derivation.h` | - | include | 2 | 2 |
| `include/iv_generation_with_entropy_verification.h` | - | include | 2 | 2 |
| `include/mutation_testing_integration.h` | - | include | 2 | 2 |
| `include/pre-commit_+_ci_hardening.h` | - | include | 1 | 2 |
| `include/replay_protection.h` | - | include | 2 | 2 |
| `include/socks5___http_proxy_support.h` | - | include | 2 | 2 |
| `include/structured_jsonl_logging.h` | - | include | 2 | 2 |
| `include/tls_client_certificate_authentication.h` | - | include | 2 | 2 |
| `include/unified_config_schema.h` | - | include | 2 | 2 |
| `install.sh` | Install build deps and build everything. | root | 0 | 0 |
| `issudo.c` | — LazyOwn RedTeam BOF (Linux/x64)  Tipos | root | 17 | 0 |
| `legacy/beacon3.c` | MemoryStruct: === ESTRUCTURAS === | legacy | 28 | 0 |
| `legacy/beacon5.c` | MemoryStruct: === ESTRUCTURAS === | legacy | 44 | 0 |
| `legacy/beacon6.c` | MemoryStruct: === ESTRUCTURAS === | legacy | 32 | 0 |
| `legacy/beacon_p2p.c` | - | legacy | 49 | 0 |
| `legacy/gopher_beacon.c` | MemoryStruct: === ESTRUCTURAS === | legacy | 28 | 0 |
| `legacy/v1_gopher_beacon.c` | MemoryStruct: === ESTRUCTURAS === | legacy | 28 | 0 |
| `mutants/src/async_i_o_for_beacon.c` | Auto-generated implementation for contract: Async I/O for Beacon | - | 1 | 0 |
| `mutants/src/beacon_common.c_extraction.c` | Auto-generated implementation for contract: beacon_common.c Extraction | - | 0 | 0 |
| `mutants/src/beacon_heartbeat___health_endpoint.c` | Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint | - | 1 | 0 |
| `mutants/src/bof_api_versioning.c` | Auto-generated implementation for contract: BOF API Versioning | - | 1 | 0 |
| `mutants/src/bof_path_traversal_hardening.c` | Auto-generated implementation for contract: BOF Path Traversal Hardening | - | 1 | 0 |
| `mutants/src/bof_streaming_(large_outputs).c` | Auto-generated implementation for contract: BOF Streaming (Large Outputs) | - | 1 | 0 |
| `mutants/src/c2_rest_api.c` | Auto-generated implementation for contract: C2 REST API | - | 1 | 0 |
| `mutants/src/certificate_pinning___tofu.c` | Auto-generated implementation for contract: Certificate Pinning / TOFU | - | 1 | 0 |
| `mutants/src/command_execution_via_execve.c` | Auto-generated implementation for contract: Command Execution via execve | - | 1 | 0 |
| `mutants/src/containerized_build_+_sbom.c` | Auto-generated implementation for contract: Containerized Build + SBOM | - | 0 | 0 |
| `mutants/src/hkdf_key_derivation.c` | Auto-generated implementation for contract: HKDF Key Derivation | - | 1 | 0 |
| `mutants/src/iv_generation_with_entropy_verification.c` | Auto-generated implementation for contract: IV Generation with Entropy Verification | - | 1 | 0 |
| `mutants/src/mutation_testing_integration.c` | Auto-generated implementation for contract: Mutation Testing Integration | - | 1 | 0 |
| `mutants/src/pre-commit_+_ci_hardening.c` | Auto-generated implementation for contract: Pre-commit + CI Hardening | - | 0 | 0 |
| `mutants/src/replay_protection.c` | Auto-generated implementation for contract: Replay Protection | - | 1 | 0 |
| `mutants/src/socks5___http_proxy_support.c` | Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support | - | 1 | 0 |
| `mutants/src/structured_jsonl_logging.c` | Auto-generated implementation for contract: Structured JSONL Logging | - | 1 | 0 |
| `mutants/src/tls_client_certificate_authentication.c` | Auto-generated implementation for contract: TLS Client Certificate Authentication | - | 1 | 0 |
| `mutants/src/unified_config_schema.c` | Auto-generated implementation for contract: Unified Config Schema | - | 1 | 0 |
| `mutants/tests/config_harness.c` | - | - | 1 | 0 |
| `mutants/tests/crypto_harness.c` | - | - | 2 | 0 |
| `mutants/tests/test_async_i_o_for_beacon.py` | Auto-generated test for contract: Async I/O for Beacon BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_async_i_o_for_beacon_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_beacon_build.py` | Sanity build test: compile the v1 beacon against include/config.c and verify the binary links... | - | 8 | 0 |
| `mutants/tests/test_beacon_common.c_extraction.py` | Auto-generated test for contract: beacon_common.c Extraction BDD-style tests derived from... | - | 0 | 0 |
| `mutants/tests/test_beacon_common.c_extraction_c.c` | - | - | 1 | 0 |
| `mutants/tests/test_beacon_heartbeat___health_endpoint.py` | Auto-generated test for contract: Beacon Heartbeat / Health Endpoint BDD-style tests derived... | - | 2 | 0 |
| `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_bof_api_versioning.py` | Auto-generated test for contract: BOF API Versioning BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_bof_api_versioning_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_bof_compile.py` | Verify every BOF compiles with the BOF build flags. | - | 7 | 0 |
| `mutants/tests/test_bof_path_traversal_hardening.py` | Auto-generated test for contract: BOF Path Traversal Hardening BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_bof_path_traversal_hardening_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_bof_streaming_(large_outputs).py` | Auto-generated test for contract: BOF Streaming (Large Outputs) BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_bof_streaming_(large_outputs)_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_c2_http_e2e.py` | End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by server.serve(), and... | - | 9 | 0 |
| `mutants/tests/test_c2_rest_api.py` | Auto-generated test for contract: C2 REST API BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_c2_rest_api_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_c2_server.py` | Unit tests for the C2 server dispatcher. | - | 11 | 0 |
| `mutants/tests/test_certificate_pinning.py` | Tests for Certificate Pinning / TOFU (Contract: Certificate Pinning / TOFU)  BDD Scenarios: 1. | - | 16 | 0 |
| `mutants/tests/test_certificate_pinning___tofu.py` | Auto-generated test for contract: Certificate Pinning / TOFU BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_certificate_pinning___tofu_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_command_execution_via_execve.py` | Auto-generated test for contract: Command Execution via execve BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_command_execution_via_execve_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_config.py` | Unit tests for the BSB JSON config loader. | - | 9 | 0 |
| `mutants/tests/test_containerized_build_+_sbom.py` | Auto-generated test for contract: Containerized Build + SBOM BDD-style tests derived from... | - | 0 | 0 |
| `mutants/tests/test_containerized_build_+_sbom_c.c` | - | - | 1 | 0 |
| `mutants/tests/test_crypto.py` | Roundtrip tests for AES-256-CFB. | - | 8 | 0 |
| `mutants/tests/test_hkdf_key_derivation.py` | Auto-generated test for contract: HKDF Key Derivation BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_hkdf_key_derivation_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_install_deploy.py` | End-to-end test for the "make beacon && ./build/beacon" workflow. | - | 8 | 0 |
| `mutants/tests/test_iv_generation_with_entropy_verification.py` | Auto-generated test for contract: IV Generation with Entropy Verification BDD-style tests... | - | 2 | 0 |
| `mutants/tests/test_iv_generation_with_entropy_verification_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_mutation_testing_integration.py` | Auto-generated test for contract: Mutation Testing Integration BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_mutation_testing_integration_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_pre-commit_+_ci_hardening.py` | Auto-generated test for contract: Pre-commit + CI Hardening BDD-style tests derived from... | - | 0 | 0 |
| `mutants/tests/test_pre-commit_+_ci_hardening_c.c` | - | - | 1 | 0 |
| `mutants/tests/test_replay_protection.py` | Auto-generated test for contract: Replay Protection BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_replay_protection_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_socks5___http_proxy_support.py` | Auto-generated test for contract: SOCKS5 / HTTP Proxy Support BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_socks5___http_proxy_support_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_structured_jsonl_logging.py` | Auto-generated test for contract: Structured JSONL Logging BDD-style tests derived from... | - | 2 | 0 |
| `mutants/tests/test_structured_jsonl_logging_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_tls_client_certificate_authentication.py` | Auto-generated test for contract: TLS Client Certificate Authentication BDD-style tests derived... | - | 2 | 0 |
| `mutants/tests/test_tls_client_certificate_authentication_c.c` | - | - | 2 | 0 |
| `mutants/tests/test_unified_config_schema.py` | Auto-generated test for contract: Unified Config Schema BDD-style tests derived from specification. | - | 2 | 0 |
| `mutants/tests/test_unified_config_schema_c.c` | - | - | 2 | 0 |
| `mutmut_config.py` | - | root | 0 | 0 |
| `scripts/mutation_test_c.py` | C Mutation Testing Script  This script performs mutation testing on C code by: 1. | misc | 6 | 0 |
| `src/async_i_o_for_beacon.c` | Auto-generated implementation for contract: Async I/O for Beacon | src | 1 | 0 |
| `src/beacon_common.c_extraction.c` | Auto-generated implementation for contract: beacon_common.c Extraction | src | 0 | 0 |
| `src/beacon_heartbeat___health_endpoint.c` | Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint | src | 1 | 0 |
| `src/bof_api_versioning.c` | Auto-generated implementation for contract: BOF API Versioning | src | 1 | 0 |
| `src/bof_path_traversal_hardening.c` | Auto-generated implementation for contract: BOF Path Traversal Hardening | src | 1 | 0 |
| `src/bof_streaming_(large_outputs).c` | Auto-generated implementation for contract: BOF Streaming (Large Outputs) | src | 1 | 0 |
| `src/c2_rest_api.c` | Auto-generated implementation for contract: C2 REST API | src | 1 | 0 |
| `src/certificate_pinning___tofu.c` | Auto-generated implementation for contract: Certificate Pinning / TOFU | src | 1 | 0 |
| `src/command_execution_via_execve.c` | Auto-generated implementation for contract: Command Execution via execve | src | 1 | 0 |
| `src/containerized_build_+_sbom.c` | Auto-generated implementation for contract: Containerized Build + SBOM | src | 0 | 0 |
| `src/hkdf_key_derivation.c` | Auto-generated implementation for contract: HKDF Key Derivation | src | 1 | 0 |
| `src/iv_generation_with_entropy_verification.c` | Auto-generated implementation for contract: IV Generation with Entropy Verification | src | 1 | 0 |
| `src/mutation_testing_integration.c` | Auto-generated implementation for contract: Mutation Testing Integration | src | 1 | 0 |
| `src/pre-commit_+_ci_hardening.c` | Auto-generated implementation for contract: Pre-commit + CI Hardening | src | 0 | 0 |
| `src/replay_protection.c` | Auto-generated implementation for contract: Replay Protection | src | 1 | 0 |
| `src/socks5___http_proxy_support.c` | Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support | src | 1 | 0 |
| `src/structured_jsonl_logging.c` | Auto-generated implementation for contract: Structured JSONL Logging | src | 1 | 0 |
| `src/tls_client_certificate_authentication.c` | Auto-generated implementation for contract: TLS Client Certificate Authentication | src | 1 | 0 |
| `src/unified_config_schema.c` | Auto-generated implementation for contract: Unified Config Schema | src | 1 | 0 |
| `tests/config_harness.c` | - | tests | 1 | 0 |
| `tests/crypto_harness.c` | - | tests | 2 | 0 |
| `tests/test_beacon_build.py` | Sanity build test: compile the v1 beacon against include/config.c and verify the binary links... | tests | 8 | 0 |
| `tests/test_bof_compile.py` | Verify every BOF compiles with the BOF build flags. | tests | 7 | 0 |
| `tests/test_bof_path_traversal.py` | Tests for BOF Path Traversal Hardening (Contract: BOF Path Traversal Hardening)  BDD Scenarios: 1. | tests | 18 | 0 |
| `tests/test_c2_beacon_bof_integration.py` | End-to-end integration test: C2 Server + Beacon + BOF execution. | tests | 10 | 0 |
| `tests/test_c2_http_e2e.py` | End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by server.serve(), and... | tests | 9 | 0 |
| `tests/test_c2_server.py` | Unit tests for the C2 server dispatcher. | tests | 11 | 0 |
| `tests/test_certificate_pinning.py` | Tests for Certificate Pinning / TOFU (Contract: Certificate Pinning / TOFU)  BDD Scenarios: 1. | tests | 24 | 0 |
| `tests/test_certificate_pinning_c.c` | test_cert_fingerprint_defaults_to_empty: #include <stdarg.h> #include <stddef.h> #include... | tests | 5 | 0 |
| `tests/test_config.py` | Unit tests for the BSB JSON config loader. | tests | 9 | 0 |
| `tests/test_crypto.py` | Roundtrip tests for AES-256-CFB. | tests | 9 | 0 |
| `tests/test_execve_command.py` | Tests for Command Execution via execve (Contract: Command Execution via execve)  BDD Scenarios: 1. | tests | 12 | 0 |
| `tests/test_hkdf_key_derivation.py` | Tests for HKDF Key Derivation (Contract: HKDF Key Derivation)  BDD Scenarios: 1. | tests | 19 | 0 |
| `tests/test_hkdf_key_derivation_c.c` | test_master_key_hex_loads_from_config: #include <stdarg.h> #include <stddef.h> #include... | tests | 11 | 0 |
| `tests/test_install_deploy.py` | End-to-end test for the "make beacon && ./build/beacon" workflow. | tests | 8 | 0 |
| `tests/test_iv_generation.py` | Tests for IV Generation with Entropy Verification (Contract: IV Generation with Entropy... | tests | 17 | 0 |
| `tests/test_iv_generation_c.c` | test_generate_secure_iv_success: #include <stdarg.h> #include <stddef.h> #include <setjmp.h>... | tests | 7 | 0 |
| `tests/test_replay_protection.py` | Tests for Replay Protection (Contract: Replay Protection)  BDD Scenarios: 1. | tests | 28 | 0 |
| `tests/test_runtime_random.py` | Tests for random per-run runtime values (Contract: random staging). | tests | 12 | 0 |
| `tests/test_stage.py` | Tests for diskless staging endpoints (Contract: fileless staging). | tests | 31 | 0 |
