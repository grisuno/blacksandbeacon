# Subsystem: tests

## tests/config_harness.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `main` (function, line 24) `int main(void)`
- Depends on: `include/config.h`

## tests/crypto_harness.c
- Layer: testing
- Language: c
- Symbols:
  - `hex_to_bytes` (function, line 12) `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)`
  - `main` (function, line 27) `int main(int argc, char **argv)`
- Depends on: `include/aes_cfb.h`

## tests/test_beacon_build.py
- Doc: Sanity build test: compile the v1 beacon against include/config.c and verify the binary links...
- Layer: testing
- Language: py
- Symbols:
  - `have_headers` (function, line 29) `def have_headers()`
  - `compile_beacon` (function, line 43) `def compile_beacon()`
  - `inspect_binary` (function, line 74) `def inspect_binary()`
  - `ensure_beacon` (function, line 79) `def ensure_beacon()`
  - `test_beacon_compiles_and_links` (function, line 93) `def test_beacon_compiles_and_links()`
  - `test_beacon_exposes_bof_api` (function, line 102) `def test_beacon_exposes_bof_api()`
  - `test_beacon_exposes_elf_loader` (function, line 122) `def test_beacon_exposes_elf_loader()`
  - `main` (function, line 132) `def main()`

## tests/test_bof_compile.py
- Doc: Verify every BOF compiles with the BOF build flags.
- Layer: testing
- Language: py
- Symbols:
  - `compile_bof` (function, line 21) `def compile_bof(name)`
  - `inspect_symbols` (function, line 44) `def inspect_symbols(obj_path)`
  - `test_compile_all` (function, line 62) `def test_compile_all()`
  - `test_export_go` (function, line 71) `def test_export_go()`
  - `test_unresolved_beacon_api` (function, line 79) `def test_unresolved_beacon_api()`
  - `test_no_libc_leak` (function, line 97) `def test_no_libc_leak()`
  - `main` (function, line 118) `def main()`

## tests/test_bof_path_traversal.py
- Doc: Tests for BOF Path Traversal Hardening (Contract: BOF Path Traversal Hardening)  BDD Scenarios: 1.
- Layer: testing
- Language: py
- Symbols:
  - `TestBOFPathTraversalConfig` (class, line 25) `class TestBOFPathTraversalConfig`
  - `TestBOFPathTraversalServer` (class, line 36) `class TestBOFPathTraversalServer`
  - `TestBOFPathTraversalMutationResistance` (class, line 175) `class TestBOFPathTraversalMutationResistance`
  - `test_upload_dir_config_exists` (method, line 28) `def test_upload_dir_config_exists(self)`
  - `test_normal_bof_name_served` (method, line 39) `def test_normal_bof_name_served(self)`
  - `test_path_traversal_parent_dir_rejected` (method, line 53) `def test_path_traversal_parent_dir_rejected(self)`
  - `test_path_traversal_multiple_parent_dirs_rejected` (method, line 65) `def test_path_traversal_multiple_parent_dirs_rejected(self)`
  - `test_path_traversal_with_subdir_rejected` (method, line 77) `def test_path_traversal_with_subdir_rejected(self)`
  - `test_absolute_path_rejected` (method, line 89) `def test_absolute_path_rejected(self)`
  - `test_url_encoded_traversal_rejected` (method, line 101) `def test_url_encoded_traversal_rejected(self)`
  - `test_double_url_encoded_traversal_rejected` (method, line 114) `def test_double_url_encoded_traversal_rejected(self)`
  - `test_null_byte_injection_rejected` (method, line 126) `def test_null_byte_injection_rejected(self)`
  - `test_upload_dir_symlink_escape_prevented` (method, line 138) `def test_upload_dir_symlink_escape_prevented(self)`
  - `test_symlink_outside_upload_dir_rejected` (method, line 156) `def test_symlink_outside_upload_dir_rejected(self)`
  - `test_basename_not_sufficient_protection` (method, line 178) `def test_basename_not_sufficient_protection(self)`
  - `test_realpath_prefix_check_not_mutated` (method, line 186) `def test_realpath_prefix_check_not_mutated(self)`
  - `test_case_sensitivity_on_linux` (method, line 216) `def test_case_sensitivity_on_linux(self)`
  - `test_unicode_normalization_not_mutated` (method, line 234) `def test_unicode_normalization_not_mutated(self)`
- Depends on: `c2/server.py`

## tests/test_c2_beacon_bof_integration.py
- Doc: End-to-end integration test: C2 Server + Beacon + BOF execution.
- Layer: testing
- Language: py
- Symbols:
  - `TestC2BeaconBOFIntegration` (class, line 34) `class TestC2BeaconBOFIntegration`
  - `test_c2_beacon_bof_integration` (function, line 300) `def test_c2_beacon_bof_integration()`
  - `setup_method` (method, line 37) `def setup_method(self)`
  - `teardown_method` (method, line 71) `def teardown_method(self)`
  - `_free_port` (method, line 76) `def _free_port(self)`
  - `_wait_for_server_ready` (method, line 84) `def _wait_for_server_ready(self, host, port, timeout)`
  - `_wait_for_bof_result` (method, line 98) `def _wait_for_bof_result(self, state, client_id, timeout)`
  - `test_beacon_executes_whoami_bof` (method, line 118) `def test_beacon_executes_whoami_bof(self)`
  - `_run_server` (method, line 283) `def _run_server(self, cfg, state)`
  - `_wait_for_server_ready` (method, line 286) `def _wait_for_server_ready(self, host, port, timeout)`
- Depends on: `c2/server.py`, `include/config_py.py`

## tests/test_c2_http_e2e.py
- Doc: End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by server.serve(), and...
- Layer: testing
- Language: py
- Symbols:
  - `_free_port` (function, line 45) `def _free_port()`
  - `_recv_response` (function, line 53) `def _recv_response(sock, timeout)`
  - `test_http_get_poll_returns_encrypted_command` (function, line 67) `def test_http_get_poll_returns_encrypted_command()`
  - `test_http_post_report_writes_log` (function, line 122) `def test_http_post_report_writes_log()`
  - `test_gopher_legacy_still_works` (function, line 192) `def test_gopher_legacy_still_works()`
  - `test_http_post_with_url_encoded_b64_payload` (function, line 246) `def test_http_post_with_url_encoded_b64_payload()`
  - `test_fragmented_post_is_dispatched_as_http` (function, line 347) `def test_fragmented_post_is_dispatched_as_http()`
  - `main` (function, line 422) `def main()`
  - `encode` (function, line 288) `def encode(s)`
- Depends on: `c2/__init__.py`, `c2/server.py`

## tests/test_c2_server.py
- Doc: Unit tests for the C2 server dispatcher.
- Layer: testing
- Language: py
- Symbols:
  - `make_state` (function, line 41) `def make_state(tmp)`
  - `test_get_command_empty` (function, line 48) `def test_get_command_empty()`
  - `test_get_command_queued` (function, line 60) `def test_get_command_queued()`
  - `test_report_writes_log` (function, line 71) `def test_report_writes_log()`
  - `test_bof_not_found` (function, line 96) `def test_bof_not_found()`
  - `test_bof_serves_existing_file` (function, line 103) `def test_bof_serves_existing_file()`
  - `test_unknown_selector` (function, line 115) `def test_unknown_selector()`
  - `test_path_traversal_in_bof_name` (function, line 122) `def test_path_traversal_in_bof_name()`
  - `test_roundtrip_empty` (function, line 131) `def test_roundtrip_empty()`
  - `test_roundtrip_text` (function, line 138) `def test_roundtrip_text()`
  - `main` (function, line 145) `def main()`
- Depends on: `c2/server.py`

## tests/test_certificate_pinning.py
- Doc: Tests for Certificate Pinning / TOFU (Contract: Certificate Pinning / TOFU)  BDD Scenarios: 1.
- Layer: testing
- Language: py
- Symbols:
  - `TestCertificatePinningConfig` (class, line 23) `class TestCertificatePinningConfig`
  - `TestCertificatePinningCConfig` (class, line 86) `class TestCertificatePinningCConfig`
  - `TestCertificatePinningIntegration` (class, line 96) `class TestCertificatePinningIntegration`
  - `TestCertificatePinningMutationResistance` (class, line 321) `class TestCertificatePinningMutationResistance`
  - `test_config_loads_empty_fingerprint` (method, line 26) `def test_config_loads_empty_fingerprint(self)`
  - `test_config_loads_valid_fingerprint` (method, line 38) `def test_config_loads_valid_fingerprint(self)`
  - `test_config_rejects_invalid_fingerprint_length` (method, line 51) `def test_config_rejects_invalid_fingerprint_length(self)`
  - `test_config_rejects_non_hex_fingerprint` (method, line 62) `def test_config_rejects_non_hex_fingerprint(self)`
  - `test_config_defaults_to_empty_fingerprint` (method, line 73) `def test_config_defaults_to_empty_fingerprint(self)`
  - `test_c_config_parses_fingerprint_field` (method, line 89) `def test_c_config_parses_fingerprint_field(self)`
  - `_free_port` (method, line 106) `def _free_port(self)`
  - `_gen_cert_and_pin` (method, line 114) `def _gen_cert_and_pin(self)`
  - `_start_tls_server` (method, line 149) `def _start_tls_server(self, port, cert_pem, key_pem, body)`
  - `_run_beacon_with_bof_tls` (method, line 181) `def _run_beacon_with_bof_tls(self, cert_pem, key_pem, pin_hex)`
  - `test_beacon_verifies_pinned_certificate` (method, line 282) `def test_beacon_verifies_pinned_certificate(self)`
  - `test_beacon_rejects_mismatched_certificate` (method, line 293) `def test_beacon_rejects_mismatched_certificate(self)`
  - `test_tofu_first_connection_stores_fingerprint` (method, line 307) `def test_tofu_first_connection_stores_fingerprint(self)`
  - `test_fingerprint_empty_check_not_mutated_to_always_true` (method, line 324) `def test_fingerprint_empty_check_not_mutated_to_always_true(self)`
  - `test_fingerprint_hex_validation_not_mutated` (method, line 334) `def test_fingerprint_hex_validation_not_mutated(self)`
  - `test_pin_option_set_only_when_fingerprint_present` (method, line 346) `def test_pin_option_set_only_when_fingerprint_present(self)`
  - `Handler` (class, line 155) `class Handler(BaseHTTPRequestHandler)`
  - `_run` (function, line 171) `def _run()`
  - `do_GET` (method, line 156) `def do_GET(self)`
  - `log_message` (method, line 162) `def log_message(self)`
- Depends on: `c2/server.py`, `include/config_py.py`

## tests/test_certificate_pinning_c.c
- Doc: test_cert_fingerprint_defaults_to_empty: #include <stdarg.h> #include <stddef.h> #include...
- Layer: testing
- Language: c
- Symbols:
  - `test_cert_fingerprint_defaults_to_empty` (function, line 19) `static void test_cert_fingerprint_defaults_to_empty(void **state)`
  - `test_cert_fingerprint_loads_from_config` (function, line 29) `static void test_cert_fingerprint_loads_from_config(void **state)`
  - `test_cert_fingerprint_invalid_length_fails` (function, line 55) `static void test_cert_fingerprint_invalid_length_fails(void **state)`
  - `test_network_struct_has_fingerprint_field` (function, line 82) `static void test_network_struct_has_fingerprint_field(void **state)`
  - `main` (function, line 90) `int main(void)`
- Depends on: `include/config.h`

## tests/test_config.py
- Doc: Unit tests for the BSB JSON config loader.
- Layer: testing
- Language: py
- Symbols:
  - `compile_harness` (function, line 25) `def compile_harness()`
  - `run_harness` (function, line 46) `def run_harness(config_text)`
  - `test_default_load` (function, line 63) `def test_default_load()`
  - `test_overrides` (function, line 81) `def test_overrides()`
  - `test_missing_file` (function, line 104) `def test_missing_file()`
  - `test_search_order_env_wins` (function, line 112) `def test_search_order_env_wins()`
  - `test_search_order_falls_back_to_cwd_default` (function, line 137) `def test_search_order_falls_back_to_cwd_default()`
  - `test_bad_hex_key` (function, line 172) `def test_bad_hex_key()`
  - `main` (function, line 187) `def main()`

## tests/test_crypto.py
- Doc: Roundtrip tests for AES-256-CFB.
- Layer: testing
- Language: py
- Symbols:
  - `compile_harness` (function, line 27) `def compile_harness()`
  - `run` (function, line 59) `def run(plaintext, key_hex)`
  - `test_short` (function, line 68) `def test_short()`
  - `test_block_boundary` (function, line 72) `def test_block_boundary()`
  - `test_longer_than_block` (function, line 77) `def test_longer_than_block()`
  - `test_known_ciphertext` (function, line 83) `def test_known_ciphertext()`
  - `test_python_can_decrypt_c_ciphertext` (function, line 104) `def test_python_can_decrypt_c_ciphertext()`
  - `test_c_replay_encrypt_python_decrypt` (function, line 136) `def test_c_replay_encrypt_python_decrypt()`
  - `main` (function, line 167) `def main()`
- Depends on: `c2/server.py`

## tests/test_execve_command.py
- Doc: Tests for Command Execution via execve (Contract: Command Execution via execve)  BDD Scenarios: 1.
- Layer: testing
- Language: py
- Symbols:
  - `TestExecveCommandExecution` (class, line 25) `class TestExecveCommandExecution`
  - `TestExecveMutationResistance` (class, line 57) `class TestExecveMutationResistance`
  - `test_simple_command_execution` (method, line 28) `def test_simple_command_execution(self)`
  - `test_command_with_arguments` (method, line 34) `def test_command_with_arguments(self)`
  - `test_quoted_arguments` (method, line 38) `def test_quoted_arguments(self)`
  - `test_non_existent_command` (method, line 42) `def test_non_existent_command(self)`
  - `test_stderr_capture` (method, line 46) `def test_stderr_capture(self)`
  - `test_shell_metacharacters_not_interpreted` (method, line 50) `def test_shell_metacharacters_not_interpreted(self)`
  - `test_no_system_call` (method, line 60) `def test_no_system_call(self)`
  - `test_no_popen_call` (method, line 67) `def test_no_popen_call(self)`
  - `test_argv_array_not_string` (method, line 71) `def test_argv_array_not_string(self)`
  - `test_shell_metacharacters_escaped` (method, line 77) `def test_shell_metacharacters_escaped(self)`

## tests/test_hkdf_key_derivation.py
- Doc: Tests for HKDF Key Derivation (Contract: HKDF Key Derivation)  BDD Scenarios: 1.
- Layer: testing
- Language: py
- Symbols:
  - `TestHKDFKeyDerivationConfig` (class, line 24) `class TestHKDFKeyDerivationConfig`
  - `TestHKDFDerivation` (class, line 87) `class TestHKDFDerivation`
  - `TestHKDFConfigIntegration` (class, line 159) `class TestHKDFConfigIntegration`
  - `TestHKDFMutationResistance` (class, line 220) `class TestHKDFMutationResistance`
  - `test_config_loads_master_key_hex` (method, line 27) `def test_config_loads_master_key_hex(self)`
  - `test_config_loads_aes_key_hex_backward_compat` (method, line 40) `def test_config_loads_aes_key_hex_backward_compat(self)`
  - `test_config_rejects_missing_both_keys` (method, line 53) `def test_config_rejects_missing_both_keys(self)`
  - `test_config_validates_master_key_hex_length` (method, line 64) `def test_config_validates_master_key_hex_length(self)`
  - `test_config_validates_master_key_hex_hex_chars` (method, line 75) `def test_config_validates_master_key_hex_hex_chars(self)`
  - `test_hkdf_derives_encryption_and_hmac_keys` (method, line 90) `def test_hkdf_derives_encryption_and_hmac_keys(self)`
  - `test_hkdf_deterministic` (method, line 123) `def test_hkdf_deterministic(self)`
  - `test_hkdf_different_info_produces_different_keys` (method, line 137) `def test_hkdf_different_info_produces_different_keys(self)`
  - `test_load_config_returns_derived_keys_when_master_key_present` (method, line 162) `def test_load_config_returns_derived_keys_when_master_key_present(self)`
  - `test_load_config_derives_from_aes_key_when_no_master_key` (method, line 180) `def test_load_config_derives_from_aes_key_when_no_master_key(self)`
  - `test_c_and_python_derive_same_keys` (method, line 196) `def test_c_and_python_derive_same_keys(self)`
  - `test_salt_is_constant_not_mutated` (method, line 223) `def test_salt_is_constant_not_mutated(self)`
  - `test_info_strings_are_enc_and_hmac_not_mutated` (method, line 238) `def test_info_strings_are_enc_and_hmac_not_mutated(self)`
  - `test_key_length_is_32_bytes_not_mutated` (method, line 263) `def test_key_length_is_32_bytes_not_mutated(self)`
  - `test_sha256_not_mutated_to_sha1_or_md5` (method, line 277) `def test_sha256_not_mutated_to_sha1_or_md5(self)`
- Depends on: `include/config_py.py`

## tests/test_hkdf_key_derivation_c.c
- Doc: test_master_key_hex_loads_from_config: #include <stdarg.h> #include <stddef.h> #include...
- Layer: testing
- Language: c
- Symbols:
  - `test_master_key_hex_loads_from_config` (function, line 19) `static void test_master_key_hex_loads_from_config(void **state)`
  - `test_aes_key_hex_backward_compat` (function, line 55) `static void test_aes_key_hex_backward_compat(void **state)`
  - `test_missing_both_keys_fails` (function, line 90) `static void test_missing_both_keys_fails(void **state)`
  - `test_invalid_master_key_hex_length_fails` (function, line 115) `static void test_invalid_master_key_hex_length_fails(void **state)`
  - `test_key_separation` (function, line 139) `static void test_key_separation(void **state)`
  - `test_deterministic_derivation` (function, line 165) `static void test_deterministic_derivation(void **state)`
  - `test_crypto_struct_has_new_fields` (function, line 200) `static void test_crypto_struct_has_new_fields(void **state)`
  - `assert_memory_equal` (function, line 207) `assert_memory_equal(crypto.master_key, (uint8_t[BSB_AES_KEY_BYTES])`
  - `assert_memory_equal` (function, line 208) `assert_memory_equal(crypto.encryption_key, (uint8_t[BSB_AES_KEY_BYTES])`
  - `assert_memory_equal` (function, line 209) `assert_memory_equal(crypto.hmac_key, (uint8_t[BSB_AES_KEY_BYTES])`
  - `main` (function, line 212) `int main(void)`
- Depends on: `include/config.h`

## tests/test_install_deploy.py
- Doc: End-to-end test for the "make beacon && ./build/beacon" workflow.
- Layer: testing
- Language: py
- Symbols:
  - `make_all` (function, line 23) `def make_all()`
  - `run_beacon` (function, line 29) `def run_beacon(binary, cwd)`
  - `test_build_beacon_lands_alongside_config` (function, line 56) `def test_build_beacon_lands_alongside_config()`
  - `test_staged_files_have_correct_modes` (function, line 67) `def test_staged_files_have_correct_modes()`
  - `test_staged_beacon_runs_from_any_cwd` (function, line 75) `def test_staged_beacon_runs_from_any_cwd()`
  - `test_staged_bofs_are_present` (function, line 90) `def test_staged_bofs_are_present()`
  - `test_clean_removes_everything` (function, line 103) `def test_clean_removes_everything()`
  - `main` (function, line 129) `def main()`

## tests/test_iv_generation.py
- Doc: Tests for IV Generation with Entropy Verification (Contract: IV Generation with Entropy...
- Layer: testing
- Language: py
- Symbols:
  - `TestIVGenerationConfig` (class, line 26) `class TestIVGenerationConfig`
  - `TestIVGenerationPython` (class, line 42) `class TestIVGenerationPython`
  - `TestIVGenerationCBehavior` (class, line 101) `class TestIVGenerationCBehavior`
  - `TestIVMutationResistance` (class, line 128) `class TestIVMutationResistance`
  - `test_config_defaults_include_iv_settings` (method, line 29) `def test_config_defaults_include_iv_settings(self)`
  - `test_encrypt_data_uses_os_urandom_for_iv` (method, line 45) `def test_encrypt_data_uses_os_urandom_for_iv(self)`
  - `test_encrypt_data_iv_is_16_bytes` (method, line 58) `def test_encrypt_data_iv_is_16_bytes(self)`
  - `test_decrypt_data_handles_iv_correctly` (method, line 73) `def test_decrypt_data_handles_iv_correctly(self)`
  - `test_encrypt_decrypt_roundtrip_with_different_ivs` (method, line 85) `def test_encrypt_decrypt_roundtrip_with_different_ivs(self)`
  - `test_rand_bytes_success_path` (method, line 104) `def test_rand_bytes_success_path(self)`
  - `test_getrandom_fallback_path` (method, line 113) `def test_getrandom_fallback_path(self)`
  - `test_fail_closed_on_entropy_failure` (method, line 121) `def test_fail_closed_on_entropy_failure(self)`
  - `test_iv_length_is_16_bytes_not_mutated` (method, line 131) `def test_iv_length_is_16_bytes_not_mutated(self)`
  - `test_iv_not_all_zeros` (method, line 146) `def test_iv_not_all_zeros(self)`
  - `test_urandom_blocks_on_low_entropy` (method, line 163) `def test_urandom_blocks_on_low_entropy(self)`
  - `test_rand_bytes_return_value_checked` (method, line 171) `def test_rand_bytes_return_value_checked(self)`
  - `test_getrandom_flags_grnd_nonblock` (method, line 177) `def test_getrandom_flags_grnd_nonblock(self)`
- Depends on: `c2/server.py`, `include/config_py.py`

## tests/test_iv_generation_c.c
- Doc: test_generate_secure_iv_success: #include <stdarg.h> #include <stddef.h> #include <setjmp.h>...
- Layer: testing
- Language: c
- Symbols:
  - `test_generate_secure_iv_success` (function, line 19) `static void test_generate_secure_iv_success(void **state)`
  - `test_generate_secure_iv_different_each_call` (function, line 31) `static void test_generate_secure_iv_different_each_call(void **state)`
  - `test_generate_secure_iv_null_input` (function, line 47) `static void test_generate_secure_iv_null_input(void **state)`
  - `test_generate_secure_iv_length` (function, line 54) `static void test_generate_secure_iv_length(void **state)`
  - `test_beacon_common_has_iv_function` (function, line 71) `static void test_beacon_common_has_iv_function(void **state)`
  - `main` (function, line 78) `int main(void)`
  - `bsb_generate_secure_iv` (function, line 74) `extern int bsb_generate_secure_iv(unsigned char *iv_out);`
- Depends on: `include/beacon_common.h`

## tests/test_replay_protection.py
- Doc: Tests for Replay Protection (Contract: Replay Protection)  BDD Scenarios: 1.
- Layer: testing
- Language: py
- Symbols:
  - `TestReplayProtectionConfig` (class, line 29) `class TestReplayProtectionConfig`
  - `TestReplayProtectionPayloadFormat` (class, line 63) `class TestReplayProtectionPayloadFormat`
  - `TestReplayProtectionServerVerification` (class, line 81) `class TestReplayProtectionServerVerification`
  - `TestReplayProtectionBeaconBehavior` (class, line 108) `class TestReplayProtectionBeaconBehavior`
  - `TestReplayProtectionIntegration` (class, line 124) `class TestReplayProtectionIntegration`
  - `TestReplayProtectionMutationResistance` (class, line 140) `class TestReplayProtectionMutationResistance`
  - `test_config_defaults_include_replay_window` (method, line 32) `def test_config_defaults_include_replay_window(self)`
  - `test_config_custom_replay_window` (method, line 43) `def test_config_custom_replay_window(self)`
  - `test_config_replay_window_validation_positive` (method, line 53) `def test_config_replay_window_validation_positive(self)`
  - `test_encrypt_includes_counter_and_timestamp` (method, line 66) `def test_encrypt_includes_counter_and_timestamp(self)`
  - `test_payload_structure_iv_16_counter_8_timestamp_8_ciphertext` (method, line 75) `def test_payload_structure_iv_16_counter_8_timestamp_8_ciphertext(self)`
  - `test_server_tracks_last_seen_counter_per_client` (method, line 84) `def test_server_tracks_last_seen_counter_per_client(self)`
  - `test_server_rejects_replay_counter_le_last_seen` (method, line 90) `def test_server_rejects_replay_counter_le_last_seen(self)`
  - `test_server_rejects_future_timestamp_gt_now_plus_60` (method, line 95) `def test_server_rejects_future_timestamp_gt_now_plus_60(self)`
  - `test_server_rejects_stale_timestamp_lt_now_minus_window` (method, line 99) `def test_server_rejects_stale_timestamp_lt_now_minus_window(self)`
  - `test_server_accepts_valid_counter_and_timestamp` (method, line 103) `def test_server_accepts_valid_counter_and_timestamp(self)`
  - `test_beacon_increments_counter_per_message` (method, line 111) `def test_beacon_increments_counter_per_message(self)`
  - `test_beacon_resets_counter_on_restart` (method, line 115) `def test_beacon_resets_counter_on_restart(self)`
  - `test_beacon_includes_timestamp_in_payload` (method, line 119) `def test_beacon_includes_timestamp_in_payload(self)`
  - `test_full_roundtrip_with_replay_protection` (method, line 127) `def test_full_roundtrip_with_replay_protection(self)`
  - `test_replay_attack_detected` (method, line 131) `def test_replay_attack_detected(self)`
  - `test_stale_payload_rejected` (method, line 135) `def test_stale_payload_rejected(self)`
  - `test_counter_comparison_not_mutated` (method, line 143) `def test_counter_comparison_not_mutated(self)`
  - `test_timestamp_future_check_not_mutated` (method, line 150) `def test_timestamp_future_check_not_mutated(self)`
  - `test_timestamp_stale_check_not_mutated` (method, line 161) `def test_timestamp_stale_check_not_mutated(self)`
  - `test_counter_increment_not_mutated` (method, line 173) `def test_counter_increment_not_mutated(self)`
  - `test_counter_reset_on_new_session` (method, line 179) `def test_counter_reset_on_new_session(self)`
  - `test_hmac_covers_counter_and_timestamp` (method, line 184) `def test_hmac_covers_counter_and_timestamp(self)`
- Depends on: `c2/server.py`, `include/config_py.py`

## tests/test_runtime_random.py
- Doc: Tests for random per-run runtime values (Contract: random staging).
- Layer: testing
- Language: py
- Symbols:
  - `lrc` (function, line 33) `def lrc(monkeypatch, tmp_path, raw, env)`
  - `TestRandomGeneration` (class, line 44) `class TestRandomGeneration`
  - `TestStageConfigCarriesRuntimeValues` (class, line 99) `class TestStageConfigCarriesRuntimeValues`
  - `test_all_generated_when_nothing_provided` (method, line 45) `def test_all_generated_when_nothing_provided(self, monkeypatch, tmp_path)`
  - `test_generated_key_parities` (method, line 54) `def test_generated_key_parities(self, monkeypatch, tmp_path)`
  - `test_random_url_points_at_generated_port` (method, line 62) `def test_random_url_points_at_generated_port(self, monkeypatch, tmp_path)`
  - `test_two_runs_differ` (method, line 66) `def test_two_runs_differ(self, monkeypatch, tmp_path)`
  - `test_provided_values_preserved` (method, line 73) `def test_provided_values_preserved(self, monkeypatch, tmp_path)`
  - `test_env_wins` (method, line 87) `def test_env_wins(self, monkeypatch, tmp_path)`
  - `test_explicit_token_no_generation` (method, line 92) `def test_explicit_token_no_generation(self, monkeypatch, tmp_path)`
  - `test_served_config_matches_runtime` (method, line 100) `def test_served_config_matches_runtime(self, monkeypatch, tmp_path)`
  - `test_file_config_values_win_when_provided` (method, line 112) `def test_file_config_values_win_when_provided(self, monkeypatch, tmp_path)`
- Depends on: `c2/server.py`, `include/config_py.py`

## tests/test_stage.py
- Doc: Tests for diskless staging endpoints (Contract: fileless staging).
- Layer: testing
- Language: py
- Symbols:
  - `make_state` (function, line 54) `def make_state(tmpdir, token, beacon)`
  - `TestStageCodec` (class, line 66) `class TestStageCodec`
  - `TestStageToken` (class, line 102) `class TestStageToken`
  - `TestStageBeacon` (class, line 120) `class TestStageBeacon`
  - `TestStageConfig` (class, line 144) `class TestStageConfig`
  - `TestStageRouting` (class, line 165) `class TestStageRouting`
  - `TestStageOneliner` (class, line 197) `class TestStageOneliner`
  - `_self_signed_cert` (function, line 210) `def _self_signed_cert(td)`
  - `TestStageTLSEndToEnd` (class, line 228) `class TestStageTLSEndToEnd`
  - `test_encode_decode_roundtrip` (method, line 67) `def test_encode_decode_roundtrip(self)`
  - `test_no_key_material_on_wire` (method, line 71) `def test_no_key_material_on_wire(self)`
  - `test_keys_derived_deterministically_from_token` (method, line 78) `def test_keys_derived_deterministically_from_token(self)`
  - `test_server_payload_hkdf_parity` (method, line 84) `def test_server_payload_hkdf_parity(self)`
  - `test_missing_token_forbidden` (method, line 103) `def test_missing_token_forbidden(self, tmp_path)`
  - `test_wrong_token_forbidden` (method, line 107) `def test_wrong_token_forbidden(self, tmp_path)`
  - `test_no_token_configured_fails_closed` (method, line 111) `def test_no_token_configured_fails_closed(self, tmp_path)`
  - `test_unknown_kind_forbidden` (method, line 115) `def test_unknown_kind_forbidden(self, tmp_path)`
  - `test_beacon_roundtrip` (method, line 121) `def test_beacon_roundtrip(self, tmp_path)`
  - `test_beacon_file_missing` (method, line 129) `def test_beacon_file_missing(self, tmp_path)`
  - `test_beacon_not_elf` (method, line 133) `def test_beacon_not_elf(self, tmp_path)`
  - `test_beacon_path_none` (method, line 139) `def test_beacon_path_none(self, tmp_path)`
  - `test_config_roundtrip` (method, line 145) `def test_config_roundtrip(self, tmp_path, monkeypatch)`
  - `test_config_always_available` (method, line 157) `def test_config_always_available(self, tmp_path, monkeypatch)`
  - `test_http_get_beacon_routed` (method, line 166) `def test_http_get_beacon_routed(self, tmp_path)`
  - `test_http_get_config_routed` (method, line 175) `def test_http_get_config_routed(self, tmp_path, monkeypatch)`
  - `test_wrong_token_routed_rejected` (method, line 184) `def test_wrong_token_routed_rejected(self, tmp_path)`
  - `test_legacy_selector_routed` (method, line 189) `def test_legacy_selector_routed(self, tmp_path)`
  - `test_oneliner_embeds_url_and_token` (method, line 198) `def test_oneliner_embeds_url_and_token(self, tmp_path)`
  - `test_tls_roundtrip` (method, line 229) `def test_tls_roundtrip(self, tmp_path, monkeypatch)`
- Depends on: `c2/server.py`
