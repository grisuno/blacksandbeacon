# Subsystem: tests

## tests/config_harness.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `main` (function, line 22) `int main(void)`
- Depends on: `include/config.h`

## tests/crypto_harness.c
- Layer: testing
- Language: c
- Symbols:
  - `hex_to_bytes` (function, line 12) `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)`
  - `main` (function, line 23) `int main(int argc, char **argv)`
- Depends on: `include/aes_cfb.h`

## tests/test_beacon_build.py
- Layer: testing
- Doc: Sanity build test: compile the v1 beacon against include/config.c and verify the binary links and embeds the symbols we 
- Language: py
- Symbols:
  - `have_headers` (function, line 20) `def have_headers()`
  - `compile_beacon` (function, line 34) `def compile_beacon()`
  - `inspect_binary` (function, line 50) `def inspect_binary()`
  - `test_beacon_compiles_and_links` (function, line 55) `def test_beacon_compiles_and_links()`
  - `test_beacon_exposes_bof_api` (function, line 64) `def test_beacon_exposes_bof_api()`
  - `test_beacon_exposes_elf_loader` (function, line 85) `def test_beacon_exposes_elf_loader()`
  - `main` (function, line 96) `def main()`

## tests/test_bof_compile.py
- Layer: testing
- Doc: Verify every BOF compiles with the BOF build flags.  A BOF is a position-independent ELF object that the beacon loads at
- Language: py
- Symbols:
  - `compile_bof` (function, line 21) `def compile_bof(name)`
  - `inspect_symbols` (function, line 35) `def inspect_symbols(obj_path)`
  - `test_compile_all` (function, line 53) `def test_compile_all()`
  - `test_export_go` (function, line 60) `def test_export_go()`
  - `test_unresolved_beacon_api` (function, line 68) `def test_unresolved_beacon_api()`
  - `test_no_libc_leak` (function, line 80) `def test_no_libc_leak()`
  - `main` (function, line 91) `def main()`

## tests/test_c2_http_e2e.py
- Layer: testing
- Doc: End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by server.serve(), and the full crypto roundtri
- Language: py
- Symbols:
  - `_free_port` (function, line 43) `def _free_port()`
  - `_recv_response` (function, line 51) `def _recv_response(sock, timeout)`
  - `test_http_get_poll_returns_encrypted_command` (function, line 65) `def test_http_get_poll_returns_encrypted_command()`
  - `test_http_post_report_writes_log` (function, line 115) `def test_http_post_report_writes_log()`
  - `test_gopher_legacy_still_works` (function, line 183) `def test_gopher_legacy_still_works()`
  - `test_http_post_with_url_encoded_b64_payload` (function, line 233) `def test_http_post_with_url_encoded_b64_payload()`
  - `test_fragmented_post_is_dispatched_as_http` (function, line 326) `def test_fragmented_post_is_dispatched_as_http()`
  - `main` (function, line 399) `def main()`
  - `encode` (function, line 274) `def encode(s)`

## tests/test_c2_server.py
- Layer: testing
- Doc: Unit tests for the C2 server dispatcher.  We import the dispatcher from c2/server.py and exercise handle_request() with 
- Language: py
- Symbols:
  - `make_state` (function, line 39) `def make_state(tmp)`
  - `test_get_command_empty` (function, line 46) `def test_get_command_empty()`
  - `test_get_command_queued` (function, line 58) `def test_get_command_queued()`
  - `test_report_writes_log` (function, line 69) `def test_report_writes_log()`
  - `test_bof_not_found` (function, line 85) `def test_bof_not_found()`
  - `test_bof_serves_existing_file` (function, line 92) `def test_bof_serves_existing_file()`
  - `test_unknown_selector` (function, line 104) `def test_unknown_selector()`
  - `test_path_traversal_in_bof_name` (function, line 111) `def test_path_traversal_in_bof_name()`
  - `test_roundtrip_empty` (function, line 120) `def test_roundtrip_empty()`
  - `test_roundtrip_text` (function, line 127) `def test_roundtrip_text()`
  - `main` (function, line 134) `def main()`
- Depends on: `c2/server.py`

## tests/test_config.py
- Layer: testing
- Doc: Unit tests for the BSB JSON config loader.  We exercise the loader via a small C harness compiled with the config.c sour
- Language: py
- Symbols:
  - `compile_harness` (function, line 24) `def compile_harness()`
  - `run_harness` (function, line 38) `def run_harness(config_text)`
  - `test_default_load` (function, line 55) `def test_default_load()`
  - `test_overrides` (function, line 73) `def test_overrides()`
  - `test_missing_file` (function, line 90) `def test_missing_file()`
  - `test_search_order_env_wins` (function, line 98) `def test_search_order_env_wins()`
  - `test_search_order_falls_back_to_cwd_default` (function, line 115) `def test_search_order_falls_back_to_cwd_default()`
  - `test_bad_hex_key` (function, line 141) `def test_bad_hex_key()`
  - `main` (function, line 156) `def main()`

## tests/test_crypto.py
- Layer: testing
- Doc: Roundtrip tests for AES-256-CFB.  Verifies the C implementation in include/aes_cfb.c is internally consistent. Cross-imp
- Language: py
- Symbols:
  - `compile_harness` (function, line 18) `def compile_harness()`
  - `run` (function, line 32) `def run(plaintext, key_hex)`
  - `test_short` (function, line 40) `def test_short()`
  - `test_block_boundary` (function, line 44) `def test_block_boundary()`
  - `test_longer_than_block` (function, line 49) `def test_longer_than_block()`
  - `test_known_ciphertext` (function, line 55) `def test_known_ciphertext()`
  - `test_python_can_decrypt_c_ciphertext` (function, line 74) `def test_python_can_decrypt_c_ciphertext()`
  - `main` (function, line 107) `def main()`

## tests/test_install_deploy.py
- Layer: testing
- Doc: End-to-end test for the "make beacon && ./build/beacon" workflow.  After `make clean && make beacon bofs`, the operator 
- Language: py
- Symbols:
  - `make_all` (function, line 23) `def make_all()`
  - `run_beacon` (function, line 29) `def run_beacon(binary, cwd)`
  - `test_build_beacon_lands_alongside_config` (function, line 42) `def test_build_beacon_lands_alongside_config()`
  - `test_staged_files_have_correct_modes` (function, line 53) `def test_staged_files_have_correct_modes()`
  - `test_staged_beacon_runs_from_any_cwd` (function, line 61) `def test_staged_beacon_runs_from_any_cwd()`
  - `test_staged_bofs_are_present` (function, line 74) `def test_staged_bofs_are_present()`
  - `test_clean_removes_everything` (function, line 82) `def test_clean_removes_everything()`
  - `main` (function, line 104) `def main()`
