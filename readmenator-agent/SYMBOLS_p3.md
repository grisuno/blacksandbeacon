# Symbols (page 3 of 3)
Previous: [SYMBOLS_p2.md](SYMBOLS_p2.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `bsb_network_t` | struct | `include/config.h:49` | `` |
| `bsb_timing_t` | struct | `include/config.h:42` | `` |
| `_deep_merge` | function | `include/config_py.py:55` | `def _deep_merge(base, overlay)` |
| `load_config` | function | `include/config_py.py:65` | `def load_config(path)` |
| `AT_FDCWD` | macro | `issudo.c:19` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `issudo.c:11` | `extern void BeaconOutput(int, const char*, int);` |
| `BeaconPrintf` | function | `issudo.c:10` | `extern void BeaconPrintf(int, const char*, ...);` |
| `CALLBACK_OUTPUT` | macro | `issudo.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `issudo.c:2` | `#define NULL` |
| `SYS_close` | macro | `issudo.c:16` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `issudo.c:18` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `issudo.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `issudo.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `issudo.c:15` | `#define SYS_read` |
| `get_username_from_uid` | function | `issudo.c:52` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `issudo.c:108` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `issudo.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `issudo.c:7` | `typedef long ssize_t;` |
| `strcmp` | function | `issudo.c:43` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `issudo.c:32` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `issudo.c:22` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `main` | function | `tests/config_harness.c:22` | `int main(void)` |
| `hex_to_bytes` | function | `tests/crypto_harness.c:12` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `tests/crypto_harness.c:23` | `int main(int argc, char **argv)` |
| `compile_beacon` | function | `tests/test_beacon_build.py:34` | `def compile_beacon()` |
| `have_headers` | function | `tests/test_beacon_build.py:20` | `def have_headers()` |
| `inspect_binary` | function | `tests/test_beacon_build.py:50` | `def inspect_binary()` |
| `main` | function | `tests/test_beacon_build.py:96` | `def main()` |
| `test_beacon_compiles_and_links` | function | `tests/test_beacon_build.py:55` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `tests/test_beacon_build.py:64` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `tests/test_beacon_build.py:85` | `def test_beacon_exposes_elf_loader()` |
| `compile_bof` | function | `tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `tests/test_bof_compile.py:35` | `def inspect_symbols(obj_path)` |
| `main` | function | `tests/test_bof_compile.py:91` | `def main()` |
| `test_compile_all` | function | `tests/test_bof_compile.py:53` | `def test_compile_all()` |
| `test_export_go` | function | `tests/test_bof_compile.py:60` | `def test_export_go()` |
| `test_no_libc_leak` | function | `tests/test_bof_compile.py:80` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `tests/test_bof_compile.py:68` | `def test_unresolved_beacon_api()` |
| `_free_port` | function | `tests/test_c2_http_e2e.py:43` | `def _free_port()` |
| `_recv_response` | function | `tests/test_c2_http_e2e.py:51` | `def _recv_response(sock, timeout)` |
| `encode` | function | `tests/test_c2_http_e2e.py:274` | `def encode(s)` |
| `main` | function | `tests/test_c2_http_e2e.py:399` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `tests/test_c2_http_e2e.py:326` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `tests/test_c2_http_e2e.py:183` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `tests/test_c2_http_e2e.py:65` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `tests/test_c2_http_e2e.py:115` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `tests/test_c2_http_e2e.py:233` | `def test_http_post_with_url_encoded_b64_payload()` |
| `main` | function | `tests/test_c2_server.py:134` | `def main()` |
| `make_state` | function | `tests/test_c2_server.py:39` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `tests/test_c2_server.py:85` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `tests/test_c2_server.py:92` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `tests/test_c2_server.py:46` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `tests/test_c2_server.py:58` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `tests/test_c2_server.py:111` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `tests/test_c2_server.py:69` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `tests/test_c2_server.py:120` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `tests/test_c2_server.py:127` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `tests/test_c2_server.py:104` | `def test_unknown_selector()` |
| `compile_harness` | function | `tests/test_config.py:24` | `def compile_harness()` |
| `main` | function | `tests/test_config.py:156` | `def main()` |
| `run_harness` | function | `tests/test_config.py:38` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `tests/test_config.py:141` | `def test_bad_hex_key()` |
| `test_default_load` | function | `tests/test_config.py:55` | `def test_default_load()` |
| `test_missing_file` | function | `tests/test_config.py:90` | `def test_missing_file()` |
| `test_overrides` | function | `tests/test_config.py:73` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `tests/test_config.py:98` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `tests/test_config.py:115` | `def test_search_order_falls_back_to_cwd_default()` |
| `compile_harness` | function | `tests/test_crypto.py:18` | `def compile_harness()` |
| `main` | function | `tests/test_crypto.py:107` | `def main()` |
| `run` | function | `tests/test_crypto.py:32` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `tests/test_crypto.py:44` | `def test_block_boundary()` |
| `test_known_ciphertext` | function | `tests/test_crypto.py:55` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `tests/test_crypto.py:49` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `tests/test_crypto.py:74` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `tests/test_crypto.py:40` | `def test_short()` |
| `main` | function | `tests/test_install_deploy.py:104` | `def main()` |
| `make_all` | function | `tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `tests/test_install_deploy.py:42` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `tests/test_install_deploy.py:82` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `tests/test_install_deploy.py:61` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `tests/test_install_deploy.py:74` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `tests/test_install_deploy.py:53` | `def test_staged_files_have_correct_modes()` |

