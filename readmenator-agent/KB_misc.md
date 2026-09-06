# Subsystem: misc

## beacons/v2/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `report_result` (function, line 65) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 138) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 187) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12)
  - `MAX_PEERS` (macro, line 26)
  - `DISCOVERY_PORT` (macro, line 28)
  - `DISCOVERY_INTERVAL` (macro, line 29)
  - `MAX_TTL` (macro, line 30)
  - `MESH_MSG_SIZE` (macro, line 31)

## beacons/v3/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `infrastructure` (function, line 7) `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
  - `compute_primes` (function, line 35) `static int compute_primes(int count)`
  - `evasive_sleep` (function, line 45) `static void evasive_sleep(int seconds)`
  - `report_result` (function, line 51) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 124) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 173) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12)

## bof/suid_enum/bof.c
- Layer: presentation
- Language: c
- Symbols:
  - `linux_stat` (struct, line 35)
  - `linux_dirent64` (struct, line 58)
  - `flush_output` (function, line 75) `static void flush_output(void)`
  - `emit` (function, line 82) `static void emit(const char *s)`
  - `format_mode` (function, line 105) `static void format_mode(unsigned int mode, char *out)`
  - `path_reset` (function, line 125) `static void path_reset(const char *root)`
  - `path_append` (function, line 134) `static void path_append(const char *name)`
  - `path_trim_to` (function, line 148) `static void path_trim_to(int len)`
  - `walk` (function, line 158) `static void walk(int depth)`
  - `go` (function, line 246) `void go(char *args, int alen)`
  - `SYS_getdents64` (macro, line 26)
  - `SYS_lstat` (macro, line 27)
  - `DT_UNKNOWN` (macro, line 30)
  - `DT_DIR` (macro, line 31)
  - `DT_LNK` (macro, line 32)

## c2/server.py
- Layer: utility
- Language: py
- Symbols:
  - `load_runtime_config` (function, line 59) `def load_runtime_config()`
  - `compute_hmac` (function, line 86) `def compute_hmac(key, data)`
  - `verify_hmac` (function, line 91) `def verify_hmac(key, data, signature)`
  - `encrypt_data` (function, line 97) `def encrypt_data(data, key, use_hmac)`
  - `decrypt_data` (function, line 117) `def decrypt_data(b64_data, key, use_hmac)`
  - `C2State` (class, line 136) `class C2State`
  - `handle_get_command` (method, line 150) `def handle_get_command(state, selector)`
  - `handle_report` (method, line 173) `def handle_report(state, b64_payload)`
  - `handle_bof` (method, line 229) `def handle_bof(state, name)`
  - `handle_request` (method, line 239) `def handle_request(state, selector)`
  - `serve_client` (method, line 272) `def serve_client(state, conn, addr)`
  - `command_injector` (method, line 294) `def command_injector(state)`
  - `main` (method, line 317) `def main()`
  - `__init__` (method, line 139) `def __init__(self, cfg)`
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`
