# Subsystem: misc

## beacons/v2/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `peer_t` (struct, line 33)
  - `mesh_msg_t` (struct, line 40)
  - `report_result` (function, line 66) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 139) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 188) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 27) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 28) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 29) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 30) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 31) `#define MESH_MSG_SIZE`
- Depends on: `include/beacon_common.h`

## beacons/v3/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `infrastructure` (function, line 8) `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
  - `compute_primes` (function, line 36) `static int compute_primes(int count)`
  - `evasive_sleep` (function, line 46) `static void evasive_sleep(int seconds)`
  - `report_result` (function, line 52) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 125) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 174) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

## bof/suid_enum/bof.c
- Doc: linux_stat: #include "beacon_api.h" #include "syscalls.h" /* getdents64 syscall number (x86_64)...
- Layer: utility
- Language: c
- Symbols:
  - `linux_stat` (struct, line 35)
  - `linux_dirent64` (struct, line 58)
  - `flush_output` (function, line 76) `static void flush_output(void)`
  - `emit` (function, line 83) `static void emit(const char *s)`
  - `format_mode` (function, line 105) `static void format_mode(unsigned int mode, char *out)`
  - `path_reset` (function, line 126) `static void path_reset(const char *root)`
  - `path_append` (function, line 135) `static void path_append(const char *name)`
  - `path_trim_to` (function, line 149) `static void path_trim_to(int len)`
  - `walk` (function, line 158) `static void walk(int depth)`
  - `go` (function, line 247) `void go(char *args, int alen)`
  - `SYS_getdents64` (macro, line 26) `#define SYS_getdents64`
  - `SYS_lstat` (macro, line 27) `#define SYS_lstat`
  - `DT_UNKNOWN` (macro, line 30) `#define DT_UNKNOWN`
  - `DT_DIR` (macro, line 31) `#define DT_DIR`
  - `DT_LNK` (macro, line 32) `#define DT_LNK`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## c2/server.py
- Doc: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Layer: utility
- Language: py
- Symbols:
  - `load_runtime_config` (function, line 60) `def load_runtime_config()`
  - `compute_hmac` (function, line 87) `def compute_hmac(key, data)`
  - `verify_hmac` (function, line 92) `def verify_hmac(key, data, signature)`
  - `encrypt_data` (function, line 98) `def encrypt_data(data, key, use_hmac)`
  - `decrypt_data` (function, line 118) `def decrypt_data(b64_data, key, use_hmac)`
  - `C2State` (class, line 137) `class C2State`
  - `handle_get_command` (function, line 151) `def handle_get_command(state, selector)`
  - `handle_report` (function, line 174) `def handle_report(state, b64_payload)`
  - `handle_bof` (function, line 230) `def handle_bof(state, name)`
  - `handle_request` (function, line 240) `def handle_request(state, selector)`
  - `_is_http_line` (function, line 282) `def _is_http_line(line)`
  - `_is_http_request` (function, line 288) `def _is_http_request(raw)`
  - `_read_request` (function, line 299) `def _read_request(conn)`
  - `_http_response` (function, line 343) `def _http_response(body, status)`
  - `serve_client` (function, line 355) `def serve_client(state, conn, addr)`
  - `serve` (function, line 380) `def serve(cfg, state)`
  - `command_injector` (function, line 404) `def command_injector(state)`
  - `main` (function, line 427) `def main()`
  - `__init__` (method, line 140) `def __init__(self, cfg)`
- Depends on: `include/config_py.py`
- Imported by: `tests/test_c2_server.py`
