# Subsystem: misc

## beacons/v2/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `peer_t` (struct, line 33)
  - `mesh_msg_t` (struct, line 40)
  - `report_result` (function, line 65) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
  - `execute_command` (function, line 138) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 187) `int main(void)`
  - `gethostname` (function, line 70) `gethostname(hostname, sizeof(hostname) - 1);`
  - `cJSON_AddStringToObject` (function, line 78) `cJSON_AddStringToObject(root, "output", output);`
  - `cJSON_AddNumberToObject` (function, line 81) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
  - `cJSON_AddNullToObject` (function, line 86) `cJSON_AddNullToObject(root, "result_portscan");`
  - `cJSON_Delete` (function, line 90) `cJSON_Delete(root);`
  - `free` (function, line 93) `free(ips);`
  - `RAND_bytes` (function, line 99) `RAND_bytes(iv_out, 16);`
  - `memcpy` (function, line 109) `memcpy(full_enc, iv_out, 16);`
  - `snprintf` (function, line 115) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
  - `srand` (function, line 189) `srand(time(NULL));`
  - `fprintf` (function, line 194) `fprintf(stderr, "config error: %s\n", cfg_err);`
  - `pthread_mutex_init` (function, line 203) `pthread_mutex_init(&g_mesh.peers_mutex, NULL);`
  - `bsb_backoff_init` (function, line 209) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
  - `sleep` (function, line 219) `sleep(bsb_backoff_next(&backoff));`
  - `bsb_backoff_reset` (function, line 246) `bsb_backoff_reset(&backoff);`
  - `bsb_output_cleanup` (function, line 257) `bsb_output_cleanup();`
  - `pthread_mutex_destroy` (function, line 259) `pthread_mutex_destroy(&g_mesh.peers_mutex);`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 26) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 28) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 29) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 30) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 31) `#define MESH_MSG_SIZE`
- Depends on: `include/beacon_common.h`

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
  - `sleep` (function, line 49) `sleep(seconds);`
  - `gethostname` (function, line 56) `gethostname(hostname, sizeof(hostname) - 1);`
  - `cJSON_AddStringToObject` (function, line 64) `cJSON_AddStringToObject(root, "output", output);`
  - `cJSON_AddNumberToObject` (function, line 67) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
  - `cJSON_AddNullToObject` (function, line 72) `cJSON_AddNullToObject(root, "result_portscan");`
  - `cJSON_Delete` (function, line 76) `cJSON_Delete(root);`
  - `free` (function, line 79) `free(ips);`
  - `RAND_bytes` (function, line 85) `RAND_bytes(iv_out, 16);`
  - `memcpy` (function, line 95) `memcpy(full_enc, iv_out, 16);`
  - `snprintf` (function, line 101) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
  - `srand` (function, line 175) `srand(time(NULL));`
  - `fprintf` (function, line 180) `fprintf(stderr, "config error: %s\n", cfg_err);`
  - `bsb_backoff_init` (function, line 191) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
  - `bsb_backoff_reset` (function, line 230) `bsb_backoff_reset(&backoff);`
  - `bsb_output_cleanup` (function, line 241) `bsb_output_cleanup();`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

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
  - `BeaconOutput` (function, line 78) `BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);`
  - `syscall1` (function, line 244) `syscall1(SYS_close, fd);`
  - `BeaconPrintf` (function, line 259) `BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] scanning %s\n", root);`
  - `SYS_getdents64` (macro, line 26) `#define SYS_getdents64`
  - `SYS_lstat` (macro, line 27) `#define SYS_lstat`
  - `DT_UNKNOWN` (macro, line 30) `#define DT_UNKNOWN`
  - `DT_DIR` (macro, line 31) `#define DT_DIR`
  - `DT_LNK` (macro, line 32) `#define DT_LNK`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

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
