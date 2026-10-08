# Index

| File | Purpose | Subsystem | Symbols | Used by |
|------|---------|-----------|---------|---------|
| `aes.c` | tiny-AES-c (https://github.com/kokke/tiny-AES-c) | root | 43 | 0 |
| `aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | root | 21 | 6 |
| `app.py` | Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación... | root | 0 | 0 |
| `beacon.h` | Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos) | root | 13 | 6 |
| `beacon3.c` | MemoryStruct: === ESTRUCTURAS === | root | 28 | 0 |
| `beacon5.c` | MemoryStruct: === ESTRUCTURAS === | root | 44 | 0 |
| `beacon6.c` | MemoryStruct: === ESTRUCTURAS === | root | 32 | 0 |
| `beacon_p2p.c` | - | root | 49 | 0 |
| `beacons/v1/beacon.c` | - | v1 | 4 | 0 |
| `beacons/v1/gopher_beacon.c` | MemoryStruct: === ESTRUCTURAS === | v1 | 28 | 0 |
| `beacons/v2/beacon.c` | - | misc | 11 | 0 |
| `beacons/v3/beacon.c` | - | misc | 7 | 0 |
| `bof.c` | - | root | 1 | 0 |
| `bof/cat/bof.c` | - | cat | 1 | 0 |
| `bof/cat/cat.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos | cat | 12 | 0 |
| `bof/include/beacon_api.h` | datap: Argument parser. | bof_include | 14 | 5 |
| `bof/include/syscalls.h` | bsf_strlen: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret... | bof_include | 38 | 5 |
| `bof/is_sudo/bof.c` | - | is_sudo | 2 | 0 |
| `bof/is_sudo/is_sudo.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o  Tipos | is_sudo | 17 | 0 |
| `bof/suid_enum/bof.c` | linux_stat: #include "beacon_api.h" #include "syscalls.h" /* getdents64 syscall number (x86_64)... | misc | 15 | 0 |
| `bof/userenum/bof.c` | - | userenum | 2 | 0 |
| `bof/userenum/userenum.c` | — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o... | userenum | 13 | 0 |
| `bof/whoami/bof.c` | - | whoami | 1 | 0 |
| `bof/whoami/whoami.c` | — LazyOwn RedTeam BOF (Linux/x64)  Tipos | whoami | 14 | 0 |
| `c2/server.py` | Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. | misc | 14 | 1 |
| `cJSON.c` | case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible... | root | 125 | 0 |
| `cJSON.h` | cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1)... | root | 37 | 6 |
| `gopher_beacon.c` | MemoryStruct: === ESTRUCTURAS === | root | 28 | 0 |
| `gopher_c2.py` | - | root | 5 | 0 |
| `include/aes.c` | tiny-AES-c (https://github.com/kokke/tiny-AES-c) | include | 43 | 0 |
| `include/aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | include | 21 | 3 |
| `include/aes_cfb.c` | - | include | 2 | 0 |
| `include/aes_cfb.h` | - | include | 3 | 1 |
| `include/beacon.h` | Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos) | include | 13 | 0 |
| `include/beacon_common.c` | MemoryStruct: if (g_cache_count >= g_cache_capacity) { size_t new_cap = g_cache_capacity ?... | include | 27 | 0 |
| `include/beacon_common.h` | http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead... | include | 57 | 4 |
| `include/cJSON.c` | case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible... | include | 125 | 0 |
| `include/cJSON.h` | cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1)... | include | 37 | 2 |
| `include/config.c` | slurp: declared in the schema. | include | 20 | 0 |
| `include/config.h` | bsb_config_load: Load config from path. | include | 21 | 3 |
| `include/config_py.py` | Python loader for BSB JSON config files. | include | 2 | 1 |
| `install.sh` | Install build deps and build everything. | root | 0 | 0 |
| `issudo.c` | — LazyOwn RedTeam BOF (Linux/x64)  Tipos | root | 17 | 0 |
| `tests/config_harness.c` | - | tests | 1 | 0 |
| `tests/crypto_harness.c` | - | tests | 2 | 0 |
| `tests/test_beacon_build.py` | Sanity build test: compile the v1 beacon against include/config.c and verify the binary links... | tests | 7 | 0 |
| `tests/test_bof_compile.py` | Verify every BOF compiles with the BOF build flags. | tests | 7 | 0 |
| `tests/test_c2_http_e2e.py` | End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by server.serve(), and... | tests | 9 | 0 |
| `tests/test_c2_server.py` | Unit tests for the C2 server dispatcher. | tests | 11 | 0 |
| `tests/test_config.py` | Unit tests for the BSB JSON config loader. | tests | 9 | 0 |
| `tests/test_crypto.py` | Roundtrip tests for AES-256-CFB. | tests | 8 | 0 |
| `tests/test_install_deploy.py` | End-to-end test for the "make beacon && ./build/beacon" workflow. | tests | 8 | 0 |
