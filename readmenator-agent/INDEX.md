# Index

| File | Purpose | Subsystem | Symbols |
|------|---------|-----------|---------|
| `aes.c` | aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) | root | 43 |
| `aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | root | 21 |
| `app.py` | app.py  Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]c | root | 0 |
| `beacon.h` | beacon_api.h   Tipos de callback  Estructura para parsing de datos (opcional, pa | root | 13 |
| `beacon3.c` | - | root | 28 |
| `beacon5.c` | - | root | 44 |
| `beacon6.c` | - | root | 32 |
| `beacon_p2p.c` | - | root | 49 |
| `beacons/v1/beacon.c` | - | v1 | 4 |
| `beacons/v1/gopher_beacon.c` | - | v1 | 28 |
| `beacons/v2/beacon.c` | - | misc | 11 |
| `beacons/v3/beacon.c` | - | misc | 7 |
| `bof.c` | bof.c | root | 1 |
| `bof/cat/bof.c` | - | cat | 1 |
| `bof/cat/cat.c` | readfile.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat | cat | 12 |
| `bof/include/beacon_api.h` | - | include | 14 |
| `bof/include/syscalls.h` | - | include | 38 |
| `bof/is_sudo/bof.c` | - | is_sudo | 2 |
| `bof/is_sudo/is_sudo.c` | is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_s | is_sudo | 17 |
| `bof/suid_enum/bof.c` | - | misc | 15 |
| `bof/userenum/bof.c` | - | userenum | 2 |
| `bof/userenum/userenum.c` | is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 user | userenum | 13 |
| `bof/whoami/bof.c` | - | whoami | 1 |
| `bof/whoami/whoami.c` | whoami.c — LazyOwn RedTeam BOF (Linux/x64)  Tipos | whoami | 14 |
| `c2/server.py` | Black Sand Beacon C2 Server  Gopher-style command and control server for Black S | misc | 14 |
| `cJSON.c` | - | root | 125 |
| `cJSON.h` | - | root | 37 |
| `gopher_beacon.c` | - | root | 28 |
| `gopher_c2.py` | - | root | 5 |
| `include/aes.c` | aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) | - | 43 |
| `include/aes.h` | #define the macros below to 1/0 to enable/disable the mode of operation. | - | 21 |
| `include/aes_cfb.c` | - | - | 2 |
| `include/aes_cfb.h` | - | - | 3 |
| `include/beacon.h` | beacon_api.h   Tipos de callback  Estructura para parsing de datos (opcional, pa | - | 13 |
| `include/beacon_common.c` | - | - | 27 |
| `include/beacon_common.h` | - | - | 57 |
| `include/cJSON.c` | - | - | 125 |
| `include/cJSON.h` | - | - | 37 |
| `include/config.c` | - | - | 20 |
| `include/config.h` | - | - | 21 |
| `include/config_py.py` | config_py.py - Python loader for BSB JSON config files.  Mirrors the C side in i | - | 2 |
| `install.sh` | install.sh - Install build deps and build everything.  Idempotent: safe to run o | root | 0 |
| `issudo.c` | is_sudo.c — LazyOwn RedTeam BOF (Linux/x64)  Tipos | root | 17 |
| `tests/config_harness.c` | - | tests | 1 |
| `tests/crypto_harness.c` | - | tests | 2 |
| `tests/test_beacon_build.py` | Sanity build test: compile the v1 beacon against include/config.c and verify the | tests | 7 |
| `tests/test_bof_compile.py` | Verify every BOF compiles with the BOF build flags.  A BOF is a position-indepen | tests | 7 |
| `tests/test_c2_http_e2e.py` | End-to-end test: a real HTTP/1.1 client talks to a real TCP socket bound by serv | tests | 9 |
| `tests/test_c2_server.py` | Unit tests for the C2 server dispatcher.  We import the dispatcher from c2/serve | tests | 11 |
| `tests/test_config.py` | Unit tests for the BSB JSON config loader.  We exercise the loader via a small C | tests | 9 |
| `tests/test_crypto.py` | Roundtrip tests for AES-256-CFB.  Verifies the C implementation in include/aes_c | tests | 8 |
| `tests/test_install_deploy.py` | End-to-end test for the "make beacon && ./build/beacon" workflow.  After `make c | tests | 8 |
