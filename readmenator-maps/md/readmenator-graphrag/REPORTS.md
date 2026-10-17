# GraphRAG Community Reports

Entities: 1237 | Relationships: 2231 | Communities: 8 | Themes: 5 | Text units: 1098

Query with `readmenator . ask "<question>"` (local: BM25 + Personalized PageRank; global: map-reduce over these reports) or the MCP tool `readmenator.graphrag`.

## Project overview (`root`, root, rating 7.0)

52 files in 8 communities and 5 themes. Highest-impact communities: include: cJSON (7.0), unassigned files (6.9), root (6.7). God nodes: cJSON.h, aes.h, include/cJSON.c, include/beacon_common.h, beacon.h.

- [include: cJSON] rating 7.0: `include/beacon_common.h` ranks 1 by PageRank, 4 importers, 57 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- [unassigned files] rating 6.9: `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- [root] rating 6.7: `aes.h` ranks 1 by PageRank, 6 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [bof/include] rating 5.2: `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- [include: config] rating 3.7: `include/config.h` ranks 1 by PageRank, 3 importers, 21 symbols: bsb_config_load: Load config from path.
- [include: server] rating 2.5: `include/config_py.py` ranks 1 by PageRank, 1 importers, 2 symbols: Python loader for BSB JSON config files.
- [include: aes] rating 2.3: `include/aes.h` ranks 1 by PageRank, 3 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [include: aes_cfb] rating 1.3: `include/aes_cfb.h` ranks 1 by PageRank, 1 importers, 3 symbols.
- Key entities: file:include/cJSON.c, file:cJSON.c, file:bof/is_sudo/is_sudo.c, file:issudo.c, file:beacon_p2p.c, file:beacon5.c
- Children: t0, t1, t2, t3, t4
- Root rating = highest community rating.

## include: cJSON + root +2 (`t0`, theme, rating 7.0)

Theme of 4 communities and 25 files: include: cJSON (9 files, rating 7.0); root (10 files, rating 6.7); include: config (3 files, rating 3.7); include: aes (3 files, rating 2.3).

- [include: cJSON] `include/beacon_common.h` ranks 1 by PageRank, 4 importers, 57 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- [include: cJSON] `cJSON.h` ranks 2 by PageRank, 6 importers, 37 symbols: cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1...
- [root] `aes.h` ranks 1 by PageRank, 6 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [root] `beacon.h` ranks 2 by PageRank, 6 importers, 13 symbols: Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)
- [include: config] `include/config.h` ranks 1 by PageRank, 3 importers, 21 symbols: bsb_config_load: Load config from path.
- [include: config] `include/config.c` ranks 2 by PageRank, 0 importers, 20 symbols: slurp: declared in the schema.
- [include: aes] `include/aes.h` ranks 1 by PageRank, 3 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [include: aes] `include/aes.c` ranks 2 by PageRank, 0 importers, 43 symbols: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Key entities: file:include/cJSON.c, file:cJSON.c, file:beacon_p2p.c, file:beacon5.c, file:include/config.c, file:include/config.h, file:include/aes.c, file:include/aes.h
- Children: c1, c0, c5, c4
- Theme rating = highest child community rating.

## unassigned files (`t1`, theme, rating 6.9)

Theme of 1 communities and 15 files: unassigned files (15 files, rating 6.9).

- [unassigned files] `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- [unassigned files] `bof/cat/cat.c` ranks 2 by PageRank, 0 importers, 12 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos
- Key entities: file:bof/is_sudo/is_sudo.c, file:issudo.c
- Children: c7
- Theme rating = highest child community rating.

## bof/include (`t2`, theme, rating 5.2)

Theme of 1 communities and 7 files: bof/include (7 files, rating 5.2).

- [bof/include] `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- [bof/include] `bof/include/syscalls.h` ranks 2 by PageRank, 5 importers, 38 symbols: bsf_strlen: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx"...
- Key entities: file:bof/include/syscalls.h, file:bof/include/beacon_api.h
- Children: c2
- Theme rating = highest child community rating.

## include: server (`t3`, theme, rating 2.5)

Theme of 1 communities and 3 files: include: server (3 files, rating 2.5).

- [include: server] `include/config_py.py` ranks 1 by PageRank, 1 importers, 2 symbols: Python loader for BSB JSON config files.
- [include: server] `c2/server.py` ranks 2 by PageRank, 1 importers, 19 symbols: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Key entities: file:c2/server.py, file:tests/test_c2_server.py
- Children: c3
- Theme rating = highest child community rating.

## include: aes_cfb (`t4`, theme, rating 1.3)

Theme of 1 communities and 2 files: include: aes_cfb (2 files, rating 1.3).

- [include: aes_cfb] `include/aes_cfb.h` ranks 1 by PageRank, 1 importers, 3 symbols.
- [include: aes_cfb] `tests/crypto_harness.c` ranks 2 by PageRank, 0 importers, 2 symbols.
- Key entities: file:include/aes_cfb.h, file:tests/crypto_harness.c
- Children: c6
- Theme rating = highest child community rating.

## include: cJSON (`c1`, community, rating 7.0)

9 files under include (c 6, h 3), mostly utility. Core file include/beacon_common.h (PageRank 0.0496, imported by 4 files): http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory. Key abstractions: http_response_t, Trampoline, SymbolResolver, TrampolineCache, bsb_backoff_t, BEACON_COMMON_H. Depends on include: aes (1), include: config (1). Used by root (5).

- `include/beacon_common.h` ranks 1 by PageRank, 4 importers, 57 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- `cJSON.h` ranks 2 by PageRank, 6 importers, 37 symbols: cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1...
- `include/cJSON.h` ranks 3 by PageRank, 2 importers, 37 symbols: cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1...
- Hotspot `cJSON.c`: 125 symbols, 10 connections (score 0.58).
- Hotspot `include/cJSON.c`: 125 symbols, 10 connections (score 0.58).
- Dataflow: 9 INFERRED issues (first: UNCHECKED_ALLOC in report_result).
- Key entities: file:include/cJSON.c, file:cJSON.c, file:include/beacon_common.h, file:include/beacon_common.c, file:cJSON.h, file:include/cJSON.h, file:beacons/v2/beacon.c, file:beacons/v3/beacon.c
- Rating 7.0/10 = 7 x PageRank share 1.00 + 3 x risk 0.00. Internal imports: 7.

## unassigned files (`c7`, community, rating 6.9)

15 files under tests (py 8, c 5, h 1, sh 1), mostly utility. Core file app.py (PageRank 0.0129, imported by 0 files): Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción: Key abstractions: NULL, CALLBACK_OUTPUT, size_t, ssize_t, BeaconPrintf, BeaconOutput.

- `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- `bof/cat/cat.c` ranks 2 by PageRank, 0 importers, 12 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos
- `bof/is_sudo/is_sudo.c` ranks 3 by PageRank, 0 importers, 17 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o  Tipos
- Hotspot `tests/test_c2_http_e2e.py`: 9 symbols, 24 connections (score 0.45).
- Hotspot `gopher_c2.py`: 5 symbols, 10 connections (score 0.19).
- Taint: 5 paths reach this group via subprocess.
- Dataflow: 1 INFERRED issues (first: UNCHECKED_ALLOC in main).
- Key entities: file:bof/is_sudo/is_sudo.c, file:issudo.c, file:bof/whoami/whoami.c, file:include/beacon.h, file:tests/test_c2_http_e2e.py, file:bof/userenum/userenum.c, file:bof/cat/cat.c, file:tests/test_config.py
- Rating 6.9/10 = 7 x PageRank share 0.98 + 3 x risk 0.00. Internal imports: 0.

## root (`c0`, community, rating 6.7)

10 files under root (c 8, h 2), mostly utility. Core file aes.h (PageRank 0.0423, imported by 6 files): #define the macros below to 1/0 to enable/disable the mode of operation. Key abstractions: AES_ctx, CBC, ECB, CTR, AES256, AES_BLOCKLEN. Depends on include: cJSON (5).

- `aes.h` ranks 1 by PageRank, 6 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- `beacon.h` ranks 2 by PageRank, 6 importers, 13 symbols: Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)
- `aes.c` ranks 3 by PageRank, 0 importers, 43 symbols: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Hotspot `beacon5.c`: 44 symbols, 34 connections (score 0.74).
- Hotspot `beacon_p2p.c`: 49 symbols, 33 connections (score 0.74).
- Dataflow: 37 INFERRED issues (first: UNCHECKED_ALLOC in base64_encode).
- Surprising bridge: bof.c <-> config.c (7 hops across communities).
- Key entities: file:beacon_p2p.c, file:beacon5.c, file:beacon6.c, file:aes.c, file:beacon3.c, file:gopher_beacon.c, file:beacons/v1/gopher_beacon.c, file:aes.h
- Rating 6.7/10 = 7 x PageRank share 0.95 + 3 x risk 0.00. Internal imports: 12.

## bof/include (`c2`, community, rating 5.2)

7 files under bof/include (c 5, h 2), mostly utility. Core file bof/include/beacon_api.h (PageRank 0.0405, imported by 5 files): datap: Argument parser. Key abstractions: datap, go, BSB_BOF_BEACON_API_H, CALLBACK_OUTPUT, CALLBACK_ERROR, CALLBACK_OUTPUT_OEM.

- `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- `bof/include/syscalls.h` ranks 2 by PageRank, 5 importers, 38 symbols: bsf_strlen: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx"...
- `bof/cat/bof.c` ranks 3 by PageRank, 0 importers, 1 symbols.
- Hotspot `bof/include/syscalls.h`: 38 symbols, 6 connections (score 0.23).
- Hotspot `bof/include/beacon_api.h`: 14 symbols, 8 connections (score 0.19).
- Key entities: file:bof/include/syscalls.h, file:bof/include/beacon_api.h, file:bof/suid_enum/bof.c, file:bof/is_sudo/bof.c, file:bof/userenum/bof.c, file:bof/cat/bof.c, file:bof/whoami/bof.c, sym:bof/include/syscalls.h::AT_FDCWD@47
- Rating 5.2/10 = 7 x PageRank share 0.74 + 3 x risk 0.00. Internal imports: 10.

## include: config (`c5`, community, rating 3.7)

3 files under include (c 2, h 1), mostly infrastructure. Core file include/config.h (PageRank 0.0771, imported by 3 files): bsb_config_load: Load config from path. Key abstractions: bsb_c2_t, bsb_crypto_t, bsb_timing_t, bsb_network_t, bsb_bof_t, bsb_backoff_config_t. Used by include: cJSON (1).

- `include/config.h` ranks 1 by PageRank, 3 importers, 21 symbols: bsb_config_load: Load config from path.
- `include/config.c` ranks 2 by PageRank, 0 importers, 20 symbols: slurp: declared in the schema.
- `tests/config_harness.c` ranks 3 by PageRank, 0 importers, 1 symbols.
- Hotspot `include/config.c`: 20 symbols, 9 connections (score 0.22).
- Hotspot `include/config.h`: 21 symbols, 5 connections (score 0.16).
- Surprising bridge: bof.c <-> config.c (7 hops across communities).
- Key entities: file:include/config.c, file:include/config.h, file:tests/config_harness.c, sym:include/config.h::BSB_AES_KEY_BYTES@25, sym:include/config.h::BSB_AES_KEY_HEX_LEN@24, sym:include/config.h::BSB_CONFIG_H@14, sym:include/config.h::BSB_CONFIG_PATH_DEFAULT@19, sym:include/config.h::BSB_CONFIG_PATH_ENV@20
- Rating 3.7/10 = 7 x PageRank share 0.52 + 3 x risk 0.00. Internal imports: 2.

## include: server (`c3`, community, rating 2.5)

3 files under include (py 3), mostly infrastructure. Core file include/config_py.py (PageRank 0.0333, imported by 1 files): Python loader for BSB JSON config files. Key abstractions: load_config, C2State, load_runtime_config, compute_hmac, verify_hmac, encrypt_data.

- `include/config_py.py` ranks 1 by PageRank, 1 importers, 2 symbols: Python loader for BSB JSON config files.
- `c2/server.py` ranks 2 by PageRank, 1 importers, 19 symbols: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- `tests/test_c2_server.py` ranks 3 by PageRank, 0 importers, 11 symbols: Unit tests for the C2 server dispatcher.
- Hotspot `c2/server.py`: 19 symbols, 20 connections (score 0.41).
- Hotspot `tests/test_c2_server.py`: 11 symbols, 10 connections (score 0.21).
- Dataflow: 1 INFERRED issues (first: UNCHECKED_ALLOC in serve).
- Key entities: file:c2/server.py, file:tests/test_c2_server.py, file:include/config_py.py, sym:c2/server.py::handle_request@240, sym:tests/test_c2_server.py::make_state@39, sym:c2/server.py::C2State@137, sym:c2/server.py::serve_client@355, sym:c2/server.py::main@427
- Rating 2.5/10 = 7 x PageRank share 0.36 + 3 x risk 0.00. Internal imports: 2.

## include: aes (`c4`, community, rating 2.3)

3 files under include (c 2, h 1), mostly utility. Core file include/aes.h (PageRank 0.0386, imported by 3 files): #define the macros below to 1/0 to enable/disable the mode of operation. Key abstractions: AES_ctx, CBC, ECB, CTR, AES256, AES_BLOCKLEN. Used by include: cJSON (1).

- `include/aes.h` ranks 1 by PageRank, 3 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- `include/aes.c` ranks 2 by PageRank, 0 importers, 43 symbols: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- `include/aes_cfb.c` ranks 3 by PageRank, 0 importers, 2 symbols.
- Hotspot `include/aes.c`: 43 symbols, 3 connections (score 0.19).
- Hotspot `include/aes.h`: 21 symbols, 5 connections (score 0.16).
- Dataflow: 2 INFERRED issues (first: UNCHECKED_ALLOC in aes256_cfb_encrypt).
- Key entities: file:include/aes.c, file:include/aes.h, file:include/aes_cfb.c, sym:include/aes.c::AES_CBC_decrypt_buffer@536, sym:include/aes.c::AES_CBC_encrypt_buffer@521, sym:include/aes.c::AES_CTR_xcrypt_buffer@558, sym:include/aes.c::AES_ECB_decrypt@496, sym:include/aes.c::AES_ECB_encrypt@490
- Rating 2.3/10 = 7 x PageRank share 0.33 + 3 x risk 0.00. Internal imports: 2.

## include: aes_cfb (`c6`, community, rating 1.3)

2 files under include (c 1, h 1), mostly testing. Core file include/aes_cfb.h (PageRank 0.0240, imported by 1 files). Key abstractions: BSB_AES_CFB_H, aes256_cfb_encrypt, aes256_cfb_decrypt, hex_to_bytes, main.

- `include/aes_cfb.h` ranks 1 by PageRank, 1 importers, 3 symbols.
- `tests/crypto_harness.c` ranks 2 by PageRank, 0 importers, 2 symbols.
- Hotspot `tests/crypto_harness.c`: 2 symbols, 5 connections (score 0.09).
- Hotspot `include/aes_cfb.h`: 3 symbols, 2 connections (score 0.04).
- Key entities: file:include/aes_cfb.h, file:tests/crypto_harness.c, sym:include/aes_cfb.h::BSB_AES_CFB_H@5, sym:include/aes_cfb.h::aes256_cfb_decrypt@11, sym:include/aes_cfb.h::aes256_cfb_encrypt@9, sym:tests/crypto_harness.c::hex_to_bytes@12, sym:tests/crypto_harness.c::main@23
- Rating 1.3/10 = 7 x PageRank share 0.19 + 3 x risk 0.00. Internal imports: 1.
