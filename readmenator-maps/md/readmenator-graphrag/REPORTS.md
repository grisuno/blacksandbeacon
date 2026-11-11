# GraphRAG Community Reports

Entities: 1816 | Relationships: 4040 | Communities: 26 | Themes: 24 | Text units: 1620

Query with `readmenator . ask "<question>"` (local: BM25 + Personalized PageRank; global: map-reduce over these reports) or the MCP tool `readmenator.graphrag`.

## Project overview (`root`, root, rating 7.0)

175 files in 26 communities and 24 themes. Highest-impact communities: unassigned files (7.0), root (3.6), c2 (3.4). God nodes: cJSON.h, aes.h, c2/server.py, include/beacon_common.h, include/cJSON.c.

- [unassigned files] rating 7.0: `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- [root] rating 3.6: `include/beacon_common.h` ranks 1 by PageRank, 5 importers, 58 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- [c2] rating 3.4: `include/config_py.py` ranks 1 by PageRank, 8 importers, 3 symbols: Python loader for BSB JSON config files.
- [include: config] rating 1.6: `include/config.h` ranks 1 by PageRank, 6 importers, 21 symbols: bsb_config_load: Load config from path.
- [bof/include] rating 1.3: `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- [include: aes] rating 1.1: `include/aes_cfb.h` ranks 1 by PageRank, 3 importers, 3 symbols.
- [mutants/src: bof_streaming_(large_outputs)] rating 0.5: `include/bof_streaming_(large_outputs).h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: c2_rest_api] rating 0.5: `include/c2_rest_api.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- Key entities: file:bof/is_sudo/is_sudo.c, file:issudo.c, file:cJSON.c, file:include/cJSON.c, file:tests/test_replay_protection.py, file:c2/server.py
- Children: t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23
- Root rating = highest community rating.

## unassigned files (`t0`, theme, rating 7.0)

Theme of 1 communities and 62 files: unassigned files (62 files, rating 7.0).

- [unassigned files] `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- [unassigned files] `bof/cat/cat.c` ranks 2 by PageRank, 0 importers, 12 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos
- Key entities: file:bof/is_sudo/is_sudo.c, file:issudo.c
- Children: c25
- Theme rating = highest child community rating.

## root + include: config +1 (`t1`, theme, rating 3.6)

Theme of 3 communities and 32 files: root (20 files, rating 3.6); include: config (6 files, rating 1.6); include: aes (6 files, rating 1.1).

- [root] `include/beacon_common.h` ranks 1 by PageRank, 5 importers, 58 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- [root] `aes.h` ranks 2 by PageRank, 6 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [include: config] `include/config.h` ranks 1 by PageRank, 6 importers, 21 symbols: bsb_config_load: Load config from path.
- [include: config] `include/config.c` ranks 2 by PageRank, 0 importers, 28 symbols: slurp: declared in the schema.
- [include: aes] `include/aes_cfb.h` ranks 1 by PageRank, 3 importers, 3 symbols.
- [include: aes] `include/aes.h` ranks 2 by PageRank, 3 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- Key entities: file:cJSON.c, file:include/cJSON.c, file:include/config.c, file:include/config.h, file:include/aes.c, file:include/aes.h
- Children: c0, c4, c3
- Theme rating = highest child community rating.

## c2 (`t2`, theme, rating 3.4)

Theme of 1 communities and 15 files: c2 (15 files, rating 3.4).

- [c2] `include/config_py.py` ranks 1 by PageRank, 8 importers, 3 symbols: Python loader for BSB JSON config files.
- [c2] `c2/server.py` ranks 2 by PageRank, 8 importers, 21 symbols: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Key entities: file:tests/test_replay_protection.py, file:c2/server.py
- Children: c1
- Theme rating = highest child community rating.

## bof/include (`t3`, theme, rating 1.3)

Theme of 1 communities and 7 files: bof/include (7 files, rating 1.3).

- [bof/include] `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- [bof/include] `bof/include/syscalls.h` ranks 2 by PageRank, 5 importers, 38 symbols: bsf_strlen: } static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx"...
- Key entities: file:bof/include/syscalls.h, file:bof/include/beacon_api.h
- Children: c2
- Theme rating = highest child community rating.

## mutants/src: iv_generation_with_entropy_verification (`t10`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: iv_generation_with_entropy_verification (3 files, rating 0.5).

- [mutants/src: iv_generation_with_entropy_verification] `include/iv_generation_with_entropy_verification.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: iv_generation_with_entropy_verification] `mutants/src/iv_generation_with_entropy_verification.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: IV Generation with Entropy Verification
- Key entities: file:include/iv_generation_with_entropy_verification.h, file:mutants/src/iv_generation_with_entropy_verification.c
- Children: c16
- Theme rating = highest child community rating.

## mutants/src: mutation_testing_integration (`t11`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: mutation_testing_integration (3 files, rating 0.5).

- [mutants/src: mutation_testing_integration] `include/mutation_testing_integration.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: mutation_testing_integration] `mutants/src/mutation_testing_integration.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Mutation Testing Integration
- Key entities: file:include/mutation_testing_integration.h, file:mutants/src/mutation_testing_integration.c
- Children: c17
- Theme rating = highest child community rating.

## mutants/src: pre-commit_+_ci_hardening (`t12`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: pre-commit_+_ci_hardening (3 files, rating 0.5).

- [mutants/src: pre-commit_+_ci_hardening] `include/pre-commit_+_ci_hardening.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- [mutants/src: pre-commit_+_ci_hardening] `mutants/src/pre-commit_+_ci_hardening.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Pre-commit + CI Hardening
- Key entities: file:include/pre-commit_+_ci_hardening.h, file:mutants/src/pre-commit_+_ci_hardening.c
- Children: c18
- Theme rating = highest child community rating.

## mutants/src: replay_protection (`t13`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: replay_protection (3 files, rating 0.5).

- [mutants/src: replay_protection] `include/replay_protection.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: replay_protection] `mutants/src/replay_protection.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Replay Protection
- Key entities: file:include/replay_protection.h, file:mutants/src/replay_protection.c
- Children: c19
- Theme rating = highest child community rating.

## mutants/src: socks5___http_proxy_support (`t14`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: socks5___http_proxy_support (3 files, rating 0.5).

- [mutants/src: socks5___http_proxy_support] `include/socks5___http_proxy_support.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: socks5___http_proxy_support] `mutants/src/socks5___http_proxy_support.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support
- Key entities: file:include/socks5___http_proxy_support.h, file:mutants/src/socks5___http_proxy_support.c
- Children: c20
- Theme rating = highest child community rating.

## mutants/src: structured_jsonl_logging (`t15`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: structured_jsonl_logging (3 files, rating 0.5).

- [mutants/src: structured_jsonl_logging] `include/structured_jsonl_logging.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: structured_jsonl_logging] `mutants/src/structured_jsonl_logging.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Structured JSONL Logging
- Key entities: file:include/structured_jsonl_logging.h, file:mutants/src/structured_jsonl_logging.c
- Children: c21
- Theme rating = highest child community rating.

## mutants/src: tls_client_certificate_authentication (`t16`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: tls_client_certificate_authentication (3 files, rating 0.5).

- [mutants/src: tls_client_certificate_authentication] `include/tls_client_certificate_authentication.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: tls_client_certificate_authentication] `mutants/src/tls_client_certificate_authentication.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: TLS Client Certificate Authentication
- Key entities: file:include/tls_client_certificate_authentication.h, file:mutants/src/tls_client_certificate_authentication.c
- Children: c22
- Theme rating = highest child community rating.

## mutants/src: unified_config_schema (`t17`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: unified_config_schema (3 files, rating 0.5).

- [mutants/src: unified_config_schema] `include/unified_config_schema.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: unified_config_schema] `mutants/src/unified_config_schema.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Unified Config Schema
- Key entities: file:include/unified_config_schema.h, file:mutants/src/unified_config_schema.c
- Children: c23
- Theme rating = highest child community rating.

## mutants/src: async_i_o_for_beacon (`t18`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: async_i_o_for_beacon (3 files, rating 0.5).

- [mutants/src: async_i_o_for_beacon] `include/async_i_o_for_beacon.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: async_i_o_for_beacon] `mutants/src/async_i_o_for_beacon.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Async I/O for Beacon
- Key entities: file:include/async_i_o_for_beacon.h, file:mutants/src/async_i_o_for_beacon.c
- Children: c5
- Theme rating = highest child community rating.

## mutants/src: beacon_common.c_extraction (`t19`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: beacon_common.c_extraction (3 files, rating 0.5).

- [mutants/src: beacon_common.c_extraction] `include/beacon_common.c_extraction.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- [mutants/src: beacon_common.c_extraction] `mutants/src/beacon_common.c_extraction.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: beacon_common.c Extraction
- Key entities: file:mutants/src/beacon_common.c_extraction.c, file:include/beacon_common.c_extraction.h
- Children: c6
- Theme rating = highest child community rating.

## mutants/src: beacon_heartbeat___health_endpoint (`t20`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: beacon_heartbeat___health_endpoint (3 files, rating 0.5).

- [mutants/src: beacon_heartbeat___health_endpoint] `include/beacon_heartbeat___health_endpoint.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: beacon_heartbeat___health_endpoint] `mutants/src/beacon_heartbeat___health_endpoint.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint
- Key entities: file:include/beacon_heartbeat___health_endpoint.h, file:mutants/src/beacon_heartbeat___health_endpoint.c
- Children: c7
- Theme rating = highest child community rating.

## mutants/src: bof_api_versioning (`t21`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: bof_api_versioning (3 files, rating 0.5).

- [mutants/src: bof_api_versioning] `include/bof_api_versioning.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: bof_api_versioning] `mutants/src/bof_api_versioning.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF API Versioning
- Key entities: file:include/bof_api_versioning.h, file:mutants/src/bof_api_versioning.c
- Children: c8
- Theme rating = highest child community rating.

## mutants/src: bof_path_traversal_hardening (`t22`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: bof_path_traversal_hardening (3 files, rating 0.5).

- [mutants/src: bof_path_traversal_hardening] `include/bof_path_traversal_hardening.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: bof_path_traversal_hardening] `mutants/src/bof_path_traversal_hardening.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Path Traversal Hardening
- Key entities: file:include/bof_path_traversal_hardening.h, file:mutants/src/bof_path_traversal_hardening.c
- Children: c9
- Theme rating = highest child community rating.

## mutants/src: bof_streaming_(large_outputs) (`t4`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: bof_streaming_(large_outputs) (3 files, rating 0.5).

- [mutants/src: bof_streaming_(large_outputs)] `include/bof_streaming_(large_outputs).h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: bof_streaming_(large_outputs)] `mutants/src/bof_streaming_(large_outputs).c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Streaming (Large Outputs)
- Key entities: file:include/bof_streaming_(large_outputs).h, file:mutants/src/bof_streaming_(large_outputs).c
- Children: c10
- Theme rating = highest child community rating.

## mutants/src: c2_rest_api (`t5`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: c2_rest_api (3 files, rating 0.5).

- [mutants/src: c2_rest_api] `include/c2_rest_api.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: c2_rest_api] `mutants/src/c2_rest_api.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: C2 REST API
- Key entities: file:include/c2_rest_api.h, file:mutants/src/c2_rest_api.c
- Children: c11
- Theme rating = highest child community rating.

## mutants/src: certificate_pinning___tofu (`t6`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: certificate_pinning___tofu (3 files, rating 0.5).

- [mutants/src: certificate_pinning___tofu] `include/certificate_pinning___tofu.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: certificate_pinning___tofu] `mutants/src/certificate_pinning___tofu.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Certificate Pinning / TOFU
- Key entities: file:include/certificate_pinning___tofu.h, file:mutants/src/certificate_pinning___tofu.c
- Children: c12
- Theme rating = highest child community rating.

## mutants/src: command_execution_via_execve (`t7`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: command_execution_via_execve (3 files, rating 0.5).

- [mutants/src: command_execution_via_execve] `include/command_execution_via_execve.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: command_execution_via_execve] `mutants/src/command_execution_via_execve.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Command Execution via execve
- Key entities: file:include/command_execution_via_execve.h, file:mutants/src/command_execution_via_execve.c
- Children: c13
- Theme rating = highest child community rating.

## mutants/src: containerized_build_+_sbom (`t8`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: containerized_build_+_sbom (3 files, rating 0.5).

- [mutants/src: containerized_build_+_sbom] `include/containerized_build_+_sbom.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- [mutants/src: containerized_build_+_sbom] `mutants/src/containerized_build_+_sbom.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Containerized Build + SBOM
- Key entities: file:include/containerized_build_+_sbom.h, file:mutants/src/containerized_build_+_sbom.c
- Children: c14
- Theme rating = highest child community rating.

## mutants/src: hkdf_key_derivation (`t9`, theme, rating 0.5)

Theme of 1 communities and 3 files: mutants/src: hkdf_key_derivation (3 files, rating 0.5).

- [mutants/src: hkdf_key_derivation] `include/hkdf_key_derivation.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- [mutants/src: hkdf_key_derivation] `mutants/src/hkdf_key_derivation.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: HKDF Key Derivation
- Key entities: file:include/hkdf_key_derivation.h, file:mutants/src/hkdf_key_derivation.c
- Children: c15
- Theme rating = highest child community rating.

## include: config_autogen (`t23`, theme, rating 0.3)

Theme of 1 communities and 2 files: include: config_autogen (2 files, rating 0.3).

- [include: config_autogen] `include/config_autogen.h` ranks 1 by PageRank, 1 importers, 12 symbols: bsb_config_load: } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff; bsb_server_t server; char path[512]; } bsb_config_t; /* Load config...
- [include: config_autogen] `include/config_autogen.c` ranks 2 by PageRank, 0 importers, 18 symbols: slurp: Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate  #define _POSIX_C_SOURCE 200809L #include "config_autogen.h" #include <stdio.h> #include <stdlib.h>...
- Key entities: file:include/config_autogen.c, file:include/config_autogen.h
- Children: c24
- Theme rating = highest child community rating.

## unassigned files (`c25`, community, rating 7.0)

62 files under mutants/tests (py 36, c 24, h 1, sh 1), mostly testing. Core file app.py (PageRank 0.0040, imported by 0 files): Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción: Key abstractions: NULL, CALLBACK_OUTPUT, size_t, ssize_t, BeaconPrintf, BeaconOutput.

- `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:
- `bof/cat/cat.c` ranks 2 by PageRank, 0 importers, 12 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o  Tipos
- `bof/is_sudo/is_sudo.c` ranks 3 by PageRank, 0 importers, 17 symbols: — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o  Tipos
- Hotspot `mutants/tests/test_crypto.py`: 8 symbols, 9 connections (score 0.18).
- Hotspot `gopher_c2.py`: 5 symbols, 9 connections (score 0.17).
- Taint: 10 paths reach this group via subprocess.
- Dataflow: 1 INFERRED issues (first: UNCHECKED_ALLOC in main).
- Key entities: file:bof/is_sudo/is_sudo.c, file:issudo.c, file:bof/whoami/whoami.c, file:bof/userenum/userenum.c, file:include/beacon.h, file:bof/cat/cat.c, file:tests/test_execve_command.py, file:contract_agent.py
- Rating 7.0/10 = 7 x PageRank share 1.00 + 3 x risk 0.00. Internal imports: 0.

## root (`c0`, community, rating 3.6)

20 files under root (c 15, h 5), mostly utility. Core file include/beacon_common.h (PageRank 0.0186, imported by 5 files): http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory. Key abstractions: http_response_t, Trampoline, SymbolResolver, TrampolineCache, bsb_backoff_t, BEACON_COMMON_H. Depends on include: aes (1), include: config (1).

- `include/beacon_common.h` ranks 1 by PageRank, 5 importers, 58 symbols: http_response_t: -- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.
- `aes.h` ranks 2 by PageRank, 6 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- `beacon.h` ranks 3 by PageRank, 6 importers, 13 symbols: Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)
- Hotspot `beacon5.c`: 44 symbols, 34 connections (score 0.74).
- Hotspot `beacon_p2p.c`: 49 symbols, 33 connections (score 0.74).
- Dataflow: 46 INFERRED issues (first: UNCHECKED_ALLOC in base64_encode).
- Surprising bridge: bof.c <-> config.c (7 hops across communities).
- Key entities: file:cJSON.c, file:include/cJSON.c, file:include/beacon_common.h, file:beacon_p2p.c, file:beacon5.c, file:include/beacon_common.c, file:beacon6.c, file:aes.c
- Rating 3.6/10 = 7 x PageRank share 0.51 + 3 x risk 0.00. Internal imports: 25.

## c2 (`c1`, community, rating 3.4)

15 files under tests (py 15), mostly testing. Core file include/config_py.py (PageRank 0.0399, imported by 8 files): Python loader for BSB JSON config files. Key abstractions: load_config, C2State, load_runtime_config, compute_hmac, verify_hmac, encrypt_data.

- `include/config_py.py` ranks 1 by PageRank, 8 importers, 3 symbols: Python loader for BSB JSON config files.
- `c2/server.py` ranks 2 by PageRank, 8 importers, 21 symbols: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- `c2/__init__.py` ranks 3 by PageRank, 2 importers, 0 symbols.
- Hotspot `tests/test_hkdf_key_derivation.py`: 19 symbols, 32 connections (score 0.63).
- Hotspot `c2/server.py`: 21 symbols, 27 connections (score 0.54).
- Taint: 6 paths reach this group via subprocess.
- Dataflow: 1 INFERRED issues (first: UNCHECKED_ALLOC in serve).
- Key entities: file:tests/test_replay_protection.py, file:c2/server.py, file:tests/test_hkdf_key_derivation.py, file:tests/test_iv_generation.py, file:mutants/tests/test_certificate_pinning.py, file:tests/test_certificate_pinning.py, file:tests/test_c2_beacon_bof_integration.py, file:tests/test_bof_path_traversal.py
- Rating 3.4/10 = 7 x PageRank share 0.49 + 3 x risk 0.00. Internal imports: 18.

## include: config (`c4`, community, rating 1.6)

6 files under tests (c 5, h 1), mostly infrastructure. Core file include/config.h (PageRank 0.0367, imported by 6 files): bsb_config_load: Load config from path. Key abstractions: bsb_c2_t, bsb_crypto_t, bsb_timing_t, bsb_network_t, bsb_bof_t, bsb_backoff_config_t. Used by root (1).

- `include/config.h` ranks 1 by PageRank, 6 importers, 21 symbols: bsb_config_load: Load config from path.
- `include/config.c` ranks 2 by PageRank, 0 importers, 28 symbols: slurp: declared in the schema.
- `mutants/tests/config_harness.c` ranks 3 by PageRank, 0 importers, 1 symbols.
- Hotspot `include/config.c`: 28 symbols, 11 connections (score 0.28).
- Hotspot `tests/test_hkdf_key_derivation_c.c`: 11 symbols, 11 connections (score 0.23).
- Surprising bridge: bof.c <-> config.c (7 hops across communities).
- Key entities: file:include/config.c, file:include/config.h, file:tests/test_hkdf_key_derivation_c.c, file:tests/test_certificate_pinning_c.c, file:mutants/tests/config_harness.c, file:tests/config_harness.c, sym:include/config.c::HKDF_INFO_ENC@289, sym:include/config.c::HKDF_INFO_HMAC@290
- Rating 1.6/10 = 7 x PageRank share 0.23 + 3 x risk 0.00. Internal imports: 5.

## bof/include (`c2`, community, rating 1.3)

7 files under bof/include (c 5, h 2), mostly utility. Core file bof/include/beacon_api.h (PageRank 0.0124, imported by 5 files): datap: Argument parser. Key abstractions: datap, go, BSB_BOF_BEACON_API_H, CALLBACK_OUTPUT, CALLBACK_ERROR, CALLBACK_OUTPUT_OEM.

- `bof/include/beacon_api.h` ranks 1 by PageRank, 5 importers, 14 symbols: datap: Argument parser.
- `bof/include/syscalls.h` ranks 2 by PageRank, 5 importers, 38 symbols: bsf_strlen: } static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx"...
- `bof/cat/bof.c` ranks 3 by PageRank, 0 importers, 1 symbols.
- Hotspot `bof/include/syscalls.h`: 38 symbols, 6 connections (score 0.23).
- Hotspot `bof/include/beacon_api.h`: 14 symbols, 8 connections (score 0.19).
- Key entities: file:bof/include/syscalls.h, file:bof/include/beacon_api.h, file:bof/suid_enum/bof.c, file:bof/is_sudo/bof.c, file:bof/userenum/bof.c, file:bof/cat/bof.c, file:bof/whoami/bof.c, sym:bof/include/syscalls.h::AT_FDCWD@47
- Rating 1.3/10 = 7 x PageRank share 0.18 + 3 x risk 0.00. Internal imports: 10.

## include: aes (`c3`, community, rating 1.1)

6 files under include (c 4, h 2), mostly utility. Core file include/aes_cfb.h (PageRank 0.0124, imported by 3 files). Key abstractions: BSB_AES_CFB_H, aes256_cfb_encrypt, aes256_cfb_decrypt, AES_ctx, CBC, ECB. Used by root (1).

- `include/aes_cfb.h` ranks 1 by PageRank, 3 importers, 3 symbols.
- `include/aes.h` ranks 2 by PageRank, 3 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- `include/aes.c` ranks 3 by PageRank, 0 importers, 43 symbols: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Hotspot `include/aes.c`: 43 symbols, 3 connections (score 0.19).
- Hotspot `include/aes.h`: 21 symbols, 5 connections (score 0.16).
- Dataflow: 2 INFERRED issues (first: UNCHECKED_ALLOC in aes256_cfb_encrypt).
- Key entities: file:include/aes.c, file:include/aes.h, file:include/aes_cfb.c, file:include/aes_cfb.h, file:mutants/tests/crypto_harness.c, file:tests/crypto_harness.c, sym:include/aes.c::AES_CBC_decrypt_buffer@552, sym:include/aes.c::AES_CBC_encrypt_buffer@537
- Rating 1.1/10 = 7 x PageRank share 0.16 + 3 x risk 0.00. Internal imports: 5.

## mutants/src: bof_streaming_(large_outputs) (`c10`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/bof_streaming_(large_outputs).h (PageRank 0.0107, imported by 2 files). Key abstractions: BOF_STREAMING_, bof_streaming_, bof_streaming_, bof_streaming_.

- `include/bof_streaming_(large_outputs).h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/bof_streaming_(large_outputs).c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Streaming (Large Outputs)
- `src/bof_streaming_(large_outputs).c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Streaming (Large Outputs)
- Hotspot `mutants/src/bof_streaming_(large_outputs).c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/bof_streaming_(large_outputs).c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/bof_streaming_(large_outputs).h, file:mutants/src/bof_streaming_(large_outputs).c, file:src/bof_streaming_(large_outputs).c, sym:include/bof_streaming_(large_outputs).h::BOF_STREAMING_@2, sym:include/bof_streaming_(large_outputs).h::bof_streaming_@4, sym:src/bof_streaming_(large_outputs).c::bof_streaming_@6, sym:mutants/src/bof_streaming_(large_outputs).c::bof_streaming_@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: c2_rest_api (`c11`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly presentation. Core file include/c2_rest_api.h (PageRank 0.0107, imported by 2 files). Key abstractions: C2_REST_API_H, c2_rest_api_process, c2_rest_api_process, c2_rest_api_process.

- `include/c2_rest_api.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/c2_rest_api.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: C2 REST API
- `src/c2_rest_api.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: C2 REST API
- Hotspot `mutants/src/c2_rest_api.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/c2_rest_api.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/c2_rest_api.h, file:mutants/src/c2_rest_api.c, file:src/c2_rest_api.c, sym:include/c2_rest_api.h::C2_REST_API_H@2, sym:include/c2_rest_api.h::c2_rest_api_process@4, sym:src/c2_rest_api.c::c2_rest_api_process@6, sym:mutants/src/c2_rest_api.c::c2_rest_api_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: certificate_pinning___tofu (`c12`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/certificate_pinning___tofu.h (PageRank 0.0107, imported by 2 files). Key abstractions: CERTIFICATE_PINNING___TOFU_H, certificate_pinning___tofu_process, certificate_pinning___tofu_process, certificate_pinning___tofu_process.

- `include/certificate_pinning___tofu.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/certificate_pinning___tofu.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Certificate Pinning / TOFU
- `src/certificate_pinning___tofu.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Certificate Pinning / TOFU
- Hotspot `mutants/src/certificate_pinning___tofu.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/certificate_pinning___tofu.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/certificate_pinning___tofu.h, file:mutants/src/certificate_pinning___tofu.c, file:src/certificate_pinning___tofu.c, sym:include/certificate_pinning___tofu.h::CERTIFICATE_PINNING___TOFU_H@2, sym:include/certificate_pinning___tofu.h::certificate_pinning___tofu_process@4, sym:src/certificate_pinning___tofu.c::certificate_pinning___tofu_process@6, sym:mutants/src/certificate_pinning___tofu.c::certificate_pinning___tofu_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: command_execution_via_execve (`c13`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/command_execution_via_execve.h (PageRank 0.0107, imported by 2 files). Key abstractions: COMMAND_EXECUTION_VIA_EXECVE_H, command_execution_via_execve_process, command_execution_via_execve_process, command_execution_via_execve_process.

- `include/command_execution_via_execve.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/command_execution_via_execve.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Command Execution via execve
- `src/command_execution_via_execve.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Command Execution via execve
- Hotspot `mutants/src/command_execution_via_execve.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/command_execution_via_execve.c`: 1 symbols, 3 connections (score 0.06).
- Taint: 4 paths reach this group via exec.
- Key entities: file:include/command_execution_via_execve.h, file:mutants/src/command_execution_via_execve.c, file:src/command_execution_via_execve.c, sym:include/command_execution_via_execve.h::COMMAND_EXECUTION_VIA_EXECVE_H@2, sym:include/command_execution_via_execve.h::command_execution_via_execve_process@4, sym:src/command_execution_via_execve.c::command_execution_via_execve_process@6, sym:mutants/src/command_execution_via_execve.c::command_execution_via_execve_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: containerized_build_+_sbom (`c14`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly infrastructure. Core file include/containerized_build_+_sbom.h (PageRank 0.0107, imported by 2 files). Key abstractions: CONTAINERIZED_BUILD_.

- `include/containerized_build_+_sbom.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- `mutants/src/containerized_build_+_sbom.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Containerized Build + SBOM
- `src/containerized_build_+_sbom.c` ranks 3 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Containerized Build + SBOM
- Hotspot `mutants/src/containerized_build_+_sbom.c`: 0 symbols, 3 connections (score 0.05).
- Hotspot `src/containerized_build_+_sbom.c`: 0 symbols, 3 connections (score 0.05).
- Key entities: file:include/containerized_build_+_sbom.h, file:mutants/src/containerized_build_+_sbom.c, file:src/containerized_build_+_sbom.c, sym:include/containerized_build_+_sbom.h::CONTAINERIZED_BUILD_@2
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: hkdf_key_derivation (`c15`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/hkdf_key_derivation.h (PageRank 0.0107, imported by 2 files). Key abstractions: HKDF_KEY_DERIVATION_H, hkdf_key_derivation_process, hkdf_key_derivation_process, hkdf_key_derivation_process.

- `include/hkdf_key_derivation.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/hkdf_key_derivation.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: HKDF Key Derivation
- `src/hkdf_key_derivation.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: HKDF Key Derivation
- Hotspot `mutants/src/hkdf_key_derivation.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/hkdf_key_derivation.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/hkdf_key_derivation.h, file:mutants/src/hkdf_key_derivation.c, file:src/hkdf_key_derivation.c, sym:include/hkdf_key_derivation.h::HKDF_KEY_DERIVATION_H@2, sym:include/hkdf_key_derivation.h::hkdf_key_derivation_process@4, sym:src/hkdf_key_derivation.c::hkdf_key_derivation_process@6, sym:mutants/src/hkdf_key_derivation.c::hkdf_key_derivation_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: iv_generation_with_entropy_verification (`c16`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/iv_generation_with_entropy_verification.h (PageRank 0.0107, imported by 2 files). Key abstractions: IV_GENERATION_WITH_ENTROPY_VERIFICATION_H, iv_generation_with_entropy_verification_process, iv_generation_with_entropy_verification_process, iv_generation_with_entropy_verification_process.

- `include/iv_generation_with_entropy_verification.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/iv_generation_with_entropy_verification.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: IV Generation with Entropy Verification
- `src/iv_generation_with_entropy_verification.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: IV Generation with Entropy Verification
- Hotspot `mutants/src/iv_generation_with_entropy_verification.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/iv_generation_with_entropy_verification.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/iv_generation_with_entropy_verification.h, file:mutants/src/iv_generation_with_entropy_verification.c, file:src/iv_generation_with_entropy_verification.c, sym:include/iv_generation_with_entropy_verification.h::IV_GENERATION_WITH_ENTROPY_VERIFICATION_H@2, sym:include/iv_generation_with_entropy_verification.h::iv_generation_with_entropy_verification_process@4, sym:src/iv_generation_with_entropy_verification.c::iv_generation_with_entropy_verification_process@6, sym:mutants/src/iv_generation_with_entropy_verification.c::iv_generation_with_entropy_verification_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: mutation_testing_integration (`c17`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly testing. Core file include/mutation_testing_integration.h (PageRank 0.0107, imported by 2 files). Key abstractions: MUTATION_TESTING_INTEGRATION_H, mutation_testing_integration_process, mutation_testing_integration_process, mutation_testing_integration_process.

- `include/mutation_testing_integration.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/mutation_testing_integration.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Mutation Testing Integration
- `src/mutation_testing_integration.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Mutation Testing Integration
- Hotspot `mutants/src/mutation_testing_integration.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/mutation_testing_integration.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/mutation_testing_integration.h, file:mutants/src/mutation_testing_integration.c, file:src/mutation_testing_integration.c, sym:include/mutation_testing_integration.h::MUTATION_TESTING_INTEGRATION_H@2, sym:include/mutation_testing_integration.h::mutation_testing_integration_process@4, sym:src/mutation_testing_integration.c::mutation_testing_integration_process@6, sym:mutants/src/mutation_testing_integration.c::mutation_testing_integration_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: pre-commit_+_ci_hardening (`c18`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/pre-commit_+_ci_hardening.h (PageRank 0.0107, imported by 2 files). Key abstractions: PRE.

- `include/pre-commit_+_ci_hardening.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- `mutants/src/pre-commit_+_ci_hardening.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Pre-commit + CI Hardening
- `src/pre-commit_+_ci_hardening.c` ranks 3 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: Pre-commit + CI Hardening
- Hotspot `mutants/src/pre-commit_+_ci_hardening.c`: 0 symbols, 3 connections (score 0.05).
- Hotspot `src/pre-commit_+_ci_hardening.c`: 0 symbols, 3 connections (score 0.05).
- Key entities: file:include/pre-commit_+_ci_hardening.h, file:mutants/src/pre-commit_+_ci_hardening.c, file:src/pre-commit_+_ci_hardening.c, sym:include/pre-commit_+_ci_hardening.h::PRE@2
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: replay_protection (`c19`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/replay_protection.h (PageRank 0.0107, imported by 2 files). Key abstractions: REPLAY_PROTECTION_H, replay_protection_process, replay_protection_process, replay_protection_process.

- `include/replay_protection.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/replay_protection.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Replay Protection
- `src/replay_protection.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Replay Protection
- Hotspot `mutants/src/replay_protection.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/replay_protection.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/replay_protection.h, file:mutants/src/replay_protection.c, file:src/replay_protection.c, sym:include/replay_protection.h::REPLAY_PROTECTION_H@2, sym:include/replay_protection.h::replay_protection_process@4, sym:src/replay_protection.c::replay_protection_process@6, sym:mutants/src/replay_protection.c::replay_protection_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: socks5___http_proxy_support (`c20`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly presentation. Core file include/socks5___http_proxy_support.h (PageRank 0.0107, imported by 2 files). Key abstractions: SOCKS5___HTTP_PROXY_SUPPORT_H, socks5___http_proxy_support_process, socks5___http_proxy_support_process, socks5___http_proxy_support_process.

- `include/socks5___http_proxy_support.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/socks5___http_proxy_support.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support
- `src/socks5___http_proxy_support.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support
- Hotspot `mutants/src/socks5___http_proxy_support.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/socks5___http_proxy_support.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/socks5___http_proxy_support.h, file:mutants/src/socks5___http_proxy_support.c, file:src/socks5___http_proxy_support.c, sym:include/socks5___http_proxy_support.h::SOCKS5___HTTP_PROXY_SUPPORT_H@2, sym:include/socks5___http_proxy_support.h::socks5___http_proxy_support_process@4, sym:src/socks5___http_proxy_support.c::socks5___http_proxy_support_process@6, sym:mutants/src/socks5___http_proxy_support.c::socks5___http_proxy_support_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: structured_jsonl_logging (`c21`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly infrastructure. Core file include/structured_jsonl_logging.h (PageRank 0.0107, imported by 2 files). Key abstractions: STRUCTURED_JSONL_LOGGING_H, structured_jsonl_logging_process, structured_jsonl_logging_process, structured_jsonl_logging_process.

- `include/structured_jsonl_logging.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/structured_jsonl_logging.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Structured JSONL Logging
- `src/structured_jsonl_logging.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Structured JSONL Logging
- Hotspot `mutants/src/structured_jsonl_logging.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/structured_jsonl_logging.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/structured_jsonl_logging.h, file:mutants/src/structured_jsonl_logging.c, file:src/structured_jsonl_logging.c, sym:include/structured_jsonl_logging.h::STRUCTURED_JSONL_LOGGING_H@2, sym:include/structured_jsonl_logging.h::structured_jsonl_logging_process@4, sym:src/structured_jsonl_logging.c::structured_jsonl_logging_process@6, sym:mutants/src/structured_jsonl_logging.c::structured_jsonl_logging_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: tls_client_certificate_authentication (`c22`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly infrastructure. Core file include/tls_client_certificate_authentication.h (PageRank 0.0107, imported by 2 files). Key abstractions: TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H, tls_client_certificate_authentication_process, tls_client_certificate_authentication_process, tls_client_certificate_authentication_process.

- `include/tls_client_certificate_authentication.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/tls_client_certificate_authentication.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: TLS Client Certificate Authentication
- `src/tls_client_certificate_authentication.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: TLS Client Certificate Authentication
- Hotspot `mutants/src/tls_client_certificate_authentication.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/tls_client_certificate_authentication.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/tls_client_certificate_authentication.h, file:mutants/src/tls_client_certificate_authentication.c, file:src/tls_client_certificate_authentication.c, sym:include/tls_client_certificate_authentication.h::TLS_CLIENT_CERTIFICATE_AUTHENTICATION_H@2, sym:include/tls_client_certificate_authentication.h::tls_client_certificate_authentication_process@4, sym:src/tls_client_certificate_authentication.c::tls_client_certificate_authentication_process@6, sym:mutants/src/tls_client_certificate_authentication.c::tls_client_certificate_authentication_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: unified_config_schema (`c23`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly infrastructure. Core file include/unified_config_schema.h (PageRank 0.0107, imported by 2 files). Key abstractions: UNIFIED_CONFIG_SCHEMA_H, unified_config_schema_process, unified_config_schema_process, unified_config_schema_process.

- `include/unified_config_schema.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/unified_config_schema.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Unified Config Schema
- `src/unified_config_schema.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Unified Config Schema
- Hotspot `mutants/src/unified_config_schema.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/unified_config_schema.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/unified_config_schema.h, file:mutants/src/unified_config_schema.c, file:src/unified_config_schema.c, sym:include/unified_config_schema.h::UNIFIED_CONFIG_SCHEMA_H@2, sym:include/unified_config_schema.h::unified_config_schema_process@4, sym:src/unified_config_schema.c::unified_config_schema_process@6, sym:mutants/src/unified_config_schema.c::unified_config_schema_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: async_i_o_for_beacon (`c5`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/async_i_o_for_beacon.h (PageRank 0.0107, imported by 2 files). Key abstractions: ASYNC_I_O_FOR_BEACON_H, async_i_o_for_beacon_process, async_i_o_for_beacon_process, async_i_o_for_beacon_process.

- `include/async_i_o_for_beacon.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/async_i_o_for_beacon.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Async I/O for Beacon
- `src/async_i_o_for_beacon.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Async I/O for Beacon
- Hotspot `mutants/src/async_i_o_for_beacon.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/async_i_o_for_beacon.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/async_i_o_for_beacon.h, file:mutants/src/async_i_o_for_beacon.c, file:src/async_i_o_for_beacon.c, sym:include/async_i_o_for_beacon.h::ASYNC_I_O_FOR_BEACON_H@2, sym:include/async_i_o_for_beacon.h::async_i_o_for_beacon_process@4, sym:src/async_i_o_for_beacon.c::async_i_o_for_beacon_process@6, sym:mutants/src/async_i_o_for_beacon.c::async_i_o_for_beacon_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: beacon_common.c_extraction (`c6`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/beacon_common.c_extraction.h (PageRank 0.0107, imported by 2 files). Key abstractions: BEACON_COMMON.

- `include/beacon_common.c_extraction.h` ranks 1 by PageRank, 2 importers, 1 symbols.
- `mutants/src/beacon_common.c_extraction.c` ranks 2 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: beacon_common.c Extraction
- `src/beacon_common.c_extraction.c` ranks 3 by PageRank, 0 importers, 0 symbols: Auto-generated implementation for contract: beacon_common.c Extraction
- Hotspot `mutants/src/beacon_common.c_extraction.c`: 0 symbols, 3 connections (score 0.05).
- Hotspot `src/beacon_common.c_extraction.c`: 0 symbols, 3 connections (score 0.05).
- Key entities: file:mutants/src/beacon_common.c_extraction.c, file:include/beacon_common.c_extraction.h, file:src/beacon_common.c_extraction.c, sym:include/beacon_common.c_extraction.h::BEACON_COMMON@2
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: beacon_heartbeat___health_endpoint (`c7`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly presentation. Core file include/beacon_heartbeat___health_endpoint.h (PageRank 0.0107, imported by 2 files). Key abstractions: BEACON_HEARTBEAT___HEALTH_ENDPOINT_H, beacon_heartbeat___health_endpoint_process, beacon_heartbeat___health_endpoint_process, beacon_heartbeat___health_endpoint_process.

- `include/beacon_heartbeat___health_endpoint.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/beacon_heartbeat___health_endpoint.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint
- `src/beacon_heartbeat___health_endpoint.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint
- Hotspot `mutants/src/beacon_heartbeat___health_endpoint.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/beacon_heartbeat___health_endpoint.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/beacon_heartbeat___health_endpoint.h, file:mutants/src/beacon_heartbeat___health_endpoint.c, file:src/beacon_heartbeat___health_endpoint.c, sym:include/beacon_heartbeat___health_endpoint.h::BEACON_HEARTBEAT___HEALTH_ENDPOINT_H@2, sym:include/beacon_heartbeat___health_endpoint.h::beacon_heartbeat___health_endpoint_process@4, sym:src/beacon_heartbeat___health_endpoint.c::beacon_heartbeat___health_endpoint_process@6, sym:mutants/src/beacon_heartbeat___health_endpoint.c::beacon_heartbeat___health_endpoint_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: bof_api_versioning (`c8`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly presentation. Core file include/bof_api_versioning.h (PageRank 0.0107, imported by 2 files). Key abstractions: BOF_API_VERSIONING_H, bof_api_versioning_process, bof_api_versioning_process, bof_api_versioning_process.

- `include/bof_api_versioning.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/bof_api_versioning.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF API Versioning
- `src/bof_api_versioning.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF API Versioning
- Hotspot `mutants/src/bof_api_versioning.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/bof_api_versioning.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/bof_api_versioning.h, file:mutants/src/bof_api_versioning.c, file:src/bof_api_versioning.c, sym:include/bof_api_versioning.h::BOF_API_VERSIONING_H@2, sym:include/bof_api_versioning.h::bof_api_versioning_process@4, sym:src/bof_api_versioning.c::bof_api_versioning_process@6, sym:mutants/src/bof_api_versioning.c::bof_api_versioning_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## mutants/src: bof_path_traversal_hardening (`c9`, community, rating 0.5)

3 files under mutants/src (c 2, h 1), mostly utility. Core file include/bof_path_traversal_hardening.h (PageRank 0.0107, imported by 2 files). Key abstractions: BOF_PATH_TRAVERSAL_HARDENING_H, bof_path_traversal_hardening_process, bof_path_traversal_hardening_process, bof_path_traversal_hardening_process.

- `include/bof_path_traversal_hardening.h` ranks 1 by PageRank, 2 importers, 2 symbols.
- `mutants/src/bof_path_traversal_hardening.c` ranks 2 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Path Traversal Hardening
- `src/bof_path_traversal_hardening.c` ranks 3 by PageRank, 0 importers, 1 symbols: Auto-generated implementation for contract: BOF Path Traversal Hardening
- Hotspot `mutants/src/bof_path_traversal_hardening.c`: 1 symbols, 3 connections (score 0.06).
- Hotspot `src/bof_path_traversal_hardening.c`: 1 symbols, 3 connections (score 0.06).
- Key entities: file:include/bof_path_traversal_hardening.h, file:mutants/src/bof_path_traversal_hardening.c, file:src/bof_path_traversal_hardening.c, sym:include/bof_path_traversal_hardening.h::BOF_PATH_TRAVERSAL_HARDENING_H@2, sym:include/bof_path_traversal_hardening.h::bof_path_traversal_hardening_process@4, sym:src/bof_path_traversal_hardening.c::bof_path_traversal_hardening_process@6, sym:mutants/src/bof_path_traversal_hardening.c::bof_path_traversal_hardening_process@6
- Rating 0.5/10 = 7 x PageRank share 0.08 + 3 x risk 0.00. Internal imports: 2.

## include: config_autogen (`c24`, community, rating 0.3)

2 files under include (c 1, h 1), mostly infrastructure. Core file include/config_autogen.h (PageRank 0.0074, imported by 1 files): bsb_config_load: } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff; bsb_server_t server; char path[512]; } bsb_config_t; /* Load config... Key abstractions: bsb_c2_t, bsb_crypto_t, bsb_timing_t, bsb_network_t, bsb_bof_t, bsb_backoff_t.

- `include/config_autogen.h` ranks 1 by PageRank, 1 importers, 12 symbols: bsb_config_load: } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff; bsb_server_t server; char path[512]; } bsb_config_t; /* Load config...
- `include/config_autogen.c` ranks 2 by PageRank, 0 importers, 18 symbols: slurp: Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate  #define _POSIX_C_SOURCE 200809L #include "config_autogen.h" #include <stdio.h> #include <stdlib.h>...
- Hotspot `include/config_autogen.c`: 18 symbols, 9 connections (score 0.22).
- Hotspot `include/config_autogen.h`: 12 symbols, 3 connections (score 0.09).
- Key entities: file:include/config_autogen.c, file:include/config_autogen.h, sym:include/config_autogen.h::BSB_CONFIG_AUTOGEN_H@6, sym:include/config_autogen.h::bsb_backoff_t@47, sym:include/config_autogen.h::bsb_bof_t@42, sym:include/config_autogen.h::bsb_c2_t@11, sym:include/config_autogen.h::bsb_config_load@69, sym:include/config_autogen.h::bsb_config_load_default@72
- Rating 0.3/10 = 7 x PageRank share 0.05 + 3 x risk 0.00. Internal imports: 1.
