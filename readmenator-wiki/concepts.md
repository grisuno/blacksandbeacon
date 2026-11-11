# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `mutants` | 74 | 75 | `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c`, `mutants/src/bof_api_versioning.c`, `mutants/src/bof_path_traversal_hardening.c` |
| `contract` | 65 | 72 | `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c`, `mutants/src/bof_api_versioning.c` |
| `generated` | 61 | 63 | `include/config_autogen.c`, `include/config_py.py`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c` |
| `implementation` | 60 | 64 | `config/generate_parsers.py`, `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `auto` | 59 | 59 | `include/config_autogen.c`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `beacon` | 53 | 305 | `beacon.h`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c` |
| `bof` | 51 | 208 | `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `beacons/v1/gopher_beacon.c` |
| `process` | 50 | 50 | `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/async_i_o_for_beacon.h`, `include/beacon_common.h` |
| `include` | 49 | 102 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `bof/suid_enum/bof.c`, `config/generate_parsers.py`, `include/aes.c` |
| `config` | 33 | 248 | `c2/server.py`, `config/generate_parsers.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.c` |
| `placeholder` | 31 | 31 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_async_i_o_for_beacon_c.c`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c`, `mutants/tests/test_bof_api_versioning.py` |
| `not` | 29 | 82 | `aes.c`, `bof/include/syscalls.h`, `c2/server.py`, `cJSON.c`, `include/aes.c` |
| `output` | 27 | 148 | `beacon.h`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c` |
| `bdd` | 27 | 44 | `contract_agent.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py` |
| `api` | 26 | 64 | `beacon.h`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c` |
| `style` | 25 | 32 | `c2/server.py`, `include/beacon_common.h`, `include/config.c`, `include/config_autogen.c`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `run` | 24 | 58 | `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `beacons/v1/gopher_beacon.c` |
| `aes` | 23 | 125 | `aes.c`, `aes.h`, `beacon3.c`, `beacon5.c`, `beacon6.c` |
| `derived` | 23 | 34 | `include/config_py.py`, `include/config_py_autogen.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py` |
| `get` | 22 | 70 | `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c` |
| `decrypt` | 22 | 45 | `aes.c`, `aes.h`, `beacon3.c`, `beacon5.c`, `beacon6.c` |
| `encrypt` | 22 | 39 | `aes.c`, `aes.h`, `beacon3.c`, `beacon5.c`, `beacon6.c` |
| `must` | 22 | 34 | `c2/server.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.c`, `mutants/tests/test_bof_compile.py` |
| `key` | 21 | 148 | `aes.c`, `aes.h`, `include/aes.c`, `include/aes.h`, `include/config.c` |
| `error` | 21 | 46 | `beacon.h`, `bof/include/beacon_api.h`, `cJSON.c`, `cJSON.h`, `include/beacon.h` |
| `fail` | 21 | 30 | `cJSON.c`, `include/beacon_common.c`, `include/beacon_common.h`, `include/cJSON.c`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `fails` | 21 | 29 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `return` | 20 | 127 | `beacon6.c`, `bof/include/syscalls.h`, `c2/server.py`, `cJSON.c`, `contract_agent.py` |
| `command` | 20 | 61 | `beacon_p2p.c`, `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `c2/server.py` |
| `path` | 19 | 82 | `bof/suid_enum/bof.c`, `c2/server.py`, `include/bof_path_traversal_hardening.h`, `include/config.h`, `include/config_autogen.h` |
| `size` | 19 | 73 | `aes.h`, `beacon5.c`, `beacons/v2/beacon.c`, `bof/cat/cat.c`, `bof/include/syscalls.h` |
| `build` | 19 | 61 | `cJSON.c`, `contract_agent.py`, `include/cJSON.c`, `include/containerized_build_+_sbom.h`, `install.sh` |
| `value` | 19 | 47 | `aes.c`, `bof/suid_enum/bof.c`, `cJSON.c`, `cJSON.h`, `include/aes.c` |
| `client` | 19 | 41 | `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `beacons/v1/gopher_beacon.c` |
| `specification` | 19 | 19 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `null` | 18 | 81 | `bof/cat/cat.c`, `bof/is_sudo/is_sudo.c`, `bof/userenum/userenum.c`, `bof/whoami/whoami.c`, `cJSON.c` |
| `returns` | 18 | 56 | `beacon6.c`, `bof/include/syscalls.h`, `c2/server.py`, `include/aes_cfb.c`, `include/beacon_common.c` |
| `until` | 18 | 18 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `bsb` | 17 | 165 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `c2/server.py`, `include/aes_cfb.h`, `include/beacon_common.c` |
| `server` | 17 | 83 | `beacon_p2p.c`, `c2/server.py`, `include/beacon_common.h`, `include/config_autogen.c`, `include/config_autogen.h` |
| `int` | 17 | 63 | `beacon.h`, `beacon6.c`, `beacon_p2p.c`, `bof/include/beacon_api.h`, `bof/include/syscalls.h` |
| `printf` | 17 | 26 | `beacon.h`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c` |
| `complete` | 17 | 18 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `json` | 16 | 213 | `c2/server.py`, `cJSON.c`, `cJSON.h`, `config/generate_parsers.py`, `include/cJSON.c` |
| `bytes` | 16 | 62 | `aes.c`, `cJSON.c`, `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c` |
| `length` | 16 | 56 | `beacon.h`, `beacon_p2p.c`, `bof/include/beacon_api.h`, `bof/suid_enum/bof.c`, `cJSON.c` |
| `source` | 16 | 19 | `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `beacons/v1/beacon.c` |
| `initially` | 16 | 16 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `suite` | 16 | 16 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `char` | 15 | 84 | `bof/include/syscalls.h`, `bof/suid_enum/bof.c`, `cJSON.c`, `include/beacon_common.c`, `include/beacon_common.h` |

## Verb Edges

| Source | Verb | Target | Strength |
|--------|------|--------|----------|
| `contract` | `depends_on` | `include` | 1.00 |
| `generated` | `depends_on` | `include` | 0.93 |
| `auto` | `depends_on` | `include` | 0.91 |
| `implementation` | `depends_on` | `include` | 0.91 |
| `contract` | `depends_on` | `process` | 0.77 |
| `process` | `depends_on` | `include` | 0.77 |
| `implementation` | `depends_on` | `process` | 0.74 |
| `generated` | `depends_on` | `process` | 0.72 |
| `auto` | `depends_on` | `process` | 0.70 |
| `bof` | `depends_on` | `int` | 0.60 |
| `mutants` | `depends_on` | `include` | 0.60 |
| `beacon` | `depends_on` | `error` | 0.56 |
| `bof` | `depends_on` | `include` | 0.56 |
| `bof` | `depends_on` | `error` | 0.53 |
| `beacon` | `depends_on` | `include` | 0.51 |
| `bof` | `depends_on` | `bsb` | 0.47 |
| `beacon` | `depends_on` | `int` | 0.44 |
| `config` | `depends_on` | `bsb` | 0.44 |
| `config` | `depends_on` | `include` | 0.44 |
| `config` | `depends_on` | `returns` | 0.44 |
| `mutants` | `depends_on` | `process` | 0.44 |
| `beacon` | `depends_on` | `bsb` | 0.42 |
| `bof` | `depends_on` | `beacon` | 0.42 |
| `source` | `depends_on` | `error` | 0.42 |
| `source` | `depends_on` | `int` | 0.42 |
| `beacon` | `depends_on` | `returns` | 0.40 |
| `get` | `depends_on` | `error` | 0.40 |
| `output` | `depends_on` | `error` | 0.40 |
| `output` | `depends_on` | `int` | 0.40 |
| `aes` | `depends_on` | `error` | 0.37 |
| `beacon` | `depends_on` | `aes` | 0.37 |
| `beacon` | `depends_on` | `config` | 0.37 |
| `beacon` | `consumes` | `error` | 0.37 |
| `beacon` | `consumes` | `int` | 0.37 |
| `beacon` | `depends_on` | `json` | 0.37 |
| `bytes` | `depends_on` | `include` | 0.37 |
| `config` | `depends_on` | `error` | 0.37 |
| `encrypt` | `depends_on` | `aes` | 0.37 |
| `include` | `depends_on` | `bsb` | 0.37 |
| `must` | `depends_on` | `bsb` | 0.37 |
| `must` | `depends_on` | `config` | 0.37 |
| `must` | `depends_on` | `returns` | 0.37 |
| `not` | `depends_on` | `bsb` | 0.37 |
| `not` | `depends_on` | `config` | 0.37 |
| `not` | `depends_on` | `returns` | 0.37 |
| `source` | `consumes` | `error` | 0.37 |
| `source` | `consumes` | `int` | 0.37 |
| `api` | `depends_on` | `int` | 0.35 |
| `beacon` | `depends_on` | `decrypt` | 0.35 |
| `beacon` | `depends_on` | `encrypt` | 0.35 |

## Dialectic Prompts

- Thesis: `aes` centralizes 23 files; Antithesis: `bytes` pulls 16 files with 9 shared (Jaccard 0.30); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `client` pulls 19 files with 11 shared (Jaccard 0.35); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `decrypt` pulls 22 files with 19 shared (Jaccard 0.73); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `encrypt` pulls 22 files with 18 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `get` pulls 22 files with 12 shared (Jaccard 0.36); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `key` pulls 21 files with 12 shared (Jaccard 0.38); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `returns` pulls 18 files with 10 shared (Jaccard 0.32); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `run` pulls 24 files with 11 shared (Jaccard 0.31); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `bof` pulls 51 files with 19 shared (Jaccard 0.33); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `output` pulls 27 files with 14 shared (Jaccard 0.36); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
