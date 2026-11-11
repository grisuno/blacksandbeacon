# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `mutants` | 74 | 75 | `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c`, `mutants/src/bof_api_versioning.c`, `mutants/src/bof_path_traversal_hardening.c` |
| `contract` | 65 | 73 | `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c`, `mutants/src/bof_api_versioning.c` |
| `generated` | 61 | 63 | `include/config_autogen.c`, `include/config_py.py`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c` |
| `implementation` | 60 | 64 | `config/generate_parsers.py`, `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `auto` | 59 | 59 | `include/config_autogen.c`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `beacon` | 53 | 311 | `beacon.h`, `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `bof/cat/cat.c` |
| `bof` | 52 | 214 | `bof.c`, `bof/cat/bof.c`, `bof/cat/cat.c`, `bof/include/beacon_api.h`, `bof/include/syscalls.h` |
| `process` | 50 | 50 | `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/async_i_o_for_beacon.h`, `include/beacon_common.h` |
| `include` | 49 | 102 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `bof/suid_enum/bof.c`, `config/generate_parsers.py`, `include/aes.c` |
| `config` | 32 | 248 | `c2/server.py`, `config/generate_parsers.py`, `include/beacon_common.h`, `include/config.c`, `include/config.h` |
| `placeholder` | 31 | 31 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_async_i_o_for_beacon_c.c`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c`, `mutants/tests/test_bof_api_versioning.py` |
| `not` | 29 | 83 | `aes.c`, `bof/include/syscalls.h`, `c2/server.py`, `cJSON.c`, `include/aes.c` |
| `output` | 28 | 152 | `beacon.h`, `bof/cat/cat.c`, `bof/include/beacon_api.h`, `bof/is_sudo/is_sudo.c`, `bof/suid_enum/bof.c` |
| `bdd` | 27 | 44 | `contract_agent.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py` |
| `api` | 26 | 64 | `beacon.h`, `bof/include/beacon_api.h`, `bof/suid_enum/bof.c`, `include/beacon.h`, `include/beacon_common.c` |
| `run` | 25 | 60 | `contract_agent.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config_autogen.c`, `include/config_py_autogen.py` |
| `style` | 25 | 32 | `c2/server.py`, `include/beacon_common.h`, `include/config.c`, `include/config_autogen.c`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `aes` | 23 | 125 | `aes.c`, `aes.h`, `c2/server.py`, `include/aes.c`, `include/aes.h` |
| `get` | 23 | 70 | `aes.c`, `bof/is_sudo/is_sudo.c`, `c2/server.py`, `cJSON.c`, `cJSON.h` |
| `derived` | 23 | 34 | `include/config_py.py`, `include/config_py_autogen.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py` |
| `key` | 22 | 153 | `aes.c`, `aes.h`, `include/aes.c`, `include/aes.h`, `include/config.c` |
| `decrypt` | 22 | 45 | `aes.c`, `aes.h`, `c2/server.py`, `gopher_c2.py`, `include/aes.c` |
| `encrypt` | 22 | 39 | `aes.c`, `aes.h`, `c2/server.py`, `gopher_c2.py`, `include/aes.c` |
| `must` | 22 | 34 | `c2/server.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.c`, `mutants/tests/test_bof_compile.py` |
| `command` | 21 | 62 | `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `c2/server.py`, `contract_agent.py` |
| `error` | 21 | 46 | `beacon.h`, `bof/include/beacon_api.h`, `cJSON.c`, `cJSON.h`, `include/beacon.h` |
| `fail` | 21 | 30 | `cJSON.c`, `include/beacon_common.c`, `include/beacon_common.h`, `include/cJSON.c`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `fails` | 21 | 29 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `return` | 20 | 127 | `bof/include/syscalls.h`, `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/beacon_common.c` |
| `path` | 19 | 82 | `bof/suid_enum/bof.c`, `c2/server.py`, `include/bof_path_traversal_hardening.h`, `include/config.h`, `include/config_autogen.h` |
| `size` | 19 | 71 | `aes.h`, `beacons/v2/beacon.c`, `bof/cat/cat.c`, `bof/include/syscalls.h`, `bof/is_sudo/is_sudo.c` |
| `build` | 19 | 61 | `cJSON.c`, `contract_agent.py`, `include/cJSON.c`, `include/containerized_build_+_sbom.h`, `install.sh` |
| `returns` | 19 | 58 | `bof/include/syscalls.h`, `c2/server.py`, `include/aes_cfb.c`, `include/beacon_common.c`, `include/beacon_common.h` |
| `value` | 19 | 47 | `aes.c`, `bof/suid_enum/bof.c`, `cJSON.c`, `cJSON.h`, `include/aes.c` |
| `client` | 19 | 41 | `c2/server.py`, `gopher_c2.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.h` |
| `until` | 19 | 20 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `specification` | 19 | 19 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `null` | 18 | 80 | `bof/cat/cat.c`, `bof/is_sudo/is_sudo.c`, `bof/userenum/userenum.c`, `bof/whoami/whoami.c`, `cJSON.c` |
| `bsb` | 17 | 165 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `c2/server.py`, `include/aes_cfb.h`, `include/beacon_common.c` |
| `server` | 17 | 84 | `c2/server.py`, `include/beacon_common.h`, `include/config_autogen.c`, `include/config_autogen.h`, `include/config_py.py` |
| `int` | 17 | 64 | `beacon.h`, `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `cJSON.h`, `include/beacon.h` |
| `bytes` | 17 | 63 | `aes.c`, `cJSON.c`, `include/aes.c`, `include/aes_cfb.c`, `include/beacon_common.c` |
| `printf` | 17 | 26 | `beacon.h`, `bof/cat/cat.c`, `bof/is_sudo/is_sudo.c`, `bof/userenum/userenum.c`, `bof/whoami/whoami.c` |
| `complete` | 17 | 18 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `json` | 16 | 213 | `c2/server.py`, `cJSON.c`, `cJSON.h`, `config/generate_parsers.py`, `include/cJSON.c` |
| `length` | 16 | 56 | `beacon.h`, `bof/include/beacon_api.h`, `bof/suid_enum/bof.c`, `cJSON.c`, `include/beacon.h` |
| `source` | 16 | 19 | `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `include/beacon_common.c`, `include/beacon_common.h` |
| `initially` | 16 | 16 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `suite` | 16 | 16 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `char` | 15 | 82 | `bof/include/syscalls.h`, `bof/suid_enum/bof.c`, `cJSON.c`, `include/beacon_common.c`, `include/beacon_common.h` |

## Verb Edges

| Source | Verb | Target | Strength |
|--------|------|--------|----------|
| `contract` | `depends_on` | `include` | 1.00 |
| `generated` | `depends_on` | `include` | 0.93 |
| `auto` | `depends_on` | `include` | 0.91 |
| `implementation` | `depends_on` | `include` | 0.91 |
| `contract` | `depends_on` | `process` | 0.79 |
| `process` | `depends_on` | `include` | 0.77 |
| `implementation` | `depends_on` | `process` | 0.74 |
| `generated` | `depends_on` | `process` | 0.72 |
| `auto` | `depends_on` | `process` | 0.70 |
| `mutants` | `depends_on` | `include` | 0.60 |
| `bof` | `depends_on` | `include` | 0.58 |
| `beacon` | `depends_on` | `include` | 0.51 |
| `bof` | `depends_on` | `bsb` | 0.51 |
| `mutants` | `depends_on` | `process` | 0.47 |
| `beacon` | `depends_on` | `bsb` | 0.44 |
| `config` | `depends_on` | `bsb` | 0.44 |
| `config` | `depends_on` | `returns` | 0.44 |
| `beacon` | `depends_on` | `returns` | 0.42 |
| `beacon` | `depends_on` | `config` | 0.40 |
| `bof` | `depends_on` | `returns` | 0.40 |
| `bytes` | `depends_on` | `include` | 0.40 |
| `must` | `depends_on` | `bsb` | 0.40 |
| `must` | `depends_on` | `config` | 0.40 |
| `must` | `depends_on` | `returns` | 0.40 |
| `not` | `depends_on` | `bsb` | 0.40 |
| `not` | `depends_on` | `config` | 0.40 |
| `not` | `depends_on` | `returns` | 0.40 |
| `beacon` | `consumes` | `error` | 0.37 |
| `beacon` | `consumes` | `int` | 0.37 |
| `beacon` | `depends_on` | `server` | 0.37 |
| `bof` | `depends_on` | `int` | 0.37 |
| `config` | `depends_on` | `include` | 0.37 |
| `include` | `depends_on` | `bsb` | 0.37 |
| `not` | `depends_on` | `json` | 0.37 |
| `not` | `depends_on` | `server` | 0.37 |
| `source` | `consumes` | `error` | 0.37 |
| `source` | `consumes` | `int` | 0.37 |
| `bof` | `depends_on` | `beacon` | 0.35 |
| `contract` | `depends_on` | `beacon` | 0.35 |
| `get` | `consumes` | `error` | 0.35 |
| `get` | `consumes` | `int` | 0.35 |
| `must` | `depends_on` | `beacon` | 0.35 |
| `must` | `depends_on` | `json` | 0.35 |
| `must` | `depends_on` | `server` | 0.35 |
| `not` | `depends_on` | `beacon` | 0.35 |
| `output` | `consumes` | `error` | 0.35 |
| `output` | `consumes` | `int` | 0.35 |
| `server` | `depends_on` | `bsb` | 0.35 |
| `server` | `depends_on` | `config` | 0.35 |
| `server` | `depends_on` | `returns` | 0.35 |

## Dialectic Prompts

- Thesis: `aes` centralizes 23 files; Antithesis: `client` pulls 19 files with 11 shared (Jaccard 0.35); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `decrypt` pulls 22 files with 19 shared (Jaccard 0.73); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `encrypt` pulls 22 files with 18 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `get` pulls 23 files with 12 shared (Jaccard 0.35); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `key` pulls 22 files with 12 shared (Jaccard 0.36); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 23 files; Antithesis: `returns` pulls 19 files with 10 shared (Jaccard 0.31); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `bof` pulls 52 files with 19 shared (Jaccard 0.32); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `output` pulls 28 files with 14 shared (Jaccard 0.35); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `printf` pulls 17 files with 12 shared (Jaccard 0.39); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `auto` centralizes 59 files; Antithesis: `contract` pulls 65 files with 57 shared (Jaccard 0.85); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
