# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `mutants` | 74 | 75 | `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c`, `mutants/src/bof_api_versioning.c`, `mutants/src/bof_path_traversal_hardening.c` |
| `contract` | 68 | 76 | `c2/server.py`, `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `generated` | 63 | 75 | `c2/server.py`, `include/config_autogen.c`, `include/config_py.py`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c` |
| `implementation` | 60 | 64 | `config/generate_parsers.py`, `contract_agent.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c`, `mutants/src/beacon_heartbeat___health_endpoint.c` |
| `auto` | 60 | 61 | `c2/server.py`, `include/config_autogen.c`, `include/config_py_autogen.py`, `mutants/src/async_i_o_for_beacon.c`, `mutants/src/beacon_common.c_extraction.c` |
| `beacon` | 56 | 328 | `beacon.h`, `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `bof/cat/cat.c` |
| `bof` | 52 | 217 | `bof.c`, `bof/cat/bof.c`, `bof/cat/cat.c`, `bof/include/beacon_api.h`, `bof/include/syscalls.h` |
| `process` | 50 | 50 | `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/async_i_o_for_beacon.h`, `include/beacon_common.h` |
| `include` | 49 | 102 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `bof/suid_enum/bof.c`, `config/generate_parsers.py`, `include/aes.c` |
| `config` | 36 | 271 | `c2/server.py`, `c2/stage_oneliner.sh`, `c2/stage_payload.py`, `config/generate_parsers.py`, `include/beacon_common.h` |
| `not` | 31 | 88 | `aes.c`, `bof/include/syscalls.h`, `c2/server.py`, `c2/stage_payload.py`, `cJSON.c` |
| `placeholder` | 31 | 31 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_async_i_o_for_beacon_c.c`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c`, `mutants/tests/test_bof_api_versioning.py` |
| `bdd` | 29 | 46 | `contract_agent.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py` |
| `output` | 28 | 152 | `beacon.h`, `bof/cat/cat.c`, `bof/include/beacon_api.h`, `bof/is_sudo/is_sudo.c`, `bof/suid_enum/bof.c` |
| `run` | 27 | 63 | `c2/server.py`, `contract_agent.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config_autogen.c` |
| `api` | 26 | 64 | `beacon.h`, `bof/include/beacon_api.h`, `bof/suid_enum/bof.c`, `include/beacon.h`, `include/beacon_common.c` |
| `derived` | 26 | 38 | `c2/server.py`, `c2/stage_payload.py`, `include/config_py.py`, `include/config_py_autogen.py`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `key` | 25 | 163 | `aes.c`, `aes.h`, `c2/server.py`, `include/aes.c`, `include/aes.h` |
| `style` | 25 | 32 | `c2/server.py`, `include/beacon_common.h`, `include/config.c`, `include/config_autogen.c`, `mutants/tests/test_async_i_o_for_beacon.py` |
| `aes` | 24 | 127 | `aes.c`, `aes.h`, `c2/server.py`, `c2/stage_payload.py`, `include/aes.c` |
| `get` | 24 | 72 | `aes.c`, `bof/is_sudo/is_sudo.c`, `c2/server.py`, `cJSON.c`, `cJSON.h` |
| `must` | 24 | 36 | `c2/server.py`, `c2/stage_oneliner.sh`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.c` |
| `fail` | 23 | 33 | `c2/server.py`, `cJSON.c`, `include/beacon_common.c`, `include/beacon_common.h`, `include/cJSON.c` |
| `decrypt` | 22 | 47 | `aes.c`, `aes.h`, `c2/server.py`, `gopher_c2.py`, `include/aes.c` |
| `encrypt` | 22 | 40 | `aes.c`, `aes.h`, `c2/server.py`, `gopher_c2.py`, `include/aes.c` |
| `fails` | 22 | 32 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py`, `mutants/tests/test_bof_streaming_(large_outputs).py` |
| `server` | 21 | 97 | `c2/server.py`, `c2/stage_oneliner.sh`, `c2/stage_payload.py`, `include/beacon_common.h`, `include/config_autogen.c` |
| `build` | 21 | 69 | `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/cJSON.c`, `include/containerized_build_+_sbom.h` |
| `command` | 21 | 62 | `beacons/v1/beacon.c`, `beacons/v2/beacon.c`, `beacons/v3/beacon.c`, `c2/server.py`, `contract_agent.py` |
| `error` | 21 | 46 | `beacon.h`, `bof/include/beacon_api.h`, `cJSON.c`, `cJSON.h`, `include/beacon.h` |
| `return` | 20 | 127 | `bof/include/syscalls.h`, `c2/server.py`, `cJSON.c`, `contract_agent.py`, `include/beacon_common.c` |
| `path` | 20 | 84 | `bof/suid_enum/bof.c`, `c2/server.py`, `include/bof_path_traversal_hardening.h`, `include/config.h`, `include/config_autogen.h` |
| `client` | 20 | 45 | `c2/server.py`, `gopher_c2.py`, `include/beacon_common.c`, `include/beacon_common.h`, `include/config.h` |
| `json` | 19 | 220 | `c2/server.py`, `c2/stage_oneliner.sh`, `c2/stage_payload.py`, `cJSON.c`, `cJSON.h` |
| `bsb` | 19 | 176 | `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `c2/server.py`, `c2/stage_oneliner.sh`, `c2/stage_payload.py` |
| `size` | 19 | 71 | `aes.h`, `beacons/v2/beacon.c`, `bof/cat/cat.c`, `bof/include/syscalls.h`, `bof/is_sudo/is_sudo.c` |
| `bytes` | 19 | 65 | `aes.c`, `c2/server.py`, `cJSON.c`, `include/aes.c`, `include/aes_cfb.c` |
| `returns` | 19 | 59 | `bof/include/syscalls.h`, `c2/server.py`, `include/aes_cfb.c`, `include/beacon_common.c`, `include/beacon_common.h` |
| `value` | 19 | 47 | `aes.c`, `bof/suid_enum/bof.c`, `cJSON.c`, `cJSON.h`, `include/aes.c` |
| `until` | 19 | 20 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `specification` | 19 | 19 | `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_common.c_extraction.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `null` | 18 | 80 | `bof/cat/cat.c`, `bof/is_sudo/is_sudo.c`, `bof/userenum/userenum.c`, `bof/whoami/whoami.c`, `cJSON.c` |
| `when` | 17 | 132 | `c2/server.py`, `cJSON.c`, `include/cJSON.c`, `mutants/tests/test_c2_http_e2e.py`, `mutants/tests/test_certificate_pinning.py` |
| `int` | 17 | 64 | `beacon.h`, `bof/include/beacon_api.h`, `bof/include/syscalls.h`, `cJSON.h`, `include/beacon.h` |
| `via` | 17 | 33 | `bof/include/beacon_api.h`, `c2/server.py`, `c2/stage_payload.py`, `contract_agent.py`, `include/beacon_common.c` |
| `printf` | 17 | 26 | `beacon.h`, `bof/cat/cat.c`, `bof/is_sudo/is_sudo.c`, `bof/userenum/userenum.c`, `bof/whoami/whoami.c` |
| `complete` | 17 | 18 | `c2/server.py`, `mutants/tests/test_async_i_o_for_beacon.py`, `mutants/tests/test_beacon_heartbeat___health_endpoint.py`, `mutants/tests/test_bof_api_versioning.py`, `mutants/tests/test_bof_path_traversal_hardening.py` |
| `then` | 16 | 121 | `bof/include/beacon_api.h`, `mutants/tests/test_beacon_build.py`, `mutants/tests/test_c2_server.py`, `mutants/tests/test_certificate_pinning.py`, `mutants/tests/test_crypto.py` |
| `length` | 16 | 56 | `beacon.h`, `bof/include/beacon_api.h`, `bof/suid_enum/bof.c`, `cJSON.c`, `include/beacon.h` |
| `url` | 16 | 35 | `c2/server.py`, `c2/stage_oneliner.sh`, `c2/stage_payload.py`, `include/beacon_common.c`, `include/beacon_common.h` |

## Verb Edges

| Source | Verb | Target | Strength |
|--------|------|--------|----------|
| `contract` | `depends_on` | `include` | 1.00 |
| `generated` | `depends_on` | `include` | 0.93 |
| `auto` | `depends_on` | `include` | 0.89 |
| `implementation` | `depends_on` | `include` | 0.87 |
| `contract` | `depends_on` | `process` | 0.80 |
| `process` | `depends_on` | `include` | 0.73 |
| `generated` | `depends_on` | `process` | 0.71 |
| `implementation` | `depends_on` | `process` | 0.71 |
| `auto` | `depends_on` | `process` | 0.67 |
| `mutants` | `depends_on` | `include` | 0.58 |
| `bof` | `depends_on` | `include` | 0.56 |
| `beacon` | `depends_on` | `include` | 0.49 |
| `bof` | `depends_on` | `bsb` | 0.49 |
| `config` | `depends_on` | `bsb` | 0.49 |
| `config` | `depends_on` | `returns` | 0.49 |
| `config` | `depends_on` | `key` | 0.47 |
| `beacon` | `depends_on` | `bsb` | 0.44 |
| `mutants` | `depends_on` | `process` | 0.44 |
| `beacon` | `depends_on` | `returns` | 0.42 |
| `contract` | `depends_on` | `beacon` | 0.42 |
| `beacon` | `depends_on` | `config` | 0.40 |
| `bytes` | `depends_on` | `include` | 0.40 |
| `must` | `depends_on` | `bsb` | 0.40 |
| `must` | `depends_on` | `config` | 0.40 |
| `must` | `depends_on` | `key` | 0.40 |
| `must` | `depends_on` | `returns` | 0.40 |
| `not` | `depends_on` | `bsb` | 0.40 |
| `not` | `depends_on` | `config` | 0.40 |
| `not` | `depends_on` | `key` | 0.40 |
| `not` | `depends_on` | `returns` | 0.40 |
| `server` | `depends_on` | `bsb` | 0.40 |
| `server` | `depends_on` | `config` | 0.40 |
| `server` | `depends_on` | `returns` | 0.40 |
| `beacon` | `depends_on` | `server` | 0.38 |
| `bof` | `depends_on` | `returns` | 0.38 |
| `config` | `depends_on` | `include` | 0.38 |
| `not` | `depends_on` | `json` | 0.38 |
| `not` | `depends_on` | `server` | 0.38 |
| `server` | `depends_on` | `key` | 0.38 |
| `beacon` | `consumes` | `error` | 0.36 |
| `beacon` | `consumes` | `int` | 0.36 |
| `bof` | `depends_on` | `int` | 0.36 |
| `bytes` | `depends_on` | `bsb` | 0.36 |
| `config` | `depends_on` | `server` | 0.36 |
| `include` | `depends_on` | `bsb` | 0.36 |
| `must` | `depends_on` | `beacon` | 0.36 |
| `must` | `depends_on` | `json` | 0.36 |
| `must` | `depends_on` | `server` | 0.36 |
| `not` | `depends_on` | `beacon` | 0.36 |
| `server` | `depends_on` | `beacon` | 0.36 |

## Dialectic Prompts

- Thesis: `aes` centralizes 24 files; Antithesis: `bytes` pulls 19 files with 10 shared (Jaccard 0.30); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `client` pulls 20 files with 11 shared (Jaccard 0.33); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `decrypt` pulls 22 files with 19 shared (Jaccard 0.70); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `encrypt` pulls 22 files with 18 shared (Jaccard 0.64); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `get` pulls 24 files with 12 shared (Jaccard 0.33); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `key` pulls 25 files with 13 shared (Jaccard 0.36); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `returns` pulls 19 files with 10 shared (Jaccard 0.30); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `run` pulls 27 files with 12 shared (Jaccard 0.31); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `aes` centralizes 24 files; Antithesis: `url` pulls 16 files with 10 shared (Jaccard 0.33); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `api` centralizes 26 files; Antithesis: `bof` pulls 52 files with 19 shared (Jaccard 0.32); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
