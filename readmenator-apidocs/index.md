# blacksandbeacon API Reference

> Generated offline by readmenator: 104 modules, 1028 documented entities, documentation coverage 35.9% (350/974 public items). Deterministic, zero tokens: signatures from source, docs parsed from Google, NumPy, reST, Javadoc/JSDoc/Doxygen, C# XML, and Rustdoc comments.

Navigate: [Interactive architecture and flows](flows.html) | [Architecture and flows (Mermaid)](architecture.md) | [Class hierarchy](classes.md) | [General index](genindex.md) | [Coverage and warnings](COVERAGE.md) | [`api/index.json`](api/index.json) | [HTML browser](index.html)

Languages: c (64), h (30), py (9), sh (1)

## Modules

### `.`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`aes.c`](modules/aes.c.md) | aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) | 0 | 23 | 33.3% |
| [`aes.h`](modules/aes.h.md) | #define the macros below to 1/0 to enable/disable the mode of operation. | 1 | 19 | 23.8% |
| [`app`](modules/app.py.md) | app.py | 0 | 0 | 100.0% |
| [`beacon.h`](modules/beacon.h.md) | beacon_api.h Tipos de callback Estructura para parsing de datos (opcional, para comandos complejos) | 1 | 11 | 46.2% |
| [`bof.c`](modules/bof.c.md) | bof.c | 0 | 1 | 50.0% |
| [`cJSON.c`](modules/cJSON.c.md) |  | 4 | 84 | 6.7% |
| [`cJSON.h`](modules/cJSON.h.md) |  | 3 | 36 | 20.0% |
| [`contract_agent`](modules/contract_agent.py.md) | Contract Driven Agent - SDD/TDD/BDD workflow for Black Sand Beacon v2. | 0 | 17 | 77.8% |
| [`gopher_c2`](modules/gopher_c2.py.md) |  | 0 | 4 | 0.0% |
| [`install.sh`](modules/install.sh.md) | install.sh - Install build deps and build everything. | 0 | 0 | 100.0% |
| [`issudo.c`](modules/issudo.c.md) |  | 2 | 11 | 57.1% |
| [`mutmut_config`](modules/mutmut_config.py.md) |  | 0 | 0 | 0.0% |

### `beacons/v1`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`beacons/v1/beacon.c`](modules/beacons.v1.beacon.c.md) |  | 0 | 2 | 33.3% |

### `beacons/v2`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`beacons/v2/beacon.c`](modules/beacons.v2.beacon.c.md) |  | 2 | 7 | 10.0% |

### `beacons/v3`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`beacons/v3/beacon.c`](modules/beacons.v3.beacon.c.md) |  | 0 | 3 | 25.0% |

### `bof/cat`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/cat/bof.c`](modules/bof.cat.bof.c.md) |  | 0 | 1 | 0.0% |
| [`bof/cat/cat.c`](modules/bof.cat.cat.c.md) |  | 2 | 9 | 66.7% |

### `bof/include`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/include/beacon_api.h`](modules/bof.include.beacon_api.h.md) |  | 1 | 12 | 28.6% |
| [`bof/include/syscalls.h`](modules/bof.include.syscalls.h.md) |  | 0 | 37 | 13.2% |

### `bof/is_sudo`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/is_sudo/bof.c`](modules/bof.is_sudo.bof.c.md) |  | 0 | 1 | 0.0% |
| [`bof/is_sudo/is_sudo.c`](modules/bof.is_sudo.is_sudo.c.md) |  | 2 | 11 | 57.1% |

### `bof/suid_enum`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/suid_enum/bof.c`](modules/bof.suid_enum.bof.c.md) |  | 2 | 6 | 44.4% |

### `bof/userenum`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/userenum/bof.c`](modules/bof.userenum.bof.c.md) |  | 0 | 1 | 0.0% |
| [`bof/userenum/userenum.c`](modules/bof.userenum.userenum.c.md) |  | 2 | 9 | 66.7% |

### `bof/whoami`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`bof/whoami/bof.c`](modules/bof.whoami.bof.c.md) |  | 0 | 1 | 0.0% |
| [`bof/whoami/whoami.c`](modules/bof.whoami.whoami.c.md) |  | 2 | 10 | 61.5% |

### `c2`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`c2`](modules/c2.__init__.py.md) |  | 0 | 0 | 0.0% |
| [`c2.server`](modules/c2.server.py.md) | Black Sand Beacon C2 Server | 1 | 16 | 94.4% |

### `config`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`config.generate_parsers`](modules/config.generate_parsers.py.md) | Config Parser Generator for Black Sand Beacon | 0 | 7 | 75.0% |

### `include`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`include/aes.c`](modules/include.aes.c.md) | aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) | 0 | 23 | 33.3% |
| [`include/aes.h`](modules/include.aes.h.md) | #define the macros below to 1/0 to enable/disable the mode of operation. | 1 | 19 | 23.8% |
| [`include/aes_cfb.c`](modules/include.aes_cfb.c.md) |  | 0 | 4 | 60.0% |
| [`include/aes_cfb.h`](modules/include.aes_cfb.h.md) |  | 0 | 2 | 33.3% |
| [`include/async_i_o_for_beacon.h`](modules/include.async_i_o_for_beacon.h.md) |  | 0 | 1 | 0.0% |
| [`include/beacon.h`](modules/include.beacon.h.md) | beacon_api.h Tipos de callback Estructura para parsing de datos (opcional, para comandos complejos) | 1 | 11 | 46.2% |
| [`include/beacon_common.c`](modules/include.beacon_common.c.md) |  | 2 | 23 | 73.1% |
| [`include/beacon_common.c_extraction.h`](modules/include.beacon_common.c_extraction.h.md) |  | 0 | 1 | 0.0% |
| [`include/beacon_common.h`](modules/include.beacon_common.h.md) |  | 5 | 28 | 67.6% |
| [`include/beacon_heartbeat___health_endpoint.h`](modules/include.beacon_heartbeat___health_endpoint.h.md) |  | 0 | 1 | 0.0% |
| [`include/bof_api_versioning.h`](modules/include.bof_api_versioning.h.md) |  | 0 | 1 | 0.0% |
| [`include/bof_path_traversal_hardening.h`](modules/include.bof_path_traversal_hardening.h.md) |  | 0 | 1 | 0.0% |
| [`include/bof_streaming_(large_outputs).h`](modules/include.bof_streaming__large_outputs_.h.md) |  | 0 | 2 | 0.0% |
| [`include/c2_rest_api.h`](modules/include.c2_rest_api.h.md) |  | 0 | 1 | 0.0% |
| [`include/cJSON.c`](modules/include.cJSON.c.md) |  | 4 | 84 | 6.7% |
| [`include/cJSON.h`](modules/include.cJSON.h.md) |  | 3 | 36 | 20.0% |
| [`include/certificate_pinning___tofu.h`](modules/include.certificate_pinning___tofu.h.md) |  | 0 | 1 | 0.0% |
| [`include/command_execution_via_execve.h`](modules/include.command_execution_via_execve.h.md) |  | 0 | 1 | 0.0% |
| [`include/config.c`](modules/include.config.c.md) |  | 0 | 7 | 50.0% |
| [`include/config.h`](modules/include.config.h.md) |  | 7 | 13 | 19.0% |
| [`include/config_autogen.c`](modules/include.config_autogen.c.md) |  | 0 | 2 | 66.7% |
| [`include/config_autogen.h`](modules/include.config_autogen.h.md) |  | 8 | 3 | 25.0% |
| [`include.config_py`](modules/include.config_py.py.md) | config_py.py - Python loader for BSB JSON config files. | 0 | 1 | 100.0% |
| [`include.config_py_autogen`](modules/include.config_py_autogen.py.md) | Auto-generated Python config loader from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate | 0 | 1 | 100.0% |
| [`include/containerized_build_+_sbom.h`](modules/include.containerized_build___sbom.h.md) |  | 0 | 1 | 0.0% |
| [`include/hkdf_key_derivation.h`](modules/include.hkdf_key_derivation.h.md) |  | 0 | 1 | 0.0% |
| [`include/iv_generation_with_entropy_verification.h`](modules/include.iv_generation_with_entropy_verification.h.md) |  | 0 | 1 | 0.0% |
| [`include/pre-commit_+_ci_hardening.h`](modules/include.pre-commit___ci_hardening.h.md) |  | 0 | 1 | 0.0% |
| [`include/replay_protection.h`](modules/include.replay_protection.h.md) |  | 0 | 1 | 0.0% |
| [`include/socks5___http_proxy_support.h`](modules/include.socks5___http_proxy_support.h.md) |  | 0 | 1 | 0.0% |
| [`include/structured_jsonl_logging.h`](modules/include.structured_jsonl_logging.h.md) |  | 0 | 1 | 0.0% |
| [`include/tls_client_certificate_authentication.h`](modules/include.tls_client_certificate_authentication.h.md) |  | 0 | 1 | 0.0% |
| [`include/unified_config_schema.h`](modules/include.unified_config_schema.h.md) |  | 0 | 1 | 0.0% |

### `legacy`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`legacy/beacon3.c`](modules/legacy.beacon3.c.md) |  | 4 | 18 | 60.9% |
| [`legacy/beacon5.c`](modules/legacy.beacon5.c.md) |  | 6 | 32 | 38.5% |
| [`legacy/beacon6.c`](modules/legacy.beacon6.c.md) |  | 4 | 18 | 60.9% |
| [`legacy/beacon_p2p.c`](modules/legacy.beacon_p2p.c.md) |  | 6 | 37 | 40.9% |
| [`legacy/gopher_beacon.c`](modules/legacy.gopher_beacon.c.md) |  | 4 | 18 | 60.9% |
| [`legacy/v1_gopher_beacon.c`](modules/legacy.v1_gopher_beacon.c.md) |  | 4 | 18 | 60.9% |

### `mutants/src`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`mutants/src/async_i_o_for_beacon.c`](modules/mutants.src.async_i_o_for_beacon.c.md) | Auto-generated implementation for contract: Async I/O for Beacon | 0 | 1 | 50.0% |
| [`mutants/src/beacon_common.c_extraction.c`](modules/mutants.src.beacon_common.c_extraction.c.md) | Auto-generated implementation for contract: beacon_common.c Extraction | 0 | 0 | 100.0% |
| [`mutants/src/beacon_heartbeat___health_endpoint.c`](modules/mutants.src.beacon_heartbeat___health_endpoint.c.md) | Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint | 0 | 1 | 50.0% |
| [`mutants/src/bof_api_versioning.c`](modules/mutants.src.bof_api_versioning.c.md) | Auto-generated implementation for contract: BOF API Versioning | 0 | 1 | 50.0% |
| [`mutants/src/bof_path_traversal_hardening.c`](modules/mutants.src.bof_path_traversal_hardening.c.md) | Auto-generated implementation for contract: BOF Path Traversal Hardening | 0 | 1 | 50.0% |
| [`mutants/src/bof_streaming_(large_outputs).c`](modules/mutants.src.bof_streaming__large_outputs_.c.md) | Auto-generated implementation for contract: BOF Streaming (Large Outputs) | 0 | 1 | 50.0% |
| [`mutants/src/c2_rest_api.c`](modules/mutants.src.c2_rest_api.c.md) | Auto-generated implementation for contract: C2 REST API | 0 | 1 | 50.0% |
| [`mutants/src/certificate_pinning___tofu.c`](modules/mutants.src.certificate_pinning___tofu.c.md) | Auto-generated implementation for contract: Certificate Pinning / TOFU | 0 | 1 | 50.0% |
| [`mutants/src/command_execution_via_execve.c`](modules/mutants.src.command_execution_via_execve.c.md) | Auto-generated implementation for contract: Command Execution via execve | 0 | 1 | 50.0% |
| [`mutants/src/containerized_build_+_sbom.c`](modules/mutants.src.containerized_build___sbom.c.md) | Auto-generated implementation for contract: Containerized Build + SBOM | 0 | 0 | 100.0% |
| [`mutants/src/hkdf_key_derivation.c`](modules/mutants.src.hkdf_key_derivation.c.md) | Auto-generated implementation for contract: HKDF Key Derivation | 0 | 1 | 50.0% |
| [`mutants/src/iv_generation_with_entropy_verification.c`](modules/mutants.src.iv_generation_with_entropy_verification.c.md) | Auto-generated implementation for contract: IV Generation with Entropy Verification | 0 | 1 | 50.0% |
| [`mutants/src/pre-commit_+_ci_hardening.c`](modules/mutants.src.pre-commit___ci_hardening.c.md) | Auto-generated implementation for contract: Pre-commit + CI Hardening | 0 | 0 | 100.0% |
| [`mutants/src/replay_protection.c`](modules/mutants.src.replay_protection.c.md) | Auto-generated implementation for contract: Replay Protection | 0 | 1 | 50.0% |
| [`mutants/src/socks5___http_proxy_support.c`](modules/mutants.src.socks5___http_proxy_support.c.md) | Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support | 0 | 1 | 50.0% |
| [`mutants/src/structured_jsonl_logging.c`](modules/mutants.src.structured_jsonl_logging.c.md) | Auto-generated implementation for contract: Structured JSONL Logging | 0 | 1 | 50.0% |
| [`mutants/src/tls_client_certificate_authentication.c`](modules/mutants.src.tls_client_certificate_authentication.c.md) | Auto-generated implementation for contract: TLS Client Certificate Authentication | 0 | 1 | 50.0% |
| [`mutants/src/unified_config_schema.c`](modules/mutants.src.unified_config_schema.c.md) | Auto-generated implementation for contract: Unified Config Schema | 0 | 1 | 50.0% |

### `src`

| Module | Summary | Types | Callables | Coverage |
|---|---|---|---|---|
| [`src/async_i_o_for_beacon.c`](modules/src.async_i_o_for_beacon.c.md) | Auto-generated implementation for contract: Async I/O for Beacon | 0 | 1 | 50.0% |
| [`src/beacon_common.c_extraction.c`](modules/src.beacon_common.c_extraction.c.md) | Auto-generated implementation for contract: beacon_common.c Extraction | 0 | 0 | 100.0% |
| [`src/beacon_heartbeat___health_endpoint.c`](modules/src.beacon_heartbeat___health_endpoint.c.md) | Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint | 0 | 1 | 50.0% |
| [`src/bof_api_versioning.c`](modules/src.bof_api_versioning.c.md) | Auto-generated implementation for contract: BOF API Versioning | 0 | 1 | 50.0% |
| [`src/bof_path_traversal_hardening.c`](modules/src.bof_path_traversal_hardening.c.md) | Auto-generated implementation for contract: BOF Path Traversal Hardening | 0 | 1 | 50.0% |
| [`src/bof_streaming_(large_outputs).c`](modules/src.bof_streaming__large_outputs_.c.md) | Auto-generated implementation for contract: BOF Streaming (Large Outputs) | 0 | 1 | 50.0% |
| [`src/c2_rest_api.c`](modules/src.c2_rest_api.c.md) | Auto-generated implementation for contract: C2 REST API | 0 | 1 | 50.0% |
| [`src/certificate_pinning___tofu.c`](modules/src.certificate_pinning___tofu.c.md) | Auto-generated implementation for contract: Certificate Pinning / TOFU | 0 | 1 | 50.0% |
| [`src/command_execution_via_execve.c`](modules/src.command_execution_via_execve.c.md) | Auto-generated implementation for contract: Command Execution via execve | 0 | 1 | 50.0% |
| [`src/containerized_build_+_sbom.c`](modules/src.containerized_build___sbom.c.md) | Auto-generated implementation for contract: Containerized Build + SBOM | 0 | 0 | 100.0% |
| [`src/hkdf_key_derivation.c`](modules/src.hkdf_key_derivation.c.md) | Auto-generated implementation for contract: HKDF Key Derivation | 0 | 1 | 50.0% |
| [`src/iv_generation_with_entropy_verification.c`](modules/src.iv_generation_with_entropy_verification.c.md) | Auto-generated implementation for contract: IV Generation with Entropy Verification | 0 | 1 | 50.0% |
| [`src/pre-commit_+_ci_hardening.c`](modules/src.pre-commit___ci_hardening.c.md) | Auto-generated implementation for contract: Pre-commit + CI Hardening | 0 | 0 | 100.0% |
| [`src/replay_protection.c`](modules/src.replay_protection.c.md) | Auto-generated implementation for contract: Replay Protection | 0 | 1 | 50.0% |
| [`src/socks5___http_proxy_support.c`](modules/src.socks5___http_proxy_support.c.md) | Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support | 0 | 1 | 50.0% |
| [`src/structured_jsonl_logging.c`](modules/src.structured_jsonl_logging.c.md) | Auto-generated implementation for contract: Structured JSONL Logging | 0 | 1 | 50.0% |
| [`src/tls_client_certificate_authentication.c`](modules/src.tls_client_certificate_authentication.c.md) | Auto-generated implementation for contract: TLS Client Certificate Authentication | 0 | 1 | 50.0% |
| [`src/unified_config_schema.c`](modules/src.unified_config_schema.c.md) | Auto-generated implementation for contract: Unified Config Schema | 0 | 1 | 50.0% |
