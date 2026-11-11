# Black Sand Beacon v2 — Security Hardening Contracts

## Contract: Certificate Pinning / TOFU

**Purpose:** Add certificate pinning with Trust-On-First-Use (TOFU) to prevent MITM attacks on the C2 channel.

**Requirements:**
- New config field `network.cert_fingerprint_sha256` (optional, 64 hex chars)
- On first successful TLS connection, if fingerprint not set, store it (TOFU)
- On subsequent connections, verify presented cert matches pinned fingerprint
- Fail closed if mismatch (no fallback)
- Configurable via `config.json` and environment variable `BSB_CERT_FINGERPRINT`

**Security Guarantees:**
- Zero Trust: no implicit trust of CAs
- Fail-closed: connection aborts on pin mismatch
- Agent-Safe: deterministic verification logic

---

## Contract: HKDF Key Derivation

**Purpose:** Replace raw hex key usage with HKDF-SHA256 to derive separate encryption and HMAC keys from a master secret.

**Requirements:**
- New config field `crypto.master_key_hex` (64 hex chars = 32 bytes)
- Derive `encryption_key` (32 bytes) and `hmac_key` (32 bytes) using HKDF-SHA256
- Salt: `b"blacksandbeacon-v2"` (domain separation)
- Info: `b"enc"` for encryption, `b"hmac"` for authentication
- Backward compat: if `aes_key_hex` present and `master_key_hex` absent, derive from `aes_key_hex` with warning
- Both C (`config.c`) and Python (`config_py.py`, `c2/server.py`) implementations must match exactly

**Security Guarantees:**
- Key separation: encryption and auth use independent keys
- Domain separation: salt prevents cross-protocol key reuse
- Post-Quantum by Default: SHA256-based KDF

---

## Contract: IV Generation with Entropy Verification

**Purpose:** Ensure IV generation never uses weak entropy; verify `RAND_bytes` success and fallback to `getrandom(2)`.

**Requirements:**
- `aes256_cfb_encrypt` checks `RAND_bytes` return value (1 = success)
- On failure, call `getrandom(iv, 16, GRND_NONBLOCK)` 
- If `getrandom` fails, abort encryption with error (fail-closed)
- Same logic in Python using `os.urandom` (which already blocks on entropy)
- Unit test that simulates `RAND_bytes` failure

**Security Guarantees:**
- Zero Knowledge: no weak IVs ever produced
- Fail-closed: no silent degradation
- Agent-Safe: deterministic error behavior

---

## Contract: Replay Protection

**Purpose:** Prevent replay attacks by adding monotonic counter + timestamp to encrypted payloads.

**Requirements:**
- Beacon maintains `uint64_t message_counter` (persisted in memory, reset on restart)
- Server tracks `last_seen_counter` per client_id
- Encrypted payload format: `iv (16) || counter (8, LE) || timestamp (8, LE) || ciphertext`
- Server rejects if `counter <= last_seen_counter` OR `timestamp > now + 60s` OR `timestamp < now - 300s`
- Config field `crypto.replay_window_seconds` (default 300)
- Counter transmitted in plaintext inside encrypted envelope (authenticated via AES-CFB)

**Security Guarantees:**
- Zero Trust: no implicit trust of message freshness
- Replay window bounded by config
- Agent-Safe: structured, verifiable payload format

---

## Contract: BOF Path Traversal Hardening

**Purpose:** Strengthen BOF serving against path traversal beyond `os.path.basename`.

**Requirements:**
- `handle_bof` resolves `upload_dir` to absolute path with `os.path.realpath`
- Requested BOF path resolved to absolute path with `os.path.realpath`
- Verify requested path starts with resolved `upload_dir` (prefix check)
- Reject with `BOF_NOT_FOUND` if outside upload directory
- Add test with `../../etc/passwd` style payloads

**Security Guarantees:**
- Zero Trust: no filesystem trust
- Path traversal eliminated
- Agent-Safe: clear reject behavior

---

## Contract: Command Execution via execve

**Purpose:** Replace `system()`/`popen()` with `execve` + argv array to prevent shell injection.

**Requirements:**
- New function `exec_cmd_safe(const char *command, int *out_len)` in `beacon_common.c`
- Parse command string into argv array (simple space split, respecting quotes)
- Use `posix_spawn` or `fork` + `execve` with argv
- Capture stdout/stderr via pipe
- No shell interpretation ever
- Fallback: if parsing fails, treat as single argv[0] with no args

**Security Guarantees:**
- Zero Trust: no shell interpretation
- Command injection eliminated
- Agent-Safe: deterministic argument parsing

---

## Contract: beacon_common.c Extraction

**Purpose:** Extract shared beacon logic (HTTP, crypto, BOF loader, output capture) into `beacons/v1/beacon_common.c` so v2/v3 can reuse.

**Requirements:**
- Move from `beacons/v1/beacon.c`:
  - `https_request`, `base64_encode/decode`, `url_encode`
  - `aes256_cfb_encrypt/decrypt` wrappers
  - `download_bof`, `run_bof_and_capture`
  - `exec_cmd` → `exec_cmd_safe`
  - `get_local_ips`, `bsb_output_init/cleanup`, `bsb_backoff_init/next/reset`
  - `bsb_config_sleep_seconds`
- Create `beacons/v1/beacon_common.h` with public API
- Update `beacons/v1/beacon.c` to include and use common
- Update `Makefile` `COMMON_SRC` to include `beacons/v1/beacon_common.c`
- v2/v3 beacons include `beacon_common.h` and link common object

**Architecture:**
- DRY: single source of truth for shared logic
- YAGNI: no over-abstraction, just extraction

---

## Contract: Unified Config Schema

**Purpose:** Single source of truth for config schema; generate C and Python parsers from it.

**Requirements:**
- Create `config/schema.json` with JSON Schema (Draft 7) describing all config sections
- Python script `config/generate_parsers.py` reads schema and:
  - Generates `include/config_autogen.h` with struct definitions
  - Generates `include/config_autogen.c` with parser (replaces manual `config.c`)
  - Generates `include/config_py_autogen.py` with `load_config` (replaces `config_py.py`)
- `Makefile` adds `generate-config` target that runs the generator
- CI runs `make generate-config` and fails if checked-in parsers diverge

**Architecture:**
- DRY: schema is single source of truth
- Generated code is checked in (reviewable diff)

---

## Contract: BOF API Versioning

**Purpose:** Add version negotiation between beacon and BOF to prevent ABI mismatches.

**Requirements:**
- `bof/include/beacon_api.h`: add `#define BEACON_API_VERSION 2`
- Beacon exports `uint32_t beacon_api_version(void)` returning `BEACON_API_VERSION`
- BOF `go` function signature unchanged, but can call `beacon_api_version()`
- Beacon loader (`run_bof_and_capture`) checks BOF's expected version via symbol `beacon_abi_version` (weak symbol in BOF, default 1)
- If mismatch, beacon logs warning and refuses to run BOF (returns error output)
- Config field `bof.strict_version_check` (default true)

**Security Guarantees:**
- Zero Trust: no implicit ABI compatibility
- Version skew detected at load time
- Agent-Safe: structured version contract

---

## Contract: Structured JSONL Logging

**Purpose:** Replace CSV logs with JSONL for easier querying and SIEM integration.

**Requirements:**
- Config field `server.log_format` = `csv` | `jsonl` (default `jsonl`)
- `C2State` writes JSONL: one line per report with all fields
- Fields: `timestamp`, `client_id`, `os`, `pid`, `hostname`, `ips`, `user`, `discovered_ips`, `result_portscan`, `result_pwd`, `command`, `output`
- Timestamp: ISO8601 UTC (`2024-01-15T10:30:00Z`)
- Backward compat: CSV still works if `log_format: csv`
- Test verifies both formats parse correctly

**Architecture:**
- YAGNI: only two formats, no pluggable system

---

## Contract: Mutation Testing Integration

**Purpose:** Ensure test suite catches mutants (killed mutants = good tests).

**Requirements:**
- Add `mutmut` for Python tests (`pip install mutmut`)
- Add `mutate` (LLVM) or custom C mutation for C tests
- `make mutation-test` runs mutation testing on both test suites
- Threshold: >= 80% mutation score required for CI pass
- Mutants that survive must have corresponding test added

**Verification:**
- Run `mutmut run --paths-to-mutate c2/ tests/` for Python
- For C: compile with `-fmutation` or use custom script that injects mutants

---

## Contract: Pre-commit + CI Hardening

**Purpose:** Automate formatting, linting, and security checks.

**Requirements:**
- `.pre-commit-config.yaml` with:
  - `clang-format` for C files
  - `black` + `ruff` for Python
  - `cppcheck` for C static analysis
  - `shellcheck` for shell scripts
  - `detect-secrets` for key leakage
  - `hadolint` for Dockerfile
- `Makefile` targets: `fmt`, `lint`, `pre-commit-install`
- GitHub Actions CI runs `make fmt lint test mutation-test`

---

## Contract: Containerized Build + SBOM

**Purpose:** Reproducible builds and supply chain transparency.

**Requirements:**
- `Dockerfile.build` multi-stage: builder (gcc, libssl-dev, libcurl4-openssl-dev) → scratch with static binary
- `make docker-build` produces `build/beacon-static`
- `make sbom` runs `syft build/beacon-static -o spdx-json > sbom.spdx.json`
- CI uploads SBOM as artifact

---

## Contract: SOCKS5 / HTTP Proxy Support

**Purpose:** Allow beacon egress via proxy.

**Requirements:**
- Config fields: `network.proxy_type` (none|socks5|http), `network.proxy_host`, `network.proxy_port`, `network.proxy_user`, `network.proxy_pass`
- `https_request` uses `curl_easy_setopt(curl, CURLOPT_PROXY, ...)` and related options
- Proxy credentials in config (not baked in binary)
- Test with local proxy (e.g., `socat` or `mitmproxy` in test)

---

## Contract: TLS Client Certificate Authentication

**Purpose:** Mutual TLS for beacon ↔ C2.

**Requirements:**
- Config fields: `network.client_cert_path`, `network.client_key_path`
- `https_request` loads cert/key via `CURLOPT_SSLCERT` / `CURLOPT_SSLKEY`
- Server (`c2/server.py`) verifies client cert if `hmac_enabled: true` (reuse TLS stack)
- CA cert for verification: `network.ca_cert_path`
- Test with self-signed CA + client cert

---

## Contract: C2 REST API

**Purpose:** Programmatic control of C2 for automation.

**Requirements:**
- New Flask/FastAPI server in `c2/api.py` (or extend `server.py`)
- Endpoints:
  - `GET /api/v1/clients` — list connected clients
  - `POST /api/v1/commands` — queue command `{client_id, command}`
  - `GET /api/v1/results/<client_id>` — fetch results
  - `GET /api/v1/health` — server health
- Auth: Bearer token from config `server.api_token`
- Runs on separate port `server.api_port` (default 7071)
- OpenAPI spec at `/api/v1/openapi.json`

---

## Contract: Beacon Heartbeat / Health Endpoint

**Purpose:** Lightweight beacon health check without full command roundtrip.

**Requirements:**
- New endpoint `GET /api/poll/<client_id>/health`
- Returns JSON: `{client_id, uptime_seconds, config_hash, beacon_version, last_poll_ts}`
- Encrypted with same AES-CFB + HMAC as regular poll
- Beacon calls health endpoint every `timing.health_interval_seconds` (default 300) if no commands pending
- Config field `timing.health_interval_seconds`

---

## Contract: BOF Streaming (Large Outputs)

**Purpose:** Support BOF outputs larger than 64KB buffer.

**Requirements:**
- `BeaconOutput` callback supports `CALLBACK_OUTPUT_STREAM` (new type 0x0F)
- BOF can call `BeaconOutput` multiple times with chunks
- Beacon accumulates chunks in memory (configurable max `bof.max_output_size`, default 1MB)
- On BOF completion, sends accumulated output as single report
- Config field `bof.max_output_size`

---

## Contract: Async I/O for Beacon

**Purpose:** Non-blocking beacon loop using libcurl multi interface.

**Requirements:**
- Replace blocking `https_request` + `sleep` with `curl_multi` event loop
- Single thread handles: DNS, connect, TLS, request, response, BOF execution
- BOF execution runs in thread pool (config `server.bof_workers`, default 2)
- `bsb_backoff` integrated into event loop timers
- Significant refactor; behind feature flag `network.async_io` (default false for v2)

---

## Mutation Testing Requirements (All Contracts)

**Every contract MUST include:**
1. **Python tests** in `tests/test_<contract>.py` — run with `mutmut`
2. **C tests** in `tests/test_<contract>_c.c` — run with custom mutation script
3. **Mutation score threshold:** >= 80% for both suites
4. **Surviving mutants** = test gaps → add tests until killed

**Mutation operators (minimum):**
- Arithmetic replacement (+ → -, * → /, etc.)
- Relational replacement (< → >, == → !=, etc.)
- Logical replacement (&& → ||, ! → removed)
- Constant replacement (0 → 1, 1 → 0, "string" → "")
- Statement deletion
- Return value replacement

---

## Execution Order (Dependencies)

1. **Certificate Pinning** (foundational)
2. **HKDF Key Derivation** (foundational)
3. **IV Generation** (foundational)
4. **Replay Protection** (depends on HKDF)
5. **BOF Path Traversal** (independent)
6. **execve Command Execution** (independent)
7. **beacon_common.c Extraction** (enables v2/v3)
8. **Unified Config Schema** (enables all config changes)
9. **BOF API Versioning** (depends on beacon_common)
10. **JSONL Logging** (independent)
11. **Mutation Testing** (parallel, ongoing)
12. **Pre-commit/CI** (parallel, ongoing)
13. **Docker/SBOM** (parallel, ongoing)
14. **Proxy Support** (depends on beacon_common)
15. **mTLS** (depends on beacon_common)
16. **C2 REST API** (independent)
17. **Beacon Heartbeat** (depends on beacon_common)
18. **BOF Streaming** (depends on beacon_common)
19. **Async I/O** (last, major refactor)

---

## Verification Commands

```bash
# Build and test
make clean && make all-beacons bofs test

# Mutation testing
make mutation-test

# Formatting & linting
make fmt lint

# Pre-commit
pre-commit run --all-files

# Docker build
make docker-build

# SBOM
make sbom

# Static analysis
cppcheck --enable=all --inconclusive beacons/ include/ tests/*_harness.c

# ASan
make asan  # (add target to Makefile)
```

<!-- readmenator-agent-kb-link -->
## Project Knowledge Base (MUST read before coding)

Generated offline by [ReadMenator](https://github.com/grisuno/ReadMenator) (zero-token static analysis). Humans: `KNOWLEDGE_BASE.md`.

0. Memory: `cat readmenator-agent/MEMORY.md` (business rules, workflow, constraints, style, done criteria, session log). Record new decisions with `readmenator . remember "<note>" --kind decision`.
1. Freshness: `readmenator . fresh` (exit 1 means stale: run `readmenator . --rebuild`). Without the CLI, compare `git_commit` in `readmenator-agent/MANIFEST.json` with `git log -1`.
2. Orient: `ls *.md readmenator-agent/ readmenator-wiki/`, then read `readmenator-wiki/index.md` (big picture, communities, god nodes).
3. Locate: `grep -n '<keyword>' readmenator-agent/INDEX*.md readmenator-agent/SYMBOLS*.md` before any `glob` over sources; for questions use `readmenator . ask "<question>"` (GraphRAG, `--global` for overviews).
4. Context: `cat readmenator-agent/KB_<subsystem>.md` for the subsystem you touch.
5. Before editing: `grep -n '<file>' readmenator-agent/GOTCHAS.md readmenator-agent/SECURITY.md` (blast radius, cycles, findings).

Also: `API*.md` (public functions, one line each), `ARCHITECTURE*.md` (dependency pairs), `recipes/*.md` (grounded task steps). Large docs are paged as `NAME_p2.md`, so always grep with `NAME*.md`.

    pip install readmenator && readmenator . --rebuild
<!-- /readmenator-agent-kb-link -->
