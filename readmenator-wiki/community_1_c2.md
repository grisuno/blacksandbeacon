# c2

*Community 1 | 15 files | cohesion 1.00*

## Definition

This community groups 15 file(s) rooted at `tests` with dominant language py (cohesion 1.00). Central symbols: `C2State`, `Handler`, `TestBOFPathTraversalConfig`, `TestBOFPathTraversalMutationResistance`, `TestBOFPathTraversalServer`, `TestC2BeaconBOFIntegration`, `TestCertificatePinningCConfig`, `TestCertificatePinningConfig`. Core file: `tests/test_replay_protection.py` (28 symbols). Documented purpose: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. Handles command queuing, result collection, and BOF distribut.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `c2/__init__.py` | py | utility | 0 | no |
| `c2/server.py` | py | utility | 21 | yes |
| `include/config_py.py` | py | infrastructure | 3 | yes |
| `mutants/tests/test_c2_http_e2e.py` | py | testing | 9 | yes |
| `mutants/tests/test_c2_server.py` | py | testing | 11 | yes |
| `mutants/tests/test_certificate_pinning.py` | py | testing | 16 | yes |
| `tests/test_bof_path_traversal.py` | py | testing | 18 | yes |
| `tests/test_c2_beacon_bof_integration.py` | py | testing | 10 | yes |
| `tests/test_c2_http_e2e.py` | py | testing | 9 | yes |
| `tests/test_c2_server.py` | py | testing | 11 | yes |
| `tests/test_certificate_pinning.py` | py | testing | 24 | yes |
| `tests/test_crypto.py` | py | testing | 9 | yes |
| `tests/test_hkdf_key_derivation.py` | py | testing | 19 | yes |
| `tests/test_iv_generation.py` | py | testing | 17 | yes |
| `tests/test_replay_protection.py` | py | testing | 28 | yes |

## Key Symbols

- `load_runtime_config` (function, `c2/server.py:62`) `def load_runtime_config()` - Load configuration from JSON file or use defaults.
- `compute_hmac` (function, `c2/server.py:110`) `def compute_hmac(key, data)` - Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function, `c2/server.py:115`) `def verify_hmac(key, data, signature)` - Verify HMAC-SHA256 signature.
- `encrypt_data` (function, `c2/server.py:121`) `def encrypt_data(data, key, hmac_key, use_hmac)` - Encrypt data with AES-256-CFB and optional HMAC (legacy format without replay protection).
- `encrypt_data_replay` (function, `c2/server.py:144`) `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)` - Encrypt data with AES-256-CFB and replay protection (counter + timestamp).
- `decrypt_data` (function, `c2/server.py:178`) `def decrypt_data(b64_data, key, hmac_key, use_hmac)` - Decrypt AES-256-CFB data with optional HMAC verification.
- `decrypt_data_replay` (function, `c2/server.py:201`) `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds` - Decrypt AES-256-CFB data with replay protection (counter + timestamp).
- `C2State` (class, `c2/server.py:271`) `class C2State` - Mutable state shared between request handlers.
- `__init__` (method, `c2/server.py:274`) `def __init__(self, cfg)`
- `handle_get_command` (function, `c2/server.py:287`) `def handle_get_command(state, selector)` - Dispatch beacon's polling GET request.
- `handle_report` (function, `c2/server.py:311`) `def handle_report(state, b64_payload)` - Process beacon result report.
- `handle_bof` (function, `c2/server.py:401`) `def handle_bof(state, name)` - Serve BOF file from upload directory with path traversal protection.
- `handle_request` (function, `c2/server.py:439`) `def handle_request(state, selector)` - Route request to appropriate handler.
- `_is_http_line` (function, `c2/server.py:490`) `def _is_http_line(line)` - True if `line` is an HTTP request line ("GET /path HTTP/1.1").
- `_is_http_request` (function, `c2/server.py:496`) `def _is_http_request(raw)` - True if the first line looks like an HTTP request line.
- `_read_request` (function, `c2/server.py:507`) `def _read_request(conn)` - Read one full request.
- `_http_response` (function, `c2/server.py:555`) `def _http_response(body, status)`
- `serve_client` (function, `c2/server.py:567`) `def serve_client(state, conn, addr)` - Handle individual client connection.
- `serve` (function, `c2/server.py:595`) `def serve(cfg, state)` - Bind and accept loop. Blocks until interrupted.
- `command_injector` (function, `c2/server.py:619`) `def command_injector(state)` - Interactive command injection REPL.
- `main` (function, `c2/server.py:642`) `def main()` - Start C2 server.
- `_derive_keys` (function, `include/config_py.py:65`) `def _derive_keys(master_key_bytes)` - Derive encryption and HMAC keys from master key using HKDF-SHA256.
- `_deep_merge` (function, `include/config_py.py:84`) `def _deep_merge(base, overlay)` - Recursively merge overlay into base; overlay wins.
- `load_config` (function, `include/config_py.py:94`) `def load_config(path)` - Load and validate a BSB config file.
- `_free_port` (function, `mutants/tests/test_c2_http_e2e.py:43`) `def _free_port()`
- `_recv_response` (function, `mutants/tests/test_c2_http_e2e.py:51`) `def _recv_response(sock, timeout)`
- `test_http_get_poll_returns_encrypted_command` (function, `mutants/tests/test_c2_http_e2e.py:65`) `def test_http_get_poll_returns_encrypted_command()` - Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64
- `test_http_post_report_writes_log` (function, `mutants/tests/test_c2_http_e2e.py:115`) `def test_http_post_report_writes_log()` - Beacon-style HTTP/1.1 POST /report/<b64> must reach the
- `test_gopher_legacy_still_works` (function, `mutants/tests/test_c2_http_e2e.py:183`) `def test_gopher_legacy_still_works()` - The old Gopher-style selector (single line, CRLF) must
- `test_http_post_with_url_encoded_b64_payload` (function, `mutants/tests/test_c2_http_e2e.py:233`) `def test_http_post_with_url_encoded_b64_payload()` - The beacon percent-encodes the base64 payload before

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 20
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `tests/test_c2_beacon_bof_integration.py` via `subprocess` (0 hops)
- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `include/config_py.py` via `subprocess` (1 hops)
- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `c2/server.py` via `subprocess` (1 hops)
- [taint high] `tests/test_certificate_pinning.py` -> `tests/test_certificate_pinning.py` via `subprocess` (0 hops)
- [taint high] `tests/test_certificate_pinning.py` -> `include/config_py.py` via `subprocess` (1 hops)
- [taint high] `tests/test_certificate_pinning.py` -> `c2/server.py` via `subprocess` (1 hops)
- [dataflow UNCHECKED_ALLOC] `c2/server.py:597` `serve` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `c2/__init__.py`)? What purpose do they serve?
- Is the dangerous import `subprocess` in `tests/test_c2_beacon_bof_integration.py` still required, or can it be isolated?
- What would break if the most connected file in c2 changed?
- Should c2 be split, given cohesion 1.00?

## Sources

- `c2/__init__.py`
- `c2/server.py`
- `include/config_py.py`
- `mutants/tests/test_c2_http_e2e.py`
- `mutants/tests/test_c2_server.py`
- `mutants/tests/test_certificate_pinning.py`
- `tests/test_bof_path_traversal.py`
- `tests/test_c2_beacon_bof_integration.py`
- `tests/test_c2_http_e2e.py`
- `tests/test_c2_server.py`
- `tests/test_certificate_pinning.py`
- `tests/test_crypto.py`
- `tests/test_hkdf_key_derivation.py`
- `tests/test_iv_generation.py`
- `tests/test_replay_protection.py`
