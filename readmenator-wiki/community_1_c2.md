# c2

*Community 1 | 17 files | cohesion 1.00*

## Definition

This community groups 17 file(s) rooted at `tests` with dominant language py (cohesion 1.00). Central symbols: `C2State`, `Handler`, `TestBOFPathTraversalConfig`, `TestBOFPathTraversalMutationResistance`, `TestBOFPathTraversalServer`, `TestC2BeaconBOFIntegration`, `TestCertificatePinningCConfig`, `TestCertificatePinningConfig`. Core file: `c2/server.py` (33 symbols). Documented purpose: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. Handles command queuing, result collection, and BOF distribut.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `c2/__init__.py` | py | utility | 0 | no |
| `c2/server.py` | py | utility | 33 | yes |
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
| `tests/test_runtime_random.py` | py | testing | 12 | yes |
| `tests/test_stage.py` | py | testing | 31 | yes |

## Key Symbols

- `_random_free_port` (function, `c2/server.py:74`) `def _random_free_port()` - Pick a free TCP port in the ephemeral range (best-effort bind probe).
- `_ensure_stage_tls` (function, `c2/server.py:87`) `def _ensure_stage_tls(cfg)` - Auto-provision TLS for staging to avoid plaintext token/header exposure.
- `load_runtime_config` (function, `c2/server.py:160`) `def load_runtime_config()` - Load configuration from JSON file or use defaults.
- `compute_hmac` (function, `c2/server.py:287`) `def compute_hmac(key, data)` - Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function, `c2/server.py:292`) `def verify_hmac(key, data, signature)` - Verify HMAC-SHA256 signature.
- `encrypt_data` (function, `c2/server.py:298`) `def encrypt_data(data, key, hmac_key, use_hmac)` - Encrypt data with AES-256-CFB and optional HMAC (legacy format without replay protection).
- `encrypt_data_replay` (function, `c2/server.py:321`) `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)` - Encrypt data with AES-256-CFB and replay protection (counter + timestamp).
- `decrypt_data` (function, `c2/server.py:355`) `def decrypt_data(b64_data, key, hmac_key, use_hmac)` - Decrypt AES-256-CFB data with optional HMAC verification.
- `decrypt_data_replay` (function, `c2/server.py:378`) `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds` - Decrypt AES-256-CFB data with replay protection (counter + timestamp).
- `hkdf_sha256` (function, `c2/server.py:472`) `def hkdf_sha256(ikm, salt, info, length)` - RFC 5869 HKDF extract+expand. Pure stdlib for parity with stager.
- `stage_keys` (function, `c2/server.py:483`) `def stage_keys(token)` - Derive staging encryption and HMAC keys from token.
- `stage_encode` (function, `c2/server.py:491`) `def stage_encode(payload, token)` - Encrypt payload with AES-256-CFB + HMAC-SHA256 using token-derived keys.
- `stage_decode` (function, `c2/server.py:503`) `def stage_decode(body, token)` - Decrypt/verify staging payload. Returns None on auth/decrypt failure.
- `stage_token_ok` (function, `c2/server.py:523`) `def stage_token_ok(state, token)` - Constant-time token check; fail closed when no token configured.
- `build_stage_config` (function, `c2/server.py:531`) `def build_stage_config(state)` - Build the beacon config JSON served by /stage/config.
- `handle_stage` (function, `c2/server.py:563`) `def handle_stage(state, kind, token)` - Serve the beacon ELF or the config.json through the staging contract.
- `build_stage_oneliner` (function, `c2/server.py:594`) `def build_stage_oneliner(cfg)` - Build the copy-paste stager one-liner for the current config.
- `copy_to_clipboard` (function, `c2/server.py:611`) `def copy_to_clipboard(text)` - Copy text to the X11/Wayland clipboard; False if no tool exists.
- `C2State` (class, `c2/server.py:634`) `class C2State` - Mutable state shared between request handlers.
- `__init__` (method, `c2/server.py:637`) `def __init__(self, cfg)`
- `handle_get_command` (function, `c2/server.py:650`) `def handle_get_command(state, selector)` - Dispatch beacon's polling GET request.
- `handle_report` (function, `c2/server.py:674`) `def handle_report(state, b64_payload)` - Process beacon result report.
- `handle_bof` (function, `c2/server.py:764`) `def handle_bof(state, name)` - Serve BOF file with path traversal protection.
- `handle_request` (function, `c2/server.py:811`) `def handle_request(state, selector)` - Route request to appropriate handler.
- `_is_http_line` (function, `c2/server.py:886`) `def _is_http_line(line)` - True if `line` is an HTTP request line ("GET /path HTTP/1.1").
- `_is_http_request` (function, `c2/server.py:892`) `def _is_http_request(raw)` - True if the first line looks like an HTTP request line.
- `_read_request` (function, `c2/server.py:903`) `def _read_request(conn)` - Read one full request.
- `_http_response` (function, `c2/server.py:951`) `def _http_response(body, status)`
- `serve_client` (function, `c2/server.py:963`) `def serve_client(state, conn, addr)` - Handle individual client connection.
- `serve` (function, `c2/server.py:993`) `def serve(cfg, state)` - Bind and accept loop. Blocks until interrupted.

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 26
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [taint high] `c2/server.py` -> `c2/server.py` via `subprocess` (0 hops)
- [taint high] `c2/server.py` -> `include/config_py.py` via `subprocess` (1 hops)
- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `tests/test_c2_beacon_bof_integration.py` via `subprocess` (0 hops)
- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `c2/server.py` via `subprocess` (1 hops)
- [taint high] `tests/test_c2_beacon_bof_integration.py` -> `include/config_py.py` via `subprocess` (1 hops)
- [taint high] `tests/test_certificate_pinning.py` -> `tests/test_certificate_pinning.py` via `subprocess` (0 hops)
- [dataflow UNCHECKED_ALLOC] `c2/server.py:995` `serve` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `c2/__init__.py`)? What purpose do they serve?
- Is the dangerous import `subprocess` in `c2/server.py` still required, or can it be isolated?
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
- `tests/test_runtime_random.py`
- `tests/test_stage.py`
