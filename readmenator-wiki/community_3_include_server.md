# include: server

*Community 3 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `include` with dominant language py (cohesion 1.00). Central symbols: `C2State`, `__init__`, `_deep_merge`, `_http_response`, `_is_http_line`, `_is_http_request`, `_read_request`, `command_injector`. Core file: `c2/server.py` (19 symbols). Documented purpose: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. Handles command queuing, result collection, and BOF distribut.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `c2/server.py` | py | utility | 19 | yes |
| `include/config_py.py` | py | infrastructure | 2 | yes |
| `tests/test_c2_server.py` | py | testing | 11 | yes |

## Key Symbols

- `load_runtime_config` (function, `c2/server.py:60`) `def load_runtime_config()` - Load configuration from JSON file or use defaults.
- `compute_hmac` (function, `c2/server.py:87`) `def compute_hmac(key, data)` - Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function, `c2/server.py:92`) `def verify_hmac(key, data, signature)` - Verify HMAC-SHA256 signature.
- `encrypt_data` (function, `c2/server.py:98`) `def encrypt_data(data, key, use_hmac)` - Encrypt data with AES-256-CFB and optional HMAC.
- `decrypt_data` (function, `c2/server.py:118`) `def decrypt_data(b64_data, key, use_hmac)` - Decrypt AES-256-CFB data with optional HMAC verification.
- `C2State` (class, `c2/server.py:137`) `class C2State` - Mutable state shared between request handlers.
- `__init__` (method, `c2/server.py:140`) `def __init__(self, cfg)`
- `handle_get_command` (function, `c2/server.py:151`) `def handle_get_command(state, selector)` - Dispatch beacon's polling GET request.
- `handle_report` (function, `c2/server.py:174`) `def handle_report(state, b64_payload)` - Process beacon result report.
- `handle_bof` (function, `c2/server.py:230`) `def handle_bof(state, name)` - Serve BOF file from upload directory.
- `handle_request` (function, `c2/server.py:240`) `def handle_request(state, selector)` - Route request to appropriate handler.
- `_is_http_line` (function, `c2/server.py:282`) `def _is_http_line(line)` - True if `line` is an HTTP request line ("GET /path HTTP/1.1").
- `_is_http_request` (function, `c2/server.py:288`) `def _is_http_request(raw)` - True if the first line looks like an HTTP request line.
- `_read_request` (function, `c2/server.py:299`) `def _read_request(conn)` - Read one full request.
- `_http_response` (function, `c2/server.py:343`) `def _http_response(body, status)`
- `serve_client` (function, `c2/server.py:355`) `def serve_client(state, conn, addr)` - Handle individual client connection.
- `serve` (function, `c2/server.py:380`) `def serve(cfg, state)` - Bind and accept loop. Blocks until interrupted.
- `command_injector` (function, `c2/server.py:404`) `def command_injector(state)` - Interactive command injection REPL.
- `main` (function, `c2/server.py:427`) `def main()` - Start C2 server.
- `_deep_merge` (function, `include/config_py.py:55`) `def _deep_merge(base, overlay)` - Recursively merge overlay into base; overlay wins.
- `load_config` (function, `include/config_py.py:65`) `def load_config(path)` - Load and validate a BSB config file.
- `make_state` (function, `tests/test_c2_server.py:39`) `def make_state(tmp)`
- `test_get_command_empty` (function, `tests/test_c2_server.py:46`) `def test_get_command_empty()`
- `test_get_command_queued` (function, `tests/test_c2_server.py:58`) `def test_get_command_queued()`
- `test_report_writes_log` (function, `tests/test_c2_server.py:69`) `def test_report_writes_log()`
- `test_bof_not_found` (function, `tests/test_c2_server.py:85`) `def test_bof_not_found()`
- `test_bof_serves_existing_file` (function, `tests/test_c2_server.py:92`) `def test_bof_serves_existing_file()`
- `test_unknown_selector` (function, `tests/test_c2_server.py:104`) `def test_unknown_selector()`
- `test_path_traversal_in_bof_name` (function, `tests/test_c2_server.py:111`) `def test_path_traversal_in_bof_name()` - Path-traversal in /bof/ should be neutralised by os.path.basename.
- `test_roundtrip_empty` (function, `tests/test_c2_server.py:120`) `def test_roundtrip_empty()` - encrypt then decrypt empty payload must yield single NUL byte.

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 3 <-> 5 (strength 0.5): Inferred shared context (layer infrastructure) with no import path between community 3 (include: server) and community 5 (include: config).
- [INFERRED] shares_context community 3 <-> 7 (strength 0.5): Inferred shared context (language py) with no import path between community 3 (include: server) and community 7 (orphans).

## Risks

- [dataflow UNCHECKED_ALLOC] `c2/server.py:382` `serve` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- What would break if the most connected file in include: server changed?
- Should include: server be split, given cohesion 1.00?

## Sources

- `c2/server.py`
- `include/config_py.py`
- `tests/test_c2_server.py`
