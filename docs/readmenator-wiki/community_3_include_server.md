# include: server

*Community 3 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `include` with dominant language py (cohesion 1.00). Central symbols: `C2State`, `__init__`, `_deep_merge`, `command_injector`, `compute_hmac`, `decrypt_data`, `encrypt_data`, `handle_bof`. Core file: `c2/server.py` (14 symbols). Documented purpose: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents. Handles command queuing, result collection, and BOF distribut.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `c2/server.py` | py | utility | 14 | yes |
| `include/config_py.py` | py | infrastructure | 2 | yes |
| `tests/test_c2_server.py` | py | testing | 11 | yes |

## Key Symbols

- `load_runtime_config` (function, `c2/server.py:59`) `def load_runtime_config()` - Load configuration from JSON file or use defaults.
- `compute_hmac` (function, `c2/server.py:86`) `def compute_hmac(key, data)` - Compute HMAC-SHA256 for message authentication.
- `verify_hmac` (function, `c2/server.py:91`) `def verify_hmac(key, data, signature)` - Verify HMAC-SHA256 signature.
- `encrypt_data` (function, `c2/server.py:97`) `def encrypt_data(data, key, use_hmac)` - Encrypt data with AES-256-CFB and optional HMAC.
- `decrypt_data` (function, `c2/server.py:117`) `def decrypt_data(b64_data, key, use_hmac)` - Decrypt AES-256-CFB data with optional HMAC verification.
- `C2State` (class, `c2/server.py:136`) `class C2State` - Mutable state shared between request handlers.
- `__init__` (method, `c2/server.py:139`) `def __init__(self, cfg)`
- `handle_get_command` (method, `c2/server.py:150`) `def handle_get_command(state, selector)` - Dispatch beacon's polling GET request.
- `handle_report` (method, `c2/server.py:173`) `def handle_report(state, b64_payload)` - Process beacon result report.
- `handle_bof` (method, `c2/server.py:229`) `def handle_bof(state, name)` - Serve BOF file from upload directory.
- `handle_request` (method, `c2/server.py:239`) `def handle_request(state, selector)` - Route request to appropriate handler.
- `serve_client` (method, `c2/server.py:272`) `def serve_client(state, conn, addr)` - Handle individual client connection.
- `command_injector` (method, `c2/server.py:294`) `def command_injector(state)` - Interactive command injection REPL.
- `main` (method, `c2/server.py:317`) `def main()` - Start C2 server.
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
- `test_roundtrip_text` (function, `tests/test_c2_server.py:127`) `def test_roundtrip_text()`
- `main` (function, `tests/test_c2_server.py:134`) `def main()`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 3 <-> 5 (strength 0.5): Inferred shared context (layer infrastructure) with no import path between community 3 (include: server) and community 5 (include: config).
- [INFERRED] shares_context community 3 <-> 7 (strength 0.5): Inferred shared context (language py) with no import path between community 3 (include: server) and community 7 (orphans).

## Risks

- [dataflow UNCHECKED_ALLOC] `c2/server.py:327` `main` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- What would break if the most connected file in include: server changed?
- Should include: server be split, given cohesion 1.00?

## Sources

- `c2/server.py`
- `include/config_py.py`
- `tests/test_c2_server.py`
