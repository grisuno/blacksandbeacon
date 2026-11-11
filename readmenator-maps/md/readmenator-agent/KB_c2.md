# Subsystem: c2

## c2/__init__.py
- Layer: utility
- Language: py
- Imported by: `mutants/tests/test_c2_http_e2e.py`, `tests/test_c2_http_e2e.py`

## c2/server.py
- Doc: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Layer: utility
- Language: py
- Symbols:
  - `load_runtime_config` (function, line 62) `def load_runtime_config()`
  - `compute_hmac` (function, line 110) `def compute_hmac(key, data)`
  - `verify_hmac` (function, line 115) `def verify_hmac(key, data, signature)`
  - `encrypt_data` (function, line 121) `def encrypt_data(data, key, hmac_key, use_hmac)`
  - `encrypt_data_replay` (function, line 144) `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)`
  - `decrypt_data` (function, line 178) `def decrypt_data(b64_data, key, hmac_key, use_hmac)`
  - `decrypt_data_replay` (function, line 201) `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds, last_seen_counter, client_id)`
  - `C2State` (class, line 271) `class C2State`
  - `handle_get_command` (function, line 287) `def handle_get_command(state, selector)`
  - `handle_report` (function, line 311) `def handle_report(state, b64_payload)`
  - `handle_bof` (function, line 401) `def handle_bof(state, name)`
  - `handle_request` (function, line 439) `def handle_request(state, selector)`
  - `_is_http_line` (function, line 490) `def _is_http_line(line)`
  - `_is_http_request` (function, line 496) `def _is_http_request(raw)`
  - `_read_request` (function, line 507) `def _read_request(conn)`
  - `_http_response` (function, line 555) `def _http_response(body, status)`
  - `serve_client` (function, line 567) `def serve_client(state, conn, addr)`
  - `serve` (function, line 595) `def serve(cfg, state)`
  - `command_injector` (function, line 619) `def command_injector(state)`
  - `main` (function, line 642) `def main()`
  - `__init__` (method, line 274) `def __init__(self, cfg)`
- Depends on: `include/config_py.py`
- Imported by: `mutants/tests/test_c2_server.py`, `tests/test_bof_path_traversal.py`, `tests/test_c2_beacon_bof_integration.py`, `tests/test_c2_http_e2e.py`, `tests/test_c2_server.py`, `tests/test_crypto.py`, `tests/test_iv_generation.py`, `tests/test_replay_protection.py`
