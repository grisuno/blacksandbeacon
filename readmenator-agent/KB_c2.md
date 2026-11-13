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
  - `_random_free_port` (function, line 74) `def _random_free_port()`
  - `_ensure_stage_tls` (function, line 87) `def _ensure_stage_tls(cfg)`
  - `load_runtime_config` (function, line 160) `def load_runtime_config()`
  - `compute_hmac` (function, line 287) `def compute_hmac(key, data)`
  - `verify_hmac` (function, line 292) `def verify_hmac(key, data, signature)`
  - `encrypt_data` (function, line 298) `def encrypt_data(data, key, hmac_key, use_hmac)`
  - `encrypt_data_replay` (function, line 321) `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)`
  - `decrypt_data` (function, line 355) `def decrypt_data(b64_data, key, hmac_key, use_hmac)`
  - `decrypt_data_replay` (function, line 378) `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds, last_seen_counter, client_id)`
  - `hkdf_sha256` (function, line 472) `def hkdf_sha256(ikm, salt, info, length)`
  - `stage_keys` (function, line 483) `def stage_keys(token)`
  - `stage_encode` (function, line 491) `def stage_encode(payload, token)`
  - `stage_decode` (function, line 503) `def stage_decode(body, token)`
  - `stage_token_ok` (function, line 523) `def stage_token_ok(state, token)`
  - `build_stage_config` (function, line 531) `def build_stage_config(state)`
  - `handle_stage` (function, line 563) `def handle_stage(state, kind, token)`
  - `build_stage_oneliner` (function, line 594) `def build_stage_oneliner(cfg)`
  - `copy_to_clipboard` (function, line 611) `def copy_to_clipboard(text)`
  - `C2State` (class, line 634) `class C2State`
  - `handle_get_command` (function, line 650) `def handle_get_command(state, selector)`
  - `handle_report` (function, line 674) `def handle_report(state, b64_payload)`
  - `handle_bof` (function, line 764) `def handle_bof(state, name)`
  - `handle_request` (function, line 811) `def handle_request(state, selector)`
  - `_is_http_line` (function, line 886) `def _is_http_line(line)`
  - `_is_http_request` (function, line 892) `def _is_http_request(raw)`
  - `_read_request` (function, line 903) `def _read_request(conn)`
  - `_http_response` (function, line 951) `def _http_response(body, status)`
  - `serve_client` (function, line 963) `def serve_client(state, conn, addr)`
  - `serve` (function, line 993) `def serve(cfg, state)`
  - `_sync_bofs_to_upload_dir` (function, line 1035) `def _sync_bofs_to_upload_dir(cfg)`
  - `command_injector` (function, line 1058) `def command_injector(state)`
  - `main` (function, line 1081) `def main()`
  - `__init__` (method, line 637) `def __init__(self, cfg)`
- Depends on: `include/config_py.py`
- Imported by: `mutants/tests/test_c2_server.py`, `tests/test_bof_path_traversal.py`, `tests/test_c2_beacon_bof_integration.py`, `tests/test_c2_http_e2e.py`, `tests/test_c2_server.py`, `tests/test_certificate_pinning.py`, `tests/test_crypto.py`, `tests/test_iv_generation.py`, `tests/test_replay_protection.py`, `tests/test_runtime_random.py`, `tests/test_stage.py`

## c2/stage_oneliner.sh
- Doc: Black Sand Beacon diskless stager (Stage-0 one-liner).
- Layer: utility
- Language: sh

## c2/stage_payload.py
- Doc: Black Sand Beacon diskless stager.
- Layer: utility
- Language: py
- Symbols:
  - `hkdf_sha256` (function, line 41) `def hkdf_sha256(ikm, salt, info, length)`
  - `_fetch_and_decode` (function, line 52) `def _fetch_and_decode(url, token, path, tls_ctx)`
  - `main` (function, line 84) `def main()`
