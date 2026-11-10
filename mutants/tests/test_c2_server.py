"""
Unit tests for the C2 server dispatcher.

We import the dispatcher from c2/server.py and exercise
handle_request() with synthetic selectors. No socket, no
threading, no real network - just the pure function.
"""
import base64
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Make c2/ importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "include"))

from c2.server import (  # noqa: E402
    C2State, handle_request, encrypt_data, decrypt_data,
)


KEY = bytes.fromhex("ab" * 32)
CFG = {
    "host": "127.0.0.1",
    "port": 0,
    "uri": "/api/poll/",
    "report_uri": "/report/",
    "aes_key": KEY,
    "log_dir": "",
    "upload_dir": "",
}


def make_state(tmp):
    cfg = dict(CFG)
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    return C2State(cfg)


def test_get_command_empty():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        resp = handle_request(state, "/api/poll/linux")
        # The response is base64(IV || CFB("\0")) - 24 bytes minimum
        decoded = base64.b64decode(resp.strip())
        assert len(decoded) >= 17, len(decoded)
        # Decrypt and confirm we got the empty-payload sentinel
        plain = decrypt_data(resp.strip().decode(), KEY)
        assert plain == b"\x00", plain


def test_get_command_queued():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        state.commands["agent42"] = "id"
        resp = handle_request(state, "/api/poll/agent42").strip()
        plain = decrypt_data(resp, KEY)
        assert plain == b"id", plain
        # Pop semantics: command is consumed on first read.
        assert "agent42" not in state.commands


def test_report_writes_log():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        report = {"client": "host1", "pid": 1234, "hostname": "lab",
                  "ips": "10.0.0.5", "user": "root", "command": "id",
                  "output": "uid=0(root)"}
        payload = encrypt_data(json.dumps(report).encode(), KEY)
        resp = handle_request(state, "/report/" + payload)
        assert resp == b"OK\r\n", resp
        log = Path(state.cfg["log_dir"]) / "host1.log"
        assert log.exists(), f"log file not written: {log}"
        content = log.read_text()
        assert "host1" in content
        assert "uid=0(root)" in content


def test_bof_not_found():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        resp = handle_request(state, "/bof/nonexistent.x64.o")
        assert resp == b"BOF_NOT_FOUND\r\n", resp


def test_bof_serves_existing_file():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        elf = state.cfg["upload_dir"] + "/whoami.x64.o"
        elf_bytes = b"\x7fELF" + b"\x00" * 100
        with open(elf, "wb") as f:
            f.write(elf_bytes)
        resp = handle_request(state, "/bof/whoami.x64.o").strip()
        decoded = base64.b64decode(resp)
        assert decoded == elf_bytes


def test_unknown_selector():
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        resp = handle_request(state, "/garbage/x")
        assert resp.startswith(b"iUNKNOWN_SELECTOR"), resp


def test_path_traversal_in_bof_name():
    """Path-traversal in /bof/ should be neutralised by os.path.basename."""
    with tempfile.TemporaryDirectory() as td:
        state = make_state(Path(td))
        # ../../etc/passwd -> basename = 'passwd', which is not in upload_dir
        resp = handle_request(state, "/bof/../../etc/passwd")
        assert resp == b"BOF_NOT_FOUND\r\n", resp


def test_roundtrip_empty():
    """encrypt then decrypt empty payload must yield single NUL byte."""
    enc = encrypt_data(b"", KEY)
    dec = decrypt_data(enc, KEY)
    assert dec == b"\x00", dec


def test_roundtrip_text():
    msg = b"id; whoami; uname -a"
    enc = encrypt_data(msg, KEY)
    dec = decrypt_data(enc, KEY)
    assert dec == msg, dec


def main():
    fails = []
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                fails.append((name, str(e)))
                print(f"FAIL {name}: {e}")
            except Exception as e:
                fails.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if fails:
        print(f"\n{len(fails)} test(s) failed")
        sys.exit(1)
    print("\nAll C2 tests passed")


if __name__ == "__main__":
    main()
