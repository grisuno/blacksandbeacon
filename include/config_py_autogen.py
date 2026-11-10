"""
Auto-generated Python config loader from config/schema.json
DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate
"""
import json
import re
from pathlib import Path
from typing import Dict, Any

DEFAULTS = {
    "c2": {
        "url": "http://127.0.0.1:7070",
        "uri": "",
        "client_id": "",
        "report_uri": "",
        "port": 0,
        "log_dir": "",
        "upload_dir": "",
    },
    "crypto": {
        "aes_key_hex": "",
        "master_key_hex": "",
        "mode": "",
        "replay_window_seconds": 300,
    },
    "timing": {
        "sleep_seconds": 0,
        "jitter_percent": 0,
        "curl_timeout_seconds": 0,
        "curl_connect_timeout_seconds": 0,
    },
    "network": {
        "user_agents": [],
        "verify_tls": False,
        "cert_fingerprint_sha256": "",
    },
    "bof": {
        "download_chunk_size": 0,
        "output_buffer_size": 0,
    },
    "backoff": {
        "base_seconds": 0,
        "max_seconds": 0,
    },
    "server": {
        "max_workers": 10,
        "hmac_enabled": false,
    },
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_FINGERPRINT_RE = re.compile(r"^([0-9a-fA-F]{64})?$")
_MASTER_KEY_RE = re.compile(r"^([0-9a-fA-F]{64})?$")

HKDF_SALT = b"blacksandbeacon-v2"
HKDF_INFO_ENC = b"enc"
HKDF_INFO_HMAC = b"hmac"

def _derive_keys(master_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Derive encryption and HMAC keys from master key using HKDF-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    hkdf_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO_ENC,
        backend=default_backend()
    )
    hkdf_hmac = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO_HMAC,
        backend=default_backend()
    )
    return hkdf_enc.derive(master_key_bytes), hkdf_hmac.derive(master_key_bytes)

def _deep_merge(base, overlay):
    """Recursively merge overlay into base; overlay wins."""
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = dict(base)
        for k, v in overlay.items():
            out[k] = _deep_merge(base.get(k), v) if k in base else v
        return out
    return overlay if overlay is not None else base

def load_config(path):
    """Load and validate a BSB config file.

    Raises ValueError on any schema violation. Returns a dict
    matching DEFAULTS' structure plus derived keys.
    """
    with open(path) as f:
        raw = json.load(f)
    merged = _deep_merge(DEFAULTS, raw)

    # Validate keys: either master_key_hex (new) or aes_key_hex (legacy) must be present
    master_key = merged["crypto"]["master_key_hex"]
    aes_key = merged["crypto"]["aes_key_hex"]

    if master_key:
        if not _MASTER_KEY_RE.match(master_key):
            raise ValueError(
                f"crypto.master_key_hex must be 64 hex chars, got {master_key!r}"
            )
        master_key_bytes = bytes.fromhex(master_key)
    elif aes_key:
        if not _HEX_RE.match(aes_key):
            raise ValueError(
                f"crypto.aes_key_hex must be 64 hex chars, got {aes_key!r}"
            )
        # Backward compat: derive from aes_key_hex
        master_key_bytes = bytes.fromhex(aes_key)
    else:
        raise ValueError("crypto.master_key_hex or crypto.aes_key_hex required")

    # Derive encryption and HMAC keys
    enc_key, hmac_key = _derive_keys(master_key_bytes)
    merged["crypto"]["encryption_key"] = enc_key
    merged["crypto"]["hmac_key"] = hmac_key

    # Validate certificate fingerprint (64 hex chars or empty).
    fp = merged["network"]["cert_fingerprint_sha256"]
    if not _FINGERPRINT_RE.match(fp):
        raise ValueError(
            f"network.cert_fingerprint_sha256 must be 64 hex chars or empty, got {fp!r}"
        )

    # Validate replay_window_seconds (must be positive).
    replay_window = merged["crypto"]["replay_window_seconds"]
    if not isinstance(replay_window, int) or replay_window <= 0:
        raise ValueError(
            f"crypto.replay_window_seconds must be a positive integer, got {replay_window!r}"
        )

    # Clamp values that must be positive.
    merged["timing"]["sleep_seconds"] = max(1, int(merged["timing"]["sleep_seconds"]))
    merged["timing"]["jitter_percent"] = max(0, int(merged["timing"]["jitter_percent"]))
    return merged