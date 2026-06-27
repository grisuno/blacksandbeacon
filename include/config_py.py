"""
config_py.py - Python loader for BSB JSON config files.

Mirrors the C side in include/config.c so the C2 server and the
beacon agree on the same schema. Generated/checked-in here so
the C2 has no Python-side runtime dependency on a separate
generator. Keep this in sync with include/config.c.
"""
import json
import os
import re
import sys
from pathlib import Path

DEFAULTS = {
    "c2": {
        "url": "http://127.0.0.1:7070",
        "uri": "/api/poll/",
        "client_id": "linux",
        "log_dir": "sessions/logs",
        "upload_dir": "sessions/uploads",
        "port": 7070,
        "report_uri": "/report/",
    },
    "crypto": {
        "aes_key_hex": "0123456789abcdef" * 4,
        "mode": "cfb",
    },
    "timing": {
        "sleep_seconds": 6,
        "jitter_percent": 20,
        "curl_timeout_seconds": 10,
        "curl_connect_timeout_seconds": 5,
    },
    "network": {
        "user_agents": [],
        "verify_tls": False,
    },
    "bof": {
        "download_chunk_size": 4096,
        "output_buffer_size": 65536,
    },
    "backoff": {
        "base_seconds": 6,
        "max_seconds": 300,
    },
    "server": {
        "max_workers": 10,
    },
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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
    matching DEFAULTS' structure.
    """
    with open(path) as f:
        raw = json.load(f)
    merged = _deep_merge(DEFAULTS, raw)

    # Validate AES key.
    key = merged["crypto"]["aes_key_hex"]
    if not _HEX_RE.match(key):
        raise ValueError(f"crypto.aes_key_hex must be 64 hex chars, got {key!r}")

    # Clamp values that must be positive.
    merged["timing"]["sleep_seconds"] = max(1, int(merged["timing"]["sleep_seconds"]))
    merged["timing"]["jitter_percent"] = max(0, int(merged["timing"]["jitter_percent"]))
    return merged
