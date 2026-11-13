"""
Tests for random per-run runtime values (Contract: random staging).

BDD Scenarios:
1. Given no port/key/token/client_id in config or env, when the server
   loads its runtime config, then all are generated at random and
   reported in cfg["generated"]
2. Given explicit values in config.json, when loaded, then nothing is
   generated (operator intent wins)
3. Given env overrides, when loaded, then env wins over generation
4. Given a generated key, when /stage/config is fetched, then the served
   config carries the runtime key/url/client_id and no server section
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "include"))
sys.path.insert(0, str(ROOT / "c2"))

from c2.server import load_runtime_config, handle_stage, stage_decode
from config_py import _derive_keys

ENV_KEYS = (
    "BSB_C2_PORT", "BSB_STAGE_TOKEN", "BSB_STAGE_BEACON",
    "BSB_TLS_CERT", "BSB_TLS_KEY", "BSB_C2_HOST",
)


def lrc(monkeypatch, tmp_path, raw=None, env=None):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw or {}))
    monkeypatch.setenv("BSB_CONFIG", str(path))
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    return load_runtime_config()


class TestRandomGeneration:
    def test_all_generated_when_nothing_provided(self, monkeypatch, tmp_path):
        cfg = lrc(monkeypatch, tmp_path)
        gen = cfg["generated"]
        assert set(gen) == {"port", "master_key_hex", "stage_token", "client_id"}
        assert 1025 <= gen["port"] <= 65535
        assert len(gen["master_key_hex"]) == 64
        assert len(gen["stage_token"]) == 32
        assert cfg["client_id"].startswith("bsb-")

    def test_generated_key_parities(self, monkeypatch, tmp_path):
        cfg = lrc(monkeypatch, tmp_path)
        master = bytes.fromhex(cfg["generated"]["master_key_hex"])
        enc, hmac_k = _derive_keys(master)
        assert cfg["aes_key"] == enc
        assert cfg["hmac_key_bytes"] == hmac_k
        assert cfg["aes_key_hex"] == cfg["generated"]["master_key_hex"]

    def test_random_url_points_at_generated_port(self, monkeypatch, tmp_path):
        cfg = lrc(monkeypatch, tmp_path)
        assert f":{cfg['generated']['port']}" in cfg["url"]

    def test_two_runs_differ(self, monkeypatch, tmp_path):
        a = lrc(monkeypatch, tmp_path)
        b = lrc(monkeypatch, tmp_path)
        assert a["generated"]["master_key_hex"] != b["generated"]["master_key_hex"]
        assert a["generated"]["stage_token"] != b["generated"]["stage_token"]
        assert a["generated"]["client_id"] != b["generated"]["client_id"]

    def test_provided_values_preserved(self, monkeypatch, tmp_path):
        aes = "ab" * 32
        raw = {
            "c2": {"port": 7099, "client_id": "myid"},
            "crypto": {"aes_key_hex": aes},
            "server": {"stage_token": "fixedtok"},
        }
        cfg = lrc(monkeypatch, tmp_path, raw=raw)
        assert cfg["generated"] == {}
        assert cfg["port"] == 7099
        assert cfg["client_id"] == "myid"
        assert cfg["stage_token"] == "fixedtok"
        assert cfg["aes_key_hex"] == aes

    def test_env_wins(self, monkeypatch, tmp_path):
        cfg = lrc(monkeypatch, tmp_path, env={"BSB_C2_PORT": "7123"})
        assert cfg["port"] == 7123
        assert "port" not in cfg["generated"]

    def test_explicit_token_no_generation(self, monkeypatch, tmp_path):
        raw = {"server": {"stage_token": "tok"}}
        cfg = lrc(monkeypatch, tmp_path, raw=raw)
        assert cfg["stage_token"] == "tok"
        assert "stage_token" not in cfg["generated"]


class TestStageConfigCarriesRuntimeValues:
    def test_served_config_matches_runtime(self, monkeypatch, tmp_path):
        cfg = lrc(monkeypatch, tmp_path, env={"BSB_STAGE_BEACON": "x"})
        from c2.server import C2State
        state = C2State(cfg)
        resp = handle_stage(state, "config", cfg["stage_token"])
        decoded = json.loads(stage_decode(resp, cfg["stage_token"]).decode())
        assert decoded["crypto"]["aes_key_hex"] == cfg["generated"]["master_key_hex"]
        assert decoded["c2"]["client_id"] == cfg["generated"]["client_id"]
        assert decoded["c2"]["url"] == cfg["url"]
        assert "server" not in decoded
        assert "encryption_key" not in decoded["crypto"]

    def test_file_config_values_win_when_provided(self, monkeypatch, tmp_path):
        aes = "cd" * 32
        raw = {"c2": {"port": 7099, "client_id": "myid"}, "crypto": {"aes_key_hex": aes},
               "server": {"stage_token": "fixedtok"}}
        cfg = lrc(monkeypatch, tmp_path, raw=raw, env={"BSB_STAGE_BEACON": "x"})
        from c2.server import C2State
        state = C2State(cfg)
        resp = handle_stage(state, "config", "fixedtok")
        decoded = json.loads(stage_decode(resp, "fixedtok").decode())
        assert decoded["crypto"]["aes_key_hex"] == aes
        assert decoded["c2"]["client_id"] == "myid"
