"""
Unit tests for the BSB JSON config loader.

We exercise the loader via a small C harness compiled with the
config.c source. The Python side just calls the harness binary
and checks the printed fields.

The harness prints lines in the form "key=value" so we can parse
the output deterministically.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HARNESS_C = ROOT / "tests" / "config_harness.c"
HARNESS_BIN = ROOT / "tests" / "config_harness"


def compile_harness():
    """Build the test harness against config.c."""
    if HARNESS_BIN.exists():
        return
    cmd = [
        "gcc", "-std=c11", "-Wall", "-Wextra", "-O0", "-g",
        str(HARNESS_C),
        str(ROOT / "include" / "config.c"),
        "-I", str(ROOT / "include"),
        "-o", str(HARNESS_BIN),
    ]
    subprocess.check_call(cmd)


def run_harness(config_text: str) -> dict:
    """Write a config file, run the harness, return parsed output."""
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "config.json")
        with open(cfg_path, "w") as f:
            f.write(config_text)
        env = os.environ.copy()
        env["BSB_CONFIG"] = cfg_path
        out = subprocess.check_output([str(HARNESS_BIN)], env=env, text=True)
    result = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            result[k] = v
    return result


def test_default_load():
    cfg = (ROOT / "config" / "config.example.json").read_text()
    out = run_harness(cfg)
    assert out["c2.url"] == "http://127.0.0.1:7070", out
    assert out["c2.uri"] == "/api/poll/", out
    assert out["c2.client_id"] == "linux", out
    assert out["c2.report_uri"] == "/report/", out
    assert out["timing.sleep_seconds"] == "6", out
    assert out["timing.jitter_percent"] == "20", out
    assert out["network.user_agents"] == "4", out
    assert out["crypto.mode"] == "cfb", out
    # AES key is the example value
    assert out["crypto.aes_key_hex"] == "0123456789abcdef" * 4, out
    # default jitter is 20% of 6s = +/- 1, so result must be in [5, 7]
    sj = int(out["sleep_with_jitter"])
    assert 5 <= sj <= 7, f"sleep_with_jitter out of range: {sj}"


def test_overrides():
    cfg = json.dumps({
        "c2": {"url": "https://evil.example:8443", "uri": "/x/", "client_id": "z"},
        "crypto": {"aes_key_hex": "ab" * 32, "mode": "cfb"},
        "timing": {"sleep_seconds": 30, "jitter_percent": 0,
                   "curl_timeout_seconds": 60, "curl_connect_timeout_seconds": 10},
        "network": {"user_agents": ["a/1", "b/2"], "verify_tls": True},
        "bof": {"download_chunk_size": 8192},
    })
    out = run_harness(cfg)
    assert out["c2.url"] == "https://evil.example:8443", out
    assert out["timing.sleep_seconds"] == "30", out
    assert out["network.user_agents"] == "2", out
    assert out["bof.download_chunk_size"] == "8192", out
    assert out["crypto.aes_key_hex"] == "ab" * 32, out


def test_missing_file():
    bin_path = HARNESS_BIN
    env = os.environ.copy()
    env["BSB_CONFIG"] = "/tmp/this_does_not_exist_xyz.json"
    r = subprocess.run([str(bin_path)], env=env, capture_output=True, text=True)
    assert r.returncode != 0, "harness should fail on missing file"


def test_search_order_env_wins():
    """$BSB_CONFIG must take precedence over the binary-relative path."""
    with tempfile.TemporaryDirectory() as td:
        env_dir = Path(td) / "env"
        env_dir.mkdir()
        cfg_path = env_dir / "override.json"
        cfg_path.write_text(json.dumps({
            "c2": {"url": "https://env.example:1", "uri": "/x/", "client_id": "env"},
            "crypto": {"aes_key_hex": "11" * 32, "mode": "cfb"},
        }))
        env = os.environ.copy()
        env["BSB_CONFIG"] = str(cfg_path)
        out = subprocess.check_output([str(HARNESS_BIN)], env=env, text=True)
        assert "env.example" in out, out
        assert "c2.client_id=env" in out, out


def test_search_order_falls_back_to_cwd_default():
    """With BSB_CONFIG unset, the harness resolves to ./config.json
    (the binary-relative lookup is irrelevant in the harness because
    the harness lives in tests/, not next to a config.json)."""
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "config.json"
        cfg_path.write_text(json.dumps({
            "c2": {"url": "https://cwd.example", "uri": "/y/", "client_id": "cwd"},
            "crypto": {"aes_key_hex": "22" * 32, "mode": "cfb"},
        }))
        env = os.environ.copy()
        env.pop("BSB_CONFIG", None)
        # We have to point the harness at this directory by symlinking
        # the config dir into CWD, since the binary-relative path
        # does not exist.
        cwd = Path(td)
        cfg_dir = cwd / "config"
        cfg_dir.mkdir()
        import shutil
        shutil.copy(cfg_path, cfg_dir / "config.json")
        r = subprocess.run([str(HARNESS_BIN)], env=env, cwd=str(cwd), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert "cwd.example" in r.stdout, r.stdout
        assert "c2.client_id=cwd" in r.stdout, r.stdout


def test_bad_hex_key():
    cfg = json.dumps({"crypto": {"aes_key_hex": "zzzz", "mode": "cfb"}})
    bin_path = HARNESS_BIN
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(cfg)
        path = f.name
    try:
        env = os.environ.copy()
        env["BSB_CONFIG"] = path
        r = subprocess.run([str(bin_path)], env=env, capture_output=True, text=True)
        assert r.returncode != 0, "harness should fail on bad hex"
    finally:
        os.unlink(path)


def main():
    compile_harness()
    failures = []
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures.append((name, str(e)))
                print(f"FAIL {name}: {e}")
            except Exception as e:
                failures.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if failures:
        print(f"\n{len(failures)} test(s) failed")
        sys.exit(1)
    print("\nAll tests passed")


if __name__ == "__main__":
    main()
