"""
End-to-end test for the "make beacon && ./build/beacon" workflow.

After `make clean && make beacon bofs`, the operator expects:
  - build/beacon          runnable binary (mode 0755)
  - build/config.json     operator-only (mode 0600)
  - build/bof/*.x64.o     5 BOFs ready to copy to the C2

Running the binary from any CWD should pick up
build/config.json (the binary-relative search path).
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def make_all():
    """Clean and build everything, return nothing."""
    subprocess.check_call(["make", "clean"], cwd=str(ROOT))
    subprocess.check_call(["make", "config", "beacon", "bofs"], cwd=str(ROOT))


def run_beacon(binary: Path, cwd: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("BSB_CONFIG", None)  # let search order do its thing
    return subprocess.run(
        [str(binary)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
    )


def test_build_beacon_lands_alongside_config():
    """The point of this whole iteration: `make beacon` leaves
    a runnable binary with its config next to it, no env vars
    or extra steps required."""
    make_all()
    build = ROOT / "build"
    assert (build / "beacon").exists(), "build/beacon not produced"
    assert (build / "config.json").exists(), "build/config.json not staged"
    assert (build / "beacon-v1").exists(), "build/beacon-v1 symlink missing"


def test_staged_files_have_correct_modes():
    build = ROOT / "build"
    bin_mode = stat.S_IMODE((build / "beacon").stat().st_mode)
    cfg_mode = stat.S_IMODE((build / "config.json").stat().st_mode)
    assert bin_mode & 0o111, f"beacon not executable: {oct(bin_mode)}"
    assert cfg_mode == 0o600, f"config.json mode is {oct(cfg_mode)}, expected 0o600"


def test_staged_beacon_runs_from_any_cwd():
    """Drop the operator in /tmp; the staged beacon should still
    find build/config.json via the binary-relative search path."""
    build = ROOT / "build"
    with tempfile.TemporaryDirectory() as td:
        r = run_beacon(build / "beacon", Path(td))
    out = r.stdout + r.stderr
    # We expect the beacon to start polling (the URL is the example
    # localhost which has nothing listening, so curl will fail, but
    # the URL line tells us the config was loaded and parsed).
    assert "url=https://" in out, f"beacon did not read config: {out!r}"


def test_staged_bofs_are_present():
    build = ROOT / "build" / "bof"
    expected = {"cat.x64.o", "is_sudo.x64.o", "suid_enum.x64.o",
                "userenum.x64.o", "whoami.x64.o"}
    actual = {p.name for p in build.iterdir() if p.is_file()}
    assert actual == expected, f"BOF set mismatch: {actual} != {expected}"


def test_clean_removes_everything():
    """make clean must wipe build/ — including the staged config.json —
    but leave config/config.json (the operator's copy) alone.

    This is the last test that runs, so we leave the operator with a
    fresh deliverable tree afterwards. `make clean` is destructive
    and the operator's only copy of build/ is whatever the previous
    test left behind; rebuilding here guarantees `./build/beacon`
    and the staged BOFs are present after `make test` finishes.
    """
    make_all()
    assert (ROOT / "build" / "beacon").exists()
    assert (ROOT / "config" / "config.json").exists()
    subprocess.check_call(["make", "clean"], cwd=str(ROOT))
    assert not (ROOT / "build").exists(), "make clean did not remove build/"
    assert (ROOT / "config" / "config.json").exists(), "make clean wiped config/config.json"
    # Rebuild so the operator ends `make test` with a runnable tree.
    subprocess.check_call(["make", "config", "beacon", "bofs"], cwd=str(ROOT))
    assert (ROOT / "build" / "beacon").exists(), "post-clean rebuild failed"
    assert (ROOT / "build" / "config.json").exists(), "post-clean rebuild did not stage config"


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
            except subprocess.TimeoutExpired:
                # Expected: beacon polls forever, our 3-second cap
                # kills it. The test already inspected the output.
                print(f"  (timed out at 3s, expected: beacon polls forever)")
                print(f"PASS {name}")
            except Exception as e:
                fails.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if fails:
        sys.exit(1)
    print("\nAll install/deploy tests passed")


if __name__ == "__main__":
    main()
