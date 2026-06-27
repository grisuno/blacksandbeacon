"""
Verify every BOF compiles with the BOF build flags.

A BOF is a position-independent ELF object that the beacon
loads at runtime. It must:
  - compile with -nostdlib (no glibc)
  - be PIC
  - export `go` with the right signature
  - leave BeaconPrintf/BeaconOutput as undefined external refs
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOFS = ["whoami", "is_sudo", "cat", "userenum", "suid_enum"]


def compile_bof(name: str) -> Path:
    out = ROOT / "build" / "bof" / f"{name}.x64.o"
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gcc", "-c", "-fPIC", "-nostdlib", "-m64", "-O2",
        "-Wall", "-Wextra",
        "-I", str(ROOT / "bof" / "include"),
        str(ROOT / "bof" / name / "bof.c"),
        "-o", str(out),
    ]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return out


def inspect_symbols(obj_path: Path) -> dict:
    out = subprocess.check_output(["nm", "--defined-only", str(obj_path)], text=True)
    defined = set()
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ [Tt] (\S+)$", line)
        if m:
            defined.add(m.group(1))

    out2 = subprocess.check_output(["nm", str(obj_path)], text=True)
    undefined = set()
    for line in out2.splitlines():
        m = re.match(r"^\s+U (\S+)$", line)
        if m:
            undefined.add(m.group(1))

    return {"defined": defined, "undefined": undefined}


def test_compile_all():
    for name in BOFS:
        obj = compile_bof(name)
        assert obj.exists() and obj.stat().st_size > 0, f"{name}.x64.o is empty"
        print(f"  compiled {name} -> {obj.relative_to(ROOT)} ({obj.stat().st_size} bytes)")


def test_export_go():
    for name in BOFS:
        obj = compile_bof(name)
        syms = inspect_symbols(obj)
        assert "go" in syms["defined"], f"{name} does not export `go`"
        print(f"  {name}: exports go ✓")


def test_unresolved_beacon_api():
    for name in BOFS:
        obj = compile_bof(name)
        syms = inspect_symbols(obj)
        # The BOF must NOT define BeaconPrintf/BeaconOutput itself.
        assert "BeaconPrintf" not in syms["defined"], f"{name} defines BeaconPrintf (must be undefined)"
        assert "BeaconOutput" not in syms["defined"], f"{name} defines BeaconOutput (must be undefined)"
        # And it must reference them so the loader resolves them.
        assert "BeaconPrintf" in syms["undefined"], f"{name} does not reference BeaconPrintf"
        print(f"  {name}: BeaconPrintf/Output are unresolved refs ✓")


def test_no_libc_leak():
    """Make sure we did not pull in glibc symbols by accident."""
    forbidden = {"printf", "puts", "fprintf", "exit", "malloc", "free", "strlen", "strcmp", "memcpy"}
    for name in BOFS:
        obj = compile_bof(name)
        syms = inspect_symbols(obj)
        leaks = forbidden & syms["undefined"]
        assert not leaks, f"{name} leaks libc refs: {leaks}"
        print(f"  {name}: no libc references ✓")


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
            except subprocess.CalledProcessError as e:
                fails.append((name, f"compile failed: {e}"))
                print(f"FAIL {name}: compile error")
            except Exception as e:
                fails.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if fails:
        sys.exit(1)
    print("\nAll BOF compile tests passed")


if __name__ == "__main__":
    main()
