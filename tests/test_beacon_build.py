"""
Sanity build test: compile the v1 beacon against include/config.c
and verify the binary links and embeds the symbols we expect.

This test is skipped (not failed) if the OpenSSL or libcurl dev
headers are missing, so it works on a clean CI runner and on a
dev box without those installed. CI installs them explicitly.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEACON = ROOT / "build" / "beacon-v1"
SRC = ROOT / "beacons" / "v1" / "beacon.c"


def have_headers():
    """Return True if openssl and curl headers are present."""
    cc = os.environ.get("CC", "gcc")
    for hdr in ("openssl/buffer.h", "curl/curl.h"):
        r = subprocess.run(
            [cc, "-E", "-x", "c", "-"],
            input=f"#include <{hdr}>\nint main(void){{return 0;}}\n".encode(),
            capture_output=True,
        )
        if r.returncode != 0:
            return False
    return True


def compile_beacon():
    BEACON.parent.mkdir(exist_ok=True)
    cmd = [
        "gcc", "-Wall", "-Wextra", "-O2", "-g",
        "-I", str(ROOT / "include"),
        "-I", str(ROOT / "beacons" / "v1"),
        "-o", str(BEACON),
        str(SRC),
        str(ROOT / "include" / "config.c"),
        str(ROOT / "include" / "aes.c"),
        str(ROOT / "include" / "cJSON.c"),
        "-lcurl", "-lssl", "-lcrypto",
    ]
    subprocess.check_call(cmd)


def inspect_binary():
    out = subprocess.check_output(["nm", "-D", str(BEACON)], text=True)
    return set(line.split()[-1] for line in out.splitlines() if line.strip())


def test_beacon_compiles_and_links():
    if not have_headers():
        print("  (skipping) openssl or libcurl dev headers not present")
        return
    compile_beacon()
    assert BEACON.exists() and BEACON.stat().st_size > 0
    print(f"  compiled {BEACON.relative_to(ROOT)} ({BEACON.stat().st_size} bytes)")


def test_beacon_exposes_bof_api():
    if not have_headers():
        print("  (skipping) openssl or libcurl dev headers not present")
        return
    if not BEACON.exists():
        compile_beacon()
    # The beacon's BOF loader does not use dlsym-style dynamic symbol
    # resolution. Instead it carries a global function-pointer table
    # (g_BeaconPrintf_ptr / g_BeaconOutput_ptr) that RunELF rewrites
    # to the real function addresses at load time. We assert the
    # pointer slots exist in BSS.
    out = subprocess.check_output(["nm", str(BEACON)], text=True)
    assert "B g_BeaconPrintf_ptr" in out, "g_BeaconPrintf_ptr BSS slot missing"
    assert "B g_BeaconOutput_ptr" in out, "g_BeaconOutput_ptr BSS slot missing"
    # The real functions must also be in the binary, otherwise the
    # pointer table is pointing at NULL.
    assert "T BeaconPrintf" in out, "BeaconPrintf text symbol missing"
    assert "T BeaconOutput" in out, "BeaconOutput text symbol missing"
    print(f"  beacon has BOF API slots (g_BeaconPrintf_ptr, g_BeaconOutput_ptr)")


def test_beacon_exposes_elf_loader():
    if not have_headers():
        print("  (skipping) openssl or libcurl dev headers not present")
        return
    if not BEACON.exists():
        compile_beacon()
    out = subprocess.check_output(["nm", str(BEACON)], text=True)
    assert "T RunELF" in out, "RunELF entry point not present"
    print(f"  beacon exports RunELF (in-memory ELF loader)")


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
                fails.append((name, f"compile/link failed: {e}"))
                print(f"FAIL {name}: compile error")
            except Exception as e:
                fails.append((name, repr(e)))
                print(f"ERROR {name}: {e!r}")
    if fails:
        sys.exit(1)
    print("\nAll beacon build tests passed")


if __name__ == "__main__":
    main()
