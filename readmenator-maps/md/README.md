# Black Sand Beacon

A Linux C2 beacon with a native in-memory ELF BOF loader, written in
C with no Go or Rust runtime. Designed to plug into the LazyOwn
RedTeam framework and inspired by Cobalt Strike's Beacon Object
Files.

This repository contains:

* **Beacons** in `beacons/v1/`, `beacons/v2/`, `beacons/v3/`
  Three variants of the same HTTPS/CFB beacon. v1 is the canonical
  pull-mode beacon. v2 adds mesh/p2p discovery. v3 is an
  experimental branch.
* **BOFs** in `bof/<name>/bof.c`
  Position-independent ELF objects the beacon can fetch and execute
  in memory. The five included are: `whoami`, `is_sudo`, `cat`,
  `userenum`, `suid_enum`.
* **C2 server** in `c2/server.py`
  A small Python Gopher-like server that serves commands, accepts
  results, and hosts BOFs.
* **Shared library** in `include/`
  AES-256 standalone (`aes.c`/`aes.h`), cJSON, the runtime
  configuration loader (`config.c`/`config.h` plus the Python
  mirror `config_py.py`), and the AES-256-CFB wrappers shared by
  the beacon and the tests.
* **Build** in `Makefile`, **CI** in `.github/workflows/ci.yml`,
  **tests** in `tests/`.

For a 5-minute end-to-end run, see [QUICKSTART.md](QUICKSTART.md).
For the BOF authoring guide, see [docs/BOF_AUTHORING.md](docs/BOF_AUTHORING.md).
For the C2 wire protocol, see [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Requirements

Build (Debian/Ubuntu):

```
sudo apt-get install gcc libcurl4-openssl-dev libssl-dev make
```

Runtime for the C2 server:

```
pip install -r requirements.txt
```

## Build

```
make config        # one-time: copies config.example.json -> config.json
make beacon        # builds build/beacon (runnable, with build/config.json staged next to it)
make bofs          # builds all BOFs into build/bof/*.x64.o
make all-beacons   # builds v1, v2, v3
make test          # runs the full test suite
make clean         # removes build/
```

After `make beacon`, the binary is ready to run:

```
./build/beacon
```

It reads `build/config.json` (next to itself) via the binary-relative
search path, so no `BSB_CONFIG` or `cd config/` is needed. The same
binary copied to another host works identically as long as a
`config.json` sits next to it.

If you only want to rebuild one BOF:

```
make bof-whoami
make bof-suid_enum
```

## Deploy to another host (optional)

For shipping to a target, the Makefile has an `install` target that
stages a self-contained directory:

```
make install-all DESTDIR=/tmp/deploy
scp -r /tmp/deploy/* user@target:/opt/bsb/
ssh user@target /opt/bsb/beacon
```

This is **not** the normal flow. Use it only when you need to
bundle the binary + config + BOFs into a single directory you can
copy somewhere.

## Run the C2

```
python3 c2/server.py
```

The server binds `0.0.0.0:7070` by default and reads its AES key
and C2 URI from `config/config.json`. Override the config path
with `BSB_CONFIG=/path/to/config.json`.

Once the server is up you can inject commands from the REPL:

```
Client ID: linux
Command:   id
```

## Run the beacon

```
./build/beacon
```

The beacon reads `config/config.json` (relative to the binary, found
via the binary-relative search path), polls the C2, and prints
what it sends and receives. With no commands queued it just
sleeps between polls.

To run a BOF, the C2 returns a JSON object with a `bof` field
pointing at `/bof/<name>.x64.o`. The beacon fetches the file and
loads it into its own process via the in-memory ELF loader
(`RunELF` in `beacons/v1/beacon.c`).

## Configuration

All operational parameters live in `config/config.json` and are
read at startup. Nothing is baked into the binaries.

| Section | Key | Default | Purpose |
|---|---|---|---|
| `c2` | `url` | `https://127.0.0.1:4444` | C2 base URL |
| `c2` | `uri` | `/api/poll/` | URI path before the client id |
| `c2` | `client_id` | `linux` | Beacon identifier |
| `crypto` | `aes_key_hex` | (placeholder) | 64 hex chars = 32 bytes |
| `crypto` | `mode` | `cfb` | Encryption mode |
| `timing` | `sleep_seconds` | `6` | Base poll interval |
| `timing` | `jitter_percent` | `20` | +/- percent jitter on sleep |
| `timing` | `curl_timeout_seconds` | `10` | libcurl total timeout |
| `timing` | `curl_connect_timeout_seconds` | `5` | libcurl connect timeout |
| `network` | `user_agents` | (4 strings) | Rotation list |
| `network` | `verify_tls` | `false` | C2 TLS verification |
| `bof` | `download_chunk_size` | `4096` | BOF download buffer |

The CI runs a guardrail that fails the build if a 64-char hex key
appears in source. Real keys belong in `config/config.json`, which
is git-ignored.

## Writing a new BOF

A BOF is just a C source file that exports `void go(char *args, int alen)`.
Include `bof/include/beacon_api.h` for the callback API and
`bof/include/syscalls.h` for direct-syscall helpers. Compile it
position-independent and with no libc:

```
gcc -c -fPIC -nostdlib -m64 -O2 -I bof/include bof/<name>/bof.c -o build/bof/<name>.x64.o
```

The `make bof-<name>` target wraps this. Drop the resulting
`.x64.o` into `sessions/uploads/` on the C2 host and trigger it
by returning a command like `bof:<name>` from your command
injection.

See [docs/BOF_AUTHORING.md](docs/BOF_AUTHORING.md) for the full
contract.

## Testing

```
make test
```

The test suite is split into several files in `tests/`:

| File | What it covers |
|---|---|
| `test_config.py` | C JSON config loader: defaults, overrides, errors |
| `test_crypto.py` | AES-256-CFB roundtrip and Python/C interop |
| `test_bof_compile.py` | Every BOF compiles, exports `go`, has no libc leak |
| `test_beacon_build.py` | Beacon binary builds, exposes BOF API + RunELF |
| `test_c2_server.py` | C2 dispatcher: GET/POST/BOF, path-traversal hardening |
| `test_c2_http_e2e.py` | Real HTTP/1.1 socket roundtrip with crypto |
| `test_install_deploy.py` | `make` workflow produces a runnable tree, `make clean` wipes it |

## Repository layout

```
beacons/
  v1/beacon.c        canonical beacon
  v2/beacon.c        mesh/p2p variant
  v3/beacon.c        experimental variant
bof/
  include/           shared BOF headers (beacon_api.h, syscalls.h)
  whoami/bof.c       sample: print effective UID
  is_sudo/bof.c      sample: check sudo/wheel membership
  cat/bof.c          sample: read a file
  userenum/bof.c     sample: list /etc/passwd users and privileges
  suid_enum/bof.c    privesc recon: walk FS, list SUID/SGID binaries
c2/
  server.py          Gopher-style C2 server
config/
  config.example.json  template (copy to config.json)
include/
  config.h, config.c  runtime config loader
  config_py.py        Python mirror for the C2
  aes.h, aes.c        standalone AES (ECB/CTR/CBC)
  aes_cfb.h, aes_cfb.c  AES-256-CFB the beacon actually uses
  cJSON.h, cJSON.c     vendored JSON parser
  beacon.h            BOF API the beacon implements
tests/
  test_*.py           Python test suite
  *_harness.c         C test harnesses
docs/
  PROTOCOL.md         wire protocol
  BOF_AUTHORING.md    BOF contract and gotchas
.github/workflows/
  ci.yml              build + test + key-leak guard
Makefile
requirements.txt      C2 server runtime deps
```

## License

GPL v3. See `LICENSE`.
