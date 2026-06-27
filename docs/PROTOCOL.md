# C2 Wire Protocol

The beacon talks to the C2 over plain TCP using a tiny
Gopher-style line protocol. Every request is a single ASCII line
the client sends; every response is a single line followed by
`\r\n`.

Three request shapes are recognised:

## GET command

```
<uri>/<client_id>\r\n
```

`<uri>` is the `c2.uri` value from `config.json` (default
`/pleasesubscribe/v1/users/`). `<client_id>` is the
`c2.client_id` value (default `linux`).

The C2 responds with:

```
<base64(iv || AES-256-CFB(command))>\r\n
```

If no command is queued, the response decrypts to a single
NUL byte. The beacon treats this as "nothing to do, sleep and
poll again".

The C2 pops the queued command on first read, so a beacon that
crashes after reading the GET but before POSTing the result will
lose the command. Operators should treat this as best-effort.

## POST result

```
/report/<base64(iv || AES-256-CFB(json))>\r\n
```

The encrypted JSON has the keys: `client`, `pid`, `hostname`,
`ips`, `user`, `command`, `output`, plus optional
`discovered_ips`, `result_portscan`, `result_pwd`.

The C2 responds with `OK\r\n` on success, `ERROR\r\n` on any
decode/parse failure. On success the row is appended to
`sessions/logs/<client>.log` in CSV form.

## GET BOF

```
/bof/<name>.x64.o\r\n
```

The C2 looks the file up in `sessions/uploads/<basename(name)>`.
On hit, the response is the file's content base64-encoded and
terminated with `\r\n`. On miss, the response is the literal
`BOF_NOT_FOUND\r\n`.

The beacon then loads the file with `RunELF()` and calls the
BOF's `go(args, alen)` entry point.

## Encryption

AES-256-CFB, 16-byte IV prepended to the ciphertext. Both the
beacon and the C2 agree on the key from `config.json`. The
Python side uses `cryptography.hazmat.primitives.ciphers` with
`modes.CFB(iv)`; the C side uses the hand-rolled CFB in
`include/aes_cfb.c` (extracted from the original beacon so it
is unit-testable).

CFB is unauthenticated. An attacker on the path can flip bits
in the encrypted command and the beacon will execute whatever
comes out. This is a known limitation; if you need integrity,
front the C2 with TLS (the `network.verify_tls` flag enables
CA verification on the beacon) and treat CFB as defense in
depth.

## Path traversal

`/bof/../../etc/passwd` is sanitised: the C2 applies
`os.path.basename()` before joining with `upload_dir`, so the
request resolves to `/sessions/uploads/passwd` (which does not
exist) and returns `BOF_NOT_FOUND`. The test
`test_path_traversal_in_bof_name` in `tests/test_c2_server.py`
pins this behaviour.
