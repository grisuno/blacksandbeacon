# BOF Authoring Guide

A BOF (Beacon Object File) is a position-independent ELF object
the beacon loads into its own process at runtime. There is no
process boundary, no shell, no interpreter. The BOF's `go` runs
in the beacon's address space with the beacon's privileges.

This document covers the contract, the build, the loader's
limitations, and the things that will silently break if you get
them wrong.

## Contract

Every BOF must export exactly one symbol:

```c
void go(char *args, int alen);
```

`args` is a raw byte buffer the operator passed when scheduling
the BOF. `alen` is its length. There is no automatic
serialisation: if you want structured args, parse them yourself
(use the helpers in `beacon_api.h` if your buffer is Cobalt
Strike-style).

The function must return. It must not call `exit()` (libc is
not linked). To stop early, just `return`.

## The two APIs the beacon provides

```
void BeaconPrintf(int type, const char *fmt, ...);
void BeaconOutput(int type, const char *data, int len);
```

`BeaconPrintf` works like `printf` but writes into the beacon's
result buffer. `BeaconOutput` takes a raw byte buffer and an
explicit length - useful for binary data.

Both `type` values are callback types from the header. In
practice you want `CALLBACK_OUTPUT` (0). Other values are
reserved for future use.

## The headers

`bof/include/beacon_api.h`
- declares `BeaconPrintf`, `BeaconOutput`, the `datap` parser
  helpers, and the callback-type constants.

`bof/include/syscalls.h`
- declares inline wrappers for the x86_64 Linux syscalls
  (`SYS_openat`, `SYS_read`, `SYS_getuid`, etc.)
- declares a `bsf_strlen` / `bsf_strcmp` / `bsf_memcmp` triplet
  that you need because libc is not linked.

Include both. Do not redeclare `BeaconPrintf`/`BeaconOutput`
yourself - it will fail to compile with a conflicting-types
error against the header.

## Build

The Makefile wraps the gcc invocation:

```
make bof-<name>
```

Which expands to:

```
gcc -c -fPIC -nostdlib -m64 -O2 -I bof/include \
    bof/<name>/bof.c -o build/bof/<name>.x64.o
```

Flags you must keep:

| Flag | Why |
|---|---|
| `-c` | Produce an object, not an executable |
| `-fPIC` | Position-independent code, required for runtime relocation |
| `-nostdlib` | No glibc, no startup files, no libc headers |
| `-m64` | x86_64 ABI |

If you break the loader by removing any of these, the failure
will be visible at load time, not compile time.

## Symbol resolution

The beacon's loader resolves these symbols from the BOF:

- `BeaconPrintf`
- `BeaconOutput`
- `BeaconDataParse` / `BeaconDataPtr` / `BeaconDataInt` / etc.
  (only if your BOF actually references them)

Anything else you call must be defined in the BOF itself. There
is no implicit libc, no `printf`, no `malloc`. If you need
memory, use `brk`/`mmap` via the syscall wrappers.

The `tests/test_bof_compile.py` suite catches the most common
mistake: leaking a libc reference. The list of forbidden
undefined symbols includes `printf`, `puts`, `malloc`, `strlen`,
`strcmp`, `memcpy`, `exit`, and `fprintf`.

## Pitfalls

- **Stack alignment.** Some libc-free paths blow up on SSE
  instructions (e.g. `movaps`) if the stack is misaligned. The
  default 16-byte alignment from the C ABI is fine for typical
  BOF code; just don't write inline assembly that ends on an
  8-byte boundary.
- **Argv length.** `alen` is `int`, not `size_t`. A negative
  value is the loader's "no args" signal - check for it.
- **NUL termination.** The loader passes a NUL-terminated
  `args` buffer for string-shaped arguments but not for binary
  payloads. If you treat binary args as a string you'll truncate.
- **Long jumps.** If you write a BOF larger than the trampoline
  cache the loader uses (see `beacons/v1/beacon.c` `trampoline_*`
  functions), you will hit a relocation error. Keep individual
  BOFs under a few hundred KB.
- **File output.** Use `SYS_write` to `STDOUT_FILENO` (1) or
  `STDERR_FILENO` (2) for direct file output, not `fwrite`.

## Testing your BOF locally

Compile with the Makefile and then inspect the symbol table:

```
make bof-mine
nm build/bof/mine.x64.o | grep -E '^[Tt]|^[Uu]'
```

You should see:

- `T go` - the entry point is defined
- `U BeaconPrintf` and `U BeaconOutput` - the API is referenced
  but not defined (the loader will fill them in)

If `go` is missing, the loader will not be able to call it. If
`BeaconPrintf` shows up as defined, your BOF is wrong: the
beacon would call *your* copy instead of its real one.

The test suite (`make test`) automates these checks for the
shipped BOFs; you can extend it to cover your own by adding
your BOF name to the `BOFS` list in `tests/test_bof_compile.py`.

## Deploying

Drop the `.x64.o` into `sessions/uploads/` on the C2 host. The
beacon will fetch it the first time a `bof:<name>` command is
scheduled. Files are served verbatim; there is no signing or
integrity check in the protocol.
