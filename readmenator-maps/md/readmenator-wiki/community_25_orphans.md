# orphans

*Community 25 | 64 files | cohesion 0.00*

## Definition

This community groups 64 file(s) rooted at `mutants/tests` with dominant language py (cohesion 0.00). Central symbols: `AT_FDCWD`, `BEACON_API_H`, `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataLength`, `BeaconDataParse`, `BeaconDataPtr`, `BeaconDataShort`. Core file: `bof/is_sudo/is_sudo.c` (17 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

### `mutants/tests` (43 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `mutants/tests/test_async_i_o_for_beacon.py` | py | testing | 2 | yes |
| `mutants/tests/test_async_i_o_for_beacon_c.c` | c | testing | 2 | no |
| `mutants/tests/test_beacon_build.py` | py | testing | 8 | yes |
| `mutants/tests/test_beacon_common.c_extraction.py` | py | testing | 0 | yes |

### `.` (6 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `contract_agent.py` | py | utility | 17 | yes |
| `gopher_c2.py` | py | utility | 5 | no |

### `tests` (5 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `tests/test_beacon_build.py` | py | testing | 8 | yes |
| `tests/test_bof_compile.py` | py | testing | 7 | yes |
| `tests/test_config.py` | py | testing | 9 | yes |

### `c2` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `c2/stage_oneliner.sh` | sh | utility | 0 | yes |
| `c2/stage_payload.py` | py | utility | 3 | yes |

### `include` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/beacon.h` | h | utility | 13 | yes |
| `include/config_py_autogen.py` | py | infrastructure | 3 | yes |

### `bof/cat` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/cat/cat.c` | c | utility | 12 | yes |

### `bof/is_sudo` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/is_sudo/is_sudo.c` | c | utility | 17 | yes |

### `bof/userenum` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/userenum/userenum.c` | c | utility | 13 | yes |

### `bof/whoami` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/whoami/whoami.c` | c | utility | 14 | yes |

### `config` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `config/generate_parsers.py` | py | infrastructure | 7 | yes |

### `scripts` (1 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `scripts/mutation_test_c.py` | py | testing | 6 | yes |

*... and 44 more files in this community.*


## Key Symbols

- `NULL` (macro, `bof/cat/cat.c:3`) `#define NULL`
- `CALLBACK_OUTPUT` (macro, `bof/cat/cat.c:4`) `#define CALLBACK_OUTPUT`
- `size_t` (type_alias, `bof/cat/cat.c:7`) `typedef unsigned long size_t;` - Tipos
- `ssize_t` (type_alias, `bof/cat/cat.c:8`) `typedef long ssize_t;`
- `BeaconPrintf` (function, `bof/cat/cat.c:11`) `extern void BeaconPrintf(int, const char *, ...);` - Símbolos del beacon
- `BeaconOutput` (function, `bof/cat/cat.c:12`) `extern void BeaconOutput(int, const char *, int);`
- `SYS_openat` (macro, `bof/cat/cat.c:15`) `#define SYS_openat`
- `SYS_read` (macro, `bof/cat/cat.c:16`) `#define SYS_read`
- `SYS_close` (macro, `bof/cat/cat.c:17`) `#define SYS_close`
- `AT_FDCWD` (macro, `bof/cat/cat.c:18`) `#define AT_FDCWD`
- `syscall3` (function, `bof/cat/cat.c:21`) `static inline long syscall3(long n, long a1, long a2, long a3)` - Wrappers (copiados de tus ejemplos)
- `go` (function, `bof/cat/cat.c:31`) `void go(char *args, int alen)`
- `NULL` (macro, `bof/is_sudo/is_sudo.c:3`) `#define NULL`
- `CALLBACK_OUTPUT` (macro, `bof/is_sudo/is_sudo.c:4`) `#define CALLBACK_OUTPUT`
- `size_t` (type_alias, `bof/is_sudo/is_sudo.c:7`) `typedef unsigned long size_t;` - Tipos
- `ssize_t` (type_alias, `bof/is_sudo/is_sudo.c:8`) `typedef long ssize_t;`
- `BeaconPrintf` (function, `bof/is_sudo/is_sudo.c:11`) `extern void BeaconPrintf(int, const char *, ...);` - Símbolos del beacon
- `BeaconOutput` (function, `bof/is_sudo/is_sudo.c:12`) `extern void BeaconOutput(int, const char *, int);`
- `SYS_openat` (macro, `bof/is_sudo/is_sudo.c:15`) `#define SYS_openat`
- `SYS_read` (macro, `bof/is_sudo/is_sudo.c:16`) `#define SYS_read`
- `SYS_close` (macro, `bof/is_sudo/is_sudo.c:17`) `#define SYS_close`
- `SYS_getuid` (macro, `bof/is_sudo/is_sudo.c:18`) `#define SYS_getuid`
- `SYS_getpwuid_r` (macro, `bof/is_sudo/is_sudo.c:19`) `#define SYS_getpwuid_r`
- `AT_FDCWD` (macro, `bof/is_sudo/is_sudo.c:20`) `#define AT_FDCWD`
- `syscall3` (function, `bof/is_sudo/is_sudo.c:23`) `static inline long syscall3(long n, long a1, long a2, long a3)` - Wrappers
- `syscall1` (function, `bof/is_sudo/is_sudo.c:33`) `static inline long syscall1(long n, long a1)`
- `strcmp` (function, `bof/is_sudo/is_sudo.c:41`) `static int strcmp(const char *s1, const char *s2)` - strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function, `bof/is_sudo/is_sudo.c:52`) `static int get_username_from_uid(long uid, char *buf, int buf_size)` - Obtener username desde /etc/passwd (sin libc)
- `go` (function, `bof/is_sudo/is_sudo.c:122`) `void go(char *args, int alen)`
- `NULL` (macro, `bof/userenum/userenum.c:3`) `#define NULL`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [taint medium] `c2/stage_payload.py` -> `c2/stage_payload.py` via `urllib.request` (0 hops)
- [taint high] `contract_agent.py` -> `contract_agent.py` via `subprocess` (0 hops)
- [taint high] `mutants/tests/test_beacon_build.py` -> `mutants/tests/test_beacon_build.py` via `subprocess` (0 hops)
- [taint high] `mutants/tests/test_bof_compile.py` -> `mutants/tests/test_bof_compile.py` via `subprocess` (0 hops)
- [taint high] `mutants/tests/test_config.py` -> `mutants/tests/test_config.py` via `subprocess` (0 hops)
- [taint high] `mutants/tests/test_crypto.py` -> `mutants/tests/test_crypto.py` via `subprocess` (0 hops)
- [taint high] `mutants/tests/test_install_deploy.py` -> `mutants/tests/test_install_deploy.py` via `subprocess` (0 hops)
- [taint high] `scripts/mutation_test_c.py` -> `scripts/mutation_test_c.py` via `subprocess` (0 hops)
- [taint high] `tests/test_beacon_build.py` -> `tests/test_beacon_build.py` via `subprocess` (0 hops)
- [taint high] `tests/test_bof_compile.py` -> `tests/test_bof_compile.py` via `subprocess` (0 hops)
- [dataflow UNCHECKED_ALLOC] `gopher_c2.py:145` `main` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- Why do 21 file(s) lack file-level docs (e.g. `gopher_c2.py`)? What purpose do they serve?
- Is the dangerous import `urllib.request` in `c2/stage_payload.py` still required, or can it be isolated?
- What would break if the most connected file in orphans changed?
- Should orphans be split, given cohesion 0.00?

## Sources

- `app.py`
- `bof/cat/cat.c`
- `bof/is_sudo/is_sudo.c`
- `bof/userenum/userenum.c`
- `bof/whoami/whoami.c`
- `c2/stage_oneliner.sh`
- `c2/stage_payload.py`
- `config/generate_parsers.py`
- `contract_agent.py`
- `gopher_c2.py`
- `include/beacon.h`
- `include/config_py_autogen.py`
- `install.sh`
- `issudo.c`
- `mutants/tests/test_async_i_o_for_beacon.py`
- `mutants/tests/test_async_i_o_for_beacon_c.c`
- `mutants/tests/test_beacon_build.py`
- `mutants/tests/test_beacon_common.c_extraction.py`
- `mutants/tests/test_beacon_common.c_extraction_c.c`
- `mutants/tests/test_beacon_heartbeat___health_endpoint.py`
- *... and 44 more*
