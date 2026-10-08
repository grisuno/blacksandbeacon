# orphans

*Community 7 | 15 files | cohesion 0.00*

## Definition

This community groups 15 file(s) rooted at `tests` with dominant language py (cohesion 0.00). Central symbols: `AT_FDCWD`, `BEACON_API_H`, `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataLength`, `BeaconDataParse`, `BeaconDataPtr`, `BeaconDataShort`. Core file: `bof/is_sudo/is_sudo.c` (17 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `bof/cat/cat.c` | c | utility | 12 | yes |
| `bof/is_sudo/is_sudo.c` | c | utility | 17 | yes |
| `bof/userenum/userenum.c` | c | utility | 13 | yes |
| `bof/whoami/whoami.c` | c | utility | 14 | yes |
| `gopher_c2.py` | py | utility | 5 | no |
| `include/beacon.h` | h | utility | 13 | yes |
| `install.sh` | sh | utility | 0 | yes |
| `issudo.c` | c | utility | 17 | yes |
| `tests/test_beacon_build.py` | py | testing | 7 | yes |
| `tests/test_bof_compile.py` | py | testing | 7 | yes |
| `tests/test_c2_http_e2e.py` | py | testing | 9 | yes |
| `tests/test_config.py` | py | testing | 9 | yes |
| `tests/test_crypto.py` | py | testing | 8 | yes |
| `tests/test_install_deploy.py` | py | testing | 8 | yes |

## Key Symbols

- `NULL` (macro, `bof/cat/cat.c:3`) `#define NULL`
- `CALLBACK_OUTPUT` (macro, `bof/cat/cat.c:4`) `#define CALLBACK_OUTPUT`
- `size_t` (type_alias, `bof/cat/cat.c:7`) `typedef unsigned long size_t;` - Tipos
- `ssize_t` (type_alias, `bof/cat/cat.c:8`) `typedef long ssize_t;`
- `BeaconPrintf` (function, `bof/cat/cat.c:11`) `extern void BeaconPrintf(int, const char*, ...);` - Símbolos del beacon
- `BeaconOutput` (function, `bof/cat/cat.c:12`) `extern void BeaconOutput(int, const char*, int);`
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
- `BeaconPrintf` (function, `bof/is_sudo/is_sudo.c:11`) `extern void BeaconPrintf(int, const char*, ...);` - Símbolos del beacon
- `BeaconOutput` (function, `bof/is_sudo/is_sudo.c:12`) `extern void BeaconOutput(int, const char*, int);`
- `SYS_openat` (macro, `bof/is_sudo/is_sudo.c:15`) `#define SYS_openat`
- `SYS_read` (macro, `bof/is_sudo/is_sudo.c:16`) `#define SYS_read`
- `SYS_close` (macro, `bof/is_sudo/is_sudo.c:17`) `#define SYS_close`
- `SYS_getuid` (macro, `bof/is_sudo/is_sudo.c:18`) `#define SYS_getuid`
- `SYS_getpwuid_r` (macro, `bof/is_sudo/is_sudo.c:19`) `#define SYS_getpwuid_r`
- `AT_FDCWD` (macro, `bof/is_sudo/is_sudo.c:20`) `#define AT_FDCWD`
- `syscall3` (function, `bof/is_sudo/is_sudo.c:23`) `static inline long syscall3(long n, long a1, long a2, long a3)` - Wrappers
- `syscall1` (function, `bof/is_sudo/is_sudo.c:33`) `static inline long syscall1(long n, long a1)`
- `strcmp` (function, `bof/is_sudo/is_sudo.c:44`) `static int strcmp(const char *s1, const char *s2)` - strcmp mínimo (necesario para comparar strings)
- `get_username_from_uid` (function, `bof/is_sudo/is_sudo.c:53`) `static int get_username_from_uid(long uid, char *buf, int buf_size)` - Obtener username desde /etc/passwd (sin libc)
- `go` (function, `bof/is_sudo/is_sudo.c:109`) `void go(char *args, int alen)`
- `NULL` (macro, `bof/userenum/userenum.c:3`) `#define NULL`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 0 (root) and community 7 (orphans).
- [INFERRED] shares_context community 1 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 1 (include: cJSON) and community 7 (orphans).
- [INFERRED] shares_context community 2 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 2 (bof/include) and community 7 (orphans).
- [INFERRED] shares_context community 3 <-> 7 (strength 0.5): Inferred shared context (language py) with no import path between community 3 (include: server) and community 7 (orphans).
- [INFERRED] shares_context community 4 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 4 (include: aes) and community 7 (orphans).

## Risks

- [taint high] `tests/test_beacon_build.py` -> `tests/test_beacon_build.py` via `subprocess` (0 hops)
- [taint high] `tests/test_bof_compile.py` -> `tests/test_bof_compile.py` via `subprocess` (0 hops)
- [taint high] `tests/test_config.py` -> `tests/test_config.py` via `subprocess` (0 hops)
- [taint high] `tests/test_crypto.py` -> `tests/test_crypto.py` via `subprocess` (0 hops)
- [taint high] `tests/test_install_deploy.py` -> `tests/test_install_deploy.py` via `subprocess` (0 hops)
- [dataflow UNCHECKED_ALLOC] `gopher_c2.py:129` `main` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `gopher_c2.py`)? What purpose do they serve?
- Is the dangerous import `subprocess` in `tests/test_beacon_build.py` still required, or can it be isolated?
- What would break if the most connected file in orphans changed?
- Should orphans be split, given cohesion 0.00?

## Sources

- `app.py`
- `bof/cat/cat.c`
- `bof/is_sudo/is_sudo.c`
- `bof/userenum/userenum.c`
- `bof/whoami/whoami.c`
- `gopher_c2.py`
- `include/beacon.h`
- `install.sh`
- `issudo.c`
- `tests/test_beacon_build.py`
- `tests/test_bof_compile.py`
- `tests/test_c2_http_e2e.py`
- `tests/test_config.py`
- `tests/test_crypto.py`
- `tests/test_install_deploy.py`
