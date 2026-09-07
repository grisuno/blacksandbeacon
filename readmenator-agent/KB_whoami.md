# Subsystem: whoami

## bof/whoami/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 18) `void go(char *args, int alen)`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/whoami/whoami.c
- Layer: utility
- Doc: whoami.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos
- Language: c
- Symbols:
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 30) `static inline long syscall1(long n, long a1)`
  - `go` (function, line 40) `void go(char *args, int alen)`
  - `NULL` (macro, line 2)
  - `CALLBACK_OUTPUT` (macro, line 3)
  - `SYS_openat` (macro, line 14)
  - `SYS_read` (macro, line 15)
  - `SYS_close` (macro, line 16)
  - `SYS_getuid` (macro, line 17)
  - `AT_FDCWD` (macro, line 18)
