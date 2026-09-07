# Subsystem: cat

## bof/cat/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 14) `void go(char *args, int alen)`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/cat/cat.c
- Layer: utility
- Doc: readfile.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o define NULL ((void*)0) d
- Language: c
- Symbols:
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `go` (function, line 30) `void go(char *args, int alen)`
  - `NULL` (macro, line 3)
  - `CALLBACK_OUTPUT` (macro, line 4)
  - `SYS_openat` (macro, line 15)
  - `SYS_read` (macro, line 16)
  - `SYS_close` (macro, line 17)
  - `AT_FDCWD` (macro, line 18)
