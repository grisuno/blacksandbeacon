# Subsystem: whoami

## bof/whoami/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 18) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 30) `BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=0 (root)\n");`
  - `BeaconOutput` (function, line 31) `BeaconOutput(CALLBACK_OUTPUT, "root", 0);`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/whoami/whoami.c
- Layer: utility
- Doc: whoami.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos
- Language: c
- Symbols:
  - `size_t` (type_alias, line 6) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 7) `typedef long ssize_t;`
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 30) `static inline long syscall1(long n, long a1)`
  - `go` (function, line 40) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 10) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 11) `extern void BeaconOutput(int, const char*, int);`
  - `volatile` (function, line 23) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
  - `NULL` (macro, line 2) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 3) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 14) `#define SYS_openat`
  - `SYS_read` (macro, line 15) `#define SYS_read`
  - `SYS_close` (macro, line 16) `#define SYS_close`
  - `SYS_getuid` (macro, line 17) `#define SYS_getuid`
  - `AT_FDCWD` (macro, line 18) `#define AT_FDCWD`
