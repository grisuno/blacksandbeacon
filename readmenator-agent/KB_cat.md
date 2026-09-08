# Subsystem: cat

## bof/cat/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 14) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 17) `BeaconPrintf(CALLBACK_OUTPUT, "[cat] missing path argument\n");`
  - `BeaconOutput` (function, line 34) `BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);`
  - `syscall1` (function, line 37) `syscall1(SYS_close, fd);`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/cat/cat.c
- Layer: utility
- Doc: readfile.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o define NULL ((void*)0) d
- Language: c
- Symbols:
  - `size_t` (type_alias, line 7) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 8) `typedef long ssize_t;`
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `go` (function, line 30) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 11) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 12) `extern void BeaconOutput(int, const char*, int);`
  - `volatile` (function, line 23) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
  - `NULL` (macro, line 3) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 4) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 15) `#define SYS_openat`
  - `SYS_read` (macro, line 16) `#define SYS_read`
  - `SYS_close` (macro, line 17) `#define SYS_close`
  - `AT_FDCWD` (macro, line 18) `#define AT_FDCWD`
