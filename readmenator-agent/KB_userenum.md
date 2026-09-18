# Subsystem: userenum

## bof/userenum/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `user_in_member_list` (function, line 52) `static int user_in_member_list(const char *username, const char *members)`
  - `go` (function, line 68) `void go(char *args, int alen)`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/userenum/userenum.c
- Layer: utility
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o  Tipos
- Language: c
- Symbols:
  - `size_t` (type_alias, line 7) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 8) `typedef long ssize_t;`
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `strcmp` (function, line 33) `static int strcmp(const char *s1, const char *s2)`
  - `go` (function, line 41) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 11) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 12) `extern void BeaconOutput(int, const char*, int);`
  - `NULL` (macro, line 3) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 4) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 15) `#define SYS_openat`
  - `SYS_read` (macro, line 16) `#define SYS_read`
  - `SYS_close` (macro, line 17) `#define SYS_close`
  - `AT_FDCWD` (macro, line 18) `#define AT_FDCWD`
