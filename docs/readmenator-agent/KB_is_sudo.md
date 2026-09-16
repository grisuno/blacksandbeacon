# Subsystem: is_sudo

## bof/is_sudo/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `user_in_group` (function, line 14) `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
  - `go` (function, line 56) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 68) `BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] uid=0 (root)\n");`
  - `BeaconOutput` (function, line 69) `BeaconOutput(CALLBACK_OUTPUT, "yes", 0);`
  - `syscall1` (function, line 96) `syscall1(SYS_close, fd);`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/is_sudo/is_sudo.c
- Layer: utility
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o define NULL ((voi
- Language: c
- Symbols:
  - `size_t` (type_alias, line 7) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 8) `typedef long ssize_t;`
  - `syscall3` (function, line 23) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 32) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 44) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 53) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 108) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 11) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 12) `extern void BeaconOutput(int, const char*, int);`
  - `volatile` (function, line 25) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`
  - `NULL` (macro, line 3) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 4) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 15) `#define SYS_openat`
  - `SYS_read` (macro, line 16) `#define SYS_read`
  - `SYS_close` (macro, line 17) `#define SYS_close`
  - `SYS_getuid` (macro, line 18) `#define SYS_getuid`
  - `SYS_getpwuid_r` (macro, line 19) `#define SYS_getpwuid_r`
  - `AT_FDCWD` (macro, line 20) `#define AT_FDCWD`
