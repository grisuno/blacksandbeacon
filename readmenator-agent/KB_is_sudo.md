# Subsystem: is_sudo

## bof/is_sudo/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `user_in_group` (function, line 14) `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)`
  - `go` (function, line 56) `void go(char *args, int alen)`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## bof/is_sudo/is_sudo.c
- Layer: utility
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o define NULL ((voi
- Language: c
- Symbols:
  - `syscall3` (function, line 23) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 32) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 44) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 53) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 108) `void go(char *args, int alen)`
  - `NULL` (macro, line 3)
  - `CALLBACK_OUTPUT` (macro, line 4)
  - `SYS_openat` (macro, line 15)
  - `SYS_read` (macro, line 16)
  - `SYS_close` (macro, line 17)
  - `SYS_getuid` (macro, line 18)
  - `SYS_getpwuid_r` (macro, line 19)
  - `AT_FDCWD` (macro, line 20)
