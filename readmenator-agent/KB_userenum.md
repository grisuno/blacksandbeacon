# Subsystem: userenum

## bof/userenum/bof.c
- Layer: utility
- Language: c
- Symbols:
  - `user_in_member_list` (function, line 51) `static int user_in_member_list(const char *username, const char *members)`
  - `go` (function, line 67) `void go(char *args, int alen)`

## bof/userenum/userenum.c
- Layer: utility
- Doc: is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o define NULL ((v
- Language: c
- Symbols:
  - `syscall3` (function, line 21) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `strcmp` (function, line 33) `static int strcmp(const char *s1, const char *s2)`
  - `go` (function, line 40) `void go(char *args, int alen)`
  - `NULL` (macro, line 3)
  - `CALLBACK_OUTPUT` (macro, line 4)
  - `SYS_openat` (macro, line 15)
  - `SYS_read` (macro, line 16)
  - `SYS_close` (macro, line 17)
  - `AT_FDCWD` (macro, line 18)
