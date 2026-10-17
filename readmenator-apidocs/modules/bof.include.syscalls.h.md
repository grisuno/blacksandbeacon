# `bof/include/syscalls.h`

> Source: [bof/include/syscalls.h:1](../../bof/include/syscalls.h#L1) | language `h` | coverage 13.2% | [API index](../index.md)

## Contents

- **Functions:** [`syscall0`](#syscall0), [`syscall1`](#syscall1), [`syscall2`](#syscall2), [`syscall3`](#syscall3), [`syscall4`](#syscall4), [`bsf_strlen`](#bsf_strlen), [`bsf_strcmp`](#bsf_strcmp), [`bsf_memcmp`](#bsf_memcmp)
- **Macros:** [`SYS_read`](#sys_read), [`SYS_write`](#sys_write), [`SYS_open`](#sys_open), [`SYS_close`](#sys_close), [`SYS_stat`](#sys_stat), [`SYS_fstat`](#sys_fstat), [`SYS_lseek`](#sys_lseek), [`SYS_mmap`](#sys_mmap), [`SYS_munmap`](#sys_munmap), [`SYS_brk`](#sys_brk), [`SYS_ioctl`](#sys_ioctl), [`SYS_access`](#sys_access), [`SYS_pipe`](#sys_pipe), [`SYS_dup2`](#sys_dup2), [`SYS_fork`](#sys_fork), [`SYS_execve`](#sys_execve), [`SYS_exit`](#sys_exit), [`SYS_wait4`](#sys_wait4), [`SYS_getuid`](#sys_getuid), [`SYS_getgid`](#sys_getgid), [`SYS_geteuid`](#sys_geteuid), [`SYS_getegid`](#sys_getegid), [`SYS_getpid`](#sys_getpid), [`SYS_getppid`](#sys_getppid), [`SYS_getpwnam_r`](#sys_getpwnam_r), [`SYS_getpwuid_r`](#sys_getpwuid_r), [`SYS_openat`](#sys_openat), [`SYS_clone`](#sys_clone), [`AT_FDCWD`](#at_fdcwd)

## Functions

<a id="syscall0"></a>

### `syscall0`

`function` `inline` `static` | [bof/include/syscalls.h:49](../../bof/include/syscalls.h#L49)

```c
static inline long syscall0(long n)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `n` | `long` |  |  |

**Returns:** `long`

---

<a id="syscall1"></a>

### `syscall1`

`function` `inline` `static` | [bof/include/syscalls.h:60](../../bof/include/syscalls.h#L60)

```c
static inline long syscall1(long n, long a1)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `n` | `long` |  |  |
| `a1` | `long` |  |  |

**Returns:** `long`

*Called by:* [`go`](bof.cat.bof.c.md#go), [`go`](bof.is_sudo.bof.c.md#go), [`go`](bof.is_sudo.is_sudo.c.md#go), [`go`](bof.userenum.bof.c.md#go), [`go`](bof.whoami.bof.c.md#go), [`go`](bof.whoami.whoami.c.md#go), [`go`](issudo.c.md#go)

---

<a id="syscall2"></a>

### `syscall2`

`function` `inline` `static` | [bof/include/syscalls.h:71](../../bof/include/syscalls.h#L71)

```c
static inline long syscall2(long n, long a1, long a2)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `n` | `long` |  |  |
| `a1` | `long` |  |  |
| `a2` | `long` |  |  |

**Returns:** `long`

---

<a id="syscall3"></a>

### `syscall3`

`function` `inline` `static` | [bof/include/syscalls.h:82](../../bof/include/syscalls.h#L82)

```c
static inline long syscall3(long n, long a1, long a2, long a3)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `n` | `long` |  |  |
| `a1` | `long` |  |  |
| `a2` | `long` |  |  |
| `a3` | `long` |  |  |

**Returns:** `long`

*Called by:* [`go`](bof.cat.bof.c.md#go), [`AT_FDCWD`](bof.cat.cat.c.md#at_fdcwd), [`go`](bof.cat.cat.c.md#go), [`go`](bof.is_sudo.bof.c.md#go), [`AT_FDCWD`](bof.is_sudo.is_sudo.c.md#at_fdcwd), [`go`](bof.is_sudo.is_sudo.c.md#go), [`go`](bof.userenum.bof.c.md#go), [`AT_FDCWD`](bof.userenum.userenum.c.md#at_fdcwd), [`go`](bof.userenum.userenum.c.md#go), [`AT_FDCWD`](bof.whoami.whoami.c.md#at_fdcwd), [`go`](bof.whoami.whoami.c.md#go), [`AT_FDCWD`](issudo.c.md#at_fdcwd) and 1 more

---

<a id="syscall4"></a>

### `syscall4`

`function` `inline` `static` | [bof/include/syscalls.h:93](../../bof/include/syscalls.h#L93)

```c
static inline long syscall4(long n, long a1, long a2, long a3, long a4)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `n` | `long` |  |  |
| `a1` | `long` |  |  |
| `a2` | `long` |  |  |
| `a3` | `long` |  |  |
| `a4` | `long` |  |  |

**Returns:** `long`

---

<a id="bsf_strlen"></a>

### `bsf_strlen`

`function` `inline` `static` | [bof/include/syscalls.h:106](../../bof/include/syscalls.h#L106)

```c
static inline size_t bsf_strlen(const char *s)
```

strlen - libc is not linked.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `s` | `char *` |  |  |

**Returns:** `size_t`

---

<a id="bsf_strcmp"></a>

### `bsf_strcmp`

`function` `inline` `static` | [bof/include/syscalls.h:113](../../bof/include/syscalls.h#L113)

```c
static inline int bsf_strcmp(const char *a, const char *b)
```

strcmp - libc is not linked.

Returns 0 on match.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `a` | `char *` |  |  |
| `b` | `char *` |  |  |

**Returns:** `int`

---

<a id="bsf_memcmp"></a>

### `bsf_memcmp`

`function` `inline` `static` | [bof/include/syscalls.h:119](../../bof/include/syscalls.h#L119)

```c
static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)
```

memcmp - libc is not linked.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `p1` | `void *` |  |  |
| `p2` | `void *` |  |  |
| `n` | `size_t` |  |  |

**Returns:** `int`

---

## Macros

<a id="sys_read"></a>

### `SYS_read`

`macro` | [bof/include/syscalls.h:17](../../bof/include/syscalls.h#L17)

```c
#define SYS_read
```

Syscall numbers - x86_64 Linux ABI.

---

<a id="sys_write"></a>

### `SYS_write`

`macro` | [bof/include/syscalls.h:18](../../bof/include/syscalls.h#L18)

```c
#define SYS_write
```

---

<a id="sys_open"></a>

### `SYS_open`

`macro` | [bof/include/syscalls.h:19](../../bof/include/syscalls.h#L19)

```c
#define SYS_open
```

---

<a id="sys_close"></a>

### `SYS_close`

`macro` | [bof/include/syscalls.h:20](../../bof/include/syscalls.h#L20)

```c
#define SYS_close
```

---

<a id="sys_stat"></a>

### `SYS_stat`

`macro` | [bof/include/syscalls.h:21](../../bof/include/syscalls.h#L21)

```c
#define SYS_stat
```

---

<a id="sys_fstat"></a>

### `SYS_fstat`

`macro` | [bof/include/syscalls.h:22](../../bof/include/syscalls.h#L22)

```c
#define SYS_fstat
```

---

<a id="sys_lseek"></a>

### `SYS_lseek`

`macro` | [bof/include/syscalls.h:23](../../bof/include/syscalls.h#L23)

```c
#define SYS_lseek
```

---

<a id="sys_mmap"></a>

### `SYS_mmap`

`macro` | [bof/include/syscalls.h:24](../../bof/include/syscalls.h#L24)

```c
#define SYS_mmap
```

---

<a id="sys_munmap"></a>

### `SYS_munmap`

`macro` | [bof/include/syscalls.h:25](../../bof/include/syscalls.h#L25)

```c
#define SYS_munmap
```

---

<a id="sys_brk"></a>

### `SYS_brk`

`macro` | [bof/include/syscalls.h:26](../../bof/include/syscalls.h#L26)

```c
#define SYS_brk
```

---

<a id="sys_ioctl"></a>

### `SYS_ioctl`

`macro` | [bof/include/syscalls.h:27](../../bof/include/syscalls.h#L27)

```c
#define SYS_ioctl
```

---

<a id="sys_access"></a>

### `SYS_access`

`macro` | [bof/include/syscalls.h:28](../../bof/include/syscalls.h#L28)

```c
#define SYS_access
```

---

<a id="sys_pipe"></a>

### `SYS_pipe`

`macro` | [bof/include/syscalls.h:29](../../bof/include/syscalls.h#L29)

```c
#define SYS_pipe
```

---

<a id="sys_dup2"></a>

### `SYS_dup2`

`macro` | [bof/include/syscalls.h:30](../../bof/include/syscalls.h#L30)

```c
#define SYS_dup2
```

---

<a id="sys_fork"></a>

### `SYS_fork`

`macro` | [bof/include/syscalls.h:31](../../bof/include/syscalls.h#L31)

```c
#define SYS_fork
```

---

<a id="sys_execve"></a>

### `SYS_execve`

`macro` | [bof/include/syscalls.h:32](../../bof/include/syscalls.h#L32)

```c
#define SYS_execve
```

---

<a id="sys_exit"></a>

### `SYS_exit`

`macro` | [bof/include/syscalls.h:33](../../bof/include/syscalls.h#L33)

```c
#define SYS_exit
```

---

<a id="sys_wait4"></a>

### `SYS_wait4`

`macro` | [bof/include/syscalls.h:34](../../bof/include/syscalls.h#L34)

```c
#define SYS_wait4
```

---

<a id="sys_getuid"></a>

### `SYS_getuid`

`macro` | [bof/include/syscalls.h:35](../../bof/include/syscalls.h#L35)

```c
#define SYS_getuid
```

---

<a id="sys_getgid"></a>

### `SYS_getgid`

`macro` | [bof/include/syscalls.h:36](../../bof/include/syscalls.h#L36)

```c
#define SYS_getgid
```

---

<a id="sys_geteuid"></a>

### `SYS_geteuid`

`macro` | [bof/include/syscalls.h:37](../../bof/include/syscalls.h#L37)

```c
#define SYS_geteuid
```

---

<a id="sys_getegid"></a>

### `SYS_getegid`

`macro` | [bof/include/syscalls.h:38](../../bof/include/syscalls.h#L38)

```c
#define SYS_getegid
```

---

<a id="sys_getpid"></a>

### `SYS_getpid`

`macro` | [bof/include/syscalls.h:39](../../bof/include/syscalls.h#L39)

```c
#define SYS_getpid
```

---

<a id="sys_getppid"></a>

### `SYS_getppid`

`macro` | [bof/include/syscalls.h:40](../../bof/include/syscalls.h#L40)

```c
#define SYS_getppid
```

---

<a id="sys_getpwnam_r"></a>

### `SYS_getpwnam_r`

`macro` | [bof/include/syscalls.h:41](../../bof/include/syscalls.h#L41)

```c
#define SYS_getpwnam_r
```

---

<a id="sys_getpwuid_r"></a>

### `SYS_getpwuid_r`

`macro` | [bof/include/syscalls.h:42](../../bof/include/syscalls.h#L42)

```c
#define SYS_getpwuid_r
```

---

<a id="sys_openat"></a>

### `SYS_openat`

`macro` | [bof/include/syscalls.h:43](../../bof/include/syscalls.h#L43)

```c
#define SYS_openat
```

---

<a id="sys_clone"></a>

### `SYS_clone`

`macro` | [bof/include/syscalls.h:44](../../bof/include/syscalls.h#L44)

```c
#define SYS_clone
```

---

<a id="at_fdcwd"></a>

### `AT_FDCWD`

`macro` | [bof/include/syscalls.h:47](../../bof/include/syscalls.h#L47)

```c
#define AT_FDCWD
```

Special fd value meaning "current working directory".

---
