# `bof/is_sudo/is_sudo.c`

> Source: [bof/is_sudo/is_sudo.c:1](../../bof/is_sudo/is_sudo.c#L1) | language `c` | coverage 57.1% | [API index](../index.md)

## Contents

- **Type Aliases:** [`size_t`](#size_t), [`ssize_t`](#ssize_t)
- **Functions:** [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`go`](#go)
- **Macros:** [`NULL`](#null), [`CALLBACK_OUTPUT`](#callback_output), [`SYS_openat`](#sys_openat), [`SYS_read`](#sys_read), [`SYS_close`](#sys_close), [`SYS_getuid`](#sys_getuid), [`SYS_getpwuid_r`](#sys_getpwuid_r), [`AT_FDCWD`](#at_fdcwd)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class size_t
    <<type_alias>> size_t
    class ssize_t
    <<type_alias>> ssize_t
```

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_bof_is_sudo_is_sudo_c__go(["go"])
    n_bof_is_sudo_is_sudo_c__BeaconOutput(["BeaconOutput"])
    n_bof_is_sudo_is_sudo_c__BeaconPrintf(["BeaconPrintf"])
    n_bof_is_sudo_is_sudo_c__AT_FDCWD(["AT_FDCWD"])
    n_bof_include_syscalls_h__syscall3["syscalls.syscall3"]
    n_bof_include_syscalls_h__syscall1["syscalls.syscall1"]
    n_bof_is_sudo_is_sudo_c__go --> n_bof_is_sudo_is_sudo_c__BeaconOutput
    n_bof_is_sudo_is_sudo_c__go --> n_bof_is_sudo_is_sudo_c__BeaconPrintf
    n_bof_is_sudo_is_sudo_c__AT_FDCWD -.-> n_bof_include_syscalls_h__syscall3
    n_bof_is_sudo_is_sudo_c__go -.-> n_bof_include_syscalls_h__syscall1
    n_bof_is_sudo_is_sudo_c__go -.-> n_bof_include_syscalls_h__syscall3
```

## Type Aliases

<a id="size_t"></a>

### `size_t`

`type_alias` | [bof/is_sudo/is_sudo.c:7](../../bof/is_sudo/is_sudo.c#L7)

```c
typedef unsigned long size_t;
```

Tipos

---

<a id="ssize_t"></a>

### `ssize_t`

`type_alias` | [bof/is_sudo/is_sudo.c:8](../../bof/is_sudo/is_sudo.c#L8)

```c
typedef long ssize_t;
```

---

## Functions

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` `extern` | [bof/is_sudo/is_sudo.c:11](../../bof/is_sudo/is_sudo.c#L11)

```c
extern void BeaconPrintf(int, const char*, ...);
```

Símbolos del beacon

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `char` |  |  |  |
| `...` |  |  |  |

*Called by:* [`go`](#go)

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` `extern` | [bof/is_sudo/is_sudo.c:12](../../bof/is_sudo/is_sudo.c#L12)

```c
extern void BeaconOutput(int, const char*, int);
```

Beacon API: raw output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `char` |  |  |  |

> **Inherited:** Documentation from [`BeaconOutput`](#beaconoutput) (include/beacon_common.h:105).

*Called by:* [`go`](#go)

---

<a id="go"></a>

### `go`

`function` | [bof/is_sudo/is_sudo.c:109](../../bof/is_sudo/is_sudo.c#L109)

```c
void go(char *args, int alen)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

*Calls:* [`syscall1`](bof.include.syscalls.h.md#syscall1), [`syscall3`](bof.include.syscalls.h.md#syscall3), [`BeaconOutput`](#beaconoutput), [`BeaconPrintf`](#beaconprintf)

---

## Macros

<a id="null"></a>

### `NULL`

`macro` | [bof/is_sudo/is_sudo.c:3](../../bof/is_sudo/is_sudo.c#L3)

```c
#define NULL
```

is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o

---

<a id="callback_output"></a>

### `CALLBACK_OUTPUT`

`macro` | [bof/is_sudo/is_sudo.c:4](../../bof/is_sudo/is_sudo.c#L4)

```c
#define CALLBACK_OUTPUT
```

Tipos de callback

> **Inherited:** Documentation from [`CALLBACK_OUTPUT`](#callback_output) (beacon.h:9).

---

<a id="sys_openat"></a>

### `SYS_openat`

`macro` | [bof/is_sudo/is_sudo.c:15](../../bof/is_sudo/is_sudo.c#L15)

```c
#define SYS_openat
```

Syscalls

---

<a id="sys_read"></a>

### `SYS_read`

`macro` | [bof/is_sudo/is_sudo.c:16](../../bof/is_sudo/is_sudo.c#L16)

```c
#define SYS_read
```

Syscall numbers - x86_64 Linux ABI.

> **Inherited:** Documentation from [`SYS_read`](#sys_read) (bof/include/syscalls.h:17).

---

<a id="sys_close"></a>

### `SYS_close`

`macro` | [bof/is_sudo/is_sudo.c:17](../../bof/is_sudo/is_sudo.c#L17)

```c
#define SYS_close
```

---

<a id="sys_getuid"></a>

### `SYS_getuid`

`macro` | [bof/is_sudo/is_sudo.c:18](../../bof/is_sudo/is_sudo.c#L18)

```c
#define SYS_getuid
```

---

<a id="sys_getpwuid_r"></a>

### `SYS_getpwuid_r`

`macro` | [bof/is_sudo/is_sudo.c:19](../../bof/is_sudo/is_sudo.c#L19)

```c
#define SYS_getpwuid_r
```

---

<a id="at_fdcwd"></a>

### `AT_FDCWD`

`macro` | [bof/is_sudo/is_sudo.c:20](../../bof/is_sudo/is_sudo.c#L20)

```c
#define AT_FDCWD
```

Special fd value meaning "current working directory".

> **Inherited:** Documentation from [`AT_FDCWD`](#at_fdcwd) (bof/include/syscalls.h:47).

*Calls:* [`syscall3`](bof.include.syscalls.h.md#syscall3)

---
