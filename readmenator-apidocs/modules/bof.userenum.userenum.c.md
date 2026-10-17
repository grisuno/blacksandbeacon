# `bof/userenum/userenum.c`

> Source: [bof/userenum/userenum.c:1](../../bof/userenum/userenum.c#L1) | language `c` | coverage 66.7% | [API index](../index.md)

## Contents

- **Type Aliases:** [`size_t`](#size_t), [`ssize_t`](#ssize_t)
- **Functions:** [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`go`](#go)
- **Macros:** [`NULL`](#null), [`CALLBACK_OUTPUT`](#callback_output), [`SYS_openat`](#sys_openat), [`SYS_read`](#sys_read), [`SYS_close`](#sys_close), [`AT_FDCWD`](#at_fdcwd)

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
    n_bof_userenum_userenum_c__go(["go"])
    n_bof_userenum_userenum_c__BeaconPrintf(["BeaconPrintf"])
    n_bof_userenum_userenum_c__AT_FDCWD(["AT_FDCWD"])
    n_bof_include_syscalls_h__syscall3["syscalls.syscall3"]
    n_bof_userenum_userenum_c__go --> n_bof_userenum_userenum_c__BeaconPrintf
    n_bof_userenum_userenum_c__AT_FDCWD -.-> n_bof_include_syscalls_h__syscall3
    n_bof_userenum_userenum_c__go -.-> n_bof_include_syscalls_h__syscall3
```

## Type Aliases

<a id="size_t"></a>

### `size_t`

`type_alias` | [bof/userenum/userenum.c:7](../../bof/userenum/userenum.c#L7)

```c
typedef unsigned long size_t;
```

Tipos

---

<a id="ssize_t"></a>

### `ssize_t`

`type_alias` | [bof/userenum/userenum.c:8](../../bof/userenum/userenum.c#L8)

```c
typedef long ssize_t;
```

---

## Functions

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` `extern` | [bof/userenum/userenum.c:11](../../bof/userenum/userenum.c#L11)

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

`function` `extern` | [bof/userenum/userenum.c:12](../../bof/userenum/userenum.c#L12)

```c
extern void BeaconOutput(int, const char*, int);
```

Beacon API: raw output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `char` |  |  |  |

> **Inherited:** Documentation from [`BeaconOutput`](#beaconoutput) (include/beacon_common.h:105).

---

<a id="go"></a>

### `go`

`function` | [bof/userenum/userenum.c:41](../../bof/userenum/userenum.c#L41)

```c
void go(char *args, int alen)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

*Calls:* [`syscall3`](bof.include.syscalls.h.md#syscall3), [`BeaconPrintf`](#beaconprintf)

---

## Macros

<a id="null"></a>

### `NULL`

`macro` | [bof/userenum/userenum.c:3](../../bof/userenum/userenum.c#L3)

```c
#define NULL
```

is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o

---

<a id="callback_output"></a>

### `CALLBACK_OUTPUT`

`macro` | [bof/userenum/userenum.c:4](../../bof/userenum/userenum.c#L4)

```c
#define CALLBACK_OUTPUT
```

Tipos de callback

> **Inherited:** Documentation from [`CALLBACK_OUTPUT`](#callback_output) (beacon.h:9).

---

<a id="sys_openat"></a>

### `SYS_openat`

`macro` | [bof/userenum/userenum.c:15](../../bof/userenum/userenum.c#L15)

```c
#define SYS_openat
```

Syscalls

---

<a id="sys_read"></a>

### `SYS_read`

`macro` | [bof/userenum/userenum.c:16](../../bof/userenum/userenum.c#L16)

```c
#define SYS_read
```

Syscall numbers - x86_64 Linux ABI.

> **Inherited:** Documentation from [`SYS_read`](#sys_read) (bof/include/syscalls.h:17).

---

<a id="sys_close"></a>

### `SYS_close`

`macro` | [bof/userenum/userenum.c:17](../../bof/userenum/userenum.c#L17)

```c
#define SYS_close
```

---

<a id="at_fdcwd"></a>

### `AT_FDCWD`

`macro` | [bof/userenum/userenum.c:18](../../bof/userenum/userenum.c#L18)

```c
#define AT_FDCWD
```

Special fd value meaning "current working directory".

> **Inherited:** Documentation from [`AT_FDCWD`](#at_fdcwd) (bof/include/syscalls.h:47).

*Calls:* [`syscall3`](bof.include.syscalls.h.md#syscall3)

---
