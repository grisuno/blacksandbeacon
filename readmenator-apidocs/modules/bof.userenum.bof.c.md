# `bof/userenum/bof.c`

> Source: [bof/userenum/bof.c:1](../../bof/userenum/bof.c#L1) | language `c` | coverage 0.0% | [API index](../index.md)

## Contents

- **Functions:** [`go`](#go)

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_bof_userenum_bof_c__go(["go"])
    n_bof_include_syscalls_h__syscall1["syscalls.syscall1"]
    n_bof_include_syscalls_h__syscall3["syscalls.syscall3"]
    n_bof_userenum_bof_c__go -.-> n_bof_include_syscalls_h__syscall1
    n_bof_userenum_bof_c__go -.-> n_bof_include_syscalls_h__syscall3
```

## Functions

<a id="go"></a>

### `go`

`function` | [bof/userenum/bof.c:68](../../bof/userenum/bof.c#L68)

```c
void go(char *args, int alen)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

*Calls:* [`syscall1`](bof.include.syscalls.h.md#syscall1), [`syscall3`](bof.include.syscalls.h.md#syscall3)

---
