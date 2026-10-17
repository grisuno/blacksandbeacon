# `bof/whoami/bof.c`

> Source: [bof/whoami/bof.c:1](../../bof/whoami/bof.c#L1) | language `c` | coverage 0.0% | [API index](../index.md)

## Contents

- **Functions:** [`go`](#go)

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_bof_whoami_bof_c__go(["go"])
    n_bof_include_beacon_api_h__BeaconOutput["beacon_api.BeaconOutput"]
    n_bof_include_syscalls_h__syscall1["syscalls.syscall1"]
    n_bof_whoami_bof_c__go -.-> n_bof_include_beacon_api_h__BeaconOutput
    n_bof_whoami_bof_c__go -.-> n_bof_include_syscalls_h__syscall1
```

## Functions

<a id="go"></a>

### `go`

`function` | [bof/whoami/bof.c:19](../../bof/whoami/bof.c#L19)

```c
void go(char *args, int alen)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

*Calls:* [`BeaconOutput`](bof.include.beacon_api.h.md#beaconoutput), [`syscall1`](bof.include.syscalls.h.md#syscall1)

---
