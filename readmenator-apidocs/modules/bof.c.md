# `bof.c`

> Source: [bof.c:1](../../bof.c#L1) | language `c` | coverage 50.0% | [API index](../index.md)

bof.c

## Contents

- **Functions:** [`__attribute__`](#__attribute__)

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_bof_c____attribute__(["__attribute__"])
    n_beacon_h__BeaconPrintf["beacon.BeaconPrintf"]
    n_bof_c____attribute__ -.-> n_beacon_h__BeaconPrintf
```

## Functions

<a id="__attribute__"></a>

### `__attribute__`

`function` | [bof.c:4](../../bof.c#L4)

```c
__attribute__((used)) __attribute__((visibility("default"))) void go(char *args, int alen)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `used` |  |  |  |

*Calls:* [`BeaconPrintf`](beacon.h.md#beaconprintf)

*Called by:* [`BLOCKLEN`](include.aes.c.md#blocklen)

---
