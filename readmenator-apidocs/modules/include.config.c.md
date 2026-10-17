# `include/config.c`

> Source: [include/config.c:1](../../include/config.c#L1) | language `c` | coverage 80.0% | [API index](../index.md)

## Contents

- **Functions:** [`bsb_config_load`](#bsb_config_load), [`bsb_config_load_default`](#bsb_config_load_default), [`bsb_config_sleep_seconds`](#bsb_config_sleep_seconds)
- **Macros:** [`_POSIX_C_SOURCE`](#_posix_c_source)

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_include_config_c__bsb_config_load_default(["bsb_config_load_default"])
    n_include_config_c__bsb_config_load(["bsb_config_load"])
    n_include_config_c__bsb_config_load_default --> n_include_config_c__bsb_config_load
```

## Functions

<a id="bsb_config_load"></a>

### `bsb_config_load`

`function` | [include/config.c:328](../../include/config.c#L328)

```c
int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)
```

--- main load ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `path` | `char *` |  |  |
| `cfg` | `bsb_config_t *` |  |  |
| `err` | `char *` |  |  |
| `errlen` | `size_t` |  |  |

**Returns:** `int`

*Called by:* [`bsb_config_load_default`](#bsb_config_load_default)

---

<a id="bsb_config_load_default"></a>

### `bsb_config_load_default`

`function` | [include/config.c:438](../../include/config.c#L438)

```c
int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)
```

Load from BSB_CONFIG env or default path.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cfg` | `bsb_config_t *` |  |  |
| `err` | `char *` |  |  |
| `errlen` | `size_t` |  |  |

**Returns:** `int`

> **Inherited:** Documentation from [`bsb_config_load_default`](#bsb_config_load_default) (include/config.h:80).

*Calls:* [`bsb_config_load`](#bsb_config_load)

---

<a id="bsb_config_sleep_seconds"></a>

### `bsb_config_sleep_seconds`

`function` | [include/config.c:466](../../include/config.c#L466)

```c
int bsb_config_sleep_seconds(const bsb_config_t *cfg)
```

Compute a sleep duration with jitter applied.

Returns seconds.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cfg` | `bsb_config_t *` |  |  |

**Returns:** `int`

> **Inherited:** Documentation from [`bsb_config_sleep_seconds`](#bsb_config_sleep_seconds) (include/config.h:83).

---

## Macros

<a id="_posix_c_source"></a>

### `_POSIX_C_SOURCE`

`macro` | [include/config.c:13](../../include/config.c#L13)

```c
#define _POSIX_C_SOURCE
```

config.c - JSON config loader for Black Sand Beacon.

Self-contained: no libc JSON dependency, only stdio/stdlib/string.
Parses the schema documented in include/config.h.

The parser is intentionally simple: it walks the JSON looking
for top-level keys ("c2", "crypto", "timing", "network", "bof")
and reads the string / integer / boolean / array values
declared in the schema. Unknown keys are skipped. Missing
sections fall back to safe defaults.

---
