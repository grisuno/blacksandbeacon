# `include/config_autogen.c`

> Source: [include/config_autogen.c:1](../../include/config_autogen.c#L1) | language `c` | coverage 66.7% | [API index](../index.md)

## Contents

- **Functions:** [`bsb_config_load`](#bsb_config_load)
- **Macros:** [`_POSIX_C_SOURCE`](#_posix_c_source)

## Functions

<a id="bsb_config_load"></a>

### `bsb_config_load`

`function` | [include/config_autogen.c:375](../../include/config_autogen.c#L375)

```c
int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)
```

Load config from path.

Returns 0 on success, -1 on error. On error, leaves a human-readable message in `err` (if non-NULL).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `path` | `char *` |  |  |
| `cfg` | `bsb_config_t *` |  |  |
| `err` | `char *` |  |  |
| `errlen` | `size_t` |  |  |

**Returns:** `int`

> **Inherited:** Documentation from [`bsb_config_load`](#bsb_config_load) (include/config.h:89).

---

## Macros

<a id="_posix_c_source"></a>

### `_POSIX_C_SOURCE`

`macro` | [include/config_autogen.c:5](../../include/config_autogen.c#L5)

```c
#define _POSIX_C_SOURCE
```

Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate

---
