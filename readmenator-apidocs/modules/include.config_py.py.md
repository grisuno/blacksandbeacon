# `include.config_py`

> Source: [include/config_py.py:1](../../include/config_py.py#L1) | language `py` | coverage 100.0% | [API index](../index.md)

config_py.py - Python loader for BSB JSON config files.

Mirrors the C side in include/config.c so the C2 server and the
beacon agree on the same schema. Generated/checked-in here so
the C2 has no Python-side runtime dependency on a separate
generator. Keep this in sync with include/config.c.

## Contents

- **Functions:** [`load_config`](#load_config)
- **Constants:** [`DEFAULTS`](#defaults)

## Functions

<a id="load_config"></a>

### `load_config`

`function` | [include/config_py.py:65](../../include/config_py.py#L65)

```python
def load_config(path)
```

Load and validate a BSB config file.

Raises ValueError on any schema violation. Returns a dict
matching DEFAULTS' structure.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `path` |  |  |  |

**Raises**

- `ValueError`: (raised in the body, not documented)

*Called by:* [`load_runtime_config`](c2.server.py.md#load_runtime_config)

---

## Constants

<a id="defaults"></a>

### `DEFAULTS`

`constant` | [include/config_py.py:15](../../include/config_py.py#L15)

```python
DEFAULTS
```

---
