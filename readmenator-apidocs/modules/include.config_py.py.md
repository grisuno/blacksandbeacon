# `include.config_py`

> Source: [include/config_py.py:1](../../include/config_py.py#L1) | language `py` | coverage 100.0% | [API index](../index.md)

config_py.py - Python loader for BSB JSON config files.

Mirrors the C side in include/config.c so the C2 server and the
beacon agree on the same schema. Generated/checked-in here so
the C2 has no Python-side runtime dependency on a separate
generator. Keep this in sync with include/config.c.

## Contents

- **Functions:** [`load_config`](#load_config)
- **Constants:** [`DEFAULTS`](#defaults), [`HKDF_SALT`](#hkdf_salt), [`HKDF_INFO_ENC`](#hkdf_info_enc), [`HKDF_INFO_HMAC`](#hkdf_info_hmac)

## Functions

<a id="load_config"></a>

### `load_config`

`function` | [include/config_py.py:94](../../include/config_py.py#L94)

```python
def load_config(path)
```

Load and validate a BSB config file.

Raises ValueError on any schema violation. Returns a dict
matching DEFAULTS' structure plus derived keys.

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

`constant` | [include/config_py.py:16](../../include/config_py.py#L16)

```python
DEFAULTS
```

---

<a id="hkdf_salt"></a>

### `HKDF_SALT`

`constant` | [include/config_py.py:60](../../include/config_py.py#L60)

```python
HKDF_SALT = b'blacksandbeacon-v2'
```

---

<a id="hkdf_info_enc"></a>

### `HKDF_INFO_ENC`

`constant` | [include/config_py.py:61](../../include/config_py.py#L61)

```python
HKDF_INFO_ENC = b'enc'
```

---

<a id="hkdf_info_hmac"></a>

### `HKDF_INFO_HMAC`

`constant` | [include/config_py.py:62](../../include/config_py.py#L62)

```python
HKDF_INFO_HMAC = b'hmac'
```

---
