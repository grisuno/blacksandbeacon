# `include.config_py_autogen`

> Source: [include/config_py_autogen.py:1](../../include/config_py_autogen.py#L1) | language `py` | coverage 100.0% | [API index](../index.md)

Auto-generated Python config loader from config/schema.json DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate

## Contents

- **Functions:** [`load_config`](#load_config)
- **Constants:** [`DEFAULTS`](#defaults), [`HKDF_SALT`](#hkdf_salt), [`HKDF_INFO_ENC`](#hkdf_info_enc), [`HKDF_INFO_HMAC`](#hkdf_info_hmac)

## Functions

<a id="load_config"></a>

### `load_config`

`function` | [include/config_py_autogen.py:89](../../include/config_py_autogen.py#L89)

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

---

## Constants

<a id="defaults"></a>

### `DEFAULTS`

`constant` | [include/config_py_autogen.py:10](../../include/config_py_autogen.py#L10)

```python
DEFAULTS
```

---

<a id="hkdf_salt"></a>

### `HKDF_SALT`

`constant` | [include/config_py_autogen.py:55](../../include/config_py_autogen.py#L55)

```python
HKDF_SALT = b'blacksandbeacon-v2'
```

---

<a id="hkdf_info_enc"></a>

### `HKDF_INFO_ENC`

`constant` | [include/config_py_autogen.py:56](../../include/config_py_autogen.py#L56)

```python
HKDF_INFO_ENC = b'enc'
```

---

<a id="hkdf_info_hmac"></a>

### `HKDF_INFO_HMAC`

`constant` | [include/config_py_autogen.py:57](../../include/config_py_autogen.py#L57)

```python
HKDF_INFO_HMAC = b'hmac'
```

---
