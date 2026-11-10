# `include/aes_cfb.c`

> Source: [include/aes_cfb.c:1](../../include/aes_cfb.c#L1) | language `c` | coverage 25.0% | [API index](../index.md)

## Contents

- **Functions:** [`EVP_EncryptUpdate`](#evp_encryptupdate), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](#aes256_cfb_decrypt)

## Functions

<a id="evp_encryptupdate"></a>

### `EVP_EncryptUpdate`

`function` | [include/aes_cfb.c:27](../../include/aes_cfb.c#L27)

```c
&& EVP_EncryptUpdate(ctx, buffer, &outl, data, (int)len) == 1 && EVP_EncryptFinal_ex(ctx, buffer + outl, &outl2) == 1) : (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv) == 1 && EVP_DecryptU
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `outl` |  |  |  |
| `len` | `(int)` |  |  |

**Returns:** `&&`

---

<a id="aes256_cfb_encrypt"></a>

### `aes256_cfb_encrypt`

`function` | [include/aes_cfb.c:38](../../include/aes_cfb.c#L38)

```c
unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t len, int* out_len)
```

AES-256-CFB encrypt/decrypt (standalone, no OpenSSL dependency)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char*` |  |  |
| `iv` | `unsigned char*` |  |  |
| `plaintext` | `unsigned char*` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int*` |  |  |

**Returns:** `unsigned char*`

> **Inherited:** Documentation from [`aes256_cfb_encrypt`](#aes256_cfb_encrypt) (include/beacon_common.h:129).

---

<a id="aes256_cfb_decrypt"></a>

### `aes256_cfb_decrypt`

`function` | [include/aes_cfb.c:43](../../include/aes_cfb.c#L43)

```c
unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t len, int* out_len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char*` |  |  |
| `iv` | `unsigned char*` |  |  |
| `ciphertext` | `unsigned char*` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int*` |  |  |

**Returns:** `unsigned char*`

---
