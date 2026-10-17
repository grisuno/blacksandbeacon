# `include/aes.h`

> Source: [include/aes.h:1](../../include/aes.h#L1) | language `h` | coverage 23.8% | [API index](../index.md)

#define the macros below to 1/0 to enable/disable the mode of operation.

## Contents

- **Structs:** [`AES_ctx`](#aes_ctx)
- **Functions:** [`AES_init_ctx`](#aes_init_ctx), [`AES_init_ctx_iv`](#aes_init_ctx_iv), [`AES_ctx_set_iv`](#aes_ctx_set_iv), [`AES_ECB_encrypt`](#aes_ecb_encrypt), [`AES_ECB_decrypt`](#aes_ecb_decrypt), [`AES_CBC_encrypt_buffer`](#aes_cbc_encrypt_buffer), [`AES_CBC_decrypt_buffer`](#aes_cbc_decrypt_buffer), [`AES_CTR_xcrypt_buffer`](#aes_ctr_xcrypt_buffer)
- **Macros:** [`CBC`](#cbc), [`ECB`](#ecb), [`CTR`](#ctr), [`AES256`](#aes256), [`AES_BLOCKLEN`](#aes_blocklen), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize)

## Structs

<a id="aes_ctx"></a>

### `AES_ctx`

`struct` | [include/aes.h:33](../../include/aes.h#L33)

```c
struct AES_ctx
```

---

## Functions

<a id="aes_init_ctx"></a>

### `AES_init_ctx`

`function` | [include/aes.h:41](../../include/aes.h#L41)

```c
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `key` | `uint8_t*` |  |  |

*Called by:* [`aes256_cfb_decrypt`](include.aes_cfb.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](include.aes_cfb.c.md#aes256_cfb_encrypt)

---

<a id="aes_init_ctx_iv"></a>

### `AES_init_ctx_iv`

`function` | [include/aes.h:43](../../include/aes.h#L43)

```c
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
```

if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `key` | `uint8_t*` |  |  |
| `iv` | `uint8_t*` |  |  |

---

<a id="aes_ctx_set_iv"></a>

### `AES_ctx_set_iv`

`function` | [include/aes.h:44](../../include/aes.h#L44)

```c
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `iv` | `uint8_t*` |  |  |

---

<a id="aes_ecb_encrypt"></a>

### `AES_ECB_encrypt`

`function` | [include/aes.h:48](../../include/aes.h#L48)

```c
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
```

if defined(ECB) && (ECB == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |

*Called by:* [`aes256_cfb_decrypt`](include.aes_cfb.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](include.aes_cfb.c.md#aes256_cfb_encrypt)

---

<a id="aes_ecb_decrypt"></a>

### `AES_ECB_decrypt`

`function` | [include/aes.h:49](../../include/aes.h#L49)

```c
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |

---

<a id="aes_cbc_encrypt_buffer"></a>

### `AES_CBC_encrypt_buffer`

`function` | [include/aes.h:53](../../include/aes.h#L53)

```c
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
```

if defined(CBC) && (CBC == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |
| `length` | `size_t` |  |  |

---

<a id="aes_cbc_decrypt_buffer"></a>

### `AES_CBC_decrypt_buffer`

`function` | [include/aes.h:54](../../include/aes.h#L54)

```c
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |
| `length` | `size_t` |  |  |

---

<a id="aes_ctr_xcrypt_buffer"></a>

### `AES_CTR_xcrypt_buffer`

`function` | [include/aes.h:58](../../include/aes.h#L58)

```c
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
```

if defined(CTR) && (CTR == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |
| `length` | `size_t` |  |  |

---

## Macros

<a id="cbc"></a>

### `CBC`

`macro` | [include/aes.h:9](../../include/aes.h#L9)

```c
#define CBC
```

---

<a id="ecb"></a>

### `ECB`

`macro` | [include/aes.h:12](../../include/aes.h#L12)

```c
#define ECB
```

---

<a id="ctr"></a>

### `CTR`

`macro` | [include/aes.h:15](../../include/aes.h#L15)

```c
#define CTR
```

---

<a id="aes256"></a>

### `AES256`

`macro` | [include/aes.h:18](../../include/aes.h#L18)

```c
#define AES256
```

---

<a id="aes_blocklen"></a>

### `AES_BLOCKLEN`

`macro` | [include/aes.h:20](../../include/aes.h#L20)

```c
#define AES_BLOCKLEN
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [include/aes.h:23](../../include/aes.h#L23)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [include/aes.h:24](../../include/aes.h#L24)

```c
#define AES_keyExpSize
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [include/aes.h:26](../../include/aes.h#L26)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [include/aes.h:27](../../include/aes.h#L27)

```c
#define AES_keyExpSize
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [include/aes.h:29](../../include/aes.h#L29)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [include/aes.h:30](../../include/aes.h#L30)

```c
#define AES_keyExpSize
```

---
