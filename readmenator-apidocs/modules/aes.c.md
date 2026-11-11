# `aes.c`

> Source: [aes.c:1](../../aes.c#L1) | language `c` | coverage 33.3% | [API index](../index.md)

aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c)

## Contents

- **Functions:** [`AES_init_ctx`](#aes_init_ctx), [`AES_init_ctx_iv`](#aes_init_ctx_iv), [`AES_ctx_set_iv`](#aes_ctx_set_iv), [`AES_ECB_encrypt`](#aes_ecb_encrypt), [`AES_ECB_decrypt`](#aes_ecb_decrypt), [`AES_CBC_encrypt_buffer`](#aes_cbc_encrypt_buffer), [`AES_CBC_decrypt_buffer`](#aes_cbc_decrypt_buffer), [`AES_CTR_xcrypt_buffer`](#aes_ctr_xcrypt_buffer)
- **Macros:** [`Nb`](#nb), [`KEYLEN_256`](#keylen_256), [`RKLENGTH`](#rklength), [`BLOCKLEN`](#blocklen), [`Nb`](#nb), [`Nk`](#nk), [`Nr`](#nr), [`Nk`](#nk), [`Nr`](#nr), [`Nk`](#nk), [`Nr`](#nr), [`MULTIPLY_AS_A_FUNCTION`](#multiply_as_a_function), [`getSBoxValue`](#getsboxvalue), [`Multiply`](#multiply), [`getSBoxInvert`](#getsboxinvert)

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_aes_c__getSBoxInvert_384(["getSBoxInvert"])
    n_aes_c__Multiply_371(["Multiply"])
    n_aes_c__getSBoxInvert_384 --> n_aes_c__Multiply_371
```

## Functions

<a id="aes_init_ctx"></a>

### `AES_init_ctx`

`function` | [aes.c:254](../../aes.c#L254)

```c
void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `key` | `uint8_t *` |  |  |

---

<a id="aes_init_ctx_iv"></a>

### `AES_init_ctx_iv`

`function` | [aes.c:259](../../aes.c#L259)

```c
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)
```

if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `key` | `uint8_t *` |  |  |
| `iv` | `uint8_t *` |  |  |

---

<a id="aes_ctx_set_iv"></a>

### `AES_ctx_set_iv`

`function` | [aes.c:264](../../aes.c#L264)

```c
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `iv` | `uint8_t *` |  |  |

---

<a id="aes_ecb_encrypt"></a>

### `AES_ECB_encrypt`

`function` | [aes.c:512](../../aes.c#L512)

```c
void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)
```

if defined(ECB) && (ECB == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `buf` | `uint8_t *` |  |  |

> **Inherited:** Documentation from [`AES_ECB_encrypt`](#aes_ecb_encrypt) (aes.h:48).

---

<a id="aes_ecb_decrypt"></a>

### `AES_ECB_decrypt`

`function` | [aes.c:518](../../aes.c#L518)

```c
void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `buf` | `uint8_t *` |  |  |

---

<a id="aes_cbc_encrypt_buffer"></a>

### `AES_CBC_encrypt_buffer`

`function` | [aes.c:537](../../aes.c#L537)

```c
void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)
```

if defined(CBC) && (CBC == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `buf` | `uint8_t *` |  |  |
| `length` | `size_t` |  |  |

> **Inherited:** Documentation from [`AES_CBC_encrypt_buffer`](#aes_cbc_encrypt_buffer) (aes.h:53).

---

<a id="aes_cbc_decrypt_buffer"></a>

### `AES_CBC_decrypt_buffer`

`function` | [aes.c:552](../../aes.c#L552)

```c
void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `buf` | `uint8_t *` |  |  |
| `length` | `size_t` |  |  |

---

<a id="aes_ctr_xcrypt_buffer"></a>

### `AES_CTR_xcrypt_buffer`

`function` | [aes.c:572](../../aes.c#L572)

```c
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)
```

Symmetrical operation: same function for encrypting as for decrypting.

Note any IV/nonce should never be reused with the same key

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx *` |  |  |
| `buf` | `uint8_t *` |  |  |
| `length` | `size_t` |  |  |

---

## Macros

<a id="nb"></a>

### `Nb`

`macro` | [aes.c:5](../../aes.c#L5)

```c
#define Nb
```

---

<a id="keylen_256"></a>

### `KEYLEN_256`

`macro` | [aes.c:7](../../aes.c#L7)

```c
#define KEYLEN_256
```

---

<a id="rklength"></a>

### `RKLENGTH`

`macro` | [aes.c:8](../../aes.c#L8)

```c
#define RKLENGTH
```

---

<a id="blocklen"></a>

### `BLOCKLEN`

`macro` | [aes.c:9](../../aes.c#L9)

```c
#define BLOCKLEN
```

---

<a id="nb"></a>

### `Nb`

`macro` | [aes.c:84](../../aes.c#L84)

```c
#define Nb
```

The number of columns comprising a state in AES.

This is a constant in AES. Value=4

---

<a id="nk"></a>

### `Nk`

`macro` | [aes.c:87](../../aes.c#L87)

```c
#define Nk
```

---

<a id="nr"></a>

### `Nr`

`macro` | [aes.c:88](../../aes.c#L88)

```c
#define Nr
```

---

<a id="nk"></a>

### `Nk`

`macro` | [aes.c:90](../../aes.c#L90)

```c
#define Nk
```

---

<a id="nr"></a>

### `Nr`

`macro` | [aes.c:91](../../aes.c#L91)

```c
#define Nr
```

---

<a id="nk"></a>

### `Nk`

`macro` | [aes.c:93](../../aes.c#L93)

```c
#define Nk
```

---

<a id="nr"></a>

### `Nr`

`macro` | [aes.c:94](../../aes.c#L94)

```c
#define Nr
```

---

<a id="multiply_as_a_function"></a>

### `MULTIPLY_AS_A_FUNCTION`

`macro` | [aes.c:101](../../aes.c#L101)

```c
#define MULTIPLY_AS_A_FUNCTION
```

---

<a id="getsboxvalue"></a>

### `getSBoxValue`

`macro` | [aes.c:177](../../aes.c#L177)

```c
#define getSBoxValue(num)
```

static uint8_t getSBoxValue(uint8_t num) { return sbox[num]; }

---

<a id="multiply"></a>

### `Multiply`

`macro` | [aes.c:371](../../aes.c#L371)

```c
#define Multiply(x, y)
```

*Called by:* [`getSBoxInvert`](#getsboxinvert)

---

<a id="getsboxinvert"></a>

### `getSBoxInvert`

`macro` | [aes.c:384](../../aes.c#L384)

```c
#define getSBoxInvert(num)
```

static uint8_t getSBoxInvert(uint8_t num) { return rsbox[num]; }

*Calls:* [`Multiply`](#multiply)

---
