# `aes.h`

> Source: [aes.h:1](../../aes.h#L1) | language `h` | coverage 23.8% | [API index](../index.md)

#define the macros below to 1/0 to enable/disable the mode of operation.

## Contents

- **Structs:** [`AES_ctx`](#aes_ctx)
- **Functions:** [`AES_init_ctx`](#aes_init_ctx), [`AES_init_ctx_iv`](#aes_init_ctx_iv), [`AES_ctx_set_iv`](#aes_ctx_set_iv), [`AES_ECB_encrypt`](#aes_ecb_encrypt), [`AES_ECB_decrypt`](#aes_ecb_decrypt), [`AES_CBC_encrypt_buffer`](#aes_cbc_encrypt_buffer), [`AES_CBC_decrypt_buffer`](#aes_cbc_decrypt_buffer), [`AES_CTR_xcrypt_buffer`](#aes_ctr_xcrypt_buffer)
- **Macros:** [`CBC`](#cbc), [`ECB`](#ecb), [`CTR`](#ctr), [`AES256`](#aes256), [`AES_BLOCKLEN`](#aes_blocklen), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize), [`AES_KEYLEN`](#aes_keylen), [`AES_keyExpSize`](#aes_keyexpsize)

## Structs

<a id="aes_ctx"></a>

### `AES_ctx`

`struct` | [aes.h:33](../../aes.h#L33)

```c
struct AES_ctx
```

---

## Functions

<a id="aes_init_ctx"></a>

### `AES_init_ctx`

`function` | [aes.h:41](../../aes.h#L41)

```c
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `key` | `uint8_t*` |  |  |

*Called by:* [`aes256_cfb_decrypt`](beacon3.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon3.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon5.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon5.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon6.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon6.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon_p2p.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon_p2p.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](gopher_beacon.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](gopher_beacon.c.md#aes256_cfb_encrypt)

---

<a id="aes_init_ctx_iv"></a>

### `AES_init_ctx_iv`

`function` | [aes.h:43](../../aes.h#L43)

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

`function` | [aes.h:44](../../aes.h#L44)

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

`function` | [aes.h:48](../../aes.h#L48)

```c
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
```

if defined(ECB) && (ECB == 1)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ctx` | `struct AES_ctx*` |  |  |
| `buf` | `uint8_t*` |  |  |

*Called by:* [`aes256_cfb_decrypt`](beacon3.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon3.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon5.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon5.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon6.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon6.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](beacon_p2p.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](beacon_p2p.c.md#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](gopher_beacon.c.md#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](gopher_beacon.c.md#aes256_cfb_encrypt)

---

<a id="aes_ecb_decrypt"></a>

### `AES_ECB_decrypt`

`function` | [aes.h:49](../../aes.h#L49)

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

`function` | [aes.h:53](../../aes.h#L53)

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

`function` | [aes.h:54](../../aes.h#L54)

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

`function` | [aes.h:58](../../aes.h#L58)

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

`macro` | [aes.h:9](../../aes.h#L9)

```c
#define CBC
```

---

<a id="ecb"></a>

### `ECB`

`macro` | [aes.h:12](../../aes.h#L12)

```c
#define ECB
```

---

<a id="ctr"></a>

### `CTR`

`macro` | [aes.h:15](../../aes.h#L15)

```c
#define CTR
```

---

<a id="aes256"></a>

### `AES256`

`macro` | [aes.h:18](../../aes.h#L18)

```c
#define AES256
```

---

<a id="aes_blocklen"></a>

### `AES_BLOCKLEN`

`macro` | [aes.h:20](../../aes.h#L20)

```c
#define AES_BLOCKLEN
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [aes.h:23](../../aes.h#L23)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [aes.h:24](../../aes.h#L24)

```c
#define AES_keyExpSize
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [aes.h:26](../../aes.h#L26)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [aes.h:27](../../aes.h#L27)

```c
#define AES_keyExpSize
```

---

<a id="aes_keylen"></a>

### `AES_KEYLEN`

`macro` | [aes.h:29](../../aes.h#L29)

```c
#define AES_KEYLEN
```

---

<a id="aes_keyexpsize"></a>

### `AES_keyExpSize`

`macro` | [aes.h:30](../../aes.h#L30)

```c
#define AES_keyExpSize
```

---
