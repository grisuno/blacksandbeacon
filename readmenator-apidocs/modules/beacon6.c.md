# `beacon6.c`

> Source: [beacon6.c:1](../../beacon6.c#L1) | language `c` | coverage 60.9% | [API index](../index.md)

## Contents

- **Structs:** [`MemoryStruct`](#memorystruct), [`Trampoline`](#trampoline), [`SymbolResolver`](#symbolresolver), [`TrampolineCache`](#trampolinecache)
- **Functions:** [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`https_request`](#https_request), [`base64_encode`](#base64_encode), [`base64_decode`](#base64_decode), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`exec_cmd`](#exec_cmd), [`RunELF`](#runelf), [`get_local_ips`](#get_local_ips), [`download_bof`](#download_bof), [`run_bof_and_capture`](#run_bof_and_capture), [`main`](#main)
- **Macros:** [`_GNU_SOURCE`](#_gnu_source), [`C2_URL`](#c2_url), [`CLIENT_ID`](#client_id), [`MALEABLE`](#maleable), [`USER_AGENTS_COUNT`](#user_agents_count)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class MemoryStruct
    <<struct>> MemoryStruct
    class Trampoline
    <<struct>> Trampoline
    class SymbolResolver
    <<struct>> SymbolResolver
    class TrampolineCache
    <<struct>> TrampolineCache
```

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_beacon6_c__download_bof(["download_bof"])
    n_beacon6_c__https_request(["https_request"])
    n_beacon6_c__run_bof_and_capture(["run_bof_and_capture"])
    n_beacon6_c__RunELF(["RunELF"])
    n_beacon6_c__main(["main"])
    n_beacon6_c__aes256_cfb_decrypt(["aes256_cfb_decrypt"])
    n_beacon6_c__aes256_cfb_encrypt(["aes256_cfb_encrypt"])
    n_beacon6_c__base64_decode(["base64_decode"])
    n_beacon6_c__base64_encode(["base64_encode"])
    n_beacon6_c__exec_cmd(["exec_cmd"])
    n_beacon6_c__get_local_ips(["get_local_ips"])
    n_aes_h__AES_ECB_encrypt["aes.AES_ECB_encrypt"]
    n_aes_h__AES_init_ctx["aes.AES_init_ctx"]
    n_beacon6_c__download_bof --> n_beacon6_c__https_request
    n_beacon6_c__run_bof_and_capture --> n_beacon6_c__RunELF
    n_beacon6_c__main --> n_beacon6_c__aes256_cfb_decrypt
    n_beacon6_c__main --> n_beacon6_c__aes256_cfb_encrypt
    n_beacon6_c__main --> n_beacon6_c__base64_decode
    n_beacon6_c__main --> n_beacon6_c__base64_encode
    n_beacon6_c__main --> n_beacon6_c__download_bof
    n_beacon6_c__main --> n_beacon6_c__exec_cmd
    n_beacon6_c__main --> n_beacon6_c__get_local_ips
    n_beacon6_c__main --> n_beacon6_c__https_request
    n_beacon6_c__main --> n_beacon6_c__run_bof_and_capture
    n_beacon6_c__aes256_cfb_encrypt -.-> n_aes_h__AES_ECB_encrypt
    n_beacon6_c__aes256_cfb_encrypt -.-> n_aes_h__AES_init_ctx
    n_beacon6_c__aes256_cfb_decrypt -.-> n_aes_h__AES_ECB_encrypt
    n_beacon6_c__aes256_cfb_decrypt -.-> n_aes_h__AES_init_ctx
```

## Structs

<a id="memorystruct"></a>

### `MemoryStruct`

`struct` | [beacon6.c:52](../../beacon6.c#L52)

```c
struct MemoryStruct
```

=== ESTRUCTURAS ===

---

<a id="trampoline"></a>

### `Trampoline`

`struct` | [beacon6.c:59](../../beacon6.c#L59)

```c
typedef struct
```

=== TRAMPOLINES ===

---

<a id="symbolresolver"></a>

### `SymbolResolver`

`struct` | [beacon6.c:67](../../beacon6.c#L67)

```c
typedef struct
```

---

<a id="trampolinecache"></a>

### `TrampolineCache`

`struct` | [beacon6.c:73](../../beacon6.c#L73)

```c
typedef struct
```

=== CACHE DE TRAMPOLINES ===

---

## Functions

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [beacon6.c:255](../../beacon6.c#L255)

```c
void BeaconPrintf(int type, const char *fmt, ...)
```

=== BEACON API ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `fmt` | `char *` |  |  |
| `...` |  |  |  |

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` | [beacon6.c:268](../../beacon6.c#L268)

```c
void BeaconOutput(int type, const char *data, int len)
```

Beacon API: raw output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `data` | `char *` |  |  |
| `len` | `int` |  |  |

> **Inherited:** Documentation from [`BeaconOutput`](#beaconoutput) (include/beacon_common.h:105).

---

<a id="https_request"></a>

### `https_request`

`function` | [beacon6.c:379](../../beacon6.c#L379)

```c
char* https_request(const char* url, const char* method, const char* post_data)
```

=== HTTPS REQUEST ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char*` |  |  |
| `method` | `char*` |  |  |
| `post_data` | `char*` |  |  |

**Returns:** `char*`

*Called by:* [`download_bof`](#download_bof), [`main`](#main)

---

<a id="base64_encode"></a>

### `base64_encode`

`function` | [beacon6.c:468](../../beacon6.c#L468)

```c
char* base64_encode(const unsigned char* input, int len)
```

=== BASE64 ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `unsigned char*` |  |  |
| `len` | `int` |  |  |

**Returns:** `char*`

*Called by:* [`main`](#main)

---

<a id="base64_decode"></a>

### `base64_decode`

`function` | [beacon6.c:485](../../beacon6.c#L485)

```c
unsigned char* base64_decode(const char* input, int* len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `char*` |  |  |
| `len` | `int*` |  |  |

**Returns:** `unsigned char*`

*Called by:* [`main`](#main)

---

<a id="aes256_cfb_encrypt"></a>

### `aes256_cfb_encrypt`

`function` | [beacon6.c:508](../../beacon6.c#L508)

```c
unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t len, int* out_len)
```

=== AES CFB ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char*` |  |  |
| `iv` | `unsigned char*` |  |  |
| `plaintext` | `unsigned char*` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int*` |  |  |

**Returns:** `unsigned char*`

*Calls:* [`AES_ECB_encrypt`](aes.h.md#aes_ecb_encrypt), [`AES_init_ctx`](aes.h.md#aes_init_ctx)

*Called by:* [`main`](#main)

---

<a id="aes256_cfb_decrypt"></a>

### `aes256_cfb_decrypt`

`function` | [beacon6.c:536](../../beacon6.c#L536)

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

*Calls:* [`AES_ECB_encrypt`](aes.h.md#aes_ecb_encrypt), [`AES_init_ctx`](aes.h.md#aes_init_ctx)

*Called by:* [`main`](#main)

---

<a id="exec_cmd"></a>

### `exec_cmd`

`function` | [beacon6.c:566](../../beacon6.c#L566)

```c
char* exec_cmd(const char* cmd, int* out_len)
```

=== EXEC CMD ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cmd` | `char*` |  |  |
| `out_len` | `int*` |  |  |

**Returns:** `char*`

*Called by:* [`main`](#main)

---

<a id="runelf"></a>

### `RunELF`

`function` | [beacon6.c:593](../../beacon6.c#L593)

```c
int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize)
```

ELF BOF loader.

Loads a position-independent ELF object into memory, resolves symbols, applies relocations, and calls the entry function in a forked child process for crash isolation. Returns 0 on success, -1 on error. BOF output is captured into g_beacon_output.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `functionname` | `char*` |  |  |
| `elf_data` | `unsigned char*` |  |  |
| `filesize` | `uint32_t` |  |  |
| `argumentdata` | `unsigned char*` |  |  |
| `argumentSize` | `int` |  |  |

**Returns:** `int`

> **Inherited:** Documentation from [`RunELF`](#runelf) (include/beacon_common.h:147).

*Called by:* [`run_bof_and_capture`](#run_bof_and_capture)

---

<a id="get_local_ips"></a>

### `get_local_ips`

`function` | [beacon6.c:974](../../beacon6.c#L974)

```c
char* get_local_ips()
```

=== GET LOCAL IPs ===

**Returns:** `char*`

*Called by:* [`main`](#main)

---

<a id="download_bof"></a>

### `download_bof`

`function` | [beacon6.c:1003](../../beacon6.c#L1003)

```c
unsigned char* download_bof(const char* url, size_t* out_size)
```

=== DOWNLOAD BOF ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char*` |  |  |
| `out_size` | `size_t*` |  |  |

**Returns:** `unsigned char*`

*Calls:* [`https_request`](#https_request)

*Called by:* [`main`](#main)

---

<a id="run_bof_and_capture"></a>

### `run_bof_and_capture`

`function` | [beacon6.c:1025](../../beacon6.c#L1025)

```c
char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize, char* args, int arglen, int* out_len)
```

=== RUN BOF AND CAPTURE ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `elf_data` | `unsigned char*` |  |  |
| `filesize` | `uint32_t` |  |  |
| `args` | `char*` |  |  |
| `arglen` | `int` |  |  |
| `out_len` | `int*` |  |  |

**Returns:** `char*`

*Calls:* [`RunELF`](#runelf)

*Called by:* [`main`](#main)

---

<a id="main"></a>

### `main`

`function` | [beacon6.c:1069](../../beacon6.c#L1069)

```c
int main()
```

=== MAIN ===

**Returns:** `int`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`base64_decode`](#base64_decode), [`base64_encode`](#base64_encode), [`download_bof`](#download_bof), [`exec_cmd`](#exec_cmd), [`get_local_ips`](#get_local_ips), [`https_request`](#https_request), [`run_bof_and_capture`](#run_bof_and_capture)

---

## Macros

<a id="_gnu_source"></a>

### `_GNU_SOURCE`

`macro` | [beacon6.c:1](../../beacon6.c#L1)

```c
#define _GNU_SOURCE
```

---

<a id="c2_url"></a>

### `C2_URL`

`macro` | [beacon6.c:35](../../beacon6.c#L35)

```c
#define C2_URL
```

---

<a id="client_id"></a>

### `CLIENT_ID`

`macro` | [beacon6.c:36](../../beacon6.c#L36)

```c
#define CLIENT_ID
```

---

<a id="maleable"></a>

### `MALEABLE`

`macro` | [beacon6.c:37](../../beacon6.c#L37)

```c
#define MALEABLE
```

---

<a id="user_agents_count"></a>

### `USER_AGENTS_COUNT`

`macro` | [beacon6.c:38](../../beacon6.c#L38)

```c
#define USER_AGENTS_COUNT
```

---
