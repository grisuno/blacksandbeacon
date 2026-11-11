# `legacy/beacon6.c`

> Source: [legacy/beacon6.c:1](../../legacy/beacon6.c#L1) | language `c` | coverage 60.9% | [API index](../index.md)

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
    n_legacy_beacon6_c__download_bof(["download_bof"])
    n_legacy_beacon6_c__https_request(["https_request"])
    n_legacy_beacon6_c__run_bof_and_capture(["run_bof_and_capture"])
    n_legacy_beacon6_c__RunELF(["RunELF"])
    n_legacy_beacon6_c__main(["main"])
    n_legacy_beacon6_c__aes256_cfb_decrypt(["aes256_cfb_decrypt"])
    n_legacy_beacon6_c__aes256_cfb_encrypt(["aes256_cfb_encrypt"])
    n_legacy_beacon6_c__base64_decode(["base64_decode"])
    n_legacy_beacon6_c__base64_encode(["base64_encode"])
    n_legacy_beacon6_c__exec_cmd(["exec_cmd"])
    n_legacy_beacon6_c__get_local_ips(["get_local_ips"])
    n_legacy_beacon6_c__download_bof --> n_legacy_beacon6_c__https_request
    n_legacy_beacon6_c__run_bof_and_capture --> n_legacy_beacon6_c__RunELF
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__aes256_cfb_decrypt
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__aes256_cfb_encrypt
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__base64_decode
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__base64_encode
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__download_bof
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__exec_cmd
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__get_local_ips
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__https_request
    n_legacy_beacon6_c__main --> n_legacy_beacon6_c__run_bof_and_capture
```

## Structs

<a id="memorystruct"></a>

### `MemoryStruct`

`struct` | [legacy/beacon6.c:53](../../legacy/beacon6.c#L53)

```c
struct MemoryStruct
```

=== ESTRUCTURAS ===

---

<a id="trampoline"></a>

### `Trampoline`

`struct` | [legacy/beacon6.c:61](../../legacy/beacon6.c#L61)

```c
typedef struct
```

=== TRAMPOLINES ===

---

<a id="symbolresolver"></a>

### `SymbolResolver`

`struct` | [legacy/beacon6.c:70](../../legacy/beacon6.c#L70)

```c
typedef struct
```

---

<a id="trampolinecache"></a>

### `TrampolineCache`

`struct` | [legacy/beacon6.c:77](../../legacy/beacon6.c#L77)

```c
typedef struct
```

=== CACHE DE TRAMPOLINES ===

---

## Functions

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [legacy/beacon6.c:266](../../legacy/beacon6.c#L266)

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

`function` | [legacy/beacon6.c:283](../../legacy/beacon6.c#L283)

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

> **Inherited:** Documentation from [`BeaconOutput`](#beaconoutput) (include/beacon_common.h:108).

---

<a id="https_request"></a>

### `https_request`

`function` | [legacy/beacon6.c:412](../../legacy/beacon6.c#L412)

```c
char *https_request(const char *url, const char *method, const char *post_data)
```

=== HTTPS REQUEST ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char *` |  |  |
| `method` | `char *` |  |  |
| `post_data` | `char *` |  |  |

**Returns:** `char *`

*Called by:* [`download_bof`](#download_bof), [`main`](#main)

---

<a id="base64_encode"></a>

### `base64_encode`

`function` | [legacy/beacon6.c:506](../../legacy/beacon6.c#L506)

```c
char *base64_encode(const unsigned char *input, int len)
```

=== BASE64 ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `unsigned char *` |  |  |
| `len` | `int` |  |  |

**Returns:** `char *`

*Called by:* [`main`](#main)

---

<a id="base64_decode"></a>

### `base64_decode`

`function` | [legacy/beacon6.c:524](../../legacy/beacon6.c#L524)

```c
unsigned char *base64_decode(const char *input, int *len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `char *` |  |  |
| `len` | `int *` |  |  |

**Returns:** `unsigned char *`

*Called by:* [`main`](#main)

---

<a id="aes256_cfb_encrypt"></a>

### `aes256_cfb_encrypt`

`function` | [legacy/beacon6.c:550](../../legacy/beacon6.c#L550)

```c
unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t len, int *out_len)
```

=== AES CFB ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char *` |  |  |
| `iv` | `unsigned char *` |  |  |
| `plaintext` | `unsigned char *` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `unsigned char *`

*Called by:* [`main`](#main)

---

<a id="aes256_cfb_decrypt"></a>

### `aes256_cfb_decrypt`

`function` | [legacy/beacon6.c:584](../../legacy/beacon6.c#L584)

```c
unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, size_t len, int *out_len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char *` |  |  |
| `iv` | `unsigned char *` |  |  |
| `ciphertext` | `unsigned char *` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `unsigned char *`

*Called by:* [`main`](#main)

---

<a id="exec_cmd"></a>

### `exec_cmd`

`function` | [legacy/beacon6.c:620](../../legacy/beacon6.c#L620)

```c
char *exec_cmd(const char *cmd, int *out_len)
```

=== EXEC CMD ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cmd` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Called by:* [`main`](#main)

---

<a id="runelf"></a>

### `RunELF`

`function` | [legacy/beacon6.c:654](../../legacy/beacon6.c#L654)

```c
int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int argumentSize)
```

ELF BOF loader.

Loads a position-independent ELF object into memory, resolves symbols, applies relocations, and calls the entry function in a forked child process for crash isolation. Returns 0 on success, -1 on error. BOF output is captured into g_beacon_output.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `functionname` | `char *` |  |  |
| `elf_data` | `unsigned char *` |  |  |
| `filesize` | `uint32_t` |  |  |
| `argumentdata` | `unsigned char *` |  |  |
| `argumentSize` | `int` |  |  |

**Returns:** `int`

> **Inherited:** Documentation from [`RunELF`](#runelf) (include/beacon_common.h:164).

*Called by:* [`run_bof_and_capture`](#run_bof_and_capture)

---

<a id="get_local_ips"></a>

### `get_local_ips`

`function` | [legacy/beacon6.c:1153](../../legacy/beacon6.c#L1153)

```c
char *get_local_ips()
```

=== GET LOCAL IPs ===

**Returns:** `char *`

*Called by:* [`main`](#main)

---

<a id="download_bof"></a>

### `download_bof`

`function` | [legacy/beacon6.c:1188](../../legacy/beacon6.c#L1188)

```c
unsigned char *download_bof(const char *url, size_t *out_size)
```

=== DOWNLOAD BOF ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char *` |  |  |
| `out_size` | `size_t *` |  |  |

**Returns:** `unsigned char *`

*Calls:* [`https_request`](#https_request)

*Called by:* [`main`](#main)

---

<a id="run_bof_and_capture"></a>

### `run_bof_and_capture`

`function` | [legacy/beacon6.c:1211](../../legacy/beacon6.c#L1211)

```c
char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len)
```

=== RUN BOF AND CAPTURE ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `elf_data` | `unsigned char *` |  |  |
| `filesize` | `uint32_t` |  |  |
| `args` | `char *` |  |  |
| `arglen` | `int` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Calls:* [`RunELF`](#runelf)

*Called by:* [`main`](#main)

---

<a id="main"></a>

### `main`

`function` | [legacy/beacon6.c:1257](../../legacy/beacon6.c#L1257)

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

`macro` | [legacy/beacon6.c:1](../../legacy/beacon6.c#L1)

```c
#define _GNU_SOURCE
```

---

<a id="c2_url"></a>

### `C2_URL`

`macro` | [legacy/beacon6.c:34](../../legacy/beacon6.c#L34)

```c
#define C2_URL
```

---

<a id="client_id"></a>

### `CLIENT_ID`

`macro` | [legacy/beacon6.c:35](../../legacy/beacon6.c#L35)

```c
#define CLIENT_ID
```

---

<a id="maleable"></a>

### `MALEABLE`

`macro` | [legacy/beacon6.c:36](../../legacy/beacon6.c#L36)

```c
#define MALEABLE
```

---

<a id="user_agents_count"></a>

### `USER_AGENTS_COUNT`

`macro` | [legacy/beacon6.c:37](../../legacy/beacon6.c#L37)

```c
#define USER_AGENTS_COUNT
```

---
