# `include/beacon_common.c`

> Source: [include/beacon_common.c:1](../../include/beacon_common.c#L1) | language `c` | coverage 73.1% | [API index](../index.md)

## Contents

- **Structs:** [`bsb_output_meta_t`](#bsb_output_meta_t), [`MemoryStruct`](#memorystruct)
- **Functions:** [`bsb_output_init`](#bsb_output_init), [`bsb_output_cleanup`](#bsb_output_cleanup), [`bsb_output_reset`](#bsb_output_reset), [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`create_trampoline`](#create_trampoline), [`cleanup_trampolines`](#cleanup_trampolines), [`get_or_create_trampoline`](#get_or_create_trampoline), [`https_request`](#https_request), [`base64_encode`](#base64_encode), [`base64_decode`](#base64_decode), [`bsb_generate_secure_iv`](#bsb_generate_secure_iv), [`url_encode`](#url_encode), [`exec_cmd`](#exec_cmd), [`bsb_backoff_init`](#bsb_backoff_init), [`bsb_backoff_next`](#bsb_backoff_next), [`bsb_backoff_reset`](#bsb_backoff_reset), [`get_local_ips`](#get_local_ips), [`download_bof`](#download_bof), [`fault`](#fault), [`RunELF`](#runelf), [`run_bof_and_capture`](#run_bof_and_capture)
- **Macros:** [`_GNU_SOURCE`](#_gnu_source)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class bsb_output_meta_t
    <<struct>> bsb_output_meta_t
    class MemoryStruct
    <<struct>> MemoryStruct
```

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_include_beacon_common_c__get_or_create_trampoline(["get_or_create_trampoline"])
    n_include_beacon_common_c__create_trampoline(["create_trampoline"])
    n_include_beacon_common_c__download_bof(["download_bof"])
    n_include_beacon_common_c__base64_decode(["base64_decode"])
    n_include_beacon_common_c__https_request(["https_request"])
    n_include_beacon_common_c__RunELF(["RunELF"])
    n_include_beacon_common_c__BeaconOutput(["BeaconOutput"])
    n_include_beacon_common_c__bsb_output_reset(["bsb_output_reset"])
    n_include_beacon_common_c__cleanup_trampolines(["cleanup_trampolines"])
    n_include_beacon_common_c__run_bof_and_capture(["run_bof_and_capture"])
    n_include_beacon_common_c__get_or_create_trampoline --> n_include_beacon_common_c__create_trampoline
    n_include_beacon_common_c__download_bof --> n_include_beacon_common_c__base64_decode
    n_include_beacon_common_c__download_bof --> n_include_beacon_common_c__https_request
    n_include_beacon_common_c__RunELF --> n_include_beacon_common_c__BeaconOutput
    n_include_beacon_common_c__RunELF --> n_include_beacon_common_c__bsb_output_reset
    n_include_beacon_common_c__RunELF --> n_include_beacon_common_c__cleanup_trampolines
    n_include_beacon_common_c__RunELF --> n_include_beacon_common_c__get_or_create_trampoline
    n_include_beacon_common_c__run_bof_and_capture --> n_include_beacon_common_c__RunELF
    n_include_beacon_common_c__run_bof_and_capture --> n_include_beacon_common_c__bsb_output_reset
```

## Structs

<a id="bsb_output_meta_t"></a>

### `bsb_output_meta_t`

`struct` | [include/beacon_common.c:43](../../include/beacon_common.c#L43)

```c
typedef struct
```

BOFs run forked: buffer and length live in MAP_SHARED memory so the parent can read whatever the child's BeaconOutput calls produced.

---

<a id="memorystruct"></a>

### `MemoryStruct`

`struct` | [include/beacon_common.c:297](../../include/beacon_common.c#L297)

```c
struct MemoryStruct
```

--- HTTP client ---

---

## Functions

<a id="bsb_output_init"></a>

### `bsb_output_init`

`function` | [include/beacon_common.c:109](../../include/beacon_common.c#L109)

```c
int bsb_output_init(size_t capacity)
```

--- Output buffer management ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `capacity` | `size_t` |  |  |

**Returns:** `int`

---

<a id="bsb_output_cleanup"></a>

### `bsb_output_cleanup`

`function` | [include/beacon_common.c:135](../../include/beacon_common.c#L135)

```c
void bsb_output_cleanup(void)
```

Free the output buffer.

Call at beacon shutdown.

> **Inherited:** Documentation from [`bsb_output_cleanup`](#bsb_output_cleanup) (include/beacon_common.h:99).

---

<a id="bsb_output_reset"></a>

### `bsb_output_reset`

`function` | [include/beacon_common.c:149](../../include/beacon_common.c#L149)

```c
void bsb_output_reset(void)
```

Reset the output buffer for a new BOF execution.

> **Inherited:** Documentation from [`bsb_output_reset`](#bsb_output_reset) (include/beacon_common.h:102).

*Called by:* [`RunELF`](#runelf), [`run_bof_and_capture`](#run_bof_and_capture)

---

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [include/beacon_common.c:159](../../include/beacon_common.c#L159)

```c
void BeaconPrintf(int type, const char *fmt, ...)
```

--- Beacon API (called by BOFs) ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `fmt` | `char *` |  |  |
| `...` |  |  |  |

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` | [include/beacon_common.c:175](../../include/beacon_common.c#L175)

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

*Called by:* [`RunELF`](#runelf)

---

<a id="create_trampoline"></a>

### `create_trampoline`

`function` | [include/beacon_common.c:211](../../include/beacon_common.c#L211)

```c
void *create_trampoline(void *target, void *near_hint)
```

Trampoline management

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `target` | `void *` |  |  |
| `near_hint` | `void *` |  |  |

**Returns:** `void *`

> **Inherited:** Documentation from [`create_trampoline`](#create_trampoline) (include/beacon_common.h:111).

*Called by:* [`get_or_create_trampoline`](#get_or_create_trampoline)

---

<a id="cleanup_trampolines"></a>

### `cleanup_trampolines`

`function` | [include/beacon_common.c:249](../../include/beacon_common.c#L249)

```c
void cleanup_trampolines(void)
```

*Called by:* [`RunELF`](#runelf)

---

<a id="get_or_create_trampoline"></a>

### `get_or_create_trampoline`

`function` | [include/beacon_common.c:266](../../include/beacon_common.c#L266)

```c
void *get_or_create_trampoline(void *target, void *near_hint)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `target` | `void *` |  |  |
| `near_hint` | `void *` |  |  |

**Returns:** `void *`

*Calls:* [`create_trampoline`](#create_trampoline)

*Called by:* [`RunELF`](#runelf)

---

<a id="https_request"></a>

### `https_request`

`function` | [include/beacon_common.c:367](../../include/beacon_common.c#L367)

```c
http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data)
```

HTTP client: performs GET or POST request.

Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). Uses config for timeouts, TLS verification, and user-agent.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cfg` | `bsb_config_t *` |  |  |
| `url` | `char *` |  |  |
| `method` | `char *` |  |  |
| `post_data` | `char *` |  |  |

**Returns:** `http_response_t`

> **Inherited:** Documentation from [`https_request`](#https_request) (include/beacon_common.h:119).

*Called by:* [`download_bof`](#download_bof)

---

<a id="base64_encode"></a>

### `base64_encode`

`function` | [include/beacon_common.c:443](../../include/beacon_common.c#L443)

```c
char *base64_encode(const unsigned char *input, int len)
```

--- Base64 ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `unsigned char *` |  |  |
| `len` | `int` |  |  |

**Returns:** `char *`

---

<a id="base64_decode"></a>

### `base64_decode`

`function` | [include/beacon_common.c:460](../../include/beacon_common.c#L460)

```c
unsigned char *base64_decode(const char *input, int *len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `char *` |  |  |
| `len` | `int *` |  |  |

**Returns:** `unsigned char *`

*Called by:* [`download_bof`](#download_bof)

---

<a id="bsb_generate_secure_iv"></a>

### `bsb_generate_secure_iv`

`function` | [include/beacon_common.c:490](../../include/beacon_common.c#L490)

```c
int bsb_generate_secure_iv(unsigned char *iv_out)
```

Generates a cryptographically secure 16-byte IV.

Tries OpenSSL RAND_bytes first, falls back to getrandom(2). Returns 1 on success, 0 on failure (fail-closed).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `iv_out` | `unsigned char *` |  |  |

**Returns:** `int`

---

<a id="url_encode"></a>

### `url_encode`

`function` | [include/beacon_common.c:521](../../include/beacon_common.c#L521)

```c
char *url_encode(const char *in, size_t in_len, size_t *out_len)
```

URL percent-encoding (RFC 3986 unreserved set)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `in` | `char *` |  |  |
| `in_len` | `size_t` |  |  |
| `out_len` | `size_t *` |  |  |

**Returns:** `char *`

> **Inherited:** Documentation from [`url_encode`](#url_encode) (include/beacon_common.h:127).

---

<a id="exec_cmd"></a>

### `exec_cmd`

`function` | [include/beacon_common.c:640](../../include/beacon_common.c#L640)

```c
char *exec_cmd(const char *cmd, int *out_len)
```

Execute command via execve (no shell) and capture stdout+stderr.

Returns malloc'd buffer with combined output (caller frees). On error, returns NULL.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cmd` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

---

<a id="bsb_backoff_init"></a>

### `bsb_backoff_init`

`function` | [include/beacon_common.c:781](../../include/beacon_common.c#L781)

```c
void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)
```

--- Backoff state ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `bo` | `bsb_backoff_t *` |  |  |
| `base` | `int` |  |  |
| `max` | `int` |  |  |

---

<a id="bsb_backoff_next"></a>

### `bsb_backoff_next`

`function` | [include/beacon_common.c:788](../../include/beacon_common.c#L788)

```c
int bsb_backoff_next(bsb_backoff_t *bo)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `bo` | `bsb_backoff_t *` |  |  |

**Returns:** `int`

---

<a id="bsb_backoff_reset"></a>

### `bsb_backoff_reset`

`function` | [include/beacon_common.c:799](../../include/beacon_common.c#L799)

```c
void bsb_backoff_reset(bsb_backoff_t *bo)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `bo` | `bsb_backoff_t *` |  |  |

---

<a id="get_local_ips"></a>

### `get_local_ips`

`function` | [include/beacon_common.c:805](../../include/beacon_common.c#L805)

```c
char *get_local_ips(void)
```

--- IP discovery ---

**Returns:** `char *`

---

<a id="download_bof"></a>

### `download_bof`

`function` | [include/beacon_common.c:840](../../include/beacon_common.c#L840)

```c
unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)
```

--- BOF download ---

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cfg` | `bsb_config_t *` |  |  |
| `url` | `char *` |  |  |
| `out_size` | `size_t *` |  |  |

**Returns:** `unsigned char *`

*Calls:* [`base64_decode`](#base64_decode), [`https_request`](#https_request)

---

<a id="fault"></a>

### `fault`

`function` | [include/beacon_common.c:941](../../include/beacon_common.c#L941)

```c
* fault (SIGSEGV inside BeaconPrintf). We save the original %rsp in * a scratch slot we own below the current stack pointer, align, call, * then restore. Callee-saved registers are restored by the BOF
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `BeaconPrintf` | `SIGSEGV inside` |  |  |

**Returns:** `*`

---

<a id="runelf"></a>

### `RunELF`

`function` | [include/beacon_common.c:961](../../include/beacon_common.c#L961)

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

*Calls:* [`BeaconOutput`](#beaconoutput), [`bsb_output_reset`](#bsb_output_reset), [`cleanup_trampolines`](#cleanup_trampolines), [`get_or_create_trampoline`](#get_or_create_trampoline)

*Called by:* [`run_bof_and_capture`](#run_bof_and_capture)

---

<a id="run_bof_and_capture"></a>

### `run_bof_and_capture`

`function` | [include/beacon_common.c:1263](../../include/beacon_common.c#L1263)

```c
char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len)
```

Execute a BOF and capture its output.

Returns malloc'd string (caller frees). On error or empty output, returns strdup("").

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `elf_data` | `unsigned char *` |  |  |
| `filesize` | `uint32_t` |  |  |
| `args` | `char *` |  |  |
| `arglen` | `int` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

> **Inherited:** Documentation from [`run_bof_and_capture`](#run_bof_and_capture) (include/beacon_common.h:173).

*Calls:* [`RunELF`](#runelf), [`bsb_output_reset`](#bsb_output_reset)

---

## Macros

<a id="_gnu_source"></a>

### `_GNU_SOURCE`

`macro` | [include/beacon_common.c:9](../../include/beacon_common.c#L9)

```c
#define _GNU_SOURCE
```

beacon_common.c - Shared beacon infrastructure implementation.

This file contains the BOF loader, HTTP client, crypto wrappers,
output capture, and utility functions used by all beacon variants.
Centralizing this code eliminates duplication and ensures consistent
behavior across v1, v2, and v3 beacons.

---
