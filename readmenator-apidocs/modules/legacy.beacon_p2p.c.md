# `legacy/beacon_p2p.c`

> Source: [legacy/beacon_p2p.c:1](../../legacy/beacon_p2p.c#L1) | language `c` | coverage 40.9% | [API index](../index.md)

## Contents

- **Structs:** [`peer_t`](#peer_t), [`p2p_header_t`](#p2p_header_t), [`Trampoline`](#trampoline), [`SymbolResolver`](#symbolresolver), [`TrampolineCache`](#trampolinecache), [`MemoryStruct`](#memorystruct)
- **Functions:** [`BeaconDataParse`](#beacondataparse), [`BeaconDataPtr`](#beacondataptr), [`BeaconDataInt`](#beacondataint), [`BeaconDataShort`](#beacondatashort), [`BeaconDataLength`](#beacondatalength), [`BeaconDataExtract`](#beacondataextract), [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`RunELF`](#runelf), [`https_request`](#https_request), [`base64_encode`](#base64_encode), [`base64_decode`](#base64_decode), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`exec_cmd`](#exec_cmd), [`get_local_ips`](#get_local_ips), [`download_bof`](#download_bof), [`run_bof_and_capture`](#run_bof_and_capture), [`add_peer`](#add_peer), [`peer_discovery_thread`](#peer_discovery_thread), [`handle_peer_connection`](#handle_peer_connection), [`peer_server_thread`](#peer_server_thread), [`send_to_peer`](#send_to_peer), [`send_to_c2_or_peer`](#send_to_c2_or_peer), [`execute_generic_command`](#execute_generic_command), [`main`](#main)
- **Macros:** [`_GNU_SOURCE`](#_gnu_source), [`C2_URL`](#c2_url), [`CLIENT_ID`](#client_id), [`MALEABLE`](#maleable), [`USER_AGENTS_COUNT`](#user_agents_count), [`PEER_DISCOVERY_PORT`](#peer_discovery_port), [`PEER_TCP_PORT`](#peer_tcp_port), [`PEER_MAGIC`](#peer_magic), [`PEER_VERSION`](#peer_version), [`BROADCAST_INTERVAL`](#broadcast_interval), [`MAX_PEERS`](#max_peers)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class peer_t
    <<struct>> peer_t
    class p2p_header_t
    <<struct>> p2p_header_t
    class Trampoline
    <<struct>> Trampoline
    class SymbolResolver
    <<struct>> SymbolResolver
    class TrampolineCache
    <<struct>> TrampolineCache
    class MemoryStruct
    <<struct>> MemoryStruct
```

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_legacy_beacon_p2p_c__BeaconDataInt(["BeaconDataInt"])
    n_legacy_beacon_p2p_c__BeaconDataPtr(["BeaconDataPtr"])
    n_legacy_beacon_p2p_c__BeaconDataShort(["BeaconDataShort"])
    n_legacy_beacon_p2p_c__BeaconDataExtract(["BeaconDataExtract"])
    n_legacy_beacon_p2p_c__download_bof(["download_bof"])
    n_legacy_beacon_p2p_c__https_request(["https_request"])
    n_legacy_beacon_p2p_c__run_bof_and_capture(["run_bof_and_capture"])
    n_legacy_beacon_p2p_c__RunELF(["RunELF"])
    n_legacy_beacon_p2p_c__peer_discovery_thread(["peer_discovery_thread"])
    n_legacy_beacon_p2p_c__add_peer(["add_peer"])
    n_legacy_beacon_p2p_c__handle_peer_connection(["handle_peer_connection"])
    n_legacy_beacon_p2p_c__aes256_cfb_decrypt(["aes256_cfb_decrypt"])
    n_legacy_beacon_p2p_c__aes256_cfb_encrypt(["aes256_cfb_encrypt"])
    n_legacy_beacon_p2p_c__execute_generic_command(["execute_generic_command"])
    n_legacy_beacon_p2p_c__send_to_peer(["send_to_peer"])
    n_legacy_beacon_p2p_c__send_to_c2_or_peer(["send_to_c2_or_peer"])
    n_legacy_beacon_p2p_c__exec_cmd(["exec_cmd"])
    n_legacy_beacon_p2p_c__main(["main"])
    n_legacy_beacon_p2p_c__base64_decode(["base64_decode"])
    n_legacy_beacon_p2p_c__base64_encode(["base64_encode"])
    n_legacy_beacon_p2p_c__get_local_ips(["get_local_ips"])
    n_legacy_beacon_p2p_c__BeaconDataInt --> n_legacy_beacon_p2p_c__BeaconDataPtr
    n_legacy_beacon_p2p_c__BeaconDataShort --> n_legacy_beacon_p2p_c__BeaconDataPtr
    n_legacy_beacon_p2p_c__BeaconDataExtract --> n_legacy_beacon_p2p_c__BeaconDataInt
    n_legacy_beacon_p2p_c__BeaconDataExtract --> n_legacy_beacon_p2p_c__BeaconDataPtr
    n_legacy_beacon_p2p_c__download_bof --> n_legacy_beacon_p2p_c__https_request
    n_legacy_beacon_p2p_c__run_bof_and_capture --> n_legacy_beacon_p2p_c__RunELF
    n_legacy_beacon_p2p_c__peer_discovery_thread --> n_legacy_beacon_p2p_c__add_peer
    n_legacy_beacon_p2p_c__handle_peer_connection --> n_legacy_beacon_p2p_c__aes256_cfb_decrypt
    n_legacy_beacon_p2p_c__handle_peer_connection --> n_legacy_beacon_p2p_c__aes256_cfb_encrypt
    n_legacy_beacon_p2p_c__handle_peer_connection --> n_legacy_beacon_p2p_c__execute_generic_command
    n_legacy_beacon_p2p_c__handle_peer_connection --> n_legacy_beacon_p2p_c__https_request
    n_legacy_beacon_p2p_c__send_to_peer --> n_legacy_beacon_p2p_c__aes256_cfb_decrypt
    n_legacy_beacon_p2p_c__send_to_peer --> n_legacy_beacon_p2p_c__aes256_cfb_encrypt
    n_legacy_beacon_p2p_c__send_to_c2_or_peer --> n_legacy_beacon_p2p_c__https_request
    n_legacy_beacon_p2p_c__send_to_c2_or_peer --> n_legacy_beacon_p2p_c__send_to_peer
    n_legacy_beacon_p2p_c__execute_generic_command --> n_legacy_beacon_p2p_c__download_bof
    n_legacy_beacon_p2p_c__execute_generic_command --> n_legacy_beacon_p2p_c__exec_cmd
    n_legacy_beacon_p2p_c__execute_generic_command --> n_legacy_beacon_p2p_c__run_bof_and_capture
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__aes256_cfb_decrypt
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__aes256_cfb_encrypt
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__base64_decode
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__base64_encode
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__execute_generic_command
    n_legacy_beacon_p2p_c__main --> n_legacy_beacon_p2p_c__get_local_ips
```

## Structs

<a id="peer_t"></a>

### `peer_t`

`struct` | [legacy/beacon_p2p.c:59](../../legacy/beacon_p2p.c#L59)

```c
typedef struct
```

ESTRUCTURAS P2P

---

<a id="p2p_header_t"></a>

### `p2p_header_t`

`struct` | [legacy/beacon_p2p.c:73](../../legacy/beacon_p2p.c#L73)

```c
typedef struct
```

---

<a id="trampoline"></a>

### `Trampoline`

`struct` | [legacy/beacon_p2p.c:175](../../legacy/beacon_p2p.c#L175)

```c
typedef struct
```

TRAMPOLINES Y RELOCACIÓN (RunELF) - SIN CAMBIOS

---

<a id="symbolresolver"></a>

### `SymbolResolver`

`struct` | [legacy/beacon_p2p.c:182](../../legacy/beacon_p2p.c#L182)

```c
typedef struct
```

---

<a id="trampolinecache"></a>

### `TrampolineCache`

`struct` | [legacy/beacon_p2p.c:192](../../legacy/beacon_p2p.c#L192)

```c
typedef struct
```

---

<a id="memorystruct"></a>

### `MemoryStruct`

`struct` | [legacy/beacon_p2p.c:676](../../legacy/beacon_p2p.c#L676)

```c
struct MemoryStruct
```

FUNCIONES DE COMUNICACIÓN (HTTPS + BASE64 + AES)

---

## Functions

<a id="beacondataparse"></a>

### `BeaconDataParse`

`function` | [legacy/beacon_p2p.c:93](../../legacy/beacon_p2p.c#L93)

```c
void BeaconDataParse(datap *parser, char *buffer, int size)
```

FUNCIONES DE LA API DE BEACON (para BOFs)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `buffer` | `char *` |  |  |
| `size` | `int` |  |  |

---

<a id="beacondataptr"></a>

### `BeaconDataPtr`

`function` | [legacy/beacon_p2p.c:100](../../legacy/beacon_p2p.c#L100)

```c
char *BeaconDataPtr(datap *parser, int size)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `size` | `int` |  |  |

**Returns:** `char *`

*Called by:* [`BeaconDataExtract`](#beacondataextract), [`BeaconDataInt`](#beacondataint), [`BeaconDataShort`](#beacondatashort)

---

<a id="beacondataint"></a>

### `BeaconDataInt`

`function` | [legacy/beacon_p2p.c:110](../../legacy/beacon_p2p.c#L110)

```c
int BeaconDataInt(datap *parser)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `int`

*Calls:* [`BeaconDataPtr`](#beacondataptr)

*Called by:* [`BeaconDataExtract`](#beacondataextract)

---

<a id="beacondatashort"></a>

### `BeaconDataShort`

`function` | [legacy/beacon_p2p.c:118](../../legacy/beacon_p2p.c#L118)

```c
short BeaconDataShort(datap *parser)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `short`

*Calls:* [`BeaconDataPtr`](#beacondataptr)

---

<a id="beacondatalength"></a>

### `BeaconDataLength`

`function` | [legacy/beacon_p2p.c:126](../../legacy/beacon_p2p.c#L126)

```c
int BeaconDataLength(datap *parser)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `int`

---

<a id="beacondataextract"></a>

### `BeaconDataExtract`

`function` | [legacy/beacon_p2p.c:131](../../legacy/beacon_p2p.c#L131)

```c
char *BeaconDataExtract(datap *parser, int *size)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `size` | `int *` |  |  |

**Returns:** `char *`

*Calls:* [`BeaconDataInt`](#beacondataint), [`BeaconDataPtr`](#beacondataptr)

---

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [legacy/beacon_p2p.c:142](../../legacy/beacon_p2p.c#L142)

```c
void BeaconPrintf(int type, const char *fmt, ...)
```

Beacon API: printf-style output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `fmt` | `char *` |  |  |
| `...` |  |  |  |

> **Inherited:** Documentation from [`BeaconPrintf`](#beaconprintf) (include/beacon_common.h:105).

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` | [legacy/beacon_p2p.c:159](../../legacy/beacon_p2p.c#L159)

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

<a id="runelf"></a>

### `RunELF`

`function` | [legacy/beacon_p2p.c:358](../../legacy/beacon_p2p.c#L358)

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

<a id="https_request"></a>

### `https_request`

`function` | [legacy/beacon_p2p.c:707](../../legacy/beacon_p2p.c#L707)

```c
char *https_request(const char *url, const char *method, const char *post_data)
```

HTTP client: performs GET or POST request.

Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). Uses config for timeouts, TLS verification, and user-agent.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char *` |  |  |
| `method` | `char *` |  |  |
| `post_data` | `char *` |  |  |

**Returns:** `char *`

> **Inherited:** Documentation from [`https_request`](#https_request) (include/beacon_common.h:119).

*Calls:* [`rand`](include.beacon_common.c.md#rand)

*Called by:* [`download_bof`](#download_bof), [`handle_peer_connection`](#handle_peer_connection), [`send_to_c2_or_peer`](#send_to_c2_or_peer)

---

<a id="base64_encode"></a>

### `base64_encode`

`function` | [legacy/beacon_p2p.c:763](../../legacy/beacon_p2p.c#L763)

```c
char *base64_encode(const unsigned char *input, int len)
```

Base64 encode/decode (OpenSSL BIO-based)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `unsigned char *` |  |  |
| `len` | `int` |  |  |

**Returns:** `char *`

> **Inherited:** Documentation from [`base64_encode`](#base64_encode) (include/beacon_common.h:123).

*Called by:* [`main`](#main)

---

<a id="base64_decode"></a>

### `base64_decode`

`function` | [legacy/beacon_p2p.c:780](../../legacy/beacon_p2p.c#L780)

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

`function` | [legacy/beacon_p2p.c:802](../../legacy/beacon_p2p.c#L802)

```c
unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t len, int *out_len)
```

AES-256-CFB encrypt/decrypt (standalone, no OpenSSL dependency)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `key` | `unsigned char *` |  |  |
| `iv` | `unsigned char *` |  |  |
| `plaintext` | `unsigned char *` |  |  |
| `len` | `size_t` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `unsigned char *`

> **Inherited:** Documentation from [`aes256_cfb_encrypt`](#aes256_cfb_encrypt) (include/beacon_common.h:134).

*Called by:* [`handle_peer_connection`](#handle_peer_connection), [`main`](#main), [`send_to_peer`](#send_to_peer)

---

<a id="aes256_cfb_decrypt"></a>

### `aes256_cfb_decrypt`

`function` | [legacy/beacon_p2p.c:832](../../legacy/beacon_p2p.c#L832)

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

*Called by:* [`handle_peer_connection`](#handle_peer_connection), [`main`](#main), [`send_to_peer`](#send_to_peer)

---

<a id="exec_cmd"></a>

### `exec_cmd`

`function` | [legacy/beacon_p2p.c:866](../../legacy/beacon_p2p.c#L866)

```c
char *exec_cmd(const char *cmd, int *out_len)
```

UTILIDADES: ejecutar comandos shell, obtener IPs, etc.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cmd` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Called by:* [`execute_generic_command`](#execute_generic_command)

---

<a id="get_local_ips"></a>

### `get_local_ips`

`function` | [legacy/beacon_p2p.c:891](../../legacy/beacon_p2p.c#L891)

```c
char *get_local_ips()
```

Get local IP addresses as a comma-separated string.

Returns malloc'd buffer (caller frees). Falls back to "127.0.0.1".

**Returns:** `char *`

> **Inherited:** Documentation from [`get_local_ips`](#get_local_ips) (include/beacon_common.h:178).

*Called by:* [`main`](#main)

---

<a id="download_bof"></a>

### `download_bof`

`function` | [legacy/beacon_p2p.c:925](../../legacy/beacon_p2p.c#L925)

```c
unsigned char *download_bof(const char *url, size_t *out_size)
```

Download a BOF from the C2 server.

Returns malloc'd buffer (caller frees). On error, sets *out_size to 0 and returns NULL.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char *` |  |  |
| `out_size` | `size_t *` |  |  |

**Returns:** `unsigned char *`

> **Inherited:** Documentation from [`download_bof`](#download_bof) (include/beacon_common.h:169).

*Calls:* [`https_request`](#https_request)

*Called by:* [`execute_generic_command`](#execute_generic_command)

---

<a id="run_bof_and_capture"></a>

### `run_bof_and_capture`

`function` | [legacy/beacon_p2p.c:939](../../legacy/beacon_p2p.c#L939)

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

*Calls:* [`RunELF`](#runelf)

*Called by:* [`execute_generic_command`](#execute_generic_command)

---

<a id="add_peer"></a>

### `add_peer`

`function` | [legacy/beacon_p2p.c:965](../../legacy/beacon_p2p.c#L965)

```c
void add_peer(struct in_addr ip, int port, const char *id)
```

FUNCIONES P2P

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ip` | `struct in_addr` |  |  |
| `port` | `int` |  |  |
| `id` | `char *` |  |  |

*Called by:* [`peer_discovery_thread`](#peer_discovery_thread)

---

<a id="peer_discovery_thread"></a>

### `peer_discovery_thread`

`function` | [legacy/beacon_p2p.c:992](../../legacy/beacon_p2p.c#L992)

```c
void *peer_discovery_thread(void *arg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `arg` | `void *` |  |  |

**Returns:** `void *`

*Calls:* [`add_peer`](#add_peer)

---

<a id="handle_peer_connection"></a>

### `handle_peer_connection`

`function` | [legacy/beacon_p2p.c:1032](../../legacy/beacon_p2p.c#L1032)

```c
void *handle_peer_connection(void *arg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `arg` | `void *` |  |  |

**Returns:** `void *`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`execute_generic_command`](#execute_generic_command), [`https_request`](#https_request)

---

<a id="peer_server_thread"></a>

### `peer_server_thread`

`function` | [legacy/beacon_p2p.c:1130](../../legacy/beacon_p2p.c#L1130)

```c
void *peer_server_thread(void *arg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `arg` | `void *` |  |  |

**Returns:** `void *`

---

<a id="send_to_peer"></a>

### `send_to_peer`

`function` | [legacy/beacon_p2p.c:1153](../../legacy/beacon_p2p.c#L1153)

```c
char *send_to_peer(peer_t *peer, const char *data, int *out_len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `peer` | `peer_t *` |  |  |
| `data` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt)

*Called by:* [`send_to_c2_or_peer`](#send_to_c2_or_peer)

---

<a id="send_to_c2_or_peer"></a>

### `send_to_c2_or_peer`

`function` | [legacy/beacon_p2p.c:1197](../../legacy/beacon_p2p.c#L1197)

```c
char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | `char *` |  |  |
| `method` | `char *` |  |  |
| `data` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Calls:* [`https_request`](#https_request), [`send_to_peer`](#send_to_peer)

*Called by:* [`main`](#main)

---

<a id="execute_generic_command"></a>

### `execute_generic_command`

`function` | [legacy/beacon_p2p.c:1231](../../legacy/beacon_p2p.c#L1231)

```c
char *execute_generic_command(const char *cmd, int *out_len)
```

EJECUTOR DE COMANDOS (unificado para shell y BOF)

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cmd` | `char *` |  |  |
| `out_len` | `int *` |  |  |

**Returns:** `char *`

*Calls:* [`download_bof`](#download_bof), [`exec_cmd`](#exec_cmd), [`run_bof_and_capture`](#run_bof_and_capture)

*Called by:* [`handle_peer_connection`](#handle_peer_connection), [`main`](#main)

---

<a id="main"></a>

### `main`

`function` | [legacy/beacon_p2p.c:1276](../../legacy/beacon_p2p.c#L1276)

```c
int main()
```

MAIN

**Returns:** `int`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`base64_decode`](#base64_decode), [`base64_encode`](#base64_encode), [`execute_generic_command`](#execute_generic_command), [`get_local_ips`](#get_local_ips), [`send_to_c2_or_peer`](#send_to_c2_or_peer)

---

## Macros

<a id="_gnu_source"></a>

### `_GNU_SOURCE`

`macro` | [legacy/beacon_p2p.c:1](../../legacy/beacon_p2p.c#L1)

```c
#define _GNU_SOURCE
```

---

<a id="c2_url"></a>

### `C2_URL`

`macro` | [legacy/beacon_p2p.c:37](../../legacy/beacon_p2p.c#L37)

```c
#define C2_URL
```

CONSTANTES

---

<a id="client_id"></a>

### `CLIENT_ID`

`macro` | [legacy/beacon_p2p.c:38](../../legacy/beacon_p2p.c#L38)

```c
#define CLIENT_ID
```

---

<a id="maleable"></a>

### `MALEABLE`

`macro` | [legacy/beacon_p2p.c:39](../../legacy/beacon_p2p.c#L39)

```c
#define MALEABLE
```

---

<a id="user_agents_count"></a>

### `USER_AGENTS_COUNT`

`macro` | [legacy/beacon_p2p.c:40](../../legacy/beacon_p2p.c#L40)

```c
#define USER_AGENTS_COUNT
```

---

<a id="peer_discovery_port"></a>

### `PEER_DISCOVERY_PORT`

`macro` | [legacy/beacon_p2p.c:42](../../legacy/beacon_p2p.c#L42)

```c
#define PEER_DISCOVERY_PORT
```

---

<a id="peer_tcp_port"></a>

### `PEER_TCP_PORT`

`macro` | [legacy/beacon_p2p.c:43](../../legacy/beacon_p2p.c#L43)

```c
#define PEER_TCP_PORT
```

---

<a id="peer_magic"></a>

### `PEER_MAGIC`

`macro` | [legacy/beacon_p2p.c:44](../../legacy/beacon_p2p.c#L44)

```c
#define PEER_MAGIC
```

---

<a id="peer_version"></a>

### `PEER_VERSION`

`macro` | [legacy/beacon_p2p.c:45](../../legacy/beacon_p2p.c#L45)

```c
#define PEER_VERSION
```

---

<a id="broadcast_interval"></a>

### `BROADCAST_INTERVAL`

`macro` | [legacy/beacon_p2p.c:46](../../legacy/beacon_p2p.c#L46)

```c
#define BROADCAST_INTERVAL
```

---

<a id="max_peers"></a>

### `MAX_PEERS`

`macro` | [legacy/beacon_p2p.c:47](../../legacy/beacon_p2p.c#L47)

```c
#define MAX_PEERS
```

---
