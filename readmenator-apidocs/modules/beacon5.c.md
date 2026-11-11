# `beacon5.c`

> Source: [beacon5.c:1](../../beacon5.c#L1) | language `c` | coverage 38.5% | [API index](../index.md)

## Contents

- **Structs:** [`MemoryStruct`](#memorystruct), [`peer_t`](#peer_t), [`mesh_msg_t`](#mesh_msg_t), [`Trampoline`](#trampoline), [`SymbolResolver`](#symbolresolver), [`TrampolineCache`](#trampolinecache)
- **Functions:** [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput), [`https_request`](#https_request), [`base64_encode`](#base64_encode), [`base64_decode`](#base64_decode), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`exec_cmd`](#exec_cmd), [`RunELF`](#runelf), [`get_local_ips`](#get_local_ips), [`download_bof`](#download_bof), [`run_bof_and_capture`](#run_bof_and_capture), [`mesh_mark_seen`](#mesh_mark_seen), [`mesh_is_seen`](#mesh_is_seen), [`mesh_add_peer`](#mesh_add_peer), [`mesh_cleanup_peers`](#mesh_cleanup_peers), [`mesh_send_to_peer`](#mesh_send_to_peer), [`mesh_propagate`](#mesh_propagate), [`mesh_discovery_thread`](#mesh_discovery_thread), [`mesh_listener_thread`](#mesh_listener_thread), [`mesh_send_message`](#mesh_send_message), [`main`](#main)
- **Macros:** [`_GNU_SOURCE`](#_gnu_source), [`MAX_PEERS`](#max_peers), [`DISCOVERY_PORT`](#discovery_port), [`DISCOVERY_INTERVAL`](#discovery_interval), [`MAX_TTL`](#max_ttl), [`MESH_MSG_SIZE`](#mesh_msg_size), [`C2_URL`](#c2_url), [`CLIENT_ID`](#client_id), [`MALEABLE`](#maleable), [`USER_AGENTS_COUNT`](#user_agents_count)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class MemoryStruct
    <<struct>> MemoryStruct
    class peer_t
    <<struct>> peer_t
    class mesh_msg_t
    <<struct>> mesh_msg_t
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
    n_beacon5_c__download_bof(["download_bof"])
    n_beacon5_c__https_request(["https_request"])
    n_beacon5_c__run_bof_and_capture(["run_bof_and_capture"])
    n_beacon5_c__RunELF(["RunELF"])
    n_beacon5_c__mesh_propagate(["mesh_propagate"])
    n_beacon5_c__mesh_mark_seen(["mesh_mark_seen"])
    n_beacon5_c__mesh_send_to_peer(["mesh_send_to_peer"])
    n_beacon5_c__mesh_discovery_thread(["mesh_discovery_thread"])
    n_beacon5_c__mesh_add_peer(["mesh_add_peer"])
    n_beacon5_c__mesh_cleanup_peers(["mesh_cleanup_peers"])
    n_beacon5_c__mesh_listener_thread(["mesh_listener_thread"])
    n_beacon5_c__aes256_cfb_decrypt(["aes256_cfb_decrypt"])
    n_beacon5_c__base64_decode(["base64_decode"])
    n_beacon5_c__exec_cmd(["exec_cmd"])
    n_beacon5_c__mesh_is_seen(["mesh_is_seen"])
    n_beacon5_c__mesh_send_message(["mesh_send_message"])
    n_beacon5_c__main(["main"])
    n_beacon5_c__aes256_cfb_encrypt(["aes256_cfb_encrypt"])
    n_beacon5_c__base64_encode(["base64_encode"])
    n_beacon5_c__download_bof --> n_beacon5_c__https_request
    n_beacon5_c__run_bof_and_capture --> n_beacon5_c__RunELF
    n_beacon5_c__mesh_propagate --> n_beacon5_c__mesh_mark_seen
    n_beacon5_c__mesh_propagate --> n_beacon5_c__mesh_send_to_peer
    n_beacon5_c__mesh_discovery_thread --> n_beacon5_c__mesh_add_peer
    n_beacon5_c__mesh_discovery_thread --> n_beacon5_c__mesh_cleanup_peers
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__aes256_cfb_decrypt
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__base64_decode
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__download_bof
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__exec_cmd
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__https_request
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__mesh_is_seen
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__mesh_mark_seen
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__mesh_send_message
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__mesh_send_to_peer
    n_beacon5_c__mesh_listener_thread --> n_beacon5_c__run_bof_and_capture
    n_beacon5_c__mesh_send_message --> n_beacon5_c__mesh_mark_seen
    n_beacon5_c__mesh_send_message --> n_beacon5_c__mesh_send_to_peer
    n_beacon5_c__main --> n_beacon5_c__aes256_cfb_decrypt
    n_beacon5_c__main --> n_beacon5_c__aes256_cfb_encrypt
    n_beacon5_c__main --> n_beacon5_c__base64_decode
    n_beacon5_c__main --> n_beacon5_c__base64_encode
    n_beacon5_c__main --> n_beacon5_c__download_bof
    n_beacon5_c__main --> n_beacon5_c__exec_cmd
```

## Structs

<a id="memorystruct"></a>

### `MemoryStruct`

`struct` | [beacon5.c:61](../../beacon5.c#L61)

```c
struct MemoryStruct
```

=== ESTRUCTURAS ===

---

<a id="peer_t"></a>

### `peer_t`

`struct` | [beacon5.c:69](../../beacon5.c#L69)

```c
typedef struct
```

=== ESTRUCTURAS MESH ===

---

<a id="mesh_msg_t"></a>

### `mesh_msg_t`

`struct` | [beacon5.c:77](../../beacon5.c#L77)

```c
typedef struct
```

---

<a id="trampoline"></a>

### `Trampoline`

`struct` | [beacon5.c:102](../../beacon5.c#L102)

```c
typedef struct
```

=== TRAMPOLINES ===

---

<a id="symbolresolver"></a>

### `SymbolResolver`

`struct` | [beacon5.c:111](../../beacon5.c#L111)

```c
typedef struct
```

---

<a id="trampolinecache"></a>

### `TrampolineCache`

`struct` | [beacon5.c:118](../../beacon5.c#L118)

```c
typedef struct
```

=== CACHE DE TRAMPOLINES ===

---

## Functions

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [beacon5.c:239](../../beacon5.c#L239)

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

`function` | [beacon5.c:256](../../beacon5.c#L256)

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

`function` | [beacon5.c:385](../../beacon5.c#L385)

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

*Called by:* [`download_bof`](#download_bof), [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="base64_encode"></a>

### `base64_encode`

`function` | [beacon5.c:479](../../beacon5.c#L479)

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

`function` | [beacon5.c:497](../../beacon5.c#L497)

```c
unsigned char *base64_decode(const char *input, int *len)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `input` | `char *` |  |  |
| `len` | `int *` |  |  |

**Returns:** `unsigned char *`

*Called by:* [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="aes256_cfb_encrypt"></a>

### `aes256_cfb_encrypt`

`function` | [beacon5.c:523](../../beacon5.c#L523)

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

*Calls:* [`AES_ECB_encrypt`](aes.h.md#aes_ecb_encrypt), [`AES_init_ctx`](aes.h.md#aes_init_ctx)

*Called by:* [`main`](#main)

---

<a id="aes256_cfb_decrypt"></a>

### `aes256_cfb_decrypt`

`function` | [beacon5.c:557](../../beacon5.c#L557)

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

*Calls:* [`AES_ECB_encrypt`](aes.h.md#aes_ecb_encrypt), [`AES_init_ctx`](aes.h.md#aes_init_ctx)

*Called by:* [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="exec_cmd"></a>

### `exec_cmd`

`function` | [beacon5.c:593](../../beacon5.c#L593)

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

*Called by:* [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="runelf"></a>

### `RunELF`

`function` | [beacon5.c:627](../../beacon5.c#L627)

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

`function` | [beacon5.c:1126](../../beacon5.c#L1126)

```c
char *get_local_ips()
```

=== GET LOCAL IPs ===

**Returns:** `char *`

*Called by:* [`main`](#main)

---

<a id="download_bof"></a>

### `download_bof`

`function` | [beacon5.c:1161](../../beacon5.c#L1161)

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

*Called by:* [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="run_bof_and_capture"></a>

### `run_bof_and_capture`

`function` | [beacon5.c:1184](../../beacon5.c#L1184)

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

*Called by:* [`main`](#main), [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="mesh_mark_seen"></a>

### `mesh_mark_seen`

`function` | [beacon5.c:1231](../../beacon5.c#L1231)

```c
void mesh_mark_seen(const char *msg_id)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `msg_id` | `char *` |  |  |

*Called by:* [`mesh_listener_thread`](#mesh_listener_thread), [`mesh_propagate`](#mesh_propagate), [`mesh_send_message`](#mesh_send_message)

---

<a id="mesh_is_seen"></a>

### `mesh_is_seen`

`function` | [beacon5.c:1240](../../beacon5.c#L1240)

```c
int mesh_is_seen(const char *msg_id)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `msg_id` | `char *` |  |  |

**Returns:** `int`

*Called by:* [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="mesh_add_peer"></a>

### `mesh_add_peer`

`function` | [beacon5.c:1255](../../beacon5.c#L1255)

```c
void mesh_add_peer(const char *ip, int port)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ip` | `char *` |  |  |
| `port` | `int` |  |  |

*Called by:* [`mesh_discovery_thread`](#mesh_discovery_thread)

---

<a id="mesh_cleanup_peers"></a>

### `mesh_cleanup_peers`

`function` | [beacon5.c:1283](../../beacon5.c#L1283)

```c
void mesh_cleanup_peers()
```

*Called by:* [`mesh_discovery_thread`](#mesh_discovery_thread)

---

<a id="mesh_send_to_peer"></a>

### `mesh_send_to_peer`

`function` | [beacon5.c:1300](../../beacon5.c#L1300)

```c
int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ip` | `char *` |  |  |
| `port` | `int` |  |  |
| `msg` | `mesh_msg_t *` |  |  |

**Returns:** `int`

*Called by:* [`mesh_listener_thread`](#mesh_listener_thread), [`mesh_propagate`](#mesh_propagate), [`mesh_send_message`](#mesh_send_message)

---

<a id="mesh_propagate"></a>

### `mesh_propagate`

`function` | [beacon5.c:1324](../../beacon5.c#L1324)

```c
void mesh_propagate(const char *command)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `command` | `char *` |  |  |

*Calls:* [`mesh_mark_seen`](#mesh_mark_seen), [`mesh_send_to_peer`](#mesh_send_to_peer)

*Called by:* [`main`](#main)

---

<a id="mesh_discovery_thread"></a>

### `mesh_discovery_thread`

`function` | [beacon5.c:1356](../../beacon5.c#L1356)

```c
void *mesh_discovery_thread(void *arg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `arg` | `void *` |  |  |

**Returns:** `void *`

*Calls:* [`mesh_add_peer`](#mesh_add_peer), [`mesh_cleanup_peers`](#mesh_cleanup_peers)

---

<a id="mesh_listener_thread"></a>

### `mesh_listener_thread`

`function` | [beacon5.c:1447](../../beacon5.c#L1447)

```c
void *mesh_listener_thread(void *arg)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `arg` | `void *` |  |  |

**Returns:** `void *`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`base64_decode`](#base64_decode), [`download_bof`](#download_bof), [`exec_cmd`](#exec_cmd), [`https_request`](#https_request), [`mesh_is_seen`](#mesh_is_seen), [`mesh_mark_seen`](#mesh_mark_seen), [`mesh_send_message`](#mesh_send_message), [`mesh_send_to_peer`](#mesh_send_to_peer), [`run_bof_and_capture`](#run_bof_and_capture)

---

<a id="mesh_send_message"></a>

### `mesh_send_message`

`function` | [beacon5.c:1667](../../beacon5.c#L1667)

```c
void mesh_send_message(int type, const char *target, const char *payload)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `target` | `char *` |  |  |
| `payload` | `char *` |  |  |

*Calls:* [`mesh_mark_seen`](#mesh_mark_seen), [`mesh_send_to_peer`](#mesh_send_to_peer)

*Called by:* [`mesh_listener_thread`](#mesh_listener_thread)

---

<a id="main"></a>

### `main`

`function` | [beacon5.c:1702](../../beacon5.c#L1702)

```c
int main(int argc, char **argv)
```

=== MAIN ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `argc` | `int` |  |  |
| `argv` | `char **` |  |  |

**Returns:** `int`

*Calls:* [`aes256_cfb_decrypt`](#aes256_cfb_decrypt), [`aes256_cfb_encrypt`](#aes256_cfb_encrypt), [`base64_decode`](#base64_decode), [`base64_encode`](#base64_encode), [`download_bof`](#download_bof), [`exec_cmd`](#exec_cmd), [`get_local_ips`](#get_local_ips), [`https_request`](#https_request), [`mesh_propagate`](#mesh_propagate), [`run_bof_and_capture`](#run_bof_and_capture)

---

## Macros

<a id="_gnu_source"></a>

### `_GNU_SOURCE`

`macro` | [beacon5.c:1](../../beacon5.c#L1)

```c
#define _GNU_SOURCE
```

---

<a id="max_peers"></a>

### `MAX_PEERS`

`macro` | [beacon5.c:36](../../beacon5.c#L36)

```c
#define MAX_PEERS
```

---

<a id="discovery_port"></a>

### `DISCOVERY_PORT`

`macro` | [beacon5.c:37](../../beacon5.c#L37)

```c
#define DISCOVERY_PORT
```

---

<a id="discovery_interval"></a>

### `DISCOVERY_INTERVAL`

`macro` | [beacon5.c:38](../../beacon5.c#L38)

```c
#define DISCOVERY_INTERVAL
```

---

<a id="max_ttl"></a>

### `MAX_TTL`

`macro` | [beacon5.c:39](../../beacon5.c#L39)

```c
#define MAX_TTL
```

---

<a id="mesh_msg_size"></a>

### `MESH_MSG_SIZE`

`macro` | [beacon5.c:40](../../beacon5.c#L40)

```c
#define MESH_MSG_SIZE
```

---

<a id="c2_url"></a>

### `C2_URL`

`macro` | [beacon5.c:42](../../beacon5.c#L42)

```c
#define C2_URL
```

---

<a id="client_id"></a>

### `CLIENT_ID`

`macro` | [beacon5.c:43](../../beacon5.c#L43)

```c
#define CLIENT_ID
```

---

<a id="maleable"></a>

### `MALEABLE`

`macro` | [beacon5.c:44](../../beacon5.c#L44)

```c
#define MALEABLE
```

---

<a id="user_agents_count"></a>

### `USER_AGENTS_COUNT`

`macro` | [beacon5.c:45](../../beacon5.c#L45)

```c
#define USER_AGENTS_COUNT
```

---
