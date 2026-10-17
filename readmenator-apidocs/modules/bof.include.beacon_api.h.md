# `bof/include/beacon_api.h`

> Source: [bof/include/beacon_api.h:1](../../bof/include/beacon_api.h#L1) | language `h` | coverage 28.6% | [API index](../index.md)

## Contents

- **Structs:** [`datap`](#datap)
- **Functions:** [`go`](#go), [`BeaconDataParse`](#beacondataparse), [`BeaconDataPtr`](#beacondataptr), [`BeaconDataInt`](#beacondataint), [`BeaconDataShort`](#beacondatashort), [`BeaconDataLength`](#beacondatalength), [`BeaconDataExtract`](#beacondataextract), [`buffer`](#buffer), [`BeaconOutput`](#beaconoutput)
- **Macros:** [`CALLBACK_OUTPUT`](#callback_output), [`CALLBACK_ERROR`](#callback_error), [`CALLBACK_OUTPUT_OEM`](#callback_output_oem)

## Structs

<a id="datap"></a>

### `datap`

`struct` | [bof/include/beacon_api.h:30](../../bof/include/beacon_api.h#L30)

```c
typedef struct
```

Argument parser.

BOFs that want to read structured args fill one of these in via BeaconDataParse then pull fields out.

---

## Functions

<a id="go"></a>

### `go`

`function` | [bof/include/beacon_api.h:10](../../bof/include/beacon_api.h#L10)

```c
* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

**Returns:** `* * BOFs MUST a with this exact signature: * * void`

---

<a id="beacondataparse"></a>

### `BeaconDataParse`

`function` | [bof/include/beacon_api.h:36](../../bof/include/beacon_api.h#L36)

```c
void BeaconDataParse(datap *parser, char *buffer, int size);
```

=== API para BOFs ===

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `buffer` | `char *` |  |  |
| `size` | `int` |  |  |

> **Inherited:** Documentation from [`BeaconDataParse`](#beacondataparse) (beacon.h:21).

---

<a id="beacondataptr"></a>

### `BeaconDataPtr`

`function` | [bof/include/beacon_api.h:37](../../bof/include/beacon_api.h#L37)

```c
char *BeaconDataPtr(datap *parser, int size);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `size` | `int` |  |  |

**Returns:** `char *`

---

<a id="beacondataint"></a>

### `BeaconDataInt`

`function` | [bof/include/beacon_api.h:38](../../bof/include/beacon_api.h#L38)

```c
int BeaconDataInt(datap *parser);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `int`

---

<a id="beacondatashort"></a>

### `BeaconDataShort`

`function` | [bof/include/beacon_api.h:39](../../bof/include/beacon_api.h#L39)

```c
short BeaconDataShort(datap *parser);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `short`

---

<a id="beacondatalength"></a>

### `BeaconDataLength`

`function` | [bof/include/beacon_api.h:40](../../bof/include/beacon_api.h#L40)

```c
int BeaconDataLength(datap *parser);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |

**Returns:** `int`

---

<a id="beacondataextract"></a>

### `BeaconDataExtract`

`function` | [bof/include/beacon_api.h:41](../../bof/include/beacon_api.h#L41)

```c
char *BeaconDataExtract(datap *parser, int *size);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `parser` | `datap *` |  |  |
| `size` | `int *` |  |  |

**Returns:** `char *`

---

<a id="buffer"></a>

### `buffer`

`function` | [bof/include/beacon_api.h:44](../../bof/include/beacon_api.h#L44)

```c
* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void BeaconPrintf(int type, const char *fmt, ...);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `terminated` | `len may be 0 for strlen-style strings * but the buffer must still be NUL-` |  |  |

**Returns:** `* takes a raw byte`

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` | [bof/include/beacon_api.h:47](../../bof/include/beacon_api.h#L47)

```c
void BeaconOutput(int type, const char *data, int len);
```

Beacon API: raw output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `data` | `char *` |  |  |
| `len` | `int` |  |  |

> **Inherited:** Documentation from [`BeaconOutput`](#beaconoutput) (include/beacon_common.h:105).

*Called by:* [`go`](bof.cat.bof.c.md#go), [`go`](bof.is_sudo.bof.c.md#go), [`go`](bof.whoami.bof.c.md#go)

---

## Macros

<a id="callback_output"></a>

### `CALLBACK_OUTPUT`

`macro` | [bof/include/beacon_api.h:24](../../bof/include/beacon_api.h#L24)

```c
#define CALLBACK_OUTPUT
```

Callback types.

Kept compatible with the original beacon.h.

---

<a id="callback_error"></a>

### `CALLBACK_ERROR`

`macro` | [bof/include/beacon_api.h:25](../../bof/include/beacon_api.h#L25)

```c
#define CALLBACK_ERROR
```

---

<a id="callback_output_oem"></a>

### `CALLBACK_OUTPUT_OEM`

`macro` | [bof/include/beacon_api.h:26](../../bof/include/beacon_api.h#L26)

```c
#define CALLBACK_OUTPUT_OEM
```

---
