# `include/beacon.h`

> Source: [include/beacon.h:1](../../include/beacon.h#L1) | language `h` | coverage 46.2% | [API index](../index.md)

beacon_api.h   Tipos de callback  Estructura para parsing de datos (opcional, para comandos complejos)

## Contents

- **Structs:** [`datap`](#datap)
- **Functions:** [`BeaconDataParse`](#beacondataparse), [`BeaconDataPtr`](#beacondataptr), [`BeaconDataInt`](#beacondataint), [`BeaconDataShort`](#beacondatashort), [`BeaconDataLength`](#beacondatalength), [`BeaconDataExtract`](#beacondataextract), [`BeaconPrintf`](#beaconprintf), [`BeaconOutput`](#beaconoutput)
- **Macros:** [`CALLBACK_OUTPUT`](#callback_output), [`CALLBACK_ERROR`](#callback_error), [`CALLBACK_OUTPUT_OEM`](#callback_output_oem)

## Structs

<a id="datap"></a>

### `datap`

`struct` | [include/beacon.h:14](../../include/beacon.h#L14)

```c
typedef struct
```

Estructura para parsing de datos (opcional, para comandos complejos)

---

## Functions

<a id="beacondataparse"></a>

### `BeaconDataParse`

`function` | [include/beacon.h:21](../../include/beacon.h#L21)

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

---

<a id="beacondataptr"></a>

### `BeaconDataPtr`

`function` | [include/beacon.h:22](../../include/beacon.h#L22)

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

`function` | [include/beacon.h:23](../../include/beacon.h#L23)

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

`function` | [include/beacon.h:24](../../include/beacon.h#L24)

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

`function` | [include/beacon.h:25](../../include/beacon.h#L25)

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

`function` | [include/beacon.h:26](../../include/beacon.h#L26)

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

<a id="beaconprintf"></a>

### `BeaconPrintf`

`function` | [include/beacon.h:27](../../include/beacon.h#L27)

```c
void BeaconPrintf(int type, const char *fmt, ...);
```

Beacon API: printf-style output capture (called by BOFs).

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `type` | `int` |  |  |
| `fmt` | `char *` |  |  |
| `...` |  |  |  |

> **Inherited:** Documentation from [`BeaconPrintf`](#beaconprintf) (include/beacon_common.h:102).

---

<a id="beaconoutput"></a>

### `BeaconOutput`

`function` | [include/beacon.h:28](../../include/beacon.h#L28)

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

---

## Macros

<a id="callback_output"></a>

### `CALLBACK_OUTPUT`

`macro` | [include/beacon.h:9](../../include/beacon.h#L9)

```c
#define CALLBACK_OUTPUT
```

Tipos de callback

---

<a id="callback_error"></a>

### `CALLBACK_ERROR`

`macro` | [include/beacon.h:10](../../include/beacon.h#L10)

```c
#define CALLBACK_ERROR
```

---

<a id="callback_output_oem"></a>

### `CALLBACK_OUTPUT_OEM`

`macro` | [include/beacon.h:11](../../include/beacon.h#L11)

```c
#define CALLBACK_OUTPUT_OEM
```

---
