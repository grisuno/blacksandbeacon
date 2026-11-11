# `cJSON.h`

> Source: [cJSON.h:1](../../cJSON.h#L1) | language `h` | coverage 20.0% | [API index](../index.md)

## Contents

- **Structs:** [`cJSON`](#cjson), [`cJSON_Hooks`](#cjson_hooks)
- **Type Aliases:** [`cJSON_bool`](#cjson_bool)
- **Functions:** [`cJSON_Parse`](#cjson_parse), [`cJSON_GetErrorPtr`](#cjson_geterrorptr), [`that`](#that), [`sensitive`](#sensitive)
- **Macros:** [`cJSON__h`](#cjson__h), [`__WINDOWS__`](#__windows__), [`CJSON_CDECL`](#cjson_cdecl), [`CJSON_STDCALL`](#cjson_stdcall), [`CJSON_EXPORT_SYMBOLS`](#cjson_export_symbols), [`CJSON_PUBLIC`](#cjson_public), [`CJSON_PUBLIC`](#cjson_public), [`CJSON_PUBLIC`](#cjson_public), [`CJSON_CDECL`](#cjson_cdecl), [`CJSON_STDCALL`](#cjson_stdcall), [`CJSON_PUBLIC`](#cjson_public), [`CJSON_PUBLIC`](#cjson_public), [`CJSON_VERSION_MAJOR`](#cjson_version_major), [`CJSON_VERSION_MINOR`](#cjson_version_minor), [`CJSON_VERSION_PATCH`](#cjson_version_patch), [`cJSON_Invalid`](#cjson_invalid), [`cJSON_False`](#cjson_false), [`cJSON_True`](#cjson_true), [`cJSON_NULL`](#cjson_null), [`cJSON_Number`](#cjson_number), [`cJSON_String`](#cjson_string), [`cJSON_Array`](#cjson_array), [`cJSON_Object`](#cjson_object), [`cJSON_Raw`](#cjson_raw), [`cJSON_IsReference`](#cjson_isreference), [`cJSON_StringIsConst`](#cjson_stringisconst), [`CJSON_NESTING_LIMIT`](#cjson_nesting_limit), [`CJSON_CIRCULAR_LIMIT`](#cjson_circular_limit), [`cJSON_SetIntValue`](#cjson_setintvalue), [`cJSON_SetNumberValue`](#cjson_setnumbervalue), [`cJSON_SetBoolValue`](#cjson_setboolvalue), [`cJSON_ArrayForEach`](#cjson_arrayforeach)
- **Variables:** [`next`](#next)

## Type Diagram

```mermaid
classDiagram
    direction LR
    class cJSON
    <<struct>> cJSON
    class cJSON_Hooks
    <<struct>> cJSON_Hooks
    class cJSON_bool
    <<type_alias>> cJSON_bool
```

## Call Graph

Solid arrows stay in this module, dashed arrows leave it.

```mermaid
flowchart LR
    n_cJSON_h__cJSON__h(["cJSON__h"])
    n_cJSON_h__CJSON_PUBLIC(["CJSON_PUBLIC"])
    n_cJSON_h__cJSON_GetErrorPtr(["cJSON_GetErrorPtr"])
    n_cJSON_h__cJSON_Parse(["cJSON_Parse"])
    n_cJSON_h__cJSON__h --> n_cJSON_h__CJSON_PUBLIC
    n_cJSON_h__cJSON__h --> n_cJSON_h__cJSON_GetErrorPtr
    n_cJSON_h__cJSON__h --> n_cJSON_h__cJSON_Parse
```

## Structs

<a id="cjson"></a>

### `cJSON`

`struct` | [cJSON.h:98](../../cJSON.h#L98)

```c
typedef struct cJSON
```

The cJSON structure:

---

<a id="cjson_hooks"></a>

### `cJSON_Hooks`

`struct` | [cJSON.h:123](../../cJSON.h#L123)

```c
typedef struct cJSON_Hooks
```

---

## Type Aliases

<a id="cjson_bool"></a>

### `cJSON_bool`

`type_alias` | [cJSON.h:130](../../cJSON.h#L130)

```c
typedef int cJSON_bool;
```

---

## Functions

<a id="cjson_parse"></a>

### `cJSON_Parse`

`function` | [cJSON.h:152](../../cJSON.h#L152)

```c
* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as appropriate). The exception is cJSON_PrintPreallocated, where the caller has * full respons
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cJSON_Delete` | `with` |  |  |

**Returns:** `*`

*Called by:* [`cJSON__h`](#cjson__h)

---

<a id="cjson_geterrorptr"></a>

### `cJSON_GetErrorPtr`

`function` | [cJSON.h:161](../../cJSON.h#L161)

```c
* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON_bool require_null_terminated);
```

**Returns:** `* a pointer to the error so will match`

*Called by:* [`CJSON_PUBLIC`](cJSON.c.md#cjson_public), [`cJSON__h`](#cjson__h)

---

<a id="that"></a>

### `that`

`function` | [cJSON.h:247](../../cJSON.h#L247)

```c
* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObjectCS(cJSON *object, const char *string, cJSON *item);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `cJSON_StringIsConst` | `item->type &` |  |  |

**Returns:** `*`

---

<a id="sensitive"></a>

### `sensitive`

`function` | [cJSON.h:286](../../cJSON.h#L286)

```c
* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bool case_sensitive);
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `1` |  |  |  |

**Returns:** `*`

---

## Macros

<a id="cjson__h"></a>

### `cJSON__h`

`macro` | [cJSON.h:24](../../cJSON.h#L24)

```c
#define cJSON__h
```

*Calls:* [`CJSON_PUBLIC`](#cjson_public), [`cJSON_GetErrorPtr`](#cjson_geterrorptr), [`cJSON_Parse`](#cjson_parse)

---

<a id="__windows__"></a>

### `__WINDOWS__`

`macro` | [cJSON.h:33](../../cJSON.h#L33)

```c
#define __WINDOWS__
```

---

<a id="cjson_cdecl"></a>

### `CJSON_CDECL`

`macro` | [cJSON.h:49](../../cJSON.h#L49)

```c
#define CJSON_CDECL
```

!__WINDOWS__

> **Inherited:** Documentation from [`CJSON_CDECL`](#cjson_cdecl) (cJSON.h:65).

---

<a id="cjson_stdcall"></a>

### `CJSON_STDCALL`

`macro` | [cJSON.h:50](../../cJSON.h#L50)

```c
#define CJSON_STDCALL
```

---

<a id="cjson_export_symbols"></a>

### `CJSON_EXPORT_SYMBOLS`

`macro` | [cJSON.h:54](../../cJSON.h#L54)

```c
#define CJSON_EXPORT_SYMBOLS
```

---

<a id="cjson_public"></a>

### `CJSON_PUBLIC`

`macro` | [cJSON.h:58](../../cJSON.h#L58)

```c
#define CJSON_PUBLIC(type)
```

*Called by:* [`cJSON__h`](#cjson__h)

---

<a id="cjson_public"></a>

### `CJSON_PUBLIC`

`macro` | [cJSON.h:60](../../cJSON.h#L60)

```c
#define CJSON_PUBLIC(type)
```

---

<a id="cjson_public"></a>

### `CJSON_PUBLIC`

`macro` | [cJSON.h:62](../../cJSON.h#L62)

```c
#define CJSON_PUBLIC(type)
```

---

<a id="cjson_cdecl"></a>

### `CJSON_CDECL`

`macro` | [cJSON.h:65](../../cJSON.h#L65)

```c
#define CJSON_CDECL
```

!__WINDOWS__

---

<a id="cjson_stdcall"></a>

### `CJSON_STDCALL`

`macro` | [cJSON.h:66](../../cJSON.h#L66)

```c
#define CJSON_STDCALL
```

---

<a id="cjson_public"></a>

### `CJSON_PUBLIC`

`macro` | [cJSON.h:70](../../cJSON.h#L70)

```c
#define CJSON_PUBLIC(type)
```

---

<a id="cjson_public"></a>

### `CJSON_PUBLIC`

`macro` | [cJSON.h:72](../../cJSON.h#L72)

```c
#define CJSON_PUBLIC(type)
```

---

<a id="cjson_version_major"></a>

### `CJSON_VERSION_MAJOR`

`macro` | [cJSON.h:77](../../cJSON.h#L77)

```c
#define CJSON_VERSION_MAJOR
```

project version

---

<a id="cjson_version_minor"></a>

### `CJSON_VERSION_MINOR`

`macro` | [cJSON.h:78](../../cJSON.h#L78)

```c
#define CJSON_VERSION_MINOR
```

---

<a id="cjson_version_patch"></a>

### `CJSON_VERSION_PATCH`

`macro` | [cJSON.h:79](../../cJSON.h#L79)

```c
#define CJSON_VERSION_PATCH
```

---

<a id="cjson_invalid"></a>

### `cJSON_Invalid`

`macro` | [cJSON.h:84](../../cJSON.h#L84)

```c
#define cJSON_Invalid
```

cJSON Types:

---

<a id="cjson_false"></a>

### `cJSON_False`

`macro` | [cJSON.h:85](../../cJSON.h#L85)

```c
#define cJSON_False
```

---

<a id="cjson_true"></a>

### `cJSON_True`

`macro` | [cJSON.h:86](../../cJSON.h#L86)

```c
#define cJSON_True
```

---

<a id="cjson_null"></a>

### `cJSON_NULL`

`macro` | [cJSON.h:87](../../cJSON.h#L87)

```c
#define cJSON_NULL
```

---

<a id="cjson_number"></a>

### `cJSON_Number`

`macro` | [cJSON.h:88](../../cJSON.h#L88)

```c
#define cJSON_Number
```

---

<a id="cjson_string"></a>

### `cJSON_String`

`macro` | [cJSON.h:89](../../cJSON.h#L89)

```c
#define cJSON_String
```

---

<a id="cjson_array"></a>

### `cJSON_Array`

`macro` | [cJSON.h:90](../../cJSON.h#L90)

```c
#define cJSON_Array
```

---

<a id="cjson_object"></a>

### `cJSON_Object`

`macro` | [cJSON.h:91](../../cJSON.h#L91)

```c
#define cJSON_Object
```

---

<a id="cjson_raw"></a>

### `cJSON_Raw`

`macro` | [cJSON.h:92](../../cJSON.h#L92)

```c
#define cJSON_Raw
```

---

<a id="cjson_isreference"></a>

### `cJSON_IsReference`

`macro` | [cJSON.h:94](../../cJSON.h#L94)

```c
#define cJSON_IsReference
```

---

<a id="cjson_stringisconst"></a>

### `cJSON_StringIsConst`

`macro` | [cJSON.h:95](../../cJSON.h#L95)

```c
#define cJSON_StringIsConst
```

---

<a id="cjson_nesting_limit"></a>

### `CJSON_NESTING_LIMIT`

`macro` | [cJSON.h:136](../../cJSON.h#L136)

```c
#define CJSON_NESTING_LIMIT
```

---

<a id="cjson_circular_limit"></a>

### `CJSON_CIRCULAR_LIMIT`

`macro` | [cJSON.h:142](../../cJSON.h#L142)

```c
#define CJSON_CIRCULAR_LIMIT
```

---

<a id="cjson_setintvalue"></a>

### `cJSON_SetIntValue`

`macro` | [cJSON.h:312](../../cJSON.h#L312)

```c
#define cJSON_SetIntValue(object, number)
```

When assigning an integer value, it needs to be propagated to valuedouble too.

---

<a id="cjson_setnumbervalue"></a>

### `cJSON_SetNumberValue`

`macro` | [cJSON.h:316](../../cJSON.h#L316)

```c
#define cJSON_SetNumberValue(object, number)
```

---

<a id="cjson_setboolvalue"></a>

### `cJSON_SetBoolValue`

`macro` | [cJSON.h:324](../../cJSON.h#L324)

```c
#define cJSON_SetBoolValue(object, boolValue)
```

If the object is not a boolean type this does nothing and returns cJSON_Invalid else it returns the new type

---

<a id="cjson_arrayforeach"></a>

### `cJSON_ArrayForEach`

`macro` | [cJSON.h:331](../../cJSON.h#L331)

```c
#define cJSON_ArrayForEach(element, array)
```

Macro for iterating over an array or object

---

## Variables

<a id="next"></a>

### `next`

`variable` `extern` | [cJSON.h:27](../../cJSON.h#L27)

```c
extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for window
```

ifdef __cplusplus

---
