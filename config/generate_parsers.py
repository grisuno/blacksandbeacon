#!/usr/bin/env python3
"""
Config Parser Generator for Black Sand Beacon

Reads config/schema.json (JSON Schema Draft 7) and generates:
1. include/config_autogen.h - C struct definitions
2. include/config_autogen.c - C parser implementation
3. include/config_py_autogen.py - Python config loader

This ensures C and Python parsers are always in sync.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "config" / "schema.json"
OUT_H = ROOT / "include" / "config_autogen.h"
OUT_C = ROOT / "include" / "config_autogen.c"
OUT_PY = ROOT / "include" / "config_py_autogen.py"


def load_schema() -> Dict[str, Any]:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def c_type_from_schema(prop: Dict[str, Any], required: bool = True) -> str:
    """Map JSON Schema type to C type."""
    prop_type = prop.get("type")
    if prop_type == "string":
        if prop.get("format") == "uri":
            return "char"  # Will use fixed buffer
        if prop.get("pattern", "").startswith("^\\["):
            return "char"  # Fixed buffer for hex strings
        return "char"
    elif prop_type == "integer":
        return "int"
    elif prop_type == "boolean":
        return "int"
    elif prop_type == "array":
        return "char"  # Will use fixed buffer array
    return "char"


def c_field_name(json_name: str) -> str:
    """Convert JSON field name to C field name (snake_case)."""
    return json_name.replace("-", "_")


def generate_c_structs(schema: Dict[str, Any]) -> str:
    """Generate C struct definitions from schema."""
    lines = [
        "/*",
        " * Auto-generated C struct definitions from config/schema.json",
        " * DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate",
        " */",
        "#ifndef BSB_CONFIG_AUTOGEN_H",
        "#define BSB_CONFIG_AUTOGEN_H",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
    ]

    # Generate struct for each top-level section
    for section_name, section_schema in schema.get("properties", {}).items():
        if section_schema.get("type") != "object":
            continue

        struct_name = f"bsb_{section_name}_t"
        lines.append(f"typedef struct {{")
        
        props = section_schema.get("properties", {})
        required = set(section_schema.get("required", []))
        
        for prop_name, prop_schema in props.items():
            field_name = c_field_name(prop_name)
            is_required = prop_name in required
            
            prop_type = prop_schema.get("type")
            if prop_type == "string":
                if "format" in prop_schema and prop_schema["format"] == "uri":
                    max_len = prop_schema.get("maxLength", 512)
                    lines.append(f"    char {field_name}[{max_len + 1}];  /* {prop_schema.get('description', '')} */")
                elif "pattern" in prop_schema and "^\\[" in prop_schema["pattern"]:
                    # Hex string
                    max_len = 64
                    lines.append(f"    char {field_name}[{max_len + 1}];  /* {prop_schema.get('description', '')} */")
                elif "maxLength" in prop_schema:
                    max_len = prop_schema["maxLength"]
                    lines.append(f"    char {field_name}[{max_len + 1}];  /* {prop_schema.get('description', '')} */")
                else:
                    lines.append(f"    char {field_name}[257];  /* {prop_schema.get('description', '')} */")
            elif prop_type == "integer":
                lines.append(f"    int {field_name};  /* {prop_schema.get('description', '')} */")
            elif prop_type == "boolean":
                lines.append(f"    int {field_name};  /* {prop_schema.get('description', '')} */")
            elif prop_type == "array":
                items = prop_schema.get("items", {})
                max_items = prop_schema.get("maxItems", 16)
                item_max_len = items.get("maxLength", 256)
                lines.append(f"    char {field_name}[{max_items}][{item_max_len + 1}];  /* {prop_schema.get('description', '')} */")
                lines.append(f"    int {field_name}_count;")
        
        lines.append(f"}} {struct_name};")
        lines.append("")

    # Main config struct
    lines.append("typedef struct {")
    for section_name in schema.get("properties", {}).keys():
        if schema["properties"][section_name].get("type") == "object":
            struct_name = f"bsb_{section_name}_t"
            lines.append(f"    {struct_name} {section_name};")
    lines.append("    char path[512];")
    lines.append("} bsb_config_t;")
    lines.append("")
    
    # Function declarations
    lines.append("/* Load config from path. Returns 0 on success, -1 on error. */")
    lines.append("int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);")
    lines.append("")
    lines.append("/* Load from BSB_CONFIG env or default path. */")
    lines.append("int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);")
    lines.append("")
    lines.append("/* Compute a sleep duration with jitter applied. Returns seconds. */")
    lines.append("int bsb_config_sleep_seconds(const bsb_config_t *cfg);")
    lines.append("")
    lines.append("#endif /* BSB_CONFIG_AUTOGEN_H */")
    
    return "\n".join(lines)


def generate_c_parser(schema: Dict[str, Any]) -> str:
    """Generate C parser implementation from schema."""
    lines = [
        "/*",
        " * Auto-generated C config parser from config/schema.json",
        " * DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate",
        " */",
        "#define _POSIX_C_SOURCE 200809L",
        "#include \"config_autogen.h\"",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "#include <ctype.h>",
        "#include <time.h>",
        "#include <unistd.h>",
        "#include <limits.h>",
        "",
        "/* --- file slurper --- */",
        "static char *slurp(const char *path, size_t *out_len)",
        "{",
        "    FILE *f = fopen(path, \"rb\");",
        "    if (!f) return NULL;",
        "    fseek(f, 0, SEEK_END);",
        "    long n = ftell(f);",
        "    fseek(f, 0, SEEK_SET);",
        "    if (n < 0) { fclose(f); return NULL; }",
        "    char *buf = (char *)malloc((size_t)n + 1);",
        "    if (!buf) { fclose(f); return NULL; }",
        "    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }",
        "    buf[n] = '\\0';",
        "    fclose(f);",
        "    *out_len = (size_t)n;",
        "    return buf;",
        "}",
        "",
        "/* --- lexer-style cursor helpers --- */",
        "static const char *skip_ws(const char *p, const char *end)",
        "{",
        "    while (p < end && isspace((unsigned char)*p)) p++;",
        "    return p;",
        "}",
        "",
        "static int read_string(const char **pp, const char *end, char *out, size_t outsz)",
        "{",
        "    const char *p = skip_ws(*pp, end);",
        "    if (p >= end || *p != '\"') return 0;",
        "    p++;",
        "    size_t i = 0;",
        "    while (p < end && *p != '\"') {",
        "        char ch = *p++;",
        "        if (ch == '\\\\' && p < end) {",
        "            char esc = *p++;",
        "            switch (esc) {",
        "                case 'n': ch = '\\n'; break;",
        "                case 't': ch = '\\t'; break;",
        "                case 'r': ch = '\\r'; break;",
        "                case '\"': ch = '\"'; break;",
        "                case '\\\\': ch = '\\\\'; break;",
        "                default: ch = esc; break;",
        "            }",
        "        }",
        "        if (i + 1 < outsz) out[i++] = ch;",
        "    }",
        "    if (p >= end) return 0;",
        "    p++;",
        "    if (outsz) out[i < outsz ? i : outsz - 1] = '\\0';",
        "    *pp = p;",
        "    return 1;",
        "}",
        "",
        "static int read_int(const char **pp, const char *end, int *out)",
        "{",
        "    const char *p = skip_ws(*pp, end);",
        "    if (p >= end) return 0;",
        "    int neg = 0;",
        "    if (*p == '-') { neg = 1; p++; }",
        "    if (p >= end || !isdigit((unsigned char)*p)) return 0;",
        "    long v = 0;",
        "    while (p < end && isdigit((unsigned char)*p)) {",
        "        v = v * 10 + (*p - '0');",
        "        p++;",
        "    }",
        "    *out = (int)(neg ? -v : v);",
        "    *pp = p;",
        "    return 1;",
        "}",
        "",
        "static int read_bool(const char **pp, const char *end, int *out)",
        "{",
        "    const char *p = skip_ws(*pp, end);",
        "    if ((end - p) >= 4 && !memcmp(p, \"true\", 4)) { *out = 1; *pp = p + 4; return 1; }",
        "    if ((end - p) >= 5 && !memcmp(p, \"false\", 5)) { *out = 0; *pp = p + 5; return 1; }",
        "    return 0;",
        "}",
        "",
        "static int expect(const char **pp, const char *end, char c)",
        "{",
        "    const char *p = skip_ws(*pp, end);",
        "    if (p >= end || *p != c) return 0;",
        "    *pp = p + 1;",
        "    return 1;",
        "}",
        "",
        "static const char *find_matching_brace(const char *p, const char *end)",
        "{",
        "    if (p >= end || *p != '{') return NULL;",
        "    int depth = 0;",
        "    while (p < end) {",
        "        char c = *p;",
        "        if (c == '\"') {",
        "            p++;",
        "            while (p < end && *p != '\"') {",
        "                if (*p == '\\\\' && p + 1 < end) p++;",
        "                p++;",
        "            }",
        "            if (p < end) p++;",
        "            continue;",
        "        }",
        "        if (c == '{') depth++;",
        "        else if (c == '}') { depth--; if (depth == 0) return p; }",
        "        p++;",
        "    }",
        "    return NULL;",
        "}",
        "",
        "static const char *skip_value(const char *p, const char *end)",
        "{",
        "    p = skip_ws(p, end);",
        "    if (p >= end) return NULL;",
        "    char c = *p;",
        "    if (c == '\"') {",
        "        p++;",
        "        while (p < end && *p != '\"') {",
        "            if (*p == '\\\\' && p + 1 < end) p++;",
        "            p++;",
        "        }",
        "        if (p < end) p++;",
        "        return p;",
        "    }",
        "    if (c == '{') return find_matching_brace(p, end) + 1;",
        "    if (c == '[') {",
        "        int depth = 0;",
        "        while (p < end) {",
        "            char ch = *p;",
        "            if (ch == '\"') {",
        "                p++;",
        "                while (p < end && *p != '\"') {",
        "                    if (*p == '\\\\' && p + 1 < end) p++;",
        "                    p++;",
        "                }",
        "                if (p < end) p++;",
        "                continue;",
        "            }",
        "            if (ch == '[') depth++;",
        "            else if (ch == ']') { depth--; if (depth == 0) return p + 1; }",
        "            p++;",
        "        }",
        "        return NULL;",
        "    }",
        "    if (c == 't') return p + 4;",
        "    if (c == 'f') return p + 5;",
        "    if (c == 'n') return p + 4;",
        "    while (p < end && (*p == '-' || isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+')) p++;",
        "    return p;",
        "}",
        "",
        "/* --- hex decode --- */",
        "static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)",
        "{",
        "    size_t hlen = strlen(hex);",
        "    if (hlen != outlen * 2) return -1;",
        "    for (size_t i = 0; i < outlen; i++) {",
        "        unsigned int byte;",
        "        if (sscanf(hex + i * 2, \"%2x\", &byte) != 1) return -1;",
        "        out[i] = (uint8_t)byte;",
        "    }",
        "    return 0;",
        "}",
        "",
    ]
    
    # Generate per-section parsers
    for section_name, section_schema in schema.get("properties", {}).items():
        if section_schema.get("type") != "object":
            continue
        
        lines.append(f"static void parse_{section_name}(const char *p, const char *end, bsb_config_t *cfg)")
        lines.append("{")
        lines.append(f"    bsb_{section_name}_t *s = &cfg->{section_name};")
        lines.append("    while (p < end) {")
        lines.append("        p = skip_ws(p, end);")
        lines.append("        if (p >= end || *p == '}') return;")
        lines.append("        char key[64];")
        lines.append("        if (!read_string(&p, end, key, sizeof(key))) return;")
        lines.append("        if (!expect(&p, end, ':')) return;")
        
        props = section_schema.get("properties", {})
        first = True
        for prop_name, prop_schema in props.items():
            field_name = c_field_name(prop_name)
            cond = "if" if first else "else if"
            first = False
            
            prop_type = prop_schema.get("type")
            if prop_type == "string":
                if "format" in prop_schema and prop_schema["format"] == "uri":
                    max_len = prop_schema.get("maxLength", 512)
                    lines.append(f"        {cond} (!strcmp(key, \"{prop_name}\"))")
                    lines.append(f"        {{")
                    lines.append(f"            if (!read_string(&p, end, s->{field_name}, sizeof(s->{field_name}))) return;")
                    lines.append(f"        }}")
                elif "maxLength" in prop_schema:
                    max_len = prop_schema["maxLength"]
                    lines.append(f"        {cond} (!strcmp(key, \"{prop_name}\"))")
                    lines.append(f"        {{")
                    lines.append(f"            if (!read_string(&p, end, s->{field_name}, sizeof(s->{field_name}))) return;")
                    lines.append(f"        }}")
            elif prop_type == "integer":
                lines.append(f"        {cond} (!strcmp(key, \"{prop_name}\"))")
                lines.append(f"        {{")
                lines.append(f"            if (!read_int(&p, end, &s->{field_name})) return;")
                lines.append(f"        }}")
            elif prop_type == "boolean":
                lines.append(f"        {cond} (!strcmp(key, \"{prop_name}\"))")
                lines.append(f"        {{")
                lines.append(f"            if (!read_bool(&p, end, &s->{field_name})) return;")
                lines.append(f"        }}")
            elif prop_type == "array":
                lines.append(f"        {cond} (!strcmp(key, \"{prop_name}\"))")
                lines.append(f"        {{")
                lines.append(f"            if (!expect(&p, end, '[')) return;")
                lines.append(f"            s->{field_name}_count = 0;")
                lines.append(f"            while (1) {{")
                lines.append(f"                p = skip_ws(p, end);")
                lines.append(f"                if (p >= end) return;")
                lines.append(f"                if (*p == ']') {{ p++; break; }}")
                lines.append(f"                if (s->{field_name}_count < {prop_schema.get('maxItems', 16)}) {{")
                lines.append(f"                    if (!read_string(&p, end, s->{field_name}[s->{field_name}_count], {prop_schema.get('items', {}).get('maxLength', 256) + 1})) return;")
                lines.append(f"                    s->{field_name}_count++;")
                lines.append(f"                }} else {{")
                lines.append(f"                    char tmp[{prop_schema.get('items', {}).get('maxLength', 256) + 1}];")
                lines.append(f"                    if (!read_string(&p, end, tmp, sizeof(tmp))) return;")
                lines.append(f"                }}")
                lines.append(f"                p = skip_ws(p, end);")
                lines.append(f"                if (p < end && *p == ',') p++;")
                lines.append(f"            }}")
                lines.append(f"        }}")
        
        lines.append("        } else {")
        lines.append("            p = skip_value(p, end); if (!p) return;")
        lines.append("        }")
        lines.append("        p = skip_ws(p, end);")
        lines.append("        if (p < end && *p == ',') p++;")
        lines.append("    }")
        lines.append("}")
        lines.append("")
    
    # Main load function
    lines.append("int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)")
    lines.append("{")
    lines.append("    if (err && errlen) err[0] = '\\0';")
    lines.append("    memset(cfg, 0, sizeof(*cfg));")
    lines.append("    snprintf(cfg->path, sizeof(cfg->path), \"%s\", path);")
    lines.append("")
    lines.append("    size_t n = 0;")
    lines.append("    char *buf = slurp(path, &n);")
    lines.append("    if (!buf)")
    lines.append("    {")
    lines.append("        if (err && errlen) snprintf(err, errlen, \"cannot open %s\", path);")
    lines.append("        return -1;")
    lines.append("    }")
    lines.append("    const char *p = buf;")
    lines.append("    const char *end = buf + n;")
    lines.append("")
    lines.append("    if (!expect(&p, end, '{'))")
    lines.append("    {")
    lines.append("        if (err && errlen) snprintf(err, errlen, \"expected { at top of file\");")
    lines.append("        free(buf); return -1;")
    lines.append("    }")
    lines.append("")
    lines.append("    while (1)")
    lines.append("    {")
    lines.append("        p = skip_ws(p, end);")
    lines.append("        if (p >= end) break;")
    lines.append("        if (*p == '}') break;")
    lines.append("        char key[64];")
    lines.append("        if (!read_string(&p, end, key, sizeof(key)))")
    lines.append("        {")
    lines.append("            if (err && errlen) snprintf(err, errlen, \"expected section key\");")
    lines.append("            free(buf); return -1;")
    lines.append("        }")
    lines.append("        if (!expect(&p, end, ':'))")
    lines.append("        {")
    lines.append("            if (err && errlen) snprintf(err, errlen, \"expected ':' after key %s\", key);")
    lines.append("            free(buf); return -1;")
    lines.append("        }")
    lines.append("        p = skip_ws(p, end);")
    lines.append("        if (p >= end || *p != '{')")
    lines.append("        {")
    lines.append("            if (err && errlen) snprintf(err, errlen, \"expected object after key %s\", key);")
    lines.append("            free(buf); return -1;")
    lines.append("        }")
    lines.append("        const char *close = find_matching_brace(p, end);")
    lines.append("        if (!close)")
    lines.append("        {")
    lines.append("            if (err && errlen) snprintf(err, errlen, \"unterminated object for %s\", key);")
    lines.append("            free(buf); return -1;")
    lines.append("        }")
    lines.append("        const char *section_start = p + 1;")
    lines.append("        const char *section_end = close;")
    
    for section_name in schema.get("properties", {}).keys():
        if schema["properties"][section_name].get("type") == "object":
            lines.append(f"        if (!strcmp(key, \"{section_name}\"))")
            lines.append(f"            parse_{section_name}(section_start, section_end, cfg);")
    
    lines.append("        p = close + 1;")
    lines.append("        p = skip_ws(p, end);")
    lines.append("        if (p < end && *p == ',') p++;")
    lines.append("    }")
    lines.append("")
    lines.append("    free(buf);")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    
    return "\n".join(lines)


def generate_python_loader(schema: Dict[str, Any]) -> str:
    """Generate Python config loader from schema."""
    lines = [
        "\"\"\"",
        "Auto-generated Python config loader from config/schema.json",
        "DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate",
        "\"\"\"",
        "import json",
        "import re",
        "from pathlib import Path",
        "from typing import Dict, Any",
        "",
    ]
    
    # Generate DEFAULTS dict
    lines.append("DEFAULTS = {")
    for section_name, section_schema in schema.get("properties", {}).items():
        if section_schema.get("type") != "object":
            continue
        lines.append(f'    "{section_name}": {{')
        for prop_name, prop_schema in section_schema.get("properties", {}).items():
            prop_type = prop_schema.get("type")
            default = prop_schema.get("default")
            if prop_type == "string":
                if default is not None:
                    lines.append(f'        "{prop_name}": "{default}",')
                elif prop_schema.get("format") == "uri":
                    lines.append(f'        "{prop_name}": "http://127.0.0.1:7070",')
                else:
                    lines.append(f'        "{prop_name}": "",')
            elif prop_type == "integer":
                lines.append(f'        "{prop_name}": {default if default is not None else 0},')
            elif prop_type == "boolean":
                lines.append(f'        "{prop_name}": {str(default).lower() if default is not None else "False"},')
            elif prop_type == "array":
                lines.append(f'        "{prop_name}": [],')
        lines.append("    },")
    lines.append("}")
    lines.append("")
    
    # Validation regexes
    lines.append("_HEX_RE = re.compile(r\"^[0-9a-fA-F]{64}$\")")
    lines.append("_FINGERPRINT_RE = re.compile(r\"^([0-9a-fA-F]{64})?$\")")
    lines.append("_MASTER_KEY_RE = re.compile(r\"^([0-9a-fA-F]{64})?$\")")
    lines.append("")
    
    # _derive_keys function
    lines.append("HKDF_SALT = b\"blacksandbeacon-v2\"")
    lines.append("HKDF_INFO_ENC = b\"enc\"")
    lines.append("HKDF_INFO_HMAC = b\"hmac\"")
    lines.append("")
    lines.append("def _derive_keys(master_key_bytes: bytes) -> tuple[bytes, bytes]:")
    lines.append("    \"\"\"Derive encryption and HMAC keys from master key using HKDF-SHA256.\"\"\"")
    lines.append("    from cryptography.hazmat.primitives import hashes")
    lines.append("    from cryptography.hazmat.primitives.kdf.hkdf import HKDF")
    lines.append("    from cryptography.hazmat.backends import default_backend")
    lines.append("    hkdf_enc = HKDF(")
    lines.append("        algorithm=hashes.SHA256(),")
    lines.append("        length=32,")
    lines.append("        salt=HKDF_SALT,")
    lines.append("        info=HKDF_INFO_ENC,")
    lines.append("        backend=default_backend()")
    lines.append("    )")
    lines.append("    hkdf_hmac = HKDF(")
    lines.append("        algorithm=hashes.SHA256(),")
    lines.append("        length=32,")
    lines.append("        salt=HKDF_SALT,")
    lines.append("        info=HKDF_INFO_HMAC,")
    lines.append("        backend=default_backend()")
    lines.append("    )")
    lines.append("    return hkdf_enc.derive(master_key_bytes), hkdf_hmac.derive(master_key_bytes)")
    lines.append("")
    
    # _deep_merge function
    lines.append("def _deep_merge(base, overlay):")
    lines.append("    \"\"\"Recursively merge overlay into base; overlay wins.\"\"\"")
    lines.append("    if isinstance(base, dict) and isinstance(overlay, dict):")
    lines.append("        out = dict(base)")
    lines.append("        for k, v in overlay.items():")
    lines.append("            out[k] = _deep_merge(base.get(k), v) if k in base else v")
    lines.append("        return out")
    lines.append("    return overlay if overlay is not None else base")
    lines.append("")
    
    # load_config function
    lines.append("def load_config(path):")
    lines.append("    \"\"\"Load and validate a BSB config file.")
    lines.append("")
    lines.append("    Raises ValueError on any schema violation. Returns a dict")
    lines.append("    matching DEFAULTS' structure plus derived keys.")
    lines.append("    \"\"\"")
    lines.append("    with open(path) as f:")
    lines.append("        raw = json.load(f)")
    lines.append("    merged = _deep_merge(DEFAULTS, raw)")
    lines.append("")
    
    # Validation for crypto section
    lines.append("    # Validate keys: either master_key_hex (new) or aes_key_hex (legacy) must be present")
    lines.append("    master_key = merged[\"crypto\"][\"master_key_hex\"]")
    lines.append("    aes_key = merged[\"crypto\"][\"aes_key_hex\"]")
    lines.append("")
    lines.append("    if master_key:")
    lines.append("        if not _MASTER_KEY_RE.match(master_key):")
    lines.append("            raise ValueError(")
    lines.append("                f\"crypto.master_key_hex must be 64 hex chars, got {master_key!r}\"")
    lines.append("            )")
    lines.append("        master_key_bytes = bytes.fromhex(master_key)")
    lines.append("    elif aes_key:")
    lines.append("        if not _HEX_RE.match(aes_key):")
    lines.append("            raise ValueError(")
    lines.append("                f\"crypto.aes_key_hex must be 64 hex chars, got {aes_key!r}\"")
    lines.append("            )")
    lines.append("        # Backward compat: derive from aes_key_hex")
    lines.append("        master_key_bytes = bytes.fromhex(aes_key)")
    lines.append("    else:")
    lines.append("        raise ValueError(\"crypto.master_key_hex or crypto.aes_key_hex required\")")
    lines.append("")
    lines.append("    # Derive encryption and HMAC keys")
    lines.append("    enc_key, hmac_key = _derive_keys(master_key_bytes)")
    lines.append("    merged[\"crypto\"][\"encryption_key\"] = enc_key")
    lines.append("    merged[\"crypto\"][\"hmac_key\"] = hmac_key")
    lines.append("")
    
    # Validate fingerprint
    lines.append("    # Validate certificate fingerprint (64 hex chars or empty).")
    lines.append("    fp = merged[\"network\"][\"cert_fingerprint_sha256\"]")
    lines.append("    if not _FINGERPRINT_RE.match(fp):")
    lines.append("        raise ValueError(")
    lines.append("            f\"network.cert_fingerprint_sha256 must be 64 hex chars or empty, got {fp!r}\"")
    lines.append("        )")
    lines.append("")
    
    # Validate replay_window_seconds
    lines.append("    # Validate replay_window_seconds (must be positive).")
    lines.append("    replay_window = merged[\"crypto\"][\"replay_window_seconds\"]")
    lines.append("    if not isinstance(replay_window, int) or replay_window <= 0:")
    lines.append("        raise ValueError(")
    lines.append("            f\"crypto.replay_window_seconds must be a positive integer, got {replay_window!r}\"")
    lines.append("        )")
    lines.append("")
    
    # Clamp values
    lines.append("    # Clamp values that must be positive.")
    lines.append("    merged[\"timing\"][\"sleep_seconds\"] = max(1, int(merged[\"timing\"][\"sleep_seconds\"]))")
    lines.append("    merged[\"timing\"][\"jitter_percent\"] = max(0, int(merged[\"timing\"][\"jitter_percent\"]))")
    lines.append("    return merged")
    
    return "\n".join(lines)


def main():
    schema = load_schema()
    
    # Generate C header
    c_header = generate_c_structs(schema)
    OUT_H.write_text(c_header)
    print(f"Generated {OUT_H}")
    
    # Generate C parser
    c_parser = generate_c_parser(schema)
    OUT_C.write_text(c_parser)
    print(f"Generated {OUT_C}")
    
    # Generate Python loader
    py_loader = generate_python_loader(schema)
    OUT_PY.write_text(py_loader)
    print(f"Generated {OUT_PY}")
    
    print("All parsers generated successfully!")


if __name__ == "__main__":
    main()