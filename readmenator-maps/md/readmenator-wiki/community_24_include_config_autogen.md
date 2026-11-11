# include: config_autogen

*Community 24 | 2 files | cohesion 1.00*

## Definition

This community groups 2 file(s) rooted at `include` with dominant language c (cohesion 1.00). Central symbols: `BSB_CONFIG_AUTOGEN_H`, `_POSIX_C_SOURCE`, `bsb_backoff_t`, `bsb_bof_t`, `bsb_c2_t`, `bsb_config_load`, `bsb_config_load_default`, `bsb_config_sleep_seconds`. Core file: `include/config_autogen.c` (18 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/config_autogen.c` | c | infrastructure | 18 | no |
| `include/config_autogen.h` | h | infrastructure | 12 | no |

## Key Symbols

- `_POSIX_C_SOURCE` (macro, `include/config_autogen.c:5`) `#define _POSIX_C_SOURCE`
- `slurp` (function, `include/config_autogen.c:16`) `static char *slurp(const char *path, size_t *out_len)` - Auto-generated C config parser from config/schema.json DO NOT EDIT MANUALLY - run config/generate_pa
- `skip_ws` (function, `include/config_autogen.c:34`) `static const char *skip_ws(const char *p, const char *end)` - fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL
- `read_string` (function, `include/config_autogen.c:40`) `static int read_string(const char **pp, const char *end, char *out, size_t outsz`
- `read_int` (function, `include/config_autogen.c:68`) `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function, `include/config_autogen.c:85`) `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function, `include/config_autogen.c:93`) `static int expect(const char **pp, const char *end, char c)`
- `find_matching_brace` (function, `include/config_autogen.c:101`) `static const char *find_matching_brace(const char *p, const char *end)`
- `skip_value` (function, `include/config_autogen.c:123`) `static const char *skip_value(const char *p, const char *end)`
- `hex_to_bytes` (function, `include/config_autogen.c:165`) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` - if (ch == '[') depth++; else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return
- `parse_c2` (function, `include/config_autogen.c:177`) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_crypto` (function, `include/config_autogen.c:206`) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function, `include/config_autogen.c:227`) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function, `include/config_autogen.c:260`) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function, `include/config_autogen.c:300`) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function, `include/config_autogen.c:325`) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_server` (function, `include/config_autogen.c:350`) `static void parse_server(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function, `include/config_autogen.c:375`) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errle`
- `BSB_CONFIG_AUTOGEN_H` (macro, `include/config_autogen.h:6`) `#define BSB_CONFIG_AUTOGEN_H`
- `bsb_c2_t` (struct, `include/config_autogen.h:11`)
- `bsb_crypto_t` (struct, `include/config_autogen.h:21`)
- `bsb_timing_t` (struct, `include/config_autogen.h:28`)
- `bsb_network_t` (struct, `include/config_autogen.h:35`)
- `bsb_bof_t` (struct, `include/config_autogen.h:42`)
- `bsb_backoff_t` (struct, `include/config_autogen.h:47`)
- `bsb_server_t` (struct, `include/config_autogen.h:52`)
- `bsb_config_t` (struct, `include/config_autogen.h:57`)
- `bsb_config_load` (function, `include/config_autogen.h:69`) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errle` - } bsb_server_t; typedef struct { bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_
- `bsb_config_load_default` (function, `include/config_autogen.h:72`) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` - bsb_c2_t c2; bsb_crypto_t crypto; bsb_timing_t timing; bsb_network_t network; bsb_bof_t bof; bsb_bac
- `bsb_config_sleep_seconds` (function, `include/config_autogen.h:75`) `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` - bsb_network_t network; bsb_bof_t bof; bsb_backoff_t backoff; bsb_server_t server; char path[512]; }

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 1
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] duplicates community 4 <-> 24 (strength 0.56): Inferred duplicated scope: communities 4 and 24 share 25 symbols (Jaccard 0.40), e.g. `_POSIX_C_SOURCE`, `bsb_bof_t`, `bsb_c2_t`, `bsb_config_load`, `bsb_config_load_default`, `bsb_config_sleep_seconds`. Candidate for consolidation.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 2 file(s) lack file-level docs (e.g. `include/config_autogen.c`)? What purpose do they serve?
- What would break if the most connected file in include: config_autogen changed?
- Should include: config_autogen be split, given cohesion 1.00?

## Sources

- `include/config_autogen.c`
- `include/config_autogen.h`
