# include: config

*Community 5 | 3 files | cohesion 0.67*

## Definition

This community groups 3 file(s) rooted at `include` with dominant language c (cohesion 0.67). Central symbols: `BSB_AES_KEY_BYTES`, `BSB_AES_KEY_HEX_LEN`, `BSB_CONFIG_H`, `BSB_CONFIG_PATH_DEFAULT`, `BSB_CONFIG_PATH_ENV`, `BSB_MAX_CLIENT_ID`, `BSB_MAX_URI`, `BSB_MAX_URL`. Core file: `include/config.h` (21 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/config.c` | c | infrastructure | 20 | no |
| `include/config.h` | h | infrastructure | 21 | no |
| `tests/config_harness.c` | c | infrastructure | 1 | no |

## Key Symbols

- `_POSIX_C_SOURCE` (macro, `include/config.c:13`) `#define _POSIX_C_SOURCE`
- `slurp` (function, `include/config.c:24`) `static char *slurp(const char *path, size_t *out_len)` - declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #def
- `skip_ws` (function, `include/config.c:41`) `static const char *skip_ws(const char *p, const char *end)` - fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL
- `read_string` (function, `include/config.c:49`) `static int read_string(const char **pp, const char *end, char *out, size_t outsz` - Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string i
- `read_int` (function, `include/config.c:76`) `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function, `include/config.c:92`) `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function, `include/config.c:100`) `static int expect(const char **pp, const char *end, char c)` - } out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *e
- `find_matching_brace` (function, `include/config.c:109`) `static const char *find_matching_brace(const char *p, const char *end)` - Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and e
- `skip_value` (function, `include/config.c:132`) `static const char *skip_value(const char *p, const char *end)` - Skip the next value at p (string, number, bool, null, object, array). * Returns the position just pa
- `hex_to_bytes` (function, `include/config.c:174`) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` - else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') r
- `parse_c2` (function, `include/config.c:186`) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` - /* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t
- `parse_crypto` (function, `include/config.c:209`) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function, `include/config.c:230`) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function, `include/config.c:253`) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function, `include/config.c:289`) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function, `include/config.c:308`) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function, `include/config.c:328`) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errle` - if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end, &cfg->
- `binary_dir` (function, `include/config.c:420`) `static const char *binary_dir(char *out, size_t outsz)` - Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms
- `bsb_config_load_default` (function, `include/config.c:438`) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- `bsb_config_sleep_seconds` (function, `include/config.c:466`) `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
- `BSB_CONFIG_H` (macro, `include/config.h:14`) `#define BSB_CONFIG_H`
- `BSB_CONFIG_PATH_DEFAULT` (macro, `include/config.h:19`) `#define BSB_CONFIG_PATH_DEFAULT`
- `BSB_CONFIG_PATH_ENV` (macro, `include/config.h:20`) `#define BSB_CONFIG_PATH_ENV`
- `BSB_MAX_URL` (macro, `include/config.h:21`) `#define BSB_MAX_URL`
- `BSB_MAX_URI` (macro, `include/config.h:22`) `#define BSB_MAX_URI`
- `BSB_MAX_CLIENT_ID` (macro, `include/config.h:23`) `#define BSB_MAX_CLIENT_ID`
- `BSB_AES_KEY_HEX_LEN` (macro, `include/config.h:24`) `#define BSB_AES_KEY_HEX_LEN`
- `BSB_AES_KEY_BYTES` (macro, `include/config.h:25`) `#define BSB_AES_KEY_BYTES`
- `BSB_MAX_USER_AGENTS` (macro, `include/config.h:26`) `#define BSB_MAX_USER_AGENTS`
- `BSB_USER_AGENT_LEN` (macro, `include/config.h:27`) `#define BSB_USER_AGENT_LEN`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 1

## Connections

- [EXTRACTED] depends_on community 1 <-> 5 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.h imports include/config.h.
- [INFERRED] shares_context community 2 <-> 5 (strength 0.5): Inferred shared context (language c) with no import path between community 2 (bof/include) and community 5 (include: config).
- [INFERRED] shares_context community 3 <-> 5 (strength 0.5): Inferred shared context (layer infrastructure) with no import path between community 3 (include: server) and community 5 (include: config).
- [INFERRED] shares_context community 4 <-> 5 (strength 0.5): Inferred shared context (language c) with no import path between community 4 (include: aes) and community 5 (include: config).
- [INFERRED] shares_context community 5 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 5 (include: config) and community 6 (include: aes_cfb).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 3 file(s) lack file-level docs (e.g. `include/config.c`)? What purpose do they serve?
- What would break if the most connected file in include: config changed?
- Should include: config be split, given cohesion 0.67?

## Sources

- `include/config.c`
- `include/config.h`
- `tests/config_harness.c`
