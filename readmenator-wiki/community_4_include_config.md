# include: config

*Community 4 | 6 files | cohesion 0.83*

## Definition

This community groups 6 file(s) rooted at `tests` with dominant language c (cohesion 0.83). Central symbols: `BSB_AES_KEY_BYTES`, `BSB_AES_KEY_HEX_LEN`, `BSB_CONFIG_H`, `BSB_CONFIG_PATH_DEFAULT`, `BSB_CONFIG_PATH_ENV`, `BSB_MAX_CLIENT_ID`, `BSB_MAX_URI`, `BSB_MAX_URL`. Core file: `include/config.c` (28 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/config.c` | c | infrastructure | 28 | no |
| `include/config.h` | h | infrastructure | 21 | no |
| `mutants/tests/config_harness.c` | c | infrastructure | 1 | no |
| `tests/config_harness.c` | c | infrastructure | 1 | no |
| `tests/test_certificate_pinning_c.c` | c | testing | 5 | no |
| `tests/test_hkdf_key_derivation_c.c` | c | testing | 11 | no |

## Key Symbols

- `_POSIX_C_SOURCE` (macro, `include/config.c:13`) `#define _POSIX_C_SOURCE`
- `slurp` (function, `include/config.c:24`) `static char *slurp(const char *path, size_t *out_len)` - declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #def
- `skip_ws` (function, `include/config.c:56`) `static const char *skip_ws(const char *p, const char *end)` - } if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; } buf[n] = '\0'
- `read_string` (function, `include/config.c:66`) `static int read_string(const char **pp, const char *end, char *out, size_t outsz` - Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string i
- `read_int` (function, `include/config.c:113`) `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (function, `include/config.c:137`) `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (function, `include/config.c:156`) `static int expect(const char **pp, const char *end, char c)` - out = 1; pp = p + 4; return 1; } if ((end - p) >= 5 && !memcmp(p, "false", 5)) { out = 0; pp = p + 5
- `find_matching_brace` (function, `include/config.c:167`) `static const char *find_matching_brace(const char *p, const char *end)` - Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and e
- `skip_value` (function, `include/config.c:203`) `static const char *skip_value(const char *p, const char *end)` - Skip the next value at p (string, number, bool, null, object, array). * Returns the position just pa
- `hex_to_bytes` (function, `include/config.c:269`) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` - if (c == 't') return p + 4; if (c == 'f') return p + 5; if (c == 'n') return p + 4; /* number while
- `HKDF_SALT` (macro, `include/config.c:288`) `#define HKDF_SALT`
- `HKDF_INFO_ENC` (macro, `include/config.c:289`) `#define HKDF_INFO_ENC`
- `HKDF_INFO_HMAC` (macro, `include/config.c:290`) `#define HKDF_INFO_HMAC`
- `hmac_sha256` (function, `include/config.c:292`) `static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,`
- `hkdf_extract` (function, `include/config.c:299`) `static void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ik`
- `hkdf_expand` (function, `include/config.c:305`) `static void hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info,`
- `hkdf_sha256` (function, `include/config.c:337`) `static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt,`
- `derive_keys_from_master` (function, `include/config.c:345`) `static void derive_keys_from_master(bsb_config_t *cfg)`
- `parse_c2` (function, `include/config.c:375`) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` - } uint8_t salt[] = HKDF_SALT; uint8_t info_enc[] = HKDF_INFO_ENC; uint8_t info_hmac[] = HKDF_INFO_HM
- `parse_crypto` (function, `include/config.c:419`) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (function, `include/config.c:474`) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (function, `include/config.c:518`) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (function, `include/config.c:586`) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (function, `include/config.c:620`) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (function, `include/config.c:655`) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errle` - } else { p = skip_value(p, end); if (!p) return; } p = skip_ws(p, end); if (p < end && *p == ',') p+
- `binary_dir` (function, `include/config.c:798`) `static const char *binary_dir(char *out, size_t outsz)` - Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms
- `bsb_config_load_default` (function, `include/config.c:820`) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- `bsb_config_sleep_seconds` (function, `include/config.c:853`) `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
- `BSB_CONFIG_H` (macro, `include/config.h:14`) `#define BSB_CONFIG_H`
- `BSB_CONFIG_PATH_DEFAULT` (macro, `include/config.h:19`) `#define BSB_CONFIG_PATH_DEFAULT`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 5
- Cross-boundary resolved imports (EXTRACTED): 1

## Connections

- [EXTRACTED] depends_on community 0 <-> 4 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.h imports include/config.h.
- [INFERRED] duplicates community 4 <-> 24 (strength 0.56): Inferred duplicated scope: communities 4 and 24 share 25 symbols (Jaccard 0.40), e.g. `_POSIX_C_SOURCE`, `bsb_bof_t`, `bsb_c2_t`, `bsb_config_load`, `bsb_config_load_default`, `bsb_config_sleep_seconds`. Candidate for consolidation.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 6 file(s) lack file-level docs (e.g. `include/config.c`)? What purpose do they serve?
- What would break if the most connected file in include: config changed?
- Should include: config be split, given cohesion 0.83?

## Sources

- `include/config.c`
- `include/config.h`
- `mutants/tests/config_harness.c`
- `tests/config_harness.c`
- `tests/test_certificate_pinning_c.c`
- `tests/test_hkdf_key_derivation_c.c`
