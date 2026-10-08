# include: aes_cfb

*Community 6 | 2 files | cohesion 1.00*

## Definition

This community groups 2 file(s) rooted at `include` with dominant language h (cohesion 1.00). Central symbols: `BSB_AES_CFB_H`, `aes256_cfb_decrypt`, `aes256_cfb_encrypt`, `hex_to_bytes`, `main`. Core file: `include/aes_cfb.h` (3 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/aes_cfb.h` | h | utility | 3 | no |
| `tests/crypto_harness.c` | c | testing | 2 | no |

## Key Symbols

- `BSB_AES_CFB_H` (macro, `include/aes_cfb.h:5`) `#define BSB_AES_CFB_H`
- `aes256_cfb_encrypt` (function, `include/aes_cfb.h:9`) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char*`
- `aes256_cfb_decrypt` (function, `include/aes_cfb.h:11`) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char*`
- `hex_to_bytes` (function, `tests/crypto_harness.c:12`) `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)`
- `main` (function, `tests/crypto_harness.c:23`) `int main(int argc, char **argv)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 1
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (root) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 1 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 1 (include: cJSON) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 2 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 2 (bof/include) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 4 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 4 (include: aes) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 5 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 5 (include: config) and community 6 (include: aes_cfb).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 2 file(s) lack file-level docs (e.g. `include/aes_cfb.h`)? What purpose do they serve?
- What would break if the most connected file in include: aes_cfb changed?
- Should include: aes_cfb be split, given cohesion 1.00?

## Sources

- `include/aes_cfb.h`
- `tests/crypto_harness.c`
