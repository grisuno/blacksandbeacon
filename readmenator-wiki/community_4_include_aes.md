# include: aes

*Community 4 | 3 files | cohesion 0.40*

## Definition

This community groups 3 file(s) rooted at `include` with dominant language c (cohesion 0.40). Central symbols: `AES256`, `AES_BLOCKLEN`, `AES_CBC_decrypt_buffer`, `AES_CBC_encrypt_buffer`, `AES_CTR_xcrypt_buffer`, `AES_ECB_decrypt`, `AES_ECB_encrypt`, `AES_KEYLEN`. Core file: `include/aes.c` (43 symbols). Documented purpose: tiny-AES-c (https://github.com/kokke/tiny-AES-c).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/aes.c` | c | utility | 43 | yes |
| `include/aes.h` | h | utility | 21 | yes |
| `include/aes_cfb.c` | c | utility | 2 | no |

## Key Symbols

- `Nb` (macro, `include/aes.c:5`) `#define Nb`
- `KEYLEN_256` (macro, `include/aes.c:9`) `#define KEYLEN_256`
- `RKLENGTH` (macro, `include/aes.c:10`) `#define RKLENGTH`
- `BLOCKLEN` (macro, `include/aes.c:11`) `#define BLOCKLEN`
- `__attribute__` (function, `include/aes.c:13`) `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)`
- `__attribute__` (function, `include/aes.c:35`) `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)`
- `__attribute__` (function, `include/aes.c:57`) `static __attribute__((unused)) uint8_t Td0(int x)`
- `__attribute__` (function, `include/aes.c:58`) `static __attribute__((unused)) uint8_t Td1(int x)`
- `__attribute__` (function, `include/aes.c:59`) `static __attribute__((unused)) uint8_t Td2(int x)`
- `__attribute__` (function, `include/aes.c:60`) `static __attribute__((unused)) uint8_t Td3(int x)`
- `__attribute__` (function, `include/aes.c:61`) `static __attribute__((unused)) uint8_t Td4(int x)`
- `Nb` (macro, `include/aes.c:67`) `#define Nb`
- `Nk` (macro, `include/aes.c:70`) `#define Nk`
- `Nr` (macro, `include/aes.c:71`) `#define Nr`
- `Nk` (macro, `include/aes.c:73`) `#define Nk`
- `Nr` (macro, `include/aes.c:74`) `#define Nr`
- `Nk` (macro, `include/aes.c:76`) `#define Nk`
- `Nr` (macro, `include/aes.c:77`) `#define Nr`
- `MULTIPLY_AS_A_FUNCTION` (macro, `include/aes.c:84`) `#define MULTIPLY_AS_A_FUNCTION`
- `getSBoxValue` (macro, `include/aes.c:163`) `#define getSBoxValue(num)`
- `KeyExpansion` (function, `include/aes.c:166`) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the sta
- `AES_init_ctx` (function, `include/aes.c:239`) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (function, `include/aes.c:244`) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - if (defined(CBC) && (CBC == 1)) \|\| (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function, `include/aes.c:249`) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (function, `include/aes.c:257`) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - This function adds the round key to state. The round key is added to the state by an XOR function.
- `SubBytes` (function, `include/aes.c:271`) `static void SubBytes(state_t* state)` - The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function, `include/aes.c:286`) `static void ShiftRows(state_t* state)` - The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with differen
- `xtime` (function, `include/aes.c:314`) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function, `include/aes.c:320`) `static void MixColumns(state_t* state)` - MixColumns function mixes the columns of the state matrix
- `Multiply` (function, `include/aes.c:340`) `static uint8_t Multiply(uint8_t x, uint8_t y)` - Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 1

## Connections

- [EXTRACTED] depends_on community 1 <-> 4 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.c imports include/aes.h.
- [INFERRED] duplicates community 0 <-> 4 (strength 0.54): Inferred duplicated scope: communities 0 and 4 share 42 symbols (Jaccard 0.36), e.g. `AES256`, `AES_BLOCKLEN`, `AES_CBC_decrypt_buffer`, `AES_CBC_encrypt_buffer`, `AES_CTR_xcrypt_buffer`, `AES_ECB_decrypt`. Candidate for consolidation.
- [INFERRED] shares_context community 2 <-> 4 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 2 (bof/include) and community 4 (include: aes).
- [INFERRED] shares_context community 4 <-> 5 (strength 0.5): Inferred shared context (language c) with no import path between community 4 (include: aes) and community 5 (include: config).
- [INFERRED] shares_context community 4 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 4 (include: aes) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 4 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 4 (include: aes) and community 7 (orphans).

## Risks

- [dataflow UNCHECKED_ALLOC] `include/aes_cfb.c:24` `aes256_cfb_encrypt` `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `include/aes_cfb.c:52` `aes256_cfb_decrypt` `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/aes_cfb.c`)? What purpose do they serve?
- What would break if the most connected file in include: aes changed?
- Should include: aes be split, given cohesion 0.40?

## Sources

- `include/aes.c`
- `include/aes.h`
- `include/aes_cfb.c`
