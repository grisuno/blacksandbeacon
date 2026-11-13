# legacy

*Community 0 | 20 files | cohesion 0.89*

## Definition

This community groups 20 file(s) rooted at `legacy` with dominant language c (cohesion 0.89). Central symbols: `AES256`, `AES_BLOCKLEN`, `AES_CBC_decrypt_buffer`, `AES_CBC_encrypt_buffer`, `AES_CTR_xcrypt_buffer`, `AES_ECB_decrypt`, `AES_ECB_encrypt`, `AES_KEYLEN`. Core file: `cJSON.c` (125 symbols). Documented purpose: tiny-AES-c (https://github.com/kokke/tiny-AES-c).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `aes.c` | c | utility | 43 | yes |
| `aes.h` | h | utility | 21 | yes |
| `beacon.h` | h | utility | 13 | yes |
| `beacons/v1/beacon.c` | c | utility | 4 | no |
| `beacons/v2/beacon.c` | c | utility | 11 | no |
| `beacons/v3/beacon.c` | c | utility | 7 | no |
| `bof.c` | c | utility | 1 | yes |
| `cJSON.c` | c | utility | 125 | no |
| `cJSON.h` | h | utility | 40 | no |
| `include/beacon_common.c` | c | utility | 36 | no |
| `include/beacon_common.h` | h | utility | 58 | no |
| `include/cJSON.c` | c | utility | 125 | no |
| `include/cJSON.h` | h | utility | 40 | no |
| `legacy/beacon3.c` | c | utility | 28 | no |
| `legacy/beacon5.c` | c | utility | 44 | no |
| `legacy/beacon6.c` | c | utility | 32 | no |
| `legacy/beacon_p2p.c` | c | utility | 49 | no |
| `legacy/gopher_beacon.c` | c | utility | 28 | no |
| `legacy/v1_gopher_beacon.c` | c | utility | 28 | no |
| `tests/test_iv_generation_c.c` | c | testing | 7 | no |

## Key Symbols

- `Nb` (macro, `aes.c:5`) `#define Nb`
- `KEYLEN_256` (macro, `aes.c:7`) `#define KEYLEN_256`
- `RKLENGTH` (macro, `aes.c:8`) `#define RKLENGTH`
- `BLOCKLEN` (macro, `aes.c:9`) `#define BLOCKLEN`
- `getSBoxValue` (function, `aes.c:11`) `static uint8_t getSBoxValue(uint8_t num)`
- `getSBoxInvert` (function, `aes.c:35`) `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (function, `aes.c:59`) `static uint8_t Td0(int x)`
- `Td1` (function, `aes.c:63`) `static uint8_t Td1(int x)`
- `Td2` (function, `aes.c:67`) `static uint8_t Td2(int x)`
- `Td3` (function, `aes.c:71`) `static uint8_t Td3(int x)`
- `Td4` (function, `aes.c:75`) `static uint8_t Td4(int x)`
- `Nb` (macro, `aes.c:84`) `#define Nb`
- `Nk` (macro, `aes.c:87`) `#define Nk`
- `Nr` (macro, `aes.c:88`) `#define Nr`
- `Nk` (macro, `aes.c:90`) `#define Nk`
- `Nr` (macro, `aes.c:91`) `#define Nr`
- `Nk` (macro, `aes.c:93`) `#define Nk`
- `Nr` (macro, `aes.c:94`) `#define Nr`
- `MULTIPLY_AS_A_FUNCTION` (macro, `aes.c:101`) `#define MULTIPLY_AS_A_FUNCTION`
- `getSBoxValue` (macro, `aes.c:177`) `#define getSBoxValue(num)`
- `KeyExpansion` (function, `aes.c:181`) `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` - This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the sta
- `AES_init_ctx` (function, `aes.c:254`) `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)`
- `AES_init_ctx_iv` (function, `aes.c:259`) `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` - if (defined(CBC) && (CBC == 1)) \|\| (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function, `aes.c:264`) `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)`
- `AddRoundKey` (function, `aes.c:272`) `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` - This function adds the round key to state. The round key is added to the state by an XOR function.
- `SubBytes` (function, `aes.c:286`) `static void SubBytes(state_t *state)` - The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function, `aes.c:301`) `static void ShiftRows(state_t *state)` - The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with differen
- `xtime` (function, `aes.c:329`) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function, `aes.c:335`) `static void MixColumns(state_t *state)` - MixColumns function mixes the columns of the state matrix
- `Multiply` (function, `aes.c:363`) `static uint8_t Multiply(uint8_t x, uint8_t y)` - Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 10
- Cross-boundary resolved imports (EXTRACTED): 2

## Connections

- [EXTRACTED] depends_on community 0 <-> 3 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.c imports include/aes.h.
- [EXTRACTED] depends_on community 0 <-> 4 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.h imports include/config.h.
- [INFERRED] shares_context community 0 <-> 2 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 2 (bof/include).
- [INFERRED] shares_context community 0 <-> 5 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 5 (mutants/src: async_i_o_for_beacon).
- [INFERRED] shares_context community 0 <-> 6 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 6 (mutants/src: beacon_common.c_extraction).
- [INFERRED] shares_context community 0 <-> 7 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 7 (mutants/src: beacon_heartbeat___health_endpoint).
- [INFERRED] shares_context community 0 <-> 8 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 8 (mutants/src: bof_api_versioning).
- [INFERRED] shares_context community 0 <-> 9 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 9 (mutants/src: bof_path_traversal_hardening).
- [INFERRED] shares_context community 0 <-> 10 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 10 (mutants/src: bof_streaming_(large_outputs)).
- [INFERRED] shares_context community 0 <-> 11 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 11 (mutants/src: c2_rest_api).

## Risks

- [dataflow UNCHECKED_ALLOC] `beacons/v1/beacon.c:78` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v1/beacon.c:111` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v2/beacon.c:123` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v2/beacon.c:156` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v3/beacon.c:116` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v3/beacon.c:149` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow DEAD_STORE] `cJSON.c:1676` `print_array` `output_pointer`: `output_pointer` assigned at line 1676 but never read afterwards.
- [dataflow DEAD_STORE] `cJSON.c:1908` `print_object` `output_pointer`: `output_pointer` assigned at line 1908 but never read afterwards.
- [dataflow DEAD_STORE] `include/beacon_common.c:375` `https_request` `chunk`: `chunk` assigned at line 375 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `include/beacon_common.c:461` `base64_encode` `buf`: Result of allocator stored in `buf` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `include/beacon_common.c:829` `get_local_ips` `result`: Result of allocator stored in `result` is never checked against NULL.
- [dataflow DEAD_STORE] `include/cJSON.c:1676` `print_array` `output_pointer`: `output_pointer` assigned at line 1676 but never read afterwards.
- [dataflow DEAD_STORE] `include/cJSON.c:1908` `print_object` `output_pointer`: `output_pointer` assigned at line 1908 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `legacy/beacon3.c:447` `base64_encode` `buf`: Result of allocator stored in `buf` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `legacy/beacon3.c:485` `aes256_cfb_encrypt` `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.

## Open Questions

- Why do 16 file(s) lack file-level docs (e.g. `beacons/v1/beacon.c`)? What purpose do they serve?
- What would break if the most connected file in legacy changed?
- Should legacy be split, given cohesion 0.89?

## Sources

- `aes.c`
- `aes.h`
- `beacon.h`
- `beacons/v1/beacon.c`
- `beacons/v2/beacon.c`
- `beacons/v3/beacon.c`
- `bof.c`
- `cJSON.c`
- `cJSON.h`
- `include/beacon_common.c`
- `include/beacon_common.h`
- `include/cJSON.c`
- `include/cJSON.h`
- `legacy/beacon3.c`
- `legacy/beacon5.c`
- `legacy/beacon6.c`
- `legacy/beacon_p2p.c`
- `legacy/gopher_beacon.c`
- `legacy/v1_gopher_beacon.c`
- `tests/test_iv_generation_c.c`
