# include: cJSON

*Community 1 | 9 files | cohesion 0.57*

## Definition

This community groups 9 file(s) rooted at `include` with dominant language c (cohesion 0.57). Central symbols: `BEACON_COMMON_H`, `BSB_OUTPUT_BUFFER_DEFAULT`, `BSB_OUTPUT_TRUNCATION_MARKER`, `BeaconOutput`, `BeaconPrintf`, `CJSON_CDECL`, `CJSON_CIRCULAR_LIMIT`, `CJSON_EXPORT_SYMBOLS`. Core file: `cJSON.c` (125 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `beacons/v1/beacon.c` | c | utility | 4 | no |
| `beacons/v2/beacon.c` | c | utility | 11 | no |
| `beacons/v3/beacon.c` | c | utility | 7 | no |
| `cJSON.c` | c | utility | 125 | no |
| `cJSON.h` | h | utility | 37 | no |
| `include/beacon_common.c` | c | utility | 27 | no |
| `include/beacon_common.h` | h | utility | 57 | no |
| `include/cJSON.c` | c | utility | 125 | no |
| `include/cJSON.h` | h | utility | 37 | no |

## Key Symbols

- `_GNU_SOURCE` (macro, `beacons/v1/beacon.c:13`) `#define _GNU_SOURCE`
- `report_result` (function, `beacons/v1/beacon.c:24`) `static void report_result(const bsb_config_t *cfg,                            co`
- `execute_command` (function, `beacons/v1/beacon.c:97`) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function, `beacons/v1/beacon.c:146`) `int main(void)`
- `_GNU_SOURCE` (macro, `beacons/v2/beacon.c:12`) `#define _GNU_SOURCE`
- `MAX_PEERS` (macro, `beacons/v2/beacon.c:27`) `#define MAX_PEERS`
- `DISCOVERY_PORT` (macro, `beacons/v2/beacon.c:28`) `#define DISCOVERY_PORT`
- `DISCOVERY_INTERVAL` (macro, `beacons/v2/beacon.c:29`) `#define DISCOVERY_INTERVAL`
- `MAX_TTL` (macro, `beacons/v2/beacon.c:30`) `#define MAX_TTL`
- `MESH_MSG_SIZE` (macro, `beacons/v2/beacon.c:31`) `#define MESH_MSG_SIZE`
- `peer_t` (struct, `beacons/v2/beacon.c:33`)
- `mesh_msg_t` (struct, `beacons/v2/beacon.c:40`)
- `report_result` (function, `beacons/v2/beacon.c:66`) `static void report_result(const bsb_config_t *cfg,                            co`
- `execute_command` (function, `beacons/v2/beacon.c:139`) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function, `beacons/v2/beacon.c:188`) `int main(void)`
- `infrastructure` (function, `beacons/v3/beacon.c:8`) `*  * All shared infrastructure (HTTP client, crypto, BOF loader)  * lives in bea`
- `_GNU_SOURCE` (macro, `beacons/v3/beacon.c:12`) `#define _GNU_SOURCE`
- `compute_primes` (function, `beacons/v3/beacon.c:36`) `static int compute_primes(int count)`
- `evasive_sleep` (function, `beacons/v3/beacon.c:46`) `static void evasive_sleep(int seconds)`
- `report_result` (function, `beacons/v3/beacon.c:52`) `static void report_result(const bsb_config_t *cfg,                            co`
- `execute_command` (function, `beacons/v3/beacon.c:125`) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (function, `beacons/v3/beacon.c:174`) `int main(void)`
- `_CRT_SECURE_NO_DEPRECATE` (macro, `cJSON.c:28`) `#define _CRT_SECURE_NO_DEPRECATE`
- `true` (macro, `cJSON.c:65`) `#define true`
- `false` (macro, `cJSON.c:70`) `#define false`
- `isinf` (macro, `cJSON.c:74`) `#define isinf(d)`
- `isnan` (macro, `cJSON.c:77`) `#define isnan(d)`
- `NAN` (macro, `cJSON.c:82`) `#define NAN`
- `NAN` (macro, `cJSON.c:84`) `#define NAN`
- `error` (struct, `cJSON.c:88`)

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 7
- Cross-boundary resolved imports (EXTRACTED): 7

## Connections

- [EXTRACTED] depends_on community 0 <-> 1 (strength 0.9): Extracted import edge crosses communities: beacon3.c imports cJSON.h.
- [EXTRACTED] depends_on community 1 <-> 4 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.c imports include/aes.h.
- [EXTRACTED] depends_on community 1 <-> 5 (strength 0.9): Extracted import edge crosses communities: include/beacon_common.h imports include/config.h.
- [INFERRED] shares_context community 1 <-> 2 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 1 (include: cJSON) and community 2 (bof/include).
- [INFERRED] shares_context community 1 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 1 (include: cJSON) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 1 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 1 (include: cJSON) and community 7 (orphans).

## Risks

- [dataflow UNCHECKED_ALLOC] `beacons/v1/beacon.c:66` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v1/beacon.c:102` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v2/beacon.c:108` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v2/beacon.c:144` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v3/beacon.c:94` `report_result` `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `beacons/v3/beacon.c:130` `execute_command` `payload`: Result of allocator stored in `payload` is never checked against NULL.
- [dataflow DEAD_STORE] `cJSON.c:1654` `print_array` `output_pointer`: `output_pointer` assigned at line 1654 but never read afterwards.
- [dataflow DEAD_STORE] `cJSON.c:1887` `print_object` `output_pointer`: `output_pointer` assigned at line 1887 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `include/beacon_common.c:300` `base64_encode` `buf`: Result of allocator stored in `buf` is never checked against NULL.

## Open Questions

- Why do 9 file(s) lack file-level docs (e.g. `beacons/v1/beacon.c`)? What purpose do they serve?
- What would break if the most connected file in include: cJSON changed?
- Should include: cJSON be split, given cohesion 0.57?

## Sources

- `beacons/v1/beacon.c`
- `beacons/v2/beacon.c`
- `beacons/v3/beacon.c`
- `cJSON.c`
- `cJSON.h`
- `include/beacon_common.c`
- `include/beacon_common.h`
- `include/cJSON.c`
- `include/cJSON.h`
