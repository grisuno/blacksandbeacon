# mutants/src: beacon_heartbeat___health_endpoint

*Community 7 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `BEACON_HEARTBEAT___HEALTH_ENDPOINT_H`, `beacon_heartbeat___health_endpoint_process`. Core file: `include/beacon_heartbeat___health_endpoint.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Beacon Heartbeat / Health Endpoint.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/beacon_heartbeat___health_endpoint.h` | h | presentation | 2 | no |
| `mutants/src/beacon_heartbeat___health_endpoint.c` | c | presentation | 1 | yes |
| `src/beacon_heartbeat___health_endpoint.c` | c | presentation | 1 | yes |

## Key Symbols

- `BEACON_HEARTBEAT___HEALTH_ENDPOINT_H` (macro, `include/beacon_heartbeat___health_endpoint.h:2`) `#define BEACON_HEARTBEAT___HEALTH_ENDPOINT_H`
- `beacon_heartbeat___health_endpoint_process` (function, `include/beacon_heartbeat___health_endpoint.h:4`) `bool beacon_heartbeat___health_endpoint_process(void);`
- `beacon_heartbeat___health_endpoint_process` (function, `mutants/src/beacon_heartbeat___health_endpoint.c:6`) `bool beacon_heartbeat___health_endpoint_process(void)`
- `beacon_heartbeat___health_endpoint_process` (function, `src/beacon_heartbeat___health_endpoint.c:6`) `bool beacon_heartbeat___health_endpoint_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 7 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 7 (mutants/src: beacon_heartbeat___health_endpoint).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/beacon_heartbeat___health_endpoint.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: beacon_heartbeat___health_endpoint changed?
- Should mutants/src: beacon_heartbeat___health_endpoint be split, given cohesion 1.00?

## Sources

- `include/beacon_heartbeat___health_endpoint.h`
- `mutants/src/beacon_heartbeat___health_endpoint.c`
- `src/beacon_heartbeat___health_endpoint.c`
