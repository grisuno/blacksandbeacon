# mutants/src: c2_rest_api

*Community 11 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `C2_REST_API_H`, `c2_rest_api_process`. Core file: `include/c2_rest_api.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: C2 REST API.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/c2_rest_api.h` | h | presentation | 2 | no |
| `mutants/src/c2_rest_api.c` | c | presentation | 1 | yes |
| `src/c2_rest_api.c` | c | presentation | 1 | yes |

## Key Symbols

- `C2_REST_API_H` (macro, `include/c2_rest_api.h:2`) `#define C2_REST_API_H`
- `c2_rest_api_process` (function, `include/c2_rest_api.h:4`) `bool c2_rest_api_process(void);`
- `c2_rest_api_process` (function, `mutants/src/c2_rest_api.c:6`) `bool c2_rest_api_process(void)`
- `c2_rest_api_process` (function, `src/c2_rest_api.c:6`) `bool c2_rest_api_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 11 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 11 (mutants/src: c2_rest_api).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/c2_rest_api.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: c2_rest_api changed?
- Should mutants/src: c2_rest_api be split, given cohesion 1.00?

## Sources

- `include/c2_rest_api.h`
- `mutants/src/c2_rest_api.c`
- `src/c2_rest_api.c`
