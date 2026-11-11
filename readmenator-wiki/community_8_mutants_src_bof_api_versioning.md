# mutants/src: bof_api_versioning

*Community 8 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `BOF_API_VERSIONING_H`, `bof_api_versioning_process`. Core file: `include/bof_api_versioning.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: BOF API Versioning.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/bof_api_versioning.h` | h | presentation | 2 | no |
| `mutants/src/bof_api_versioning.c` | c | presentation | 1 | yes |
| `src/bof_api_versioning.c` | c | presentation | 1 | yes |

## Key Symbols

- `BOF_API_VERSIONING_H` (macro, `include/bof_api_versioning.h:2`) `#define BOF_API_VERSIONING_H`
- `bof_api_versioning_process` (function, `include/bof_api_versioning.h:4`) `bool bof_api_versioning_process(void);`
- `bof_api_versioning_process` (function, `mutants/src/bof_api_versioning.c:6`) `bool bof_api_versioning_process(void)`
- `bof_api_versioning_process` (function, `src/bof_api_versioning.c:6`) `bool bof_api_versioning_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 8 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (legacy) and community 8 (mutants/src: bof_api_versioning).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/bof_api_versioning.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: bof_api_versioning changed?
- Should mutants/src: bof_api_versioning be split, given cohesion 1.00?

## Sources

- `include/bof_api_versioning.h`
- `mutants/src/bof_api_versioning.c`
- `src/bof_api_versioning.c`
