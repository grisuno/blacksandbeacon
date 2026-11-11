# mutants/src: beacon_common.c_extraction

*Community 6 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `BEACON_COMMON`. Core file: `include/beacon_common.c_extraction.h` (1 symbols). Documented purpose: Auto-generated implementation for contract: beacon_common.c Extraction.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/beacon_common.c_extraction.h` | h | utility | 1 | no |
| `mutants/src/beacon_common.c_extraction.c` | c | utility | 0 | yes |
| `src/beacon_common.c_extraction.c` | c | utility | 0 | yes |

## Key Symbols

- `BEACON_COMMON` (macro, `include/beacon_common.c_extraction.h:2`) `#define BEACON_COMMON`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 6 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (root) and community 6 (mutants/src: beacon_common.c_extraction).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/beacon_common.c_extraction.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: beacon_common.c_extraction changed?
- Should mutants/src: beacon_common.c_extraction be split, given cohesion 1.00?

## Sources

- `include/beacon_common.c_extraction.h`
- `mutants/src/beacon_common.c_extraction.c`
- `src/beacon_common.c_extraction.c`
