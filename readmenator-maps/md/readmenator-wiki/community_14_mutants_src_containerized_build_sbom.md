# mutants/src: containerized_build_+_sbom

*Community 14 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `CONTAINERIZED_BUILD_`. Core file: `include/containerized_build_+_sbom.h` (1 symbols). Documented purpose: Auto-generated implementation for contract: Containerized Build + SBOM.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/containerized_build_+_sbom.h` | h | infrastructure | 1 | no |
| `mutants/src/containerized_build_+_sbom.c` | c | infrastructure | 0 | yes |
| `src/containerized_build_+_sbom.c` | c | infrastructure | 0 | yes |

## Key Symbols

- `CONTAINERIZED_BUILD_` (macro, `include/containerized_build_+_sbom.h:2`) `#define CONTAINERIZED_BUILD_`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 14 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (root) and community 14 (mutants/src: containerized_build_+_sbom).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/containerized_build_+_sbom.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: containerized_build_+_sbom changed?
- Should mutants/src: containerized_build_+_sbom be split, given cohesion 1.00?

## Sources

- `include/containerized_build_+_sbom.h`
- `mutants/src/containerized_build_+_sbom.c`
- `src/containerized_build_+_sbom.c`
