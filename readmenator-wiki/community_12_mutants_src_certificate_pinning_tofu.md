# mutants/src: certificate_pinning___tofu

*Community 12 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `CERTIFICATE_PINNING___TOFU_H`, `certificate_pinning___tofu_process`. Core file: `include/certificate_pinning___tofu.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Certificate Pinning / TOFU.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/certificate_pinning___tofu.h` | h | utility | 2 | no |
| `mutants/src/certificate_pinning___tofu.c` | c | utility | 1 | yes |
| `src/certificate_pinning___tofu.c` | c | utility | 1 | yes |

## Key Symbols

- `CERTIFICATE_PINNING___TOFU_H` (macro, `include/certificate_pinning___tofu.h:2`) `#define CERTIFICATE_PINNING___TOFU_H`
- `certificate_pinning___tofu_process` (function, `include/certificate_pinning___tofu.h:4`) `bool certificate_pinning___tofu_process(void);`
- `certificate_pinning___tofu_process` (function, `mutants/src/certificate_pinning___tofu.c:6`) `bool certificate_pinning___tofu_process(void)`
- `certificate_pinning___tofu_process` (function, `src/certificate_pinning___tofu.c:6`) `bool certificate_pinning___tofu_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 12 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (root) and community 12 (mutants/src: certificate_pinning___tofu).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/certificate_pinning___tofu.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: certificate_pinning___tofu changed?
- Should mutants/src: certificate_pinning___tofu be split, given cohesion 1.00?

## Sources

- `include/certificate_pinning___tofu.h`
- `mutants/src/certificate_pinning___tofu.c`
- `src/certificate_pinning___tofu.c`
