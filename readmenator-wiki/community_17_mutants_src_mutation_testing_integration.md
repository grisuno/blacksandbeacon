# mutants/src: mutation_testing_integration

*Community 17 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `MUTATION_TESTING_INTEGRATION_H`, `mutation_testing_integration_process`. Core file: `include/mutation_testing_integration.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Mutation Testing Integration.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/mutation_testing_integration.h` | h | testing | 2 | no |
| `mutants/src/mutation_testing_integration.c` | c | testing | 1 | yes |
| `src/mutation_testing_integration.c` | c | testing | 1 | yes |

## Key Symbols

- `MUTATION_TESTING_INTEGRATION_H` (macro, `include/mutation_testing_integration.h:2`) `#define MUTATION_TESTING_INTEGRATION_H`
- `mutation_testing_integration_process` (function, `include/mutation_testing_integration.h:4`) `bool mutation_testing_integration_process(void);`
- `mutation_testing_integration_process` (function, `mutants/src/mutation_testing_integration.c:6`) `bool mutation_testing_integration_process(void)`
- `mutation_testing_integration_process` (function, `src/mutation_testing_integration.c:6`) `bool mutation_testing_integration_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 17 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (root) and community 17 (mutants/src: mutation_testing_integration).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/mutation_testing_integration.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: mutation_testing_integration changed?
- Should mutants/src: mutation_testing_integration be split, given cohesion 1.00?

## Sources

- `include/mutation_testing_integration.h`
- `mutants/src/mutation_testing_integration.c`
- `src/mutation_testing_integration.c`
