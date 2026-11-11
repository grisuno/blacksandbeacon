# mutants/src: replay_protection

*Community 19 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `REPLAY_PROTECTION_H`, `replay_protection_process`. Core file: `include/replay_protection.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Replay Protection.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/replay_protection.h` | h | utility | 2 | no |
| `mutants/src/replay_protection.c` | c | utility | 1 | yes |
| `src/replay_protection.c` | c | utility | 1 | yes |

## Key Symbols

- `REPLAY_PROTECTION_H` (macro, `include/replay_protection.h:2`) `#define REPLAY_PROTECTION_H`
- `replay_protection_process` (function, `include/replay_protection.h:4`) `bool replay_protection_process(void);`
- `replay_protection_process` (function, `mutants/src/replay_protection.c:6`) `bool replay_protection_process(void)`
- `replay_protection_process` (function, `src/replay_protection.c:6`) `bool replay_protection_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 19 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (root) and community 19 (mutants/src: replay_protection).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/replay_protection.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: replay_protection changed?
- Should mutants/src: replay_protection be split, given cohesion 1.00?

## Sources

- `include/replay_protection.h`
- `mutants/src/replay_protection.c`
- `src/replay_protection.c`
