# mutants/src: structured_jsonl_logging

*Community 21 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `STRUCTURED_JSONL_LOGGING_H`, `structured_jsonl_logging_process`. Core file: `include/structured_jsonl_logging.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Structured JSONL Logging.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/structured_jsonl_logging.h` | h | infrastructure | 2 | no |
| `mutants/src/structured_jsonl_logging.c` | c | infrastructure | 1 | yes |
| `src/structured_jsonl_logging.c` | c | infrastructure | 1 | yes |

## Key Symbols

- `STRUCTURED_JSONL_LOGGING_H` (macro, `include/structured_jsonl_logging.h:2`) `#define STRUCTURED_JSONL_LOGGING_H`
- `structured_jsonl_logging_process` (function, `include/structured_jsonl_logging.h:4`) `bool structured_jsonl_logging_process(void);`
- `structured_jsonl_logging_process` (function, `mutants/src/structured_jsonl_logging.c:6`) `bool structured_jsonl_logging_process(void)`
- `structured_jsonl_logging_process` (function, `src/structured_jsonl_logging.c:6`) `bool structured_jsonl_logging_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/structured_jsonl_logging.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: structured_jsonl_logging changed?
- Should mutants/src: structured_jsonl_logging be split, given cohesion 1.00?

## Sources

- `include/structured_jsonl_logging.h`
- `mutants/src/structured_jsonl_logging.c`
- `src/structured_jsonl_logging.c`
