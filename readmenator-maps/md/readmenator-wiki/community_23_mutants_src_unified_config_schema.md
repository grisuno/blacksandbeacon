# mutants/src: unified_config_schema

*Community 23 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `UNIFIED_CONFIG_SCHEMA_H`, `unified_config_schema_process`. Core file: `include/unified_config_schema.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: Unified Config Schema.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/unified_config_schema.h` | h | infrastructure | 2 | no |
| `mutants/src/unified_config_schema.c` | c | infrastructure | 1 | yes |
| `src/unified_config_schema.c` | c | infrastructure | 1 | yes |

## Key Symbols

- `UNIFIED_CONFIG_SCHEMA_H` (macro, `include/unified_config_schema.h:2`) `#define UNIFIED_CONFIG_SCHEMA_H`
- `unified_config_schema_process` (function, `include/unified_config_schema.h:4`) `bool unified_config_schema_process(void);`
- `unified_config_schema_process` (function, `mutants/src/unified_config_schema.c:6`) `bool unified_config_schema_process(void)`
- `unified_config_schema_process` (function, `src/unified_config_schema.c:6`) `bool unified_config_schema_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/unified_config_schema.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: unified_config_schema changed?
- Should mutants/src: unified_config_schema be split, given cohesion 1.00?

## Sources

- `include/unified_config_schema.h`
- `mutants/src/unified_config_schema.c`
- `src/unified_config_schema.c`
