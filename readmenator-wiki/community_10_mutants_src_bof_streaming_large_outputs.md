# mutants/src: bof_streaming_(large_outputs)

*Community 10 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `BOF_STREAMING_`, `bof_streaming_`. Core file: `include/bof_streaming_(large_outputs).h` (2 symbols). Documented purpose: Auto-generated implementation for contract: BOF Streaming (Large Outputs).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/bof_streaming_(large_outputs).h` | h | utility | 2 | no |
| `mutants/src/bof_streaming_(large_outputs).c` | c | utility | 1 | yes |
| `src/bof_streaming_(large_outputs).c` | c | utility | 1 | yes |

## Key Symbols

- `BOF_STREAMING_` (macro, `include/bof_streaming_(large_outputs).h:2`) `#define BOF_STREAMING_(LARGE_OUTPUTS)`
- `bof_streaming_` (function, `include/bof_streaming_(large_outputs).h:4`) `bool bof_streaming_(large_outputs)_process(void);`
- `bof_streaming_` (function, `mutants/src/bof_streaming_(large_outputs).c:6`) `bool bof_streaming_(large_outputs)_process(void)`
- `bof_streaming_` (function, `src/bof_streaming_(large_outputs).c:6`) `bool bof_streaming_(large_outputs)_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 10 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (legacy) and community 10 (mutants/src: bof_streaming_(large_outputs)).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/bof_streaming_(large_outputs).h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: bof_streaming_(large_outputs) changed?
- Should mutants/src: bof_streaming_(large_outputs) be split, given cohesion 1.00?

## Sources

- `include/bof_streaming_(large_outputs).h`
- `mutants/src/bof_streaming_(large_outputs).c`
- `src/bof_streaming_(large_outputs).c`
