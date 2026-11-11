# mutants/src: socks5___http_proxy_support

*Community 20 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `mutants/src` with dominant language c (cohesion 1.00). Central symbols: `SOCKS5___HTTP_PROXY_SUPPORT_H`, `socks5___http_proxy_support_process`. Core file: `include/socks5___http_proxy_support.h` (2 symbols). Documented purpose: Auto-generated implementation for contract: SOCKS5 / HTTP Proxy Support.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `include/socks5___http_proxy_support.h` | h | presentation | 2 | no |
| `mutants/src/socks5___http_proxy_support.c` | c | presentation | 1 | yes |
| `src/socks5___http_proxy_support.c` | c | presentation | 1 | yes |

## Key Symbols

- `SOCKS5___HTTP_PROXY_SUPPORT_H` (macro, `include/socks5___http_proxy_support.h:2`) `#define SOCKS5___HTTP_PROXY_SUPPORT_H`
- `socks5___http_proxy_support_process` (function, `include/socks5___http_proxy_support.h:4`) `bool socks5___http_proxy_support_process(void);`
- `socks5___http_proxy_support_process` (function, `mutants/src/socks5___http_proxy_support.c:6`) `bool socks5___http_proxy_support_process(void)`
- `socks5___http_proxy_support_process` (function, `src/socks5___http_proxy_support.c:6`) `bool socks5___http_proxy_support_process(void)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 20 (strength 0.5): Inferred shared context (language c) with no import path between community 0 (root) and community 20 (mutants/src: socks5___http_proxy_support).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `include/socks5___http_proxy_support.h`)? What purpose do they serve?
- What would break if the most connected file in mutants/src: socks5___http_proxy_support changed?
- Should mutants/src: socks5___http_proxy_support be split, given cohesion 1.00?

## Sources

- `include/socks5___http_proxy_support.h`
- `mutants/src/socks5___http_proxy_support.c`
- `src/socks5___http_proxy_support.c`
