# Second Brain

*Last synthesized: 2026-10-07 | 52 files | 8 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `cJSON.h`, `aes.h`, `cJSON.c`. Architecturally it is 4 layers, dominant utility (39 files) across 8 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between root, include: cJSON, bof/include: 3 extracted cross-community imports and 17 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (44% file coverage), 0 security findings, 5 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 52 |
| Symbols | 1069 |
| Resolved imports | 43 |
| Languages | c, h, py, sh |
| Communities | 8 |
| Doc coverage | 44% (23/52 files) |
| Security findings | 0 |
| Estimated read cost | ~16515 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target readmenator_blacksandbeacon_40630rqb
```

## Concept Wiki

- [root (10 files, cohesion 0.61)](./community_0_root.md)
- [include: cJSON (9 files, cohesion 0.57)](./community_1_include_cjson.md)
- [bof/include (7 files, cohesion 1.00)](./community_2_bof_include.md)
- [include: server (3 files, cohesion 1.00)](./community_3_include_server.md)
- [include: aes (3 files, cohesion 0.40)](./community_4_include_aes.md)
- [include: config (3 files, cohesion 0.67)](./community_5_include_config.md)
- [include: aes_cfb (2 files, cohesion 1.00)](./community_6_include_aes_cfb.md)
- [orphans (15 files, cohesion 0.00)](./community_7_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `cJSON.h` | 27.7 |
| `aes.h` | 22.1 |
| `include/cJSON.c` | 16.5 |
| `include/beacon_common.h` | 15.7 |
| `beacon.h` | 15.3 |

## Strongest Connections

- 0 -> 1: depends_on (strength 0.9, EXTRACTED)
- 1 -> 4: depends_on (strength 0.9, EXTRACTED)
- 1 -> 5: depends_on (strength 0.9, EXTRACTED)
- 0 -> 4: duplicates (strength 0.54, INFERRED)
- 0 -> 2: shares_context (strength 0.5, INFERRED)
- 0 -> 6: shares_context (strength 0.5, INFERRED)
- 0 -> 7: shares_context (strength 0.5, INFERRED)
- 1 -> 2: shares_context (strength 0.5, INFERRED)
- 1 -> 6: shares_context (strength 0.5, INFERRED)
- 1 -> 7: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
