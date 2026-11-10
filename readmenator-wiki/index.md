# Second Brain

*Last synthesized: 2026-11-09 | 52 files | 7 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `cJSON.h`, `aes.h`, `cJSON.c`. Architecturally it is 4 layers, dominant utility (39 files) across 7 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between include: cJSON, root, bof/include: 2 extracted cross-community imports and 17 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (44% file coverage), 0 security findings, 5 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 52 |
| Symbols | 1077 |
| Resolved imports | 42 |
| Languages | c, h, py, sh |
| Communities | 7 |
| Doc coverage | 44% (23/52 files) |
| Security findings | 0 |
| Estimated read cost | ~16971 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target blacksandbeacon
```

## Concept Wiki

- [include: cJSON (11 files, cohesion 0.61)](./community_0_include_cjson.md)
- [root (10 files, cohesion 0.64)](./community_1_root.md)
- [bof/include (7 files, cohesion 1.00)](./community_2_bof_include.md)
- [include: server (3 files, cohesion 1.00)](./community_3_include_server.md)
- [include: config (3 files, cohesion 0.67)](./community_4_include_config.md)
- [include: aes_cfb (2 files, cohesion 1.00)](./community_5_include_aes_cfb.md)
- [orphans (16 files, cohesion 0.00)](./community_6_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `cJSON.h` | 27.7 |
| `aes.h` | 20.1 |
| `include/cJSON.c` | 16.5 |
| `include/beacon_common.h` | 15.7 |
| `beacon.h` | 15.3 |

## Strongest Connections

- 1 -> 0: depends_on (strength 0.9, EXTRACTED)
- 0 -> 4: depends_on (strength 0.9, EXTRACTED)
- 0 -> 2: shares_context (strength 0.5, INFERRED)
- 0 -> 5: shares_context (strength 0.5, INFERRED)
- 0 -> 6: shares_context (strength 0.5, INFERRED)
- 1 -> 2: shares_context (strength 0.5, INFERRED)
- 1 -> 5: shares_context (strength 0.5, INFERRED)
- 1 -> 6: shares_context (strength 0.5, INFERRED)
- 2 -> 4: shares_context (strength 0.5, INFERRED)
- 2 -> 5: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
