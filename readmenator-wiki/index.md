# Second Brain

*Last synthesized: 2026-11-10 | 175 files | 26 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `cJSON.h`, `aes.h`, `server.py`. Architecturally it is 4 layers, dominant utility (71 files) across 26 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between root, c2, bof/include: 2 extracted cross-community imports and 18 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (57% file coverage), 0 security findings, 20 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 175 |
| Symbols | 1521 |
| Resolved imports | 104 |
| Languages | c, h, py, sh |
| Communities | 26 |
| Doc coverage | 57% (99/175 files) |
| Security findings | 0 |
| Estimated read cost | ~30522 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target blacksandbeacon
```

## Concept Wiki

- [root (20 files, cohesion 0.89)](./community_0_root.md)
- [c2 (15 files, cohesion 1.00)](./community_1_c2.md)
- [bof/include (7 files, cohesion 1.00)](./community_2_bof_include.md)
- [include: aes (6 files, cohesion 0.62)](./community_3_include_aes.md)
- [include: config (6 files, cohesion 0.83)](./community_4_include_config.md)
- [mutants/src: async_i_o_for_beacon (3 files, cohesion 1.00)](./community_5_mutants_src_async_i_o_for_beacon.md)
- [mutants/src: beacon_common.c_extraction (3 files, cohesion 1.00)](./community_6_mutants_src_beacon_common_c_extraction.md)
- [mutants/src: beacon_heartbeat___health_endpoint (3 files, cohesion 1.00)](./community_7_mutants_src_beacon_heartbeat_health_endpoint.md)
- [mutants/src: bof_api_versioning (3 files, cohesion 1.00)](./community_8_mutants_src_bof_api_versioning.md)
- [mutants/src: bof_path_traversal_hardening (3 files, cohesion 1.00)](./community_9_mutants_src_bof_path_traversal_hardening.md)
- [mutants/src: bof_streaming_(large_outputs) (3 files, cohesion 1.00)](./community_10_mutants_src_bof_streaming_large_outputs.md)
- [mutants/src: c2_rest_api (3 files, cohesion 1.00)](./community_11_mutants_src_c2_rest_api.md)
- [mutants/src: certificate_pinning___tofu (3 files, cohesion 1.00)](./community_12_mutants_src_certificate_pinning_tofu.md)
- [mutants/src: command_execution_via_execve (3 files, cohesion 1.00)](./community_13_mutants_src_command_execution_via_execve.md)
- [mutants/src: containerized_build_+_sbom (3 files, cohesion 1.00)](./community_14_mutants_src_containerized_build_sbom.md)
- [mutants/src: hkdf_key_derivation (3 files, cohesion 1.00)](./community_15_mutants_src_hkdf_key_derivation.md)
- [mutants/src: iv_generation_with_entropy_verification (3 files, cohesion 1.00)](./community_16_mutants_src_iv_generation_with_entropy_verification.md)
- [mutants/src: mutation_testing_integration (3 files, cohesion 1.00)](./community_17_mutants_src_mutation_testing_integration.md)
- [mutants/src: pre-commit_+_ci_hardening (3 files, cohesion 1.00)](./community_18_mutants_src_pre_commit_ci_hardening.md)
- [mutants/src: replay_protection (3 files, cohesion 1.00)](./community_19_mutants_src_replay_protection.md)
- [mutants/src: socks5___http_proxy_support (3 files, cohesion 1.00)](./community_20_mutants_src_socks5_http_proxy_support.md)
- [mutants/src: structured_jsonl_logging (3 files, cohesion 1.00)](./community_21_mutants_src_structured_jsonl_logging.md)
- [mutants/src: tls_client_certificate_authentication (3 files, cohesion 1.00)](./community_22_mutants_src_tls_client_certificate_authentication.md)
- [mutants/src: unified_config_schema (3 files, cohesion 1.00)](./community_23_mutants_src_unified_config_schema.md)
- [include: config_autogen (2 files, cohesion 1.00)](./community_24_include_config_autogen.md)
- [orphans (62 files, cohesion 0.00)](./community_25_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `cJSON.h` | 28.0 |
| `aes.h` | 22.1 |
| `c2/server.py` | 20.1 |
| `include/beacon_common.h` | 17.8 |
| `include/cJSON.c` | 16.5 |

## Strongest Connections

- 0 -> 3: depends_on (strength 0.9, EXTRACTED)
- 0 -> 4: depends_on (strength 0.9, EXTRACTED)
- 4 -> 24: duplicates (strength 0.56, INFERRED)
- 0 -> 2: shares_context (strength 0.5, INFERRED)
- 0 -> 5: shares_context (strength 0.5, INFERRED)
- 0 -> 6: shares_context (strength 0.5, INFERRED)
- 0 -> 7: shares_context (strength 0.5, INFERRED)
- 0 -> 8: shares_context (strength 0.5, INFERRED)
- 0 -> 9: shares_context (strength 0.5, INFERRED)
- 0 -> 10: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
