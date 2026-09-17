# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `cJSON.h` (score: 27.70)
- `aes.h` (score: 22.10)
- `include/cJSON.c` (score: 16.50)
- `include/beacon_common.h` (score: 15.70)
- `beacon.h` (score: 15.30)
- `cJSON.c` (score: 14.50)
- `bof/include/syscalls.h` (score: 13.80)
- `include/beacon_common.c` (score: 12.70)
- `bof/include/beacon_api.h` (score: 11.40)
- `beacon_p2p.c` (score: 10.90)

## Hotspots (complexity + centrality)

- `beacon5.c` -- complexity: 0.4, centrality: 1.0, combined: 0.7
- `beacon_p2p.c` -- complexity: 0.4, centrality: 1.0, combined: 0.7
- `beacon6.c` -- complexity: 0.3, centrality: 1.0, combined: 0.7
- `beacon3.c` -- complexity: 0.2, centrality: 0.9, combined: 0.7
- `gopher_beacon.c` -- complexity: 0.2, centrality: 0.9, combined: 0.6
- `cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/beacon_common.c` -- complexity: 0.2, centrality: 0.8, combined: 0.6
- `beacons/v1/gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.5
- `cJSON.h` -- complexity: 0.3, centrality: 0.6, combined: 0.5

## Dataflow Issues (INFERRED, review each lead)

- `beacon3.c:416` `base64_encode` [UNCHECKED_ALLOC] `buf`: Result of allocator stored in `buf` is never checked against NULL.
- `beacon3.c:450` `aes256_cfb_encrypt` [UNCHECKED_ALLOC] `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- `beacon3.c:478` `aes256_cfb_decrypt` [UNCHECKED_ALLOC] `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- `beacon3.c:925` `get_local_ips` [UNCHECKED_ALLOC] `result`: Result of allocator stored in `result` is never checked against NULL.
- `beacon3.c:1163` `main` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `beacon5.c:458` `base64_encode` [UNCHECKED_ALLOC] `buf`: Result of allocator stored in `buf` is never checked against NULL.
- `beacon5.c:492` `aes256_cfb_encrypt` [UNCHECKED_ALLOC] `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- `beacon5.c:520` `aes256_cfb_decrypt` [UNCHECKED_ALLOC] `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- `beacon5.c:967` `get_local_ips` [UNCHECKED_ALLOC] `result`: Result of allocator stored in `result` is never checked against NULL.
- `beacon5.c:1215` `mesh_discovery_thread` [DEAD_STORE] `ip_tok`: `ip_tok` assigned at line 1215 but never read afterwards.
