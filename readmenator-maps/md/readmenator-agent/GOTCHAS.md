# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `cJSON.h` (score: 28.00, imported by 6 files)
- `aes.h` (score: 22.10, imported by 6 files)
- `c2/server.py` (score: 20.10, imported by 8 files)
- `include/beacon_common.h` (score: 17.80, imported by 5 files)
- `include/cJSON.c` (score: 16.50)
- `beacon.h` (score: 15.30, imported by 6 files)
- `cJSON.c` (score: 14.50)
- `include/config_py.py` (score: 14.30, imported by 7 files)
- `include/config.h` (score: 14.10, imported by 6 files)
- `bof/include/syscalls.h` (score: 13.80, imported by 5 files)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `include/config_py.py` -- 7 direct, 12 total dependents
- `include/config.h` -- 6 direct, 11 total dependents
- `c2/server.py` -- 8 direct, 8 total dependents
- `aes.h` -- 6 direct, 6 total dependents
- `beacon.h` -- 6 direct, 6 total dependents
- `cJSON.h` -- 6 direct, 6 total dependents
- `bof/include/beacon_api.h` -- 5 direct, 5 total dependents
- `bof/include/syscalls.h` -- 5 direct, 5 total dependents
- `include/beacon_common.h` -- 5 direct, 5 total dependents
- `include/aes.h` -- 3 direct, 3 total dependents

## Hotspots (complexity + centrality)

- `beacon5.c` -- complexity: 0.4, centrality: 1.0, combined: 0.7
- `beacon_p2p.c` -- complexity: 0.4, centrality: 1.0, combined: 0.7
- `beacon6.c` -- complexity: 0.3, centrality: 1.0, combined: 0.7
- `beacon3.c` -- complexity: 0.2, centrality: 0.9, combined: 0.7
- `include/beacon_common.c` -- complexity: 0.3, centrality: 0.9, combined: 0.6
- `gopher_beacon.c` -- complexity: 0.2, centrality: 0.9, combined: 0.6
- `cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `beacons/v1/gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.5
- `c2/server.py` -- complexity: 0.2, centrality: 0.8, combined: 0.5

## Dataflow Issues (INFERRED, review each lead)

- `beacon3.c:447` `base64_encode` [UNCHECKED_ALLOC] `buf`: Result of allocator stored in `buf` is never checked against NULL.
- `beacon3.c:485` `aes256_cfb_encrypt` [UNCHECKED_ALLOC] `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- `beacon3.c:519` `aes256_cfb_decrypt` [UNCHECKED_ALLOC] `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- `beacon3.c:1099` `get_local_ips` [UNCHECKED_ALLOC] `result`: Result of allocator stored in `result` is never checked against NULL.
- `beacon3.c:1373` `main` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `beacon5.c:490` `base64_encode` [UNCHECKED_ALLOC] `buf`: Result of allocator stored in `buf` is never checked against NULL.
- `beacon5.c:528` `aes256_cfb_encrypt` [UNCHECKED_ALLOC] `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- `beacon5.c:562` `aes256_cfb_decrypt` [UNCHECKED_ALLOC] `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- `beacon5.c:1142` `get_local_ips` [UNCHECKED_ALLOC] `result`: Result of allocator stored in `result` is never checked against NULL.
- `beacon5.c:1420` `mesh_discovery_thread` [DEAD_STORE] `ip_tok`: `ip_tok` assigned at line 1420 but never read afterwards.
