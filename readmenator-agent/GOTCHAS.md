# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `cJSON.h` (score: 28.00, imported by 1 files)
- `aes.h` (score: 22.10, imported by 1 files)
- `c2/server.py` (score: 22.10, imported by 9 files)
- `include/beacon_common.h` (score: 17.80, imported by 5 files)
- `include/cJSON.c` (score: 16.50)
- `beacon.h` (score: 15.30, imported by 1 files)
- `cJSON.c` (score: 14.50)
- `include/config_py.py` (score: 14.30, imported by 7 files)
- `include/config.h` (score: 14.10, imported by 6 files)
- `bof/include/syscalls.h` (score: 13.80, imported by 5 files)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `include/config_py.py` -- 7 direct, 12 total dependents
- `include/config.h` -- 6 direct, 11 total dependents
- `c2/server.py` -- 9 direct, 9 total dependents
- `bof/include/beacon_api.h` -- 5 direct, 5 total dependents
- `bof/include/syscalls.h` -- 5 direct, 5 total dependents
- `include/beacon_common.h` -- 5 direct, 5 total dependents
- `include/aes.h` -- 3 direct, 3 total dependents
- `include/aes_cfb.h` -- 3 direct, 3 total dependents
- `c2/__init__.py` -- 2 direct, 2 total dependents
- `include/async_i_o_for_beacon.h` -- 2 direct, 2 total dependents

## Hotspots (complexity + centrality)

- `legacy/beacon5.c` -- complexity: 0.4, centrality: 1.0, combined: 0.7
- `legacy/beacon_p2p.c` -- complexity: 0.4, centrality: 0.9, combined: 0.7
- `legacy/beacon6.c` -- complexity: 0.3, centrality: 0.9, combined: 0.7
- `include/beacon_common.c` -- complexity: 0.3, centrality: 0.9, combined: 0.7
- `legacy/beacon3.c` -- complexity: 0.2, centrality: 0.9, combined: 0.6
- `c2/server.py` -- complexity: 0.2, centrality: 0.9, combined: 0.6
- `cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `legacy/gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.6
- `legacy/v1_gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.6

## Dataflow Issues (INFERRED, review each lead)

- `beacons/v1/beacon.c:78` `report_result` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `beacons/v1/beacon.c:111` `execute_command` [UNCHECKED_ALLOC] `payload`: Result of allocator stored in `payload` is never checked against NULL.
- `beacons/v2/beacon.c:123` `report_result` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `beacons/v2/beacon.c:156` `execute_command` [UNCHECKED_ALLOC] `payload`: Result of allocator stored in `payload` is never checked against NULL.
- `beacons/v3/beacon.c:116` `report_result` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `beacons/v3/beacon.c:149` `execute_command` [UNCHECKED_ALLOC] `payload`: Result of allocator stored in `payload` is never checked against NULL.
- `c2/server.py:597` `serve` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
- `cJSON.c:1676` `print_array` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1676 but never read afterwards.
- `cJSON.c:1908` `print_object` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1908 but never read afterwards.
- `gopher_c2.py:145` `main` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
