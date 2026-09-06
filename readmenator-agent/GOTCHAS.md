# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `cJSON.h` (score: 27.40)
- `aes.h` (score: 21.30)
- `beacon.h` (score: 14.40)
- `cJSON.c` (score: 14.20)
- `include/cJSON.c` (score: 14.20)
- `beacon_p2p.c` (score: 10.40)
- `beacon5.c` (score: 9.90)
- `beacon6.c` (score: 8.90)
- `beacon3.c` (score: 8.50)
- `beacons/v1/gopher_beacon.c` (score: 8.50)

## Hotspots (complexity + centrality)

- `beacon5.c` -- complexity: 0.3, centrality: 1.0, combined: 0.7
- `beacon_p2p.c` -- complexity: 0.4, centrality: 0.9, combined: 0.7
- `beacon6.c` -- complexity: 0.2, centrality: 0.9, combined: 0.7
- `beacon3.c` -- complexity: 0.2, centrality: 0.9, combined: 0.6
- `beacons/v1/gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.6
- `gopher_beacon.c` -- complexity: 0.2, centrality: 0.8, combined: 0.6
- `cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/cJSON.c` -- complexity: 1.0, centrality: 0.3, combined: 0.6
- `include/beacon_common.c` -- complexity: 0.2, centrality: 0.8, combined: 0.5
- `tests/test_c2_http_e2e.py` -- complexity: 0.1, centrality: 0.8, combined: 0.5
