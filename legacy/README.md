# Legacy snapshots

Historical single-file beacon iterations kept for reference only.
They are NOT part of the build (see Makefile: `COMMON_SRC` + `beacons/v*/beacon.c`).

- `beacon3.c`, `beacon5.c`, `beacon6.c` — superseded dev snapshots of the
  BOF loader. They contain old `RunELF` variants and `[DEBUG]` stderr
  prints. Do not audit them as current behavior; the maintained loader
  lives in `include/beacon_common.c` (fork isolation + MAP_SHARED
  output buffer + W^X section/trampoline protections).
- `gopher_beacon.c`, `v1_gopher_beacon.c` — old gopher-style beacon.
- `beacon_p2p.c` — unused experiment.
