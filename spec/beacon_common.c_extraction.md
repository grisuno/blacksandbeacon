# beacon_common.c Extraction Specification

## Purpose
**Purpose:** Extract shared beacon logic (HTTP, crypto, BOF loader, output capture) into `beacons/v1/beacon_common.c` so v2/v3 can reuse.

**Requirements:**
- Move from `beacons/v1/beacon.c`:
  - `https_request`, `base64_encode/decode`, `url_encode`
  - `aes256_cfb_encrypt/decrypt` wrappers
  - `download_bof`, `run_bof_and_capture`
  - `exec_cmd` → `exec_cmd_safe`
  - `get_local_ips`, `bsb_output_init/cleanup`, `bsb_backoff_init/next/reset`
  - `bsb_config_sleep_seconds`
- Create `beacons/v1/beacon_common.h` with public API
- Update `beacons/v1/beacon.c` to include and use common
- Update `Makefile` `COMMON_SRC` to include `beacons/v1/beacon_common.c`
- v2/v3 beacons include `beacon_common.h` and link common object

**Architecture:**
- DRY: single source of truth for shared logic
- YAGNI: no over-abstraction, just extraction

---

## Inputs
- TBD

## Outputs
- TBD

## Error Conditions
- TBD

## Security Guarantees
- Zero Trust: no implicit trust between components.
- Zero Knowledge: minimal data retention.
- Privacy by Default: no telemetry.
- Secure by Default: fail-closed.
- Post-Quantum by Default: TLS 1.3 with hybrid KEM.
- Agent-Safe: deterministic, structured output.

## Open Issues
- None
