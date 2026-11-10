# BOF API Versioning Specification

## Purpose
**Purpose:** Add version negotiation between beacon and BOF to prevent ABI mismatches.

**Requirements:**
- `bof/include/beacon_api.h`: add `#define BEACON_API_VERSION 2`
- Beacon exports `uint32_t beacon_api_version(void)` returning `BEACON_API_VERSION`
- BOF `go` function signature unchanged, but can call `beacon_api_version()`
- Beacon loader (`run_bof_and_capture`) checks BOF's expected version via symbol `beacon_abi_version` (weak symbol in BOF, default 1)
- If mismatch, beacon logs warning and refuses to run BOF (returns error output)
- Config field `bof.strict_version_check` (default true)

**Security Guarantees:**
- Zero Trust: no implicit ABI compatibility
- Version skew detected at load time
- Agent-Safe: structured version contract

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
