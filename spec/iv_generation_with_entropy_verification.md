# IV Generation with Entropy Verification Specification

## Purpose
**Purpose:** Ensure IV generation never uses weak entropy; verify `RAND_bytes` success and fallback to `getrandom(2)`.

**Requirements:**
- `aes256_cfb_encrypt` checks `RAND_bytes` return value (1 = success)
- On failure, call `getrandom(iv, 16, GRND_NONBLOCK)` 
- If `getrandom` fails, abort encryption with error (fail-closed)
- Same logic in Python using `os.urandom` (which already blocks on entropy)
- Unit test that simulates `RAND_bytes` failure

**Security Guarantees:**
- Zero Knowledge: no weak IVs ever produced
- Fail-closed: no silent degradation
- Agent-Safe: deterministic error behavior

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
