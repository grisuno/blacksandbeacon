# Certificate Pinning / TOFU Specification

## Purpose
**Purpose:** Add certificate pinning with Trust-On-First-Use (TOFU) to prevent MITM attacks on the C2 channel.

**Requirements:**
- New config field `network.cert_fingerprint_sha256` (optional, 64 hex chars)
- On first successful TLS connection, if fingerprint not set, store it (TOFU)
- On subsequent connections, verify presented cert matches pinned fingerprint
- Fail closed if mismatch (no fallback)
- Configurable via `config.json` and environment variable `BSB_CERT_FINGERPRINT`

**Security Guarantees:**
- Zero Trust: no implicit trust of CAs
- Fail-closed: connection aborts on pin mismatch
- Agent-Safe: deterministic verification logic

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
