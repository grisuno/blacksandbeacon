# TLS Client Certificate Authentication Specification

## Purpose
**Purpose:** Mutual TLS for beacon ↔ C2.

**Requirements:**
- Config fields: `network.client_cert_path`, `network.client_key_path`
- `https_request` loads cert/key via `CURLOPT_SSLCERT` / `CURLOPT_SSLKEY`
- Server (`c2/server.py`) verifies client cert if `hmac_enabled: true` (reuse TLS stack)
- CA cert for verification: `network.ca_cert_path`
- Test with self-signed CA + client cert

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
