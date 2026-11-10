# Beacon Heartbeat / Health Endpoint Specification

## Purpose
**Purpose:** Lightweight beacon health check without full command roundtrip.

**Requirements:**
- New endpoint `GET /api/poll/<client_id>/health`
- Returns JSON: `{client_id, uptime_seconds, config_hash, beacon_version, last_poll_ts}`
- Encrypted with same AES-CFB + HMAC as regular poll
- Beacon calls health endpoint every `timing.health_interval_seconds` (default 300) if no commands pending
- Config field `timing.health_interval_seconds`

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
