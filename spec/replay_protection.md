# Replay Protection Specification

## Purpose
**Purpose:** Prevent replay attacks by adding monotonic counter + timestamp to encrypted payloads.

**Requirements:**
- Beacon maintains `uint64_t message_counter` (persisted in memory, reset on restart)
- Server tracks `last_seen_counter` per client_id
- Encrypted payload format: `iv (16) || counter (8, LE) || timestamp (8, LE) || ciphertext`
- Server rejects if `counter <= last_seen_counter` OR `timestamp > now + 60s` OR `timestamp < now - 300s`
- Config field `crypto.replay_window_seconds` (default 300)
- Counter transmitted in plaintext inside encrypted envelope (authenticated via AES-CFB)

**Security Guarantees:**
- Zero Trust: no implicit trust of message freshness
- Replay window bounded by config
- Agent-Safe: structured, verifiable payload format

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
