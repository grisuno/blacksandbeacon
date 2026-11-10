# Structured JSONL Logging Specification

## Purpose
**Purpose:** Replace CSV logs with JSONL for easier querying and SIEM integration.

**Requirements:**
- Config field `server.log_format` = `csv` | `jsonl` (default `jsonl`)
- `C2State` writes JSONL: one line per report with all fields
- Fields: `timestamp`, `client_id`, `os`, `pid`, `hostname`, `ips`, `user`, `discovered_ips`, `result_portscan`, `result_pwd`, `command`, `output`
- Timestamp: ISO8601 UTC (`2024-01-15T10:30:00Z`)
- Backward compat: CSV still works if `log_format: csv`
- Test verifies both formats parse correctly

**Architecture:**
- YAGNI: only two formats, no pluggable system

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
