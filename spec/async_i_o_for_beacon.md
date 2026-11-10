# Async I/O for Beacon Specification

## Purpose
**Purpose:** Non-blocking beacon loop using libcurl multi interface.

**Requirements:**
- Replace blocking `https_request` + `sleep` with `curl_multi` event loop
- Single thread handles: DNS, connect, TLS, request, response, BOF execution
- BOF execution runs in thread pool (config `server.bof_workers`, default 2)
- `bsb_backoff` integrated into event loop timers
- Significant refactor; behind feature flag `network.async_io` (default false for v2)

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
