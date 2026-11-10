# BOF Streaming (Large Outputs) Specification

## Purpose
**Purpose:** Support BOF outputs larger than 64KB buffer.

**Requirements:**
- `BeaconOutput` callback supports `CALLBACK_OUTPUT_STREAM` (new type 0x0F)
- BOF can call `BeaconOutput` multiple times with chunks
- Beacon accumulates chunks in memory (configurable max `bof.max_output_size`, default 1MB)
- On BOF completion, sends accumulated output as single report
- Config field `bof.max_output_size`

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
