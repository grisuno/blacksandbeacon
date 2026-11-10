# BOF Path Traversal Hardening Specification

## Purpose
**Purpose:** Strengthen BOF serving against path traversal beyond `os.path.basename`.

**Requirements:**
- `handle_bof` resolves `upload_dir` to absolute path with `os.path.realpath`
- Requested BOF path resolved to absolute path with `os.path.realpath`
- Verify requested path starts with resolved `upload_dir` (prefix check)
- Reject with `BOF_NOT_FOUND` if outside upload directory
- Add test with `../../etc/passwd` style payloads

**Security Guarantees:**
- Zero Trust: no filesystem trust
- Path traversal eliminated
- Agent-Safe: clear reject behavior

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
