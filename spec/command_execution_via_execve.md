# Command Execution via execve Specification

## Purpose
**Purpose:** Replace `system()`/`popen()` with `execve` + argv array to prevent shell injection.

**Requirements:**
- New function `exec_cmd_safe(const char *command, int *out_len)` in `beacon_common.c`
- Parse command string into argv array (simple space split, respecting quotes)
- Use `posix_spawn` or `fork` + `execve` with argv
- Capture stdout/stderr via pipe
- No shell interpretation ever
- Fallback: if parsing fails, treat as single argv[0] with no args

**Security Guarantees:**
- Zero Trust: no shell interpretation
- Command injection eliminated
- Agent-Safe: deterministic argument parsing

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
