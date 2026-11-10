# Pre-commit + CI Hardening Specification

## Purpose
**Purpose:** Automate formatting, linting, and security checks.

**Requirements:**
- `.pre-commit-config.yaml` with:
  - `clang-format` for C files
  - `black` + `ruff` for Python
  - `cppcheck` for C static analysis
  - `shellcheck` for shell scripts
  - `detect-secrets` for key leakage
  - `hadolint` for Dockerfile
- `Makefile` targets: `fmt`, `lint`, `pre-commit-install`
- GitHub Actions CI runs `make fmt lint test mutation-test`

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
