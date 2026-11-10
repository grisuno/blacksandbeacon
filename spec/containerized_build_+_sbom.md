# Containerized Build + SBOM Specification

## Purpose
**Purpose:** Reproducible builds and supply chain transparency.

**Requirements:**
- `Dockerfile.build` multi-stage: builder (gcc, libssl-dev, libcurl4-openssl-dev) → scratch with static binary
- `make docker-build` produces `build/beacon-static`
- `make sbom` runs `syft build/beacon-static -o spdx-json > sbom.spdx.json`
- CI uploads SBOM as artifact

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
