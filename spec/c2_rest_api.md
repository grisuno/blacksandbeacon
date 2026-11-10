# C2 REST API Specification

## Purpose
**Purpose:** Programmatic control of C2 for automation.

**Requirements:**
- New Flask/FastAPI server in `c2/api.py` (or extend `server.py`)
- Endpoints:
  - `GET /api/v1/clients` — list connected clients
  - `POST /api/v1/commands` — queue command `{client_id, command}`
  - `GET /api/v1/results/<client_id>` — fetch results
  - `GET /api/v1/health` — server health
- Auth: Bearer token from config `server.api_token`
- Runs on separate port `server.api_port` (default 7071)
- OpenAPI spec at `/api/v1/openapi.json`

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
