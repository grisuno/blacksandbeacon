# HKDF Key Derivation Specification

## Purpose
**Purpose:** Replace raw hex key usage with HKDF-SHA256 to derive separate encryption and HMAC keys from a master secret.

**Requirements:**
- New config field `crypto.master_key_hex` (64 hex chars = 32 bytes)
- Derive `encryption_key` (32 bytes) and `hmac_key` (32 bytes) using HKDF-SHA256
- Salt: `b"blacksandbeacon-v2"` (domain separation)
- Info: `b"enc"` for encryption, `b"hmac"` for authentication
- Backward compat: if `aes_key_hex` present and `master_key_hex` absent, derive from `aes_key_hex` with warning
- Both C (`config.c`) and Python (`config_py.py`, `c2/server.py`) implementations must match exactly

**Security Guarantees:**
- Key separation: encryption and auth use independent keys
- Domain separation: salt prevents cross-protocol key reuse
- Post-Quantum by Default: SHA256-based KDF

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
