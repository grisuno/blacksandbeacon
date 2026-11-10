# SOCKS5 / HTTP Proxy Support Specification

## Purpose
**Purpose:** Allow beacon egress via proxy.

**Requirements:**
- Config fields: `network.proxy_type` (none|socks5|http), `network.proxy_host`, `network.proxy_port`, `network.proxy_user`, `network.proxy_pass`
- `https_request` uses `curl_easy_setopt(curl, CURLOPT_PROXY, ...)` and related options
- Proxy credentials in config (not baked in binary)
- Test with local proxy (e.g., `socat` or `mitmproxy` in test)

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
