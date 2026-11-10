# Unified Config Schema Specification

## Purpose
**Purpose:** Single source of truth for config schema; generate C and Python parsers from it.

**Requirements:**
- Create `config/schema.json` with JSON Schema (Draft 7) describing all config sections
- Python script `config/generate_parsers.py` reads schema and:
  - Generates `include/config_autogen.h` with struct definitions
  - Generates `include/config_autogen.c` with parser (replaces manual `config.c`)
  - Generates `include/config_py_autogen.py` with `load_config` (replaces `config_py.py`)
- `Makefile` adds `generate-config` target that runs the generator
- CI runs `make generate-config` and fails if checked-in parsers diverge

**Architecture:**
- DRY: schema is single source of truth
- Generated code is checked in (reviewable diff)

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
