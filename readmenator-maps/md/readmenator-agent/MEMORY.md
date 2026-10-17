# Project Memory

> Cross-session context for agents. Sections 1-6 are regenerated from the source tree with zero LLM tokens: declared rules are quoted verbatim with `file:line`, measured baselines come from the scan. Section 7 is written by agents and humans and is preserved across rebuilds.

Generated from 52 files at commit `515d3e0782d6`. Read this first, then `readmenator-wiki/index.md`, then `readmenator . ask "<question>"` for anything specific.

## 1. Purpose and domain

- What it is: A Linux C2 beacon with a native in-memory ELF BOF loader, written in (`README.md:3`)
- Domain vocabulary (term, files): `bof` (28), `beacon` (26), `output` (22), `aes` (18), `decrypt` (18), `include` (18), `size` (17), `get` (17), `encrypt` (17), `printf` (16), `callback` (15), `run` (14), `api` (14), `null` (13), `read` (13)
- Subsystem `root`: 10 files, core `beacon_p2p.c`
- Subsystem `include: cJSON`: 9 files, core `cJSON.c`: case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible...
- Subsystem `bof/include`: 7 files, core `bof/include/syscalls.h`: bsf_strlen: static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret...
- Subsystem `include: server`: 3 files, core `c2/server.py`: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Subsystem `include: aes`: 3 files, core `include/aes.c`: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Subsystem `include: config`: 3 files, core `include/config.h`: bsb_config_load: Load config from path.
- Subsystem `include: aes_cfb`: 2 files, core `include/aes_cfb.h`
- Business rules that the code cannot show live in section 7: record them there.

## 2. Workflow

Detected commands:
- `python -m pytest -q` (tests/ layout)
- `make all` (Makefile)
- `make help` (Makefile)
- `make config` (Makefile)
- `make beacon` (Makefile)
- `make beacon-v1` (Makefile)
- `make beacon-v2` (Makefile)
- `make beacon-v3` (Makefile)
- `make all-beacons` (Makefile)
- `make bofs` (Makefile)
- `make bof-whoami` (Makefile)
- `make bof-is_sudo` (Makefile)

Session protocol:
1. Start: read this file, then `readmenator . fresh` (exit 1 means run `readmenator . --rebuild`).
2. Orient: `readmenator-wiki/index.md`; for a question use `readmenator . ask "<question>"` (local = entities + sources, `--global` = community reports).
3. Before editing a file: `grep -n '<file>' readmenator-agent/GOTCHAS.md readmenator-agent/SECURITY.md`.
4. After the change: run the tests above, then `readmenator . --rebuild` so the maps, wiki, and this file stay true.
5. End: record decisions, business rules, and gotchas with `readmenator . remember "<note>" --kind decision`.

## 3. Rules and constraints

Declared:
- Never commit `config/config.json` to version control (`SECURITY.md:41`)
- Use strong, randomly generated AES keys (32 bytes / 64 hex characters) (`SECURITY.md:42`)
- Restrict file permissions: `chmod 600 config/config.json` (`SECURITY.md:43`)
- Rotate keys regularly and after each engagement (`SECURITY.md:44`)

Measured baseline:
- Security findings at medium or above: 0 (see `readmenator-agent/SECURITY.md`); do not add new ones.
- Dependency cycles: 0; layer violations: 0 (see `readmenator-agent/GOTCHAS.md`).

## 4. Style norms

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- c: 29 files, 714 symbols; docstrings on 30% of symbols; functions snake_case (55%); types PascalCase (61%); median file 244 lines, max 3203.
- h: 11 files, 275 symbols; docstrings on 16% of symbols; functions snake_case (46%); types PascalCase (14%); median file 61 lines, max 295.
- py: 11 files, 86 symbols; docstrings on 47% of symbols; functions snake_case (100%); types PascalCase (100%); median file 146 lines, max 456.
- sh: 1 files, 0 symbols; median file 34 lines, max 34.
- Tests: 9 files under tests; follow the existing naming (e.g. `test_beacon_build.py`).

## 5. Minimum deliverables

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- Tests pass: `python -m pytest -q`.
- Docstring coverage stays at or above 28%.
- No new security findings at medium or above (current: 0).
- No new dependency cycles (current: 0).
- Files stay under 300 lines where possible (`readmenator . lint`).
- Docs refreshed: `readmenator . --rebuild`, and decisions recorded in section 7.

## 6. Risks to respect

- God nodes (changes ripple widely): `cJSON.h`, `aes.h`, `include/cJSON.c`, `include/beacon_common.h`, `beacon.h`
- Hotspots (complex and central): `beacon5.c`, `beacon_p2p.c`, `beacon6.c`, `beacon3.c`, `gopher_beacon.c`
- Full blast radius: `readmenator-agent/GOTCHAS.md`; findings: `readmenator-agent/SECURITY.md`.

## 7. Session log (preserved across rebuilds)

Append with `readmenator . remember "<note>" --kind <kind>` (kinds: business, decision, rule, workflow, style, deliverable, gotcha, todo, note) or the MCP tool `readmenator.remember`. Record business rules, decisions and their reasons, workflow changes, and anything the next session must not rediscover.

<!-- readmenator:memory:notes:begin -->
<!-- readmenator:memory:notes:end -->
