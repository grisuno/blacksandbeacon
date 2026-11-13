# Project Memory

> Cross-session context for agents. Sections 1-6 are regenerated from the source tree with zero LLM tokens: declared rules are quoted verbatim with `file:line`, measured baselines come from the scan. Section 7 is written by agents and humans and is preserved across rebuilds.

Generated from 179 files at commit `e9feea6269c6`. Read this first, then `readmenator-wiki/index.md`, then `readmenator . ask "<question>"` for anything specific.

## 1. Purpose and domain

- What it is: A Linux C2 beacon with a native in-memory ELF BOF loader, written in (`README.md:3`)
- Domain vocabulary (term, files): `mutants` (74), `generated` (63), `implementation` (60), `auto` (60), `beacon` (56), `bof` (52), `process` (50), `include` (49), `config` (36), `not` (31), `placeholder` (31), `bdd` (29), `output` (28), `run` (27), `api` (26)
- Subsystem `legacy`: 20 files, core `cJSON.c`: case_insensitive_strcmp: /* This is a safeguard to prevent copy-pasters from using incompatible...
- Subsystem `c2`: 17 files, core `c2/server.py`: Black Sand Beacon C2 Server  Gopher-style command and control server for Black Sand Beacon agents.
- Subsystem `bof/include`: 7 files, core `bof/include/syscalls.h`: bsf_strlen: } static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long...
- Subsystem `include: aes`: 6 files, core `include/aes.c`: tiny-AES-c (https://github.com/kokke/tiny-AES-c)
- Subsystem `include: config`: 6 files, core `include/config.c`: slurp: declared in the schema.
- Subsystem `mutants/src: async_i_o_for_beacon`: 3 files, core `include/async_i_o_for_beacon.h`
- Subsystem `mutants/src: beacon_common.c_extraction`: 3 files, core `include/beacon_common.c_extraction.h`
- Subsystem `mutants/src: beacon_heartbeat___health_endpoint`: 3 files, core `include/beacon_heartbeat___health_endpoint.h`
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
- c: 92 files, 844 symbols; docstrings on 28% of symbols; functions snake_case (62%); types PascalCase (60%); median file 27 lines, max 3260.
- py: 54 files, 417 symbols; docstrings on 66% of symbols; functions snake_case (100%); types PascalCase (100%); median file 141 lines, max 1144.
- h: 31 files, 329 symbols; docstrings on 15% of symbols; functions snake_case (54%); types PascalCase (10%); median file 6 lines, max 344.
- sh: 2 files, 0 symbols; median file 34 lines, max 34.
- Tests: 69 files under mutants/tests, tests; follow the existing naming (e.g. `test_async_i_o_for_beacon.py`).

## 5. Minimum deliverables

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- Tests pass: `python -m pytest -q`.
- Docstring coverage stays at or above 35%.
- No new security findings at medium or above (current: 0).
- No new dependency cycles (current: 0).
- Files stay under 300 lines where possible (`readmenator . lint`).
- Docs refreshed: `readmenator . --rebuild`, and decisions recorded in section 7.

## 6. Risks to respect

- God nodes (changes ripple widely): `cJSON.h`, `c2/server.py`, `aes.h`, `include/beacon_common.h`, `include/cJSON.c`
- Hotspots (complex and central): `c2/server.py`, `legacy/beacon_p2p.c`, `legacy/beacon5.c`, `cJSON.c`, `include/cJSON.c`
- Full blast radius: `readmenator-agent/GOTCHAS.md`; findings: `readmenator-agent/SECURITY.md`.

## 7. Session log (preserved across rebuilds)

Append with `readmenator . remember "<note>" --kind <kind>` (kinds: business, decision, rule, workflow, style, deliverable, gotcha, todo, note) or the MCP tool `readmenator.remember`. Record business rules, decisions and their reasons, workflow changes, and anything the next session must not rediscover.

<!-- readmenator:memory:notes:begin -->
- 2026-11-11 [decision] Boy-scout round (post-HackTricks audit): fixed BOF round-trip broken by base64-encoded BOF serving not decoded in beacon download_bof (root cause of empty BOF output at C2; HackTricks' fork/COW finding was about legacy beacon3.c, current loader in include/beacon_common.c forks with MAP_SHARED output + crash guard). Trampolines now RW->RX (W^X), verified 0 RWX mappings at runtime via strace. Un-skipped tests/test_c2_beacon_bof_integration.py round-trip regression (beof:whoami -> '[whoami] uid=...
- 2026-11-11 [decision] Second boy-scout round: (1) call_bof_isolated now force-aligns rsp to 16 in the asm block itself (save rsp in scratch slot, and -16, call, restore) — fixes movaps SIGSEGV in -O0/debug builds of beacon_common; -O2 unchanged. (2) Fixed dead-on-arrival cert pinning: config stores 64-hex but CURLOPT_PINNEDPUBLICKEY requires sha256//<b64>; added bsb_curl_pin_format conversion in https_request (verified empirically: raw hex pin always rejected by curl). (3) Un-skipped 2 cert-pinning integration tes...
- 2026-11-13 [decision] Staging contract added: GET /stage/beacon/<token> and /stage/config/<token> in c2/server.py. Packing = 3 XOR layers with keys derived from token via HKDF-SHA256 (salt blacksandbeacon-stage-v1, info stage-l1/2/3) — no key material on the wire. Server serves TLS when server.tls_cert/tls_key set. Stager c2/stage_payload.py (stdlib-only) fetch+decode in RAM, memfd_create + execve, beacon gets config via BSB_CONFIG=/proc/self/fd/N (memfd without CLOEXEC). Startup prints + clipboard-copies one-line...
- 2026-11-13 [gotcha] Staging debugging: config_py.py deep-merge passes server.stage_token through correctly. Two gotchas fixed: (1) copy_to_clipboard now only fires on interactive TTY — headless server runs (tests/smoke) must not pollute the operator clipboard; (2) stage_payload exits with a clear message on HTTP 404/403: staging disabled or token mismatch, one-liner must come from the running server. Real incident: a stale server.py process loaded before stage_token was added kept serving STAGE_FORBIDDEN on :707...
- 2026-11-13 [decision] Random per-run runtime values in c2/server.py load_runtime_config: port (free-port probe), master_key_hex (secrets.token_hex(32) -> HKDF enc/hmac), stage_token, client_id (bsb-<hex4>) generated when absent from config.json+env; recorded in cfg['generated'] and printed in main banner. build_stage_config() serves runtime-wins JSON (file values replaced by generated ones, server section + derived key bytes stripped) so fileless beacons match the server run. Bug fixed: beacon_common.c:378 rand()...
<!-- readmenator:memory:notes:end -->
