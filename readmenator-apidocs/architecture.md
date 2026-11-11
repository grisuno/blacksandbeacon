# blacksandbeacon Architecture and Execution Flows

[Back to index](index.md)

## Architecture Overview

28 components stacked in 2 dependency tiers (weighted Eades-Lin-Smyth ordering: arrows point from dependent to dependency, top to bottom). Labels are import counts, thick arrows the top quartile; 0 transitively implied edges are omitted. Dashed red arrows are upward dependencies: the smallest set of imports that closes every cycle and breaks the layering. Cyan components hold entry points. Interactive version: `readmenator-apidocs/index.html#/flows`.

```mermaid
flowchart TB
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    subgraph lane_0["Tier 1 - entry / orchestration"]
        direction LR
        n_c0["legacy<br/>19 files, 732 symbols<br/>Core / utility"]:::default
        n_d_include["include<br/>2 files, 16 symbols<br/>Infrastructure"]:::default
        n_d_config["config<br/>1 files, 7 symbols<br/>Infrastructure"]:::default
        n_d_bof["bof<br/>4 files, 56 symbols<br/>Core / utility"]:::default
        n_d__root_["(root)<br/>6 files, 39 symbols<br/>Core / utility"]:::entry
        n_c9["mutants/src: bof_path_traversal_hardening<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c8["mutants/src: bof_api_versioning<br/>3 files, 4 symbols<br/>Presentation / entry"]:::default
        n_c7["mutants/src: beacon_heartbeat___health_endpoint<br/>3 files, 4 symbols<br/>Presentation / entry"]:::default
        n_c6["mutants/src: beacon_common.c_extraction<br/>3 files, 1 symbols<br/>Core / utility"]:::default
        n_c5["mutants/src: async_i_o_for_beacon<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c24["include: config_autogen<br/>2 files, 30 symbols<br/>Infrastructure"]:::default
        n_c23["mutants/src: unified_config_schema<br/>3 files, 4 symbols<br/>Infrastructure"]:::default
        n_c22["mutants/src: tls_client_certificate_authentication<br/>3 files, 4 symbols<br/>Infrastructure"]:::default
        n_c21["mutants/src: structured_jsonl_logging<br/>3 files, 4 symbols<br/>Infrastructure"]:::default
        n_c20["mutants/src: socks5___http_proxy_support<br/>3 files, 4 symbols<br/>Presentation / entry"]:::default
        n_c2["bof/include<br/>7 files, 73 symbols<br/>Core / utility"]:::default
        n_c19["mutants/src: replay_protection<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c18["mutants/src: pre-commit_+_ci_hardening<br/>3 files, 1 symbols<br/>Core / utility"]:::default
        n_c16["mutants/src: iv_generation_with_entropy_verification<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c15["mutants/src: hkdf_key_derivation<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c14["mutants/src: containerized_build_+_sbom<br/>3 files, 1 symbols<br/>Infrastructure"]:::default
        n_c13["mutants/src: command_execution_via_execve<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c12["mutants/src: certificate_pinning___tofu<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c11["mutants/src: c2_rest_api<br/>3 files, 4 symbols<br/>Presentation / entry"]:::default
        n_c10["mutants/src: bof_streaming_(large_outputs)<br/>3 files, 4 symbols<br/>Core / utility"]:::default
        n_c1["c2<br/>3 files, 24 symbols<br/>Core / utility"]:::entry
    end
    subgraph lane_1["Tier 2 - foundation"]
        direction LR
        n_c4["include: config<br/>4 files, 51 symbols<br/>Infrastructure"]:::default
        n_c3["include: aes<br/>4 files, 71 symbols<br/>Core / utility"]:::default
    end
    n_c0 -->|"1"| n_c3
    n_c0 -->|"1"| n_c4
    n_c0 ~~~ n_c4
```

---

## Execution Flows

Entry points are scored from `__main__` guards, `main` functions, entry-style names and files, and call-graph sources. Each flow walks resolved calls in call-site order (depth <= 4, <= 40 steps); numbers give the call order, dashed arrows revisit an already expanded callee, red arrows are recursion. Interactive version with zoom and per-node docs: `readmenator-apidocs/index.html#/flows`.

### `cJSON.CJSON_PUBLIC`

`cJSON.c:1143`, score 13: call-graph source with 7 calls; call-graph source with 3 calls; call-graph source with 4 calls.

Call tree:

```mermaid
flowchart LR
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_cJSON_c__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.c:96"]:::entry
    n_cJSON_h__cJSON_GetErrorPtr["cJSON.cJSON_GetErrorPtr<br/>cJSON.h:161"]:::external
    n_cJSON_h__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.h:58"]:::external
    n_cJSON_c__CJSON_PUBLIC -.->|"recursion"| n_cJSON_c__CJSON_PUBLIC
    n_cJSON_c__CJSON_PUBLIC -->|"1"| n_cJSON_h__cJSON_GetErrorPtr
    n_cJSON_h__cJSON_GetErrorPtr -->|"1"| n_cJSON_h__CJSON_PUBLIC
    n_cJSON_h__cJSON_GetErrorPtr -.->|"recursion"| n_cJSON_h__cJSON_GetErrorPtr
    linkStyle 0,3 stroke:#f87171,stroke-width:2px;
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_cJSON_c as cJSON.c
    participant p_cJSON_h as cJSON.h
    p_cJSON_c->>p_cJSON_h: cJSON_GetErrorPtr()
```

### `cJSON.CJSON_PUBLIC`

`include/cJSON.c:1143`, score 13: call-graph source with 7 calls; call-graph source with 3 calls; call-graph source with 4 calls.

Call tree:

```mermaid
flowchart LR
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_include_cJSON_c__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.c:96"]:::entry
    n_include_cJSON_h__cJSON_GetErrorPtr["cJSON.cJSON_GetErrorPtr<br/>cJSON.h:161"]:::external
    n_include_cJSON_h__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.h:58"]:::external
    n_include_cJSON_c__CJSON_PUBLIC -.->|"recursion"| n_include_cJSON_c__CJSON_PUBLIC
    n_include_cJSON_c__CJSON_PUBLIC -->|"1"| n_include_cJSON_h__cJSON_GetErrorPtr
    n_include_cJSON_h__cJSON_GetErrorPtr -->|"1"| n_include_cJSON_h__CJSON_PUBLIC
    n_include_cJSON_h__cJSON_GetErrorPtr -.->|"recursion"| n_include_cJSON_h__cJSON_GetErrorPtr
    linkStyle 0,3 stroke:#f87171,stroke-width:2px;
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_include_cJSON_c as cJSON.c
    participant p_include_cJSON_h as cJSON.h
    p_include_cJSON_c->>p_include_cJSON_h: cJSON_GetErrorPtr()
```

### `beacon.main`

`beacons/v1/beacon.c:167`, score 11: `main` in a compiled-language file; entry-style name `main`.

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_beacons_v1_beacon_c__main["beacon.main<br/>beacon.c:167"]:::entry
    n_include_beacon_common_h__bsb_output_init["beacon_common.bsb_output_init<br/>Initialize the output buffer.<br/>beacon_common.h:96"]:::external
    n_include_beacon_common_h__bsb_backoff_init["beacon_common.bsb_backoff_init<br/>beacon_common.h:189"]:::external
    n_include_beacon_common_h__https_request["beacon_common.https_request<br/>HTTP client: performs GET or POST request.<br/>beacon_common.h:119"]:::external
    n_include_beacon_common_h__bsb_backoff_next["beacon_common.bsb_backoff_next<br/>beacon_common.h:190"]:::external
    n_include_beacon_common_h__base64_decode["beacon_common.base64_decode<br/>beacon_common.h:124"]:::external
    n_include_beacon_common_h__aes256_cfb_decrypt["beacon_common.aes256_cfb_decrypt<br/>beacon_common.h:136"]:::external
    n_include_beacon_common_h__bsb_backoff_reset["beacon_common.bsb_backoff_reset<br/>beacon_common.h:191"]:::external
    n_beacons_v1_beacon_c__execute_command["beacon.execute_command<br/>beacon.c:104"]:::default
    n_include_beacon_common_h__download_bof["beacon_common.download_bof<br/>Download a BOF from the C2 server.<br/>beacon_common.h:169"]:::external
    n_include_beacon_common_h__run_bof_and_capture["beacon_common.run_bof_and_capture<br/>Execute a BOF and capture its output.<br/>beacon_common.h:173"]:::external
    n_beacons_v1_beacon_c__report_result["beacon.report_result<br/>beacon.c:24"]:::default
    n_include_beacon_common_h__get_local_ips["beacon_common.get_local_ips<br/>Get local IP addresses as a comma-separated s...<br/>beacon_common.h:178"]:::external
    n_include_beacon_common_h__bsb_generate_secure_iv["beacon_common.bsb_generate_secure_iv<br/>Secure IV generation: tries RAND_bytes, falls...<br/>beacon_common.h:131"]:::external
    n_include_beacon_common_h__aes256_cfb_encrypt_replay["beacon_common.aes256_cfb_encrypt_replay<br/>Replay-protected encryption: prepends counter...<br/>beacon_common.h:142"]:::external
    n_include_beacon_common_h__base64_encode["beacon_common.base64_encode<br/>HTTP client: performs GET or POST request.<br/>beacon_common.h:123"]:::external
    n_include_beacon_common_h__bsb_output_cleanup["beacon_common.bsb_output_cleanup<br/>Initialize the output buffer.<br/>beacon_common.h:99"]:::external
    n_beacons_v1_beacon_c__main -.->|"recursion"| n_beacons_v1_beacon_c__main
    n_beacons_v1_beacon_c__main -->|"1"| n_include_beacon_common_h__bsb_output_init
    n_include_beacon_common_h__bsb_output_init -.->|"recursion"| n_include_beacon_common_h__bsb_output_init
    n_beacons_v1_beacon_c__main -->|"2"| n_include_beacon_common_h__bsb_backoff_init
    n_include_beacon_common_h__bsb_backoff_init -.->|"recursion"| n_include_beacon_common_h__bsb_backoff_init
    n_beacons_v1_beacon_c__main -->|"3"| n_include_beacon_common_h__https_request
    n_include_beacon_common_h__https_request -.->|"recursion"| n_include_beacon_common_h__https_request
    n_beacons_v1_beacon_c__main -->|"4"| n_include_beacon_common_h__bsb_backoff_next
    n_include_beacon_common_h__bsb_backoff_next -.->|"recursion"| n_include_beacon_common_h__bsb_backoff_next
    n_beacons_v1_beacon_c__main -->|"5"| n_include_beacon_common_h__base64_decode
    n_include_beacon_common_h__base64_decode -.->|"recursion"| n_include_beacon_common_h__base64_decode
    n_beacons_v1_beacon_c__main -->|"6"| n_include_beacon_common_h__aes256_cfb_decrypt
    n_include_beacon_common_h__aes256_cfb_decrypt -.->|"recursion"| n_include_beacon_common_h__aes256_cfb_decrypt
    n_beacons_v1_beacon_c__main -->|"7"| n_include_beacon_common_h__bsb_backoff_reset
    n_include_beacon_common_h__bsb_backoff_reset -.->|"recursion"| n_include_beacon_common_h__bsb_backoff_reset
    n_beacons_v1_beacon_c__main -->|"8"| n_beacons_v1_beacon_c__execute_command
    n_beacons_v1_beacon_c__execute_command -->|"1"| n_include_beacon_common_h__download_bof
    n_include_beacon_common_h__download_bof -.->|"recursion"| n_include_beacon_common_h__download_bof
    n_beacons_v1_beacon_c__execute_command -->|"2"| n_include_beacon_common_h__run_bof_and_capture
    n_include_beacon_common_h__run_bof_and_capture -.->|"recursion"| n_include_beacon_common_h__run_bof_and_capture
    n_beacons_v1_beacon_c__main -->|"9"| n_beacons_v1_beacon_c__report_result
    n_beacons_v1_beacon_c__report_result -->|"1"| n_include_beacon_common_h__get_local_ips
    n_include_beacon_common_h__get_local_ips -.->|"recursion"| n_include_beacon_common_h__get_local_ips
    n_beacons_v1_beacon_c__report_result -->|"2"| n_include_beacon_common_h__bsb_generate_secure_iv
    n_include_beacon_common_h__bsb_generate_secure_iv -.->|"recursion"| n_include_beacon_common_h__bsb_generate_secure_iv
    n_beacons_v1_beacon_c__report_result -->|"3"| n_include_beacon_common_h__aes256_cfb_encrypt_replay
    n_include_beacon_common_h__aes256_cfb_encrypt_replay -.->|"recursion"| n_include_beacon_common_h__aes256_cfb_encrypt_replay
    n_beacons_v1_beacon_c__report_result -->|"4"| n_include_beacon_common_h__base64_encode
    n_include_beacon_common_h__base64_encode -.->|"recursion"| n_include_beacon_common_h__base64_encode
    n_beacons_v1_beacon_c__report_result -.-> n_include_beacon_common_h__https_request
    n_beacons_v1_beacon_c__main -->|"10"| n_include_beacon_common_h__bsb_output_cleanup
    n_include_beacon_common_h__bsb_output_cleanup -.->|"recursion"| n_include_beacon_common_h__bsb_output_cleanup
    linkStyle 0,2,4,6,8,10,12,14,17,19,22,24,26,28,31 stroke:#f87171,stroke-width:2px;
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_beacons_v1_beacon_c as beacon.c
    participant p_include_beacon_common_h as beacon_common.h
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_output_init()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_backoff_init()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: https_request()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_backoff_next()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: base64_decode()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: aes256_cfb_decrypt()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_backoff_reset()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: download_bof()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: run_bof_and_capture()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: get_local_ips()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_generate_secure_iv()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: aes256_cfb_encrypt_replay()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: base64_encode()
    p_beacons_v1_beacon_c->>p_include_beacon_common_h: bsb_output_cleanup()
```

---
