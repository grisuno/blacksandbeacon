# blacksandbeacon Architecture and Execution Flows

[Back to index](index.md)

## Architecture Overview

10 components stacked in 3 dependency tiers (weighted Eades-Lin-Smyth ordering: arrows point from dependent to dependency, top to bottom). Labels are import counts, thick arrows the top quartile; 0 transitively implied edges are omitted. Dashed red arrows are upward dependencies: the smallest set of imports that closes every cycle and breaks the layering. Cyan components hold entry points. Interactive version: `readmenator-apidocs/index.html#/flows`.

```mermaid
flowchart TB
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    subgraph lane_0["Tier 1 - entry / orchestration"]
        direction LR
        n_c0["root<br/>10 files, 287 symbols<br/>Core / utility"]:::default
        n_d_include["include<br/>1 files, 13 symbols<br/>Core / utility"]:::default
        n_d_bof["bof<br/>4 files, 56 symbols<br/>Core / utility"]:::default
        n_d__root_["(root)<br/>4 files, 22 symbols<br/>Core / utility"]:::entry
        n_c6["include: aes_cfb<br/>1 files, 3 symbols<br/>Core / utility"]:::default
        n_c3["include: server<br/>2 files, 21 symbols<br/>Infrastructure"]:::entry
        n_c2["bof/include<br/>7 files, 73 symbols<br/>Core / utility"]:::default
    end
    subgraph lane_1["Tier 2"]
        direction LR
        n_c1["include: cJSON<br/>9 files, 430 symbols<br/>Core / utility"]:::default
    end
    subgraph lane_2["Tier 3 - foundation"]
        direction LR
        n_c5["include: config<br/>3 files, 42 symbols<br/>Infrastructure"]:::default
        n_c4["include: aes<br/>3 files, 66 symbols<br/>Core / utility"]:::default
    end
    n_c0 ==>|"5"| n_c1
    n_c1 -->|"1"| n_c4
    n_c1 -->|"1"| n_c5
    n_c0 ~~~ n_c1
    n_c1 ~~~ n_c5
```

---

## Execution Flows

Entry points are scored from `__main__` guards, `main` functions, entry-style names and files, and call-graph sources. Each flow walks resolved calls in call-site order (depth <= 4, <= 40 steps); numbers give the call order, dashed arrows revisit an already expanded callee, red arrows are recursion. Interactive version with zoom and per-node docs: `readmenator-apidocs/index.html#/flows`.

### `cJSON.CJSON_PUBLIC`

`cJSON.c:1134`, score 13: call-graph source with 6 calls; call-graph source with 3 calls; call-graph source with 4 calls.

Call tree:

```mermaid
flowchart LR
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_cJSON_c__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.c:95"]:::entry
    n_cJSON_c__CJSON_PUBLIC -.->|"recursion"| n_cJSON_c__CJSON_PUBLIC
    linkStyle 0 stroke:#f87171,stroke-width:2px;
```

### `cJSON.CJSON_PUBLIC`

`include/cJSON.c:1134`, score 13: call-graph source with 6 calls; call-graph source with 3 calls; call-graph source with 4 calls.

Call tree:

```mermaid
flowchart LR
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_include_cJSON_c__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.c:95"]:::entry
    n_include_cJSON_c__CJSON_PUBLIC -.->|"recursion"| n_include_cJSON_c__CJSON_PUBLIC
    linkStyle 0 stroke:#f87171,stroke-width:2px;
```

### `beacon3.main`

`beacon3.c:1007`, score 11: `main` in a compiled-language file; entry-style name `main`.

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_beacon3_c__main["beacon3.main<br/>=== MAIN ===<br/>beacon3.c:1007"]:::entry
    n_beacon3_c__https_request["beacon3.https_request<br/>=== HTTPS REQUEST ===<br/>beacon3.c:317"]:::default
    n_beacon3_c__base64_decode["beacon3.base64_decode<br/>beacon3.c:423"]:::default
    n_beacon3_c__aes256_cfb_decrypt["beacon3.aes256_cfb_decrypt<br/>beacon3.c:474"]:::default
    n_aes_h__AES_init_ctx["aes.AES_init_ctx<br/>aes.h:41"]:::external
    n_aes_h__AES_ECB_encrypt["aes.AES_ECB_encrypt<br/>if defined(ECB) && (ECB == 1)<br/>aes.h:48"]:::external
    n_beacon3_c__download_bof["beacon3.download_bof<br/>=== DOWNLOAD BOF ===<br/>beacon3.c:941"]:::default
    n_beacon3_c__run_bof_and_capture["beacon3.run_bof_and_capture<br/>=== RUN BOF AND CAPTURE ===<br/>beacon3.c:963"]:::default
    n_beacon3_c__RunELF["beacon3.RunELF<br/>beacon3.c:531"]:::default
    n_beacon3_c__page_align["beacon3.page_align<br/>=== Función auxiliar: alinear al tamaño de pá...<br/>beacon3.c:525"]:::default
    n_beacon3_c__get_or_create_trampoline["beacon3.get_or_create_trampoline<br/>beacon3.c:269"]:::default
    n_beacon3_c__create_trampoline["beacon3.create_trampoline<br/>=== CRATE TRAPOLINE ===<br/>beacon3.c:217"]:::default
    n_beacon3_c__cleanup_trampolines["beacon3.cleanup_trampolines<br/>=== CLEAN TRAMPOLINE ===<br/>beacon3.c:253"]:::default
    n_beacon3_c__exec_cmd["beacon3.exec_cmd<br/>=== EXEC CMD ===<br/>beacon3.c:504"]:::default
    n_beacon3_c__get_local_ips["beacon3.get_local_ips<br/>=== GET LOCAL IPs ===<br/>beacon3.c:912"]:::default
    n_beacon3_c__aes256_cfb_encrypt["beacon3.aes256_cfb_encrypt<br/>=== AES CFB ===<br/>beacon3.c:446"]:::default
    n_beacon3_c__base64_encode["beacon3.base64_encode<br/>=== BASE64 ===<br/>beacon3.c:406"]:::default
    n_beacon3_c__main -.->|"recursion"| n_beacon3_c__main
    n_beacon3_c__main -->|"1"| n_beacon3_c__https_request
    n_beacon3_c__https_request -.->|"recursion"| n_beacon3_c__https_request
    n_beacon3_c__main -->|"2"| n_beacon3_c__base64_decode
    n_beacon3_c__base64_decode -.->|"recursion"| n_beacon3_c__base64_decode
    n_beacon3_c__main -->|"3"| n_beacon3_c__aes256_cfb_decrypt
    n_beacon3_c__aes256_cfb_decrypt -.->|"recursion"| n_beacon3_c__aes256_cfb_decrypt
    n_beacon3_c__aes256_cfb_decrypt -->|"1"| n_aes_h__AES_init_ctx
    n_aes_h__AES_init_ctx -.->|"recursion"| n_aes_h__AES_init_ctx
    n_beacon3_c__aes256_cfb_decrypt -->|"2"| n_aes_h__AES_ECB_encrypt
    n_aes_h__AES_ECB_encrypt -.->|"recursion"| n_aes_h__AES_ECB_encrypt
    n_beacon3_c__main -->|"4"| n_beacon3_c__download_bof
    n_beacon3_c__download_bof -.->|"recursion"| n_beacon3_c__download_bof
    n_beacon3_c__download_bof -.-> n_beacon3_c__https_request
    n_beacon3_c__main -->|"5"| n_beacon3_c__run_bof_and_capture
    n_beacon3_c__run_bof_and_capture -.->|"recursion"| n_beacon3_c__run_bof_and_capture
    n_beacon3_c__run_bof_and_capture -->|"1"| n_beacon3_c__RunELF
    n_beacon3_c__RunELF -.->|"recursion"| n_beacon3_c__RunELF
    n_beacon3_c__RunELF -->|"1"| n_beacon3_c__page_align
    n_beacon3_c__RunELF -->|"2"| n_beacon3_c__get_or_create_trampoline
    n_beacon3_c__get_or_create_trampoline -->|"1"| n_beacon3_c__create_trampoline
    n_beacon3_c__RunELF -->|"3"| n_beacon3_c__cleanup_trampolines
    n_beacon3_c__main -->|"6"| n_beacon3_c__exec_cmd
    n_beacon3_c__exec_cmd -.->|"recursion"| n_beacon3_c__exec_cmd
    n_beacon3_c__main -->|"7"| n_beacon3_c__get_local_ips
    n_beacon3_c__get_local_ips -.->|"recursion"| n_beacon3_c__get_local_ips
    n_beacon3_c__main -->|"8"| n_beacon3_c__aes256_cfb_encrypt
    n_beacon3_c__aes256_cfb_encrypt -.->|"recursion"| n_beacon3_c__aes256_cfb_encrypt
    n_beacon3_c__aes256_cfb_encrypt -.-> n_aes_h__AES_init_ctx
    n_beacon3_c__aes256_cfb_encrypt -.-> n_aes_h__AES_ECB_encrypt
    n_beacon3_c__main -->|"9"| n_beacon3_c__base64_encode
    n_beacon3_c__base64_encode -.->|"recursion"| n_beacon3_c__base64_encode
    linkStyle 0,2,4,6,8,10,12,15,17,23,25,27,31 stroke:#f87171,stroke-width:2px;
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_beacon3_c as beacon3.c
    participant p_aes_h as aes.h
    p_beacon3_c->>p_aes_h: AES_init_ctx()
    p_beacon3_c->>p_aes_h: AES_ECB_encrypt()
```

---
