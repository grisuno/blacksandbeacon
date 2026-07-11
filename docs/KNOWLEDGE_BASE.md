# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 53 | **Total Symbols Extracted:** 904 | **Total Imports:** 401

## Structural Knowledge Map
> **Note:** The visual graph below has been intelligently pruned to the top 300 most relevant nodes to prevent rendering crashes. Full details of all 53 files are documented below.

```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
    beacon5_c["beacon5.c (c)"]
    class beacon5_c mod;
    beacon5_c_MemoryStruct["MemoryStruct"]
    class beacon5_c_MemoryStruct cls;
    beacon5_c --> beacon5_c_MemoryStruct
    beacon5_c___attribute__["__attribute__"]
    class beacon5_c___attribute__ fn;
    beacon5_c --> beacon5_c___attribute__
    beacon5_c_BeaconPrintf["BeaconPrintf"]
    class beacon5_c_BeaconPrintf fn;
    beacon5_c --> beacon5_c_BeaconPrintf
    beacon5_c_BeaconOutput["BeaconOutput"]
    class beacon5_c_BeaconOutput fn;
    beacon5_c --> beacon5_c_BeaconOutput
    beacon5_c_create_trampoline["create_trampoline"]
    class beacon5_c_create_trampoline fn;
    beacon5_c --> beacon5_c_create_trampoline
    beacon_p2p_c["beacon_p2p.c (c)"]
    class beacon_p2p_c mod;
    beacon_p2p_c_MemoryStruct["MemoryStruct"]
    class beacon_p2p_c_MemoryStruct cls;
    beacon_p2p_c --> beacon_p2p_c_MemoryStruct
    beacon_p2p_c_BeaconDataParse["BeaconDataParse"]
    class beacon_p2p_c_BeaconDataParse fn;
    beacon_p2p_c --> beacon_p2p_c_BeaconDataParse
    beacon_p2p_c_BeaconDataPtr["BeaconDataPtr"]
    class beacon_p2p_c_BeaconDataPtr fn;
    beacon_p2p_c --> beacon_p2p_c_BeaconDataPtr
    beacon_p2p_c_BeaconDataInt["BeaconDataInt"]
    class beacon_p2p_c_BeaconDataInt fn;
    beacon_p2p_c --> beacon_p2p_c_BeaconDataInt
    beacon_p2p_c_BeaconDataShort["BeaconDataShort"]
    class beacon_p2p_c_BeaconDataShort fn;
    beacon_p2p_c --> beacon_p2p_c_BeaconDataShort
    beacon6_c["beacon6.c (c)"]
    class beacon6_c mod;
    beacon6_c_MemoryStruct["MemoryStruct"]
    class beacon6_c_MemoryStruct cls;
    beacon6_c --> beacon6_c_MemoryStruct
    beacon6_c___attribute__["__attribute__"]
    class beacon6_c___attribute__ fn;
    beacon6_c --> beacon6_c___attribute__
    beacon6_c_delay_ms["delay_ms"]
    class beacon6_c_delay_ms fn;
    beacon6_c --> beacon6_c_delay_ms
    beacon6_c_is_prime["is_prime"]
    class beacon6_c_is_prime fn;
    beacon6_c --> beacon6_c_is_prime
    beacon6_c_get_nth_prime_limited["get_nth_prime_limited"]
    class beacon6_c_get_nth_prime_limited fn;
    beacon6_c --> beacon6_c_get_nth_prime_limited
    beacon3_c["beacon3.c (c)"]
    class beacon3_c mod;
    beacon3_c_MemoryStruct["MemoryStruct"]
    class beacon3_c_MemoryStruct cls;
    beacon3_c --> beacon3_c_MemoryStruct
    beacon3_c___attribute__["__attribute__"]
    class beacon3_c___attribute__ fn;
    beacon3_c --> beacon3_c___attribute__
    beacon3_c_BeaconPrintf["BeaconPrintf"]
    class beacon3_c_BeaconPrintf fn;
    beacon3_c --> beacon3_c_BeaconPrintf
    beacon3_c_BeaconOutput["BeaconOutput"]
    class beacon3_c_BeaconOutput fn;
    beacon3_c --> beacon3_c_BeaconOutput
    beacon3_c_create_trampoline["create_trampoline"]
    class beacon3_c_create_trampoline fn;
    beacon3_c --> beacon3_c_create_trampoline
    beacons_v1_gopher_beacon_c["gopher_beacon.c (c)"]
    class beacons_v1_gopher_beacon_c mod;
    beacons_v1_gopher_beacon_c_MemoryStruct["MemoryStruct"]
    class beacons_v1_gopher_beacon_c_MemoryStruct cls;
    beacons_v1_gopher_beacon_c --> beacons_v1_gopher_beacon_c_MemoryStruct
    beacons_v1_gopher_beacon_c___attribute__["__attribute__"]
    class beacons_v1_gopher_beacon_c___attribute__ fn;
    beacons_v1_gopher_beacon_c --> beacons_v1_gopher_beacon_c___attribute__
    beacons_v1_gopher_beacon_c_BeaconPrintf["BeaconPrintf"]
    class beacons_v1_gopher_beacon_c_BeaconPrintf fn;
    beacons_v1_gopher_beacon_c --> beacons_v1_gopher_beacon_c_BeaconPrintf
    beacons_v1_gopher_beacon_c_BeaconOutput["BeaconOutput"]
    class beacons_v1_gopher_beacon_c_BeaconOutput fn;
    beacons_v1_gopher_beacon_c --> beacons_v1_gopher_beacon_c_BeaconOutput
    beacons_v1_gopher_beacon_c_create_trampoline["create_trampoline"]
    class beacons_v1_gopher_beacon_c_create_trampoline fn;
    beacons_v1_gopher_beacon_c --> beacons_v1_gopher_beacon_c_create_trampoline
    gopher_beacon_c["gopher_beacon.c (c)"]
    class gopher_beacon_c mod;
    gopher_beacon_c_MemoryStruct["MemoryStruct"]
    class gopher_beacon_c_MemoryStruct cls;
    gopher_beacon_c --> gopher_beacon_c_MemoryStruct
    gopher_beacon_c___attribute__["__attribute__"]
    class gopher_beacon_c___attribute__ fn;
    gopher_beacon_c --> gopher_beacon_c___attribute__
    gopher_beacon_c_BeaconPrintf["BeaconPrintf"]
    class gopher_beacon_c_BeaconPrintf fn;
    gopher_beacon_c --> gopher_beacon_c_BeaconPrintf
    gopher_beacon_c_BeaconOutput["BeaconOutput"]
    class gopher_beacon_c_BeaconOutput fn;
    gopher_beacon_c --> gopher_beacon_c_BeaconOutput
    gopher_beacon_c_create_trampoline["create_trampoline"]
    class gopher_beacon_c_create_trampoline fn;
    gopher_beacon_c --> gopher_beacon_c_create_trampoline
    include_beacon_common_c["beacon_common.c (c)"]
    class include_beacon_common_c mod;
    include_beacon_common_c_MemoryStruct["MemoryStruct"]
    class include_beacon_common_c_MemoryStruct cls;
    include_beacon_common_c --> include_beacon_common_c_MemoryStruct
    include_beacon_common_c_bsb_output_init["bsb_output_init"]
    class include_beacon_common_c_bsb_output_init fn;
    include_beacon_common_c --> include_beacon_common_c_bsb_output_init
    include_beacon_common_c_bsb_output_cleanup["bsb_output_cleanup"]
    class include_beacon_common_c_bsb_output_cleanup fn;
    include_beacon_common_c --> include_beacon_common_c_bsb_output_cleanup
    include_beacon_common_c_bsb_output_reset["bsb_output_reset"]
    class include_beacon_common_c_bsb_output_reset fn;
    include_beacon_common_c --> include_beacon_common_c_bsb_output_reset
    include_beacon_common_c_BeaconPrintf["BeaconPrintf"]
    class include_beacon_common_c_BeaconPrintf fn;
    include_beacon_common_c --> include_beacon_common_c_BeaconPrintf
    tests_test_c2_http_e2e_py["test_c2_http_e2e.py (py)"]
    class tests_test_c2_http_e2e_py mod;
    tests_test_c2_http_e2e_py__free_port["_free_port"]
    class tests_test_c2_http_e2e_py__free_port fn;
    tests_test_c2_http_e2e_py --> tests_test_c2_http_e2e_py__free_port
    tests_test_c2_http_e2e_py__recv_response["_recv_response"]
    class tests_test_c2_http_e2e_py__recv_response fn;
    tests_test_c2_http_e2e_py --> tests_test_c2_http_e2e_py__recv_response
    tests_test_c2_http_e2e_py_test_http_get_poll_returns_encrypted_command["test_http_get_poll_returns_encrypted_command"]
    class tests_test_c2_http_e2e_py_test_http_get_poll_returns_encrypted_command fn;
    tests_test_c2_http_e2e_py --> tests_test_c2_http_e2e_py_test_http_get_poll_returns_encrypted_command
    tests_test_c2_http_e2e_py_test_http_post_report_writes_log["test_http_post_report_writes_log"]
    class tests_test_c2_http_e2e_py_test_http_post_report_writes_log fn;
    tests_test_c2_http_e2e_py --> tests_test_c2_http_e2e_py_test_http_post_report_writes_log
    tests_test_c2_http_e2e_py_test_gopher_legacy_still_works["test_gopher_legacy_still_works"]
    class tests_test_c2_http_e2e_py_test_gopher_legacy_still_works fn;
    tests_test_c2_http_e2e_py --> tests_test_c2_http_e2e_py_test_gopher_legacy_still_works
    c2_server_py["server.py (py)"]
    class c2_server_py mod;
    c2_server_py_load_runtime_config["load_runtime_config"]
    class c2_server_py_load_runtime_config fn;
    c2_server_py --> c2_server_py_load_runtime_config
    c2_server_py_compute_hmac["compute_hmac"]
    class c2_server_py_compute_hmac fn;
    c2_server_py --> c2_server_py_compute_hmac
    c2_server_py_verify_hmac["verify_hmac"]
    class c2_server_py_verify_hmac fn;
    c2_server_py --> c2_server_py_verify_hmac
    c2_server_py_encrypt_data["encrypt_data"]
    class c2_server_py_encrypt_data fn;
    c2_server_py --> c2_server_py_encrypt_data
    c2_server_py_decrypt_data["decrypt_data"]
    class c2_server_py_decrypt_data fn;
    c2_server_py --> c2_server_py_decrypt_data
    beacons_v2_beacon_c["beacon.c (c)"]
    class beacons_v2_beacon_c mod;
    beacons_v2_beacon_c_report_result["report_result"]
    class beacons_v2_beacon_c_report_result fn;
    beacons_v2_beacon_c --> beacons_v2_beacon_c_report_result
    beacons_v2_beacon_c_execute_command["execute_command"]
    class beacons_v2_beacon_c_execute_command fn;
    beacons_v2_beacon_c --> beacons_v2_beacon_c_execute_command
    beacons_v2_beacon_c_main["main"]
    class beacons_v2_beacon_c_main fn;
    beacons_v2_beacon_c --> beacons_v2_beacon_c_main
    beacons_v2_beacon_c__GNU_SOURCE["_GNU_SOURCE"]
    class beacons_v2_beacon_c__GNU_SOURCE fn;
    beacons_v2_beacon_c --> beacons_v2_beacon_c__GNU_SOURCE
    beacons_v2_beacon_c_MAX_PEERS["MAX_PEERS"]
    class beacons_v2_beacon_c_MAX_PEERS fn;
    beacons_v2_beacon_c --> beacons_v2_beacon_c_MAX_PEERS
    gopher_c2_py["gopher_c2.py (py)"]
    class gopher_c2_py mod;
    gopher_c2_py_encrypt_data["encrypt_data"]
    class gopher_c2_py_encrypt_data fn;
    gopher_c2_py --> gopher_c2_py_encrypt_data
    gopher_c2_py_decrypt_data["decrypt_data"]
    class gopher_c2_py_decrypt_data fn;
    gopher_c2_py --> gopher_c2_py_decrypt_data
    gopher_c2_py_handle_client["handle_client"]
    class gopher_c2_py_handle_client fn;
    gopher_c2_py --> gopher_c2_py_handle_client
    gopher_c2_py_main["main"]
    class gopher_c2_py_main fn;
    gopher_c2_py --> gopher_c2_py_main
    gopher_c2_py_command_injector["command_injector"]
    class gopher_c2_py_command_injector fn;
    gopher_c2_py --> gopher_c2_py_command_injector
    cJSON_c["cJSON.c (c)"]
    class cJSON_c mod;
    cJSON_c_internal_hooks["internal_hooks"]
    class cJSON_c_internal_hooks cls;
    cJSON_c --> cJSON_c_internal_hooks
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    include_cJSON_c["cJSON.c (c)"]
    class include_cJSON_c mod;
    include_cJSON_c_internal_hooks["internal_hooks"]
    class include_cJSON_c_internal_hooks cls;
    include_cJSON_c --> include_cJSON_c_internal_hooks
    include_cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class include_cJSON_c_CJSON_PUBLIC fn;
    include_cJSON_c --> include_cJSON_c_CJSON_PUBLIC
    include_cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class include_cJSON_c_CJSON_PUBLIC fn;
    include_cJSON_c --> include_cJSON_c_CJSON_PUBLIC
    include_cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class include_cJSON_c_CJSON_PUBLIC fn;
    include_cJSON_c --> include_cJSON_c_CJSON_PUBLIC
    include_cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class include_cJSON_c_CJSON_PUBLIC fn;
    include_cJSON_c --> include_cJSON_c_CJSON_PUBLIC
    tests_test_c2_server_py["test_c2_server.py (py)"]
    class tests_test_c2_server_py mod;
    tests_test_c2_server_py_make_state["make_state"]
    class tests_test_c2_server_py_make_state fn;
    tests_test_c2_server_py --> tests_test_c2_server_py_make_state
    tests_test_c2_server_py_test_get_command_empty["test_get_command_empty"]
    class tests_test_c2_server_py_test_get_command_empty fn;
    tests_test_c2_server_py --> tests_test_c2_server_py_test_get_command_empty
    tests_test_c2_server_py_test_get_command_queued["test_get_command_queued"]
    class tests_test_c2_server_py_test_get_command_queued fn;
    tests_test_c2_server_py --> tests_test_c2_server_py_test_get_command_queued
    tests_test_c2_server_py_test_report_writes_log["test_report_writes_log"]
    class tests_test_c2_server_py_test_report_writes_log fn;
    tests_test_c2_server_py --> tests_test_c2_server_py_test_report_writes_log
    tests_test_c2_server_py_test_bof_not_found["test_bof_not_found"]
    class tests_test_c2_server_py_test_bof_not_found fn;
    tests_test_c2_server_py --> tests_test_c2_server_py_test_bof_not_found
    tests_test_crypto_py["test_crypto.py (py)"]
    class tests_test_crypto_py mod;
    tests_test_crypto_py_compile_harness["compile_harness"]
    class tests_test_crypto_py_compile_harness fn;
    tests_test_crypto_py --> tests_test_crypto_py_compile_harness
    tests_test_crypto_py_run["run"]
    class tests_test_crypto_py_run fn;
    tests_test_crypto_py --> tests_test_crypto_py_run
    tests_test_crypto_py_test_short["test_short"]
    class tests_test_crypto_py_test_short fn;
    tests_test_crypto_py --> tests_test_crypto_py_test_short
    tests_test_crypto_py_test_block_boundary["test_block_boundary"]
    class tests_test_crypto_py_test_block_boundary fn;
    tests_test_crypto_py --> tests_test_crypto_py_test_block_boundary
    tests_test_crypto_py_test_longer_than_block["test_longer_than_block"]
    class tests_test_crypto_py_test_longer_than_block fn;
    tests_test_crypto_py --> tests_test_crypto_py_test_longer_than_block
    beacons_v3_beacon_c["beacon.c (c)"]
    class beacons_v3_beacon_c mod;
    beacons_v3_beacon_c_infrastructure["infrastructure"]
    class beacons_v3_beacon_c_infrastructure fn;
    beacons_v3_beacon_c --> beacons_v3_beacon_c_infrastructure
    beacons_v3_beacon_c_compute_primes["compute_primes"]
    class beacons_v3_beacon_c_compute_primes fn;
    beacons_v3_beacon_c --> beacons_v3_beacon_c_compute_primes
    beacons_v3_beacon_c_evasive_sleep["evasive_sleep"]
    class beacons_v3_beacon_c_evasive_sleep fn;
    beacons_v3_beacon_c --> beacons_v3_beacon_c_evasive_sleep
    beacons_v3_beacon_c_report_result["report_result"]
    class beacons_v3_beacon_c_report_result fn;
    beacons_v3_beacon_c --> beacons_v3_beacon_c_report_result
    beacons_v3_beacon_c_execute_command["execute_command"]
    class beacons_v3_beacon_c_execute_command fn;
    beacons_v3_beacon_c --> beacons_v3_beacon_c_execute_command
    beacons_v1_beacon_c["beacon.c (c)"]
    class beacons_v1_beacon_c mod;
    beacons_v1_beacon_c_report_result["report_result"]
    class beacons_v1_beacon_c_report_result fn;
    beacons_v1_beacon_c --> beacons_v1_beacon_c_report_result
    beacons_v1_beacon_c_execute_command["execute_command"]
    class beacons_v1_beacon_c_execute_command fn;
    beacons_v1_beacon_c --> beacons_v1_beacon_c_execute_command
    beacons_v1_beacon_c_main["main"]
    class beacons_v1_beacon_c_main fn;
    beacons_v1_beacon_c --> beacons_v1_beacon_c_main
    beacons_v1_beacon_c__GNU_SOURCE["_GNU_SOURCE"]
    class beacons_v1_beacon_c__GNU_SOURCE fn;
    beacons_v1_beacon_c --> beacons_v1_beacon_c__GNU_SOURCE
    include_config_c["config.c (c)"]
    class include_config_c mod;
    include_config_c_slurp["slurp"]
    class include_config_c_slurp fn;
    include_config_c --> include_config_c_slurp
    include_config_c_skip_ws["skip_ws"]
    class include_config_c_skip_ws fn;
    include_config_c --> include_config_c_skip_ws
    include_config_c_read_string["read_string"]
    class include_config_c_read_string fn;
    include_config_c --> include_config_c_read_string
    include_config_c_read_int["read_int"]
    class include_config_c_read_int fn;
    include_config_c --> include_config_c_read_int
    include_config_c_read_bool["read_bool"]
    class include_config_c_read_bool fn;
    include_config_c --> include_config_c_read_bool
    tests_test_config_py["test_config.py (py)"]
    class tests_test_config_py mod;
    tests_test_config_py_compile_harness["compile_harness"]
    class tests_test_config_py_compile_harness fn;
    tests_test_config_py --> tests_test_config_py_compile_harness
    tests_test_config_py_run_harness["run_harness"]
    class tests_test_config_py_run_harness fn;
    tests_test_config_py --> tests_test_config_py_run_harness
    tests_test_config_py_test_default_load["test_default_load"]
    class tests_test_config_py_test_default_load fn;
    tests_test_config_py --> tests_test_config_py_test_default_load
    tests_test_config_py_test_overrides["test_overrides"]
    class tests_test_config_py_test_overrides fn;
    tests_test_config_py --> tests_test_config_py_test_overrides
    tests_test_config_py_test_missing_file["test_missing_file"]
    class tests_test_config_py_test_missing_file fn;
    tests_test_config_py --> tests_test_config_py_test_missing_file
    tests_test_install_deploy_py["test_install_deploy.py (py)"]
    class tests_test_install_deploy_py mod;
    tests_test_install_deploy_py_make_all["make_all"]
    class tests_test_install_deploy_py_make_all fn;
    tests_test_install_deploy_py --> tests_test_install_deploy_py_make_all
    tests_test_install_deploy_py_run_beacon["run_beacon"]
    class tests_test_install_deploy_py_run_beacon fn;
    tests_test_install_deploy_py --> tests_test_install_deploy_py_run_beacon
    tests_test_install_deploy_py_test_build_beacon_lands_alongside_config["test_build_beacon_lands_alongside_config"]
    class tests_test_install_deploy_py_test_build_beacon_lands_alongside_config fn;
    tests_test_install_deploy_py --> tests_test_install_deploy_py_test_build_beacon_lands_alongside_config
    tests_test_install_deploy_py_test_staged_files_have_correct_modes["test_staged_files_have_correct_modes"]
    class tests_test_install_deploy_py_test_staged_files_have_correct_modes fn;
    tests_test_install_deploy_py --> tests_test_install_deploy_py_test_staged_files_have_correct_modes
    tests_test_install_deploy_py_test_staged_beacon_runs_from_any_cwd["test_staged_beacon_runs_from_any_cwd"]
    class tests_test_install_deploy_py_test_staged_beacon_runs_from_any_cwd fn;
    tests_test_install_deploy_py --> tests_test_install_deploy_py_test_staged_beacon_runs_from_any_cwd
    tests_test_beacon_build_py["test_beacon_build.py (py)"]
    class tests_test_beacon_build_py mod;
    tests_test_beacon_build_py_have_headers["have_headers"]
    class tests_test_beacon_build_py_have_headers fn;
    tests_test_beacon_build_py --> tests_test_beacon_build_py_have_headers
    tests_test_beacon_build_py_compile_beacon["compile_beacon"]
    class tests_test_beacon_build_py_compile_beacon fn;
    tests_test_beacon_build_py --> tests_test_beacon_build_py_compile_beacon
    tests_test_beacon_build_py_inspect_binary["inspect_binary"]
    class tests_test_beacon_build_py_inspect_binary fn;
    tests_test_beacon_build_py --> tests_test_beacon_build_py_inspect_binary
    tests_test_beacon_build_py_test_beacon_compiles_and_links["test_beacon_compiles_and_links"]
    class tests_test_beacon_build_py_test_beacon_compiles_and_links fn;
    tests_test_beacon_build_py --> tests_test_beacon_build_py_test_beacon_compiles_and_links
    tests_test_beacon_build_py_test_beacon_exposes_bof_api["test_beacon_exposes_bof_api"]
    class tests_test_beacon_build_py_test_beacon_exposes_bof_api fn;
    tests_test_beacon_build_py --> tests_test_beacon_build_py_test_beacon_exposes_bof_api
    tests_test_bof_compile_py["test_bof_compile.py (py)"]
    class tests_test_bof_compile_py mod;
    tests_test_bof_compile_py_compile_bof["compile_bof"]
    class tests_test_bof_compile_py_compile_bof fn;
    tests_test_bof_compile_py --> tests_test_bof_compile_py_compile_bof
    tests_test_bof_compile_py_inspect_symbols["inspect_symbols"]
    class tests_test_bof_compile_py_inspect_symbols fn;
    tests_test_bof_compile_py --> tests_test_bof_compile_py_inspect_symbols
    tests_test_bof_compile_py_test_compile_all["test_compile_all"]
    class tests_test_bof_compile_py_test_compile_all fn;
    tests_test_bof_compile_py --> tests_test_bof_compile_py_test_compile_all
    tests_test_bof_compile_py_test_export_go["test_export_go"]
    class tests_test_bof_compile_py_test_export_go fn;
    tests_test_bof_compile_py --> tests_test_bof_compile_py_test_export_go
    tests_test_bof_compile_py_test_unresolved_beacon_api["test_unresolved_beacon_api"]
    class tests_test_bof_compile_py_test_unresolved_beacon_api fn;
    tests_test_bof_compile_py --> tests_test_bof_compile_py_test_unresolved_beacon_api
    include_config_py_py["config_py.py (py)"]
    class include_config_py_py mod;
    include_config_py_py__deep_merge["_deep_merge"]
    class include_config_py_py__deep_merge fn;
    include_config_py_py --> include_config_py_py__deep_merge
    include_config_py_py_load_config["load_config"]
    class include_config_py_py_load_config fn;
    include_config_py_py --> include_config_py_py_load_config
    include_beacon_common_h["beacon_common.h (h)"]
    class include_beacon_common_h mod;
    include_beacon_common_h_BEACON_COMMON_H["BEACON_COMMON_H"]
    class include_beacon_common_h_BEACON_COMMON_H fn;
    include_beacon_common_h --> include_beacon_common_h_BEACON_COMMON_H
    include_beacon_common_h__GNU_SOURCE["_GNU_SOURCE"]
    class include_beacon_common_h__GNU_SOURCE fn;
    include_beacon_common_h --> include_beacon_common_h__GNU_SOURCE
    include_beacon_common_h_BSB_OUTPUT_BUFFER_DEFAULT["BSB_OUTPUT_BUFFER_DEFAULT"]
    class include_beacon_common_h_BSB_OUTPUT_BUFFER_DEFAULT fn;
    include_beacon_common_h --> include_beacon_common_h_BSB_OUTPUT_BUFFER_DEFAULT
    include_beacon_common_h_BSB_OUTPUT_TRUNCATION_MARKER["BSB_OUTPUT_TRUNCATION_MARKER"]
    class include_beacon_common_h_BSB_OUTPUT_TRUNCATION_MARKER fn;
    include_beacon_common_h --> include_beacon_common_h_BSB_OUTPUT_TRUNCATION_MARKER
    tests_crypto_harness_c["crypto_harness.c (c)"]
    class tests_crypto_harness_c mod;
    tests_crypto_harness_c_hex_to_bytes["hex_to_bytes"]
    class tests_crypto_harness_c_hex_to_bytes fn;
    tests_crypto_harness_c --> tests_crypto_harness_c_hex_to_bytes
    tests_crypto_harness_c_main["main"]
    class tests_crypto_harness_c_main fn;
    tests_crypto_harness_c --> tests_crypto_harness_c_main
    tests_config_harness_c["config_harness.c (c)"]
    class tests_config_harness_c mod;
    tests_config_harness_c_main["main"]
    class tests_config_harness_c_main fn;
    tests_config_harness_c --> tests_config_harness_c_main
    bof_include_beacon_api_h["beacon_api.h (h)"]
    class bof_include_beacon_api_h mod;
    bof_include_beacon_api_h_BSB_BOF_BEACON_API_H["BSB_BOF_BEACON_API_H"]
    class bof_include_beacon_api_h_BSB_BOF_BEACON_API_H fn;
    bof_include_beacon_api_h --> bof_include_beacon_api_h_BSB_BOF_BEACON_API_H
    bof_include_beacon_api_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_include_beacon_api_h_CALLBACK_OUTPUT fn;
    bof_include_beacon_api_h --> bof_include_beacon_api_h_CALLBACK_OUTPUT
    bof_include_beacon_api_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class bof_include_beacon_api_h_CALLBACK_ERROR fn;
    bof_include_beacon_api_h --> bof_include_beacon_api_h_CALLBACK_ERROR
    bof_include_beacon_api_h_CALLBACK_OUTPUT_OEM["CALLBACK_OUTPUT_OEM"]
    class bof_include_beacon_api_h_CALLBACK_OUTPUT_OEM fn;
    bof_include_beacon_api_h --> bof_include_beacon_api_h_CALLBACK_OUTPUT_OEM
    include_aes_cfb_c["aes_cfb.c (c)"]
    class include_aes_cfb_c mod;
    include_aes_cfb_c_aes256_cfb_encrypt["aes256_cfb_encrypt"]
    class include_aes_cfb_c_aes256_cfb_encrypt fn;
    include_aes_cfb_c --> include_aes_cfb_c_aes256_cfb_encrypt
    include_aes_cfb_c_aes256_cfb_decrypt["aes256_cfb_decrypt"]
    class include_aes_cfb_c_aes256_cfb_decrypt fn;
    include_aes_cfb_c --> include_aes_cfb_c_aes256_cfb_decrypt
    aes_c["aes.c (c)"]
    class aes_c mod;
    aes_c_getSBoxValue["getSBoxValue"]
    class aes_c_getSBoxValue fn;
    aes_c --> aes_c_getSBoxValue
    aes_c_getSBoxInvert["getSBoxInvert"]
    class aes_c_getSBoxInvert fn;
    aes_c --> aes_c_getSBoxInvert
    aes_c_Td0["Td0"]
    class aes_c_Td0 fn;
    aes_c --> aes_c_Td0
    aes_c_Td1["Td1"]
    class aes_c_Td1 fn;
    aes_c --> aes_c_Td1
    aes_c_Td2["Td2"]
    class aes_c_Td2 fn;
    aes_c --> aes_c_Td2
    include_aes_c["aes.c (c)"]
    class include_aes_c mod;
    include_aes_c___attribute__["__attribute__"]
    class include_aes_c___attribute__ fn;
    include_aes_c --> include_aes_c___attribute__
    include_aes_c___attribute__["__attribute__"]
    class include_aes_c___attribute__ fn;
    include_aes_c --> include_aes_c___attribute__
    include_aes_c___attribute__["__attribute__"]
    class include_aes_c___attribute__ fn;
    include_aes_c --> include_aes_c___attribute__
    include_aes_c___attribute__["__attribute__"]
    class include_aes_c___attribute__ fn;
    include_aes_c --> include_aes_c___attribute__
    include_aes_c___attribute__["__attribute__"]
    class include_aes_c___attribute__ fn;
    include_aes_c --> include_aes_c___attribute__
    bof_suid_enum_bof_c["bof.c (c)"]
    class bof_suid_enum_bof_c mod;
    bof_suid_enum_bof_c_linux_stat["linux_stat"]
    class bof_suid_enum_bof_c_linux_stat cls;
    bof_suid_enum_bof_c --> bof_suid_enum_bof_c_linux_stat
    bof_suid_enum_bof_c_linux_dirent64["linux_dirent64"]
    class bof_suid_enum_bof_c_linux_dirent64 cls;
    bof_suid_enum_bof_c --> bof_suid_enum_bof_c_linux_dirent64
    bof_suid_enum_bof_c_flush_output["flush_output"]
    class bof_suid_enum_bof_c_flush_output fn;
    bof_suid_enum_bof_c --> bof_suid_enum_bof_c_flush_output
    bof_suid_enum_bof_c_emit["emit"]
    class bof_suid_enum_bof_c_emit fn;
    bof_suid_enum_bof_c --> bof_suid_enum_bof_c_emit
    bof_suid_enum_bof_c_format_mode["format_mode"]
    class bof_suid_enum_bof_c_format_mode fn;
    bof_suid_enum_bof_c --> bof_suid_enum_bof_c_format_mode
    aes_h["aes.h (h)"]
    class aes_h mod;
    aes_h_AES_ctx["AES_ctx"]
    class aes_h_AES_ctx cls;
    aes_h --> aes_h_AES_ctx
    aes_h__AES_H_["_AES_H_"]
    class aes_h__AES_H_ fn;
    aes_h --> aes_h__AES_H_
    aes_h_CBC["CBC"]
    class aes_h_CBC fn;
    aes_h --> aes_h_CBC
    aes_h_ECB["ECB"]
    class aes_h_ECB fn;
    aes_h --> aes_h_ECB
    aes_h_CTR["CTR"]
    class aes_h_CTR fn;
    aes_h --> aes_h_CTR
    include_aes_h["aes.h (h)"]
    class include_aes_h mod;
    include_aes_h_AES_ctx["AES_ctx"]
    class include_aes_h_AES_ctx cls;
    include_aes_h --> include_aes_h_AES_ctx
    include_aes_h__AES_H_["_AES_H_"]
    class include_aes_h__AES_H_ fn;
    include_aes_h --> include_aes_h__AES_H_
    include_aes_h_CBC["CBC"]
    class include_aes_h_CBC fn;
    include_aes_h --> include_aes_h_CBC
    include_aes_h_ECB["ECB"]
    class include_aes_h_ECB fn;
    include_aes_h --> include_aes_h_ECB
    include_aes_h_CTR["CTR"]
    class include_aes_h_CTR fn;
    include_aes_h --> include_aes_h_CTR
    include_config_h["config.h (h)"]
    class include_config_h mod;
    include_config_h_BSB_CONFIG_H["BSB_CONFIG_H"]
    class include_config_h_BSB_CONFIG_H fn;
    include_config_h --> include_config_h_BSB_CONFIG_H
    include_config_h_BSB_CONFIG_PATH_DEFAULT["BSB_CONFIG_PATH_DEFAULT"]
    class include_config_h_BSB_CONFIG_PATH_DEFAULT fn;
    include_config_h --> include_config_h_BSB_CONFIG_PATH_DEFAULT
    include_config_h_BSB_CONFIG_PATH_ENV["BSB_CONFIG_PATH_ENV"]
    class include_config_h_BSB_CONFIG_PATH_ENV fn;
    include_config_h --> include_config_h_BSB_CONFIG_PATH_ENV
    include_config_h_BSB_MAX_URL["BSB_MAX_URL"]
    class include_config_h_BSB_MAX_URL fn;
    include_config_h --> include_config_h_BSB_MAX_URL
    include_config_h_BSB_MAX_URI["BSB_MAX_URI"]
    class include_config_h_BSB_MAX_URI fn;
    include_config_h --> include_config_h_BSB_MAX_URI
    beacon_h["beacon.h (h)"]
    class beacon_h mod;
    beacon_h_BEACON_API_H["BEACON_API_H"]
    class beacon_h_BEACON_API_H fn;
    beacon_h --> beacon_h_BEACON_API_H
    beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class beacon_h_CALLBACK_OUTPUT fn;
    beacon_h --> beacon_h_CALLBACK_OUTPUT
    beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class beacon_h_CALLBACK_ERROR fn;
    beacon_h --> beacon_h_CALLBACK_ERROR
    beacon_h_CALLBACK_OUTPUT_OEM["CALLBACK_OUTPUT_OEM"]
    class beacon_h_CALLBACK_OUTPUT_OEM fn;
    beacon_h --> beacon_h_CALLBACK_OUTPUT_OEM
    include_beacon_h["beacon.h (h)"]
    class include_beacon_h mod;
    include_beacon_h_BEACON_API_H["BEACON_API_H"]
    class include_beacon_h_BEACON_API_H fn;
    include_beacon_h --> include_beacon_h_BEACON_API_H
    include_beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class include_beacon_h_CALLBACK_OUTPUT fn;
    include_beacon_h --> include_beacon_h_CALLBACK_OUTPUT
    include_beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class include_beacon_h_CALLBACK_ERROR fn;
    include_beacon_h --> include_beacon_h_CALLBACK_ERROR
    include_beacon_h_CALLBACK_OUTPUT_OEM["CALLBACK_OUTPUT_OEM"]
    class include_beacon_h_CALLBACK_OUTPUT_OEM fn;
    include_beacon_h --> include_beacon_h_CALLBACK_OUTPUT_OEM
    bof_is_sudo_bof_c["bof.c (c)"]
    class bof_is_sudo_bof_c mod;
    bof_is_sudo_bof_c_user_in_group["user_in_group"]
    class bof_is_sudo_bof_c_user_in_group fn;
    bof_is_sudo_bof_c --> bof_is_sudo_bof_c_user_in_group
    bof_is_sudo_bof_c_go["go"]
    class bof_is_sudo_bof_c_go fn;
    bof_is_sudo_bof_c --> bof_is_sudo_bof_c_go
    bof_userenum_bof_c["bof.c (c)"]
    class bof_userenum_bof_c mod;
    bof_userenum_bof_c_user_in_member_list["user_in_member_list"]
    class bof_userenum_bof_c_user_in_member_list fn;
    bof_userenum_bof_c --> bof_userenum_bof_c_user_in_member_list
    bof_userenum_bof_c_go["go"]
    class bof_userenum_bof_c_go fn;
    bof_userenum_bof_c --> bof_userenum_bof_c_go
    bof_cat_bof_c["bof.c (c)"]
    class bof_cat_bof_c mod;
    bof_cat_bof_c_go["go"]
    class bof_cat_bof_c_go fn;
    bof_cat_bof_c --> bof_cat_bof_c_go
    bof_whoami_bof_c["bof.c (c)"]
    class bof_whoami_bof_c mod;
    bof_whoami_bof_c_go["go"]
    class bof_whoami_bof_c_go fn;
    bof_whoami_bof_c --> bof_whoami_bof_c_go
    bof_include_syscalls_h["syscalls.h (h)"]
    class bof_include_syscalls_h mod;
    bof_include_syscalls_h_syscall0["syscall0"]
    class bof_include_syscalls_h_syscall0 fn;
    bof_include_syscalls_h --> bof_include_syscalls_h_syscall0
    bof_include_syscalls_h_syscall1["syscall1"]
    class bof_include_syscalls_h_syscall1 fn;
    bof_include_syscalls_h --> bof_include_syscalls_h_syscall1
    bof_include_syscalls_h_syscall2["syscall2"]
    class bof_include_syscalls_h_syscall2 fn;
    bof_include_syscalls_h --> bof_include_syscalls_h_syscall2
    bof_include_syscalls_h_syscall3["syscall3"]
    class bof_include_syscalls_h_syscall3 fn;
    bof_include_syscalls_h --> bof_include_syscalls_h_syscall3
    bof_include_syscalls_h_syscall4["syscall4"]
    class bof_include_syscalls_h_syscall4 fn;
    bof_include_syscalls_h --> bof_include_syscalls_h_syscall4
    cJSON_h["cJSON.h (h)"]
    class cJSON_h mod;
    cJSON_h_cJSON["cJSON"]
    class cJSON_h_cJSON cls;
    cJSON_h --> cJSON_h_cJSON
    cJSON_h_cJSON_Hooks["cJSON_Hooks"]
    class cJSON_h_cJSON_Hooks cls;
    cJSON_h --> cJSON_h_cJSON_Hooks
    cJSON_h_cJSON__h["cJSON__h"]
    class cJSON_h_cJSON__h fn;
    cJSON_h --> cJSON_h_cJSON__h
    cJSON_h___WINDOWS__["__WINDOWS__"]
    class cJSON_h___WINDOWS__ fn;
    cJSON_h --> cJSON_h___WINDOWS__
    cJSON_h_CJSON_CDECL["CJSON_CDECL"]
    class cJSON_h_CJSON_CDECL fn;
    cJSON_h --> cJSON_h_CJSON_CDECL
    include_cJSON_h["cJSON.h (h)"]
    class include_cJSON_h mod;
    include_cJSON_h_cJSON["cJSON"]
    class include_cJSON_h_cJSON cls;
    include_cJSON_h --> include_cJSON_h_cJSON
    include_cJSON_h_cJSON_Hooks["cJSON_Hooks"]
    class include_cJSON_h_cJSON_Hooks cls;
    include_cJSON_h --> include_cJSON_h_cJSON_Hooks
    include_cJSON_h_cJSON__h["cJSON__h"]
    class include_cJSON_h_cJSON__h fn;
    include_cJSON_h --> include_cJSON_h_cJSON__h
    include_cJSON_h___WINDOWS__["__WINDOWS__"]
    class include_cJSON_h___WINDOWS__ fn;
    include_cJSON_h --> include_cJSON_h___WINDOWS__
    include_cJSON_h_CJSON_CDECL["CJSON_CDECL"]
    class include_cJSON_h_CJSON_CDECL fn;
    include_cJSON_h --> include_cJSON_h_CJSON_CDECL
    bof_c["bof.c (c)"]
    class bof_c mod;
    bof_c___attribute__["__attribute__"]
    class bof_c___attribute__ fn;
    bof_c --> bof_c___attribute__
    include_aes_cfb_h["aes_cfb.h (h)"]
    class include_aes_cfb_h mod;
    include_aes_cfb_h_BSB_AES_CFB_H["BSB_AES_CFB_H"]
    class include_aes_cfb_h_BSB_AES_CFB_H fn;
    include_aes_cfb_h --> include_aes_cfb_h_BSB_AES_CFB_H
    app_py["app.py (py)"]
    class app_py mod;
    bof_is_sudo_is_sudo_c["is_sudo.c (c)"]
    class bof_is_sudo_is_sudo_c mod;
    bof_is_sudo_is_sudo_c_syscall3["syscall3"]
    class bof_is_sudo_is_sudo_c_syscall3 fn;
    bof_is_sudo_is_sudo_c --> bof_is_sudo_is_sudo_c_syscall3
    bof_is_sudo_is_sudo_c_syscall1["syscall1"]
    class bof_is_sudo_is_sudo_c_syscall1 fn;
    bof_is_sudo_is_sudo_c --> bof_is_sudo_is_sudo_c_syscall1
    bof_is_sudo_is_sudo_c_strcmp["strcmp"]
    class bof_is_sudo_is_sudo_c_strcmp fn;
    bof_is_sudo_is_sudo_c --> bof_is_sudo_is_sudo_c_strcmp
    bof_is_sudo_is_sudo_c_get_username_from_uid["get_username_from_uid"]
    class bof_is_sudo_is_sudo_c_get_username_from_uid fn;
    bof_is_sudo_is_sudo_c --> bof_is_sudo_is_sudo_c_get_username_from_uid
    bof_is_sudo_is_sudo_c_go["go"]
    class bof_is_sudo_is_sudo_c_go fn;
    bof_is_sudo_is_sudo_c --> bof_is_sudo_is_sudo_c_go
    issudo_c["issudo.c (c)"]
    class issudo_c mod;
    issudo_c_syscall3["syscall3"]
    class issudo_c_syscall3 fn;
    issudo_c --> issudo_c_syscall3
    issudo_c_syscall1["syscall1"]
    class issudo_c_syscall1 fn;
    issudo_c --> issudo_c_syscall1
    issudo_c_strcmp["strcmp"]
    class issudo_c_strcmp fn;
    issudo_c --> issudo_c_strcmp
    issudo_c_get_username_from_uid["get_username_from_uid"]
    class issudo_c_get_username_from_uid fn;
    issudo_c --> issudo_c_get_username_from_uid
    issudo_c_go["go"]
    class issudo_c_go fn;
    issudo_c --> issudo_c_go
    bof_whoami_whoami_c["whoami.c (c)"]
    class bof_whoami_whoami_c mod;
    bof_whoami_whoami_c_syscall3["syscall3"]
    class bof_whoami_whoami_c_syscall3 fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_syscall3
    bof_whoami_whoami_c_syscall1["syscall1"]
    class bof_whoami_whoami_c_syscall1 fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_syscall1
    bof_whoami_whoami_c_go["go"]
    class bof_whoami_whoami_c_go fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_go
    bof_whoami_whoami_c_NULL["NULL"]
    class bof_whoami_whoami_c_NULL fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_NULL
    bof_whoami_whoami_c_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_whoami_whoami_c_CALLBACK_OUTPUT fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_CALLBACK_OUTPUT
    bof_userenum_userenum_c["userenum.c (c)"]
    class bof_userenum_userenum_c mod;
    bof_userenum_userenum_c_syscall3["syscall3"]
    class bof_userenum_userenum_c_syscall3 fn;
    bof_userenum_userenum_c --> bof_userenum_userenum_c_syscall3
    bof_userenum_userenum_c_strcmp["strcmp"]
    class bof_userenum_userenum_c_strcmp fn;
    bof_userenum_userenum_c --> bof_userenum_userenum_c_strcmp
    bof_userenum_userenum_c_go["go"]
    class bof_userenum_userenum_c_go fn;
    bof_userenum_userenum_c --> bof_userenum_userenum_c_go
    bof_userenum_userenum_c_NULL["NULL"]
    class bof_userenum_userenum_c_NULL fn;
    bof_userenum_userenum_c --> bof_userenum_userenum_c_NULL
    bof_userenum_userenum_c_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_userenum_userenum_c_CALLBACK_OUTPUT fn;
    bof_userenum_userenum_c --> bof_userenum_userenum_c_CALLBACK_OUTPUT
    bof_cat_cat_c["cat.c (c)"]
    class bof_cat_cat_c mod;
    bof_cat_cat_c_syscall3["syscall3"]
    class bof_cat_cat_c_syscall3 fn;
    bof_cat_cat_c --> bof_cat_cat_c_syscall3
    bof_cat_cat_c_go["go"]
    class bof_cat_cat_c_go fn;
    bof_cat_cat_c --> bof_cat_cat_c_go
    bof_cat_cat_c_NULL["NULL"]
    class bof_cat_cat_c_NULL fn;
    bof_cat_cat_c --> bof_cat_cat_c_NULL
    bof_cat_cat_c_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_cat_cat_c_CALLBACK_OUTPUT fn;
    bof_cat_cat_c --> bof_cat_cat_c_CALLBACK_OUTPUT
    bof_cat_cat_c_SYS_openat["SYS_openat"]
    class bof_cat_cat_c_SYS_openat fn;
    bof_cat_cat_c --> bof_cat_cat_c_SYS_openat
    bof_build_sh["build.sh (sh)"]
    class bof_build_sh mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
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
    beacon5_c -.->|imports| ext_arpa_inet_h
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
```

---

## Architecture Reference

### C (29 files)

#### `aes.c`
**Path:** `aes.c`

**Functions:**
- `getSBoxValue` (line 12) - *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h> define Nb 4 define KEYLEN_256 32 define RKLENGTH (4 * (...*
- `getSBoxInvert` (line 34)
- `Td0` (line 56)
- `Td1` (line 58)
- `Td2` (line 59)
- `Td3` (line 60)
- `Td4` (line 61)
- `KeyExpansion` (line 166) - *static uint8_t getSBoxValue(uint8_t num) { return sbox[num]; }  define getSBoxValue(num) (sbox[(num)]) This function produces Nb(Nr+1) round keys. ...*
- `AES_init_ctx` (line 238)
- `AES_init_ctx_iv` (line 244) - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249)
- `AddRoundKey` (line 257) - *endif This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row...*
- `xtime` (line 313)
- `MixColumns` (line 320) - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary...*
- `InvMixColumns` (line 370) - *static uint8_t getSBoxInvert(uint8_t num) { return rsbox[num]; }  define getSBoxInvert(num) (rsbox[(num)]) MixColumns function mixes the columns of...*
- `InvSubBytes` (line 391) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402)
- `Cipher` (line 433) - *endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); }  } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB...*
- `AES_ECB_decrypt` (line 495)
- `XorWithIv` (line 510) - *endif // #if defined(ECB) && (ECB == 1) if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520)
- `AES_CBC_decrypt_buffer` (line 535)
- `AES_CTR_xcrypt_buffer` (line 558) - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; }  }  #endif // #if defined(CBC) && (CBC == 1)    #if def...*

**Macros:**
- `Nb` (line 4)
- `KEYLEN_256` (line 6)
- `RKLENGTH` (line 10)
- `BLOCKLEN` (line 11)
- `Nb` (line 67)
- `Nk` (line 70)
- `Nr` (line 71)
- `Nk` (line 73)
- `Nr` (line 74)
- `Nk` (line 76)
- `Nr` (line 77)
- `MULTIPLY_AS_A_FUNCTION` (line 84)
- `getSBoxValue` (line 163)
- `Multiply` (line 349)
- `getSBoxInvert` (line 365)

#### `beacon3.c`
**Path:** `beacon3.c`

**Functions:**
- `__attribute__` (line 140)
- `BeaconPrintf` (line 193) - *=== BEACON API ===*
- `BeaconOutput` (line 205)
- `create_trampoline` (line 217) - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 253) - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 268)
- `WriteMemoryCallback` (line 300) - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 317) - *=== HTTPS REQUEST ===*
- `base64_encode` (line 406) - *=== BASE64 ===*
- `base64_decode` (line 422)
- `aes256_cfb_encrypt` (line 446) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 473)
- `exec_cmd` (line 504) - *=== EXEC CMD ===*
- `page_align` (line 525) - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 530)
- `get_local_ips` (line 912) - *=== GET LOCAL IPs ===*
- `download_bof` (line 941) - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 963) - *=== RUN BOF AND CAPTURE ===*
- `main` (line 1007) - *=== MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2_URL` (line 32)
- `CLIENT_ID` (line 34)
- `MALEABLE` (line 35)
- `USER_AGENTS_COUNT` (line 36)

**Structs:**
- `MemoryStruct` (line 50) - *=== ESTRUCTURAS ===*

#### `beacon5.c`
**Path:** `beacon5.c`

**Functions:**
- `__attribute__` (line 182)
- `BeaconPrintf` (line 235) - *=== BEACON API ===*
- `BeaconOutput` (line 247)
- `create_trampoline` (line 259) - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 295) - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 310)
- `WriteMemoryCallback` (line 342) - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 359) - *=== HTTPS REQUEST ===*
- `base64_encode` (line 448) - *=== BASE64 ===*
- `base64_decode` (line 464)
- `aes256_cfb_encrypt` (line 488) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 515)
- `exec_cmd` (line 546) - *=== EXEC CMD ===*
- `page_align` (line 567) - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 572)
- `get_local_ips` (line 954) - *=== GET LOCAL IPs ===*
- `download_bof` (line 983) - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 1005) - *=== RUN BOF AND CAPTURE ===*
- `mesh_mark_seen` (line 1049) - *========== UTILIDADES MESH ==========*
- `mesh_is_seen` (line 1057)
- `mesh_add_peer` (line 1069)
- `mesh_cleanup_peers` (line 1094)
- `mesh_send_to_peer` (line 1108) - *========== PROPAGACIÓN MESH ==========*
- `mesh_propagate` (line 1130)
- `mesh_discovery_thread` (line 1157) - *========== DISCOVERY THREAD ==========*
- `mesh_listener_thread` (line 1240) - *========== MESH LISTENER THREAD ==========*
- `mesh_send_message` (line 1416)
- `main` (line 1444) - *=== MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `MAX_PEERS` (line 35)
- `DISCOVERY_PORT` (line 38)
- `DISCOVERY_INTERVAL` (line 39)
- `MAX_TTL` (line 40)
- `MESH_MSG_SIZE` (line 41)
- `C2_URL` (line 42)
- `CLIENT_ID` (line 45)
- `MALEABLE` (line 46)
- `USER_AGENTS_COUNT` (line 47)

**Structs:**
- `MemoryStruct` (line 61) - *=== ESTRUCTURAS ===*

#### `beacon6.c`
**Path:** `beacon6.c`

**Functions:**
- `__attribute__` (line 142)
- `delay_ms` (line 195) - *sleep ofuscated using poll*
- `is_prime` (line 202) - *-- Lógica de números primos (sin cambios esenciales) ---*
- `get_nth_prime_limited` (line 218) - *if (x < 2) return 0; if (x == 2) return 1; if ((x & 1) == 0) return 0; /* even > 2  unsigned int d = 3; while (d * d <= x) { if (x % d == 0) return...*
- `portable_rand_19k_29k` (line 242)
- `BeaconPrintf` (line 255) - *=== BEACON API ===*
- `BeaconOutput` (line 267)
- `create_trampoline` (line 279) - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 315) - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 330)
- `WriteMemoryCallback` (line 362) - *=== CURL WRITE CALLBACK ===*
- `https_request` (line 379) - *=== HTTPS REQUEST ===*
- `base64_encode` (line 468) - *=== BASE64 ===*
- `base64_decode` (line 484)
- `aes256_cfb_encrypt` (line 508) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 535)
- `exec_cmd` (line 566) - *=== EXEC CMD ===*
- `page_align` (line 587) - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 592)
- `get_local_ips` (line 974) - *=== GET LOCAL IPs ===*
- `download_bof` (line 1003) - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 1025) - *=== RUN BOF AND CAPTURE ===*
- `main` (line 1069) - *=== MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2_URL` (line 34)
- `CLIENT_ID` (line 36)
- `MALEABLE` (line 37)
- `USER_AGENTS_COUNT` (line 38)

**Structs:**
- `MemoryStruct` (line 52) - *=== ESTRUCTURAS ===*

#### `beacon_p2p.c`
**Path:** `beacon_p2p.c`

**Functions:**
- `BeaconDataParse` (line 91) - *======================================================================= FUNCIONES DE LA API DE BEACON (para BOFs) =================================...*
- `BeaconDataPtr` (line 96)
- `BeaconDataInt` (line 104)
- `BeaconDataShort` (line 110)
- `BeaconDataLength` (line 116)
- `BeaconDataExtract` (line 120)
- `BeaconPrintf` (line 128)
- `BeaconOutput` (line 141)
- `__attribute__` (line 228)
- `create_trampoline` (line 258)
- `cleanup_trampolines` (line 283)
- `get_or_create_trampoline` (line 296)
- `page_align` (line 317)
- `RunELF` (line 323)
- `WriteMemoryCallback` (line 554)
- `https_request` (line 574)
- `base64_encode` (line 624)
- `base64_decode` (line 640)
- `aes256_cfb_encrypt` (line 653)
- `aes256_cfb_decrypt` (line 680)
- `exec_cmd` (line 712) - *======================================================================= UTILIDADES: ejecutar comandos shell, obtener IPs, etc. ====================...*
- `get_local_ips` (line 728)
- `download_bof` (line 756)
- `run_bof_and_capture` (line 765)
- `add_peer` (line 783) - *======================================================================= FUNCIONES P2P =============================================================...*
- `peer_discovery_thread` (line 806)
- `handle_peer_connection` (line 845)
- `peer_server_thread` (line 915)
- `send_to_peer` (line 934)
- `send_to_c2_or_peer` (line 967)
- `execute_generic_command` (line 996) - *======================================================================= EJECUTOR DE COMANDOS (unificado para shell y BOF) =========================...*
- `main` (line 1031) - *======================================================================= MAIN =======================================================================*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2_URL` (line 37)
- `CLIENT_ID` (line 38)
- `MALEABLE` (line 39)
- `USER_AGENTS_COUNT` (line 40)
- `PEER_DISCOVERY_PORT` (line 41)
- `PEER_TCP_PORT` (line 43)
- `PEER_MAGIC` (line 44)
- `PEER_VERSION` (line 45)
- `BROADCAST_INTERVAL` (line 46)
- `MAX_PEERS` (line 47)

**Structs:**
- `MemoryStruct` (line 549) - *======================================================================= FUNCIONES DE COMUNICACIÓN (HTTPS + BASE64 + AES) ==========================...*

#### `beacon.c`
**Path:** `beacons/v1/beacon.c`

**Functions:**
- `report_result` (line 23) - *This beacon uses exponential backoff on failures to reduce noise when the C2 is unreachable. The backoff resets on the first successful command exc...*
- `execute_command` (line 96)
- `main` (line 145)

**Macros:**
- `_GNU_SOURCE` (line 13)

#### `gopher_beacon.c`
**Path:** `beacons/v1/gopher_beacon.c`

**Functions:**
- `__attribute__` (line 137)
- `BeaconPrintf` (line 190) - *=== BEACON API ===*
- `BeaconOutput` (line 202)
- `create_trampoline` (line 214) - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 250) - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 265)
- `WriteMemoryCallback` (line 297) - *=== CURL WRITE CALLBACK ===*
- `gopher_request` (line 314) - *=== GOPHER REQUEST () ===*
- `base64_encode` (line 377) - *=== BASE64 ===*
- `base64_decode` (line 393)
- `aes256_cfb_encrypt` (line 417) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 444)
- `exec_cmd` (line 475) - *=== EXEC CMD ===*
- `page_align` (line 506) - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 511)
- `get_local_ips` (line 893) - *=== GET LOCAL IPs ===*
- `download_bof` (line 922) - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 950) - *=== RUN BOF AND CAPTURE ===*
- `main` (line 994) - *=== MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2` (line 29)
- `CLIENT_ID` (line 31)
- `MALEABLE` (line 32)
- `USER_AGENTS_COUNT` (line 33)

**Structs:**
- `MemoryStruct` (line 47) - *=== ESTRUCTURAS ===*

#### `beacon.c`
**Path:** `beacons/v2/beacon.c`

**Functions:**
- `report_result` (line 65) - *Mesh functions would be implemented here, but for this refactor we keep the same structure as v1 with mesh stubs. A production mesh implementation ...*
- `execute_command` (line 138)
- `main` (line 187)

**Macros:**
- `_GNU_SOURCE` (line 12)
- `MAX_PEERS` (line 26)
- `DISCOVERY_PORT` (line 28)
- `DISCOVERY_INTERVAL` (line 29)
- `MAX_TTL` (line 30)
- `MESH_MSG_SIZE` (line 31)

#### `beacon.c`
**Path:** `beacons/v3/beacon.c`

**Functions:**
- `infrastructure` (line 7)
- `compute_primes` (line 35)
- `evasive_sleep` (line 45)
- `report_result` (line 51)
- `execute_command` (line 124)
- `main` (line 173)

**Macros:**
- `_GNU_SOURCE` (line 12)

#### `bof.c`
**Path:** `bof/cat/bof.c`

**Functions:**
- `go` (line 14) - *bof/cat/bof.c  Read a file from disk and stream it back through the beacon.  args/alen: a NUL-terminated path string. The beacon's args parser is w...*

#### `cat.c`
**Path:** `bof/cat/cat.c`

**Functions:**
- `syscall3` (line 21) - *Syscalls (ya usadas en whoami/is_sudo) define SYS_openat 257 define SYS_read   0 define SYS_close  3 define AT_FDCWD   -100 Wrappers (copiados de t...*
- `go` (line 30)

**Macros:**
- `NULL` (line 3)
- `CALLBACK_OUTPUT` (line 4)
- `SYS_openat` (line 15)
- `SYS_read` (line 16)
- `SYS_close` (line 17)
- `AT_FDCWD` (line 18)

#### `bof.c`
**Path:** `bof/is_sudo/bof.c`

**Functions:**
- `user_in_group` (line 14) - *bof/is_sudo/bof.c  Check whether the current user is in the sudo or wheel group.  Reads /etc/group, looks for the user's name in the member list of...*
- `go` (line 56)

#### `is_sudo.c`
**Path:** `bof/is_sudo/is_sudo.c`

**Functions:**
- `syscall3` (line 23) - *Syscalls define SYS_openat 257 define SYS_read   0 define SYS_close  3 define SYS_getuid 102 define SYS_getpwuid_r 168  // opcional, pero no lo usa...*
- `syscall1` (line 32)
- `strcmp` (line 44) - *strcmp mínimo (necesario para comparar strings)*
- `get_username_from_uid` (line 53) - *Obtener username desde /etc/passwd (sin libc)*
- `go` (line 108)

**Macros:**
- `NULL` (line 3)
- `CALLBACK_OUTPUT` (line 4)
- `SYS_openat` (line 15)
- `SYS_read` (line 16)
- `SYS_close` (line 17)
- `SYS_getuid` (line 18)
- `SYS_getpwuid_r` (line 19)
- `AT_FDCWD` (line 20)

#### `bof.c`
**Path:** `bof/suid_enum/bof.c`

**Functions:**
- `flush_output` (line 75)
- `emit` (line 82)
- `format_mode` (line 105) - *Format `mode` (a st_mode value) into a 10-char permission * string, like ls -l does.*
- `path_reset` (line 125)
- `path_append` (line 134)
- `path_trim_to` (line 148)
- `walk` (line 158) - *Walk one directory, recursing into subdirectories. `depth` * bounds the recursion so a symlink loop cannot blow the stack.*
- `go` (line 246)

**Macros:**
- `SYS_getdents64` (line 26)
- `SYS_lstat` (line 27)
- `DT_UNKNOWN` (line 30)
- `DT_DIR` (line 31)
- `DT_LNK` (line 32)

**Structs:**
- `linux_stat` (line 35) - *#include "beacon_api.h" #include "syscalls.h"  /* getdents64 syscall number (x86_64) and the dirent layout. #define SYS_getdents64 217 #define SYS_...*
- `linux_dirent64` (line 58) - *getdents64 entry layout (kernel ABI). The d_reclen field tells * us the actual record size since names are variable length.*

#### `bof.c`
**Path:** `bof/userenum/bof.c`

**Functions:**
- `user_in_member_list` (line 51)
- `go` (line 67)

#### `userenum.c`
**Path:** `bof/userenum/userenum.c`

**Functions:**
- `syscall3` (line 21) - *Syscalls define SYS_openat 257 define SYS_read   0 define SYS_close  3 define AT_FDCWD   -100 Wrappers*
- `strcmp` (line 33) - *strcmp mínimo (necesario para comparar strings)*
- `go` (line 40)

**Macros:**
- `NULL` (line 3)
- `CALLBACK_OUTPUT` (line 4)
- `SYS_openat` (line 15)
- `SYS_read` (line 16)
- `SYS_close` (line 17)
- `AT_FDCWD` (line 18)

#### `bof.c`
**Path:** `bof/whoami/bof.c`

**Functions:**
- `go` (line 18) - *BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the * beacon's loader resolves by symbol name.*

#### `whoami.c`
**Path:** `bof/whoami/whoami.c`

**Functions:**
- `syscall3` (line 21) - *Números de syscall (x86_64 Linux) define SYS_openat 257 define SYS_read   0 define SYS_close  3 define SYS_getuid 102 define AT_FDCWD   -100 Syscal...*
- `syscall1` (line 30)
- `go` (line 40)

**Macros:**
- `NULL` (line 2)
- `CALLBACK_OUTPUT` (line 3)
- `SYS_openat` (line 14)
- `SYS_read` (line 15)
- `SYS_close` (line 16)
- `SYS_getuid` (line 17)
- `AT_FDCWD` (line 18)

#### `bof.c`
**Path:** `bof.c`

**Functions:**
- `__attribute__` (line 3) - *bof.c include "beacon.h"  // ← Incluir la API*

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94)
- `CJSON_PUBLIC` (line 99)
- `CJSON_PUBLIC` (line 109)
- `CJSON_PUBLIC` (line 124) - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; }  return item->valuedouble...*
- `case_insensitive_strcmp` (line 134) - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR !=...*
- `internal_malloc` (line 166) - *}  return tolower(*string1) - tolower(*string2); }  typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *...*
- `internal_free` (line 170)
- `internal_realloc` (line 174)
- `cJSON_strdup` (line 188)
- `CJSON_PUBLIC` (line 209)
- `cJSON_New_Item` (line 242) - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; }  /* use realloc only if both free and malloc are used global_hooks.reallo...*
- `get_decimal_point` (line 281) - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->strin...*
- `parse_number` (line 309) - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer;  /*...*
- `ensure` (line 494) - *}  typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool...*
- `update_offset` (line 579) - *p->buffer = NULL;  return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = n...*
- `compare_double` (line 592) - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsi...*
- `print_number` (line 599) - *} buffer_pointer = buffer->buffer + buffer->offset;  buffer->offset += strlen((const char*)buffer_pointer); }  /* securely comparison of floating-p...*
- `parse_hex4` (line 669) - *output_pointer[i] = '.'; continue; }  output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0';  output_buffer->offset += (size_t)length;  ...*
- `utf16_literal_to_utf8` (line 706) - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); }  output_pointer += utf8_length;  return sequence_length;  fail: return 0; }  /* ...*
- `print_string_ptr` (line 957) - *{ input_buffer->hooks.deallocate(output); output = NULL; }  if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buff...*
- `print_string` (line 1079) - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_l...*
- `buffer_skip_whitespace` (line 1093) - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } ...*
- `skip_utf8_bom` (line 1119) - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; }  if (buffer->offset == buffer->length) { buffer...*
- `CJSON_PUBLIC` (line 1133)
- `CJSON_PUBLIC` (line 1235)
- `print` (line 1242) - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315)
- `CJSON_PUBLIC` (line 1320)
- `CJSON_PUBLIC` (line 1351)
- `parse_value` (line 1372) - *return false; }  p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_...*
- `print_value` (line 1427) - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (c...*
- `parse_array` (line 1501) - *return print_string(item, output_buffer);  case cJSON_Array: return print_array(item, output_buffer);  case cJSON_Object: return print_object(item,...*
- `print_array` (line 1599) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an array to text*
- `parse_object` (line 1661) - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buff...*
- `print_object` (line 1780) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an object to text.*
- `get_array_item` (line 1915)
- `CJSON_PUBLIC` (line 1934)
- `get_object_item` (line 1944)
- `CJSON_PUBLIC` (line 1976)
- `CJSON_PUBLIC` (line 1981)
- `CJSON_PUBLIC` (line 1986)
- `suffix_object` (line 1993) - *return get_object_item(object, string, false); }  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...*
- `create_reference` (line 2000) - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; }  /* U...*
- `add_item_to_array` (line 2020)
- `cast_away_const` (line 2066) - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); }  #...*
- `add_item_to_object` (line 2073) - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111)
- `CJSON_PUBLIC` (line 2122)
- `CJSON_PUBLIC` (line 2132)
- `CJSON_PUBLIC` (line 2142)
- `CJSON_PUBLIC` (line 2154)
- `CJSON_PUBLIC` (line 2166)
- `CJSON_PUBLIC` (line 2178)
- `CJSON_PUBLIC` (line 2190)
- `CJSON_PUBLIC` (line 2202)
- `CJSON_PUBLIC` (line 2214)
- `CJSON_PUBLIC` (line 2226)
- `CJSON_PUBLIC` (line 2238)
- `CJSON_PUBLIC` (line 2250)
- `CJSON_PUBLIC` (line 2286)
- `CJSON_PUBLIC` (line 2296)
- `CJSON_PUBLIC` (line 2301)
- `CJSON_PUBLIC` (line 2308)
- `CJSON_PUBLIC` (line 2315)
- `CJSON_PUBLIC` (line 2320)
- `CJSON_PUBLIC` (line 2362)
- `CJSON_PUBLIC` (line 2412)
- `replace_item_in_object` (line 2422)
- `CJSON_PUBLIC` (line 2445)
- `CJSON_PUBLIC` (line 2450)
- `CJSON_PUBLIC` (line 2467)
- `CJSON_PUBLIC` (line 2478)
- `CJSON_PUBLIC` (line 2489)
- `CJSON_PUBLIC` (line 2500)
- `CJSON_PUBLIC` (line 2525)
- `CJSON_PUBLIC` (line 2542)
- `CJSON_PUBLIC` (line 2554)
- `CJSON_PUBLIC` (line 2566)
- `CJSON_PUBLIC` (line 2578)
- `CJSON_PUBLIC` (line 2595)
- `CJSON_PUBLIC` (line 2606)
- `CJSON_PUBLIC` (line 2658)
- `CJSON_PUBLIC` (line 2698)
- `CJSON_PUBLIC` (line 2738)
- `cJSON_Duplicate_rec` (line 2785)
- `skip_oneline_comment` (line 2872)
- `skip_multiline_comment` (line 2885)
- `minify_string` (line 2899)
- `CJSON_PUBLIC` (line 2921)
- `CJSON_PUBLIC` (line 2971)
- `CJSON_PUBLIC` (line 2981)
- `CJSON_PUBLIC` (line 2991)
- `CJSON_PUBLIC` (line 3001)
- `CJSON_PUBLIC` (line 3011)
- `CJSON_PUBLIC` (line 3021)
- `CJSON_PUBLIC` (line 3031)
- `CJSON_PUBLIC` (line 3041)
- `CJSON_PUBLIC` (line 3051)
- `CJSON_PUBLIC` (line 3061)
- `CJSON_PUBLIC` (line 3071)
- `cJSON_ArrayForEach` (line 3157)
- `cJSON_ArrayForEach` (line 3173) - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193)
- `CJSON_PUBLIC` (line 3198)

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28)
- `true` (line 65)
- `false` (line 70)
- `isinf` (line 74)
- `isnan` (line 77)
- `NAN` (line 82)
- `NAN` (line 84)
- `internal_malloc` (line 179)
- `internal_free` (line 180)
- `internal_realloc` (line 181)
- `static_strlen` (line 185)
- `can_read` (line 301)
- `can_access_at_index` (line 303)
- `cannot_access_at_index` (line 304)
- `buffer_at_offset` (line 306)
- `cjson_min` (line 1240)

**Structs:**
- `internal_hooks` (line 157)

#### `gopher_beacon.c`
**Path:** `gopher_beacon.c`

**Functions:**
- `__attribute__` (line 137)
- `BeaconPrintf` (line 190) - *=== BEACON API ===*
- `BeaconOutput` (line 202)
- `create_trampoline` (line 214) - *=== CRATE TRAPOLINE ===*
- `cleanup_trampolines` (line 250) - *=== CLEAN TRAMPOLINE ===*
- `get_or_create_trampoline` (line 265)
- `WriteMemoryCallback` (line 297) - *=== CURL WRITE CALLBACK ===*
- `gopher_request` (line 314) - *=== GOPHER REQUEST () ===*
- `base64_encode` (line 377) - *=== BASE64 ===*
- `base64_decode` (line 393)
- `aes256_cfb_encrypt` (line 417) - *=== AES CFB ===*
- `aes256_cfb_decrypt` (line 444)
- `exec_cmd` (line 475) - *=== EXEC CMD ===*
- `page_align` (line 506) - *=== Función auxiliar: alinear al tamaño de página ===*
- `RunELF` (line 511)
- `get_local_ips` (line 893) - *=== GET LOCAL IPs ===*
- `download_bof` (line 922) - *=== DOWNLOAD BOF ===*
- `run_bof_and_capture` (line 950) - *=== RUN BOF AND CAPTURE ===*
- `main` (line 994) - *=== MAIN ===*

**Macros:**
- `_GNU_SOURCE` (line 1)
- `C2` (line 29)
- `CLIENT_ID` (line 31)
- `MALEABLE` (line 32)
- `USER_AGENTS_COUNT` (line 33)

**Structs:**
- `MemoryStruct` (line 47) - *=== ESTRUCTURAS ===*

#### `aes.c`
**Path:** `include/aes.c`

**Functions:**
- `__attribute__` (line 12) - *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h> define Nb 4 define KEYLEN_256 32 define RKLENGTH (4 * (...*
- `__attribute__` (line 34)
- `__attribute__` (line 56)
- `__attribute__` (line 58)
- `__attribute__` (line 59)
- `__attribute__` (line 60)
- `__attribute__` (line 61)
- `KeyExpansion` (line 166) - *static uint8_t getSBoxValue(uint8_t num) { return sbox[num]; }  define getSBoxValue(num) (sbox[(num)]) This function produces Nb(Nr+1) round keys. ...*
- `AES_init_ctx` (line 238)
- `AES_init_ctx_iv` (line 244) - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249)
- `AddRoundKey` (line 257) - *endif This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row...*
- `xtime` (line 313)
- `MixColumns` (line 320) - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary...*
- `InvMixColumns` (line 370) - *static uint8_t getSBoxInvert(uint8_t num) { return rsbox[num]; }  define getSBoxInvert(num) (rsbox[(num)]) MixColumns function mixes the columns of...*
- `InvSubBytes` (line 391) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402)
- `Cipher` (line 433) - *endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); }  } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB...*
- `AES_ECB_decrypt` (line 495)
- `XorWithIv` (line 510) - *endif // #if defined(ECB) && (ECB == 1) if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520)
- `AES_CBC_decrypt_buffer` (line 535)
- `AES_CTR_xcrypt_buffer` (line 558) - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; }  }  #endif // #if defined(CBC) && (CBC == 1)    #if def...*

**Macros:**
- `Nb` (line 4)
- `KEYLEN_256` (line 6)
- `RKLENGTH` (line 10)
- `BLOCKLEN` (line 11)
- `Nb` (line 67)
- `Nk` (line 70)
- `Nr` (line 71)
- `Nk` (line 73)
- `Nr` (line 74)
- `Nk` (line 76)
- `Nr` (line 77)
- `MULTIPLY_AS_A_FUNCTION` (line 84)
- `getSBoxValue` (line 163)
- `Multiply` (line 349)
- `getSBoxInvert` (line 365)

#### `aes_cfb.c`
**Path:** `include/aes_cfb.c`

**Functions:**
- `aes256_cfb_encrypt` (line 19) - *This is the same algorithm the v1 beacon uses to wrap C2 commands and results. The C2 server in c2/server.py implements the matching Python side us...*
- `aes256_cfb_decrypt` (line 47)

#### `beacon_common.c`
**Path:** `include/beacon_common.c`

**Functions:**
- `bsb_output_init` (line 100) - *{ "BeaconOutput",   &g_BeaconOutput_ptr }, { "socket",         &g_socket_ptr }, { "connect",        &g_connect_ptr }, { "inet_addr",      &g_inet_a...*
- `bsb_output_cleanup` (line 109)
- `bsb_output_reset` (line 116)
- `BeaconPrintf` (line 125) - *free(g_beacon_output); g_beacon_output = NULL; g_output_capacity = 0; g_output_len = 0; }  void bsb_output_reset(void) { if (g_beacon_output) { g_o...*
- `BeaconOutput` (line 137)
- `create_trampoline` (line 151) - *void BeaconOutput(int type, const char *data, int len) { (void)type; if (!g_beacon_output || len <= 0 || !data) return; size_t remaining = g_output...*
- `cleanup_trampolines` (line 180)
- `get_or_create_trampoline` (line 195)
- `WriteMemoryCallback` (line 224)
- `https_request` (line 236)
- `base64_encode` (line 291) - *curl_easy_cleanup(curl); return resp; }  long http_code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code); resp.status = (int)http_c...*
- `base64_decode` (line 306)
- `_is_unreserved` (line 329) - *if (!buffer) { BIO_free_all(b64); return NULL; } len = BIO_read(b64, buffer, input_len); BIO_free_all(b64); if (*len <= 0) { free(buffer); return N...*
- `url_encode` (line 334)
- `exec_cmd` (line 358) - *static const char hex[] = "0123456789ABCDEF"; out[j++] = '%'; out[j++] = hex[(c >> 4) & 0xF]; out[j++] = hex[c & 0xF]; } } out[j] = '\0'; out_len =...*
- `bsb_backoff_init` (line 385) - *if (total >= capacity - 1) { capacity *= 2; char *tmp = realloc(buffer, capacity); if (!tmp) break; buffer = tmp; } } pclose(fp); buffer[total] = '...*
- `bsb_backoff_next` (line 390)
- `bsb_backoff_reset` (line 399)
- `get_local_ips` (line 405) - *int bsb_backoff_next(bsb_backoff_t *bo) { int val = bo->current_seconds; bo->current_seconds *= 2; if (bo->current_seconds > bo->max_seconds) { bo-...*
- `download_bof` (line 434) - *for (int i = 0; i < n; i++) { struct sockaddr_in *addr = (struct sockaddr_in*)&ifr[i].ifr_addr; if (addr->sin_family == AF_INET && strcmp(ifr[i].if...*
- `init_function_pointers` (line 446) - */* --- BOF download --- unsigned char *download_bof(const bsb_config_t *cfg, const char *url, size_t *out_size) { http_response_t resp = https_requ...*
- `page_align` (line 471)
- `__attribute__` (line 477)
- `RunELF` (line 506)
- `run_bof_and_capture` (line 710)

**Macros:**
- `_GNU_SOURCE` (line 9)

**Structs:**
- `MemoryStruct` (line 220) - *if (g_cache_count >= g_cache_capacity) { size_t new_cap = g_cache_capacity ? g_cache_capacity * 2 : 8; TrampolineCache *tmp = realloc(g_trampoline_...*

#### `cJSON.c`
**Path:** `include/cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94)
- `CJSON_PUBLIC` (line 99)
- `CJSON_PUBLIC` (line 109)
- `CJSON_PUBLIC` (line 124) - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; }  return item->valuedouble...*
- `case_insensitive_strcmp` (line 134) - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR !=...*
- `internal_malloc` (line 166) - *}  return tolower(*string1) - tolower(*string2); }  typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *...*
- `internal_free` (line 170)
- `internal_realloc` (line 174)
- `cJSON_strdup` (line 188)
- `CJSON_PUBLIC` (line 209)
- `cJSON_New_Item` (line 242) - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; }  /* use realloc only if both free and malloc are used global_hooks.reallo...*
- `get_decimal_point` (line 281) - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->strin...*
- `parse_number` (line 309) - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer;  /*...*
- `ensure` (line 494) - *}  typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool...*
- `update_offset` (line 579) - *p->buffer = NULL;  return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = n...*
- `compare_double` (line 592) - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsi...*
- `print_number` (line 599) - *} buffer_pointer = buffer->buffer + buffer->offset;  buffer->offset += strlen((const char*)buffer_pointer); }  /* securely comparison of floating-p...*
- `parse_hex4` (line 669) - *output_pointer[i] = '.'; continue; }  output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0';  output_buffer->offset += (size_t)length;  ...*
- `utf16_literal_to_utf8` (line 706) - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); }  output_pointer += utf8_length;  return sequence_length;  fail: return 0; }  /* ...*
- `print_string_ptr` (line 957) - *{ input_buffer->hooks.deallocate(output); output = NULL; }  if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buff...*
- `print_string` (line 1079) - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_l...*
- `buffer_skip_whitespace` (line 1093) - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } ...*
- `skip_utf8_bom` (line 1119) - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; }  if (buffer->offset == buffer->length) { buffer...*
- `CJSON_PUBLIC` (line 1133)
- `CJSON_PUBLIC` (line 1235)
- `print` (line 1242) - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315)
- `CJSON_PUBLIC` (line 1320)
- `CJSON_PUBLIC` (line 1351)
- `parse_value` (line 1372) - *return false; }  p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_...*
- `print_value` (line 1427) - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (c...*
- `parse_array` (line 1501) - *return print_string(item, output_buffer);  case cJSON_Array: return print_array(item, output_buffer);  case cJSON_Object: return print_object(item,...*
- `print_array` (line 1599) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an array to text*
- `parse_object` (line 1661) - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buff...*
- `print_object` (line 1780) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an object to text.*
- `get_array_item` (line 1915)
- `CJSON_PUBLIC` (line 1934)
- `get_object_item` (line 1944)
- `CJSON_PUBLIC` (line 1976)
- `CJSON_PUBLIC` (line 1981)
- `CJSON_PUBLIC` (line 1986)
- `suffix_object` (line 1993) - *return get_object_item(object, string, false); }  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...*
- `create_reference` (line 2000) - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; }  /* U...*
- `add_item_to_array` (line 2020)
- `cast_away_const` (line 2066) - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); }  #...*
- `add_item_to_object` (line 2073) - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111)
- `CJSON_PUBLIC` (line 2122)
- `CJSON_PUBLIC` (line 2132)
- `CJSON_PUBLIC` (line 2142)
- `CJSON_PUBLIC` (line 2154)
- `CJSON_PUBLIC` (line 2166)
- `CJSON_PUBLIC` (line 2178)
- `CJSON_PUBLIC` (line 2190)
- `CJSON_PUBLIC` (line 2202)
- `CJSON_PUBLIC` (line 2214)
- `CJSON_PUBLIC` (line 2226)
- `CJSON_PUBLIC` (line 2238)
- `CJSON_PUBLIC` (line 2250)
- `CJSON_PUBLIC` (line 2286)
- `CJSON_PUBLIC` (line 2296)
- `CJSON_PUBLIC` (line 2301)
- `CJSON_PUBLIC` (line 2308)
- `CJSON_PUBLIC` (line 2315)
- `CJSON_PUBLIC` (line 2320)
- `CJSON_PUBLIC` (line 2362)
- `CJSON_PUBLIC` (line 2412)
- `replace_item_in_object` (line 2422)
- `CJSON_PUBLIC` (line 2445)
- `CJSON_PUBLIC` (line 2450)
- `CJSON_PUBLIC` (line 2467)
- `CJSON_PUBLIC` (line 2478)
- `CJSON_PUBLIC` (line 2489)
- `CJSON_PUBLIC` (line 2500)
- `CJSON_PUBLIC` (line 2525)
- `CJSON_PUBLIC` (line 2542)
- `CJSON_PUBLIC` (line 2554)
- `CJSON_PUBLIC` (line 2566)
- `CJSON_PUBLIC` (line 2578)
- `CJSON_PUBLIC` (line 2595)
- `CJSON_PUBLIC` (line 2606)
- `CJSON_PUBLIC` (line 2658)
- `CJSON_PUBLIC` (line 2698)
- `CJSON_PUBLIC` (line 2738)
- `cJSON_Duplicate_rec` (line 2785)
- `skip_oneline_comment` (line 2872)
- `skip_multiline_comment` (line 2885)
- `minify_string` (line 2899)
- `CJSON_PUBLIC` (line 2921)
- `CJSON_PUBLIC` (line 2971)
- `CJSON_PUBLIC` (line 2981)
- `CJSON_PUBLIC` (line 2991)
- `CJSON_PUBLIC` (line 3001)
- `CJSON_PUBLIC` (line 3011)
- `CJSON_PUBLIC` (line 3021)
- `CJSON_PUBLIC` (line 3031)
- `CJSON_PUBLIC` (line 3041)
- `CJSON_PUBLIC` (line 3051)
- `CJSON_PUBLIC` (line 3061)
- `CJSON_PUBLIC` (line 3071)
- `cJSON_ArrayForEach` (line 3157)
- `cJSON_ArrayForEach` (line 3173) - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193)
- `CJSON_PUBLIC` (line 3198)

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28)
- `true` (line 65)
- `false` (line 70)
- `isinf` (line 74)
- `isnan` (line 77)
- `NAN` (line 82)
- `NAN` (line 84)
- `internal_malloc` (line 179)
- `internal_free` (line 180)
- `internal_realloc` (line 181)
- `static_strlen` (line 185)
- `can_read` (line 301)
- `can_access_at_index` (line 303)
- `cannot_access_at_index` (line 304)
- `buffer_at_offset` (line 306)
- `cjson_min` (line 1240)

**Structs:**
- `internal_hooks` (line 157)

#### `config.c`
**Path:** `include/config.c`

**Functions:**
- `slurp` (line 24) - *declared in the schema. Unknown keys are skipped. Missing sections fall back to safe defaults.  #define _POSIX_C_SOURCE 200809L #include "config.h"...*
- `skip_ws` (line 41) - *fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); if (n < 0) { fclose(f); return NULL; } char *buf = (char *)malloc((size_t)n + 1); ...*
- `read_string` (line 49) - *Read a JSON string starting at *pp (which must point at "). On success, write the unescaped string into out (NUL terminated) * and advance *pp past...*
- `read_int` (line 75)
- `read_bool` (line 91)
- `expect` (line 100) - *} out = (int)(neg ? -v : v); pp = p; return 1; }  static int read_bool(const char **pp, const char *end, int *out) { const char *p = skip_ws(*pp, e...*
- `find_matching_brace` (line 109) - *Find the byte position of the matching closing brace for the * opening { at *pp. Honors string and escape rules.*
- `skip_value` (line 132) - *Skip the next value at p (string, number, bool, null, object, array). * Returns the position just past the value, or NULL on error.*
- `hex_to_bytes` (line 174) - *else if (ch == ']') { depth--; if (depth == 0) return p + 1; } p++; } return NULL; } if (c == 't') return p + 4; if (c == 'f') return p + 5; if (c ...*
- `parse_c2` (line 186) - */* --- hex decode --- static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) { size_t hlen = strlen(hex); if (hlen != outlen * 2) re...*
- `parse_crypto` (line 208)
- `parse_timing` (line 229)
- `parse_network` (line 252)
- `parse_bof` (line 288)
- `parse_backoff` (line 307)
- `bsb_config_load` (line 328) - *if (!expect(&p, end, ':')) return; if (!strcmp(key, "base_seconds")) { if (!read_int(&p, end, &cfg->backoff.base_seconds)) return; } else if (!strc...*
- `binary_dir` (line 420) - *Return the directory the running binary lives in, or NULL if we cannot resolve it (e.g. on platforms without /proc/self/exe). The returned buffer i...*
- `bsb_config_load_default` (line 437)
- `bsb_config_sleep_seconds` (line 465)

**Macros:**
- `_POSIX_C_SOURCE` (line 13)

#### `issudo.c`
**Path:** `issudo.c`

**Functions:**
- `syscall3` (line 22) - *Syscalls define SYS_openat 257 define SYS_read   0 define SYS_close  3 define SYS_getuid 102 define SYS_getpwuid_r 168  // opcional, pero no lo usa...*
- `syscall1` (line 31)
- `strcmp` (line 43) - *strcmp mínimo (necesario para comparar strings)*
- `get_username_from_uid` (line 52) - *Obtener username desde /etc/passwd (sin libc)*
- `go` (line 107)

**Macros:**
- `NULL` (line 2)
- `CALLBACK_OUTPUT` (line 3)
- `SYS_openat` (line 14)
- `SYS_read` (line 15)
- `SYS_close` (line 16)
- `SYS_getuid` (line 17)
- `SYS_getpwuid_r` (line 18)
- `AT_FDCWD` (line 19)

#### `config_harness.c`
**Path:** `tests/config_harness.c`

**Functions:**
- `main` (line 21)

#### `crypto_harness.c`
**Path:** `tests/crypto_harness.c`

**Functions:**
- `hex_to_bytes` (line 11) - *crypto_harness.c - Roundtrip test harness for AES-256-CFB.  Used by tests/test_crypto.py to validate the AES path the beacon and C2 server use for ...*
- `main` (line 22)

### H (11 files)

#### `aes.h`
**Path:** `aes.h`

**Macros:**
- `_AES_H_` (line 2)
- `CBC` (line 9)
- `ECB` (line 12)
- `CTR` (line 15)
- `AES256` (line 17)
- `AES_BLOCKLEN` (line 19)
- `AES_KEYLEN` (line 23)
- `AES_keyExpSize` (line 24)
- `AES_KEYLEN` (line 26)
- `AES_keyExpSize` (line 27)
- `AES_KEYLEN` (line 29)
- `AES_keyExpSize` (line 30)

**Structs:**
- `AES_ctx` (line 33) - *define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExp...*

#### `beacon.h`
**Path:** `beacon.h`

**Macros:**
- `BEACON_API_H` (line 3)
- `CALLBACK_OUTPUT` (line 9)
- `CALLBACK_ERROR` (line 10)
- `CALLBACK_OUTPUT_OEM` (line 11)

#### `beacon_api.h`
**Path:** `bof/include/beacon_api.h`

**Macros:**
- `BSB_BOF_BEACON_API_H` (line 17)
- `CALLBACK_OUTPUT` (line 24)
- `CALLBACK_ERROR` (line 25)
- `CALLBACK_OUTPUT_OEM` (line 26)

#### `syscalls.h`
**Path:** `bof/include/syscalls.h`

**Functions:**
- `syscall0` (line 48) - *#define SYS_wait4      61 #define SYS_getuid     102 #define SYS_getgid     104 #define SYS_geteuid    107 #define SYS_getegid    108 #define SYS_g...*
- `syscall1` (line 59)
- `syscall2` (line 70)
- `syscall3` (line 81)
- `syscall4` (line 92)
- `bsf_strlen` (line 106) - *static inline long syscall4(long n, long a1, long a2, long a3, long a4) { long ret; register long r10 __asm__("r10") = a4; __asm__ volatile ( "sysc...*
- `bsf_strcmp` (line 113) - *: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory" ); return ret; }  /* strlen - libc is not linked. static inline size_t bsf_s...*
- `bsf_memcmp` (line 119) - */* strlen - libc is not linked. static inline size_t bsf_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); }  /* s...*

**Macros:**
- `BSB_BOF_SYSCALLS_H` (line 12)
- `SYS_read` (line 17)
- `SYS_write` (line 18)
- `SYS_open` (line 19)
- `SYS_close` (line 20)
- `SYS_stat` (line 21)
- `SYS_fstat` (line 22)
- `SYS_lseek` (line 23)
- `SYS_mmap` (line 24)
- `SYS_munmap` (line 25)
- `SYS_brk` (line 26)
- `SYS_ioctl` (line 27)
- `SYS_access` (line 28)
- `SYS_pipe` (line 29)
- `SYS_dup2` (line 30)
- `SYS_fork` (line 31)
- `SYS_execve` (line 32)
- `SYS_exit` (line 33)
- `SYS_wait4` (line 34)
- `SYS_getuid` (line 35)
- `SYS_getgid` (line 36)
- `SYS_geteuid` (line 37)
- `SYS_getegid` (line 38)
- `SYS_getpid` (line 39)
- `SYS_getppid` (line 40)
- `SYS_getpwnam_r` (line 41)
- `SYS_getpwuid_r` (line 42)
- `SYS_openat` (line 43)
- `SYS_clone` (line 44)
- `AT_FDCWD` (line 47)

#### `cJSON.h`
**Path:** `cJSON.h`

**Macros:**
- `cJSON__h` (line 24)
- `__WINDOWS__` (line 32)
- `CJSON_CDECL` (line 43)
- `CJSON_STDCALL` (line 45)
- `CJSON_EXPORT_SYMBOLS` (line 49)
- `CJSON_PUBLIC` (line 53)
- `CJSON_PUBLIC` (line 55)
- `CJSON_PUBLIC` (line 57)
- `CJSON_CDECL` (line 60)
- `CJSON_STDCALL` (line 61)
- `CJSON_PUBLIC` (line 64)
- `CJSON_PUBLIC` (line 66)
- `CJSON_VERSION_MAJOR` (line 71)
- `CJSON_VERSION_MINOR` (line 72)
- `CJSON_VERSION_PATCH` (line 73)
- `cJSON_Invalid` (line 78)
- `cJSON_False` (line 79)
- `cJSON_True` (line 80)
- `cJSON_NULL` (line 81)
- `cJSON_Number` (line 82)
- `cJSON_String` (line 83)
- `cJSON_Array` (line 84)
- `cJSON_Object` (line 85)
- `cJSON_Raw` (line 86)
- `cJSON_IsReference` (line 87)
- `cJSON_StringIsConst` (line 89)
- `CJSON_NESTING_LIMIT` (line 126)
- `CJSON_CIRCULAR_LIMIT` (line 132)
- `cJSON_SetIntValue` (line 270)
- `cJSON_SetNumberValue` (line 273)
- `cJSON_SetBoolValue` (line 278)
- `cJSON_ArrayForEach` (line 285)

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #...*
- `cJSON_Hooks` (line 114)

#### `aes.h`
**Path:** `include/aes.h`

**Macros:**
- `_AES_H_` (line 2)
- `CBC` (line 9)
- `ECB` (line 12)
- `CTR` (line 15)
- `AES256` (line 17)
- `AES_BLOCKLEN` (line 19)
- `AES_KEYLEN` (line 23)
- `AES_keyExpSize` (line 24)
- `AES_KEYLEN` (line 26)
- `AES_keyExpSize` (line 27)
- `AES_KEYLEN` (line 29)
- `AES_keyExpSize` (line 30)

**Structs:**
- `AES_ctx` (line 33) - *define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExp...*

#### `aes_cfb.h`
**Path:** `include/aes_cfb.h`

**Macros:**
- `BSB_AES_CFB_H` (line 5)

#### `beacon.h`
**Path:** `include/beacon.h`

**Macros:**
- `BEACON_API_H` (line 3)
- `CALLBACK_OUTPUT` (line 9)
- `CALLBACK_ERROR` (line 10)
- `CALLBACK_OUTPUT_OEM` (line 11)

#### `beacon_common.h`
**Path:** `include/beacon_common.h`

**Macros:**
- `BEACON_COMMON_H` (line 13)
- `_GNU_SOURCE` (line 14)
- `BSB_OUTPUT_BUFFER_DEFAULT` (line 26)
- `BSB_OUTPUT_TRUNCATION_MARKER` (line 27)

#### `cJSON.h`
**Path:** `include/cJSON.h`

**Macros:**
- `cJSON__h` (line 24)
- `__WINDOWS__` (line 32)
- `CJSON_CDECL` (line 43)
- `CJSON_STDCALL` (line 45)
- `CJSON_EXPORT_SYMBOLS` (line 49)
- `CJSON_PUBLIC` (line 53)
- `CJSON_PUBLIC` (line 55)
- `CJSON_PUBLIC` (line 57)
- `CJSON_CDECL` (line 60)
- `CJSON_STDCALL` (line 61)
- `CJSON_PUBLIC` (line 64)
- `CJSON_PUBLIC` (line 66)
- `CJSON_VERSION_MAJOR` (line 71)
- `CJSON_VERSION_MINOR` (line 72)
- `CJSON_VERSION_PATCH` (line 73)
- `cJSON_Invalid` (line 78)
- `cJSON_False` (line 79)
- `cJSON_True` (line 80)
- `cJSON_NULL` (line 81)
- `cJSON_Number` (line 82)
- `cJSON_String` (line 83)
- `cJSON_Array` (line 84)
- `cJSON_Object` (line 85)
- `cJSON_Raw` (line 86)
- `cJSON_IsReference` (line 87)
- `cJSON_StringIsConst` (line 89)
- `CJSON_NESTING_LIMIT` (line 126)
- `CJSON_CIRCULAR_LIMIT` (line 132)
- `cJSON_SetIntValue` (line 270)
- `cJSON_SetNumberValue` (line 273)
- `cJSON_SetBoolValue` (line 278)
- `cJSON_ArrayForEach` (line 285)

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #...*
- `cJSON_Hooks` (line 114)

#### `config.h`
**Path:** `include/config.h`

**Macros:**
- `BSB_CONFIG_H` (line 14)
- `BSB_CONFIG_PATH_DEFAULT` (line 18)
- `BSB_CONFIG_PATH_ENV` (line 20)
- `BSB_MAX_URL` (line 21)
- `BSB_MAX_URI` (line 22)
- `BSB_MAX_CLIENT_ID` (line 23)
- `BSB_AES_KEY_HEX_LEN` (line 24)
- `BSB_AES_KEY_BYTES` (line 25)
- `BSB_MAX_USER_AGENTS` (line 26)
- `BSB_USER_AGENT_LEN` (line 27)
- `BSB_REPORT_URI_DEFAULT` (line 28)

### PY (11 files)

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

#### `server.py`
**Path:** `c2/server.py`

**Classs:**
- `C2State` (line 136) - *Mutable state shared between request handlers.*

**Functions:**
- `load_runtime_config` (line 59) - *Load configuration from JSON file or use defaults.*
- `compute_hmac` (line 86) - *Compute HMAC-SHA256 for message authentication.*
- `verify_hmac` (line 91) - *Verify HMAC-SHA256 signature.*
- `encrypt_data` (line 97) - *Encrypt data with AES-256-CFB and optional HMAC.*
- `decrypt_data` (line 117) - *Decrypt AES-256-CFB data with optional HMAC verification.*
- `handle_get_command` (line 150) - *Dispatch beacon's polling GET request.*
- `handle_report` (line 173) - *Process beacon result report.*
- `handle_bof` (line 229) - *Serve BOF file from upload directory.*
- `handle_request` (line 239) - *Route request to appropriate handler.*
- `serve_client` (line 272) - *Handle individual client connection.*
- `command_injector` (line 294) - *Interactive command injection REPL.*
- `main` (line 317) - *Start C2 server.*
- `__init__` (line 139)

#### `gopher_c2.py`
**Path:** `gopher_c2.py`

**Functions:**
- `encrypt_data` (line 28)
- `decrypt_data` (line 37)
- `handle_client` (line 45)
- `main` (line 127)
- `command_injector` (line 136)

#### `config_py.py`
**Path:** `include/config_py.py`

**Functions:**
- `_deep_merge` (line 55) - *Recursively merge overlay into base; overlay wins.*
- `load_config` (line 65) - *Load and validate a BSB config file.

Raises ValueError on any schema violation. Returns a dict
matching DEFAULTS' structure.*

#### `test_beacon_build.py`
**Path:** `tests/test_beacon_build.py`

**Functions:**
- `have_headers` (line 20) - *Return True if openssl and curl headers are present.*
- `compile_beacon` (line 34)
- `inspect_binary` (line 50)
- `test_beacon_compiles_and_links` (line 55)
- `test_beacon_exposes_bof_api` (line 64)
- `test_beacon_exposes_elf_loader` (line 85)
- `main` (line 96)

#### `test_bof_compile.py`
**Path:** `tests/test_bof_compile.py`

**Functions:**
- `compile_bof` (line 21)
- `inspect_symbols` (line 35)
- `test_compile_all` (line 53)
- `test_export_go` (line 60)
- `test_unresolved_beacon_api` (line 68)
- `test_no_libc_leak` (line 80) - *Make sure we did not pull in glibc symbols by accident.*
- `main` (line 91)

#### `test_c2_http_e2e.py`
**Path:** `tests/test_c2_http_e2e.py`

**Functions:**
- `_free_port` (line 43)
- `_recv_response` (line 51)
- `test_http_get_poll_returns_encrypted_command` (line 65) - *Beacon-style HTTP/1.1 GET /<uri>/<id> must return a base64
body the server can encrypt and we can decrypt with the shared
AES key. Before the fix, the server returned iUNKNOWN_SELECTOR.*
- `test_http_post_report_writes_log` (line 115) - *Beacon-style HTTP/1.1 POST /report/<b64> must reach the
report handler, decrypt, parse, and write a CSV row. Before
the fix, the POST went to the same URL as the GET (poll),
so the server logged an UNKNOWN_SELECTOR error and the
CSV never had a row for this client.*
- `test_gopher_legacy_still_works` (line 183) - *The old Gopher-style selector (single line, CRLF) must
still dispatch correctly — server.py keeps that path so
anything that depended on it is not broken by the new
HTTP/1.1 entry point.*
- `test_http_post_with_url_encoded_b64_payload` (line 233) - *The beacon percent-encodes the base64 payload before
splicing it onto the URL path. Standard base64 uses '+',
'/', and '=' which would otherwise produce an invalid
HTTP request line (extra '/' would split the path, '+'
is space-encoded, '=' is a query marker). This test
replicates that: encode the payload exactly as the
beacon does, send it, and assert the report is decrypted
and logged.*
- `test_fragmented_post_is_dispatched_as_http` (line 326) - *When the client sends a long POST URL that crosses a TCP
segment boundary, the first recv() inside server.serve() may
not include "HTTP/1.1" yet. Before the _read_http_request
fix, this made the dispatcher fall through to the legacy
Gopher branch and return iUNKNOWN_SELECTOR. We reproduce that
fragmentation here by sending the request in two pieces with
a small delay between them. The expected behavior is that the
server still parses the full request, decrypts, and writes
the log line.*
- `main` (line 399)
- `encode` (line 274)

#### `test_c2_server.py`
**Path:** `tests/test_c2_server.py`

**Functions:**
- `make_state` (line 39)
- `test_get_command_empty` (line 46)
- `test_get_command_queued` (line 58)
- `test_report_writes_log` (line 69)
- `test_bof_not_found` (line 85)
- `test_bof_serves_existing_file` (line 92)
- `test_unknown_selector` (line 104)
- `test_path_traversal_in_bof_name` (line 111) - *Path-traversal in /bof/ should be neutralised by os.path.basename.*
- `test_roundtrip_empty` (line 120) - *encrypt then decrypt empty payload must yield single NUL byte.*
- `test_roundtrip_text` (line 127)
- `main` (line 134)

#### `test_config.py`
**Path:** `tests/test_config.py`

**Functions:**
- `compile_harness` (line 24) - *Build the test harness against config.c.*
- `run_harness` (line 38) - *Write a config file, run the harness, return parsed output.*
- `test_default_load` (line 55)
- `test_overrides` (line 73)
- `test_missing_file` (line 90)
- `test_search_order_env_wins` (line 98) - *$BSB_CONFIG must take precedence over the binary-relative path.*
- `test_search_order_falls_back_to_cwd_default` (line 115) - *With BSB_CONFIG unset, the harness resolves to ./config.json
(the binary-relative lookup is irrelevant in the harness because
the harness lives in tests/, not next to a config.json).*
- `test_bad_hex_key` (line 141)
- `main` (line 156)

#### `test_crypto.py`
**Path:** `tests/test_crypto.py`

**Functions:**
- `compile_harness` (line 18)
- `run` (line 32)
- `test_short` (line 40)
- `test_block_boundary` (line 44)
- `test_longer_than_block` (line 49)
- `test_known_ciphertext` (line 55)
- `test_python_can_decrypt_c_ciphertext` (line 74) - *The Python C2 server must be able to decrypt C-encrypted
commands. We feed a known key+plaintext through the C harness,
extract the ciphertext, then decrypt with Python and check we
recover the original plain.*
- `main` (line 107)

#### `test_install_deploy.py`
**Path:** `tests/test_install_deploy.py`

**Functions:**
- `make_all` (line 23) - *Clean and build everything, return nothing.*
- `run_beacon` (line 29)
- `test_build_beacon_lands_alongside_config` (line 42) - *The point of this whole iteration: `make beacon` leaves
a runnable binary with its config next to it, no env vars
or extra steps required.*
- `test_staged_files_have_correct_modes` (line 53)
- `test_staged_beacon_runs_from_any_cwd` (line 61) - *Drop the operator in /tmp; the staged beacon should still
find build/config.json via the binary-relative search path.*
- `test_staged_bofs_are_present` (line 74)
- `test_clean_removes_everything` (line 82) - *make clean must wipe build/ — including the staged config.json —
but leave config/config.json (the operator's copy) alone.

This is the last test that runs, so we leave the operator with a
fresh deliverable tree afterwards. `make clean` is destructive
and the operator's only copy of build/ is whatever the previous
test left behind; rebuilding here guarantees `./build/beacon`
and the staged BOFs are present after `make test` finishes.*
- `main` (line 104)

### SH (2 files)

#### `build.sh`
**Path:** `bof/build.sh`

*No symbols extracted*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*
