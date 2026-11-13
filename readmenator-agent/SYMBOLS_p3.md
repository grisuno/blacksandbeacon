# Symbols (page 3 of 4)
Previous: [SYMBOLS_p2.md](SYMBOLS_p2.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `aes256_cfb_decrypt` | function | `legacy/beacon5.c:557` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/beacon5.c:523` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/beacon5.c:497` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/beacon5.c:479` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/beacon5.c:311` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/beacon5.c:270` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/beacon5.c:1161` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `legacy/beacon5.c:593` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/beacon5.c:1126` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/beacon5.c:329` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `legacy/beacon5.c:385` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `legacy/beacon5.c:1702` | `int main(int argc, char **argv)` |
| `mesh_add_peer` | function | `legacy/beacon5.c:1255` | `void mesh_add_peer(const char *ip, int port)` |
| `mesh_cleanup_peers` | function | `legacy/beacon5.c:1283` | `void mesh_cleanup_peers()` |
| `mesh_discovery_thread` | function | `legacy/beacon5.c:1356` | `void *mesh_discovery_thread(void *arg)` |
| `mesh_is_seen` | function | `legacy/beacon5.c:1240` | `int mesh_is_seen(const char *msg_id)` |
| `mesh_listener_thread` | function | `legacy/beacon5.c:1447` | `void *mesh_listener_thread(void *arg)` |
| `mesh_mark_seen` | function | `legacy/beacon5.c:1231` | `void mesh_mark_seen(const char *msg_id)` |
| `mesh_msg_t` | struct | `legacy/beacon5.c:77` | `` |
| `mesh_propagate` | function | `legacy/beacon5.c:1324` | `void mesh_propagate(const char *command)` |
| `mesh_send_message` | function | `legacy/beacon5.c:1667` | `void mesh_send_message(int type, const char *target, const char *payload)` |
| `mesh_send_to_peer` | function | `legacy/beacon5.c:1300` | `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)` |
| `page_align` | function | `legacy/beacon5.c:619` | `static size_t page_align(size_t size)` |
| `peer_t` | struct | `legacy/beacon5.c:69` | `` |
| `run_bof_and_capture` | function | `legacy/beacon5.c:1184` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BeaconOutput` | function | `legacy/beacon6.c:283` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/beacon6.c:266` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `legacy/beacon6.c:34` | `#define C2_URL` |
| `CLIENT_ID` | macro | `legacy/beacon6.c:35` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `legacy/beacon6.c:36` | `#define MALEABLE` |
| `MemoryStruct` | struct | `legacy/beacon6.c:53` | `` |
| `RunELF` | function | `legacy/beacon6.c:654` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/beacon6.c:70` | `` |
| `Trampoline` | struct | `legacy/beacon6.c:61` | `` |
| `TrampolineCache` | struct | `legacy/beacon6.c:77` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/beacon6.c:37` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/beacon6.c:394` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/beacon6.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/beacon6.c:146` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `legacy/beacon6.c:584` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/beacon6.c:550` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/beacon6.c:524` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/beacon6.c:506` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/beacon6.c:338` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/beacon6.c:297` | `static void *create_trampoline(void *target)` |
| `delay_ms` | function | `legacy/beacon6.c:197` | `static void delay_ms(int ms)` |
| `download_bof` | function | `legacy/beacon6.c:1188` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `legacy/beacon6.c:620` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/beacon6.c:1153` | `char *get_local_ips()` |
| `get_nth_prime_limited` | function | `legacy/beacon6.c:224` | `static unsigned int get_nth_prime_limited(unsigned int n)` |
| `get_or_create_trampoline` | function | `legacy/beacon6.c:356` | `static void *get_or_create_trampoline(void *target)` |
| `https_request` | function | `legacy/beacon6.c:412` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `is_prime` | function | `legacy/beacon6.c:204` | `static unsigned int is_prime(unsigned int x)` |
| `main` | function | `legacy/beacon6.c:1257` | `int main()` |
| `page_align` | function | `legacy/beacon6.c:646` | `static size_t page_align(size_t size)` |
| `portable_rand_19k_29k` | function | `legacy/beacon6.c:253` | `static unsigned int portable_rand_19k_29k(void)` |
| `run_bof_and_capture` | function | `legacy/beacon6.c:1211` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BROADCAST_INTERVAL` | macro | `legacy/beacon_p2p.c:46` | `#define BROADCAST_INTERVAL` |
| `BeaconDataExtract` | function | `legacy/beacon_p2p.c:131` | `char *BeaconDataExtract(datap *parser, int *size)` |
| `BeaconDataInt` | function | `legacy/beacon_p2p.c:110` | `int BeaconDataInt(datap *parser)` |
| `BeaconDataLength` | function | `legacy/beacon_p2p.c:126` | `int BeaconDataLength(datap *parser)` |
| `BeaconDataParse` | function | `legacy/beacon_p2p.c:93` | `void BeaconDataParse(datap *parser, char *buffer, int size)` |
| `BeaconDataPtr` | function | `legacy/beacon_p2p.c:100` | `char *BeaconDataPtr(datap *parser, int size)` |
| `BeaconDataShort` | function | `legacy/beacon_p2p.c:118` | `short BeaconDataShort(datap *parser)` |
| `BeaconOutput` | function | `legacy/beacon_p2p.c:159` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/beacon_p2p.c:142` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2_URL` | macro | `legacy/beacon_p2p.c:37` | `#define C2_URL` |
| `CLIENT_ID` | macro | `legacy/beacon_p2p.c:38` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `legacy/beacon_p2p.c:39` | `#define MALEABLE` |
| `MAX_PEERS` | macro | `legacy/beacon_p2p.c:47` | `#define MAX_PEERS` |
| `MemoryStruct` | struct | `legacy/beacon_p2p.c:676` | `` |
| `PEER_DISCOVERY_PORT` | macro | `legacy/beacon_p2p.c:42` | `#define PEER_DISCOVERY_PORT` |
| `PEER_MAGIC` | macro | `legacy/beacon_p2p.c:44` | `#define PEER_MAGIC` |
| `PEER_TCP_PORT` | macro | `legacy/beacon_p2p.c:43` | `#define PEER_TCP_PORT` |
| `PEER_VERSION` | macro | `legacy/beacon_p2p.c:45` | `#define PEER_VERSION` |
| `RunELF` | function | `legacy/beacon_p2p.c:358` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/beacon_p2p.c:182` | `` |
| `Trampoline` | struct | `legacy/beacon_p2p.c:175` | `` |
| `TrampolineCache` | struct | `legacy/beacon_p2p.c:192` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/beacon_p2p.c:40` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/beacon_p2p.c:683` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/beacon_p2p.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/beacon_p2p.c:250` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `add_peer` | function | `legacy/beacon_p2p.c:965` | `void add_peer(struct in_addr ip, int port, const char *id)` |
| `aes256_cfb_decrypt` | function | `legacy/beacon_p2p.c:832` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/beacon_p2p.c:802` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/beacon_p2p.c:780` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/beacon_p2p.c:763` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/beacon_p2p.c:309` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/beacon_p2p.c:278` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/beacon_p2p.c:925` | `unsigned char *download_bof(const char *url, size_t *out_size)` |
| `exec_cmd` | function | `legacy/beacon_p2p.c:866` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `execute_generic_command` | function | `legacy/beacon_p2p.c:1231` | `char *execute_generic_command(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/beacon_p2p.c:891` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/beacon_p2p.c:323` | `static void *get_or_create_trampoline(void *target)` |
| `handle_peer_connection` | function | `legacy/beacon_p2p.c:1032` | `void *handle_peer_connection(void *arg)` |
| `https_request` | function | `legacy/beacon_p2p.c:707` | `char *https_request(const char *url, const char *method, const char *post_data)` |
| `main` | function | `legacy/beacon_p2p.c:1276` | `int main()` |
| `p2p_header_t` | struct | `legacy/beacon_p2p.c:73` | `` |
| `page_align` | function | `legacy/beacon_p2p.c:350` | `static size_t page_align(size_t size)` |
| `peer_discovery_thread` | function | `legacy/beacon_p2p.c:992` | `void *peer_discovery_thread(void *arg)` |
| `peer_server_thread` | function | `legacy/beacon_p2p.c:1130` | `void *peer_server_thread(void *arg)` |
| `peer_t` | struct | `legacy/beacon_p2p.c:59` | `` |
| `run_bof_and_capture` | function | `legacy/beacon_p2p.c:939` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `send_to_c2_or_peer` | function | `legacy/beacon_p2p.c:1197` | `char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)` |
| `send_to_peer` | function | `legacy/beacon_p2p.c:1153` | `char *send_to_peer(peer_t *peer, const char *data, int *out_len)` |
| `BeaconOutput` | function | `legacy/gopher_beacon.c:210` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/gopher_beacon.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `legacy/gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `legacy/gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `legacy/gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `legacy/gopher_beacon.c:49` | `` |
| `RunELF` | function | `legacy/gopher_beacon.c:581` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/gopher_beacon.c:66` | `` |
| `Trampoline` | struct | `legacy/gopher_beacon.c:57` | `` |
| `TrampolineCache` | struct | `legacy/gopher_beacon.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/gopher_beacon.c:321` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/gopher_beacon.c:142` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `legacy/gopher_beacon.c:500` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/gopher_beacon.c:466` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/gopher_beacon.c:440` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/gopher_beacon.c:422` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/gopher_beacon.c:265` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/gopher_beacon.c:224` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/gopher_beacon.c:1115` | `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` |
| `exec_cmd` | function | `legacy/gopher_beacon.c:536` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/gopher_beacon.c:1080` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/gopher_beacon.c:283` | `static void *get_or_create_trampoline(void *target)` |
| `gopher_request` | function | `legacy/gopher_beacon.c:339` | `char *gopher_request(const char *host, int port, const char *selector, const char *method,       ...` |
| `main` | function | `legacy/gopher_beacon.c:1193` | `int main()` |
| `page_align` | function | `legacy/gopher_beacon.c:573` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `legacy/gopher_beacon.c:1147` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `BeaconOutput` | function | `legacy/v1_gopher_beacon.c:210` | `void BeaconOutput(int type, const char *data, int len)` |
| `BeaconPrintf` | function | `legacy/v1_gopher_beacon.c:193` | `void BeaconPrintf(int type, const char *fmt, ...)` |
| `C2` | macro | `legacy/v1_gopher_beacon.c:30` | `#define C2` |
| `CLIENT_ID` | macro | `legacy/v1_gopher_beacon.c:31` | `#define CLIENT_ID` |
| `MALEABLE` | macro | `legacy/v1_gopher_beacon.c:32` | `#define MALEABLE` |
| `MemoryStruct` | struct | `legacy/v1_gopher_beacon.c:49` | `` |
| `RunELF` | function | `legacy/v1_gopher_beacon.c:581` | `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,            unsig...` |
| `SymbolResolver` | struct | `legacy/v1_gopher_beacon.c:66` | `` |
| `Trampoline` | struct | `legacy/v1_gopher_beacon.c:57` | `` |
| `TrampolineCache` | struct | `legacy/v1_gopher_beacon.c:73` | `` |
| `USER_AGENTS_COUNT` | macro | `legacy/v1_gopher_beacon.c:33` | `#define USER_AGENTS_COUNT` |
| `WriteMemoryCallback` | function | `legacy/v1_gopher_beacon.c:321` | `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)` |
| `_GNU_SOURCE` | macro | `legacy/v1_gopher_beacon.c:1` | `#define _GNU_SOURCE` |
| `__attribute__` | function | `legacy/v1_gopher_beacon.c:142` | `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,             ...` |
| `aes256_cfb_decrypt` | function | `legacy/v1_gopher_beacon.c:500` | `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `aes256_cfb_encrypt` | function | `legacy/v1_gopher_beacon.c:466` | `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,             ...` |
| `base64_decode` | function | `legacy/v1_gopher_beacon.c:440` | `unsigned char *base64_decode(const char *input, int *len)` |
| `base64_encode` | function | `legacy/v1_gopher_beacon.c:422` | `char *base64_encode(const unsigned char *input, int len)` |
| `cleanup_trampolines` | function | `legacy/v1_gopher_beacon.c:265` | `static void cleanup_trampolines(void)` |
| `create_trampoline` | function | `legacy/v1_gopher_beacon.c:224` | `static void *create_trampoline(void *target)` |
| `download_bof` | function | `legacy/v1_gopher_beacon.c:1115` | `unsigned char *download_bof(const char *bof_selector, size_t *out_size)` |
| `exec_cmd` | function | `legacy/v1_gopher_beacon.c:536` | `char *exec_cmd(const char *cmd, int *out_len)` |
| `get_local_ips` | function | `legacy/v1_gopher_beacon.c:1080` | `char *get_local_ips()` |
| `get_or_create_trampoline` | function | `legacy/v1_gopher_beacon.c:283` | `static void *get_or_create_trampoline(void *target)` |
| `gopher_request` | function | `legacy/v1_gopher_beacon.c:339` | `char *gopher_request(const char *host, int port, const char *selector, const char *method,       ...` |
| `main` | function | `legacy/v1_gopher_beacon.c:1193` | `int main()` |
| `page_align` | function | `legacy/v1_gopher_beacon.c:573` | `static size_t page_align(size_t size)` |
| `run_bof_and_capture` | function | `legacy/v1_gopher_beacon.c:1147` | `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,    ...` |
| `async_i_o_for_beacon_process` | function | `mutants/src/async_i_o_for_beacon.c:6` | `bool async_i_o_for_beacon_process(void)` |
| `beacon_heartbeat___health_endpoint_process` | function | `mutants/src/beacon_heartbeat___health_endpoint.c:6` | `bool beacon_heartbeat___health_endpoint_process(void)` |
| `bof_api_versioning_process` | function | `mutants/src/bof_api_versioning.c:6` | `bool bof_api_versioning_process(void)` |
| `bof_path_traversal_hardening_process` | function | `mutants/src/bof_path_traversal_hardening.c:6` | `bool bof_path_traversal_hardening_process(void)` |
| `bof_streaming_` | function | `mutants/src/bof_streaming_(large_outputs).c:6` | `bool bof_streaming_(large_outputs)_process(void)` |
| `c2_rest_api_process` | function | `mutants/src/c2_rest_api.c:6` | `bool c2_rest_api_process(void)` |
| `certificate_pinning___tofu_process` | function | `mutants/src/certificate_pinning___tofu.c:6` | `bool certificate_pinning___tofu_process(void)` |
| `command_execution_via_execve_process` | function | `mutants/src/command_execution_via_execve.c:6` | `bool command_execution_via_execve_process(void)` |
| `hkdf_key_derivation_process` | function | `mutants/src/hkdf_key_derivation.c:6` | `bool hkdf_key_derivation_process(void)` |
| `iv_generation_with_entropy_verification_process` | function | `mutants/src/iv_generation_with_entropy_verification.c:6` | `bool iv_generation_with_entropy_verification_process(void)` |
| `mutation_testing_integration_process` | function | `mutants/src/mutation_testing_integration.c:6` | `bool mutation_testing_integration_process(void)` |
| `replay_protection_process` | function | `mutants/src/replay_protection.c:6` | `bool replay_protection_process(void)` |
| `socks5___http_proxy_support_process` | function | `mutants/src/socks5___http_proxy_support.c:6` | `bool socks5___http_proxy_support_process(void)` |
| `structured_jsonl_logging_process` | function | `mutants/src/structured_jsonl_logging.c:6` | `bool structured_jsonl_logging_process(void)` |
| `tls_client_certificate_authentication_process` | function | `mutants/src/tls_client_certificate_authentication.c:6` | `bool tls_client_certificate_authentication_process(void)` |
| `unified_config_schema_process` | function | `mutants/src/unified_config_schema.c:6` | `bool unified_config_schema_process(void)` |
| `main` | function | `mutants/tests/config_harness.c:22` | `int main(void)` |
| `hex_to_bytes` | function | `mutants/tests/crypto_harness.c:12` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `mutants/tests/crypto_harness.c:23` | `int main(int argc, char **argv)` |
| `TestAsyncIOforBeacon` | class | `mutants/tests/test_async_i_o_for_beacon.py:18` | `class TestAsyncIOforBeacon` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_async_i_o_for_beacon.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_async_i_o_for_beacon_c.c:21` | `int main(void)` |
| `test_async_i_o_for_beacon_placeholder` | function | `mutants/tests/test_async_i_o_for_beacon_c.c:14` | `static void test_async_i_o_for_beacon_placeholder(void **state)` |
| `compile_beacon` | function | `mutants/tests/test_beacon_build.py:43` | `def compile_beacon()` |
| `ensure_beacon` | function | `mutants/tests/test_beacon_build.py:70` | `def ensure_beacon()` |
| `have_headers` | function | `mutants/tests/test_beacon_build.py:29` | `def have_headers()` |
| `inspect_binary` | function | `mutants/tests/test_beacon_build.py:65` | `def inspect_binary()` |
| `main` | function | `mutants/tests/test_beacon_build.py:123` | `def main()` |
| `test_beacon_compiles_and_links` | function | `mutants/tests/test_beacon_build.py:84` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `mutants/tests/test_beacon_build.py:93` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `mutants/tests/test_beacon_build.py:113` | `def test_beacon_exposes_elf_loader()` |
| `main` | function | `mutants/tests/test_beacon_common.c_extraction_c.c:21` | `int main(void)` |
| `TestBeaconHeartbeatHealthEndpoint` | class | `mutants/tests/test_beacon_heartbeat___health_endpoint.py:18` | `class TestBeaconHeartbeatHealthEndpoint` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_beacon_heartbeat___health_endpoint.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c:21` | `int main(void)` |
| `test_beacon_heartbeat___health_endpoint_placeholder` | function | `mutants/tests/test_beacon_heartbeat___health_endpoint_c.c:14` | `static void test_beacon_heartbeat___health_endpoint_placeholder(void **state)` |
| `TestBOFAPIVersioning` | class | `mutants/tests/test_bof_api_versioning.py:18` | `class TestBOFAPIVersioning` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_api_versioning.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_api_versioning_c.c:21` | `int main(void)` |
| `test_bof_api_versioning_placeholder` | function | `mutants/tests/test_bof_api_versioning_c.c:14` | `static void test_bof_api_versioning_placeholder(void **state)` |
| `compile_bof` | function | `mutants/tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `mutants/tests/test_bof_compile.py:35` | `def inspect_symbols(obj_path)` |
| `main` | function | `mutants/tests/test_bof_compile.py:91` | `def main()` |
| `test_compile_all` | function | `mutants/tests/test_bof_compile.py:53` | `def test_compile_all()` |
| `test_export_go` | function | `mutants/tests/test_bof_compile.py:60` | `def test_export_go()` |
| `test_no_libc_leak` | function | `mutants/tests/test_bof_compile.py:80` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `mutants/tests/test_bof_compile.py:68` | `def test_unresolved_beacon_api()` |
| `TestBOFPathTraversalHardening` | class | `mutants/tests/test_bof_path_traversal_hardening.py:18` | `class TestBOFPathTraversalHardening` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_path_traversal_hardening.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_path_traversal_hardening_c.c:21` | `int main(void)` |
| `test_bof_path_traversal_hardening_placeholder` | function | `mutants/tests/test_bof_path_traversal_hardening_c.c:14` | `static void test_bof_path_traversal_hardening_placeholder(void **state)` |
| `TestBOFStreaming` | class | `mutants/tests/test_bof_streaming_(large_outputs).py:18` | `class TestBOFStreaming(LargeOutputs)` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_bof_streaming_(large_outputs).py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_bof_streaming_(large_outputs)_c.c:21` | `int main(void)` |
| `test_bof_streaming_` | function | `mutants/tests/test_bof_streaming_(large_outputs)_c.c:14` | `static void test_bof_streaming_(large_outputs)_placeholder(void **state)` |
| `_free_port` | function | `mutants/tests/test_c2_http_e2e.py:43` | `def _free_port()` |
| `_recv_response` | function | `mutants/tests/test_c2_http_e2e.py:51` | `def _recv_response(sock, timeout)` |
| `encode` | function | `mutants/tests/test_c2_http_e2e.py:274` | `def encode(s)` |
| `main` | function | `mutants/tests/test_c2_http_e2e.py:399` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `mutants/tests/test_c2_http_e2e.py:326` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `mutants/tests/test_c2_http_e2e.py:183` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `mutants/tests/test_c2_http_e2e.py:65` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `mutants/tests/test_c2_http_e2e.py:115` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `mutants/tests/test_c2_http_e2e.py:233` | `def test_http_post_with_url_encoded_b64_payload()` |
| `TestC2RESTAPI` | class | `mutants/tests/test_c2_rest_api.py:18` | `class TestC2RESTAPI` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_c2_rest_api.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_c2_rest_api_c.c:21` | `int main(void)` |
| `test_c2_rest_api_placeholder` | function | `mutants/tests/test_c2_rest_api_c.c:14` | `static void test_c2_rest_api_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_c2_server.py:134` | `def main()` |
| `make_state` | function | `mutants/tests/test_c2_server.py:39` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `mutants/tests/test_c2_server.py:85` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `mutants/tests/test_c2_server.py:92` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `mutants/tests/test_c2_server.py:46` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `mutants/tests/test_c2_server.py:58` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `mutants/tests/test_c2_server.py:111` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `mutants/tests/test_c2_server.py:69` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `mutants/tests/test_c2_server.py:120` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `mutants/tests/test_c2_server.py:127` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `mutants/tests/test_c2_server.py:104` | `def test_unknown_selector()` |
| `TestCertificatePinningCConfig` | class | `mutants/tests/test_certificate_pinning.py:86` | `class TestCertificatePinningCConfig` |
| `TestCertificatePinningConfig` | class | `mutants/tests/test_certificate_pinning.py:23` | `class TestCertificatePinningConfig` |
| `TestCertificatePinningIntegration` | class | `mutants/tests/test_certificate_pinning.py:96` | `class TestCertificatePinningIntegration` |
| `TestCertificatePinningMutationResistance` | class | `mutants/tests/test_certificate_pinning.py:126` | `class TestCertificatePinningMutationResistance` |
| `test_beacon_rejects_mismatched_certificate` | method | `mutants/tests/test_certificate_pinning.py:109` | `def test_beacon_rejects_mismatched_certificate(self)` |
| `test_beacon_verifies_pinned_certificate` | method | `mutants/tests/test_certificate_pinning.py:99` | `def test_beacon_verifies_pinned_certificate(self)` |
| `test_c_config_parses_fingerprint_field` | method | `mutants/tests/test_certificate_pinning.py:89` | `def test_c_config_parses_fingerprint_field(self)` |
| `test_config_defaults_to_empty_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:73` | `def test_config_defaults_to_empty_fingerprint(self)` |
| `test_config_loads_empty_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:26` | `def test_config_loads_empty_fingerprint(self)` |
| `test_config_loads_valid_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:38` | `def test_config_loads_valid_fingerprint(self)` |
| `test_config_rejects_invalid_fingerprint_length` | method | `mutants/tests/test_certificate_pinning.py:51` | `def test_config_rejects_invalid_fingerprint_length(self)` |
| `test_config_rejects_non_hex_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:62` | `def test_config_rejects_non_hex_fingerprint(self)` |
| `test_fingerprint_empty_check_not_mutated_to_always_true` | method | `mutants/tests/test_certificate_pinning.py:129` | `def test_fingerprint_empty_check_not_mutated_to_always_true(self)` |
| `test_fingerprint_hex_validation_not_mutated` | method | `mutants/tests/test_certificate_pinning.py:139` | `def test_fingerprint_hex_validation_not_mutated(self)` |
| `test_pin_option_set_only_when_fingerprint_present` | method | `mutants/tests/test_certificate_pinning.py:151` | `def test_pin_option_set_only_when_fingerprint_present(self)` |
| `test_tofu_first_connection_stores_fingerprint` | method | `mutants/tests/test_certificate_pinning.py:117` | `def test_tofu_first_connection_stores_fingerprint(self)` |
| `TestCertificatePinningTOFU` | class | `mutants/tests/test_certificate_pinning___tofu.py:18` | `class TestCertificatePinningTOFU` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_certificate_pinning___tofu.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_certificate_pinning___tofu_c.c:21` | `int main(void)` |
| `test_certificate_pinning___tofu_placeholder` | function | `mutants/tests/test_certificate_pinning___tofu_c.c:14` | `static void test_certificate_pinning___tofu_placeholder(void **state)` |
| `TestCommandExecutionviaexecve` | class | `mutants/tests/test_command_execution_via_execve.py:18` | `class TestCommandExecutionviaexecve` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_command_execution_via_execve.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_command_execution_via_execve_c.c:21` | `int main(void)` |
| `test_command_execution_via_execve_placeholder` | function | `mutants/tests/test_command_execution_via_execve_c.c:14` | `static void test_command_execution_via_execve_placeholder(void **state)` |
| `compile_harness` | function | `mutants/tests/test_config.py:24` | `def compile_harness()` |
| `main` | function | `mutants/tests/test_config.py:156` | `def main()` |
| `run_harness` | function | `mutants/tests/test_config.py:38` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `mutants/tests/test_config.py:141` | `def test_bad_hex_key()` |
| `test_default_load` | function | `mutants/tests/test_config.py:55` | `def test_default_load()` |
| `test_missing_file` | function | `mutants/tests/test_config.py:90` | `def test_missing_file()` |
| `test_overrides` | function | `mutants/tests/test_config.py:73` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `mutants/tests/test_config.py:98` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `mutants/tests/test_config.py:115` | `def test_search_order_falls_back_to_cwd_default()` |
| `main` | function | `mutants/tests/test_containerized_build_+_sbom_c.c:21` | `int main(void)` |
| `compile_harness` | function | `mutants/tests/test_crypto.py:27` | `def compile_harness()` |
| `main` | function | `mutants/tests/test_crypto.py:126` | `def main()` |
| `run` | function | `mutants/tests/test_crypto.py:50` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `mutants/tests/test_crypto.py:63` | `def test_block_boundary()` |
| `test_known_ciphertext` | function | `mutants/tests/test_crypto.py:74` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `mutants/tests/test_crypto.py:68` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `mutants/tests/test_crypto.py:93` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `mutants/tests/test_crypto.py:59` | `def test_short()` |
| `TestHKDFKeyDerivation` | class | `mutants/tests/test_hkdf_key_derivation.py:18` | `class TestHKDFKeyDerivation` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_hkdf_key_derivation.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_hkdf_key_derivation_c.c:21` | `int main(void)` |
| `test_hkdf_key_derivation_placeholder` | function | `mutants/tests/test_hkdf_key_derivation_c.c:14` | `static void test_hkdf_key_derivation_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_install_deploy.py:120` | `def main()` |
| `make_all` | function | `mutants/tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `mutants/tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `mutants/tests/test_install_deploy.py:56` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `mutants/tests/test_install_deploy.py:98` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `mutants/tests/test_install_deploy.py:75` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `mutants/tests/test_install_deploy.py:90` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `mutants/tests/test_install_deploy.py:67` | `def test_staged_files_have_correct_modes()` |
| `TestIVGenerationwithEntropyVerification` | class | `mutants/tests/test_iv_generation_with_entropy_verification.py:18` | `class TestIVGenerationwithEntropyVerification` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_iv_generation_with_entropy_verification.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_iv_generation_with_entropy_verification_c.c:21` | `int main(void)` |
| `test_iv_generation_with_entropy_verification_placeholder` | function | `mutants/tests/test_iv_generation_with_entropy_verification_c.c:14` | `static void test_iv_generation_with_entropy_verification_placeholder(void **state)` |
| `TestMutationTestingIntegration` | class | `mutants/tests/test_mutation_testing_integration.py:18` | `class TestMutationTestingIntegration` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_mutation_testing_integration.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_mutation_testing_integration_c.c:21` | `int main(void)` |
| `test_mutation_testing_integration_placeholder` | function | `mutants/tests/test_mutation_testing_integration_c.c:14` | `static void test_mutation_testing_integration_placeholder(void **state)` |
| `main` | function | `mutants/tests/test_pre-commit_+_ci_hardening_c.c:21` | `int main(void)` |
| `TestReplayProtection` | class | `mutants/tests/test_replay_protection.py:18` | `class TestReplayProtection` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_replay_protection.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_replay_protection_c.c:21` | `int main(void)` |
| `test_replay_protection_placeholder` | function | `mutants/tests/test_replay_protection_c.c:14` | `static void test_replay_protection_placeholder(void **state)` |
| `TestSOCKS5HTTPProxySupport` | class | `mutants/tests/test_socks5___http_proxy_support.py:18` | `class TestSOCKS5HTTPProxySupport` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_socks5___http_proxy_support.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_socks5___http_proxy_support_c.c:21` | `int main(void)` |
| `test_socks5___http_proxy_support_placeholder` | function | `mutants/tests/test_socks5___http_proxy_support_c.c:14` | `static void test_socks5___http_proxy_support_placeholder(void **state)` |
| `TestStructuredJSONLLogging` | class | `mutants/tests/test_structured_jsonl_logging.py:18` | `class TestStructuredJSONLLogging` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_structured_jsonl_logging.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_structured_jsonl_logging_c.c:21` | `int main(void)` |
| `test_structured_jsonl_logging_placeholder` | function | `mutants/tests/test_structured_jsonl_logging_c.c:14` | `static void test_structured_jsonl_logging_placeholder(void **state)` |
| `TestTLSClientCertificateAuthentication` | class | `mutants/tests/test_tls_client_certificate_authentication.py:18` | `class TestTLSClientCertificateAuthentication` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_tls_client_certificate_authentication.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_tls_client_certificate_authentication_c.c:21` | `int main(void)` |
| `test_tls_client_certificate_authentication_placeholder` | function | `mutants/tests/test_tls_client_certificate_authentication_c.c:14` | `static void test_tls_client_certificate_authentication_placeholder(void **state)` |
| `TestUnifiedConfigSchema` | class | `mutants/tests/test_unified_config_schema.py:18` | `class TestUnifiedConfigSchema` |
| `test_placeholder_fails_initially` | method | `mutants/tests/test_unified_config_schema.py:21` | `def test_placeholder_fails_initially(self)` |
| `main` | function | `mutants/tests/test_unified_config_schema_c.c:21` | `int main(void)` |
| `test_unified_config_schema_placeholder` | function | `mutants/tests/test_unified_config_schema_c.c:14` | `static void test_unified_config_schema_placeholder(void **state)` |
| `apply_mutation` | function | `scripts/mutation_test_c.py:103` | `def apply_mutation(content, line_num, mutated_line)` |
| `compile_and_test` | function | `scripts/mutation_test_c.py:111` | `def compile_and_test(mutant_dir, test_name)` |
| `find_mutable_lines` | function | `scripts/mutation_test_c.py:82` | `def find_mutable_lines(content)` |
| `main` | function | `scripts/mutation_test_c.py:222` | `def main()` |
| `run_mutation_test` | function | `scripts/mutation_test_c.py:136` | `def run_mutation_test()` |
| `should_mutate` | function | `scripts/mutation_test_c.py:73` | `def should_mutate(filepath)` |
| `async_i_o_for_beacon_process` | function | `src/async_i_o_for_beacon.c:6` | `bool async_i_o_for_beacon_process(void)` |
| `beacon_heartbeat___health_endpoint_process` | function | `src/beacon_heartbeat___health_endpoint.c:6` | `bool beacon_heartbeat___health_endpoint_process(void)` |
| `bof_api_versioning_process` | function | `src/bof_api_versioning.c:6` | `bool bof_api_versioning_process(void)` |
| `bof_path_traversal_hardening_process` | function | `src/bof_path_traversal_hardening.c:6` | `bool bof_path_traversal_hardening_process(void)` |
| `bof_streaming_` | function | `src/bof_streaming_(large_outputs).c:6` | `bool bof_streaming_(large_outputs)_process(void)` |
| `c2_rest_api_process` | function | `src/c2_rest_api.c:6` | `bool c2_rest_api_process(void)` |
| `certificate_pinning___tofu_process` | function | `src/certificate_pinning___tofu.c:6` | `bool certificate_pinning___tofu_process(void)` |
| `command_execution_via_execve_process` | function | `src/command_execution_via_execve.c:6` | `bool command_execution_via_execve_process(void)` |
| `hkdf_key_derivation_process` | function | `src/hkdf_key_derivation.c:6` | `bool hkdf_key_derivation_process(void)` |
| `iv_generation_with_entropy_verification_process` | function | `src/iv_generation_with_entropy_verification.c:6` | `bool iv_generation_with_entropy_verification_process(void)` |
| `mutation_testing_integration_process` | function | `src/mutation_testing_integration.c:6` | `bool mutation_testing_integration_process(void)` |
| `replay_protection_process` | function | `src/replay_protection.c:6` | `bool replay_protection_process(void)` |
| `socks5___http_proxy_support_process` | function | `src/socks5___http_proxy_support.c:6` | `bool socks5___http_proxy_support_process(void)` |
| `structured_jsonl_logging_process` | function | `src/structured_jsonl_logging.c:6` | `bool structured_jsonl_logging_process(void)` |
| `tls_client_certificate_authentication_process` | function | `src/tls_client_certificate_authentication.c:6` | `bool tls_client_certificate_authentication_process(void)` |
| `unified_config_schema_process` | function | `src/unified_config_schema.c:6` | `bool unified_config_schema_process(void)` |
| `main` | function | `tests/config_harness.c:24` | `int main(void)` |
| `hex_to_bytes` | function | `tests/crypto_harness.c:12` | `static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)` |
| `main` | function | `tests/crypto_harness.c:27` | `int main(int argc, char **argv)` |
| `compile_beacon` | function | `tests/test_beacon_build.py:43` | `def compile_beacon()` |
| `ensure_beacon` | function | `tests/test_beacon_build.py:79` | `def ensure_beacon()` |
| `have_headers` | function | `tests/test_beacon_build.py:29` | `def have_headers()` |
| `inspect_binary` | function | `tests/test_beacon_build.py:74` | `def inspect_binary()` |
| `main` | function | `tests/test_beacon_build.py:132` | `def main()` |
| `test_beacon_compiles_and_links` | function | `tests/test_beacon_build.py:93` | `def test_beacon_compiles_and_links()` |
| `test_beacon_exposes_bof_api` | function | `tests/test_beacon_build.py:102` | `def test_beacon_exposes_bof_api()` |
| `test_beacon_exposes_elf_loader` | function | `tests/test_beacon_build.py:122` | `def test_beacon_exposes_elf_loader()` |
| `compile_bof` | function | `tests/test_bof_compile.py:21` | `def compile_bof(name)` |
| `inspect_symbols` | function | `tests/test_bof_compile.py:44` | `def inspect_symbols(obj_path)` |
| `main` | function | `tests/test_bof_compile.py:118` | `def main()` |
| `test_compile_all` | function | `tests/test_bof_compile.py:62` | `def test_compile_all()` |
| `test_export_go` | function | `tests/test_bof_compile.py:71` | `def test_export_go()` |
| `test_no_libc_leak` | function | `tests/test_bof_compile.py:97` | `def test_no_libc_leak()` |
| `test_unresolved_beacon_api` | function | `tests/test_bof_compile.py:79` | `def test_unresolved_beacon_api()` |
| `TestBOFPathTraversalConfig` | class | `tests/test_bof_path_traversal.py:25` | `class TestBOFPathTraversalConfig` |
| `TestBOFPathTraversalMutationResistance` | class | `tests/test_bof_path_traversal.py:175` | `class TestBOFPathTraversalMutationResistance` |
| `TestBOFPathTraversalServer` | class | `tests/test_bof_path_traversal.py:36` | `class TestBOFPathTraversalServer` |
| `test_absolute_path_rejected` | method | `tests/test_bof_path_traversal.py:89` | `def test_absolute_path_rejected(self)` |
| `test_basename_not_sufficient_protection` | method | `tests/test_bof_path_traversal.py:178` | `def test_basename_not_sufficient_protection(self)` |
| `test_case_sensitivity_on_linux` | method | `tests/test_bof_path_traversal.py:216` | `def test_case_sensitivity_on_linux(self)` |
| `test_double_url_encoded_traversal_rejected` | method | `tests/test_bof_path_traversal.py:114` | `def test_double_url_encoded_traversal_rejected(self)` |
| `test_normal_bof_name_served` | method | `tests/test_bof_path_traversal.py:39` | `def test_normal_bof_name_served(self)` |
| `test_null_byte_injection_rejected` | method | `tests/test_bof_path_traversal.py:126` | `def test_null_byte_injection_rejected(self)` |
| `test_path_traversal_multiple_parent_dirs_rejected` | method | `tests/test_bof_path_traversal.py:65` | `def test_path_traversal_multiple_parent_dirs_rejected(self)` |
| `test_path_traversal_parent_dir_rejected` | method | `tests/test_bof_path_traversal.py:53` | `def test_path_traversal_parent_dir_rejected(self)` |
| `test_path_traversal_with_subdir_rejected` | method | `tests/test_bof_path_traversal.py:77` | `def test_path_traversal_with_subdir_rejected(self)` |
| `test_realpath_prefix_check_not_mutated` | method | `tests/test_bof_path_traversal.py:186` | `def test_realpath_prefix_check_not_mutated(self)` |
| `test_symlink_outside_upload_dir_rejected` | method | `tests/test_bof_path_traversal.py:156` | `def test_symlink_outside_upload_dir_rejected(self)` |
| `test_unicode_normalization_not_mutated` | method | `tests/test_bof_path_traversal.py:234` | `def test_unicode_normalization_not_mutated(self)` |
| `test_upload_dir_config_exists` | method | `tests/test_bof_path_traversal.py:28` | `def test_upload_dir_config_exists(self)` |
| `test_upload_dir_symlink_escape_prevented` | method | `tests/test_bof_path_traversal.py:138` | `def test_upload_dir_symlink_escape_prevented(self)` |
| `test_url_encoded_traversal_rejected` | method | `tests/test_bof_path_traversal.py:101` | `def test_url_encoded_traversal_rejected(self)` |
| `TestC2BeaconBOFIntegration` | class | `tests/test_c2_beacon_bof_integration.py:34` | `class TestC2BeaconBOFIntegration` |
| `_free_port` | method | `tests/test_c2_beacon_bof_integration.py:76` | `def _free_port(self)` |
| `_run_server` | method | `tests/test_c2_beacon_bof_integration.py:283` | `def _run_server(self, cfg, state)` |
| `_wait_for_bof_result` | method | `tests/test_c2_beacon_bof_integration.py:98` | `def _wait_for_bof_result(self, state, client_id, timeout)` |
| `_wait_for_server_ready` | method | `tests/test_c2_beacon_bof_integration.py:84` | `def _wait_for_server_ready(self, host, port, timeout)` |
| `_wait_for_server_ready` | method | `tests/test_c2_beacon_bof_integration.py:286` | `def _wait_for_server_ready(self, host, port, timeout)` |
| `setup_method` | method | `tests/test_c2_beacon_bof_integration.py:37` | `def setup_method(self)` |
| `teardown_method` | method | `tests/test_c2_beacon_bof_integration.py:71` | `def teardown_method(self)` |
| `test_beacon_executes_whoami_bof` | method | `tests/test_c2_beacon_bof_integration.py:118` | `def test_beacon_executes_whoami_bof(self)` |
| `test_c2_beacon_bof_integration` | function | `tests/test_c2_beacon_bof_integration.py:300` | `def test_c2_beacon_bof_integration()` |
| `_free_port` | function | `tests/test_c2_http_e2e.py:45` | `def _free_port()` |
| `_recv_response` | function | `tests/test_c2_http_e2e.py:53` | `def _recv_response(sock, timeout)` |
| `encode` | function | `tests/test_c2_http_e2e.py:288` | `def encode(s)` |
| `main` | function | `tests/test_c2_http_e2e.py:422` | `def main()` |
| `test_fragmented_post_is_dispatched_as_http` | function | `tests/test_c2_http_e2e.py:347` | `def test_fragmented_post_is_dispatched_as_http()` |
| `test_gopher_legacy_still_works` | function | `tests/test_c2_http_e2e.py:192` | `def test_gopher_legacy_still_works()` |
| `test_http_get_poll_returns_encrypted_command` | function | `tests/test_c2_http_e2e.py:67` | `def test_http_get_poll_returns_encrypted_command()` |
| `test_http_post_report_writes_log` | function | `tests/test_c2_http_e2e.py:122` | `def test_http_post_report_writes_log()` |
| `test_http_post_with_url_encoded_b64_payload` | function | `tests/test_c2_http_e2e.py:246` | `def test_http_post_with_url_encoded_b64_payload()` |
| `main` | function | `tests/test_c2_server.py:145` | `def main()` |
| `make_state` | function | `tests/test_c2_server.py:41` | `def make_state(tmp)` |
| `test_bof_not_found` | function | `tests/test_c2_server.py:96` | `def test_bof_not_found()` |
| `test_bof_serves_existing_file` | function | `tests/test_c2_server.py:103` | `def test_bof_serves_existing_file()` |
| `test_get_command_empty` | function | `tests/test_c2_server.py:48` | `def test_get_command_empty()` |
| `test_get_command_queued` | function | `tests/test_c2_server.py:60` | `def test_get_command_queued()` |
| `test_path_traversal_in_bof_name` | function | `tests/test_c2_server.py:122` | `def test_path_traversal_in_bof_name()` |
| `test_report_writes_log` | function | `tests/test_c2_server.py:71` | `def test_report_writes_log()` |
| `test_roundtrip_empty` | function | `tests/test_c2_server.py:131` | `def test_roundtrip_empty()` |
| `test_roundtrip_text` | function | `tests/test_c2_server.py:138` | `def test_roundtrip_text()` |
| `test_unknown_selector` | function | `tests/test_c2_server.py:115` | `def test_unknown_selector()` |
| `Handler` | class | `tests/test_certificate_pinning.py:155` | `class Handler(BaseHTTPRequestHandler)` |
| `TestCertificatePinningCConfig` | class | `tests/test_certificate_pinning.py:86` | `class TestCertificatePinningCConfig` |
| `TestCertificatePinningConfig` | class | `tests/test_certificate_pinning.py:23` | `class TestCertificatePinningConfig` |
| `TestCertificatePinningIntegration` | class | `tests/test_certificate_pinning.py:96` | `class TestCertificatePinningIntegration` |
| `TestCertificatePinningMutationResistance` | class | `tests/test_certificate_pinning.py:321` | `class TestCertificatePinningMutationResistance` |
| `_free_port` | method | `tests/test_certificate_pinning.py:106` | `def _free_port(self)` |
| `_gen_cert_and_pin` | method | `tests/test_certificate_pinning.py:114` | `def _gen_cert_and_pin(self)` |
| `_run` | function | `tests/test_certificate_pinning.py:171` | `def _run()` |
| `_run_beacon_with_bof_tls` | method | `tests/test_certificate_pinning.py:181` | `def _run_beacon_with_bof_tls(self, cert_pem, key_pem, pin_hex)` |
| `_start_tls_server` | method | `tests/test_certificate_pinning.py:149` | `def _start_tls_server(self, port, cert_pem, key_pem, body)` |
| `do_GET` | method | `tests/test_certificate_pinning.py:156` | `def do_GET(self)` |
| `log_message` | method | `tests/test_certificate_pinning.py:162` | `def log_message(self)` |
| `test_beacon_rejects_mismatched_certificate` | method | `tests/test_certificate_pinning.py:293` | `def test_beacon_rejects_mismatched_certificate(self)` |
| `test_beacon_verifies_pinned_certificate` | method | `tests/test_certificate_pinning.py:282` | `def test_beacon_verifies_pinned_certificate(self)` |
| `test_c_config_parses_fingerprint_field` | method | `tests/test_certificate_pinning.py:89` | `def test_c_config_parses_fingerprint_field(self)` |
| `test_config_defaults_to_empty_fingerprint` | method | `tests/test_certificate_pinning.py:73` | `def test_config_defaults_to_empty_fingerprint(self)` |
| `test_config_loads_empty_fingerprint` | method | `tests/test_certificate_pinning.py:26` | `def test_config_loads_empty_fingerprint(self)` |
| `test_config_loads_valid_fingerprint` | method | `tests/test_certificate_pinning.py:38` | `def test_config_loads_valid_fingerprint(self)` |
| `test_config_rejects_invalid_fingerprint_length` | method | `tests/test_certificate_pinning.py:51` | `def test_config_rejects_invalid_fingerprint_length(self)` |
| `test_config_rejects_non_hex_fingerprint` | method | `tests/test_certificate_pinning.py:62` | `def test_config_rejects_non_hex_fingerprint(self)` |
| `test_fingerprint_empty_check_not_mutated_to_always_true` | method | `tests/test_certificate_pinning.py:324` | `def test_fingerprint_empty_check_not_mutated_to_always_true(self)` |
| `test_fingerprint_hex_validation_not_mutated` | method | `tests/test_certificate_pinning.py:334` | `def test_fingerprint_hex_validation_not_mutated(self)` |
| `test_pin_option_set_only_when_fingerprint_present` | method | `tests/test_certificate_pinning.py:346` | `def test_pin_option_set_only_when_fingerprint_present(self)` |
| `test_tofu_first_connection_stores_fingerprint` | method | `tests/test_certificate_pinning.py:307` | `def test_tofu_first_connection_stores_fingerprint(self)` |
| `main` | function | `tests/test_certificate_pinning_c.c:90` | `int main(void)` |
| `test_cert_fingerprint_defaults_to_empty` | function | `tests/test_certificate_pinning_c.c:19` | `static void test_cert_fingerprint_defaults_to_empty(void **state)` |
| `test_cert_fingerprint_invalid_length_fails` | function | `tests/test_certificate_pinning_c.c:55` | `static void test_cert_fingerprint_invalid_length_fails(void **state)` |
| `test_cert_fingerprint_loads_from_config` | function | `tests/test_certificate_pinning_c.c:29` | `static void test_cert_fingerprint_loads_from_config(void **state)` |
| `test_network_struct_has_fingerprint_field` | function | `tests/test_certificate_pinning_c.c:82` | `static void test_network_struct_has_fingerprint_field(void **state)` |
| `compile_harness` | function | `tests/test_config.py:25` | `def compile_harness()` |
| `main` | function | `tests/test_config.py:187` | `def main()` |
| `run_harness` | function | `tests/test_config.py:46` | `def run_harness(config_text)` |
| `test_bad_hex_key` | function | `tests/test_config.py:172` | `def test_bad_hex_key()` |
| `test_default_load` | function | `tests/test_config.py:63` | `def test_default_load()` |
| `test_missing_file` | function | `tests/test_config.py:104` | `def test_missing_file()` |
| `test_overrides` | function | `tests/test_config.py:81` | `def test_overrides()` |
| `test_search_order_env_wins` | function | `tests/test_config.py:112` | `def test_search_order_env_wins()` |
| `test_search_order_falls_back_to_cwd_default` | function | `tests/test_config.py:137` | `def test_search_order_falls_back_to_cwd_default()` |
| `compile_harness` | function | `tests/test_crypto.py:27` | `def compile_harness()` |
| `main` | function | `tests/test_crypto.py:167` | `def main()` |
| `run` | function | `tests/test_crypto.py:59` | `def run(plaintext, key_hex)` |
| `test_block_boundary` | function | `tests/test_crypto.py:72` | `def test_block_boundary()` |
| `test_c_replay_encrypt_python_decrypt` | function | `tests/test_crypto.py:136` | `def test_c_replay_encrypt_python_decrypt()` |
| `test_known_ciphertext` | function | `tests/test_crypto.py:83` | `def test_known_ciphertext()` |
| `test_longer_than_block` | function | `tests/test_crypto.py:77` | `def test_longer_than_block()` |
| `test_python_can_decrypt_c_ciphertext` | function | `tests/test_crypto.py:104` | `def test_python_can_decrypt_c_ciphertext()` |
| `test_short` | function | `tests/test_crypto.py:68` | `def test_short()` |
| `TestExecveCommandExecution` | class | `tests/test_execve_command.py:25` | `class TestExecveCommandExecution` |
| `TestExecveMutationResistance` | class | `tests/test_execve_command.py:57` | `class TestExecveMutationResistance` |
| `test_argv_array_not_string` | method | `tests/test_execve_command.py:71` | `def test_argv_array_not_string(self)` |
| `test_command_with_arguments` | method | `tests/test_execve_command.py:34` | `def test_command_with_arguments(self)` |
| `test_no_popen_call` | method | `tests/test_execve_command.py:67` | `def test_no_popen_call(self)` |
| `test_no_system_call` | method | `tests/test_execve_command.py:60` | `def test_no_system_call(self)` |
| `test_non_existent_command` | method | `tests/test_execve_command.py:42` | `def test_non_existent_command(self)` |
| `test_quoted_arguments` | method | `tests/test_execve_command.py:38` | `def test_quoted_arguments(self)` |
| `test_shell_metacharacters_escaped` | method | `tests/test_execve_command.py:77` | `def test_shell_metacharacters_escaped(self)` |
| `test_shell_metacharacters_not_interpreted` | method | `tests/test_execve_command.py:50` | `def test_shell_metacharacters_not_interpreted(self)` |
| `test_simple_command_execution` | method | `tests/test_execve_command.py:28` | `def test_simple_command_execution(self)` |
| `test_stderr_capture` | method | `tests/test_execve_command.py:46` | `def test_stderr_capture(self)` |
| `TestHKDFConfigIntegration` | class | `tests/test_hkdf_key_derivation.py:159` | `class TestHKDFConfigIntegration` |
| `TestHKDFDerivation` | class | `tests/test_hkdf_key_derivation.py:87` | `class TestHKDFDerivation` |
| `TestHKDFKeyDerivationConfig` | class | `tests/test_hkdf_key_derivation.py:24` | `class TestHKDFKeyDerivationConfig` |
| `TestHKDFMutationResistance` | class | `tests/test_hkdf_key_derivation.py:220` | `class TestHKDFMutationResistance` |
| `test_c_and_python_derive_same_keys` | method | `tests/test_hkdf_key_derivation.py:196` | `def test_c_and_python_derive_same_keys(self)` |
| `test_config_loads_aes_key_hex_backward_compat` | method | `tests/test_hkdf_key_derivation.py:40` | `def test_config_loads_aes_key_hex_backward_compat(self)` |
| `test_config_loads_master_key_hex` | method | `tests/test_hkdf_key_derivation.py:27` | `def test_config_loads_master_key_hex(self)` |
| `test_config_rejects_missing_both_keys` | method | `tests/test_hkdf_key_derivation.py:53` | `def test_config_rejects_missing_both_keys(self)` |
| `test_config_validates_master_key_hex_hex_chars` | method | `tests/test_hkdf_key_derivation.py:75` | `def test_config_validates_master_key_hex_hex_chars(self)` |
| `test_config_validates_master_key_hex_length` | method | `tests/test_hkdf_key_derivation.py:64` | `def test_config_validates_master_key_hex_length(self)` |
| `test_hkdf_derives_encryption_and_hmac_keys` | method | `tests/test_hkdf_key_derivation.py:90` | `def test_hkdf_derives_encryption_and_hmac_keys(self)` |
| `test_hkdf_deterministic` | method | `tests/test_hkdf_key_derivation.py:123` | `def test_hkdf_deterministic(self)` |
| `test_hkdf_different_info_produces_different_keys` | method | `tests/test_hkdf_key_derivation.py:137` | `def test_hkdf_different_info_produces_different_keys(self)` |
| `test_info_strings_are_enc_and_hmac_not_mutated` | method | `tests/test_hkdf_key_derivation.py:238` | `def test_info_strings_are_enc_and_hmac_not_mutated(self)` |
| `test_key_length_is_32_bytes_not_mutated` | method | `tests/test_hkdf_key_derivation.py:263` | `def test_key_length_is_32_bytes_not_mutated(self)` |
| `test_load_config_derives_from_aes_key_when_no_master_key` | method | `tests/test_hkdf_key_derivation.py:180` | `def test_load_config_derives_from_aes_key_when_no_master_key(self)` |
| `test_load_config_returns_derived_keys_when_master_key_present` | method | `tests/test_hkdf_key_derivation.py:162` | `def test_load_config_returns_derived_keys_when_master_key_present(self)` |
| `test_salt_is_constant_not_mutated` | method | `tests/test_hkdf_key_derivation.py:223` | `def test_salt_is_constant_not_mutated(self)` |
| `test_sha256_not_mutated_to_sha1_or_md5` | method | `tests/test_hkdf_key_derivation.py:277` | `def test_sha256_not_mutated_to_sha1_or_md5(self)` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:207` | `assert_memory_equal(crypto.master_key, (uint8_t[BSB_AES_KEY_BYTES])` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:208` | `assert_memory_equal(crypto.encryption_key, (uint8_t[BSB_AES_KEY_BYTES])` |
| `assert_memory_equal` | function | `tests/test_hkdf_key_derivation_c.c:209` | `assert_memory_equal(crypto.hmac_key, (uint8_t[BSB_AES_KEY_BYTES])` |

Next: [SYMBOLS_p4.md](SYMBOLS_p4.md)
