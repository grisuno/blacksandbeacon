# Subsystem: legacy

## legacy/beacon3.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 52)
  - `Trampoline` (struct, line 60)
  - `SymbolResolver` (struct, line 69)
  - `TrampolineCache` (struct, line 76)
  - `__attribute__` (function, line 145) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 196) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 213) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 227) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 268) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 286) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 324) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 342) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 436) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 454) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 480) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 514) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 550) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 576) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 584) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1083) `char *get_local_ips()`
  - `download_bof` (function, line 1118) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1141) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1187) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 33) `#define C2_URL`
  - `CLIENT_ID` (macro, line 34) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 35) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 36) `#define USER_AGENTS_COUNT`

## legacy/beacon5.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 61)
  - `peer_t` (struct, line 69)
  - `mesh_msg_t` (struct, line 77)
  - `Trampoline` (struct, line 102)
  - `SymbolResolver` (struct, line 111)
  - `TrampolineCache` (struct, line 118)
  - `__attribute__` (function, line 188) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 239) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 256) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 270) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 311) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 329) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 367) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 385) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 479) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 497) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 523) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 557) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 593) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 619) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 627) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1126) `char *get_local_ips()`
  - `download_bof` (function, line 1161) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1184) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `mesh_mark_seen` (function, line 1231) `void mesh_mark_seen(const char *msg_id)`
  - `mesh_is_seen` (function, line 1240) `int mesh_is_seen(const char *msg_id)`
  - `mesh_add_peer` (function, line 1255) `void mesh_add_peer(const char *ip, int port)`
  - `mesh_cleanup_peers` (function, line 1283) `void mesh_cleanup_peers()`
  - `mesh_send_to_peer` (function, line 1300) `int mesh_send_to_peer(const char *ip, int port, const mesh_msg_t *msg)`
  - `mesh_propagate` (function, line 1324) `void mesh_propagate(const char *command)`
  - `mesh_discovery_thread` (function, line 1356) `void *mesh_discovery_thread(void *arg)`
  - `mesh_listener_thread` (function, line 1447) `void *mesh_listener_thread(void *arg)`
  - `mesh_send_message` (function, line 1667) `void mesh_send_message(int type, const char *target, const char *payload)`
  - `main` (function, line 1702) `int main(int argc, char **argv)`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 36) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 37) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 38) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 39) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 40) `#define MESH_MSG_SIZE`
  - `C2_URL` (macro, line 42) `#define C2_URL`
  - `CLIENT_ID` (macro, line 43) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 44) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 45) `#define USER_AGENTS_COUNT`

## legacy/beacon6.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 53)
  - `Trampoline` (struct, line 61)
  - `SymbolResolver` (struct, line 70)
  - `TrampolineCache` (struct, line 77)
  - `__attribute__` (function, line 146) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `delay_ms` (function, line 197) `static void delay_ms(int ms)`
  - `is_prime` (function, line 204) `static unsigned int is_prime(unsigned int x)`
  - `get_nth_prime_limited` (function, line 224) `static unsigned int get_nth_prime_limited(unsigned int n)`
  - `portable_rand_19k_29k` (function, line 253) `static unsigned int portable_rand_19k_29k(void)`
  - `BeaconPrintf` (function, line 266) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 283) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 297) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 338) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 356) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 394) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 412) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 506) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 524) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 550) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 584) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 620) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 646) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 654) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1153) `char *get_local_ips()`
  - `download_bof` (function, line 1188) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1211) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1257) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 34) `#define C2_URL`
  - `CLIENT_ID` (macro, line 35) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 36) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 37) `#define USER_AGENTS_COUNT`

## legacy/beacon_p2p.c
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 676)
  - `peer_t` (struct, line 59)
  - `p2p_header_t` (struct, line 73)
  - `Trampoline` (struct, line 175)
  - `SymbolResolver` (struct, line 182)
  - `TrampolineCache` (struct, line 192)
  - `BeaconDataParse` (function, line 93) `void BeaconDataParse(datap *parser, char *buffer, int size)`
  - `BeaconDataPtr` (function, line 100) `char *BeaconDataPtr(datap *parser, int size)`
  - `BeaconDataInt` (function, line 110) `int BeaconDataInt(datap *parser)`
  - `BeaconDataShort` (function, line 118) `short BeaconDataShort(datap *parser)`
  - `BeaconDataLength` (function, line 126) `int BeaconDataLength(datap *parser)`
  - `BeaconDataExtract` (function, line 131) `char *BeaconDataExtract(datap *parser, int *size)`
  - `BeaconPrintf` (function, line 142) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 159) `void BeaconOutput(int type, const char *data, int len)`
  - `__attribute__` (function, line 250) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `create_trampoline` (function, line 278) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 309) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 323) `static void *get_or_create_trampoline(void *target)`
  - `page_align` (function, line 350) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 358) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `WriteMemoryCallback` (function, line 683) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `https_request` (function, line 707) `char *https_request(const char *url, const char *method, const char *post_data)`
  - `base64_encode` (function, line 763) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 780) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 802) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 832) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 866) `char *exec_cmd(const char *cmd, int *out_len)`
  - `get_local_ips` (function, line 891) `char *get_local_ips()`
  - `download_bof` (function, line 925) `unsigned char *download_bof(const char *url, size_t *out_size)`
  - `run_bof_and_capture` (function, line 939) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `add_peer` (function, line 965) `void add_peer(struct in_addr ip, int port, const char *id)`
  - `peer_discovery_thread` (function, line 992) `void *peer_discovery_thread(void *arg)`
  - `handle_peer_connection` (function, line 1032) `void *handle_peer_connection(void *arg)`
  - `peer_server_thread` (function, line 1130) `void *peer_server_thread(void *arg)`
  - `send_to_peer` (function, line 1153) `char *send_to_peer(peer_t *peer, const char *data, int *out_len)`
  - `send_to_c2_or_peer` (function, line 1197) `char *send_to_c2_or_peer(const char *url, const char *method, const char *data, int *out_len)`
  - `execute_generic_command` (function, line 1231) `char *execute_generic_command(const char *cmd, int *out_len)`
  - `main` (function, line 1276) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2_URL` (macro, line 37) `#define C2_URL`
  - `CLIENT_ID` (macro, line 38) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 39) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 40) `#define USER_AGENTS_COUNT`
  - `PEER_DISCOVERY_PORT` (macro, line 42) `#define PEER_DISCOVERY_PORT`
  - `PEER_TCP_PORT` (macro, line 43) `#define PEER_TCP_PORT`
  - `PEER_MAGIC` (macro, line 44) `#define PEER_MAGIC`
  - `PEER_VERSION` (macro, line 45) `#define PEER_VERSION`
  - `BROADCAST_INTERVAL` (macro, line 46) `#define BROADCAST_INTERVAL`
  - `MAX_PEERS` (macro, line 47) `#define MAX_PEERS`

## legacy/gopher_beacon.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 49)
  - `Trampoline` (struct, line 57)
  - `SymbolResolver` (struct, line 66)
  - `TrampolineCache` (struct, line 73)
  - `__attribute__` (function, line 142) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 193) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 210) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 224) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 265) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 283) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 321) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `gopher_request` (function, line 339) `char *gopher_request(const char *host, int port, const char *selector, const char *method,
      ...`
  - `base64_encode` (function, line 422) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 440) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 466) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 500) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 536) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 573) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 581) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1080) `char *get_local_ips()`
  - `download_bof` (function, line 1115) `unsigned char *download_bof(const char *bof_selector, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1147) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1193) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2` (macro, line 30) `#define C2`
  - `CLIENT_ID` (macro, line 31) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 32) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 33) `#define USER_AGENTS_COUNT`

## legacy/v1_gopher_beacon.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 49)
  - `Trampoline` (struct, line 57)
  - `SymbolResolver` (struct, line 66)
  - `TrampolineCache` (struct, line 73)
  - `__attribute__` (function, line 142) `static void __attribute__((noinline)) call_bof_isolated(bof_func_t func, char *args,
            ...`
  - `BeaconPrintf` (function, line 193) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 210) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 224) `static void *create_trampoline(void *target)`
  - `cleanup_trampolines` (function, line 265) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 283) `static void *get_or_create_trampoline(void *target)`
  - `WriteMemoryCallback` (function, line 321) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `gopher_request` (function, line 339) `char *gopher_request(const char *host, int port, const char *selector, const char *method,
      ...`
  - `base64_encode` (function, line 422) `char *base64_encode(const unsigned char *input, int len)`
  - `base64_decode` (function, line 440) `unsigned char *base64_decode(const char *input, int *len)`
  - `aes256_cfb_encrypt` (function, line 466) `unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 500) `unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
            ...`
  - `exec_cmd` (function, line 536) `char *exec_cmd(const char *cmd, int *out_len)`
  - `page_align` (function, line 573) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 581) `int RunELF(const char *functionname, unsigned char *elf_data, uint32_t filesize,
           unsig...`
  - `get_local_ips` (function, line 1080) `char *get_local_ips()`
  - `download_bof` (function, line 1115) `unsigned char *download_bof(const char *bof_selector, size_t *out_size)`
  - `run_bof_and_capture` (function, line 1147) `char *run_bof_and_capture(unsigned char *elf_data, uint32_t filesize, char *args, int arglen,
   ...`
  - `main` (function, line 1193) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2` (macro, line 30) `#define C2`
  - `CLIENT_ID` (macro, line 31) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 32) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 33) `#define USER_AGENTS_COUNT`
