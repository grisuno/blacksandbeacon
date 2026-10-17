# Documentation Coverage

Overall: **34.4%** (278 of 807 public modules, types, and callables). Data members are excluded from the ratio.

[Back to index](index.md)

## By kind

| Kind | Documented | Total | Coverage |
|---|---|---|---|
| class | 1 | 1 | 100.0% |
| constructor | 0 | 1 | 0.0% |
| function | 161 | 398 | 40.5% |
| macro | 68 | 290 | 23.4% |
| module | 11 | 43 | 25.6% |
| struct | 32 | 62 | 51.6% |
| type_alias | 5 | 12 | 41.7% |

## By module (lowest first)

| Module | Documented | Total | Coverage |
|---|---|---|---|
| [`bof/cat/bof.c`](modules/bof.cat.bof.c.md) | 0 | 2 | 0.0% |
| [`bof/is_sudo/bof.c`](modules/bof.is_sudo.bof.c.md) | 0 | 2 | 0.0% |
| [`bof/userenum/bof.c`](modules/bof.userenum.bof.c.md) | 0 | 2 | 0.0% |
| [`bof/whoami/bof.c`](modules/bof.whoami.bof.c.md) | 0 | 2 | 0.0% |
| [`gopher_c2`](modules/gopher_c2.py.md) | 0 | 5 | 0.0% |
| [`cJSON.c`](modules/cJSON.c.md) | 6 | 89 | 6.7% |
| [`include/cJSON.c`](modules/include.cJSON.c.md) | 6 | 89 | 6.7% |
| [`beacons/v2/beacon.c`](modules/beacons.v2.beacon.c.md) | 1 | 10 | 10.0% |
| [`bof/include/syscalls.h`](modules/bof.include.syscalls.h.md) | 5 | 38 | 13.2% |
| [`include/config.h`](modules/include.config.h.md) | 4 | 21 | 19.0% |
| [`cJSON.h`](modules/cJSON.h.md) | 8 | 37 | 21.6% |
| [`include/cJSON.h`](modules/include.cJSON.h.md) | 8 | 37 | 21.6% |
| [`aes.h`](modules/aes.h.md) | 5 | 21 | 23.8% |
| [`include/aes.h`](modules/include.aes.h.md) | 5 | 21 | 23.8% |
| [`beacons/v3/beacon.c`](modules/beacons.v3.beacon.c.md) | 1 | 4 | 25.0% |
| [`bof/include/beacon_api.h`](modules/bof.include.beacon_api.h.md) | 4 | 14 | 28.6% |
| [`aes.c`](modules/aes.c.md) | 8 | 24 | 33.3% |
| [`beacons/v1/beacon.c`](modules/beacons.v1.beacon.c.md) | 1 | 3 | 33.3% |
| [`include/aes.c`](modules/include.aes.c.md) | 8 | 24 | 33.3% |
| [`include/aes_cfb.c`](modules/include.aes_cfb.c.md) | 1 | 3 | 33.3% |
| [`include/aes_cfb.h`](modules/include.aes_cfb.h.md) | 1 | 3 | 33.3% |
| [`beacon5.c`](modules/beacon5.c.md) | 15 | 39 | 38.5% |
| [`beacon_p2p.c`](modules/beacon_p2p.c.md) | 18 | 44 | 40.9% |
| [`bof/suid_enum/bof.c`](modules/bof.suid_enum.bof.c.md) | 4 | 9 | 44.4% |
| [`beacon.h`](modules/beacon.h.md) | 6 | 13 | 46.2% |
| [`include/beacon.h`](modules/include.beacon.h.md) | 6 | 13 | 46.2% |
| [`bof.c`](modules/bof.c.md) | 1 | 2 | 50.0% |
| [`bof/is_sudo/is_sudo.c`](modules/bof.is_sudo.is_sudo.c.md) | 8 | 14 | 57.1% |
| [`issudo.c`](modules/issudo.c.md) | 8 | 14 | 57.1% |
| [`beacon3.c`](modules/beacon3.c.md) | 14 | 23 | 60.9% |
| [`beacon6.c`](modules/beacon6.c.md) | 14 | 23 | 60.9% |
| [`beacons/v1/gopher_beacon.c`](modules/beacons.v1.gopher_beacon.c.md) | 14 | 23 | 60.9% |
| [`gopher_beacon.c`](modules/gopher_beacon.c.md) | 14 | 23 | 60.9% |
| [`bof/whoami/whoami.c`](modules/bof.whoami.whoami.c.md) | 8 | 13 | 61.5% |
| [`include/beacon_common.h`](modules/include.beacon_common.h.md) | 20 | 31 | 64.5% |
| [`bof/cat/cat.c`](modules/bof.cat.cat.c.md) | 8 | 12 | 66.7% |
| [`bof/userenum/userenum.c`](modules/bof.userenum.userenum.c.md) | 8 | 12 | 66.7% |
| [`include/beacon_common.c`](modules/include.beacon_common.c.md) | 17 | 23 | 73.9% |
| [`include/config.c`](modules/include.config.c.md) | 4 | 5 | 80.0% |
| [`c2.server`](modules/c2.server.py.md) | 15 | 16 | 93.8% |
| [`app`](modules/app.py.md) | 1 | 1 | 100.0% |
| [`include.config_py`](modules/include.config_py.py.md) | 2 | 2 | 100.0% |
| [`install.sh`](modules/install.sh.md) | 1 | 1 | 100.0% |

## Warnings

DOC001 undocumented public item, DOC002 parameter not documented, DOC003 documented parameter missing from the signature (stale doc), DOC004 return value not documented, DOC005 raised exception not documented.

DOC001: 528

- DOC001 `aes.c:5` macro Nb is not documented
- DOC001 `aes.c:9` macro KEYLEN_256 is not documented
- DOC001 `aes.c:10` macro RKLENGTH is not documented
- DOC001 `aes.c:11` macro BLOCKLEN is not documented
- DOC001 `aes.c:70` macro Nk is not documented
- DOC001 `aes.c:71` macro Nr is not documented
- DOC001 `aes.c:73` macro Nk is not documented
- DOC001 `aes.c:74` macro Nr is not documented
- DOC001 `aes.c:76` macro Nk is not documented
- DOC001 `aes.c:77` macro Nr is not documented
- DOC001 `aes.c:84` macro MULTIPLY_AS_A_FUNCTION is not documented
- DOC001 `aes.c:239` function AES_init_ctx is not documented
- DOC001 `aes.c:249` function AES_ctx_set_iv is not documented
- DOC001 `aes.c:349` macro Multiply is not documented
- DOC001 `aes.c:496` function AES_ECB_decrypt is not documented
- DOC001 `aes.c:536` function AES_CBC_decrypt_buffer is not documented
- DOC001 `aes.h:9` macro CBC is not documented
- DOC001 `aes.h:12` macro ECB is not documented
- DOC001 `aes.h:15` macro CTR is not documented
- DOC001 `aes.h:18` macro AES256 is not documented
- DOC001 `aes.h:20` macro AES_BLOCKLEN is not documented
- DOC001 `aes.h:23` macro AES_KEYLEN is not documented
- DOC001 `aes.h:24` macro AES_keyExpSize is not documented
- DOC001 `aes.h:26` macro AES_KEYLEN is not documented
- DOC001 `aes.h:27` macro AES_keyExpSize is not documented
- DOC001 `aes.h:29` macro AES_KEYLEN is not documented
- DOC001 `aes.h:30` macro AES_keyExpSize is not documented
- DOC001 `aes.h:33` struct AES_ctx is not documented
- DOC001 `aes.h:41` function AES_init_ctx is not documented
- DOC001 `aes.h:44` function AES_ctx_set_iv is not documented
- DOC001 `aes.h:49` function AES_ECB_decrypt is not documented
- DOC001 `aes.h:54` function AES_CBC_decrypt_buffer is not documented
- DOC001 `beacon.h:10` macro CALLBACK_ERROR is not documented
- DOC001 `beacon.h:11` macro CALLBACK_OUTPUT_OEM is not documented
- DOC001 `beacon.h:22` function BeaconDataPtr is not documented
- DOC001 `beacon.h:23` function BeaconDataInt is not documented
- DOC001 `beacon.h:24` function BeaconDataShort is not documented
- DOC001 `beacon.h:25` function BeaconDataLength is not documented
- DOC001 `beacon.h:26` function BeaconDataExtract is not documented
- DOC001 `beacon3.c:1` macro _GNU_SOURCE is not documented
- DOC001 `beacon3.c:1` module beacon3.c is not documented
- DOC001 `beacon3.c:33` macro C2_URL is not documented
- DOC001 `beacon3.c:34` macro CLIENT_ID is not documented
- DOC001 `beacon3.c:35` macro MALEABLE is not documented
- DOC001 `beacon3.c:36` macro USER_AGENTS_COUNT is not documented
- DOC001 `beacon3.c:65` struct SymbolResolver is not documented
- DOC001 `beacon3.c:423` function base64_decode is not documented
- DOC001 `beacon3.c:474` function aes256_cfb_decrypt is not documented
- DOC001 `beacon5.c:1` macro _GNU_SOURCE is not documented
- DOC001 `beacon5.c:1` module beacon5.c is not documented
- DOC001 `beacon5.c:37` macro MAX_PEERS is not documented
- DOC001 `beacon5.c:38` macro DISCOVERY_PORT is not documented
- DOC001 `beacon5.c:39` macro DISCOVERY_INTERVAL is not documented
- DOC001 `beacon5.c:40` macro MAX_TTL is not documented
- DOC001 `beacon5.c:41` macro MESH_MSG_SIZE is not documented
- DOC001 `beacon5.c:44` macro C2_URL is not documented
- DOC001 `beacon5.c:45` macro CLIENT_ID is not documented
- DOC001 `beacon5.c:46` macro MALEABLE is not documented
- DOC001 `beacon5.c:47` macro USER_AGENTS_COUNT is not documented
- DOC001 `beacon5.c:75` struct mesh_msg_t is not documented
- DOC001 `beacon5.c:106` struct SymbolResolver is not documented
- DOC001 `beacon5.c:465` function base64_decode is not documented
- DOC001 `beacon5.c:516` function aes256_cfb_decrypt is not documented
- DOC001 `beacon5.c:1050` function mesh_mark_seen is not documented
- DOC001 `beacon5.c:1058` function mesh_is_seen is not documented
- DOC001 `beacon5.c:1070` function mesh_add_peer is not documented
- DOC001 `beacon5.c:1095` function mesh_cleanup_peers is not documented
- DOC001 `beacon5.c:1109` function mesh_send_to_peer is not documented
- DOC001 `beacon5.c:1131` function mesh_propagate is not documented
- DOC001 `beacon5.c:1158` function mesh_discovery_thread is not documented
- DOC001 `beacon5.c:1241` function mesh_listener_thread is not documented
- DOC001 `beacon5.c:1417` function mesh_send_message is not documented
- DOC001 `beacon6.c:1` macro _GNU_SOURCE is not documented
- DOC001 `beacon6.c:1` module beacon6.c is not documented
- DOC001 `beacon6.c:35` macro C2_URL is not documented
- DOC001 `beacon6.c:36` macro CLIENT_ID is not documented
- DOC001 `beacon6.c:37` macro MALEABLE is not documented
- DOC001 `beacon6.c:38` macro USER_AGENTS_COUNT is not documented
- DOC001 `beacon6.c:67` struct SymbolResolver is not documented
- DOC001 `beacon6.c:485` function base64_decode is not documented
- DOC001 `beacon6.c:536` function aes256_cfb_decrypt is not documented
- DOC001 `beacon_p2p.c:1` macro _GNU_SOURCE is not documented
- DOC001 `beacon_p2p.c:1` module beacon_p2p.c is not documented
- DOC001 `beacon_p2p.c:38` macro CLIENT_ID is not documented
- DOC001 `beacon_p2p.c:39` macro MALEABLE is not documented
- DOC001 `beacon_p2p.c:40` macro USER_AGENTS_COUNT is not documented
- DOC001 `beacon_p2p.c:42` macro PEER_DISCOVERY_PORT is not documented
- DOC001 `beacon_p2p.c:43` macro PEER_TCP_PORT is not documented
- DOC001 `beacon_p2p.c:44` macro PEER_MAGIC is not documented
- DOC001 `beacon_p2p.c:45` macro PEER_VERSION is not documented
- DOC001 `beacon_p2p.c:46` macro BROADCAST_INTERVAL is not documented
- DOC001 `beacon_p2p.c:47` macro MAX_PEERS is not documented
- DOC001 `beacon_p2p.c:72` struct p2p_header_t is not documented
- DOC001 `beacon_p2p.c:97` function BeaconDataPtr is not documented
- DOC001 `beacon_p2p.c:105` function BeaconDataInt is not documented
- DOC001 `beacon_p2p.c:111` function BeaconDataShort is not documented
- DOC001 `beacon_p2p.c:117` function BeaconDataLength is not documented
- DOC001 `beacon_p2p.c:121` function BeaconDataExtract is not documented
- DOC001 `beacon_p2p.c:161` struct SymbolResolver is not documented
- DOC001 `beacon_p2p.c:170` struct TrampolineCache is not documented
- DOC001 `beacon_p2p.c:641` function base64_decode is not documented
- DOC001 `beacon_p2p.c:681` function aes256_cfb_decrypt is not documented
- DOC001 `beacon_p2p.c:807` function peer_discovery_thread is not documented
- DOC001 `beacon_p2p.c:846` function handle_peer_connection is not documented
- DOC001 `beacon_p2p.c:916` function peer_server_thread is not documented
- DOC001 `beacon_p2p.c:935` function send_to_peer is not documented
- DOC001 `beacon_p2p.c:968` function send_to_c2_or_peer is not documented
- DOC001 `beacons/v1/beacon.c:1` module beacons/v1/beacon.c is not documented
- DOC001 `beacons/v1/beacon.c:146` function main is not documented
- DOC001 `beacons/v1/gopher_beacon.c:1` macro _GNU_SOURCE is not documented
- DOC001 `beacons/v1/gopher_beacon.c:1` module beacons/v1/gopher_beacon.c is not documented
- DOC001 `beacons/v1/gopher_beacon.c:30` macro C2 is not documented
- DOC001 `beacons/v1/gopher_beacon.c:31` macro CLIENT_ID is not documented
- DOC001 `beacons/v1/gopher_beacon.c:32` macro MALEABLE is not documented
- DOC001 `beacons/v1/gopher_beacon.c:33` macro USER_AGENTS_COUNT is not documented
- DOC001 `beacons/v1/gopher_beacon.c:62` struct SymbolResolver is not documented
- DOC001 `beacons/v1/gopher_beacon.c:394` function base64_decode is not documented
- DOC001 `beacons/v1/gopher_beacon.c:445` function aes256_cfb_decrypt is not documented
- DOC001 `beacons/v2/beacon.c:1` module beacons/v2/beacon.c is not documented
- DOC001 `beacons/v2/beacon.c:27` macro MAX_PEERS is not documented
- DOC001 `beacons/v2/beacon.c:28` macro DISCOVERY_PORT is not documented
- DOC001 `beacons/v2/beacon.c:29` macro DISCOVERY_INTERVAL is not documented
- DOC001 `beacons/v2/beacon.c:30` macro MAX_TTL is not documented
- DOC001 `beacons/v2/beacon.c:31` macro MESH_MSG_SIZE is not documented
- DOC001 `beacons/v2/beacon.c:33` struct peer_t is not documented
- DOC001 `beacons/v2/beacon.c:40` struct mesh_msg_t is not documented
- DOC001 `beacons/v2/beacon.c:188` function main is not documented
- DOC001 `beacons/v3/beacon.c:1` module beacons/v3/beacon.c is not documented
- DOC001 `beacons/v3/beacon.c:8` function infrastructure is not documented
- DOC001 `beacons/v3/beacon.c:174` function main is not documented
- DOC001 `bof.c:4` function __attribute__ is not documented
- DOC001 `bof/cat/bof.c:1` module bof/cat/bof.c is not documented
- DOC001 `bof/cat/bof.c:15` function go is not documented
- DOC001 `bof/cat/cat.c:1` module bof/cat/cat.c is not documented
- DOC001 `bof/cat/cat.c:8` type_alias ssize_t is not documented
- DOC001 `bof/cat/cat.c:17` macro SYS_close is not documented
- DOC001 `bof/cat/cat.c:31` function go is not documented
- DOC001 `bof/include/beacon_api.h:1` module bof/include/beacon_api.h is not documented
- DOC001 `bof/include/beacon_api.h:10` function go is not documented
- DOC001 `bof/include/beacon_api.h:25` macro CALLBACK_ERROR is not documented
- DOC001 `bof/include/beacon_api.h:26` macro CALLBACK_OUTPUT_OEM is not documented
- DOC001 `bof/include/beacon_api.h:37` function BeaconDataPtr is not documented
- DOC001 `bof/include/beacon_api.h:38` function BeaconDataInt is not documented
- DOC001 `bof/include/beacon_api.h:39` function BeaconDataShort is not documented
- DOC001 `bof/include/beacon_api.h:40` function BeaconDataLength is not documented
- DOC001 `bof/include/beacon_api.h:41` function BeaconDataExtract is not documented
- DOC001 `bof/include/beacon_api.h:44` function buffer is not documented
- DOC001 `bof/include/syscalls.h:1` module bof/include/syscalls.h is not documented
- DOC001 `bof/include/syscalls.h:18` macro SYS_write is not documented
- DOC001 `bof/include/syscalls.h:19` macro SYS_open is not documented
- DOC001 `bof/include/syscalls.h:20` macro SYS_close is not documented
- DOC001 `bof/include/syscalls.h:21` macro SYS_stat is not documented
- DOC001 `bof/include/syscalls.h:22` macro SYS_fstat is not documented
- DOC001 `bof/include/syscalls.h:23` macro SYS_lseek is not documented
- DOC001 `bof/include/syscalls.h:24` macro SYS_mmap is not documented
- DOC001 `bof/include/syscalls.h:25` macro SYS_munmap is not documented
- DOC001 `bof/include/syscalls.h:26` macro SYS_brk is not documented
- DOC001 `bof/include/syscalls.h:27` macro SYS_ioctl is not documented
- DOC001 `bof/include/syscalls.h:28` macro SYS_access is not documented
- DOC001 `bof/include/syscalls.h:29` macro SYS_pipe is not documented
- DOC001 `bof/include/syscalls.h:30` macro SYS_dup2 is not documented
- DOC001 `bof/include/syscalls.h:31` macro SYS_fork is not documented
- DOC001 `bof/include/syscalls.h:32` macro SYS_execve is not documented
- DOC001 `bof/include/syscalls.h:33` macro SYS_exit is not documented
- DOC001 `bof/include/syscalls.h:34` macro SYS_wait4 is not documented
- DOC001 `bof/include/syscalls.h:35` macro SYS_getuid is not documented
- DOC001 `bof/include/syscalls.h:36` macro SYS_getgid is not documented
- DOC001 `bof/include/syscalls.h:37` macro SYS_geteuid is not documented
- DOC001 `bof/include/syscalls.h:38` macro SYS_getegid is not documented
- DOC001 `bof/include/syscalls.h:39` macro SYS_getpid is not documented
- DOC001 `bof/include/syscalls.h:40` macro SYS_getppid is not documented
- DOC001 `bof/include/syscalls.h:41` macro SYS_getpwnam_r is not documented
- DOC001 `bof/include/syscalls.h:42` macro SYS_getpwuid_r is not documented
- DOC001 `bof/include/syscalls.h:43` macro SYS_openat is not documented
- DOC001 `bof/include/syscalls.h:44` macro SYS_clone is not documented
- DOC001 `bof/include/syscalls.h:49` function syscall0 is not documented
- DOC001 `bof/include/syscalls.h:60` function syscall1 is not documented
- DOC001 `bof/include/syscalls.h:71` function syscall2 is not documented
- DOC001 `bof/include/syscalls.h:82` function syscall3 is not documented
- DOC001 `bof/include/syscalls.h:93` function syscall4 is not documented
- DOC001 `bof/is_sudo/bof.c:1` module bof/is_sudo/bof.c is not documented
- DOC001 `bof/is_sudo/bof.c:57` function go is not documented
- DOC001 `bof/is_sudo/is_sudo.c:1` module bof/is_sudo/is_sudo.c is not documented
- DOC001 `bof/is_sudo/is_sudo.c:8` type_alias ssize_t is not documented
- DOC001 `bof/is_sudo/is_sudo.c:17` macro SYS_close is not documented
- DOC001 `bof/is_sudo/is_sudo.c:18` macro SYS_getuid is not documented
- DOC001 `bof/is_sudo/is_sudo.c:19` macro SYS_getpwuid_r is not documented
- DOC001 `bof/is_sudo/is_sudo.c:109` function go is not documented
- DOC001 `bof/suid_enum/bof.c:1` module bof/suid_enum/bof.c is not documented
- DOC001 `bof/suid_enum/bof.c:27` macro SYS_lstat is not documented
- DOC001 `bof/suid_enum/bof.c:31` macro DT_DIR is not documented
- DOC001 `bof/suid_enum/bof.c:32` macro DT_LNK is not documented
- DOC001 `bof/suid_enum/bof.c:247` function go is not documented
- DOC001 `bof/userenum/bof.c:1` module bof/userenum/bof.c is not documented
- DOC001 `bof/userenum/bof.c:68` function go is not documented
- DOC001 `bof/userenum/userenum.c:1` module bof/userenum/userenum.c is not documented
- DOC001 `bof/userenum/userenum.c:8` type_alias ssize_t is not documented
- DOC001 `bof/userenum/userenum.c:17` macro SYS_close is not documented
- DOC001 `bof/userenum/userenum.c:41` function go is not documented
- DOC001 `bof/whoami/bof.c:1` module bof/whoami/bof.c is not documented
- DOC001 `bof/whoami/bof.c:19` function go is not documented
- DOC001 `bof/whoami/whoami.c:1` module bof/whoami/whoami.c is not documented
- DOC001 `bof/whoami/whoami.c:7` type_alias ssize_t is not documented
- DOC001 `bof/whoami/whoami.c:16` macro SYS_close is not documented
- DOC001 `bof/whoami/whoami.c:17` macro SYS_getuid is not documented
- DOC001 `bof/whoami/whoami.c:41` function go is not documented
- DOC001 `cJSON.c:1` module cJSON.c is not documented
- DOC001 `cJSON.c:28` macro _CRT_SECURE_NO_DEPRECATE is not documented
- DOC001 `cJSON.c:65` macro true is not documented
- DOC001 `cJSON.c:70` macro false is not documented
- DOC001 `cJSON.c:74` macro isinf is not documented
- DOC001 `cJSON.c:77` macro isnan is not documented
- DOC001 `cJSON.c:82` macro NAN is not documented
- DOC001 `cJSON.c:84` macro NAN is not documented
- DOC001 `cJSON.c:88` struct error is not documented
- DOC001 `cJSON.c:95` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:100` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:110` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:125` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:157` struct internal_hooks is not documented
- DOC001 `cJSON.c:179` macro internal_malloc is not documented
- DOC001 `cJSON.c:180` macro internal_free is not documented
- DOC001 `cJSON.c:181` macro internal_realloc is not documented
- DOC001 `cJSON.c:210` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:291` struct parse_buffer is not documented
- DOC001 `cJSON.c:304` macro cannot_access_at_index is not documented
- DOC001 `cJSON.c:482` struct printbuffer is not documented
- DOC001 `cJSON.c:1134` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1236` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1241` macro cjson_min is not documented
- DOC001 `cJSON.c:1316` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1321` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1352` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1935` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1977` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1982` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1987` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2112` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2123` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2133` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2143` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2155` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2167` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2179` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2191` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2203` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2215` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2227` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2239` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2251` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2287` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2297` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2302` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2309` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2316` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2321` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2363` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2413` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2446` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2451` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2468` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2479` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2490` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2501` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2526` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2543` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2555` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2567` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2579` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2596` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2607` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2659` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2699` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2739` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2786` function cJSON_Duplicate_rec is not documented
- DOC001 `cJSON.c:2922` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2972` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2982` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2992` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3002` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3012` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3022` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3032` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3042` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3052` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3062` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3072` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3194` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3199` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:1` module cJSON.h is not documented
- DOC001 `cJSON.h:24` macro cJSON__h is not documented
- DOC001 `cJSON.h:32` macro __WINDOWS__ is not documented
- DOC001 `cJSON.h:45` macro CJSON_STDCALL is not documented
- DOC001 `cJSON.h:49` macro CJSON_EXPORT_SYMBOLS is not documented
- DOC001 `cJSON.h:53` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:55` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:57` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:61` macro CJSON_STDCALL is not documented
- DOC001 `cJSON.h:64` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:66` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:72` macro CJSON_VERSION_MINOR is not documented
- DOC001 `cJSON.h:73` macro CJSON_VERSION_PATCH is not documented
- DOC001 `cJSON.h:79` macro cJSON_False is not documented
- DOC001 `cJSON.h:80` macro cJSON_True is not documented
- DOC001 `cJSON.h:81` macro cJSON_NULL is not documented
- DOC001 `cJSON.h:82` macro cJSON_Number is not documented
- DOC001 `cJSON.h:83` macro cJSON_String is not documented
- DOC001 `cJSON.h:84` macro cJSON_Array is not documented
- DOC001 `cJSON.h:85` macro cJSON_Object is not documented
- DOC001 `cJSON.h:86` macro cJSON_Raw is not documented
- DOC001 `cJSON.h:88` macro cJSON_IsReference is not documented
- DOC001 `cJSON.h:89` macro cJSON_StringIsConst is not documented
- DOC001 `cJSON.h:114` struct cJSON_Hooks is not documented
- DOC001 `cJSON.h:120` type_alias cJSON_bool is not documented
- DOC001 `cJSON.h:126` macro CJSON_NESTING_LIMIT is not documented
- DOC001 `cJSON.h:132` macro CJSON_CIRCULAR_LIMIT is not documented
- DOC001 `cJSON.h:249` function sensitive is not documented
- DOC001 `cJSON.h:273` macro cJSON_SetNumberValue is not documented
- DOC001 `gopher_beacon.c:1` macro _GNU_SOURCE is not documented
- DOC001 `gopher_beacon.c:1` module gopher_beacon.c is not documented
- DOC001 `gopher_beacon.c:30` macro C2 is not documented
- DOC001 `gopher_beacon.c:31` macro CLIENT_ID is not documented
- DOC001 `gopher_beacon.c:32` macro MALEABLE is not documented
- DOC001 `gopher_beacon.c:33` macro USER_AGENTS_COUNT is not documented
- DOC001 `gopher_beacon.c:62` struct SymbolResolver is not documented
- DOC001 `gopher_beacon.c:394` function base64_decode is not documented
- DOC001 `gopher_beacon.c:445` function aes256_cfb_decrypt is not documented
- DOC001 `gopher_c2.py:1` module gopher_c2.py is not documented
- DOC001 `gopher_c2.py:28` function encrypt_data is not documented
- DOC001 `gopher_c2.py:37` function decrypt_data is not documented
- DOC001 `gopher_c2.py:45` function handle_client is not documented
- DOC001 `gopher_c2.py:127` function main is not documented
- DOC001 `include/aes.c:5` macro Nb is not documented
- DOC001 `include/aes.c:9` macro KEYLEN_256 is not documented
- DOC001 `include/aes.c:10` macro RKLENGTH is not documented
- DOC001 `include/aes.c:11` macro BLOCKLEN is not documented
- DOC001 `include/aes.c:70` macro Nk is not documented
- DOC001 `include/aes.c:71` macro Nr is not documented
- DOC001 `include/aes.c:73` macro Nk is not documented
- DOC001 `include/aes.c:74` macro Nr is not documented
- DOC001 `include/aes.c:76` macro Nk is not documented
- DOC001 `include/aes.c:77` macro Nr is not documented
- DOC001 `include/aes.c:84` macro MULTIPLY_AS_A_FUNCTION is not documented
- DOC001 `include/aes.c:239` function AES_init_ctx is not documented
- DOC001 `include/aes.c:249` function AES_ctx_set_iv is not documented
- DOC001 `include/aes.c:349` macro Multiply is not documented
- DOC001 `include/aes.c:496` function AES_ECB_decrypt is not documented
- DOC001 `include/aes.c:536` function AES_CBC_decrypt_buffer is not documented
- DOC001 `include/aes.h:9` macro CBC is not documented
- DOC001 `include/aes.h:12` macro ECB is not documented
- DOC001 `include/aes.h:15` macro CTR is not documented
- DOC001 `include/aes.h:18` macro AES256 is not documented
- DOC001 `include/aes.h:20` macro AES_BLOCKLEN is not documented
- DOC001 `include/aes.h:23` macro AES_KEYLEN is not documented
- DOC001 `include/aes.h:24` macro AES_keyExpSize is not documented
- DOC001 `include/aes.h:26` macro AES_KEYLEN is not documented
- DOC001 `include/aes.h:27` macro AES_keyExpSize is not documented
- DOC001 `include/aes.h:29` macro AES_KEYLEN is not documented
- DOC001 `include/aes.h:30` macro AES_keyExpSize is not documented
- DOC001 `include/aes.h:33` struct AES_ctx is not documented
- DOC001 `include/aes.h:41` function AES_init_ctx is not documented
- DOC001 `include/aes.h:44` function AES_ctx_set_iv is not documented
- DOC001 `include/aes.h:49` function AES_ECB_decrypt is not documented
- DOC001 `include/aes.h:54` function AES_CBC_decrypt_buffer is not documented
- DOC001 `include/aes_cfb.c:1` module include/aes_cfb.c is not documented
- DOC001 `include/aes_cfb.c:48` function aes256_cfb_decrypt is not documented
- DOC001 `include/aes_cfb.h:1` module include/aes_cfb.h is not documented
- DOC001 `include/aes_cfb.h:11` function aes256_cfb_decrypt is not documented
- DOC001 `include/beacon.h:10` macro CALLBACK_ERROR is not documented
- DOC001 `include/beacon.h:11` macro CALLBACK_OUTPUT_OEM is not documented
- DOC001 `include/beacon.h:22` function BeaconDataPtr is not documented
- DOC001 `include/beacon.h:23` function BeaconDataInt is not documented
- DOC001 `include/beacon.h:24` function BeaconDataShort is not documented
- DOC001 `include/beacon.h:25` function BeaconDataLength is not documented
- DOC001 `include/beacon.h:26` function BeaconDataExtract is not documented
- DOC001 `include/beacon_common.c:1` module include/beacon_common.c is not documented
- DOC001 `include/beacon_common.c:181` function cleanup_trampolines is not documented
- DOC001 `include/beacon_common.c:196` function get_or_create_trampoline is not documented
- DOC001 `include/beacon_common.c:307` function base64_decode is not documented
- DOC001 `include/beacon_common.c:391` function bsb_backoff_next is not documented
- DOC001 `include/beacon_common.c:400` function bsb_backoff_reset is not documented
- DOC001 `include/beacon_common.h:1` module include/beacon_common.h is not documented
- DOC001 `include/beacon_common.h:15` macro _GNU_SOURCE is not documented
- DOC001 `include/beacon_common.h:27` macro BSB_OUTPUT_TRUNCATION_MARKER is not documented
- DOC001 `include/beacon_common.h:109` function cleanup_trampolines is not documented
- DOC001 `include/beacon_common.h:110` function get_or_create_trampoline is not documented
- DOC001 `include/beacon_common.h:123` function base64_decode is not documented
- DOC001 `include/beacon_common.h:133` function aes256_cfb_decrypt is not documented
- DOC001 `include/beacon_common.h:139` function buffer is not documented
- DOC001 `include/beacon_common.h:179` function bsb_backoff_init is not documented
- DOC001 `include/beacon_common.h:180` function bsb_backoff_next is not documented
- DOC001 `include/beacon_common.h:181` function bsb_backoff_reset is not documented
- DOC001 `include/cJSON.c:1` module include/cJSON.c is not documented
- DOC001 `include/cJSON.c:28` macro _CRT_SECURE_NO_DEPRECATE is not documented
- DOC001 `include/cJSON.c:65` macro true is not documented
- DOC001 `include/cJSON.c:70` macro false is not documented
- DOC001 `include/cJSON.c:74` macro isinf is not documented
- DOC001 `include/cJSON.c:77` macro isnan is not documented
- DOC001 `include/cJSON.c:82` macro NAN is not documented
- DOC001 `include/cJSON.c:84` macro NAN is not documented
- DOC001 `include/cJSON.c:88` struct error is not documented
- DOC001 `include/cJSON.c:95` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:100` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:110` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:125` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:157` struct internal_hooks is not documented
- DOC001 `include/cJSON.c:179` macro internal_malloc is not documented
- DOC001 `include/cJSON.c:180` macro internal_free is not documented
- DOC001 `include/cJSON.c:181` macro internal_realloc is not documented
- DOC001 `include/cJSON.c:210` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:291` struct parse_buffer is not documented
- DOC001 `include/cJSON.c:304` macro cannot_access_at_index is not documented
- DOC001 `include/cJSON.c:482` struct printbuffer is not documented
- DOC001 `include/cJSON.c:1134` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1236` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1241` macro cjson_min is not documented
- DOC001 `include/cJSON.c:1316` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1321` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1352` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1935` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1977` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1982` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:1987` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2112` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2123` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2133` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2143` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2155` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2167` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2179` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2191` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2203` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2215` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2227` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2239` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2251` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2287` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2297` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2302` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2309` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2316` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2321` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2363` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2413` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2446` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2451` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2468` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2479` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2490` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2501` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2526` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2543` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2555` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2567` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2579` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2596` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2607` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2659` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2699` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2739` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2786` function cJSON_Duplicate_rec is not documented
- DOC001 `include/cJSON.c:2922` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2972` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2982` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:2992` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3002` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3012` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3022` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3032` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3042` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3052` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3062` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3072` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3194` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.c:3199` function CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:1` module include/cJSON.h is not documented
- DOC001 `include/cJSON.h:24` macro cJSON__h is not documented
- DOC001 `include/cJSON.h:32` macro __WINDOWS__ is not documented
- DOC001 `include/cJSON.h:45` macro CJSON_STDCALL is not documented
- DOC001 `include/cJSON.h:49` macro CJSON_EXPORT_SYMBOLS is not documented
- DOC001 `include/cJSON.h:53` macro CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:55` macro CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:57` macro CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:61` macro CJSON_STDCALL is not documented
- DOC001 `include/cJSON.h:64` macro CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:66` macro CJSON_PUBLIC is not documented
- DOC001 `include/cJSON.h:72` macro CJSON_VERSION_MINOR is not documented
- DOC001 `include/cJSON.h:73` macro CJSON_VERSION_PATCH is not documented
- DOC001 `include/cJSON.h:79` macro cJSON_False is not documented
- DOC001 `include/cJSON.h:80` macro cJSON_True is not documented
- DOC001 `include/cJSON.h:81` macro cJSON_NULL is not documented
- DOC001 `include/cJSON.h:82` macro cJSON_Number is not documented
- DOC001 `include/cJSON.h:83` macro cJSON_String is not documented
- DOC001 `include/cJSON.h:84` macro cJSON_Array is not documented
- DOC001 `include/cJSON.h:85` macro cJSON_Object is not documented
- DOC001 `include/cJSON.h:86` macro cJSON_Raw is not documented
- DOC001 `include/cJSON.h:88` macro cJSON_IsReference is not documented
- DOC001 `include/cJSON.h:89` macro cJSON_StringIsConst is not documented
- DOC001 `include/cJSON.h:114` struct cJSON_Hooks is not documented
- DOC001 `include/cJSON.h:120` type_alias cJSON_bool is not documented
- ... 28 more in `api/warnings.jsonl`
