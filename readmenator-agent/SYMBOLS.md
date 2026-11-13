# Symbols (page 1 of 4)
Pages: [SYMBOLS.md](SYMBOLS.md), [SYMBOLS_p2.md](SYMBOLS_p2.md), [SYMBOLS_p3.md](SYMBOLS_p3.md), [SYMBOLS_p4.md](SYMBOLS_p4.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AES_CBC_decrypt_buffer` | function | `aes.c:552` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:537` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:572` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:518` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ECB_encrypt` | function | `aes.c:512` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ctx_set_iv` | function | `aes.c:264` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)` |
| `AES_init_ctx` | function | `aes.c:254` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)` |
| `AES_init_ctx_iv` | function | `aes.c:259` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` |
| `AddRoundKey` | function | `aes.c:272` | `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:9` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:455` | `static void Cipher(state_t *state, const uint8_t *RoundKey)` |
| `InvCipher` | function | `aes.c:482` | `static void InvCipher(state_t *state, const uint8_t *RoundKey)` |
| `InvMixColumns` | function | `aes.c:389` | `static void InvMixColumns(state_t *state)` |
| `InvShiftRows` | function | `aes.c:425` | `static void InvShiftRows(state_t *state)` |
| `InvSubBytes` | function | `aes.c:413` | `static void InvSubBytes(state_t *state)` |
| `KEYLEN_256` | macro | `aes.c:7` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:181` | `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:101` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:335` | `static void MixColumns(state_t *state)` |
| `Multiply` | function | `aes.c:363` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:371` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:5` | `#define Nb` |
| `Nb` | macro | `aes.c:84` | `#define Nb` |
| `Nk` | macro | `aes.c:87` | `#define Nk` |
| `Nk` | macro | `aes.c:90` | `#define Nk` |
| `Nk` | macro | `aes.c:93` | `#define Nk` |
| `Nr` | macro | `aes.c:88` | `#define Nr` |
| `Nr` | macro | `aes.c:91` | `#define Nr` |
| `Nr` | macro | `aes.c:94` | `#define Nr` |
| `RKLENGTH` | macro | `aes.c:8` | `#define RKLENGTH` |
| `ShiftRows` | function | `aes.c:301` | `static void ShiftRows(state_t *state)` |
| `SubBytes` | function | `aes.c:286` | `static void SubBytes(state_t *state)` |
| `Td0` | function | `aes.c:59` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:63` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:67` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:71` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:75` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:528` | `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)` |
| `getSBoxInvert` | function | `aes.c:35` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:384` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:11` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:177` | `#define getSBoxValue(num)` |
| `xtime` | function | `aes.c:329` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:18` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:20` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);` |
| `AES_ECB_decrypt` | function | `aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_ECB_encrypt` | function | `aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);` |
| `AES_KEYLEN` | macro | `aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);` |
| `AES_init_ctx` | function | `aes.h:41` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);` |
| `AES_init_ctx_iv` | function | `aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);` |
| `AES_keyExpSize` | macro | `aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `aes.h:9` | `#define CBC` |
| `CTR` | macro | `aes.h:15` | `#define CTR` |
| `ECB` | macro | `aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `aes.h:2` | `#define _AES_H_` |
| `BEACON_API_H` | macro | `beacon.h:3` | `#define BEACON_API_H` |
| `BeaconDataExtract` | function | `beacon.h:27` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `beacon.h:24` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `beacon.h:26` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `beacon.h:22` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `beacon.h:23` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `beacon.h:25` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `beacon.h:29` | `void BeaconOutput(int type, const char *data, int len);` |
| `BeaconPrintf` | function | `beacon.h:28` | `void BeaconPrintf(int type, const char *fmt, ...);` |
| `CALLBACK_ERROR` | macro | `beacon.h:10` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `beacon.h:9` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `beacon.h:11` | `#define CALLBACK_OUTPUT_OEM` |
| `datap` | struct | `beacon.h:14` | `` |
| `_GNU_SOURCE` | macro | `beacons/v1/beacon.c:13` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v1/beacon.c:104` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v1/beacon.c:167` | `int main(void)` |
| `report_result` | function | `beacons/v1/beacon.c:24` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `DISCOVERY_INTERVAL` | macro | `beacons/v2/beacon.c:29` | `#define DISCOVERY_INTERVAL` |
| `DISCOVERY_PORT` | macro | `beacons/v2/beacon.c:28` | `#define DISCOVERY_PORT` |
| `MAX_PEERS` | macro | `beacons/v2/beacon.c:27` | `#define MAX_PEERS` |
| `MAX_TTL` | macro | `beacons/v2/beacon.c:30` | `#define MAX_TTL` |
| `MESH_MSG_SIZE` | macro | `beacons/v2/beacon.c:31` | `#define MESH_MSG_SIZE` |
| `_GNU_SOURCE` | macro | `beacons/v2/beacon.c:12` | `#define _GNU_SOURCE` |
| `execute_command` | function | `beacons/v2/beacon.c:149` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `main` | function | `beacons/v2/beacon.c:212` | `int main(void)` |
| `mesh_msg_t` | struct | `beacons/v2/beacon.c:41` | `` |
| `peer_t` | struct | `beacons/v2/beacon.c:33` | `` |
| `report_result` | function | `beacons/v2/beacon.c:69` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `_GNU_SOURCE` | macro | `beacons/v3/beacon.c:12` | `#define _GNU_SOURCE` |
| `compute_primes` | function | `beacons/v3/beacon.c:42` | `static int compute_primes(int count)` |
| `evasive_sleep` | function | `beacons/v3/beacon.c:55` | `static void evasive_sleep(int seconds)` |
| `execute_command` | function | `beacons/v3/beacon.c:142` | `static char *execute_command(const bsb_config_t *cfg, const char *command)` |
| `infrastructure` | function | `beacons/v3/beacon.c:8` | `*  * All shared infrastructure (HTTP client, crypto, BOF loader)  * lives in beacon_common.c. Thi...` |
| `main` | function | `beacons/v3/beacon.c:205` | `int main(void)` |
| `report_result` | function | `beacons/v3/beacon.c:62` | `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)` |
| `__attribute__` | function | `bof.c:4` | `__attribute__((used)) __attribute__((visibility("default"))) void go(char *args, int alen)` |
| `go` | function | `bof/cat/bof.c:15` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/cat/cat.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/cat/cat.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/cat/cat.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/cat/cat.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/cat/cat.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/cat/cat.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/cat/cat.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/cat/cat.c:16` | `#define SYS_read` |
| `go` | function | `bof/cat/cat.c:31` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/cat/cat.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/cat/cat.c:8` | `typedef long ssize_t;` |
| `syscall3` | function | `bof/cat/cat.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `BSB_BOF_BEACON_API_H` | macro | `bof/include/beacon_api.h:17` | `#define BSB_BOF_BEACON_API_H` |
| `BeaconDataExtract` | function | `bof/include/beacon_api.h:42` | `char *BeaconDataExtract(datap *parser, int *size);` |
| `BeaconDataInt` | function | `bof/include/beacon_api.h:39` | `int BeaconDataInt(datap *parser);` |
| `BeaconDataLength` | function | `bof/include/beacon_api.h:41` | `int BeaconDataLength(datap *parser);` |
| `BeaconDataParse` | function | `bof/include/beacon_api.h:37` | `void BeaconDataParse(datap *parser, char *buffer, int size);` |
| `BeaconDataPtr` | function | `bof/include/beacon_api.h:38` | `char *BeaconDataPtr(datap *parser, int size);` |
| `BeaconDataShort` | function | `bof/include/beacon_api.h:40` | `short BeaconDataShort(datap *parser);` |
| `BeaconOutput` | function | `bof/include/beacon_api.h:48` | `void BeaconOutput(int type, const char *data, int len);` |
| `CALLBACK_ERROR` | macro | `bof/include/beacon_api.h:25` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/include/beacon_api.h:24` | `#define CALLBACK_OUTPUT` |
| `CALLBACK_OUTPUT_OEM` | macro | `bof/include/beacon_api.h:26` | `#define CALLBACK_OUTPUT_OEM` |
| `buffer` | function | `bof/include/beacon_api.h:45` | `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffer must still be NUL-terminated). */...` |
| `datap` | struct | `bof/include/beacon_api.h:30` | `` |
| `go` | function | `bof/include/beacon_api.h:10` | `* * BOFs MUST export a function with this exact signature: * * void go(char *args, int alen);` |
| `AT_FDCWD` | macro | `bof/include/syscalls.h:47` | `#define AT_FDCWD` |
| `BSB_BOF_SYSCALLS_H` | macro | `bof/include/syscalls.h:12` | `#define BSB_BOF_SYSCALLS_H` |
| `SYS_access` | macro | `bof/include/syscalls.h:28` | `#define SYS_access` |
| `SYS_brk` | macro | `bof/include/syscalls.h:26` | `#define SYS_brk` |
| `SYS_clone` | macro | `bof/include/syscalls.h:44` | `#define SYS_clone` |
| `SYS_close` | macro | `bof/include/syscalls.h:20` | `#define SYS_close` |
| `SYS_dup2` | macro | `bof/include/syscalls.h:30` | `#define SYS_dup2` |
| `SYS_execve` | macro | `bof/include/syscalls.h:32` | `#define SYS_execve` |
| `SYS_exit` | macro | `bof/include/syscalls.h:33` | `#define SYS_exit` |
| `SYS_fork` | macro | `bof/include/syscalls.h:31` | `#define SYS_fork` |
| `SYS_fstat` | macro | `bof/include/syscalls.h:22` | `#define SYS_fstat` |
| `SYS_getegid` | macro | `bof/include/syscalls.h:38` | `#define SYS_getegid` |
| `SYS_geteuid` | macro | `bof/include/syscalls.h:37` | `#define SYS_geteuid` |
| `SYS_getgid` | macro | `bof/include/syscalls.h:36` | `#define SYS_getgid` |
| `SYS_getpid` | macro | `bof/include/syscalls.h:39` | `#define SYS_getpid` |
| `SYS_getppid` | macro | `bof/include/syscalls.h:40` | `#define SYS_getppid` |
| `SYS_getpwnam_r` | macro | `bof/include/syscalls.h:41` | `#define SYS_getpwnam_r` |
| `SYS_getpwuid_r` | macro | `bof/include/syscalls.h:42` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `bof/include/syscalls.h:35` | `#define SYS_getuid` |
| `SYS_ioctl` | macro | `bof/include/syscalls.h:27` | `#define SYS_ioctl` |
| `SYS_lseek` | macro | `bof/include/syscalls.h:23` | `#define SYS_lseek` |
| `SYS_mmap` | macro | `bof/include/syscalls.h:24` | `#define SYS_mmap` |
| `SYS_munmap` | macro | `bof/include/syscalls.h:25` | `#define SYS_munmap` |
| `SYS_open` | macro | `bof/include/syscalls.h:19` | `#define SYS_open` |
| `SYS_openat` | macro | `bof/include/syscalls.h:43` | `#define SYS_openat` |
| `SYS_pipe` | macro | `bof/include/syscalls.h:29` | `#define SYS_pipe` |
| `SYS_read` | macro | `bof/include/syscalls.h:17` | `#define SYS_read` |
| `SYS_stat` | macro | `bof/include/syscalls.h:21` | `#define SYS_stat` |
| `SYS_wait4` | macro | `bof/include/syscalls.h:34` | `#define SYS_wait4` |
| `SYS_write` | macro | `bof/include/syscalls.h:18` | `#define SYS_write` |
| `bsf_memcmp` | function | `bof/include/syscalls.h:112` | `static inline int bsf_memcmp(const void *p1, const void *p2, size_t n)` |
| `bsf_strcmp` | function | `bof/include/syscalls.h:101` | `static inline int bsf_strcmp(const char *a, const char *b)` |
| `bsf_strlen` | function | `bof/include/syscalls.h:92` | `static inline size_t bsf_strlen(const char *s)` |
| `syscall0` | function | `bof/include/syscalls.h:49` | `static inline long syscall0(long n)` |
| `syscall1` | function | `bof/include/syscalls.h:56` | `static inline long syscall1(long n, long a1)` |
| `syscall2` | function | `bof/include/syscalls.h:63` | `static inline long syscall2(long n, long a1, long a2)` |
| `syscall3` | function | `bof/include/syscalls.h:70` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `syscall4` | function | `bof/include/syscalls.h:80` | `static inline long syscall4(long n, long a1, long a2, long a3, long a4)` |
| `go` | function | `bof/is_sudo/bof.c:74` | `void go(char *args, int alen)` |
| `user_in_group` | function | `bof/is_sudo/bof.c:15` | `static int user_in_group(const char *group, const char *username, char *filebuf, long filesize)` |
| `AT_FDCWD` | macro | `bof/is_sudo/is_sudo.c:20` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/is_sudo/is_sudo.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/is_sudo/is_sudo.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/is_sudo/is_sudo.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/is_sudo/is_sudo.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/is_sudo/is_sudo.c:17` | `#define SYS_close` |
| `SYS_getpwuid_r` | macro | `bof/is_sudo/is_sudo.c:19` | `#define SYS_getpwuid_r` |
| `SYS_getuid` | macro | `bof/is_sudo/is_sudo.c:18` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/is_sudo/is_sudo.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/is_sudo/is_sudo.c:16` | `#define SYS_read` |
| `get_username_from_uid` | function | `bof/is_sudo/is_sudo.c:52` | `static int get_username_from_uid(long uid, char *buf, int buf_size)` |
| `go` | function | `bof/is_sudo/is_sudo.c:122` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/is_sudo/is_sudo.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/is_sudo/is_sudo.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/is_sudo/is_sudo.c:41` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall1` | function | `bof/is_sudo/is_sudo.c:33` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/is_sudo/is_sudo.c:23` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `DT_DIR` | macro | `bof/suid_enum/bof.c:31` | `#define DT_DIR` |
| `DT_LNK` | macro | `bof/suid_enum/bof.c:32` | `#define DT_LNK` |
| `DT_UNKNOWN` | macro | `bof/suid_enum/bof.c:30` | `#define DT_UNKNOWN` |
| `SYS_getdents64` | macro | `bof/suid_enum/bof.c:26` | `#define SYS_getdents64` |
| `SYS_lstat` | macro | `bof/suid_enum/bof.c:27` | `#define SYS_lstat` |
| `emit` | function | `bof/suid_enum/bof.c:87` | `static void emit(const char *s)` |
| `flush_output` | function | `bof/suid_enum/bof.c:78` | `static void flush_output(void)` |
| `format_mode` | function | `bof/suid_enum/bof.c:114` | `static void format_mode(unsigned int mode, char *out)` |
| `go` | function | `bof/suid_enum/bof.c:298` | `void go(char *args, int alen)` |
| `linux_dirent64` | struct | `bof/suid_enum/bof.c:59` | `` |
| `linux_stat` | struct | `bof/suid_enum/bof.c:35` | `` |
| `path_append` | function | `bof/suid_enum/bof.c:148` | `static void path_append(const char *name)` |
| `path_reset` | function | `bof/suid_enum/bof.c:137` | `static void path_reset(const char *root)` |
| `path_trim_to` | function | `bof/suid_enum/bof.c:166` | `static void path_trim_to(int len)` |
| `walk` | function | `bof/suid_enum/bof.c:178` | `static void walk(int depth)` |
| `go` | function | `bof/userenum/bof.c:89` | `void go(char *args, int alen)` |
| `user_in_member_list` | function | `bof/userenum/bof.c:67` | `static int user_in_member_list(const char *username, const char *members)` |
| `AT_FDCWD` | macro | `bof/userenum/userenum.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/userenum/userenum.c:12` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/userenum/userenum.c:11` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/userenum/userenum.c:4` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/userenum/userenum.c:3` | `#define NULL` |
| `SYS_close` | macro | `bof/userenum/userenum.c:17` | `#define SYS_close` |
| `SYS_openat` | macro | `bof/userenum/userenum.c:15` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/userenum/userenum.c:16` | `#define SYS_read` |
| `go` | function | `bof/userenum/userenum.c:42` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/userenum/userenum.c:7` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/userenum/userenum.c:8` | `typedef long ssize_t;` |
| `strcmp` | function | `bof/userenum/userenum.c:32` | `static int strcmp(const char *s1, const char *s2)` |
| `syscall3` | function | `bof/userenum/userenum.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `go` | function | `bof/whoami/bof.c:19` | `void go(char *args, int alen)` |
| `AT_FDCWD` | macro | `bof/whoami/whoami.c:18` | `#define AT_FDCWD` |
| `BeaconOutput` | function | `bof/whoami/whoami.c:11` | `extern void BeaconOutput(int, const char *, int);` |
| `BeaconPrintf` | function | `bof/whoami/whoami.c:10` | `extern void BeaconPrintf(int, const char *, ...);` |
| `CALLBACK_OUTPUT` | macro | `bof/whoami/whoami.c:3` | `#define CALLBACK_OUTPUT` |
| `NULL` | macro | `bof/whoami/whoami.c:2` | `#define NULL` |
| `SYS_close` | macro | `bof/whoami/whoami.c:16` | `#define SYS_close` |
| `SYS_getuid` | macro | `bof/whoami/whoami.c:17` | `#define SYS_getuid` |
| `SYS_openat` | macro | `bof/whoami/whoami.c:14` | `#define SYS_openat` |
| `SYS_read` | macro | `bof/whoami/whoami.c:15` | `#define SYS_read` |
| `go` | function | `bof/whoami/whoami.c:38` | `void go(char *args, int alen)` |
| `size_t` | type_alias | `bof/whoami/whoami.c:6` | `typedef unsigned long size_t;` |
| `ssize_t` | type_alias | `bof/whoami/whoami.c:7` | `typedef long ssize_t;` |
| `syscall1` | function | `bof/whoami/whoami.c:31` | `static inline long syscall1(long n, long a1)` |
| `syscall3` | function | `bof/whoami/whoami.c:21` | `static inline long syscall3(long n, long a1, long a2, long a3)` |
| `C2State` | class | `c2/server.py:552` | `class C2State` |
| `__init__` | method | `c2/server.py:555` | `def __init__(self, cfg)` |
| `_http_response` | function | `c2/server.py:848` | `def _http_response(body, status)` |
| `_is_http_line` | function | `c2/server.py:783` | `def _is_http_line(line)` |
| `_is_http_request` | function | `c2/server.py:789` | `def _is_http_request(raw)` |
| `_random_free_port` | function | `c2/server.py:73` | `def _random_free_port()` |
| `_read_request` | function | `c2/server.py:800` | `def _read_request(conn)` |
| `build_stage_config` | function | `c2/server.py:449` | `def build_stage_config(state)` |
| `build_stage_oneliner` | function | `c2/server.py:512` | `def build_stage_oneliner(cfg)` |
| `command_injector` | function | `c2/server.py:932` | `def command_injector(state)` |
| `compute_hmac` | function | `c2/server.py:210` | `def compute_hmac(key, data)` |
| `copy_to_clipboard` | function | `c2/server.py:529` | `def copy_to_clipboard(text)` |
| `decrypt_data` | function | `c2/server.py:278` | `def decrypt_data(b64_data, key, hmac_key, use_hmac)` |
| `decrypt_data_replay` | function | `c2/server.py:301` | `def decrypt_data_replay(b64_data, key, hmac_key, use_hmac, replay_window_seconds, last_seen_counter, client_id)` |
| `encrypt_data` | function | `c2/server.py:221` | `def encrypt_data(data, key, hmac_key, use_hmac)` |
| `encrypt_data_replay` | function | `c2/server.py:244` | `def encrypt_data_replay(data, key, counter, timestamp, hmac_key, use_hmac)` |
| `handle_bof` | function | `c2/server.py:682` | `def handle_bof(state, name)` |
| `handle_get_command` | function | `c2/server.py:568` | `def handle_get_command(state, selector)` |
| `handle_report` | function | `c2/server.py:592` | `def handle_report(state, b64_payload)` |
| `handle_request` | function | `c2/server.py:720` | `def handle_request(state, selector)` |
| `handle_stage` | function | `c2/server.py:481` | `def handle_stage(state, kind, token)` |
| `hkdf_sha256` | function | `c2/server.py:398` | `def hkdf_sha256(ikm, salt, info, length)` |
| `load_runtime_config` | function | `c2/server.py:86` | `def load_runtime_config()` |
| `main` | function | `c2/server.py:955` | `def main()` |
| `serve` | function | `c2/server.py:890` | `def serve(cfg, state)` |
| `serve_client` | function | `c2/server.py:860` | `def serve_client(state, conn, addr)` |
| `stage_decode` | function | `c2/server.py:430` | `def stage_decode(body, token)` |
| `stage_encode` | function | `c2/server.py:422` | `def stage_encode(payload, token)` |
| `stage_keys` | function | `c2/server.py:410` | `def stage_keys(token)` |
| `stage_token_ok` | function | `c2/server.py:441` | `def stage_token_ok(state, token)` |
| `verify_hmac` | function | `c2/server.py:215` | `def verify_hmac(key, data, signature)` |
| `xor_layer` | function | `c2/server.py:416` | `def xor_layer(data, key)` |
| `_fetch_and_decode` | function | `c2/stage_payload.py:48` | `def _fetch_and_decode(url, token, path, tls_ctx)` |
| `hkdf_sha256` | function | `c2/stage_payload.py:37` | `def hkdf_sha256(ikm, salt, info, length)` |
| `main` | function | `c2/stage_payload.py:67` | `def main()` |
| `CJSON_PUBLIC` | function | `cJSON.c:96` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:101` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:111` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:126` | `CJSON_PUBLIC(const char *) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:211` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks *hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1143` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end,      ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1251` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1333` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1338` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1369` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1956` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2003` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *const object, const char *const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2008` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON *const object, const char *con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2014` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2143` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2154` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2164` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2176` | `CJSON_PUBLIC(cJSON *) cJSON_AddNullToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2188` | `CJSON_PUBLIC(cJSON *) cJSON_AddTrueToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2200` | `CJSON_PUBLIC(cJSON *) cJSON_AddFalseToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2212` | `CJSON_PUBLIC(cJSON *) cJSON_AddBoolToObject(cJSON *const object, const char *const name, const cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2225` | `CJSON_PUBLIC(cJSON *) cJSON_AddNumberToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2238` | `CJSON_PUBLIC(cJSON *) cJSON_AddStringToObject(cJSON *const object, const char *const name, const ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2251` | `CJSON_PUBLIC(cJSON *) cJSON_AddRawToObject(cJSON *const object, const char *const name, const cha...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2264` | `CJSON_PUBLIC(cJSON *) cJSON_AddObjectToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2276` | `CJSON_PUBLIC(cJSON *) cJSON_AddArrayToObject(cJSON *const object, const char *const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2288` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2324` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2334` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2339` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2346` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2353` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2358` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2400` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON *const parent, cJSON *const item, cJSO...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2451` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2486` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2492` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2510` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2521` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2532` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2543` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2568` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2585` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2597` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2609` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2621` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2638` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2649` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2702` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2743` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2784` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2977` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3027` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3037` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3047` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3057` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3067` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3077` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3087` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3097` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3107` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3117` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON *const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3127` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON *const b, const cJSON_bo...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3251` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3256` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:83` | `#define NAN` |
| `NAN` | macro | `cJSON.c:85` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2048` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `cJSON.c:2104` | `static cJSON_bool add_item_to_object(cJSON *const object, const char *const string,              ...` |
| `buffer_at_offset` | macro | `cJSON.c:308` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1101` | `static parse_buffer *buffer_skip_whitespace(parse_buffer *const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3214` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3230` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2832` | `cJSON *cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:243` | `static cJSON *cJSON_New_Item(const internal_hooks *const hooks)` |
| `cJSON_strdup` | function | `cJSON.c:190` | `static unsigned char *cJSON_strdup(const unsigned char *string, const internal_hooks *const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:304` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:302` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:306` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:135` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2095` | `static void *cast_away_const(const void *string)` |
| `cjson_min` | macro | `cJSON.c:1256` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:596` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2027` | `static cJSON *create_reference(const cJSON *item, const internal_hooks *const hooks)` |
| `ensure` | function | `cJSON.c:497` | `static unsigned char *ensure(printbuffer *const p, size_t needed)` |
| `error` | struct | `cJSON.c:89` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `get_array_item` | function | `cJSON.c:1937` | `static cJSON *get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:282` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1966` | `static cJSON *get_object_item(const cJSON *const object, const char *const name,                 ...` |
| `internal_free` | function | `cJSON.c:171` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:181` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:158` | `` |
| `internal_malloc` | function | `cJSON.c:167` | `static void *CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:180` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:175` | `static void *CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:182` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:75` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:78` | `#define isnan(d)` |
| `minify_string` | function | `cJSON.c:2951` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1524` | `static cJSON_bool parse_array(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:292` | `` |
| `parse_hex4` | function | `cJSON.c:673` | `static unsigned parse_hex4(const unsigned char *const input)` |
| `parse_number` | function | `cJSON.c:311` | `static cJSON_bool parse_number(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_object` | function | `cJSON.c:1683` | `static cJSON_bool parse_object(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_string` | function | `cJSON.c:832` | `static cJSON_bool parse_string(cJSON *const item, parse_buffer *const input_buffer)` |
| `parse_value` | function | `cJSON.c:1390` | `static cJSON_bool parse_value(cJSON *const item, parse_buffer *const input_buffer)` |
| `print` | function | `cJSON.c:1258` | `static unsigned char *print(const cJSON *const item, cJSON_bool format,                          ...` |
| `print_array` | function | `cJSON.c:1621` | `static cJSON_bool print_array(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_number` | function | `cJSON.c:603` | `static cJSON_bool print_number(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_object` | function | `cJSON.c:1801` | `static cJSON_bool print_object(const cJSON *const item, printbuffer *const output_buffer)` |
| `print_string` | function | `cJSON.c:1087` | `static cJSON_bool print_string(const cJSON *const item, printbuffer *const p)` |
| `print_string_ptr` | function | `cJSON.c:964` | `static cJSON_bool print_string_ptr(const unsigned char *const input,                             ...` |
| `print_value` | function | `cJSON.c:1450` | `static cJSON_bool print_value(const cJSON *const item, printbuffer *const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:485` | `` |
| `replace_item_in_object` | function | `cJSON.c:2461` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement,  ...` |
| `skip_multiline_comment` | function | `cJSON.c:2937` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2923` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1127` | `static parse_buffer *skip_utf8_bom(parse_buffer *const buffer)` |
| `static_strlen` | macro | `cJSON.c:186` | `#define static_strlen(string_literal)` |
| `suffix_object` | function | `cJSON.c:2020` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:583` | `static void update_offset(printbuffer *const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:710` | `static unsigned char utf16_literal_to_utf8(const unsigned char *const input_pointer,             ...` |
| `CJSON_CDECL` | macro | `cJSON.h:49` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `cJSON.h:65` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `cJSON.h:142` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `cJSON.h:54` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `cJSON.h:136` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `cJSON.h:58` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:60` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:62` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:70` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:72` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `cJSON.h:50` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `cJSON.h:66` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `cJSON.h:77` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `cJSON.h:78` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `cJSON.h:79` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `cJSON.h:33` | `#define __WINDOWS__` |
| `cJSON` | struct | `cJSON.h:98` | `` |
| `cJSON_Array` | macro | `cJSON.h:90` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `cJSON.h:331` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `cJSON.h:85` | `#define cJSON_False` |
| `cJSON_GetErrorPtr` | function | `cJSON.h:161` | `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...` |
| `cJSON_Hooks` | struct | `cJSON.h:123` | `` |
| `cJSON_Invalid` | macro | `cJSON.h:84` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `cJSON.h:94` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `cJSON.h:87` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `cJSON.h:88` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `cJSON.h:91` | `#define cJSON_Object` |
| `cJSON_Parse` | function | `cJSON.h:152` | `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...` |
| `cJSON_Raw` | macro | `cJSON.h:92` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `cJSON.h:324` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `cJSON.h:312` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `cJSON.h:316` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `cJSON.h:89` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `cJSON.h:95` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `cJSON.h:86` | `#define cJSON_True` |
| `cJSON__h` | macro | `cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `cJSON.h:130` | `typedef int cJSON_bool;` |
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\|...` |
| `sensitive` | function | `cJSON.h:286` | `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...` |
| `that` | function | `cJSON.h:247` | `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...` |
| `c_field_name` | function | `config/generate_parsers.py:48` | `def c_field_name(json_name)` |
| `c_type_from_schema` | function | `config/generate_parsers.py:30` | `def c_type_from_schema(prop, required)` |
| `generate_c_parser` | function | `config/generate_parsers.py:136` | `def generate_c_parser(schema)` |
| `generate_c_structs` | function | `config/generate_parsers.py:53` | `def generate_c_structs(schema)` |
| `generate_python_loader` | function | `config/generate_parsers.py:465` | `def generate_python_loader(schema)` |
| `load_schema` | function | `config/generate_parsers.py:25` | `def load_schema()` |
| `main` | function | `config/generate_parsers.py:615` | `def main()` |
| `ensure_dir` | function | `contract_agent.py:29` | `def ensure_dir(path)` |
| `extract_contracts` | function | `contract_agent.py:41` | `def extract_contracts(claude_content)` |
| `git` | function | `contract_agent.py:33` | `def git()` |
| `git_commit_and_branch` | function | `contract_agent.py:275` | `def git_commit_and_branch(contract_name)` |
| `main` | function | `contract_agent.py:316` | `def main()` |
| `make_target` | function | `contract_agent.py:37` | `def make_target(target)` |
| `process_contract` | function | `contract_agent.py:289` | `def process_contract(contract_name, body)` |
| `run_asan` | function | `contract_agent.py:256` | `def run_asan()` |
| `run_c_tests` | function | `contract_agent.py:223` | `def run_c_tests()` |
| `run_cmd` | function | `contract_agent.py:23` | `def run_cmd(cmd, cwd)` |
| `run_mutation_testing` | function | `contract_agent.py:233` | `def run_mutation_testing()` |
| `run_python_tests` | function | `contract_agent.py:213` | `def run_python_tests()` |
| `run_qa` | function | `contract_agent.py:266` | `def run_qa()` |
| `write_c_test` | function | `contract_agent.py:141` | `def write_c_test(contract_name, body)` |
| `write_implementation_stub` | function | `contract_agent.py:179` | `def write_implementation_stub(contract_name)` |
| `write_python_test` | function | `contract_agent.py:96` | `def write_python_test(contract_name, body)` |
| `write_spec` | function | `contract_agent.py:62` | `def write_spec(contract_name, body)` |
| `command_injector` | function | `gopher_c2.py:152` | `def command_injector()` |
| `decrypt_data` | function | `gopher_c2.py:40` | `def decrypt_data(b64_data)` |
| `encrypt_data` | function | `gopher_c2.py:30` | `def encrypt_data(data)` |
| `handle_client` | function | `gopher_c2.py:49` | `def handle_client(conn, addr)` |
| `main` | function | `gopher_c2.py:143` | `def main()` |
| `AES_CBC_decrypt_buffer` | function | `include/aes.c:552` | `void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `include/aes.c:537` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `include/aes.c:572` | `void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length)` |
| `AES_ECB_decrypt` | function | `include/aes.c:518` | `void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ECB_encrypt` | function | `include/aes.c:512` | `void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf)` |
| `AES_ctx_set_iv` | function | `include/aes.c:264` | `void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)` |
| `AES_init_ctx` | function | `include/aes.c:254` | `void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key)` |
| `AES_init_ctx_iv` | function | `include/aes.c:259` | `void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)` |
| `AddRoundKey` | function | `include/aes.c:272` | `static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)` |
| `BLOCKLEN` | macro | `include/aes.c:9` | `#define BLOCKLEN` |
| `Cipher` | function | `include/aes.c:455` | `static void Cipher(state_t *state, const uint8_t *RoundKey)` |
| `InvCipher` | function | `include/aes.c:482` | `static void InvCipher(state_t *state, const uint8_t *RoundKey)` |
| `InvMixColumns` | function | `include/aes.c:389` | `static void InvMixColumns(state_t *state)` |
| `InvShiftRows` | function | `include/aes.c:425` | `static void InvShiftRows(state_t *state)` |
| `InvSubBytes` | function | `include/aes.c:413` | `static void InvSubBytes(state_t *state)` |
| `KEYLEN_256` | macro | `include/aes.c:7` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `include/aes.c:181` | `static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `include/aes.c:101` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `include/aes.c:335` | `static void MixColumns(state_t *state)` |
| `Multiply` | function | `include/aes.c:363` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `include/aes.c:371` | `#define Multiply(x, y)` |
| `Nb` | macro | `include/aes.c:5` | `#define Nb` |
| `Nb` | macro | `include/aes.c:84` | `#define Nb` |
| `Nk` | macro | `include/aes.c:87` | `#define Nk` |
| `Nk` | macro | `include/aes.c:90` | `#define Nk` |
| `Nk` | macro | `include/aes.c:93` | `#define Nk` |
| `Nr` | macro | `include/aes.c:88` | `#define Nr` |
| `Nr` | macro | `include/aes.c:91` | `#define Nr` |
| `Nr` | macro | `include/aes.c:94` | `#define Nr` |
| `RKLENGTH` | macro | `include/aes.c:8` | `#define RKLENGTH` |
| `ShiftRows` | function | `include/aes.c:301` | `static void ShiftRows(state_t *state)` |
| `SubBytes` | function | `include/aes.c:286` | `static void SubBytes(state_t *state)` |
| `XorWithIv` | function | `include/aes.c:528` | `static void XorWithIv(uint8_t *buf, const uint8_t *Iv)` |
| `__attribute__` | function | `include/aes.c:11` | `static __attribute__((unused)) uint8_t getSBoxValue(uint8_t num)` |
| `__attribute__` | function | `include/aes.c:35` | `static __attribute__((unused)) uint8_t getSBoxInvert(uint8_t num)` |

Next: [SYMBOLS_p2.md](SYMBOLS_p2.md)
