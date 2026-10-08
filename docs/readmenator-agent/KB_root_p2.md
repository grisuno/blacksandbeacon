# Subsystem: root (page 2 of 2)
Previous: [KB_root.md](KB_root.md)

## gopher_beacon.c
- Doc: MemoryStruct: === ESTRUCTURAS ===
- Layer: utility
- Language: c
- Symbols:
  - `MemoryStruct` (struct, line 47)
  - `Trampoline` (struct, line 54)
  - `SymbolResolver` (struct, line 62)
  - `TrampolineCache` (struct, line 68)
  - `__attribute__` (function, line 137) `static void __attribute__((noinline))
call_bof_isolated(bof_func_t func, char* args, uintptr_t ar...`
  - `BeaconPrintf` (function, line 190) `void BeaconPrintf(int type, const char *fmt, ...)`
  - `BeaconOutput` (function, line 203) `void BeaconOutput(int type, const char *data, int len)`
  - `create_trampoline` (function, line 214) `static void* create_trampoline(void* target)`
  - `cleanup_trampolines` (function, line 250) `static void cleanup_trampolines(void)`
  - `get_or_create_trampoline` (function, line 266) `static void* get_or_create_trampoline(void* target)`
  - `WriteMemoryCallback` (function, line 297) `static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)`
  - `gopher_request` (function, line 314) `char* gopher_request(const char* host, int port, const char* selector, const char* method, const ...`
  - `base64_encode` (function, line 377) `char* base64_encode(const unsigned char* input, int len)`
  - `base64_decode` (function, line 394) `unsigned char* base64_decode(const char* input, int* len)`
  - `aes256_cfb_encrypt` (function, line 417) `unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `aes256_cfb_decrypt` (function, line 445) `unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
            ...`
  - `exec_cmd` (function, line 475) `char* exec_cmd(const char* cmd, int* out_len)`
  - `page_align` (function, line 506) `static size_t page_align(size_t size)`
  - `RunELF` (function, line 512) `int RunELF(const char* functionname, unsigned char* elf_data, uint32_t filesize, 
           unsi...`
  - `get_local_ips` (function, line 893) `char* get_local_ips()`
  - `download_bof` (function, line 922) `unsigned char* download_bof(const char* bof_selector, size_t* out_size)`
  - `run_bof_and_capture` (function, line 950) `char* run_bof_and_capture(unsigned char* elf_data, uint32_t filesize,
                          c...`
  - `main` (function, line 994) `int main()`
  - `_GNU_SOURCE` (macro, line 1) `#define _GNU_SOURCE`
  - `C2` (macro, line 30) `#define C2`
  - `CLIENT_ID` (macro, line 31) `#define CLIENT_ID`
  - `MALEABLE` (macro, line 32) `#define MALEABLE`
  - `USER_AGENTS_COUNT` (macro, line 33) `#define USER_AGENTS_COUNT`
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## gopher_c2.py
- Layer: utility
- Language: py
- Symbols:
  - `encrypt_data` (function, line 28) `def encrypt_data(data)`
  - `decrypt_data` (function, line 37) `def decrypt_data(b64_data)`
  - `handle_client` (function, line 45) `def handle_client(conn, addr)`
  - `main` (function, line 127) `def main()`
  - `command_injector` (function, line 136) `def command_injector()`

## install.sh
- Doc: Install build deps and build everything.
- Layer: utility
- Language: sh

## issudo.c
- Doc: — LazyOwn RedTeam BOF (Linux/x64)  Tipos
- Layer: utility
- Language: c
- Symbols:
  - `size_t` (type_alias, line 6) `typedef unsigned long size_t;`
  - `ssize_t` (type_alias, line 7) `typedef long ssize_t;`
  - `syscall3` (function, line 22) `static inline long syscall3(long n, long a1, long a2, long a3)`
  - `syscall1` (function, line 32) `static inline long syscall1(long n, long a1)`
  - `strcmp` (function, line 43) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 52) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 108) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 10) `extern void BeaconPrintf(int, const char*, ...);`
  - `BeaconOutput` (function, line 11) `extern void BeaconOutput(int, const char*, int);`
  - `NULL` (macro, line 2) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 3) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 14) `#define SYS_openat`
  - `SYS_read` (macro, line 15) `#define SYS_read`
  - `SYS_close` (macro, line 16) `#define SYS_close`
  - `SYS_getuid` (macro, line 17) `#define SYS_getuid`
  - `SYS_getpwuid_r` (macro, line 18) `#define SYS_getpwuid_r`
  - `AT_FDCWD` (macro, line 19) `#define AT_FDCWD`

