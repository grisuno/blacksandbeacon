# Subsystem: root (page 2 of 2)
Previous: [KB_root.md](KB_root.md)

## cJSON.h
- Doc: cJSON: #define cJSON_Invalid (0) #define cJSON_False (1 << 0) #define cJSON_True (1 << 1)...
- Layer: utility
- Language: h
- Symbols:
  - `cJSON` (struct, line 98)
  - `cJSON_Hooks` (struct, line 123)
  - `cJSON_bool` (type_alias, line 130) `typedef int cJSON_bool;`
  - `cJSON_Parse` (function, line 152) `* cJSON_Parse (with cJSON_Delete) and cJSON_Print (with stdlib free, cJSON_Hooks.free_fn, or * cJSON_free as...`
  - `cJSON_GetErrorPtr` (function, line 161) `* a pointer to the error so will match cJSON_GetErrorPtr(). */ CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char...`
  - `that` (function, line 247) `* that (item->type & cJSON_StringIsConst) is zero before writing to `item->string` */ CJSON_PUBLIC(cJSON_bool)...`
  - `sensitive` (function, line 286) `* sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON *const a, const cJSON...`
  - `next` (variable, line 27) `extern "C" { #endif #if !defined(__WINDOWS__) && \ (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) ||...`
  - `cJSON__h` (macro, line 24) `#define cJSON__h`
  - `__WINDOWS__` (macro, line 33) `#define __WINDOWS__`
  - `CJSON_CDECL` (macro, line 49) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 50) `#define CJSON_STDCALL`
  - `CJSON_EXPORT_SYMBOLS` (macro, line 54) `#define CJSON_EXPORT_SYMBOLS`
  - `CJSON_PUBLIC` (macro, line 58) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 60) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 62) `#define CJSON_PUBLIC(type)`
  - `CJSON_CDECL` (macro, line 65) `#define CJSON_CDECL`
  - `CJSON_STDCALL` (macro, line 66) `#define CJSON_STDCALL`
  - `CJSON_PUBLIC` (macro, line 70) `#define CJSON_PUBLIC(type)`
  - `CJSON_PUBLIC` (macro, line 72) `#define CJSON_PUBLIC(type)`
  - `CJSON_VERSION_MAJOR` (macro, line 77) `#define CJSON_VERSION_MAJOR`
  - `CJSON_VERSION_MINOR` (macro, line 78) `#define CJSON_VERSION_MINOR`
  - `CJSON_VERSION_PATCH` (macro, line 79) `#define CJSON_VERSION_PATCH`
  - `cJSON_Invalid` (macro, line 84) `#define cJSON_Invalid`
  - `cJSON_False` (macro, line 85) `#define cJSON_False`
  - `cJSON_True` (macro, line 86) `#define cJSON_True`
  - `cJSON_NULL` (macro, line 87) `#define cJSON_NULL`
  - `cJSON_Number` (macro, line 88) `#define cJSON_Number`
  - `cJSON_String` (macro, line 89) `#define cJSON_String`
  - `cJSON_Array` (macro, line 90) `#define cJSON_Array`
  - `cJSON_Object` (macro, line 91) `#define cJSON_Object`
  - `cJSON_Raw` (macro, line 92) `#define cJSON_Raw`
  - `cJSON_IsReference` (macro, line 94) `#define cJSON_IsReference`
  - `cJSON_StringIsConst` (macro, line 95) `#define cJSON_StringIsConst`
  - `CJSON_NESTING_LIMIT` (macro, line 136) `#define CJSON_NESTING_LIMIT`
  - `CJSON_CIRCULAR_LIMIT` (macro, line 142) `#define CJSON_CIRCULAR_LIMIT`
  - `cJSON_SetIntValue` (macro, line 312) `#define cJSON_SetIntValue(object, number)`
  - `cJSON_SetNumberValue` (macro, line 316) `#define cJSON_SetNumberValue(object, number)`
  - `cJSON_SetBoolValue` (macro, line 324) `#define cJSON_SetBoolValue(object, boolValue)`
  - `cJSON_ArrayForEach` (macro, line 331) `#define cJSON_ArrayForEach(element, array)`
- Imported by: `beacon3.c`, `beacon5.c`, `beacon6.c`, `beacon_p2p.c`, `cJSON.c`, `gopher_beacon.c`

## contract_agent.py
- Doc: Contract Driven Agent - SDD/TDD/BDD workflow for Black Sand Beacon v2.
- Layer: utility
- Language: py
- Symbols:
  - `run_cmd` (function, line 23) `def run_cmd(cmd, cwd)`
  - `ensure_dir` (function, line 29) `def ensure_dir(path)`
  - `git` (function, line 33) `def git()`
  - `make_target` (function, line 37) `def make_target(target)`
  - `extract_contracts` (function, line 41) `def extract_contracts(claude_content)`
  - `write_spec` (function, line 62) `def write_spec(contract_name, body)`
  - `write_python_test` (function, line 96) `def write_python_test(contract_name, body)`
  - `write_c_test` (function, line 141) `def write_c_test(contract_name, body)`
  - `write_implementation_stub` (function, line 179) `def write_implementation_stub(contract_name)`
  - `run_python_tests` (function, line 213) `def run_python_tests()`
  - `run_c_tests` (function, line 223) `def run_c_tests()`
  - `run_mutation_testing` (function, line 233) `def run_mutation_testing()`
  - `run_asan` (function, line 256) `def run_asan()`
  - `run_qa` (function, line 266) `def run_qa()`
  - `git_commit_and_branch` (function, line 275) `def git_commit_and_branch(contract_name)`
  - `process_contract` (function, line 289) `def process_contract(contract_name, body)`
  - `main` (function, line 316) `def main()`

## gopher_beacon.c
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
- Depends on: `aes.h`, `beacon.h`, `cJSON.h`

## gopher_c2.py
- Layer: utility
- Language: py
- Symbols:
  - `encrypt_data` (function, line 30) `def encrypt_data(data)`
  - `decrypt_data` (function, line 40) `def decrypt_data(b64_data)`
  - `handle_client` (function, line 49) `def handle_client(conn, addr)`
  - `main` (function, line 143) `def main()`
  - `command_injector` (function, line 152) `def command_injector()`

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
  - `strcmp` (function, line 40) `static int strcmp(const char *s1, const char *s2)`
  - `get_username_from_uid` (function, line 51) `static int get_username_from_uid(long uid, char *buf, int buf_size)`
  - `go` (function, line 121) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 10) `extern void BeaconPrintf(int, const char *, ...);`
  - `BeaconOutput` (function, line 11) `extern void BeaconOutput(int, const char *, int);`
  - `NULL` (macro, line 2) `#define NULL`
  - `CALLBACK_OUTPUT` (macro, line 3) `#define CALLBACK_OUTPUT`
  - `SYS_openat` (macro, line 14) `#define SYS_openat`
  - `SYS_read` (macro, line 15) `#define SYS_read`
  - `SYS_close` (macro, line 16) `#define SYS_close`
  - `SYS_getuid` (macro, line 17) `#define SYS_getuid`
  - `SYS_getpwuid_r` (macro, line 18) `#define SYS_getpwuid_r`
  - `AT_FDCWD` (macro, line 19) `#define AT_FDCWD`

## mutmut_config.py
- Layer: infrastructure
- Language: py

