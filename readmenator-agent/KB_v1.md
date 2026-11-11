# Subsystem: v1

## beacons/v1/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `report_result` (function, line 24) `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
  - `execute_command` (function, line 104) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 167) `int main(void)`
  - `_GNU_SOURCE` (macro, line 13) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

## beacons/v1/gopher_beacon.c
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
