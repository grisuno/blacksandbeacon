# Subsystem: misc

## beacons/v1/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `report_result` (function, line 24) `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
  - `execute_command` (function, line 104) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 167) `int main(void)`
  - `_GNU_SOURCE` (macro, line 13) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

## beacons/v2/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `peer_t` (struct, line 33)
  - `mesh_msg_t` (struct, line 41)
  - `report_result` (function, line 69) `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
  - `execute_command` (function, line 149) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 212) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
  - `MAX_PEERS` (macro, line 27) `#define MAX_PEERS`
  - `DISCOVERY_PORT` (macro, line 28) `#define DISCOVERY_PORT`
  - `DISCOVERY_INTERVAL` (macro, line 29) `#define DISCOVERY_INTERVAL`
  - `MAX_TTL` (macro, line 30) `#define MAX_TTL`
  - `MESH_MSG_SIZE` (macro, line 31) `#define MESH_MSG_SIZE`
- Depends on: `include/beacon_common.h`

## beacons/v3/beacon.c
- Layer: utility
- Language: c
- Symbols:
  - `infrastructure` (function, line 8) `*
 * All shared infrastructure (HTTP client, crypto, BOF loader)
 * lives in beacon_common.c. Thi...`
  - `compute_primes` (function, line 42) `static int compute_primes(int count)`
  - `evasive_sleep` (function, line 55) `static void evasive_sleep(int seconds)`
  - `report_result` (function, line 62) `static void report_result(const bsb_config_t *cfg, const char *command, const char *output)`
  - `execute_command` (function, line 142) `static char *execute_command(const bsb_config_t *cfg, const char *command)`
  - `main` (function, line 205) `int main(void)`
  - `_GNU_SOURCE` (macro, line 12) `#define _GNU_SOURCE`
- Depends on: `include/beacon_common.h`

## bof/suid_enum/bof.c
- Doc: linux_stat: #include "beacon_api.h" #include "syscalls.h" /* getdents64 syscall number (x86_64)...
- Layer: utility
- Language: c
- Symbols:
  - `linux_stat` (struct, line 35)
  - `linux_dirent64` (struct, line 59)
  - `flush_output` (function, line 78) `static void flush_output(void)`
  - `emit` (function, line 87) `static void emit(const char *s)`
  - `format_mode` (function, line 114) `static void format_mode(unsigned int mode, char *out)`
  - `path_reset` (function, line 137) `static void path_reset(const char *root)`
  - `path_append` (function, line 148) `static void path_append(const char *name)`
  - `path_trim_to` (function, line 166) `static void path_trim_to(int len)`
  - `walk` (function, line 178) `static void walk(int depth)`
  - `go` (function, line 298) `void go(char *args, int alen)`
  - `SYS_getdents64` (macro, line 26) `#define SYS_getdents64`
  - `SYS_lstat` (macro, line 27) `#define SYS_lstat`
  - `DT_UNKNOWN` (macro, line 30) `#define DT_UNKNOWN`
  - `DT_DIR` (macro, line 31) `#define DT_DIR`
  - `DT_LNK` (macro, line 32) `#define DT_LNK`
- Depends on: `bof/include/beacon_api.h`, `bof/include/syscalls.h`

## config/generate_parsers.py
- Doc: Config Parser Generator for Black Sand Beacon  Reads config/schema.json (JSON Schema Draft 7)...
- Layer: infrastructure
- Language: py
- Symbols:
  - `load_schema` (function, line 25) `def load_schema()`
  - `c_type_from_schema` (function, line 30) `def c_type_from_schema(prop, required)`
  - `c_field_name` (function, line 48) `def c_field_name(json_name)`
  - `generate_c_structs` (function, line 53) `def generate_c_structs(schema)`
  - `generate_c_parser` (function, line 136) `def generate_c_parser(schema)`
  - `generate_python_loader` (function, line 465) `def generate_python_loader(schema)`
  - `main` (function, line 615) `def main()`

## scripts/mutation_test_c.py
- Doc: C Mutation Testing Script  This script performs mutation testing on C code by: 1.
- Layer: testing
- Language: py
- Symbols:
  - `should_mutate` (function, line 73) `def should_mutate(filepath)`
  - `find_mutable_lines` (function, line 82) `def find_mutable_lines(content)`
  - `apply_mutation` (function, line 103) `def apply_mutation(content, line_num, mutated_line)`
  - `compile_and_test` (function, line 111) `def compile_and_test(mutant_dir, test_name)`
  - `run_mutation_test` (function, line 136) `def run_mutation_test()`
  - `main` (function, line 222) `def main()`
