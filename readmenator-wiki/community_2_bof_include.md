# bof/include

*Community 2 | 7 files | cohesion 1.00*

## Definition

This community groups 7 file(s) rooted at `bof/include` with dominant language c (cohesion 1.00). Central symbols: `AT_FDCWD`, `BSB_BOF_BEACON_API_H`, `BSB_BOF_SYSCALLS_H`, `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataLength`, `BeaconDataParse`, `BeaconDataPtr`. Core file: `bof/include/syscalls.h` (38 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/cat/bof.c` | c | utility | 1 | no |
| `bof/include/beacon_api.h` | h | presentation | 14 | no |
| `bof/include/syscalls.h` | h | utility | 38 | no |
| `bof/is_sudo/bof.c` | c | utility | 2 | no |
| `bof/suid_enum/bof.c` | c | utility | 15 | no |
| `bof/userenum/bof.c` | c | utility | 2 | no |
| `bof/whoami/bof.c` | c | utility | 1 | no |

## Key Symbols

- `go` (function, `bof/cat/bof.c:15`) `void go(char *args, int alen)`
- `go` (function, `bof/include/beacon_api.h:10`) `* * BOFs MUST export a function with this exact signature: * * void go(char *arg`
- `BSB_BOF_BEACON_API_H` (macro, `bof/include/beacon_api.h:17`) `#define BSB_BOF_BEACON_API_H`
- `CALLBACK_OUTPUT` (macro, `bof/include/beacon_api.h:24`) `#define CALLBACK_OUTPUT`
- `CALLBACK_ERROR` (macro, `bof/include/beacon_api.h:25`) `#define CALLBACK_ERROR`
- `CALLBACK_OUTPUT_OEM` (macro, `bof/include/beacon_api.h:26`) `#define CALLBACK_OUTPUT_OEM`
- `datap` (struct, `bof/include/beacon_api.h:30`) - Argument parser. BOFs that want to read structured args fill * one of these in via BeaconDataParse t
- `BeaconDataParse` (function, `bof/include/beacon_api.h:36`) `void BeaconDataParse(datap *parser, char *buffer, int size);`
- `BeaconDataPtr` (function, `bof/include/beacon_api.h:37`) `char *BeaconDataPtr(datap *parser, int size);`
- `BeaconDataInt` (function, `bof/include/beacon_api.h:38`) `int BeaconDataInt(datap *parser);`
- `BeaconDataShort` (function, `bof/include/beacon_api.h:39`) `short BeaconDataShort(datap *parser);`
- `BeaconDataLength` (function, `bof/include/beacon_api.h:40`) `int BeaconDataLength(datap *parser);`
- `BeaconDataExtract` (function, `bof/include/beacon_api.h:41`) `char *BeaconDataExtract(datap *parser, int *size);`
- `buffer` (function, `bof/include/beacon_api.h:44`) `* takes a raw byte buffer (len may be 0 for strlen-style strings * but the buffe`
- `BeaconOutput` (function, `bof/include/beacon_api.h:47`) `void BeaconOutput(int type, const char *data, int len);`
- `BSB_BOF_SYSCALLS_H` (macro, `bof/include/syscalls.h:12`) `#define BSB_BOF_SYSCALLS_H`
- `SYS_read` (macro, `bof/include/syscalls.h:17`) `#define SYS_read`
- `SYS_write` (macro, `bof/include/syscalls.h:18`) `#define SYS_write`
- `SYS_open` (macro, `bof/include/syscalls.h:19`) `#define SYS_open`
- `SYS_close` (macro, `bof/include/syscalls.h:20`) `#define SYS_close`
- `SYS_stat` (macro, `bof/include/syscalls.h:21`) `#define SYS_stat`
- `SYS_fstat` (macro, `bof/include/syscalls.h:22`) `#define SYS_fstat`
- `SYS_lseek` (macro, `bof/include/syscalls.h:23`) `#define SYS_lseek`
- `SYS_mmap` (macro, `bof/include/syscalls.h:24`) `#define SYS_mmap`
- `SYS_munmap` (macro, `bof/include/syscalls.h:25`) `#define SYS_munmap`
- `SYS_brk` (macro, `bof/include/syscalls.h:26`) `#define SYS_brk`
- `SYS_ioctl` (macro, `bof/include/syscalls.h:27`) `#define SYS_ioctl`
- `SYS_access` (macro, `bof/include/syscalls.h:28`) `#define SYS_access`
- `SYS_pipe` (macro, `bof/include/syscalls.h:29`) `#define SYS_pipe`
- `SYS_dup2` (macro, `bof/include/syscalls.h:30`) `#define SYS_dup2`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 10
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 2 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 0 (root) and community 2 (bof/include).
- [INFERRED] shares_context community 1 <-> 2 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 1 (include: cJSON) and community 2 (bof/include).
- [INFERRED] shares_context community 2 <-> 4 (strength 0.5): Inferred shared context (language c and layer utility) with no import path between community 2 (bof/include) and community 4 (include: aes).
- [INFERRED] shares_context community 2 <-> 5 (strength 0.5): Inferred shared context (language c) with no import path between community 2 (bof/include) and community 5 (include: config).
- [INFERRED] shares_context community 2 <-> 6 (strength 0.5): Inferred shared context (language c) with no import path between community 2 (bof/include) and community 6 (include: aes_cfb).
- [INFERRED] shares_context community 2 <-> 7 (strength 0.5): Inferred shared context (layer utility) with no import path between community 2 (bof/include) and community 7 (orphans).

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 7 file(s) lack file-level docs (e.g. `bof/cat/bof.c`)? What purpose do they serve?
- What would break if the most connected file in bof/include changed?
- Should bof/include be split, given cohesion 1.00?

## Sources

- `bof/cat/bof.c`
- `bof/include/beacon_api.h`
- `bof/include/syscalls.h`
- `bof/is_sudo/bof.c`
- `bof/suid_enum/bof.c`
- `bof/userenum/bof.c`
- `bof/whoami/bof.c`
