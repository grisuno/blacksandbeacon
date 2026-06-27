/*
 * bof/whoami/bof.c
 *
 * Print the current effective username.
 *
 * Built as a position-independent ELF object (BOF). Compiled with
 * -nostdlib -fPIC so it can be loaded into the beacon process at
 * runtime without a libc dependency.
 *
 * Build:
 *   make bof-whoami
 */
#include "beacon_api.h"
#include "syscalls.h"

/* BeaconPrintf/BeaconOutput are declared in beacon_api.h, which the
 * beacon's loader resolves by symbol name. */

void go(char *args, int alen) {
    (void)args;
    (void)alen;

    long uid = syscall1(SYS_geteuid, 0);
    char buf[32];
    char *p = buf + sizeof(buf) - 1;
    *p = '\0';

    long n = uid;
    if (n == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=0 (root)\n");
        BeaconOutput(CALLBACK_OUTPUT, "root", 0);
        return;
    }

    do {
        *--p = '0' + (n % 10);
        n /= 10;
    } while (n && p > buf);

    BeaconPrintf(CALLBACK_OUTPUT, "[whoami] uid=%s\n", p);
    BeaconOutput(CALLBACK_OUTPUT, p, 0);
}
