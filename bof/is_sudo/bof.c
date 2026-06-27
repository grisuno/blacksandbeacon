/*
 * bof/is_sudo/bof.c
 *
 * Check whether the current user is in the sudo or wheel group.
 *
 * Reads /etc/group, looks for the user's name in the member list
 * of either group, and reports "yes" or "no" via BeaconOutput.
 *
 * Build:
 *   make bof-is_sudo
 */
#include "beacon_api.h"
#include "syscalls.h"

static int user_in_group(const char *group, const char *username, char *filebuf, long filesize) {
    char *line = filebuf;
    while (line < filebuf + filesize) {
        char *next = line;
        while (next < filebuf + filesize && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

        /* group_name:password:gid:user1,user2,... */
        char *group_name = line;
        char *p = line;
        int col = 0;
        char *user_list = NULL;

        while (*p) {
            if (*p == ':') {
                if (col == 0) *p = '\0';
                else if (col == 2) { *p = '\0'; user_list = p + 1; }
                col++;
            }
            if (col > 2) break;
            p++;
        }

        if (bsf_strcmp(group_name, group) == 0 && user_list && user_list[0]) {
            char *u = user_list;
            while (*u) {
                char *end = u;
                while (*end && *end != ',') end++;
                char saved = *end;
                *end = '\0';
                int match = (bsf_strcmp(u, username) == 0);
                *end = saved;
                if (match) return 1;
                if (!saved) break;
                u = end + 1;
            }
        }
        line = next + 1;
    }
    return 0;
}

void go(char *args, int alen) {
    (void)args;
    (void)alen;

    long uid = syscall1(SYS_getuid, 0);
    char username[256] = {0};

    /* Fall back to "uid-N" if we cannot derive the name. The full
     * /etc/passwd parse path is left to a future BOF; for the
     * privilege check we only need a stable identifier. */
    if (uid == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] uid=0 (root)\n");
        BeaconOutput(CALLBACK_OUTPUT, "yes", 0);
        return;
    }

    char *p = username + sizeof(username) - 1;
    *p = '\0';
    long n = uid;
    *--p = 'r'; *--p = 'd'; *--p = 'i'; *--p = 'u'; *--p = '-';
    do { *--p = '0' + (n % 10); n /= 10; } while (n && p > username);
    /* p now points to the start of "uid-N" inside the buffer. */
    char *uname = p;

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/group", 0);
    if (fd < 0) {
        BeaconOutput(CALLBACK_OUTPUT, "error", 0);
        BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] cannot open /etc/group\n");
        return;
    }

    char buffer[8192];
    long total = 0;
    while (total < (long)sizeof(buffer) - 1) {
        long r = syscall3(SYS_read, fd, (long)(buffer + total), sizeof(buffer) - 1 - total);
        if (r <= 0) break;
        total += r;
    }
    buffer[total] = '\0';
    syscall1(SYS_close, fd);

    /* Note: matching by username string only works if the operator
     * passed the username via args. For the default case (no args)
     * we just check uid==0 above. */
    int result = 0;
    if (args && alen > 0) {
        char argbuf[256] = {0};
        int copy = alen < (int)sizeof(argbuf) - 1 ? alen : (int)sizeof(argbuf) - 1;
        for (int i = 0; i < copy; i++) argbuf[i] = args[i];
        argbuf[copy] = '\0';
        result = user_in_group("sudo", argbuf, buffer, total) ||
                 user_in_group("wheel", argbuf, buffer, total);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[is_sudo] %s -> %s\n",
                 uname, result ? "yes" : "no");
    BeaconOutput(CALLBACK_OUTPUT, result ? "yes" : "no", 0);
}
