/*
 * bof/userenum/bof.c
 *
 * Enumerate users from /etc/passwd and mark which ones are in
 * the sudo or wheel group.
 *
 * Build:
 *   make bof-userenum
 */
#include "beacon_api.h"
#include "syscalls.h"

/* Copy members of a target group out of /etc/group into outbuf.
 * Returns number of bytes written (excluding the trailing NUL). */
static int copy_group_members(const char *group, const char *filebuf, long filesize,
                              char *outbuf, int outsize) {
    int written = 0;
    char *line = (char *)filebuf;
    while (line < filebuf + filesize) {
        char *next = line;
        while (next < filebuf + filesize && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

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
            while (*user_list && written < outsize - 1) {
                outbuf[written++] = *user_list++;
            }
            outbuf[written] = '\0';
            return written;
        }
        line = next + 1;
    }
    if (outsize > 0) outbuf[0] = '\0';
    return 0;
}

static int user_in_member_list(const char *username, const char *members) {
    while (*members) {
        const char *end = members;
        while (*end && *end != ',') end++;
        int saved = *end;
        int match = !bsf_strcmp(members, username);
        if (saved == '\0') {
            if (match) return 1;
            break;
        }
        if (match) return 1;
        members = end + 1;
    }
    return 0;
}

void go(char *args, int alen) {
    (void)args;
    (void)alen;

    char sudo_members[4096] = {0};
    char wheel_members[4096] = {0};

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/group", 0);
    if (fd >= 0) {
        char gbuf[8192];
        long total = 0;
        while (total < (long)sizeof(gbuf) - 1) {
            long n = syscall3(SYS_read, fd, (long)(gbuf + total),
                              sizeof(gbuf) - 1 - total);
            if (n <= 0) break;
            total += n;
        }
        gbuf[total] = '\0';
        syscall1(SYS_close, fd);
        copy_group_members("sudo", gbuf, total, sudo_members, sizeof(sudo_members));
        copy_group_members("wheel", gbuf, total, wheel_members, sizeof(wheel_members));
    }

    fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/passwd", 0);
    if (fd < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[userenum] cannot open /etc/passwd\n");
        return;
    }

    char pbuf[8192];
    long total = 0;
    while (total < (long)sizeof(pbuf) - 1) {
        long n = syscall3(SYS_read, fd, (long)(pbuf + total),
                          sizeof(pbuf) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    pbuf[total] = '\0';
    syscall1(SYS_close, fd);

    char *line = pbuf;
    while (line < pbuf + total) {
        char *next = line;
        while (next < pbuf + total && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

        char *username = line;
        char *p = line;
        int col = 0;
        while (*p) {
            if (*p == ':') {
                if (col == 0) *p = '\0';
                col++;
            }
            if (col > 0) break;
            p++;
        }

        if (username[0]) {
            int priv = user_in_member_list(username, sudo_members) ||
                       user_in_member_list(username, wheel_members);
            BeaconPrintf(CALLBACK_OUTPUT, "[userenum] %s %s\n",
                         username, priv ? "priv" : "user");
        }
        line = next + 1;
    }
}
