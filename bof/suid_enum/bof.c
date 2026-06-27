/*
 * bof/suid_enum/bof.c
 *
 * Walk the filesystem and report every file with the SUID or SGID
 * bit set. These are the canonical privilege-escalation vectors on
 * Linux (GTFOBins-style).
 *
 * Why a BOF instead of `find / -perm -4000`:
 *   - No shell. The BOF cannot spawn a child process and does not
 *     have /usr/bin/find, so we walk the tree ourselves.
 *   - No libc getdents wrapper; we use SYS_getdents64 directly so
 *     the BOF stays -nostdlib-clean.
 *   - Output is reported through BeaconOutput line-by-line so the
 *     operator can grep the result for known GTFOBins payloads.
 *
 * Usage: `suid_enum:` (no args) or `suid_enum:/some/root` to scope
 * the walk to a directory.
 *
 * Build:
 *   make bof-suid_enum
 */
#include "beacon_api.h"
#include "syscalls.h"

/* getdents64 syscall number (x86_64) and the dirent layout. */
#define SYS_getdents64 217
#define SYS_lstat      6

/* d_type values we care about (from <dirent.h>). */
#define DT_UNKNOWN 0
#define DT_DIR     4
#define DT_LNK     10

/* Linux stat struct (matches the kernel ABI for x86_64). */
struct linux_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned int  st_mode;
    unsigned int  st_uid;
    unsigned int  st_gid;
    unsigned int  __pad0;
    unsigned long st_rdev;
    long          st_size;
    long          st_blksize;
    long          st_blocks;
    unsigned long st_atime;
    unsigned long st_atime_nsec;
    unsigned long st_mtime;
    unsigned long st_mtime_nsec;
    unsigned long st_ctime;
    unsigned long st_ctime_nsec;
    long          __unused[3];
};

/* getdents64 entry layout (kernel ABI). The d_reclen field tells
 * us the actual record size since names are variable length. */
struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

/* --- small helpers --- */

/* Append `s` to the line buffer at *pos. Returns 1 if a newline
 * was emitted, 0 if the buffer is full. The operator can keep
 * calling emit() and we will flush the buffer via BeaconOutput
 * once it fills up. */
static char  out_buf[1024];
static int   out_pos = 0;
static int   out_lines = 0;

static void flush_output(void) {
    if (out_pos > 0) {
        BeaconOutput(CALLBACK_OUTPUT, out_buf, out_pos);
        out_pos = 0;
    }
}

static void emit(const char *s) {
    /* Write to a small stack buffer first so a single hit does
     * not get chopped mid-line if out_buf is nearly full. */
    char tmp[512];
    int n = 0;
    while (s[n] && n < (int)sizeof(tmp) - 1) tmp[n] = s[n], n++;
    tmp[n] = '\0';

    /* If the line is longer than out_buf, emit it in chunks. */
    if (n >= (int)sizeof(out_buf)) {
        flush_output();
        BeaconOutput(CALLBACK_OUTPUT, tmp, n);
        out_lines++;
        return;
    }
    if (out_pos + n >= (int)sizeof(out_buf)) flush_output();
    for (int i = 0; i < n; i++) out_buf[out_pos++] = tmp[i];
    out_lines++;
}

/* Format `mode` (a st_mode value) into a 10-char permission
 * string, like ls -l does. */
static void format_mode(unsigned int mode, char *out) {
    out[0] = (mode & 0170000) == 0040000 ? 'd' :
             (mode & 0170000) == 0120000 ? 'l' :
             (mode & 0170000) == 0100000 ? '-' : '?';
    out[1] = (mode & 0400) ? 'r' : '-';
    out[2] = (mode & 0200) ? 'w' : '-';
    out[3] = (mode & 04000) ? 's' : (mode & 0100) ? 'x' : '-';
    out[4] = (mode & 040) ? 'r' : '-';
    out[5] = (mode & 020) ? 'w' : '-';
    out[6] = (mode & 02000) ? 's' : (mode & 010) ? 'x' : '-';
    out[7] = (mode & 04) ? 'r' : '-';
    out[8] = (mode & 02) ? 'w' : '-';
    out[9] = (mode & 020000) ? 't' : (mode & 01) ? 'x' : '-';
    out[10] = '\0';
}

/* --- recursive walk --- */

static char  path_buf[1024];
static int   path_len = 0;

static void path_reset(const char *root) {
    path_len = 0;
    while (root[path_len] && path_len < (int)sizeof(path_buf) - 1) {
        path_buf[path_len] = root[path_len];
        path_len++;
    }
    path_buf[path_len] = '\0';
}

static void path_append(const char *name) {
    /* Ensure trailing slash before the new component. */
    if (path_len > 0 && path_buf[path_len - 1] != '/') {
        if (path_len < (int)sizeof(path_buf) - 1) {
            path_buf[path_len++] = '/';
            path_buf[path_len] = '\0';
        }
    }
    while (*name && path_len < (int)sizeof(path_buf) - 1) {
        path_buf[path_len++] = *name++;
    }
    path_buf[path_len] = '\0';
}

static void path_trim_to(int len) {
    if (len < 0) len = 0;
    if (len > path_len) len = path_len;
    path_len = len;
    path_buf[path_len] = '\0';
}

/* Walk one directory, recursing into subdirectories. `depth`
 * bounds the recursion so a symlink loop cannot blow the stack. */
static void walk(int depth) {
    if (depth > 6) return;          /* -L 6 by default */
    if (path_len >= (int)sizeof(path_buf) - 256) return;

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)path_buf, 0x10000); /* O_RDONLY|O_DIRECTORY */
    if (fd < 0) return;

    char buf[4096];
    for (;;) {
        long n = syscall3(SYS_getdents64, fd, (long)buf, (long)sizeof(buf));
        if (n <= 0) break;

        long pos = 0;
        while (pos < n) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
            if (d->d_reclen == 0) break;
            const char *name = d->d_name;

            /* Skip . and .. and known-noisy mount points. */
            int skip = (name[0] == '.' &&
                        (name[1] == '\0' ||
                         (name[1] == '.' && name[2] == '\0')));
            if (!skip) skip = !bsf_strcmp(name, "proc") ||
                              !bsf_strcmp(name, "sys")  ||
                              !bsf_strcmp(name, "dev");
            if (!skip) {
                int saved = path_len;
                path_append(name);

                /* lstat the entry. lstat avoids following symlinks
                 * so a symlinked SUID file still shows up (and a
                 * symlink loop does not recurse forever). */
                struct linux_stat st;
                long r = syscall3(SYS_lstat, AT_FDCWD, (long)path_buf, (long)&st);
                if (r == 0) {
                    unsigned int m = st.st_mode;
                    int is_suid = (m & 04000) != 0;
                    int is_sgid = (m & 02000) != 0;
                    if (is_suid || is_sgid) {
                        char mode_str[11];
                        format_mode(m, mode_str);
                        /* line: mode owner size path */
                        char line[600];
                        int li = 0;
                        for (int i = 0; mode_str[i] && li < 580; i++) line[li++] = mode_str[i];
                        line[li++] = ' ';
                        /* uid/gid as decimal */
                        char num[24];
                        int nu = 0;
                        unsigned int v = st.st_uid;
                        if (v == 0) num[nu++] = '0';
                        else {
                            char tmp[12]; int tn = 0;
                            while (v) { tmp[tn++] = '0' + (v % 10); v /= 10; }
                            while (tn) num[nu++] = tmp[--tn];
                        }
                        num[nu] = '\0';
                        for (int i = 0; num[i] && li < 580; i++) line[li++] = num[i];
                        line[li++] = '/';
                        nu = 0; v = st.st_gid;
                        if (v == 0) num[nu++] = '0';
                        else {
                            char tmp[12]; int tn = 0;
                            while (v) { tmp[tn++] = '0' + (v % 10); v /= 10; }
                            while (tn) num[nu++] = tmp[--tn];
                        }
                        num[nu] = '\0';
                        for (int i = 0; num[i] && li < 580; i++) line[li++] = num[i];
                        line[li++] = ' ';
                        /* size (skip - just print path) */
                        for (int i = 0; path_buf[i] && li < 580; i++) line[li++] = path_buf[i];
                        line[li++] = '\n';
                        line[li] = '\0';
                        emit(line);
                    }

                    if (d->d_type == DT_DIR && (m & 0170000) == 0040000) {
                        walk(depth + 1);
                    }
                }

                path_trim_to(saved);
            }
            pos += d->d_reclen;
        }
    }
    syscall1(SYS_close, fd);
}

void go(char *args, int alen) {
    /* Default to walking the whole filesystem. Operator can scope
     * by passing a path as the arg. */
    const char *root = "/";
    if (args && alen > 0) {
        /* Use a static buffer; args is NUL-terminated by the loader. */
        static char argbuf[256];
        int copy = alen < (int)sizeof(argbuf) - 1 ? alen : (int)sizeof(argbuf) - 1;
        for (int i = 0; i < copy; i++) argbuf[i] = args[i];
        argbuf[copy] = '\0';
        if (argbuf[0] == '/') root = argbuf;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] scanning %s\n", root);
    path_reset(root);
    walk(0);
    flush_output();
    BeaconPrintf(CALLBACK_OUTPUT, "[suid_enum] done (%d entries)\n", out_lines);
}
