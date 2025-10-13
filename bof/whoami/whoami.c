// whoami.c — LazyOwn RedTeam BOF (Linux/x64)
#define NULL ((void*)0)
#define CALLBACK_OUTPUT 0

// Tipos
typedef unsigned long size_t;
typedef long ssize_t;

// Símbolos del beacon
extern void BeaconPrintf(int, const char*, ...);
extern void BeaconOutput(int, const char*, int);

// Números de syscall (x86_64 Linux)
#define SYS_openat 257
#define SYS_read   0
#define SYS_close  3
#define SYS_getuid 102
#define AT_FDCWD   -100

// Syscall wrappers
static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall1(long n, long a1) {
    long ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 🚀 Iniciando...\n");

    long uid = syscall1(SYS_getuid, 0);
    if (uid == 0) {
        BeaconOutput(CALLBACK_OUTPUT, "root", 4);
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ✅ root\n");
        return;
    }

    // openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/passwd", 0);
    if (fd < 0) {
        // Fallback: devolver UID como string
        char buf[16];
        char *p = buf + 15;
        *p = '\0';
        long n = uid;
        do {
            *--p = '0' + (n % 10);
            n /= 10;
        } while (n);
        BeaconOutput(CALLBACK_OUTPUT, p, buf + 15 - p);
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ⚠️ /etc/passwd no accesible\n");
        return;
    }

    char buffer[4096];
    long total = 0;
    while (total < 4095) {
        long n = syscall3(SYS_read, fd, (long)(buffer + total), 4095 - total);
        if (n <= 0) break;
        total += n;
    }
    buffer[total] = '\0';
    syscall3(SYS_close, fd, 0, 0);

    // Parsear /etc/passwd
    char *line = buffer;
    while (line < buffer + total) {
        char *next = line;
        while (next < buffer + total && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

        // name:passwd:uid:...
        char *name = line;
        char *p = line;
        int col = 0;
        long parsed_uid = -1;

        while (*p && col < 3) {
            if (*p == ':') {
                if (col == 0) *p = '\0'; // fin de name
                else if (col == 2) {
                    *p = '\0';
                    parsed_uid = 0;
                    char *u = p + 1;
                    while (*u >= '0' && *u <= '9') {
                        parsed_uid = parsed_uid * 10 + (*u - '0');
                        u++;
                    }
                }
                col++;
            }
            p++;
        }

        if (parsed_uid == uid && name[0]) {
            BeaconOutput(CALLBACK_OUTPUT, name, 0);
            BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ✅ %s\n", name);
            return;
        }

        line = next + 1;
    }

    // Fallback final: UID
    char buf[16];
    char *p = buf + 15;
    *p = '\0';
    long n = uid;
    do {
        *--p = '0' + (n % 10);
        n /= 10;
    } while (n);
    BeaconOutput(CALLBACK_OUTPUT, p, buf + 15 - p);
    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ⚠️ Usuario no encontrado\n");
}
