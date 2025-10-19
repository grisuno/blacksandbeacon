// is_sudo.c — LazyOwn RedTeam BOF (Linux/x64)
// gcc -c -nostdlib -fPIC -m64 -O2 is_sudo.c -o is_sudo.x64.o
#define NULL ((void*)0)
#define CALLBACK_OUTPUT 0

// Tipos
typedef unsigned long size_t;
typedef long ssize_t;

// Símbolos del beacon
extern void BeaconPrintf(int, const char*, ...);
extern void BeaconOutput(int, const char*, int);

// Syscalls
#define SYS_openat 257
#define SYS_read   0
#define SYS_close  3
#define SYS_getuid 102
#define SYS_getpwuid_r 168  // opcional, pero no lo usamos
#define AT_FDCWD   -100

// Wrappers
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

// strcmp mínimo (necesario para comparar strings)
static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Obtener username desde /etc/passwd (sin libc)
static int get_username_from_uid(long uid, char *buf, int buf_size) {
    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/passwd", 0);
    if (fd < 0) return 0;

    char buffer[4096];
    long total = 0;
    while (total < 4095) {
        long n = syscall3(SYS_read, fd, (long)(buffer + total), 4095 - total);
        if (n <= 0) break;
        total += n;
    }
    buffer[total] = '\0';
    syscall3(SYS_close, fd, 0, 0);

    char *line = buffer;
    while (line < buffer + total) {
        char *next = line;
        while (next < buffer + total && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

        char *name = line;
        char *p = line;
        int col = 0;
        long parsed_uid = -1;

        while (*p && col < 3) {
            if (*p == ':') {
                if (col == 0) *p = '\0';
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
            int len = 0;
            while (name[len] && len < buf_size - 1) {
                buf[len] = name[len];
                len++;
            }
            buf[len] = '\0';
            return len;
        }
        line = next + 1;
    }
    return 0;
}

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[IS_SUDO] 🕵️‍♂️ Verificando pertenencia a sudo/wheel...\n");

    long uid = syscall1(SYS_getuid, 0);
    char username[256] = {0};

    if (!get_username_from_uid(uid, username, sizeof(username))) {
        // Fallback: usar UID como nombre
        char *p = username + 255;
        *p = '\0';
        long n = uid;
        do { *--p = '0' + (n % 10); n /= 10; } while (n);
        while (*p) { *(username + (p - (username + 255))) = *p; p++; }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[IS_SUDO] Usuario: %s (UID=%ld)\n", username, uid);

    // Abrir /etc/group
    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/group", 0);
    if (fd < 0) {
        BeaconOutput(CALLBACK_OUTPUT, "error:/etc/group", 17);
        BeaconPrintf(CALLBACK_OUTPUT, "[IS_SUDO] ❌ No se puede leer /etc/group\n");
        return;
    }

    char buffer[8192];
    long total = 0;
    while (total < 8191) {
        long n = syscall3(SYS_read, fd, (long)(buffer + total), 8191 - total);
        if (n <= 0) break;
        total += n;
    }
    buffer[total] = '\0';
    syscall3(SYS_close, fd, 0, 0);

    // Buscar líneas de "sudo" o "wheel" que contengan el username
    char *line = buffer;
    int is_sudo = 0;
    const char *target_groups[] = {"sudo", "wheel", NULL};
    int i;

    while (line < buffer + total) {
        char *next = line;
        while (next < buffer + total && *next != '\n') next++;
        if (*next == '\n') *next = '\0';

        // group_name:password:gid:user1,user2,...
        char *group_name = line;
        char *p = line;
        int col = 0;
        char *user_list = NULL;

        while (*p) {
            if (*p == ':') {
                if (col == 0) {
                    *p = '\0'; // fin de group_name
                } else if (col == 2) {
                    *p = '\0'; // fin de gid
                    user_list = p + 1;
                }
                col++;
            }
            if (col > 2) break;
            p++;
        }

        // ¿Es un grupo objetivo?
        for (i = 0; target_groups[i]; i++) {
            if (strcmp(group_name, target_groups[i]) == 0 && user_list && user_list[0]) {
                // Buscar username en la lista (puede ser "user" o "user,other")
                char *u = user_list;
                while (*u) {
                    char *end = u;
                    while (*end && *end != ',') end++;
                    char saved = *end;
                    *end = '\0';
                    if (strcmp(u, username) == 0) {
                        is_sudo = 1;
                        *end = saved;
                        break;
                    }
                    *end = saved;
                    if (!saved) break;
                    u = end + 1;
                }
                if (is_sudo) break;
            }
        }
        if (is_sudo) break;
        line = next + 1;
    }

    if (is_sudo) {
        BeaconOutput(CALLBACK_OUTPUT, "yes", 3);
        BeaconPrintf(CALLBACK_OUTPUT, "[IS_SUDO] ✅ %s pertenece a sudo/wheel\n", username);
    } else {
        BeaconOutput(CALLBACK_OUTPUT, "no", 2);
        BeaconPrintf(CALLBACK_OUTPUT, "[IS_SUDO] ❌ %s NO tiene privilegios sudo\n", username);
    }
}
