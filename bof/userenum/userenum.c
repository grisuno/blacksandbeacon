// is_sudo.c — LazyOwn RedTeam BOF (Linux/x64)
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


// strcmp mínimo (necesario para comparar strings)
static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[ENUM_USERS] 🕵️‍♂️ Enumerando usuarios y privilegios sudo/wheel...\n");

    // --- Paso 1: Leer /etc/group y extraer miembros de sudo/wheel ---
    char sudo_members[4096] = {0};  // buffer para concatenar "user1,user2,..."
    char wheel_members[4096] = {0};

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/group", 0);
    if (fd >= 0) {
        char gbuf[8192];
        long total = 0;
        while (total < 8191) {
            long n = syscall3(SYS_read, fd, (long)(gbuf + total), 8191 - total);
            if (n <= 0) break;
            total += n;
        }
        gbuf[total] = '\0';
        syscall3(SYS_close, fd, 0, 0);

        char *line = gbuf;
        while (line < gbuf + total) {
            char *next = line;
            while (next < gbuf + total && *next != '\n') next++;
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

            if (user_list && user_list[0]) {
                if (strcmp(group_name, "sudo") == 0) {
                    // Copiar lista a sudo_members
                    char *src = user_list;
                    char *dst = sudo_members;
                    while (*src && (dst - sudo_members) < sizeof(sudo_members) - 1) *dst++ = *src++;
                    *dst = '\0';
                } else if (strcmp(group_name, "wheel") == 0) {
                    char *src = user_list;
                    char *dst = wheel_members;
                    while (*src && (dst - wheel_members) < sizeof(wheel_members) - 1) *dst++ = *src++;
                    *dst = '\0';
                }
            }
            line = next + 1;
        }
    }

    // --- Paso 2: Leer /etc/passwd y verificar cada usuario ---
    fd = syscall3(SYS_openat, AT_FDCWD, (long)"/etc/passwd", 0);
    if (fd < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[ENUM_USERS] ❌ No se puede leer /etc/passwd\n");
        return;
    }

    char pbuf[8192];
    long total = 0;
    while (total < 8191) {
        long n = syscall3(SYS_read, fd, (long)(pbuf + total), 8191 - total);
        if (n <= 0) break;
        total += n;
    }
    pbuf[total] = '\0';
    syscall3(SYS_close, fd, 0, 0);

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
                if (col == 0) *p = '\0'; // termina username
                col++;
            }
            if (col > 0) break;
            p++;
        }

        if (username[0]) {
            int is_priv = 0;

            // Buscar username en sudo_members
            char *list = sudo_members;
            while (*list) {
                char *end = list;
                while (*end && *end != ',') end++;
                char saved = *end;
                *end = '\0';
                if (strcmp(list, username) == 0) { is_priv = 1; }
                *end = saved;
                if (!saved) break;
                list = end + 1;
            }

            if (!is_priv) {
                list = wheel_members;
                while (*list) {
                    char *end = list;
                    while (*end && *end != ',') end++;
                    char saved = *end;
                    *end = '\0';
                    if (strcmp(list, username) == 0) { is_priv = 1; }
                    *end = saved;
                    if (!saved) break;
                    list = end + 1;
                }
            }

            BeaconPrintf(CALLBACK_OUTPUT, "[ENUM_USERS] %s %s\n",
                username,
                is_priv ? "✅ (sudo/wheel)" : "❌"
            );
        }
        line = next + 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[ENUM_USERS] 🔚 Finalizado.\n");
}
