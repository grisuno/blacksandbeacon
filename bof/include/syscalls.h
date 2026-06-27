/*
 * syscalls.h - Direct x86_64 Linux syscall wrappers for BOFs.
 *
 * BOFs are compiled with -nostdlib, so they cannot link against
 * glibc. These inline wrappers let BOFs hit the kernel directly
 * with no libc dependency.
 *
 * Only the syscalls used by the current BOFs are declared here.
 * Add new ones as you need them.
 */
#ifndef BSB_BOF_SYSCALLS_H
#define BSB_BOF_SYSCALLS_H

#include <stddef.h>

/* Syscall numbers - x86_64 Linux ABI. */
#define SYS_read       0
#define SYS_write      1
#define SYS_open       2
#define SYS_close      3
#define SYS_stat       4
#define SYS_fstat      5
#define SYS_lseek      8
#define SYS_mmap       9
#define SYS_munmap     11
#define SYS_brk        12
#define SYS_ioctl      16
#define SYS_access     21
#define SYS_pipe       22
#define SYS_dup2       33
#define SYS_fork       57
#define SYS_execve     59
#define SYS_exit       60
#define SYS_wait4      61
#define SYS_getuid     102
#define SYS_getgid     104
#define SYS_geteuid    107
#define SYS_getegid    108
#define SYS_getpid     39
#define SYS_getppid    110
#define SYS_getpwnam_r 124
#define SYS_getpwuid_r 168
#define SYS_openat     257
#define SYS_clone      56

/* Special fd value meaning "current working directory". */
#define AT_FDCWD ((long)-100)

static inline long syscall0(long n) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall1(long n, long a1) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall2(long n, long a1, long a2) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* strlen - libc is not linked. */
static inline size_t bsf_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

/* strcmp - libc is not linked. Returns 0 on match. */
static inline int bsf_strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(const unsigned char *)a - *(const unsigned char *)b;
}

/* memcmp - libc is not linked. */
static inline int bsf_memcmp(const void *p1, const void *p2, size_t n) {
    const unsigned char *a = p1, *b = p2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    }
    return 0;
}

#endif /* BSB_BOF_SYSCALLS_H */
