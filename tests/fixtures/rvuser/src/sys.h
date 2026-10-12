/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: FreeBSD riscv64 raw system calls for the freestanding fixtures.
 * Number in t0, arguments a0..a5, on return t0 = 1 flags an error and a0
 * holds the errno (lib/libsys/riscv/SYS.h). A successful call may modify a0, a1 and t0
 * (cpu_set_syscall_retval writes td_retval[1] to a1), so all three are asm outputs. */
#ifndef RVUSER_FIXTURE_SYS_H
#define RVUSER_FIXTURE_SYS_H

typedef unsigned long u64;
typedef long i64;

/* Numbers from FreeBSD sys/kern/syscalls.master; O_* from sys/sys/fcntl.h. */
enum {
    SYS_exit = 1, SYS_read = 3, SYS_write = 4, SYS_open = 5, SYS_close = 6, SYS_pread = 475,
    SYS_pwrite = 476, SYS_mmap = 477, SYS_lseek = 478, SYS_openat = 499, SYS_fstat = 551
};
enum { O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0x200, O_TRUNC = 0x400, AT_FDCWD = -100 };

/* Returns a0; *err is nonzero when the kernel set the error flag. */
static inline i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f, int *err)
{
    register i64 t0 __asm__("t0") = n;
    register i64 a0 __asm__("a0") = a;
    register i64 a1 __asm__("a1") = b; /* written back too: the second return value */
    register i64 a2 __asm__("a2") = c;
    register i64 a3 __asm__("a3") = d;
    register i64 a4 __asm__("a4") = e;
    register i64 a5 __asm__("a5") = f;
    __asm__ volatile("ecall"
                     : "+r"(t0), "+r"(a0), "+r"(a1)
                     : "r"(a2), "r"(a3), "r"(a4), "r"(a5)
                     : "memory");
    *err = (int)t0;
    return a0;
}

static inline i64 sys3(i64 n, i64 a, i64 b, i64 c, int *err)
{
    return sys6(n, a, b, c, 0, 0, 0, err);
}

static inline i64 sys4(i64 n, i64 a, i64 b, i64 c, i64 d, int *err)
{
    return sys6(n, a, b, c, d, 0, 0, err);
}

static inline void put(int fd, const char *s, u64 n)
{
    int err;
    sys3(SYS_write, fd, (i64)s, (i64)n, &err);
}

static inline u64 cstrlen(const char *s)
{
    u64 n = 0;
    while (s[n]) n++;
    return n;
}

static inline void puts_fd1(const char *s)
{
    put(1, s, cstrlen(s));
}


/* Decimal text of v into buf (room for 21 bytes); returns the length. */
static inline u64 fmt_u64(char *buf, u64 v)
{
    char tmp[21];
    u64 n = 0, len = 0;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) buf[len++] = tmp[--n];
    return len;
}

static inline void put_num(int fd, u64 v)
{
    char b[22];
    u64 n = fmt_u64(b, v);
    b[n++] = '\n';
    put(fd, b, n);
}
#endif
