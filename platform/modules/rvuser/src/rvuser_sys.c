/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: table-driven FreeBSD riscv64 system call layer. Convention, from
 * FreeBSD sys/riscv/riscv/trap.c cpu_fetch_syscall_args and vm_machdep.c
 * cpu_set_syscall_retval, lib/libsys/riscv/SYS.h and cerror.S:
 *   number in t0 (x5, NOT a7); arguments in a0..a5; success: t0 = 0 and
 *   a0 (a1) hold the result; failure: t0 = 1 and a0 holds the errno.
 * Numbers come from sys/kern/syscalls.master. The host clock is never read. */
#include "rvuser_internal.h"
#include "base/serialize_le.h"
#include "base/log_macros.h"
#include <string.h>

enum {
    SYS_exit = 1, SYS_read = 3, SYS_write = 4, SYS_open = 5, SYS_close = 6, SYS_getpid = 20,
    SYS_munmap = 73, SYS_mprotect = 74, SYS_clock_gettime = 232, SYS_issetugid = 253,
    SYS_sigprocmask = 340, SYS_sigaction = 416, SYS_thr_self = 432, SYS_mmap = 477,
    SYS_pread = 475, SYS_pwrite = 476, SYS_lseek = 478, SYS_openat = 499, SYS_fstat = 551
};
enum { E_BADF = 9, E_NOMEM = 12, E_ACCES = 13, E_FAULT = 14, E_INVAL = 22, E_NOSYS = 78 };
enum { MAP_FIXED = 0x10, MAP_ANON = 0x1000 };
enum { SIG_BLOCK = 1, SIG_UNBLOCK = 2, SIG_SETMASK = 3, SIGKILL = 9, SIGSTOP = 17 };
#define T0_REG 5u
#define A0_REG 10u

#define RU_PID 1u
#define RU_TID 100001u
#define SIGSET_BYTES 16u

typedef int (*ru_handler)(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);

struct ru_sysent {
    uint32_t number;
    ru_handler fn;
};

uint8_t *ru_guest_ptr(const struct ru_proc *p, uint64_t addr, uint64_t len)
{
    if (addr < p->mem.base) return NULL;
    uint64_t off = addr - p->mem.base;
    if (off > p->mem.size || len > p->mem.size - off) return NULL;
    return p->mem.bytes + off;
}

static int ru_fd_open(const struct ru_proc *p, uint64_t fd)
{
    return fd <= 2u && !(p->closed_fds & (1u << fd));
}

static int sys_exit(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    p->exited = 1;
    p->exit_status = (int)(a[0] & 0xffu);
    return 0;
}

static int sys_read(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    if (a[0] >= RU_FD_FIRST) return ru_sys_read_fd(p, a, ret);
    if (a[0] != 0 || !ru_fd_open(p, a[0])) return E_BADF;
    uint64_t n = a[2] > RU_IO_CHUNK ? RU_IO_CHUNK : a[2];
    /* FreeBSD never touches the buffer of a zero-length read or write (no copyin/copyout, so no
     * EFAULT): it returns 0. No host pointer is formed for n == 0. */
    uint8_t *buf = n ? ru_guest_ptr(p, a[1], n) : NULL;
    if (n && !buf) return E_FAULT;
    size_t got = (n && p->io->read) ? p->io->read(p->io->ctx, buf, (size_t)n) : 0;
    *ret = got > n ? n : got;
    return 0;
}

static int sys_write(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    if (a[0] >= RU_FD_FIRST) return ru_sys_write_fd(p, a, ret);
    if (a[0] < 1u || a[0] > 2u || !ru_fd_open(p, a[0]) || !p->io->write) return E_BADF;
    uint64_t n = a[2] > RU_IO_CHUNK ? RU_IO_CHUNK : a[2];
    const uint8_t *buf = n ? ru_guest_ptr(p, a[1], n) : NULL;
    if (n && !buf) return E_FAULT;
    size_t put = n ? p->io->write(p->io->ctx, (int)a[0], buf, (size_t)n) : 0;
    *ret = put > n ? n : put;
    return 0;
}

static int sys_close(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    if (a[0] >= RU_FD_FIRST) return ru_sys_close_fd(p, a, ret);
    if (!ru_fd_open(p, a[0])) return E_BADF;
    p->closed_fds |= 1u << a[0];
    return 0;
}

static int sys_getpid(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)p; (void)a;
    *ret = RU_PID;
    return 0;
}

static int sys_issetugid(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)p; (void)a;
    *ret = 0;
    return 0;
}

static int sys_thr_self(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    uint8_t *id = ru_guest_ptr(p, a[0], 8);
    if (!id) return E_FAULT;
    zcl_write_u64_le(id, RU_TID);
    return 0;
}

static int sys_clock_gettime(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    uint8_t *tp = ru_guest_ptr(p, a[1], 16);
    uint64_t ns = 0;
    if (!tp) return E_FAULT;
    if (!p->io->clock_ns || p->io->clock_ns(p->io->ctx, (uint32_t)a[0], &ns) != 0) return E_INVAL;
    zcl_write_u64_le(tp, ns / 1000000000ull);
    zcl_write_u64_le(tp + 8, ns % 1000000000ull);
    return 0;
}

static int sys_mmap(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    uint64_t flags = (uint32_t)a[3];
    if (!(flags & MAP_ANON) || (flags & MAP_FIXED) || (int32_t)a[4] != -1 || a[1] == 0)
        return E_INVAL;
    if (a[1] > p->heap_end - p->heap_cur) return E_NOMEM;
    uint64_t len = (a[1] + RU_PAGE - 1u) & ~(RU_PAGE - 1u);
    if (len > p->heap_end - p->heap_cur) return E_NOMEM;
    *ret = p->heap_cur;
    p->heap_cur += len;
    return 0;
}

static int sys_munmap(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    if ((a[0] & (RU_PAGE - 1u)) || a[1] == 0 || a[0] < p->heap_base || a[0] > p->heap_cur ||
        a[1] > p->heap_cur - a[0])
        return E_INVAL;
    return 0;
}

static int sys_mprotect(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    if ((a[0] & (RU_PAGE - 1u)) || !ru_guest_ptr(p, a[0], a[1])) return E_NOMEM;
    return 0;
}

static int ru_mask_update(struct ru_proc *p, uint64_t how, const uint8_t *set)
{
    uint64_t in[2] = {zcl_read_u64_le(set), zcl_read_u64_le(set + 8)};
    for (unsigned i = 0; i < 2; i++) {
        if (how == SIG_BLOCK) p->sigmask[i] |= in[i];
        else if (how == SIG_UNBLOCK) p->sigmask[i] &= ~in[i];
        else p->sigmask[i] = in[i];
    }
    return 0;
}

static int sys_sigprocmask(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    const uint8_t *set = a[1] ? ru_guest_ptr(p, a[1], SIGSET_BYTES) : NULL;
    uint8_t *old = a[2] ? ru_guest_ptr(p, a[2], SIGSET_BYTES) : NULL;
    if ((a[1] && !set) || (a[2] && !old)) return E_FAULT;
    if (set && a[0] != SIG_BLOCK && a[0] != SIG_UNBLOCK && a[0] != SIG_SETMASK) return E_INVAL;
    if (old) {
        zcl_write_u64_le(old, p->sigmask[0]);
        zcl_write_u64_le(old + 8, p->sigmask[1]);
    }
    return set ? ru_mask_update(p, a[0], set) : 0;
}

static int sys_sigaction(struct ru_proc *p, const uint64_t a[6], uint64_t *ret)
{
    (void)ret;
    if (a[0] == 0 || a[0] > RU_NSIG) return E_INVAL;
    uint8_t *act = a[1] ? ru_guest_ptr(p, a[1], RU_SIGACT_BYTES) : NULL;
    uint8_t *old = a[2] ? ru_guest_ptr(p, a[2], RU_SIGACT_BYTES) : NULL;
    if ((a[1] && !act) || (a[2] && !old)) return E_FAULT;
    if (act && (a[0] == SIGKILL || a[0] == SIGSTOP)) return E_INVAL;
    if (old) memcpy(old, p->sigact[a[0]], RU_SIGACT_BYTES);
    if (act) memcpy(p->sigact[a[0]], act, RU_SIGACT_BYTES);
    return 0;
}

static const struct ru_sysent ru_sysent[] = {
    {SYS_exit, sys_exit},
    {SYS_read, sys_read},
    {SYS_write, sys_write},
    {SYS_open, ru_sys_open},
    {SYS_close, sys_close},
    {SYS_getpid, sys_getpid},
    {SYS_munmap, sys_munmap},
    {SYS_mprotect, sys_mprotect},
    {SYS_clock_gettime, sys_clock_gettime},
    {SYS_issetugid, sys_issetugid},
    {SYS_sigprocmask, sys_sigprocmask},
    {SYS_sigaction, sys_sigaction},
    {SYS_thr_self, sys_thr_self},
    {SYS_mmap, sys_mmap},
    {SYS_openat, ru_sys_openat},
    {SYS_pread, ru_sys_pread},
    {SYS_pwrite, ru_sys_pwrite},
    {SYS_lseek, ru_sys_lseek},
    {SYS_fstat, ru_sys_fstat},
};

static void ru_note_unknown(struct ru_proc *p, uint64_t number)
{
    for (unsigned i = 0; i < p->unknown_count; i++)
        if (p->unknown_seen[i] == (uint32_t)number) return;
    if (p->unknown_count >= RU_UNKNOWN_LOG_MAX) return;
    p->unknown_seen[p->unknown_count++] = (uint32_t)number;
    LOG_WARN("rvuser", "unknown system call %llu answered ENOSYS", (unsigned long long)number);
}

static const struct ru_sysent *ru_lookup(uint64_t number)
{
    for (size_t i = 0; i < sizeof(ru_sysent) / sizeof(ru_sysent[0]); i++)
        if (ru_sysent[i].number == number) return &ru_sysent[i];
    return NULL;
}

#ifdef ZCL_TESTING
/* Red-twin hook (see rvuser.h): 0 means the FreeBSD register. Test builds only. */
static unsigned ru_test_syscall_reg;
void rvuser_test_set_syscall_reg(unsigned reg)
{
    ru_test_syscall_reg = reg > 31u ? 0 : reg;
}
#define RU_NUMBER_REG (ru_test_syscall_reg ? ru_test_syscall_reg : T0_REG)
#else
#define RU_NUMBER_REG T0_REG
#endif

void ru_syscall(struct ru_proc *p)
{
    unsigned reg = RU_NUMBER_REG;
    uint64_t number = p->hart.x[reg & 31u], ret = 0;
    uint64_t args[6];
    memcpy(args, &p->hart.x[A0_REG], sizeof(args));
    const struct ru_sysent *e = ru_lookup(number);
    int err = E_NOSYS;
    if (e) err = e->fn(p, args, &ret);
    else ru_note_unknown(p, number);
    p->hart.x[T0_REG] = err ? 1u : 0u;
    p->hart.x[A0_REG] = err ? (uint64_t)err : ret;
    if (!err) p->hart.x[A0_REG + 1u] = 0;
}
