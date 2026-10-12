/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Generates, evaluates and installs the fixed-result compiler
 *          child's seccomp allowlist. The allowlist is the measured
 *          syscall set of the worker and its GCC 14 driver, cc1 and as
 *          (plus the worker's socket and scratch calls); every other call
 *          fails EPERM. Network, ptrace, mount, namespaces, keyrings, BPF,
 *          userfaultfd, perf and io_uring are therefore refused; a foreign
 *          architecture or an x32 number kills the process. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_seccomp.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <sched.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__linux__) && defined(__x86_64__)
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#define FRS_SUPPORTED 1
#else
#define FRS_SUPPORTED 0
#endif

#define FRS_X32_BIT 0x40000000u
#define FRS_ARCH_X86_64 0xc000003eu /* AUDIT_ARCH_X86_64 */
#define FRS_EPERM 1u
#define FRS_ENOSYS 38u
/* clone(2) flags that would create a namespace. CLONE_NEWTIME (0x80) is
 * not among them: in clone(2) the low byte is the exit signal. */
#define FRS_CLONE_NS_MASK \
    ((uint32_t)(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | \
                CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET))
static_assert(FRS_CLONE_NS_MASK == 0x7e020000u, "x86-64 namespace clone flags");
#define FRS_PR_GET_SECCOMP 21u
#define FRS_PR_GET_NO_NEW_PRIVS 39u
#define FRS_TCGETS 0x5401u

/* Classic BPF opcodes (linux/bpf_common.h). */
#define FRS_LD_ABS 0x20u
#define FRS_JEQ 0x15u
#define FRS_JGE 0x35u
#define FRS_JSET 0x45u
#define FRS_RET 0x06u

enum frs_rule { FRS_PLAIN, FRS_CLONE, FRS_CLONE3, FRS_IOCTL, FRS_PRCTL };

struct frs_call {
    int nr;
    const char *name;
    enum frs_rule rule;
};

#if FRS_SUPPORTED
#define FRS_A(n) {SYS_##n, #n, FRS_PLAIN}
static const struct frs_call k_frs_calls[] = {
    /* process image, loader and memory */
    FRS_A(execve), FRS_A(brk), FRS_A(mmap), FRS_A(mprotect), FRS_A(munmap),
    FRS_A(mremap), FRS_A(madvise), FRS_A(arch_prctl), FRS_A(set_tid_address),
    FRS_A(set_robust_list), FRS_A(rseq), FRS_A(prlimit64), FRS_A(getrandom),
    FRS_A(futex), FRS_A(exit), FRS_A(exit_group), FRS_A(restart_syscall),
    /* files: the image is read-only; scratch is private */
    FRS_A(read), FRS_A(write), FRS_A(pread64), FRS_A(lseek), FRS_A(close),
    FRS_A(close_range), FRS_A(openat), FRS_A(newfstatat), FRS_A(fstat),
    FRS_A(statfs), FRS_A(fstatfs), FRS_A(access), FRS_A(faccessat2),
    FRS_A(readlink), FRS_A(getcwd), FRS_A(chdir), FRS_A(mkdir), FRS_A(rmdir),
    FRS_A(unlink), FRS_A(umask), FRS_A(fcntl), FRS_A(dup), FRS_A(dup2),
    /* signals, time, identity */
    FRS_A(rt_sigaction), FRS_A(rt_sigprocmask), FRS_A(rt_sigreturn),
    FRS_A(clock_gettime), FRS_A(clock_nanosleep), FRS_A(nanosleep),
    FRS_A(getrusage), FRS_A(sysinfo), FRS_A(getpid), FRS_A(getppid),
    FRS_A(gettid), FRS_A(getuid), FRS_A(geteuid), FRS_A(getgid),
    FRS_A(getegid), FRS_A(getresuid), FRS_A(getresgid), FRS_A(getgroups),
    /* children: the driver spawns cc1 and as; the worker waits and kills */
    FRS_A(wait4), FRS_A(setpgid), FRS_A(kill), FRS_A(tgkill),
    /* the launcher's inherited SEQPACKET socket, never a new one */
    FRS_A(poll), FRS_A(ppoll), FRS_A(recvfrom), FRS_A(recvmsg),
    FRS_A(sendmsg), FRS_A(getsockopt),
    {SYS_clone, "clone", FRS_CLONE},
    {SYS_clone3, "clone3", FRS_CLONE3},
    {SYS_ioctl, "ioctl", FRS_IOCTL},
    {SYS_prctl, "prctl", FRS_PRCTL},
};
#undef FRS_A
#define FRS_CALLS (sizeof(k_frs_calls) / sizeof(*k_frs_calls))
#else
static const struct frs_call k_frs_calls[1] = {{0, "", FRS_PLAIN}};
#define FRS_CALLS 0u
#endif

static const char *const k_frs_rule_names[] = {
    "allow", "allow_without_namespace_flags", "enosys_for_clone_fallback",
    "allow_tcgets_only", "allow_get_no_new_privs_and_get_seccomp_only"
};

size_t zcl_frs_allowed_count(void) { return FRS_CALLS; }

bool zcl_frs_allowed(size_t i, int *nr, const char **name, const char **rule)
{
    if (i >= FRS_CALLS) return false;
    *nr = k_frs_calls[i].nr;
    *name = k_frs_calls[i].name;
    *rule = k_frs_rule_names[k_frs_calls[i].rule];
    return true;
}

/* ── program assembly ──────────────────────────────────────────────── */

struct frs_insn {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};

struct frs_prog {
    struct frs_insn v[ZCL_FRS_MAX_INSNS];
    size_t n;
    bool overflow;
};

static size_t frs_emit(struct frs_prog *p, uint16_t code, uint8_t jt,
                       uint8_t jf, uint32_t k)
{
    if (p->n == ZCL_FRS_MAX_INSNS) { p->overflow = true; return p->n; }
    p->v[p->n] = (struct frs_insn){code, jt, jf, k};
    return p->n++;
}

/* Points the jt of instruction `at` at instruction `target`. */
static void frs_patch(struct frs_prog *p, size_t at, size_t target)
{
    size_t d = target - at - 1u;
    if (target <= at || d > 255u) { p->overflow = true; return; }
    p->v[at].jt = (uint8_t)d;
}

/* ld args[i] low word; returns nothing, program position advances. */
static void frs_ld_arg(struct frs_prog *p, unsigned i)
{
    frs_emit(p, FRS_LD_ABS, 0, 0, 16u + 8u * i);
}

/* Two allowed values of a low argument word, else EPERM. */
static void frs_arg_pair(struct frs_prog *p, unsigned arg, uint32_t a,
                         uint32_t b)
{
    frs_ld_arg(p, arg);
    frs_emit(p, FRS_JEQ, 2, 0, a);
    frs_emit(p, FRS_JEQ, 1, 0, b);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ERRNO | FRS_EPERM);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ALLOW);
}

static void frs_assemble(struct frs_prog *p)
{
    size_t jumps[ZCL_FRS_MAX_INSNS];
    frs_emit(p, FRS_LD_ABS, 0, 0, 4u); /* arch */
    frs_emit(p, FRS_JEQ, 1, 0, FRS_ARCH_X86_64);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_KILL_PROCESS);
    frs_emit(p, FRS_LD_ABS, 0, 0, 0u); /* nr */
    frs_emit(p, FRS_JGE, 0, 1, FRS_X32_BIT);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_KILL_PROCESS);
    for (size_t i = 0; i < FRS_CALLS; i++)
        jumps[i] = frs_emit(p, FRS_JEQ, 0, 0, (uint32_t)k_frs_calls[i].nr);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ERRNO | FRS_EPERM);
    size_t allow = frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ALLOW);
    size_t enosys = frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ERRNO | FRS_ENOSYS);
    size_t clone = p->n;
    frs_ld_arg(p, 0);
    frs_emit(p, FRS_JSET, 0, 1, FRS_CLONE_NS_MASK);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ERRNO | FRS_EPERM);
    frs_emit(p, FRS_RET, 0, 0, ZCL_FRS_ALLOW);
    size_t ioctl = p->n;
    frs_arg_pair(p, 1, FRS_TCGETS, FRS_TCGETS);
    size_t prctl = p->n;
    frs_arg_pair(p, 0, FRS_PR_GET_NO_NEW_PRIVS, FRS_PR_GET_SECCOMP);
    const size_t targets[] = {allow, clone, enosys, ioctl, prctl};
    for (size_t i = 0; i < FRS_CALLS; i++)
        frs_patch(p, jumps[i], targets[k_frs_calls[i].rule]);
}

bool zcl_frs_build(uint8_t out[ZCL_FRS_MAX_BYTES], size_t *len,
                   const char **why)
{
    *len = 0;
    if (!FRS_SUPPORTED) { *why = "seccomp_arch_unsupported"; return false; }
    static struct frs_prog p;
    memset(&p, 0, sizeof(p));
    frs_assemble(&p);
    if (p.overflow) { *why = "seccomp_program_limit"; return false; }
    for (size_t i = 0; i < p.n; i++) {
        uint8_t *b = out + i * ZCL_FRS_INSN_BYTES;
        zcl_write_u16_le(b, p.v[i].code);
        b[2] = p.v[i].jt;
        b[3] = p.v[i].jf;
        zcl_write_u32_le(b + 4, p.v[i].k);
    }
    *len = p.n * ZCL_FRS_INSN_BYTES;
    return true;
}

bool zcl_frs_sha3(uint8_t digest[32], size_t *insns, const char **why)
{
    uint8_t prog[ZCL_FRS_MAX_BYTES];
    size_t len = 0;
    if (!zcl_frs_build(prog, &len, why)) return false;
    zcl_sha3_256(prog, len, digest);
    *insns = len / ZCL_FRS_INSN_BYTES;
    return true;
}

/* ── reference evaluator ───────────────────────────────────────────── */

static bool frs_load(const struct zcl_frs_data *d, uint32_t off, uint32_t *a)
{
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    zcl_write_i32_le(raw, d->nr);
    zcl_write_u32_le(raw + 4, d->arch);
    zcl_write_u64_le(raw + 8, d->ip);
    for (unsigned i = 0; i < 6; i++) zcl_write_u64_le(raw + 16 + 8 * i, d->args[i]);
    if (off % 4u || off > 60u) return false;
    *a = zcl_read_u32_le(raw + off);
    return true;
}

uint32_t zcl_frs_eval(const uint8_t *prog, size_t len,
                      const struct zcl_frs_data *d)
{
    size_t n = len / ZCL_FRS_INSN_BYTES, pc = 0;
    uint32_t a = 0;
    if (len % ZCL_FRS_INSN_BYTES || n == 0 || n > ZCL_FRS_MAX_INSNS)
        return ZCL_FRS_KILL_PROCESS;
    while (pc < n) {
        const uint8_t *b = prog + pc * ZCL_FRS_INSN_BYTES;
        uint16_t code = zcl_read_u16_le(b);
        uint32_t k = zcl_read_u32_le(b + 4);
        pc++;
        bool taken;
        switch (code) {
        case FRS_LD_ABS: if (!frs_load(d, k, &a)) return ZCL_FRS_KILL_PROCESS;
                         continue;
        case FRS_RET: return k;
        case FRS_JEQ: taken = a == k; break;
        case FRS_JGE: taken = a >= k; break;
        case FRS_JSET: taken = (a & k) != 0; break;
        default: return ZCL_FRS_KILL_PROCESS;
        }
        pc += taken ? b[2] : b[3];
    }
    return ZCL_FRS_KILL_PROCESS;
}

bool zcl_frs_install(const uint8_t *prog, size_t len, const char **why)
{
#if FRS_SUPPORTED
    static struct sock_filter filter[ZCL_FRS_MAX_INSNS];
    size_t n = len / ZCL_FRS_INSN_BYTES;
    if (len % ZCL_FRS_INSN_BYTES || n == 0 || n > ZCL_FRS_MAX_INSNS) {
        *why = "seccomp_program_malformed";
        return false;
    }
    memcpy(filter, prog, len); /* sock_filter is the same LE record */
    struct sock_fprog fprog = {.len = (unsigned short)n, .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        *why = "seccomp_no_new_privs_failed";
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0) {
        *why = "seccomp_install_failed";
        return false;
    }
    return true;
#else
    (void)prog;
    (void)len;
    *why = "seccomp_arch_unsupported";
    return false;
#endif
}
