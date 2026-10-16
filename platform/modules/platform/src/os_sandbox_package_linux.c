/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Linux package-confinement selection over the Landlock backend. */

#define _GNU_SOURCE
#include "platform/os_sandbox.h"
#include <sys/syscall.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#if defined(__has_include)
#  if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) \
       && __has_include(<linux/audit.h>)
#    define PKG_HAVE_SECCOMP 1
#    include <linux/seccomp.h>
#    include <linux/filter.h>
#    include <linux/audit.h>
#  endif
#endif

enum os_sandbox_package_confinement
os_sandbox_package_confinement(void)
{
    return os_sandbox_landlock_abi() >= 1
        ? OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP
        : OS_SANDBOX_PACKAGE_CONFINEMENT_NONE;
}

const char *os_sandbox_package_confinement_name(
    enum os_sandbox_package_confinement confinement)
{
    switch (confinement) {
    case OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP:
        return "landlock+seccomp";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT:
        return "seatbelt";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_NONE:
    default:
        return "none";
    }
}

struct zcl_result os_sandbox_package_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    if (os_sandbox_package_confinement() ==
        OS_SANDBOX_PACKAGE_CONFINEMENT_NONE)
        return ZCL_ERR(OS_SANDBOX_ERR_CONFINEMENT_UNAVAILABLE,
                       "package confinement is unavailable");
    return os_sandbox_landlock_restrict(rules, n_rules);
}

struct zcl_result os_sandbox_package_leaf_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    ZCL_CHECK(os_sandbox_package_restrict(rules, n_rules));
    static const int denied[] = {
        SYS_clone, SYS_setsid, SYS_setpgid, SYS_kill, SYS_tkill, SYS_tgkill,
        SYS_rt_sigqueueinfo, SYS_rt_tgsigqueueinfo,
#ifdef SYS_pidfd_send_signal
        SYS_pidfd_send_signal,
#endif
#ifdef SYS_pidfd_getfd
        SYS_pidfd_getfd,
#endif
#ifdef SYS_clone3
        SYS_clone3,
#endif
#ifdef SYS_fork
        SYS_fork,
#endif
#ifdef SYS_vfork
        SYS_vfork,
#endif
    };
    return os_sandbox_seccomp_deny(denied, sizeof(denied) / sizeof(denied[0]), false);
}

/* kill(2) guard. Job control needs kill of the shell's own children and jobs,
 * so kill stays allowed, but this STACKED filter answers EPERM for the
 * targets that would reach beyond the cage: pid 0, pid -1, the supervisor
 * (the parent at entry) and its process group, each as +N and -N. The low 32
 * bits of args[0] are compared (kill takes a pid_t). Layout for n compares:
 * 4 arch/nr, 1 kill test, 1 load, n compares, ALLOW, EPERM. An unrelated
 * same-uid positive pid is NOT distinguishable by seccomp: that residual is
 * documented in os_sandbox.h. */
#define PKG_GUARD_N 6u
struct zcl_result os_sandbox_seccomp_guard_signals(void)
{
#ifndef PKG_HAVE_SECCOMP
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "seccomp headers absent at build time");
#else
    pid_t sup = getppid();
    pid_t sup_pg = getpgid(sup);
    const uint32_t vals[PKG_GUARD_N] = {
        0u, 0xffffffffu, (uint32_t)sup, (uint32_t)-sup,
        (uint32_t)(sup_pg > 0 ? sup_pg : 0),
        (uint32_t)(sup_pg > 0 ? -sup_pg : 0) };
    struct sock_filter f[8 + PKG_GUARD_N];
    size_t k = 0;
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, arch));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64, 1, 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0x80000000U);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        (uint32_t)__NR_kill, 0, PKG_GUARD_N + 1u);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, args[0]));
    for (size_t i = 0; i < PKG_GUARD_N; i++)
        f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
            vals[i], (uint8_t)(PKG_GUARD_N - i), 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    long r = syscall(__NR_seccomp, (long)SECCOMP_SET_MODE_FILTER,
                     (long)SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (r != 0 && errno == ENOSYS)
        r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (r != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "kill guard filter install failed errno=%d (%s)",
                       errno, strerror(errno));
    return ZCL_OK;
#endif
}
