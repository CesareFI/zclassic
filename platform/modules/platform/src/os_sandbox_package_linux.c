/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Linux package-confinement selection over the Landlock backend. */

#include "platform/os_sandbox.h"
#include <sys/syscall.h>
#include <stdio.h>

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
