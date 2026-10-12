/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: execution-tier picker. exec_tier_select is pure, exec_tier_host_facts
 * probes the host, exec_tier_format only formats a decision into a line. */
#include "platform/exec_tier.h"
#include "platform/os_sandbox.h"
#include "base/log_macros.h"

#include <stdio.h>
#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

#define KVM_DEVICE_NODE "/dev/kvm"
#define YAMA_PTRACE_SCOPE_PATH "/proc/sys/kernel/yama/ptrace_scope"

static const char *const k_tier_names[] = {
    [EXEC_TIER_NONE] = "none",
    [EXEC_TIER_NATIVE] = "native",
    [EXEC_TIER_HWVIRT] = "hwvirt",
    [EXEC_TIER_EMULATOR] = "emulator",
};

static const char *const k_reject_names[EXEC_TIER_REJECT_COUNT] = {
    [EXEC_TIER_REJECT_NONE] = "none",
    [EXEC_TIER_REJECT_NULL_FACTS] = "null_facts",
    [EXEC_TIER_REJECT_MANIFEST_CAPABILITY] = "manifest_capability_unprovided",
    [EXEC_TIER_REJECT_NATIVE_NO_IMAGE] = "no_native_image",
    [EXEC_TIER_REJECT_NATIVE_NO_BACKEND] = "no_native_backend",
    [EXEC_TIER_REJECT_NATIVE_NO_NEW_PRIVS] = "no_new_privs_unavailable",
    [EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABSENT] = "landlock_absent",
    [EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABI_LOW] = "landlock_abi_below_minimum",
    [EXEC_TIER_REJECT_NATIVE_SECCOMP_UNAVAILABLE] = "seccomp_unavailable",
    [EXEC_TIER_REJECT_NATIVE_ARCH_UNSUPPORTED] = "native_arch_unsupported",
    [EXEC_TIER_REJECT_NATIVE_EXEC_CONFIRM_UNAVAILABLE] = "native_exec_confirm_unavailable",
    [EXEC_TIER_REJECT_HWVIRT_NO_BACKEND] = "no_hwvirt_backend",
    [EXEC_TIER_REJECT_HWVIRT_NO_DEVICE] = "no_hwvirt_device",
    [EXEC_TIER_REJECT_HWVIRT_NOT_OPENABLE] = "hwvirt_device_not_openable",
    [EXEC_TIER_REJECT_HWVIRT_NO_USER_GRANT] = "no_user_grant",
    [EXEC_TIER_REJECT_HWVIRT_NO_GUEST_IMAGE] = "hwvirt_no_guest_image",
    [EXEC_TIER_REJECT_EMULATOR_RUNNER_ABSENT] = "emulator_runner_absent",
    [EXEC_TIER_REJECT_EMULATOR_NO_MANIFEST_BRIDGE] = "emulator_no_manifest_bridge",
    [EXEC_TIER_REJECT_EMULATOR_NO_RISCV64_IMAGE] = "no_riscv64_image",
};

const char *exec_tier_name(enum exec_tier tier)
{
    if ((unsigned)tier >= sizeof(k_tier_names) / sizeof(k_tier_names[0]))
        return "unknown";
    return k_tier_names[tier];
}

const char *exec_tier_reject_name(enum exec_tier_reject reason)
{
    if ((unsigned)reason >= EXEC_TIER_REJECT_COUNT || !k_reject_names[reason])
        return "unknown";
    return k_reject_names[reason];
}

static enum exec_tier_reject reject_native(const struct exec_tier_facts *f)
{
    if (!f->app.has_native_image) return EXEC_TIER_REJECT_NATIVE_NO_IMAGE;
    if (!f->native.backend_built) return EXEC_TIER_REJECT_NATIVE_NO_BACKEND;
    if (!f->native.arch_supported) return EXEC_TIER_REJECT_NATIVE_ARCH_UNSUPPORTED;
    if (!f->native.no_new_privs) return EXEC_TIER_REJECT_NATIVE_NO_NEW_PRIVS;
    if (f->native.landlock_abi < 1) return EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABSENT;
    if (f->native.landlock_abi < f->app.min_landlock_abi)
        return EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABI_LOW;
    if (!f->native.seccomp) return EXEC_TIER_REJECT_NATIVE_SECCOMP_UNAVAILABLE;
    if (!f->native.exec_confirm)
        return EXEC_TIER_REJECT_NATIVE_EXEC_CONFIRM_UNAVAILABLE;
    return EXEC_TIER_REJECT_NONE;
}

static enum exec_tier_reject reject_hwvirt(const struct exec_tier_facts *f)
{
    if (!f->hwvirt.backend_built) return EXEC_TIER_REJECT_HWVIRT_NO_BACKEND;
    if (!f->hwvirt.device_present) return EXEC_TIER_REJECT_HWVIRT_NO_DEVICE;
    if (!f->hwvirt.device_openable) return EXEC_TIER_REJECT_HWVIRT_NOT_OPENABLE;
    if (!f->hwvirt.user_grant) return EXEC_TIER_REJECT_HWVIRT_NO_USER_GRANT;
    if (!f->hwvirt.guest_image_ready) return EXEC_TIER_REJECT_HWVIRT_NO_GUEST_IMAGE;
    return EXEC_TIER_REJECT_NONE;
}

static enum exec_tier_reject reject_emulator(const struct exec_tier_facts *f)
{
    if (!f->emulator.runner_linked)
        return EXEC_TIER_REJECT_EMULATOR_RUNNER_ABSENT;
    if (!f->emulator.manifest_bridge)
        return EXEC_TIER_REJECT_EMULATOR_NO_MANIFEST_BRIDGE;
    if (!f->app.has_riscv64_image) return EXEC_TIER_REJECT_EMULATOR_NO_RISCV64_IMAGE;
    return EXEC_TIER_REJECT_NONE;
}

struct exec_tier_decision exec_tier_select(const struct exec_tier_facts *f)
{
    struct exec_tier_decision d = { .tier = EXEC_TIER_NONE };
    if (!f) {
        d.native = d.hwvirt = d.emulator = EXEC_TIER_REJECT_NULL_FACTS;
        return d;
    }
    d.exec_confirm_hint = f->native.exec_confirm;
    if (f->app.needs_network) {
        d.native = d.hwvirt = d.emulator = EXEC_TIER_REJECT_MANIFEST_CAPABILITY;
        return d;
    }
    d.native = reject_native(f);
    if (d.native == EXEC_TIER_REJECT_NONE) {
        d.tier = EXEC_TIER_NATIVE;
        return d;
    }
    d.hwvirt = reject_hwvirt(f);
    if (d.hwvirt == EXEC_TIER_REJECT_NONE) {
        d.tier = EXEC_TIER_HWVIRT;
        return d;
    }
    d.emulator = reject_emulator(f);
    if (d.emulator == EXEC_TIER_REJECT_NONE) d.tier = EXEC_TIER_EMULATOR;
    return d;
}

#if defined(__linux__)
/* Yama ptrace_scope 0 or 1 lets the runner confirm exec through PTRACE_TRACEME;
 * 2 or 3 forbids it. An absent file (Yama not built) allows it. Reads at most
 * 8 bytes: one digit, optionally followed by a newline. Any other read error or
 * content refuses. */
static bool yama_allows_traceme(void)
{
    int fd = open(YAMA_PTRACE_SCOPE_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT;
    char buf[8];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n < 1 || n > 2) return false;
    if (n == 2 && buf[1] != '\n') return false;
    return buf[0] == '0' || buf[0] == '1';
}
#endif

struct exec_tier_facts exec_tier_host_facts(void)
{
    struct exec_tier_facts f = { 0 };
#if defined(__linux__)
    /* os_sandbox_probe_caps() forks one short-lived probe child (user-namespace
     * unshare) and leaves this process unchanged. */
    struct os_sandbox_caps caps = os_sandbox_probe_caps();
    f.native.backend_built = true;
    f.native.landlock_abi = caps.landlock_abi;
    f.native.seccomp = caps.seccomp;
    /* The native runner's seccomp arch check accepts only x86_64 Linux, so
     * arch_supported is true only when compiled for that target. */
#if defined(__x86_64__)
    f.native.arch_supported = true;
#endif
    /* exec_confirm is a HINT: necessary but not sufficient. The runner confirms
     * exec through PTRACE_TRACEME, which Yama ptrace_scope 2 or 3 forbids, but
     * seccomp or another LSM can still deny it. Read-only file read; there is
     * no ptrace probe. The runner's own typed exec-confirm-unavailable refusal
     * stays authoritative. */
    f.native.exec_confirm = yama_allows_traceme();
    /* native.no_new_privs means "the kernel supports PR_SET_NO_NEW_PRIVS",
     * not "the flag is set": this is a get-only prctl (never PR_SET), and the
     * launcher must still set the flag in the child. 0 or 1 = supported. */
    f.native.no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) >= 0;
    /* access(R_OK|W_OK) only approximates openability: an LSM, ACL or device
     * cgroup can still deny the real open, so the launcher must treat an open
     * failure as a named refusal. */
    f.hwvirt.device_present = access(KVM_DEVICE_NODE, F_OK) == 0;
    f.hwvirt.device_openable =
        f.hwvirt.device_present && access(KVM_DEVICE_NODE, R_OK | W_OK) == 0;
#endif
    /* hwvirt.backend_built stays false until a KVM/HVF run backend is built
     * and linked. Native stays false off Linux until a Seatbelt/Windows
     * resident backend lands. The runner owner flips the two emulator facts
     * below to true when the riscv64 runner is linked and the manifest bridge
     * (same grants, limits and timeout as the native runner) exists. */
    f.hwvirt.backend_built = false;
    /* hwvirt.guest_image_ready is set by the virtualization backend owner once a
     * guest image for the app can be provided; constant false until then. */
    f.hwvirt.guest_image_ready = false;
    f.emulator.runner_linked = false;
    f.emulator.manifest_bridge = false;
    return f;
}

bool exec_tier_format(const struct exec_tier_decision *d, char *out, size_t n)
{
    if (!d || !out || n == 0) LOG_FAIL("exec_tier", "format: null argument");
    int w = snprintf(out, n, "tier=%s native=%s hwvirt=%s emulator=%s exec_confirm=%s",
                     exec_tier_name(d->tier), exec_tier_reject_name(d->native),
                     exec_tier_reject_name(d->hwvirt),
                     exec_tier_reject_name(d->emulator),
                     d->exec_confirm_hint ? "hint_ok" : "hint_blocked");
    if (w < 0 || (size_t)w >= n) {
        out[0] = '\0';
        LOG_FAIL("exec_tier", "format: buffer of %zu bytes too small", n);
    }
    return true;
}
