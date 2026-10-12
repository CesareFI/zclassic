/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * exec_tier — pick WHICH confining tier may run an app.
 *
 * Fallback chain (owner plan): (1) a native process confined by the OS
 * sandbox, about full speed; (2) hardware virtualization, only with a user
 * grant; (3) a RISC-V emulator that needs nothing, the failsafe. If no
 * confining tier can run the app it does NOT run: there is no unconfined
 * tier and no override input.
 *
 * exec_tier_select() is pure: it reads a facts struct and has no side effects.
 * exec_tier_host_facts() probes the host: it forks one short-lived probe child
 * (os_sandbox_probe_caps), makes one access(2) check on /dev/kvm and one
 * prctl(PR_GET_NO_NEW_PRIVS) get. It runs no app.
 * exec_tier_format() only formats a decision into a line.
 * A decision is NOT execution authority: it only names the tier a later,
 * separately authorised launcher may try.
 * This selector is NOT launch qualification: it binds no manifest identity,
 * grants or limits. The picker must be called before exec; there is no
 * fallback after a start or an uncertain launch, and that no-retry-after-start
 * rule is enforced by the caller, not here.
 * native.exec_confirm is a hint derived from Yama ptrace_scope: necessary, not
 * sufficient (seccomp or another LSM can still deny PTRACE_TRACEME). There is
 * no ptrace probe; the runner's own typed exec-confirm-unavailable refusal
 * stays authoritative.
 */
#ifndef ZCL_PLATFORM_EXEC_TIER_H
#define ZCL_PLATFORM_EXEC_TIER_H

#include <stdbool.h>
#include <stddef.h>

enum exec_tier {
    EXEC_TIER_NONE = 0,
    EXEC_TIER_NATIVE,
    EXEC_TIER_HWVIRT,
    EXEC_TIER_EMULATOR,
};

/* One stable value per reason a tier is rejected. */
enum exec_tier_reject {
    EXEC_TIER_REJECT_NONE = 0,              /* accepted, or not considered */
    EXEC_TIER_REJECT_NULL_FACTS,
    EXEC_TIER_REJECT_MANIFEST_CAPABILITY,   /* no tier provides it         */
    EXEC_TIER_REJECT_NATIVE_NO_IMAGE,
    EXEC_TIER_REJECT_NATIVE_NO_BACKEND,     /* host OS has no backend yet  */
    EXEC_TIER_REJECT_NATIVE_NO_NEW_PRIVS,
    EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABSENT,
    EXEC_TIER_REJECT_NATIVE_LANDLOCK_ABI_LOW,
    EXEC_TIER_REJECT_NATIVE_SECCOMP_UNAVAILABLE,
    EXEC_TIER_REJECT_NATIVE_ARCH_UNSUPPORTED,
    EXEC_TIER_REJECT_NATIVE_EXEC_CONFIRM_UNAVAILABLE,
    EXEC_TIER_REJECT_HWVIRT_NO_BACKEND,
    EXEC_TIER_REJECT_HWVIRT_NO_DEVICE,
    EXEC_TIER_REJECT_HWVIRT_NOT_OPENABLE,
    EXEC_TIER_REJECT_HWVIRT_NO_USER_GRANT,
    EXEC_TIER_REJECT_HWVIRT_NO_GUEST_IMAGE, /* checked last in the hwvirt order */
    EXEC_TIER_REJECT_EMULATOR_RUNNER_ABSENT,
    EXEC_TIER_REJECT_EMULATOR_NO_MANIFEST_BRIDGE,
    EXEC_TIER_REJECT_EMULATOR_NO_RISCV64_IMAGE,
    EXEC_TIER_REJECT_COUNT
};

struct exec_tier_facts {
    struct { bool backend_built; bool no_new_privs; int landlock_abi;
             bool seccomp; bool arch_supported; bool exec_confirm; } native;
    struct { bool backend_built; bool device_present; bool device_openable;
             bool user_grant; bool guest_image_ready; } hwvirt;
    /* runner_linked: the user-mode riscv64 runner is linked into this binary.
     * manifest_bridge: the bridge that applies the same grants, limits and
     * timeout as the native runner exists. The emulator tier is selectable only
     * when runner_linked AND manifest_bridge AND app.has_riscv64_image; until
     * then selecting it is a typed refusal, never a run. */
    struct { bool runner_linked; bool manifest_bridge; } emulator;
    /* needs_network: the manifest asks for a network channel; no tier
     * provides one, so it is rejected for every tier (fail closed). */
    struct { int min_landlock_abi; bool has_native_image;
             bool has_riscv64_image; bool needs_network; } app;
};

struct exec_tier_decision {
    enum exec_tier tier;
    enum exec_tier_reject native, hwvirt, emulator;
    bool exec_confirm_hint;   /* facts.native.exec_confirm, for the format line */
};

const char *exec_tier_name(enum exec_tier tier);
const char *exec_tier_reject_name(enum exec_tier_reject reason);

/* Native, then hwvirt, then emulator; the first tier with no reject reason
 * wins. Tiers tried before the winner carry their reason, tiers after it
 * carry none. NULL facts or no qualifying tier gives EXEC_TIER_NONE with all
 * three reasons set. hwvirt.guest_image_ready is set by the virtualization
 * backend owner (host facts leave it false). */
struct exec_tier_decision exec_tier_select(const struct exec_tier_facts *f);

/* Host part only (native, hwvirt, emulator); app fields zero, user_grant
 * false (the caller supplies it). Runs the probes listed in the file header;
 * the calling process's own state is unchanged. */
struct exec_tier_facts exec_tier_host_facts(void);

/* One line: tier=none native=landlock_absent hwvirt=no_user_grant
 * emulator=emulator_runner_absent exec_confirm=hint_ok|hint_blocked
 * Returns false (and writes nothing useful) when the buffer is too small. */
bool exec_tier_format(const struct exec_tier_decision *d, char *out, size_t n);

#endif /* ZCL_PLATFORM_EXEC_TIER_H */
