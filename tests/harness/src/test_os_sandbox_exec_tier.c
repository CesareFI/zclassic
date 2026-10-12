/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: table and exhaustive tests of the pure execution-tier picker; run from test_os_sandbox.
 * min_landlock_abi values below 1 behave as 0: the minimum adds no reject, and
 * only landlock_abi < 1 (landlock absent) does. */
#include "test/test_core.h"
#include "platform/exec_tier.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define ET_CHECK(name, expr) do { \
    if (!(expr)) { printf("exec_tier: FAIL %s\n", (name)); failures++; } \
} while (0)

#define R(x) EXEC_TIER_REJECT_##x
#define T(x) EXEC_TIER_##x

/* A full Linux sandbox host with an app that has every image. */
static struct exec_tier_facts et_full_linux(void)
{
    struct exec_tier_facts f = { 0 };
    f.native.backend_built = true;
    f.native.no_new_privs = true;
    f.native.landlock_abi = 3;
    f.native.seccomp = true;
    f.native.arch_supported = true;
    f.native.exec_confirm = true;
    f.app.min_landlock_abi = 1;
    f.app.has_native_image = true;
    f.app.has_riscv64_image = true;
    return f;
}

static void et_hw_ok(struct exec_tier_facts *f)
{
    f->hwvirt.backend_built = true;
    f->hwvirt.device_present = true;
    f->hwvirt.device_openable = true;
    f->hwvirt.user_grant = true;
    f->hwvirt.guest_image_ready = true;
}

static bool et_is(const struct exec_tier_decision *d, enum exec_tier t,
                  enum exec_tier_reject n, enum exec_tier_reject h,
                  enum exec_tier_reject e)
{
    return d->tier == t && d->native == n && d->hwvirt == h && d->emulator == e;
}

struct et_row {
    const char *name;
    void (*mutate)(struct exec_tier_facts *);
    enum exec_tier tier;
    enum exec_tier_reject n, h, e;
};

static void m_none(struct exec_tier_facts *f) { (void)f; }
static void m_nnp(struct exec_tier_facts *f) { f->native.no_new_privs = false; }
static void m_ll0(struct exec_tier_facts *f) { f->native.landlock_abi = 0; }
static void m_llneg(struct exec_tier_facts *f) { f->native.landlock_abi = -1; }
static void m_llmin(struct exec_tier_facts *f) { f->app.min_landlock_abi = 4; }
static void m_sec(struct exec_tier_facts *f) { f->native.seccomp = false; }
static void m_nobk(struct exec_tier_facts *f) { f->native.backend_built = false; }
static void m_arch(struct exec_tier_facts *f) { f->native.arch_supported = false; }
static void m_confirm(struct exec_tier_facts *f) { f->native.exec_confirm = false; }
static void m_noimg(struct exec_tier_facts *f) { f->app.has_native_image = false; }
static void m_net(struct exec_tier_facts *f) { f->app.needs_network = true; }
static void m_net_all(struct exec_tier_facts *f)
{ m_net(f); et_hw_ok(f); f->emulator.runner_linked = true; f->emulator.manifest_bridge = true; f->app.has_riscv64_image = true; }
static void m_llmin_neg(struct exec_tier_facts *f) { f->app.min_landlock_abi = -1; }
static void m_llmin_neg_ll0(struct exec_tier_facts *f)
{ f->app.min_landlock_abi = -1; f->native.landlock_abi = 0; }
static void m_hw(struct exec_tier_facts *f) { m_nnp(f); et_hw_ok(f); }
static void m_hw_nogrant(struct exec_tier_facts *f)
{ m_nnp(f); et_hw_ok(f); f->hwvirt.user_grant = false; }
static void m_hw_grant_only(struct exec_tier_facts *f)
{ m_nnp(f); f->hwvirt.backend_built = true; f->hwvirt.user_grant = true; }
static void m_hw_noopen(struct exec_tier_facts *f)
{ m_nnp(f); et_hw_ok(f); f->hwvirt.device_openable = false; }
static void m_hw_noguest(struct exec_tier_facts *f)
{ m_nnp(f); et_hw_ok(f); f->hwvirt.guest_image_ready = false; }
static void m_hw_noguest_emu(struct exec_tier_facts *f)
{ m_hw_noguest(f); f->emulator.runner_linked = true; f->emulator.manifest_bridge = true; }
static void m_hw_nobk(struct exec_tier_facts *f)
{ m_nnp(f); et_hw_ok(f); f->hwvirt.backend_built = false; }
static void m_emu(struct exec_tier_facts *f)
{ m_nnp(f); f->emulator.runner_linked = true; f->emulator.manifest_bridge = true; }
static void m_emu_noimg(struct exec_tier_facts *f)
{ m_emu(f); f->app.has_riscv64_image = false; }
static void m_emu_runner_only(struct exec_tier_facts *f)
{ m_nnp(f); f->emulator.runner_linked = true; }
static void m_emu_runner_only_noimg(struct exec_tier_facts *f)
{ m_emu_runner_only(f); f->app.has_riscv64_image = false; }
static void m_nnp_noimg(struct exec_tier_facts *f)
{ m_nnp(f); f->app.has_riscv64_image = false; }
static void m_hw_and_emu(struct exec_tier_facts *f) { m_hw(f); f->emulator.runner_linked = true; f->emulator.manifest_bridge = true; }
static void m_native_and_hw(struct exec_tier_facts *f) { et_hw_ok(f); f->emulator.runner_linked = true; f->emulator.manifest_bridge = true; }

static const struct et_row k_rows[] = {
    { "native wins on full sandbox", m_none, T(NATIVE), R(NONE), R(NONE), R(NONE) },
    { "native wins even with hw and emulator ready", m_native_and_hw, T(NATIVE), R(NONE), R(NONE), R(NONE) },
    { "no_new_privs missing", m_nnp, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "landlock abi 0", m_ll0, T(NONE), R(NATIVE_LANDLOCK_ABSENT), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "landlock abi -1", m_llneg, T(NONE), R(NATIVE_LANDLOCK_ABSENT), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "landlock below manifest minimum", m_llmin, T(NONE), R(NATIVE_LANDLOCK_ABI_LOW), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "seccomp missing", m_sec, T(NONE), R(NATIVE_SECCOMP_UNAVAILABLE), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "no native backend", m_nobk, T(NONE), R(NATIVE_NO_BACKEND), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "native arch unsupported", m_arch, T(NONE), R(NATIVE_ARCH_UNSUPPORTED), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "exec confirm unavailable (yama ptrace_scope 2 or 3)", m_confirm, T(NONE), R(NATIVE_EXEC_CONFIRM_UNAVAILABLE), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "no native image", m_noimg, T(NONE), R(NATIVE_NO_IMAGE), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "needs network: no tier provides it", m_net, T(NONE), R(MANIFEST_CAPABILITY), R(MANIFEST_CAPABILITY), R(MANIFEST_CAPABILITY) },
    { "needs network refused even with all three tiers ready", m_net_all, T(NONE), R(MANIFEST_CAPABILITY), R(MANIFEST_CAPABILITY), R(MANIFEST_CAPABILITY) },
    { "landlock minimum -1 behaves as 0: native wins", m_llmin_neg, T(NATIVE), R(NONE), R(NONE), R(NONE) },
    { "landlock minimum -1 with abi 0: landlock absent, not abi low", m_llmin_neg_ll0, T(NONE), R(NATIVE_LANDLOCK_ABSENT), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "hwvirt wins when native defective", m_hw, T(HWVIRT), R(NATIVE_NO_NEW_PRIVS), R(NONE), R(NONE) },
    { "hwvirt without grant refused", m_hw_nogrant, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_USER_GRANT), R(EMULATOR_RUNNER_ABSENT) },
    { "grant alone without device refused", m_hw_grant_only, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_DEVICE), R(EMULATOR_RUNNER_ABSENT) },
    { "device not openable refused", m_hw_noopen, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NOT_OPENABLE), R(EMULATOR_RUNNER_ABSENT) },
    { "hwvirt backend not built refused", m_hw_nobk, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "hwvirt guest image not ready: rejected, falls through, emulator not ready", m_hw_noguest, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_GUEST_IMAGE), R(EMULATOR_RUNNER_ABSENT) },
    { "hwvirt guest image not ready: rejected, falls through to emulator", m_hw_noguest_emu, T(EMULATOR), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_GUEST_IMAGE), R(NONE) },
    { "emulator wins as failsafe", m_emu, T(EMULATOR), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(NONE) },
    { "emulator needs a riscv64 image", m_emu_noimg, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(EMULATOR_NO_RISCV64_IMAGE) },
    { "hwvirt before emulator, emulator carries none", m_hw_and_emu, T(HWVIRT), R(NATIVE_NO_NEW_PRIVS), R(NONE), R(NONE) },
    { "emulator runner absent wins over bridge absent and image absent", m_nnp_noimg, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(EMULATOR_RUNNER_ABSENT) },
    { "emulator bridge absent wins over image absent", m_emu_runner_only_noimg, T(NONE), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(EMULATOR_NO_MANIFEST_BRIDGE) },
    { "all three emulator facts true, native and hwvirt unavailable: emulator selected", m_emu, T(EMULATOR), R(NATIVE_NO_NEW_PRIVS), R(HWVIRT_NO_BACKEND), R(NONE) },
};

static int et_table(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof k_rows / sizeof k_rows[0]; i++) {
        struct exec_tier_facts f = et_full_linux();
        k_rows[i].mutate(&f);
        struct exec_tier_decision d = exec_tier_select(&f);
        ET_CHECK(k_rows[i].name, et_is(&d, k_rows[i].tier, k_rows[i].n,
                                       k_rows[i].h, k_rows[i].e));
    }
    return failures;
}

static int et_nothing_and_null(void)
{
    int failures = 0;
    struct exec_tier_facts z = { 0 };
    struct exec_tier_decision d = exec_tier_select(&z);
    ET_CHECK("zero facts: none with three named reasons",
             et_is(&d, T(NONE), R(NATIVE_NO_IMAGE), R(HWVIRT_NO_BACKEND),
                   R(EMULATOR_RUNNER_ABSENT)));
    d = exec_tier_select(NULL);
    ET_CHECK("NULL facts: none with dedicated reason",
             et_is(&d, T(NONE), R(NULL_FACTS), R(NULL_FACTS), R(NULL_FACTS)));
    return failures;
}

/* Independent oracle for the exhaustive loop. Each tier's reason is the first
 * failing condition of a hand-written priority list (the order the spec
 * fixes); no exec_tier.c helper is called. */
static enum exec_tier_reject o_native_reason(const struct exec_tier_facts *f)
{
    if (!f->app.has_native_image) return R(NATIVE_NO_IMAGE);
    if (!f->native.backend_built) return R(NATIVE_NO_BACKEND);
    if (!f->native.arch_supported) return R(NATIVE_ARCH_UNSUPPORTED);
    if (!f->native.no_new_privs) return R(NATIVE_NO_NEW_PRIVS);
    if (f->native.landlock_abi < 1) return R(NATIVE_LANDLOCK_ABSENT);
    if (f->native.landlock_abi < f->app.min_landlock_abi) return R(NATIVE_LANDLOCK_ABI_LOW);
    if (!f->native.seccomp) return R(NATIVE_SECCOMP_UNAVAILABLE);
    if (!f->native.exec_confirm) return R(NATIVE_EXEC_CONFIRM_UNAVAILABLE);
    return R(NONE);
}
static enum exec_tier_reject o_hw_reason(const struct exec_tier_facts *f)
{
    if (!f->hwvirt.backend_built) return R(HWVIRT_NO_BACKEND);
    if (!f->hwvirt.device_present) return R(HWVIRT_NO_DEVICE);
    if (!f->hwvirt.device_openable) return R(HWVIRT_NOT_OPENABLE);
    if (!f->hwvirt.user_grant) return R(HWVIRT_NO_USER_GRANT);
    if (!f->hwvirt.guest_image_ready) return R(HWVIRT_NO_GUEST_IMAGE);
    return R(NONE);
}
static enum exec_tier_reject o_emu_reason(const struct exec_tier_facts *f)
{
    if (!f->emulator.runner_linked) return R(EMULATOR_RUNNER_ABSENT);
    if (!f->emulator.manifest_bridge) return R(EMULATOR_NO_MANIFEST_BRIDGE);
    if (!f->app.has_riscv64_image) return R(EMULATOR_NO_RISCV64_IMAGE);
    return R(NONE);
}

static void et_unpack(struct exec_tier_facts *f, unsigned bits, int abi, int min)
{
    memset(f, 0, sizeof *f);
    f->native.backend_built = bits & 1u;
    f->native.no_new_privs = bits & 2u;
    f->native.seccomp = bits & 4u;
    f->native.arch_supported = bits & 2048u;
    f->native.exec_confirm = bits & 4096u;
    f->hwvirt.backend_built = bits & 8u;
    f->hwvirt.device_present = bits & 16u;
    f->hwvirt.device_openable = bits & 32u;
    f->hwvirt.user_grant = bits & 64u;
    f->emulator.runner_linked = bits & 128u;
    f->emulator.manifest_bridge = bits & 8192u;
    f->hwvirt.guest_image_ready = bits & 16384u;
    f->app.has_native_image = bits & 256u;
    f->app.has_riscv64_image = bits & 512u;
    f->app.needs_network = bits & 1024u;
    f->native.landlock_abi = abi;
    f->app.min_landlock_abi = min;
}

/* Expected decision, exact: the tiers before the winner carry their reason,
 * the winner and every later tier carry none; NONE carries all three. A
 * manifest that needs the network refuses every tier with the manifest reason. */
static struct exec_tier_decision o_expected(const struct exec_tier_facts *f)
{
    struct exec_tier_decision e = { T(NONE), R(NONE), R(NONE), R(NONE), f->native.exec_confirm };
    if (f->app.needs_network) {
        e.native = e.hwvirt = e.emulator = R(MANIFEST_CAPABILITY);
        return e;
    }
    e.native = o_native_reason(f);
    if (e.native == R(NONE)) { e.tier = T(NATIVE); return e; }
    e.hwvirt = o_hw_reason(f);
    if (e.hwvirt == R(NONE)) { e.tier = T(HWVIRT); return e; }
    e.emulator = o_emu_reason(f);
    if (e.emulator == R(NONE)) e.tier = T(EMULATOR);
    return e;
}

static bool et_consistent(const struct exec_tier_facts *f,
                          const struct exec_tier_decision *d)
{
    struct exec_tier_decision e = o_expected(f);
    return et_is(d, e.tier, e.native, e.hwvirt, e.emulator) &&
           d->exec_confirm_hint == e.exec_confirm_hint;
}

static int et_exhaustive(void)
{
    int failures = 0;
    static const int abis[] = { INT_MIN, -1, 0, 1, 3, INT_MAX };
    static const int mins[] = { INT_MIN, -1, 0, 1, 3, INT_MAX };
    unsigned bad = 0, rows = 0;
    for (unsigned bits = 0; bits < (1u << 15); bits++)
        for (size_t a = 0; a < sizeof abis / sizeof abis[0]; a++)
            for (size_t m = 0; m < sizeof mins / sizeof mins[0]; m++) {
                struct exec_tier_facts f;
                et_unpack(&f, bits, abis[a], mins[m]);
                struct exec_tier_decision d = exec_tier_select(&f);
                rows++;
                if (!et_consistent(&f, &d)) bad++;
            }
    printf("exec_tier: exhaustive %u rows, %u inconsistent\n", rows, bad);
    ET_CHECK("exhaustive: combination total is 2^15 fact bits x 6 abi x 6 min = 1179648",
             rows == (1u << 15) * 36u && rows == 1179648u);
    ET_CHECK("exhaustive: exact tier and per-tier reason match the oracle", bad == 0);
    return failures;
}

/* Adjacent-pair order cases: for each tier, break condition i and condition
 * i+1 together on an otherwise sound base; the tier must report reason i. */
static void b_n_img(struct exec_tier_facts *f) { f->app.has_native_image = false; }
static void b_n_bk(struct exec_tier_facts *f) { f->native.backend_built = false; }
static void b_n_arch(struct exec_tier_facts *f) { f->native.arch_supported = false; }
static void b_n_nnp(struct exec_tier_facts *f) { f->native.no_new_privs = false; }
static void b_n_ll0(struct exec_tier_facts *f) { f->native.landlock_abi = 0; }
static void b_n_lllow(struct exec_tier_facts *f)
{ f->app.min_landlock_abi = 4; }
static void b_n_sec(struct exec_tier_facts *f) { f->native.seccomp = false; }
static void b_h_bk(struct exec_tier_facts *f) { f->hwvirt.backend_built = false; }
static void b_h_dev(struct exec_tier_facts *f) { f->hwvirt.device_present = false; }
static void b_h_open(struct exec_tier_facts *f) { f->hwvirt.device_openable = false; }
static void b_h_grant(struct exec_tier_facts *f) { f->hwvirt.user_grant = false; }
static void b_h_guest(struct exec_tier_facts *f) { f->hwvirt.guest_image_ready = false; }
static void b_e_run(struct exec_tier_facts *f) { f->emulator.runner_linked = false; }
static void b_e_br(struct exec_tier_facts *f) { f->emulator.manifest_bridge = false; }
static void b_e_img(struct exec_tier_facts *f) { f->app.has_riscv64_image = false; }

typedef void (*et_break)(struct exec_tier_facts *);

static int et_pairs_for(const char *tier, const struct exec_tier_facts *base,
                        const et_break *brk, const enum exec_tier_reject *why,
                        size_t n, int which)
{
    int failures = 0;
    char name[96];
    for (size_t i = 0; i + 1 < n; i++) {
        struct exec_tier_facts f = *base;
        brk[i](&f);
        brk[i + 1](&f);
        struct exec_tier_decision d = exec_tier_select(&f);
        enum exec_tier_reject got = which == 0 ? d.native
                                  : which == 1 ? d.hwvirt : d.emulator;
        snprintf(name, sizeof name, "%s order: %s wins over the next condition", tier, exec_tier_reject_name(why[i]));
        ET_CHECK(name, got == why[i]);
    }
    return failures;
}

static int et_pairs(void)
{
    int failures = 0;
    static const et_break nb[] = { b_n_img, b_n_bk, b_n_arch, b_n_nnp, b_n_ll0,
                                   b_n_lllow, b_n_sec, m_confirm };
    static const enum exec_tier_reject nw[] = {
        R(NATIVE_NO_IMAGE), R(NATIVE_NO_BACKEND), R(NATIVE_ARCH_UNSUPPORTED),
        R(NATIVE_NO_NEW_PRIVS), R(NATIVE_LANDLOCK_ABSENT), R(NATIVE_LANDLOCK_ABI_LOW),
        R(NATIVE_SECCOMP_UNAVAILABLE), R(NATIVE_EXEC_CONFIRM_UNAVAILABLE) };
    static const et_break hb[] = { b_h_bk, b_h_dev, b_h_open, b_h_grant, b_h_guest };
    static const enum exec_tier_reject hw[] = {
        R(HWVIRT_NO_BACKEND), R(HWVIRT_NO_DEVICE), R(HWVIRT_NOT_OPENABLE),
        R(HWVIRT_NO_USER_GRANT), R(HWVIRT_NO_GUEST_IMAGE) };
    static const et_break eb[] = { b_e_run, b_e_br, b_e_img };
    static const enum exec_tier_reject ew[] = {
        R(EMULATOR_RUNNER_ABSENT), R(EMULATOR_NO_MANIFEST_BRIDGE),
        R(EMULATOR_NO_RISCV64_IMAGE) };

    struct exec_tier_facts nbase = et_full_linux();
    failures += et_pairs_for("native", &nbase, nb, nw, sizeof nb / sizeof nb[0], 0);

    struct exec_tier_facts hbase = et_full_linux();
    m_nnp(&hbase);
    et_hw_ok(&hbase);
    failures += et_pairs_for("hwvirt", &hbase, hb, hw, sizeof hb / sizeof hb[0], 1);

    struct exec_tier_facts ebase = et_full_linux();
    m_emu(&ebase);
    failures += et_pairs_for("emulator", &ebase, eb, ew, sizeof eb / sizeof eb[0], 2);
    return failures;
}

static int et_names_and_format(void)
{
    int failures = 0;
    for (int i = 0; i < EXEC_TIER_REJECT_COUNT; i++) {
        const char *a = exec_tier_reject_name((enum exec_tier_reject)i);
        ET_CHECK("reject name non-empty", a[0] && strcmp(a, "unknown") != 0);
        for (int j = 0; j < i; j++)
            ET_CHECK("reject names distinct",
                     strcmp(a, exec_tier_reject_name((enum exec_tier_reject)j)) != 0);
    }
    for (int i = 0; i <= T(EMULATOR); i++) {
        const char *a = exec_tier_name((enum exec_tier)i);
        ET_CHECK("tier name non-empty", a[0] && strcmp(a, "unknown") != 0);
        for (int j = 0; j < i; j++)
            ET_CHECK("tier names distinct", strcmp(a, exec_tier_name((enum exec_tier)j)) != 0);
    }
    ET_CHECK("out-of-range names are 'unknown'",
             !strcmp(exec_tier_name((enum exec_tier)99), "unknown") &&
             !strcmp(exec_tier_reject_name((enum exec_tier_reject)99), "unknown"));

    struct exec_tier_decision d = {
        .tier = T(NONE), .native = R(NATIVE_LANDLOCK_ABSENT),
        .hwvirt = R(HWVIRT_NO_USER_GRANT),
        .emulator = R(EMULATOR_RUNNER_ABSENT), .exec_confirm_hint = false
    };
    char buf[160];
    ET_CHECK("format ok", exec_tier_format(&d, buf, sizeof buf));
    ET_CHECK("format text", !strcmp(buf, "tier=none native=landlock_absent "
             "hwvirt=no_user_grant emulator=emulator_runner_absent "
             "exec_confirm=hint_blocked"));
    d.exec_confirm_hint = true;
    ET_CHECK("format hint ok", exec_tier_format(&d, buf, sizeof buf) &&
             !strcmp(buf, "tier=none native=landlock_absent hwvirt=no_user_grant "
                     "emulator=emulator_runner_absent exec_confirm=hint_ok"));
    d.exec_confirm_hint = false;
    exec_tier_format(&d, buf, sizeof buf);
    size_t need = strlen(buf) + 1;
    ET_CHECK("format exact-fit buffer", exec_tier_format(&d, buf, need));
    ET_CHECK("format buffer one byte short", !exec_tier_format(&d, buf, need - 1));
    ET_CHECK("format 1-byte buffer", !exec_tier_format(&d, buf, 1));
    ET_CHECK("format zero buffer", !exec_tier_format(&d, buf, 0));
    ET_CHECK("format NULL decision", !exec_tier_format(NULL, buf, sizeof buf));
    return failures;
}

static int et_host(void)
{
    int failures = 0;
    struct exec_tier_facts f = exec_tier_host_facts();
    f.app.has_native_image = true;
    f.app.has_riscv64_image = true;
    ET_CHECK("host: emulator runner not linked", !f.emulator.runner_linked);
    ET_CHECK("host: emulator manifest bridge absent", !f.emulator.manifest_bridge);
    ET_CHECK("host: hwvirt backend not built", !f.hwvirt.backend_built);
    ET_CHECK("host: hwvirt guest image not ready", !f.hwvirt.guest_image_ready);
    ET_CHECK("host: user grant is the caller's", !f.hwvirt.user_grant);
    struct exec_tier_decision d = exec_tier_select(&f);
    char line[160];
    ET_CHECK("host: native or none, never hwvirt/emulator",
             d.tier == T(NATIVE) || d.tier == T(NONE));
    ET_CHECK("host: decision formats", exec_tier_format(&d, line, sizeof line));
    printf("exec_tier: host decision: %s\n", line);
    return failures;
}

/* Pure cases only (no host probe): safe on every platform. */
int test_exec_tier_pure_cases(void);
int test_exec_tier_pure_cases(void)
{
    int failures = 0;
    printf("\n=== exec_tier picker tests ===\n");
    failures += et_table();
    failures += et_nothing_and_null();
    failures += et_exhaustive();
    failures += et_pairs();
    failures += et_names_and_format();
    return failures;
}

int test_exec_tier_cases(void);
int test_exec_tier_cases(void)
{
    int failures = test_exec_tier_pure_cases();
    failures += et_host();
    printf("=== exec_tier tests done: %d failure(s) ===\n", failures);
    return failures;
}
