/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Exact current build-only result.c profile witness; never
 *          authorizes reuse. Pins the ordered GCC 14 argv in
 *          fixed_result_gcc14.args against the Make recipe, compiles the
 *          translation unit twice and preprocesses it once. Run from the
 *          repository root through fixed_result_gcc14_probe.sh; --selftest
 *          checks the helpers. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "verify/fixed_result_profile.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FRG_SOURCE "platform/modules/base/src/result.c"
#define FRG_MANIFEST "tools/verify/fixed_result_gcc14.args"
#define FRG_MANIFEST_SHA3 \
    "befa08b481efd3d6387c61d39095f77ec65e9bf229f55a3da4a9cf4efdd20cfa"
#define FRG_GCC "/usr/bin/x86_64-linux-gnu-gcc-14"
#define FRG_FLAGS 180u
#define FRG_RECIPE \
    "__z23_result_profile: ; @printf \"__PROFILE_BEGIN__\\n\"; " \
    "printf \"%s\\n\" $(CC) $(BUILD_ONLY_OBJECT_CFLAGS); " \
    "printf \"__TARGET__\\n%s\\n\" " \
    "\"$(OBJ_DIR)/platform/modules/base/src/result.o\""

struct frg_probe {
    char repo[PU_PATH_MAX];
    char work[PU_PATH_MAX];
    char gcc[PATH_MAX];
    char manifest_sha3[65];
    struct frp_lines actual, pinned, args;
    const char *target;
    struct frp_timing cold, repeat, preprocess;
};

static _Noreturn void frg_fail(const char *why)
{
    fprintf(stderr, "fixed_result_refuse=%s\n", why);
    exit(2);
}

static void frg_run_or_exit(const struct pu_argv *a, const char *out,
                            const char *err, struct frp_timing *t)
{
    int rc = frp_run(nullptr, a, out, err, t);
    if (rc != 0) exit(rc > 0 ? rc : 1);
}

static void frg_preflight(struct frg_probe *p)
{
    struct stat st, lst;
    const char *why = frp_checkout(p->repo, sizeof p->repo);
    if (why) frg_fail(why);
    if (!realpath("/usr/bin/cc", p->gcc) || strcmp(p->gcc, FRG_GCC) != 0)
        frg_fail("gcc14_driver_mismatch");
    if (stat(FRG_SOURCE, &st) != 0 || !S_ISREG(st.st_mode) ||
        lstat(FRG_SOURCE, &lst) != 0 || S_ISLNK(lst.st_mode))
        frg_fail("source_missing");
    frp_sha3_file(FRG_MANIFEST, p->manifest_sha3);
    if (strcmp(p->manifest_sha3, FRG_MANIFEST_SHA3) != 0)
        frg_fail("pinned_manifest_bytes_mismatch");
    if (!pu_scratch_make("/tmp/z23-fixed-result-gcc14.XXXXXX", p->work,
                         sizeof p->work)) exit(1);
}

/* Expand the same Make variables as the build-only epoch recipe. The only
 * automatic variable not available here is the source seed. */
static void frg_load_profile(struct frg_probe *p)
{
    struct pu_argv make = {.n = 0};
    char zcc[PU_PATH_MAX + 16u];
    const char *out = pu_at(p->work, "make.args");
    pu_argv_addv(&make, (const char *const[]){"make", "-s",
                 "--eval=" FRG_RECIPE, "__z23_result_profile", nullptr});
    frg_run_or_exit(&make, out, nullptr, nullptr);
    if (!frp_lines_load(out, &p->actual) ||
        !frp_lines_load(FRG_MANIFEST, &p->pinned)) exit(1);
    if (p->actual.n != 184u || p->pinned.n != 181u)
        frg_fail("argv_count_mismatch");
    snprintf(zcc, sizeof zcc, "%s/build/bin/zcc", p->repo);
    if (strcmp(p->actual.v[0], "__PROFILE_BEGIN__") != 0 ||
        strcmp(p->actual.v[1], zcc) != 0 || strcmp(p->actual.v[2], "cc") != 0 ||
        strcmp(p->actual.v[182], "__TARGET__") != 0)
        frg_fail("make_recipe_mismatch");
    p->target = p->actual.v[183];
    if (!frp_glob(p->target, "build/obj/epochs/*/platform/modules/base/src/result.o"))
        frg_fail("epoch_target_malformed");
}

static void frg_pin_args(struct frg_probe *p)
{
    char seed[sizeof "-frandom-seed=" + sizeof FRG_SOURCE];
    if (!frp_expand(&p->pinned, FRG_FLAGS, p->repo, &p->args)) exit(1);
    for (size_t i = 0; i < FRG_FLAGS; ++i)
        if (strcmp(p->actual.v[i + 2u], p->args.v[i]) != 0)
            frg_fail("pinned_profile_mismatch");
    snprintf(seed, sizeof seed, "-frandom-seed=%s", FRG_SOURCE);
    if (strcmp(p->pinned.v[FRG_FLAGS], seed) != 0)
        frg_fail("source_seed_mismatch");
    if (!frp_lines_add(&p->args, seed)) exit(1);
}

/* One GCC launch under the fixed environment: compile (-c) or preprocess (-E). */
static void frg_gcc(struct frg_probe *p, const char *mode, const char *object,
                    const char *dep, const char *err, struct frp_timing *t)
{
    struct pu_argv a = {.n = 0};
    frp_env_argv(&a, &p->args);
    pu_argv_addv(&a, (const char *const[]){"-MMD", "-MP", "-MF", dep, "-MT",
                 p->target, mode, "-o", object, FRG_SOURCE, nullptr});
    frg_run_or_exit(&a, nullptr, err, t);
}

static void frg_require_same(const struct frg_probe *p, const char *a,
                             const char *b, const char *why)
{
    if (!pu_same_file(pu_at(p->work, a), pu_at(p->work, b))) frg_fail(why);
}

static void frg_compile_all(struct frg_probe *p)
{
    frg_gcc(p, "-c", pu_at(p->work, "cold.o"), pu_at(p->work, "cold.d"),
            pu_at(p->work, "cold.stderr"), &p->cold);
    frg_gcc(p, "-c", pu_at(p->work, "repeat.o"), pu_at(p->work, "repeat.d"),
            pu_at(p->work, "repeat.stderr"), &p->repeat);
    frg_require_same(p, "cold.o", "repeat.o", "object_bytes_differ");
    frg_require_same(p, "cold.d", "repeat.d", "dep_bytes_differ");
    frg_require_same(p, "cold.stderr", "repeat.stderr", "stderr_bytes_differ");
    frg_gcc(p, "-E", pu_at(p->work, "result.i"), pu_at(p->work, "preprocess.d"),
            pu_at(p->work, "preprocess.stderr"), &p->preprocess);
    frg_require_same(p, "cold.d", "preprocess.d", "fresh_dep_bytes_differ");
}

static void frg_sha256(const struct frg_probe *p)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, "sha256sum");
    for (const char *const *n = (const char *const[]){"cold.o", "repeat.o",
             "cold.d", "result.i", nullptr}; *n; ++n)
        pu_argv_add(&a, pu_at(p->work, *n));
    frg_run_or_exit(&a, nullptr, nullptr, nullptr);
}

static void frg_print_time(const char *run, const struct frp_timing *t)
{
    printf("%s wall_seconds=%.2f user_seconds=%.2f system_seconds=%.2f\n", run,
           t->wall, t->user, t->sys);
}

static void frg_report(const struct frg_probe *p)
{
    const char *w = p->work;
    printf("profile_green=1 source=%s cwd=%s gcc=%s flags=%u epoch_target=%s\n",
           FRG_SOURCE, p->repo, p->gcc, FRG_FLAGS, p->target);
    printf("manifest_sha3=%s\n", p->manifest_sha3);
    frg_sha256(p);
    frg_print_time("cold", &p->cold);
    frg_print_time("repeat", &p->repeat);
    frg_print_time("preprocess", &p->preprocess);
    printf("cold_bytes object=%lld dep=%lld stderr=%lld preprocess=%lld\n",
           frp_size(pu_at(w, "cold.o")), frp_size(pu_at(w, "cold.d")),
           frp_size(pu_at(w, "cold.stderr")), frp_size(pu_at(w, "result.i")));
    printf("repeat_bytes object=%lld dep=%lld stderr=%lld\n",
           frp_size(pu_at(w, "repeat.o")), frp_size(pu_at(w, "repeat.d")),
           frp_size(pu_at(w, "repeat.stderr")));
    puts("object_equal=1 dep_equal=1 fresh_dep_equal=1 compiler_launches=2 "
         "preprocess_launches=1 proof_launches_avoided=0 attest_eligible=0");
}

static int frg_selftest(void)
{
    return frp_selftest() == 0 && pu_selftest() == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    static struct frg_probe p;
    if (argc == 3 && strcmp(argv[2], "--selftest") == 0) return frg_selftest();
    frg_preflight(&p);
    frg_load_profile(&p);
    frg_pin_args(&p);
    frg_compile_all(&p);
    frg_report(&p);
    return 0;
}
