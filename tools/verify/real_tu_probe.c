/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Linux x86-64 GCC 13/14 witness and unprivileged compile-core
 *          qualification. The result never authorizes reuse: the complete
 *          input/tool closure is absent. Run from within the repository
 *          through real_tu_probe.sh; --selftest checks argument validation
 *          and the helpers. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "verify/probe_util.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SOURCE_TU "platform/modules/base/src/result.c"

struct probe {
    const char *compiler;
    const char *standard;
    char repo[PU_PATH_MAX];
    char work[PU_PATH_MAX];
    char driver[PU_PATH_MAX];
    char hash_driver[PU_PATH_MAX], hash_source[PU_PATH_MAX], hash_pp[PU_PATH_MAX];
    char prefix_map[PU_PATH_MAX + 32u];
    char seed[PU_PATH_MAX];
};

static int validate(const char *compiler, const char *standard)
{
    if (strcmp(standard, "-std=c23") != 0 && strcmp(standard, "-std=c2x") != 0) {
        fprintf(stderr, "unsupported standard: %s\n", standard);
        return 2;
    }
    if (compiler[0] != '/') {
        fputs("compiler path must be absolute\n", stderr);
        return 2;
    }
    if (strcmp(compiler, "/usr/bin/gcc") != 0) {
        fputs("qualification supports only root-owned /usr/bin/gcc\n", stderr);
        return 2;
    }
    return 0;
}

static int selftest(void)
{
    bool ok = validate("/usr/bin/gcc", "-std=c23") == 0 &&
              validate("/usr/bin/gcc", "-std=c2x") == 0 &&
              validate("/usr/bin/gcc", "-std=gnu23") == 2 &&
              validate("gcc", "-std=c23") == 2 &&
              validate("/opt/gcc", "-std=c23") == 2;
    puts(ok ? "real_tu_probe_selftest=PASS" : "real_tu_probe_selftest=FAIL");
    return ok && pu_selftest() == 0 ? 0 : 1;
}

/* Compile flags shared by the three baseline invocations; the order is the
 * profile compile_core reproduces. */
static void base_flags(const struct probe *p, struct pu_argv *a)
{
    static const char *const head[] = {
        "-g", "-O3", "-march=x86-64-v3", "-flto=auto", "-Wall", "-Wextra",
        "-Werror", "-pedantic", nullptr};
    static const char *const tail[] = {
        "-gno-record-gcc-switches", "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2", "-fcf-protection=full",
        "-fPIE", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include", "-D_POSIX_C_SOURCE=200809L",
        nullptr};
    pu_argv_add(a, p->compiler);
    pu_argv_add(a, p->standard);
    pu_argv_addv(a, head);
    pu_argv_add(a, p->prefix_map);
    pu_argv_addv(a, tail);
    pu_argv_add(a, p->seed);
}

static void die_rc(int rc)
{
    exit(rc > 0 ? rc : 1);
}

static void run_or_exit(const struct pu_argv *a, const char *out, const char *err)
{
    int rc = pu_run(a, out, err);
    if (rc != 0) die_rc(rc);
}

static void baseline_compile(const struct probe *p)
{
    struct pu_argv pre = {.n = 0}, cold = {.n = 0}, cpp = {.n = 0};
    base_flags(p, &pre);
    pu_argv_addv(&pre, (const char *const[]){"-E", SOURCE_TU, "-o",
                 pu_at(p->work, "input.i"), nullptr});
    run_or_exit(&pre, nullptr, nullptr);
    base_flags(p, &cold);
    pu_argv_addv(&cold, (const char *const[]){"-c", "-MD", "-MF",
                 pu_at(p->work, "cold.d"), "-MT", "result.o", SOURCE_TU, "-o",
                 pu_at(p->work, "result.o"), nullptr});
    run_or_exit(&cold, nullptr, pu_at(p->work, "cold.stderr"));
    if (!pu_copy(pu_at(p->work, "result.o"), pu_at(p->work, "source.o")))
        exit(1);
    base_flags(p, &cpp);
    pu_argv_addv(&cpp, (const char *const[]){"-x", "cpp-output", "-c",
                 pu_at(p->work, "input.i"), "-o", pu_at(p->work, "result.o"),
                 nullptr});
    run_or_exit(&cpp, nullptr, nullptr);
}

static int baseline(const struct probe *p)
{
    long long start = pu_now_ns();
    baseline_compile(p);
    long long end = pu_now_ns();
    int equal = pu_same_file(pu_at(p->work, "source.o"),
                             pu_at(p->work, "result.o")) ? 1 : 0;
    struct pu_argv sum = {.n = 0};
    printf("real_tu=%s compiler=%s standard=%s source_vs_cpp_equal=%d\n",
           SOURCE_TU, p->compiler, p->standard, equal);
    pu_argv_add(&sum, "sha256sum");
    pu_argv_add(&sum, pu_at(p->work, "source.o"));
    pu_argv_add(&sum, pu_at(p->work, "result.o"));
    run_or_exit(&sum, nullptr, nullptr);
    printf("baseline_compiler_launches=3 reusable_object=%d baseline_ms=%d\n",
           equal, (int)((end - start) / 1000000));
    if (equal) {
        fputs("expected GCC debug/LTO direct-source mismatch disappeared\n",
              stderr);
        return 1;
    }
    return 0;
}

/* hash of a file by the compile core; out receives the trimmed digest. */
static void core_hash(const struct probe *p, const char *file, char *out)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, pu_at(p->work, "compile-core"));
    pu_argv_add(&a, "hash");
    pu_argv_add(&a, file);
    run_or_exit(&a, pu_at(p->work, "hash.out"), nullptr);
    if (!pu_read(pu_at(p->work, "hash.out"), out, PU_PATH_MAX, nullptr, true))
        exit(1);
}

static void build_core(const struct probe *p)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, p->compiler);
    pu_argv_add(&a, p->standard);
    pu_argv_addv(&a, (const char *const[]){"-D_XOPEN_SOURCE=700", "-Wall",
                 "-Wextra", "-Werror", "-pedantic",
                 "-Iplatform/modules/sha3/include",
                 "-Iplatform/modules/base/include",
                 "tools/verify/compile_core.c",
                 "platform/modules/sha3/src/sha3.c", "-o",
                 pu_at(p->work, "compile-core"), nullptr});
    run_or_exit(&a, nullptr, nullptr);
}

static void compile_args(const struct probe *p, struct pu_argv *a,
                         const char *compiler, const char *standard,
                         const char *driver_hash, const char *source_hash,
                         const char *outdir)
{
    pu_argv_add(a, pu_at(p->work, "compile-core"));
    pu_argv_add(a, "compile");
    pu_argv_add(a, compiler);
    pu_argv_add(a, standard);
    pu_argv_add(a, driver_hash);
    pu_argv_add(a, source_hash);
    pu_argv_add(a, p->hash_pp);
    pu_argv_add(a, outdir);
}

static void require_line(const struct probe *p, const char *key, const char *file)
{
    char hash[PU_PATH_MAX], line[PU_PATH_MAX + 32u];
    core_hash(p, file, hash);
    snprintf(line, sizeof line, "%s=%s", key, hash);
    if (!pu_has_line(pu_at(p->work, "qualified.out"), line)) exit(1);
}

static void require_same(const char *a, const char *b)
{
    if (pu_same_file(a, b)) return;
    fprintf(stderr, "%s %s differ\n", a, b);
    exit(1);
}

static void echo_line(const struct probe *p, const char *line)
{
    if (!pu_has_line(pu_at(p->work, "qualified.out"), line)) exit(1);
    puts(line);
}

static void qualify(struct probe *p)
{
    struct pu_argv a = {.n = 0};
    char q[PU_PATH_MAX];
    snprintf(q, sizeof q, "%s", pu_at(p->work, "qualified"));
    core_hash(p, p->driver, p->hash_driver);
    core_hash(p, SOURCE_TU, p->hash_source);
    core_hash(p, pu_at(p->work, "input.i"), p->hash_pp);
    if (mkdir(q, 0700) != 0 || chmod(q, 0700) != 0) exit(1);
    compile_args(p, &a, p->compiler, p->standard, p->hash_driver,
                 p->hash_source, q);
    long long start = pu_now_ns();
    run_or_exit(&a, pu_at(p->work, "qualified.out"), nullptr);
    long long end = pu_now_ns();
    require_same(pu_at(p->work, "source.o"), pu_at(q, "result.o"));
    require_same(pu_at(p->work, "cold.d"), pu_at(q, "result.d"));
    require_same(pu_at(p->work, "cold.stderr"), pu_at(q, "compile.stderr"));
    require_line(p, "object_sha3", pu_at(q, "result.o"));
    require_line(p, "dep_sha3", pu_at(q, "result.d"));
    require_line(p, "stderr_sha3", pu_at(q, "compile.stderr"));
    echo_line(p, "attest_eligible=0");
    echo_line(p, "reason=tool_and_input_closure_unproven");
    printf("direct_source_artifacts_equal=1 core_compiler_launches=2 "
           "core_ms=%d qualification_only=1 proof_launches_avoided=0\n",
           (int)((end - start) / 1000000));
}

static void refuse(const struct probe *p, const char *want,
                   const struct pu_argv *a)
{
    char line[160];
    int rc = pu_run(a, pu_at(p->work, "refused.out"),
                    pu_at(p->work, "refused.err"));
    if (rc == 0) {
        fprintf(stderr, "expected refusal: %s\n", want);
        exit(1);
    }
    if (rc != 2) {
        fprintf(stderr, "wrong refusal exit for %s: %d\n", want, rc);
        exit(1);
    }
    snprintf(line, sizeof line, "compile_core_refuse=%s", want);
    if (!pu_has_line(pu_at(p->work, "refused.err"), line)) exit(1);
}

static void refuse_compile(const struct probe *p, const char *want,
                           const char *compiler, const char *standard,
                           const char *driver_hash, const char *source_hash,
                           const char *pp_hash, const char *outdir)
{
    struct pu_argv a = {.n = 0};
    struct probe q = *p;
    snprintf(q.hash_pp, sizeof q.hash_pp, "%s", pp_hash);
    compile_args(&q, &a, compiler, standard, driver_hash, source_hash,
                 pu_at(p->work, outdir));
    refuse(p, want, &a);
}

static void make_dirs(const struct probe *p)
{
    static const char *const strict[] = {"bad-std", "bad-hash", "bad-source",
                                         "bad-pp", "bad-driver"};
    for (size_t i = 0; i < 5u; ++i)
        if (mkdir(pu_at(p->work, strict[i]), 0700) != 0 ||
            chmod(pu_at(p->work, strict[i]), 0700) != 0) exit(1);
    if (mkdir(pu_at(p->work, "bad-output"), 0755) != 0 ||
        chmod(pu_at(p->work, "bad-output"), 0755) != 0) exit(1);
}

static void red_tests(struct probe *p)
{
    char zeros[65], replacement[PU_PATH_MAX];
    struct pu_argv shape = {.n = 0};
    const char *c = p->compiler, *s = p->standard;
    const char *dh = p->hash_driver, *sh = p->hash_source, *ph = p->hash_pp;
    memset(zeros, '0', 64);
    zeros[64] = '\0';
    make_dirs(p);
    pu_argv_add(&shape, pu_at(p->work, "compile-core"));
    pu_argv_add(&shape, "compile");
    refuse(p, "request_shape_unsupported", &shape);
    refuse_compile(p, "standard_unsupported", c, "-std=gnu23", dh, sh, ph, "bad-std");
    refuse_compile(p, "hash_malformed", c, s, "X", sh, ph, "bad-hash");
    refuse_compile(p, "source_bytes_mismatch", c, s, dh, zeros, ph, "bad-source");
    refuse_compile(p, "preprocessed_bytes_mismatch", c, s, dh, sh, zeros, "bad-pp");
    refuse_compile(p, "output_dir_unsafe", c, s, dh, sh, ph, "bad-output");
    char fake[PU_PATH_MAX];
    FILE *f;
    snprintf(fake, sizeof fake, "%s", pu_at(p->work, "replaced-gcc"));
    if (!pu_copy(p->driver, fake) || !(f = fopen(fake, "ab")) ||
        fputc(1, f) == EOF || fclose(f) != 0 || chmod(fake, 0700) != 0)
        exit(1);
    core_hash(p, fake, replacement);
    refuse_compile(p, "driver_bytes_mismatch", c, s, replacement, sh, ph, "bad-driver");
    refuse_compile(p, "compiler_path_unsupported", fake, s, dh, sh, ph, "bad-driver");
    puts("red_refusals=8 replacement_byte_claim_refused=1 "
         "arbitrary_compiler_refused=1");
}

static int run_probe(struct probe *p)
{
    if (!pu_repo_root(p->repo, sizeof p->repo) || chdir(p->repo) != 0 ||
        !realpath(p->compiler, p->driver)) exit(1);
    if (!pu_scratch_make("/tmp/z23-verify-real-tu.XXXXXX", p->work,
                         sizeof p->work)) exit(1);
    snprintf(p->prefix_map, sizeof p->prefix_map,
             "-ffile-prefix-map=%s=/zclassic23", p->repo);
    snprintf(p->seed, sizeof p->seed, "-frandom-seed=%s", SOURCE_TU);
    int rc = baseline(p);
    if (rc != 0) return rc;
    build_core(p);
    qualify(p);
    red_tests(p);
    return 0;
}

int main(int argc, char **argv)
{
    static struct probe p;
    if (argc >= 2 && argc != 4 &&
        !(argc == 3 && strcmp(argv[2], "--selftest") == 0)) {
        fprintf(stderr, "usage: %s /absolute/gcc -std=c23|-std=c2x\n", argv[1]);
        return 2;
    }
    if (argc < 2) return 2;
    if (argc == 3) return selftest();
    int rc = validate(argv[2], argv[3]);
    if (rc != 0) return rc;
    p.compiler = argv[2];
    p.standard = argv[3];
    return run_probe(&p);
}
