/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The no-root completeness proof for a fixed-result tool image.
 *          Without root there is no chroot or bind mount, so the pinned
 *          compile runs from the image through the image's own loader and
 *          must reproduce the host's cold object byte for byte, while
 *          strace names every path it touched outside the image, snapshot
 *          and scratch. A second trace of the host compile checks that the
 *          image presents every path the compile found and hides every
 *          path it missed, with the bytes the host served. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char *const k_frp_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

struct frp {
    struct zcl_fri_proof *p;
    const char *tool, *profile;
    char scratch[PATH_MAX], src[PATH_MAX];
    char loader[PATH_MAX], libpath[PATH_MAX * 2], driver[PATH_MAX];
    char wrapper[PATH_MAX * 3], sysroot[PATH_MAX + 16], prefix_map[PATH_MAX + 32];
    char exec_prefix[PATH_MAX + 32], compiler_path[PATH_MAX * 2 + 32];
};

static bool frp_fail(struct zcl_fri_proof *p, const char *why, const char *path)
{
    if (!p->why) {
        p->why = why;
        snprintf(p->why_path, sizeof(p->why_path), "%s", path ? path : "");
    }
    return false;
}

static void frp_name(char list[ZCL_FRI_NAMED][PATH_MAX], unsigned count,
                     const char *path)
{
    if (count < ZCL_FRI_NAMED) snprintf(list[count], PATH_MAX, "%s", path);
}

static bool frp_dir(char out[PATH_MAX], const char *base, const char *leaf)
{
    return snprintf(out, PATH_MAX, "%s/%s", base, leaf) < PATH_MAX &&
           mkdir(out, 0700) == 0;
}

static bool frp_files_equal(const char *a, const char *b)
{
    uint8_t x[32], y[32];
    uint64_t sx = 0, sy = 0;
    return zcl_fri_sha3_file(a, x, &sx) && zcl_fri_sha3_file(b, y, &sy) &&
           sx == sy && memcmp(x, y, 32u) == 0;
}

/* The driver's own cc1, asked the same way the image was built. */
static bool frp_cc1_host(const struct frp *f, char out[PATH_MAX])
{
    char path[PATH_MAX];
    char *argv[] = {"cc", "-print-prog-name=cc1", NULL};
    if (snprintf(path, sizeof(path), "%s/cc1-query.out", f->scratch) >= PATH_MAX)
        return false;
    struct zcl_fri_run r = {.argv = argv, .envp = k_frp_env,
                            .path = "/usr/bin/cc", .cwd = f->scratch,
                            .out_path = path};
    int code = -1;
    if (!zcl_fri_run_wait(&r, &code) || code != 0) return false;
    FILE *fp = fopen(path, "re");
    bool ok = fp && fgets(out, PATH_MAX, fp) != NULL;
    if (fp) fclose(fp);
    if (!ok) return false;
    out[strcspn(out, "\n")] = '\0';
    return out[0] == '/';
}

/* COMPILER_PATH is the image directory that holds that cc1. */
static bool frp_bind_cc1(struct frp *f)
{
    char host[PATH_MAX], rel[PATH_MAX];
    if (!frp_cc1_host(f, host) ||
        zcl_fri_image_lookup(f->tool, host, rel) != 'F')
        return false;
    char *slash = strrchr(rel, '/');
    if (!slash) return false;
    *slash = '\0';
    int n = snprintf(f->compiler_path, sizeof(f->compiler_path),
                     "COMPILER_PATH=%s/%s:%s/usr/bin", f->tool, rel, f->tool);
    return n > 0 && (size_t)n < sizeof(f->compiler_path);
}

/* The image's loader, driver and search roots, all under the image. */
static bool frp_layout(struct frp *f)
{
    char rel[PATH_MAX], interp[PATH_MAX];
    const char *why = NULL;
    const char *t = f->tool;
    if (zcl_fri_image_lookup(t, "/usr/bin/cc", rel) != 'F' ||
        snprintf(f->driver, sizeof(f->driver), "%s/%s", t, rel) >= PATH_MAX ||
        !zcl_fri_elf_interp(f->driver, interp, &why) || !interp[0] ||
        zcl_fri_image_lookup(t, interp, rel) != 'F' ||
        snprintf(f->loader, sizeof(f->loader), "%s/%s", t, rel) >= PATH_MAX ||
        !frp_bind_cc1(f))
        return frp_fail(f->p, ZCL_FRI_WHY_MISSING, t);
    int n = snprintf(f->libpath, sizeof(f->libpath),
                     "%s/lib/x86_64-linux-gnu:%s/usr/lib/x86_64-linux-gnu:"
                     "%s/lib:%s/usr/lib", t, t, t, t);
    bool ok = n > 0 && (size_t)n < sizeof(f->libpath);
    ok = ok && (size_t)snprintf(f->wrapper, sizeof(f->wrapper),
                                "%s,--inhibit-cache,--library-path,%s",
                                f->loader, f->libpath) < sizeof(f->wrapper);
    ok = ok && (size_t)snprintf(f->sysroot, sizeof(f->sysroot), "--sysroot=%s",
                                t) < sizeof(f->sysroot);
    ok = ok && (size_t)snprintf(f->prefix_map, sizeof(f->prefix_map),
                                "-ffile-prefix-map=%s=", t) < sizeof(f->prefix_map);
    ok = ok && (size_t)snprintf(f->exec_prefix, sizeof(f->exec_prefix),
                                "GCC_EXEC_PREFIX=%s/usr/lib/gcc/", t)
                   < sizeof(f->exec_prefix);
    return ok || frp_fail(f->p, ZCL_FRI_WHY_LIMIT, t);
}

static bool frp_outputs(const char *dir, char obj[PATH_MAX], char dep[PATH_MAX],
                        char err[PATH_MAX])
{
    return snprintf(obj, PATH_MAX, "%s/result.o", dir) < PATH_MAX &&
           snprintf(dep, PATH_MAX, "%s/deps.d", dir) < PATH_MAX &&
           snprintf(err, PATH_MAX, "%s/stderr.bin", dir) < PATH_MAX;
}

static bool frp_host_compile(struct frp *f, const char *leaf, bool preprocess,
                             const char *trace_dir)
{
    char dir[PATH_MAX], obj[PATH_MAX], dep[PATH_MAX], err[PATH_MAX];
    if (!frp_dir(dir, f->scratch, leaf) || !frp_outputs(dir, obj, dep, err))
        return frp_fail(f->p, ZCL_FRI_WHY_WRITE, f->scratch);
    struct zcl_fri_argv a;
    const char *why = zcl_fri_argv_make(&a, f->profile, f->src, ZCL_FRI_TARGET,
                                        obj, dep, preprocess);
    if (why) { zcl_fri_argv_free(&a); return frp_fail(f->p, why, f->profile); }
    struct zcl_fri_run r = {.argv = a.argv, .envp = k_frp_env,
                            .path = "/usr/bin/cc", .cwd = f->src, .err_path = err};
    int code = -1;
    bool ran = trace_dir ? zcl_fri_trace_run(&r, trace_dir, &code)
                         : zcl_fri_run_wait(&r, &code);
    zcl_fri_argv_free(&a);
    if (!ran) return frp_fail(f->p, ZCL_FRI_WHY_SPAWN, "/usr/bin/cc");
    return code == 0 || frp_fail(f->p, ZCL_FRI_WHY_COMPILE, err);
}

/* The pinned argv, run by the image's loader from the image's driver. */
static bool frp_image_compile(struct frp *f, const char *trace_dir)
{
    char dir[PATH_MAX], obj[PATH_MAX], dep[PATH_MAX], err[PATH_MAX];
    if (!frp_dir(dir, f->scratch, "image") || !frp_outputs(dir, obj, dep, err))
        return frp_fail(f->p, ZCL_FRI_WHY_WRITE, f->scratch);
    struct zcl_fri_argv a;
    const char *why = zcl_fri_argv_make(&a, f->profile, f->src, ZCL_FRI_TARGET,
                                        obj, dep, false);
    if (why) { zcl_fri_argv_free(&a); return frp_fail(f->p, why, f->profile); }
    char image_cc[PATH_MAX];
    snprintf(image_cc, sizeof(image_cc), "%s/usr/bin/cc", f->tool);
    char *argv[ZCL_FRI_PROFILE_ARGS + 40u];
    size_t n = 0;
    char *head[] = {f->loader, "--inhibit-cache", "--library-path", f->libpath,
                    "--argv0", image_cc, image_cc};
    for (size_t i = 0; i < sizeof(head) / sizeof(*head); i++) argv[n++] = head[i];
    for (size_t i = 1; i < ZCL_FRI_PROFILE_ARGS; i++) argv[n++] = a.argv[i];
    char *confine[] = {f->sysroot, f->prefix_map, "-wrapper", f->wrapper};
    for (size_t i = 0; i < sizeof(confine) / sizeof(*confine); i++)
        argv[n++] = confine[i];
    for (size_t i = ZCL_FRI_PROFILE_ARGS; i < a.argc; i++) argv[n++] = a.argv[i];
    argv[n] = NULL;
    char *env[] = {k_frp_env[0], k_frp_env[1], k_frp_env[2], k_frp_env[3],
                   f->exec_prefix, f->compiler_path, NULL};
    struct zcl_fri_run r = {.argv = argv, .envp = env, .path = f->loader,
                            .cwd = f->src, .err_path = err};
    int code = -1;
    bool ran = trace_dir ? zcl_fri_trace_run(&r, trace_dir, &code)
                         : zcl_fri_run_wait(&r, &code);
    zcl_fri_argv_free(&a);
    if (!ran) return frp_fail(f->p, ZCL_FRI_WHY_SPAWN, f->loader);
    return code == 0 || frp_fail(f->p, ZCL_FRI_WHY_COMPILE, err);
}

static bool frp_compare(struct frp *f)
{
    char ref[PATH_MAX], img[PATH_MAX];
    const char *names[] = {"result.o", "deps.d", "stderr.bin"};
    bool *flags[] = {&f->p->object_equal, &f->p->dep_equal, &f->p->stderr_equal};
    for (size_t i = 0; i < 3; i++) {
        if (snprintf(ref, sizeof(ref), "%s/reference/%s", f->scratch, names[i])
                >= PATH_MAX ||
            snprintf(img, sizeof(img), "%s/image/%s", f->scratch, names[i])
                >= PATH_MAX)
            return frp_fail(f->p, ZCL_FRI_WHY_LIMIT, f->scratch);
        *flags[i] = frp_files_equal(ref, img);
        if (i == 0 &&
            (!zcl_fri_sha3_file(ref, f->p->reference_object, &f->p->object_size) ||
             !zcl_fri_sha3_file(img, f->p->image_object, NULL)))
            return frp_fail(f->p, ZCL_FRI_WHY_COMPILE, ref);
    }
    return true;
}

static void frp_leak_one(struct zcl_fri_proof *p, const struct zcl_fri_access *x,
                         enum zcl_fri_class c)
{
    bool reads_outside = c == ZCL_FRI_C_TOOL || c == ZCL_FRI_C_LOADER_CACHE;
    if (c == ZCL_FRI_C_IMAGE) {
        p->image_reads += !x->write;
        if (x->write) { frp_name(p->leak, p->leaks, x->path); p->leaks++; }
    } else if (c == ZCL_FRI_C_ANCESTOR && !x->write) {
        p->ancestors++;
    } else if (reads_outside && x->state == ZCL_FRI_ABSENT && !x->write) {
        frp_name(p->absent, p->absent_outside, x->path);
        p->absent_outside++;
    } else if (reads_outside || c == ZCL_FRI_C_ANCESTOR ||
               (x->write && c == ZCL_FRI_C_SNAPSHOT)) {
        frp_name(p->leak, p->leaks, x->path);
        p->leaks++;
    }
}

static bool frp_leaks(struct frp *f, const char *trace_dir)
{
    struct zcl_fri_trace t = {0};
    struct zcl_fri_zones z = {.image = f->tool, .snapshot = f->src,
                              .scratch = f->scratch};
    bool ok = zcl_fri_trace_parse_dir(&t, trace_dir, f->src);
    if (!ok) frp_fail(f->p, t.why, t.why_line);
    for (size_t i = 0; ok && i < t.count; i++)
        frp_leak_one(f->p, &t.v[i], zcl_fri_classify(&z, t.v[i].path));
    zcl_fri_trace_free(&t);
    return ok;
}

static char frp_host_kind(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode) ? 'F' : S_ISDIR(st.st_mode) ? 'D' : 'S';
}

/* The jail's view of one path the host compile touched must equal the
 * host's: present with the same kind and bytes, or absent. */
static bool frp_equivalent(const struct frp *f, const struct zcl_fri_access *x)
{
    char rel[PATH_MAX], img[PATH_MAX], real[PATH_MAX];
    char kind = zcl_fri_image_lookup(f->tool, x->path, rel);
    if (x->state == ZCL_FRI_ABSENT) return kind == 0;
    if (kind != frp_host_kind(x->path)) return false;
    if (kind != 'F') return true;
    uint8_t a[32], b[32];
    uint64_t sa = 0, sb = 0;
    return realpath(x->path, real) &&
           snprintf(img, sizeof(img), "%s/%s", f->tool, rel) < PATH_MAX &&
           zcl_fri_sha3_file(real, a, &sa) && zcl_fri_sha3_file(img, b, &sb) &&
           sa == sb && memcmp(a, b, 32u) == 0;
}

static bool frp_equivalence(struct frp *f, const char *dir_e, const char *dir_c)
{
    struct zcl_fri_trace t = {0};
    struct zcl_fri_zones z = {.snapshot = f->src, .scratch = f->scratch};
    bool ok = zcl_fri_trace_parse_dir(&t, dir_e, f->src) &&
              zcl_fri_trace_parse_dir(&t, dir_c, f->src);
    if (!ok) frp_fail(f->p, t.why, t.why_line);
    for (size_t i = 0; ok && i < t.count; i++) {
        const struct zcl_fri_access *x = &t.v[i];
        if (zcl_fri_classify(&z, x->path) != ZCL_FRI_C_TOOL) continue;
        if (x->state == ZCL_FRI_PRESENT) f->p->eq_present++;
        else f->p->eq_absent++;
        if (frp_equivalent(f, x)) continue;
        frp_name(f->p->mismatch, f->p->eq_mismatch, x->path);
        f->p->eq_mismatch++;
    }
    zcl_fri_trace_free(&t);
    return ok;
}

static bool frp_within(const char *path, const char *dir)
{
    size_t n = strlen(dir);
    return strncmp(path, dir, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

static bool frp_disjoint(const char *a, const char *b)
{
    return !frp_within(a, b) && !frp_within(b, a);
}

/* A fresh source image of `repo`, the compile's cwd. */
static bool frp_snapshot(struct frp *f, const char *repo)
{
    struct zcl_fri_image src;
    struct zcl_fri_roots roots;
    bool ok = zcl_fri_image_begin(&src, f->src, NULL) &&
              zcl_fri_build_source(&src, repo, f->profile) &&
              zcl_fri_image_finish(&src, &roots);
    if (!ok) frp_fail(f->p, src.why, src.why_path);
    zcl_fri_image_free(&src);
    return ok;
}

/* Leaks from the image run, then the host run's view against the image. */
static bool frp_traced_checks(struct frp *f, const char *ti)
{
    char te[PATH_MAX], tc[PATH_MAX];
    if (!frp_dir(te, f->scratch, "trace-host-e") ||
        !frp_dir(tc, f->scratch, "trace-host-c"))
        return frp_fail(f->p, ZCL_FRI_WHY_WRITE, f->scratch);
    return frp_leaks(f, ti) && frp_host_compile(f, "host-e", true, te) &&
           frp_host_compile(f, "host-c", false, tc) &&
           frp_equivalence(f, te, tc);
}

static bool frp_run(struct frp *f, const char *repo)
{
    char ti[PATH_MAX];
    bool traced = f->p->traced;
    if (!frp_snapshot(f, repo) || !frp_layout(f)) return false;
    if (traced && !frp_dir(ti, f->scratch, "trace-image"))
        return frp_fail(f->p, ZCL_FRI_WHY_WRITE, f->scratch);
    return frp_host_compile(f, "reference", false, NULL) &&
           frp_image_compile(f, traced ? ti : NULL) && frp_compare(f) &&
           (!traced || frp_traced_checks(f, ti));
}

bool zcl_fri_prove(const char *tool_image, const char *repo,
                   const char *profile, const char *scratch,
                   struct zcl_fri_proof *p)
{
    memset(p, 0, sizeof(*p));
    struct frp *f = zcl_calloc(1, sizeof(*f), "frp");
    if (!f) return frp_fail(p, ZCL_FRI_WHY_ALLOC, scratch);
    f->p = p;
    f->tool = tool_image;
    f->profile = profile;
    p->traced = zcl_fri_strace_available();
    bool ok = tool_image && tool_image[0] == '/' && scratch && scratch[0] == '/' &&
              frp_disjoint(tool_image, scratch) &&
              snprintf(f->scratch, sizeof(f->scratch), "%s", scratch) < PATH_MAX &&
              snprintf(f->src, sizeof(f->src), "%s/src", scratch) < PATH_MAX;
    if (!ok) frp_fail(p, ZCL_FRI_WHY_ARGS, scratch);
    else ok = frp_run(f, repo);
    free(f);
    return ok;
}
