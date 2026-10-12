/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Builds the fixed-result source, tool and check images. The tool
 *          image is the union of what strace saw both worker compiles use
 *          and what a static walk names (driver, cc1 and as with their
 *          loader and DSOs, specs, include directories and the full
 *          header dependency list), plus the jail's mount points and the
 *          pinned profile. Every path the compile probed and missed must
 *          stay missing in the image. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"
#include "fixed_result_contract.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char *const k_frb_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

/* The three pinned inputs; fixed_result_worker.c refuses any other bytes. */
static const struct { const char *path, *sha3; } k_frb_pins[] = {
    {ZCL_FR_SOURCE,
     "f8a4357fa0cd51537c90b476512c18869a940fd6442a1f140baacec1367a923a"},
    {"platform/modules/base/include/base/result.h",
     "e92c831f3170655fd955fcc8ca3ec7d886c7b15416e4c9045822bc87029fdd68"},
    {"platform/modules/base/include/base/format_attribute.h",
     "1667ffb42ea55553d38f931037cae523dfe61cabe6ec8a1f7c78b3b6b960d9be"},
};

/* Bind-mount targets the jail lays over the read-only tool image. */
static const char *const k_frb_mount_dirs[] = {"proc", "tmp", "work", "zclassic23"};

static bool frb_fail(struct zcl_fri_image *img, const char *why, const char *path)
{
    if (!img->why) {
        img->why = why;
        snprintf(img->why_path, sizeof(img->why_path), "%s", path ? path : "");
    }
    return false;
}

/* ── the worker's argv ───────────────────────────────────────────────── */

static const char *frb_profile_bytes(struct zcl_fri_argv *a, const char *path)
{
    uint8_t sha3[32];
    uint64_t size = 0;
    char hex[65];
    if (!zcl_fri_sha3_file(path, sha3, &size) || size == 0 || size > 65535u)
        return ZCL_FRI_WHY_PROFILE;
    zcl_hex_encode(sha3, 32u, hex);
    a->bytes = zcl_malloc((size_t)size + 1u, "frb_profile");
    if (!a->bytes) return ZCL_FRI_WHY_ALLOC;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t got = fd >= 0 ? read(fd, a->bytes, (size_t)size) : -1;
    if (fd >= 0) close(fd);
    if (got != (ssize_t)size || strcmp(hex, ZCL_FR_PROFILE_SHA3) != 0)
        return ZCL_FRI_WHY_PROFILE;
    zcl_sha3_256((const unsigned char *)a->bytes, (size_t)size, sha3);
    zcl_hex_encode(sha3, 32u, hex);
    if (strcmp(hex, ZCL_FR_PROFILE_SHA3) != 0 || a->bytes[size - 1] != '\n' ||
        memchr(a->bytes, '\0', (size_t)size)) return ZCL_FRI_WHY_PROFILE;
    a->bytes[size] = '\0';
    return NULL;
}

static const char *frb_profile_lines(struct zcl_fri_argv *a, const char *cwd)
{
    char *line = a->bytes;
    unsigned cwds = 0;
    for (char *p = a->bytes; *p; p++) {
        if (*p != '\n') continue;
        *p = '\0';
        if (!*line || a->argc == ZCL_FRI_PROFILE_ARGS) return ZCL_FRI_WHY_PROFILE;
        char *tag = strstr(line, "@CWD@");
        if (tag) {
            size_t head = (size_t)(tag - line);
            if (cwds++ || strstr(tag + 5, "@CWD@") ||
                snprintf(a->expanded, sizeof(a->expanded), "%.*s%s%s",
                         (int)head, line, cwd, tag + 5) >= (int)sizeof(a->expanded))
                return ZCL_FRI_WHY_PROFILE;
            line = a->expanded;
        }
        a->argv[a->argc++] = line;
        line = p + 1;
    }
    if (a->argc != ZCL_FRI_PROFILE_ARGS || cwds != 1 || strcmp(a->argv[0], "cc"))
        return ZCL_FRI_WHY_PROFILE;
    return NULL;
}

const char *zcl_fri_argv_make(struct zcl_fri_argv *a, const char *profile,
                              const char *cwd, const char *target,
                              const char *out, const char *dep,
                              bool preprocess)
{
    memset(a, 0, sizeof(*a));
    const char *why = frb_profile_bytes(a, profile);
    if (!why) why = frb_profile_lines(a, cwd);
    if (why) return why;
    if (!out) return NULL; /* profile only */
    /* fixed_result_worker.c gcc_args(): the same tail, in the same order. */
    char *tail[] = {"-MMD", "-MP", "-MF", (char *)dep, "-MT", (char *)target};
    for (size_t i = 0; i < sizeof(tail) / sizeof(*tail); i++)
        a->argv[a->argc++] = tail[i];
    if (preprocess) a->argv[a->argc++] = "-fno-working-directory";
    a->argv[a->argc++] = preprocess ? "-E" : "-c";
    a->argv[a->argc++] = "-o";
    a->argv[a->argc++] = (char *)out;
    a->argv[a->argc++] = ZCL_FR_SOURCE;
    a->argv[a->argc] = NULL;
    return NULL;
}

void zcl_fri_argv_free(struct zcl_fri_argv *a)
{
    free(a->bytes);
    memset(a, 0, sizeof(*a));
}

/* ── classification ─────────────────────────────────────────────────── */

static bool frb_under(const char *path, const char *dir)
{
    size_t n = dir ? strlen(dir) : 0;
    return n && strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static bool frb_ancestor(const char *path, const char *dir)
{
    if (!dir) return false;
    if (strcmp(path, "/") == 0) return true;
    size_t n = strlen(path);
    return strncmp(dir, path, n) == 0 && dir[n] == '/';
}

/* Lexical: collapses "//", "." and "..", never following a link. Only the
 * zone test uses it; tool paths are resolved physically. */
static void frb_normalize(const char *in, char out[PATH_MAX])
{
    size_t used = 0;
    out[0] = '\0';
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        const char *end = strchrnul(p, '/');
        size_t n = (size_t)(end - p);
        if (n == 2 && p[0] == '.' && p[1] == '.') {
            while (used && out[used - 1] != '/') used--;
            if (used) used--;
        } else if (n && !(n == 1 && p[0] == '.') && used + n + 2 < PATH_MAX) {
            out[used++] = '/';
            memcpy(out + used, p, n);
            used += n;
        }
        out[used] = '\0';
        p = end;
    }
    if (!used) snprintf(out, PATH_MAX, "/");
}

/* A traced name inside the process's own proc entry. This classifies
 * strings strace recorded; it reads nothing from proc itself. */
static bool frb_proc_self(const char *n)
{
    if (!frb_under(n, "/proc")) return false;
    const char *rest = n + strlen("/proc");
    return strncmp(rest, "/self", 5) == 0 && (rest[5] == '\0' || rest[5] == '/');
}

enum zcl_fri_class zcl_fri_classify(const struct zcl_fri_zones *z,
                                    const char *path)
{
    char n[PATH_MAX];
    frb_normalize(path, n);
    if (frb_under(n, z->image)) return ZCL_FRI_C_IMAGE;
    if (frb_under(n, z->snapshot)) return ZCL_FRI_C_SNAPSHOT;
    if (frb_under(n, z->scratch)) return ZCL_FRI_C_SCRATCH;
    if (frb_under(n, "/tmp")) return ZCL_FRI_C_TMP;
    if (strcmp(n, "/dev/null") == 0) return ZCL_FRI_C_DEV_NULL;
    if (frb_proc_self(n)) return ZCL_FRI_C_PROC_SELF;
    if (strcmp(n, "/etc/ld.so.cache") == 0) return ZCL_FRI_C_LOADER_CACHE;
    if (frb_ancestor(n, z->image) || frb_ancestor(n, z->snapshot) ||
        frb_ancestor(n, z->scratch)) return ZCL_FRI_C_ANCESTOR;
    return ZCL_FRI_C_TOOL;
}

/* ── source image ───────────────────────────────────────────────────── */

bool zcl_fri_build_source(struct zcl_fri_image *img, const char *repo,
                          const char *profile)
{
    struct zcl_fri_argv a;
    const char *why = zcl_fri_argv_make(&a, profile, ZCL_FR_CWD, NULL, NULL,
                                        NULL, false);
    bool ok = !why || frb_fail(img, why, profile);
    for (size_t i = 1; ok && i < a.argc; i++)
        if (strncmp(a.argv[i], "-I", 2) == 0 && a.argv[i][2] != '/')
            ok = zcl_fri_add_dir(img, a.argv[i] + 2);
    zcl_fri_argv_free(&a);
    for (size_t i = 0; ok && i < sizeof(k_frb_pins) / sizeof(*k_frb_pins); i++) {
        char host[PATH_MAX], hex[65];
        if (snprintf(host, sizeof(host), "%s/%s", repo, k_frb_pins[i].path)
                >= PATH_MAX) return frb_fail(img, ZCL_FRI_WHY_LIMIT, repo);
        ok = zcl_fri_add_copy(img, k_frb_pins[i].path, host);
        const struct zcl_fri_entry *e = ok ? zcl_fri_find(img, k_frb_pins[i].path)
                                           : NULL;
        if (e) zcl_hex_encode(e->sha3, 32u, hex);
        if (ok && strcmp(hex, k_frb_pins[i].sha3) != 0)
            ok = frb_fail(img, ZCL_FRI_WHY_PIN, host);
    }
    return ok;
}

/* ── tool image ─────────────────────────────────────────────────────── */

struct frb_paths { char **v; size_t count, cap; };

static bool frb_paths_add(struct frb_paths *s, const char *path)
{
    for (size_t i = 0; i < s->count; i++) if (strcmp(s->v[i], path) == 0) return true;
    if (s->count == s->cap) {
        size_t next = s->cap ? s->cap * 2u : 64u;
        char **grown = zcl_realloc(s->v, next * sizeof(*grown), "frb_paths");
        if (!grown) return false;
        s->v = grown;
        s->cap = next;
    }
    s->v[s->count] = zcl_strdup(path, "frb_path");
    return s->v[s->count++] != NULL;
}

static bool frb_paths_has(const struct frb_paths *s, const char *path)
{
    for (size_t i = 0; i < s->count; i++) if (strcmp(s->v[i], path) == 0) return true;
    return false;
}

static void frb_paths_free(struct frb_paths *s)
{
    for (size_t i = 0; i < s->count; i++) free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

struct frb_tool {
    struct zcl_fri_image *img;
    const char *profile;
    char scratch[PATH_MAX], src[PATH_MAX];
    struct zcl_fri_zones zones;
    struct frb_paths traced_files, static_files;
    struct zcl_fri_trace trace;
    struct zcl_fri_discovery *d;
};

static bool frb_subdir(char out[PATH_MAX], const char *base, const char *name)
{
    return snprintf(out, PATH_MAX, "%s/%s", base, name) < PATH_MAX &&
           mkdir(out, 0700) == 0;
}

/* Adds a host path; when it lands on a regular file, remembers that file. */
static bool frb_add_file(struct frb_tool *t, const char *path,
                         struct frb_paths *files)
{
    char physical[PATH_MAX];
    if (!zcl_fri_add_host_path(t->img, path, physical)) return false;
    const struct zcl_fri_entry *e = zcl_fri_find(t->img, physical + 1);
    if (e && e->kind == 'F' && !frb_paths_add(files, physical))
        return frb_fail(t->img, ZCL_FRI_WHY_ALLOC, physical);
    return true;
}

static bool frb_compile(struct frb_tool *t, bool preprocess, bool traced)
{
    char out[PATH_MAX], dep[PATH_MAX], err[PATH_MAX], dir[PATH_MAX], tr[PATH_MAX];
    const char *leaf = preprocess ? "out-e" : "out-c";
    if (!frb_subdir(dir, t->scratch, leaf) ||
        snprintf(out, sizeof(out), "%s/%s", dir, preprocess ? "result.i" : "result.o")
            >= PATH_MAX ||
        snprintf(dep, sizeof(dep), "%s/deps.d", dir) >= PATH_MAX ||
        snprintf(err, sizeof(err), "%s/stderr.bin", dir) >= PATH_MAX)
        return frb_fail(t->img, ZCL_FRI_WHY_WRITE, t->scratch);
    struct zcl_fri_argv a;
    const char *why = zcl_fri_argv_make(&a, t->profile, t->src, ZCL_FRI_TARGET,
                                        out, dep, preprocess);
    if (why) { zcl_fri_argv_free(&a); return frb_fail(t->img, why, t->profile); }
    struct zcl_fri_run r = {.argv = a.argv, .envp = k_frb_env,
                            .path = "/usr/bin/cc", .cwd = t->src,
                            .err_path = err};
    int code = -1;
    bool ran = traced
        ? (frb_subdir(tr, t->scratch, preprocess ? "trace-e" : "trace-c") &&
           zcl_fri_trace_run(&r, tr, &code))
        : zcl_fri_run_wait(&r, &code);
    zcl_fri_argv_free(&a);
    if (!ran) return frb_fail(t->img, ZCL_FRI_WHY_SPAWN, "/usr/bin/cc");
    if (code != 0) return frb_fail(t->img, ZCL_FRI_WHY_COMPILE, err);
    if (traced && !zcl_fri_trace_parse_dir(&t->trace, tr, t->src))
        return frb_fail(t->img, t->trace.why, t->trace.why_line);
    return true;
}

/* A traced tool path the compile found is materialized; one it wrote to
 * refuses. Zones outside the tool namespace are left to the jail. */
static bool frb_trace_apply(struct frb_tool *t)
{
    for (size_t i = 0; i < t->trace.count; i++) {
        const struct zcl_fri_access *x = &t->trace.v[i];
        enum zcl_fri_class c = zcl_fri_classify(&t->zones, x->path);
        if (x->write && c != ZCL_FRI_C_SCRATCH && c != ZCL_FRI_C_TMP &&
            c != ZCL_FRI_C_DEV_NULL)
            return frb_fail(t->img, ZCL_FRI_WHY_TRACE_WRITE, x->path);
        if (c != ZCL_FRI_C_TOOL) continue;
        if (x->state == ZCL_FRI_PRESENT) {
            if (!frb_add_file(t, x->path, &t->traced_files)) return false;
            t->d->trace_present++;
        } else {
            t->d->trace_absent++;
        }
    }
    return true;
}

static bool frb_query(struct frb_tool *t, const char *flag, char out[PATH_MAX])
{
    char path[PATH_MAX];
    char *argv[] = {"cc", (char *)flag, NULL};
    if (snprintf(path, sizeof(path), "%s/query.out", t->scratch) >= PATH_MAX)
        return false;
    struct zcl_fri_run r = {.argv = argv, .envp = k_frb_env,
                            .path = "/usr/bin/cc", .cwd = t->src, .out_path = path};
    int code = -1;
    if (!zcl_fri_run_wait(&r, &code) || code != 0) return false;
    FILE *f = fopen(path, "re");
    bool ok = f && fgets(out, PATH_MAX, f) != NULL;
    if (f) fclose(f);
    if (!ok) return false;
    out[strcspn(out, "\n")] = '\0';
    return out[0] != '\0';
}

static bool frb_static_seen(void *ctx, const char *physical)
{
    return frb_paths_add(&((struct frb_tool *)ctx)->static_files, physical);
}

static bool frb_static_programs(struct frb_tool *t)
{
    char cc1[PATH_MAX], as[PATH_MAX], specs[PATH_MAX];
    if (!frb_query(t, "-print-prog-name=cc1", cc1) || cc1[0] != '/' ||
        !frb_query(t, "-print-prog-name=as", as) ||
        !frb_query(t, "-print-file-name=specs", specs))
        return frb_fail(t->img, ZCL_FRI_WHY_COMPILE, "-print-prog-name");
    /* A bare "as" is found on PATH=/usr/bin:/bin, as the driver does. */
    if (as[0] != '/') {
        char name[NAME_MAX + 1];
        struct stat st;
        if (strchr(as, '/') || snprintf(name, sizeof(name), "%s", as) > NAME_MAX)
            return frb_fail(t->img, ZCL_FRI_WHY_COMPILE, as);
        snprintf(as, sizeof(as), "/usr/bin/%s", name);
        if (stat(as, &st) != 0) snprintf(as, sizeof(as), "/bin/%s", name);
    }
    t->d->specs_builtin = specs[0] != '/';
    const char *programs[] = {"/usr/bin/cc", cc1, as};
    for (size_t i = 0; i < 3; i++)
        if (!zcl_fri_add_elf_closure(t->img, programs[i], frb_static_seen, t))
            return false;
    return t->d->specs_builtin || frb_add_file(t, specs, &t->static_files);
}

/* "#include <...> search starts here:" through "End of search list." */
static bool frb_search_dirs(struct frb_tool *t, const char *err_path)
{
    FILE *f = fopen(err_path, "re");
    if (!f) return frb_fail(t->img, ZCL_FRI_WHY_COMPILE, err_path);
    char line[PATH_MAX + 16];
    bool inside = false, ok = true, ended = false;
    while (ok && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strstr(line, "search starts here:")) { inside = true; continue; }
        if (strcmp(line, "End of search list.") == 0) { ended = true; break; }
        if (inside && line[0] == ' ' && line[1] == '/')
            ok = zcl_fri_add_host_path(t->img, line + 1, NULL);
    }
    fclose(f);
    return ok && (ended || frb_fail(t->img, ZCL_FRI_WHY_COMPILE, err_path));
}

static bool frb_dep_tokens(struct frb_tool *t, const char *dep_path)
{
    FILE *f = fopen(dep_path, "re");
    if (!f) return frb_fail(t->img, ZCL_FRI_WHY_COMPILE, dep_path);
    char tok[PATH_MAX];
    bool ok = true, after_colon = false;
    while (ok && fscanf(f, "%4095s", tok) == 1) {
        if (!after_colon) { after_colon = tok[strlen(tok) - 1] == ':'; continue; }
        if (strcmp(tok, "\\") == 0 || tok[0] != '/') continue;
        ok = frb_add_file(t, tok, &t->static_files);
    }
    fclose(f);
    return ok && (after_colon || frb_fail(t->img, ZCL_FRI_WHY_COMPILE, dep_path));
}

/* -E -v for the search list, and -M for every header, system ones too. */
static bool frb_static_headers(struct frb_tool *t)
{
    char dir[PATH_MAX], err[PATH_MAX], dep[PATH_MAX];
    if (!frb_subdir(dir, t->scratch, "static") ||
        snprintf(err, sizeof(err), "%s/search.err", dir) >= PATH_MAX ||
        snprintf(dep, sizeof(dep), "%s/all.d", dir) >= PATH_MAX)
        return frb_fail(t->img, ZCL_FRI_WHY_WRITE, t->scratch);
    struct zcl_fri_argv a;
    const char *why = zcl_fri_argv_make(&a, t->profile, t->src, NULL, NULL,
                                        NULL, false);
    if (why) { zcl_fri_argv_free(&a); return frb_fail(t->img, why, t->profile); }
    size_t base = a.argc;
    char *verbose[] = {"-E", "-v", "-o", "/dev/null", ZCL_FR_SOURCE, NULL};
    char *deps[] = {"-M", "-MF", dep, "-MT", "x", "-o", "/dev/null",
                    ZCL_FR_SOURCE, NULL};
    bool ok = true;
    for (int pass = 0; ok && pass < 2; pass++) {
        char *const *tail = pass ? deps : verbose;
        a.argc = base;
        for (size_t i = 0; tail[i]; i++) a.argv[a.argc++] = tail[i];
        a.argv[a.argc] = NULL;
        struct zcl_fri_run r = {.argv = a.argv, .envp = k_frb_env,
                                .path = "/usr/bin/cc", .cwd = t->src,
                                .err_path = pass ? NULL : err};
        int code = -1;
        ok = zcl_fri_run_wait(&r, &code) && code == 0;
        if (!ok) frb_fail(t->img, ZCL_FRI_WHY_COMPILE, pass ? dep : err);
    }
    zcl_fri_argv_free(&a);
    return ok && frb_search_dirs(t, err) && frb_dep_tokens(t, dep);
}

static bool frb_jail_points(struct frb_tool *t)
{
    for (size_t i = 0; i < sizeof(k_frb_mount_dirs) / sizeof(*k_frb_mount_dirs); i++)
        if (!zcl_fri_add_dir(t->img, k_frb_mount_dirs[i])) return false;
    return zcl_fri_add_empty(t->img, "dev/null", 0444) &&
           zcl_fri_add_empty(t->img, "usr/local/libexec/z23-fixed-result-worker",
                             0555) &&
           zcl_fri_add_copy(t->img, "etc/z23verify/fixed_result_fast.args",
                            t->profile);
}

/* Every path the compile probed and missed must be missing in the image. */
static bool frb_absent_hold(struct frb_tool *t)
{
    for (size_t i = 0; i < t->trace.count; i++) {
        const struct zcl_fri_access *x = &t->trace.v[i];
        char rel[PATH_MAX];
        if (x->state != ZCL_FRI_ABSENT ||
            zcl_fri_classify(&t->zones, x->path) != ZCL_FRI_C_TOOL) continue;
        if (zcl_fri_image_lookup(t->img->root, x->path, rel) != 0)
            return frb_fail(t->img, ZCL_FRI_WHY_CONFLICT, x->path);
    }
    return true;
}

static void frb_cross_check(struct frb_tool *t)
{
    struct zcl_fri_discovery *d = t->d;
    d->static_files = (unsigned)t->static_files.count;
    for (size_t i = 0; t->d->traced && i < t->static_files.count; i++) {
        if (frb_paths_has(&t->traced_files, t->static_files.v[i])) continue;
        if (!d->static_only++)
            snprintf(d->static_only_first, PATH_MAX, "%s", t->static_files.v[i]);
    }
    for (size_t i = 0; i < t->traced_files.count; i++) {
        if (frb_paths_has(&t->static_files, t->traced_files.v[i])) continue;
        if (!d->trace_only++)
            snprintf(d->trace_only_first, PATH_MAX, "%s", t->traced_files.v[i]);
    }
}

static bool frb_tool_run(struct frb_tool *t, const char *repo, bool traced)
{
    struct zcl_fri_image src;
    struct zcl_fri_roots roots;
    bool ok = zcl_fri_image_begin(&src, t->src, NULL) &&
              zcl_fri_build_source(&src, repo, t->profile) &&
              zcl_fri_image_finish(&src, &roots);
    if (!ok) frb_fail(t->img, src.why, src.why_path);
    zcl_fri_image_free(&src);
    return ok && frb_compile(t, true, traced) && frb_compile(t, false, traced) &&
           frb_trace_apply(t) && frb_static_programs(t) &&
           frb_static_headers(t) && frb_jail_points(t) && frb_absent_hold(t);
}

bool zcl_fri_build_tool(struct zcl_fri_image *img, const char *profile,
                        const char *repo, const char *scratch,
                        bool allow_trace, struct zcl_fri_discovery *d)
{
    memset(d, 0, sizeof(*d));
    struct frb_tool *t = zcl_calloc(1, sizeof(*t), "frb_tool");
    if (!t) return frb_fail(img, ZCL_FRI_WHY_ALLOC, scratch);
    t->img = img;
    t->profile = profile;
    t->d = d;
    bool ok = snprintf(t->scratch, sizeof(t->scratch), "%s", scratch) < PATH_MAX &&
              snprintf(t->src, sizeof(t->src), "%s/src", scratch) < PATH_MAX;
    t->zones = (struct zcl_fri_zones){.snapshot = t->src, .scratch = t->scratch};
    d->traced = allow_trace && zcl_fri_strace_available();
    if (!ok) frb_fail(img, ZCL_FRI_WHY_LIMIT, scratch);
    else ok = frb_tool_run(t, repo, d->traced);
    if (ok) frb_cross_check(t);
    zcl_fri_trace_free(&t->trace);
    frb_paths_free(&t->traced_files);
    frb_paths_free(&t->static_files);
    free(t);
    return ok;
}

/* ── check image ────────────────────────────────────────────────────── */

static bool frb_check_name(const char *name, size_t n)
{
    if (n == 0 || n > 64 || (n <= 2 && name[0] == '.')) return false;
    return strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-_.") >= n;
}

bool zcl_fri_build_check(struct zcl_fri_image *img, char *const *specs,
                         size_t count)
{
    for (size_t i = 0; i < count; i++) {
        const char *eq = strchr(specs[i], '=');
        char rel[PATH_MAX];
        if (!eq || !frb_check_name(specs[i], (size_t)(eq - specs[i])) ||
            eq[1] != '/' ||
            snprintf(rel, sizeof(rel), "usr/local/libexec/%.*s",
                     (int)(eq - specs[i]), specs[i]) >= PATH_MAX)
            return frb_fail(img, ZCL_FRI_WHY_NAME, specs[i]);
        char interp[PATH_MAX];
        const char *why = NULL;
        if (!zcl_fri_elf_interp(eq + 1, interp, &why))
            return frb_fail(img, why, eq + 1);
        if (!zcl_fri_add_copy(img, rel, eq + 1)) return false;
        const struct zcl_fri_entry *e = zcl_fri_find(img, rel);
        if (!e || e->mode != 0555) return frb_fail(img, ZCL_FRI_WHY_SPECIAL, eq + 1);
        if (!zcl_fri_add_elf_deps(img, eq + 1)) return false;
    }
    return count > 0 || frb_fail(img, ZCL_FRI_WHY_ARGS, "check");
}
