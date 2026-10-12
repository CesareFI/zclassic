/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Declaration-identity consumer: the universe of TUs that read a changed file (manifests cross-checked against the depfile graph), and the plan and report it drives. */
#include "devloop_facts_consumer.h"

#include "codeindex/codeindex.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A scan deeper than this, or with more manifests than the report holds,
 * does not know its universe. */
#define FXC_SCAN_DEPTH 32
#define FXC_READERS_MAX 4096

/* ---- small shared helpers ---------------------------------------------------- */

bool fxc_strs_add(struct fxc_strs *s, const char *v)
{
    char *d;
    if (s->n == s->cap) {
        size_t next = s->cap ? s->cap * 2 : 32;
        char **g = zcl_realloc(s->v, next * sizeof(*g), "facts_consumer.strs");
        if (g == NULL)
            return false;
        s->v = g;
        s->cap = next;
    }
    d = zcl_malloc(strlen(v) + 1, "facts_consumer.str");
    if (d == NULL)
        return false;
    memcpy(d, v, strlen(v) + 1);
    s->v[s->n++] = d;
    return true;
}

bool fxc_strs_has(const struct fxc_strs *s, const char *v)
{
    for (size_t k = 0; k < s->n; k++)
        if (strcmp(s->v[k], v) == 0)
            return true;
    return false;
}

void fxc_strs_free(struct fxc_strs *s)
{
    for (size_t k = 0; k < s->n; k++)
        free(s->v[k]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

bool fxc_is_changed(const struct fxc *c, const char *path)
{
    for (size_t k = 0; k < c->nfiles; k++)
        if (strcmp(c->files[k], path) == 0)
            return true;
    return false;
}

struct fxc_hdr *fxc_hdr_of(struct fxc *c, const char *path)
{
    for (size_t k = 0; k < c->nfiles; k++)
        if (strcmp(c->files[k], path) == 0)
            return &c->hdrs[k];
    return NULL;
}

struct zcl_devloop_facts_tu_verdict *fxc_tu_new(struct fxc *c, const char *path)
{
    struct zcl_devloop_facts_report *r = c->report;
    struct zcl_devloop_facts_tu_verdict *t;
    if (r->ntus == c->captus) {
        size_t next = c->captus ? c->captus * 2 : 64;
        struct zcl_devloop_facts_tu_verdict *g =
            zcl_realloc(r->tus, next * sizeof(*g), "facts_consumer.tus");
        if (g == NULL)
            return NULL;
        r->tus = g;
        c->captus = next;
    }
    t = &r->tus[r->ntus++];
    memset(t, 0, sizeof(*t));
    (void)snprintf(t->path, sizeof(t->path), "%s", path);
    t->reason = "";
    t->action_reason = "";
    return t;
}

static struct zcl_devloop_facts_tu_verdict *fxc_tu_find(struct fxc *c,
                                                        const char *path)
{
    for (size_t k = 0; k < c->report->ntus; k++)
        if (strcmp(c->report->tus[k].path, path) == 0)
            return &c->report->tus[k];
    return NULL;
}

int fxc_readers(struct fxc *c, const char *path, char (*out)[256], int cap)
{
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int n;
    if (c->ci == NULL) {
        c->graph = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        return -1;
    }
    n = codeindex_reverse_includes(c->ci, path, out, cap, &dim);
    c->graph = (int)dim;
    return n < 0 || dim != CODEINDEX_INCLUDE_DIM_COMPLETE ? -1 : n;
}

/* ---- created and deleted paths ------------------------------------------------ */

static bool fxc_exists(const char *root, const char *dir, const char *file,
                       const char *suffix)
{
    char path[ZCL_DEVLOOP_PATH_MAX * 2 + 64];
    if (snprintf(path, sizeof(path), "%s/%s%s%s%s", root, dir ? dir : "",
                 dir ? "/" : "", file, suffix) >= (int)sizeof(path))
        return false;
    enum platform_file_shape shape = platform_file_shape_read(path);
    return shape != PLATFORM_FILE_SHAPE_MISSING &&
           shape != PLATFORM_FILE_SHAPE_UNREADABLE;
}

/* A changed path is created or deleted when the tree has nothing there now
 * or the facts directory holds no before text of it (a created path; or a
 * producer that saved none, which can only widen). */
static void fxc_note_moved(struct fxc *c)
{
    for (size_t k = 0; k < c->nfiles; k++)
        c->hdrs[k].moved =
            !fxc_exists(c->root, NULL, c->files[k], "") ||
            !fxc_exists(c->root, c->facts_dir, c->files[k], ".before");
}

/* ---- candidates: every after manifest under facts_dir ------------------------ */

static bool fxc_ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static bool fxc_scan(struct fxc *c, const char *rel, int depth);

static bool fxc_scan_entry(struct fxc *c, const char *rel, const char *name,
                           int depth)
{
    char child[ZCL_DEVLOOP_PATH_MAX], full[ZCL_DEVLOOP_PATH_MAX * 2];
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return true;
    if (snprintf(child, sizeof(child), "%s%s%s", rel, rel[0] ? "/" : "",
                 name) >= (int)sizeof(child) ||
        snprintf(full, sizeof(full), "%s/%s/%s", c->root, c->facts_dir,
                 child) >= (int)sizeof(full))
        return false;
    enum platform_file_shape shape = platform_file_shape_read(full);
    if (shape == PLATFORM_FILE_SHAPE_MISSING ||
        shape == PLATFORM_FILE_SHAPE_UNREADABLE)
        return false;
    if (shape == PLATFORM_FILE_SHAPE_OTHER) {
        if (platform_directory_probe_real(full) != PLATFORM_DIRECTORY_PROBE_OK)
            return false;
        return depth < FXC_SCAN_DEPTH && fxc_scan(c, child, depth + 1);
    }
    if (shape != PLATFORM_FILE_SHAPE_REGULAR ||
        !fxc_ends_with(child, ".after.zsm"))
        return true;
    child[strlen(child) - strlen(".after.zsm")] = '\0';
    return c->cand.n < ZCL_DEVLOOP_FACTS_TU_MAX && fxc_strs_add(&c->cand, child);
}

static bool fxc_scan(struct fxc *c, const char *rel, int depth)
{
    char dir[ZCL_DEVLOOP_PATH_MAX * 2];
    struct dirent *de;
    DIR *d;
    bool ok = true;
    if (snprintf(dir, sizeof(dir), "%s/%s%s%s", c->root, c->facts_dir,
                 rel[0] ? "/" : "", rel) >= (int)sizeof(dir))
        return false;
    d = opendir(dir);
    if (d == NULL)
        return depth == 0; /* no facts directory: no candidates */
    while (ok && (de = readdir(d)) != NULL)
        ok = fxc_scan_entry(c, rel, de->d_name, depth);
    (void)closedir(d);
    return ok;
}

static int fxc_str_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ---- the depfile cross-check ---------------------------------------------------- */

void fxc_incomplete(struct fxc *c, const char *reason, const char *path)
{
    struct zcl_devloop_facts_report *r = c->report;
    if (!r->complete)
        return;
    r->complete = false;
    r->reason = reason;
    (void)snprintf(r->detail, sizeof(r->detail), "%s", path);
}

static const char *fxc_graph_reason(const struct fxc *c)
{
    if (c->ci == NULL)
        return "no-code-index";
    return c->graph == CODEINDEX_INCLUDE_DIM_TRUNCATED
               ? "include-graph-truncated"
               : "include-graph-unavailable";
}

/* A TU the depfile graph says reads `file` that no manifest pair here
 * describes as reading it is affected: without facts nothing narrows it.
 * When `file` is a .c it compiles as an include, nothing names the
 * functions it defines from it either, so the universe is incomplete. */
static bool fxc_reader(struct fxc *c, const char *file, const char *reader)
{
    struct zcl_devloop_facts_tu_verdict *t;
    if (!fxc_ends_with(reader, ".c") || fxc_tu_find(c, reader) != NULL)
        return true;
    t = fxc_tu_new(c, reader);
    if (t == NULL)
        return false;
    t->affected = true;
    t->broadened = true;
    t->reason = fxc_strs_has(&c->cand, reader) ? "include-resolution-change"
                                               : "facts-missing";
    (void)snprintf(t->detail, sizeof(t->detail),
                   "the depfile graph says it reads %s", file);
    if (fxc_ends_with(file, ".c") && strcmp(file, reader) != 0)
        fxc_incomplete(c, t->reason, reader);
    return true;
}

static bool fxc_cross_check(struct fxc *c)
{
    char(*readers)[256] = zcl_calloc(FXC_READERS_MAX, 256, "facts_consumer.rd");
    bool ok = readers != NULL;
    for (size_t k = 0; ok && k < c->nfiles; k++) {
        int n = fxc_readers(c, c->files[k], readers, FXC_READERS_MAX);
        if (n < 0) {
            fxc_incomplete(c, fxc_graph_reason(c), c->files[k]);
            continue;
        }
        for (int i = 0; ok && i < n; i++)
            ok = fxc_reader(c, c->files[k], readers[i]);
    }
    free(readers);
    return ok;
}

/* ---- build inputs: changed files no compile records reading -------------------- */

/* A changed file that is not C text or prose: a makefile, a flag file, a
 * catalog, a script, a fixture. No manifest records reading it. */
static bool fxc_build_input(const char *path)
{
    return !fxc_ends_with(path, ".c") && !fxc_ends_with(path, ".h") &&
           !fxc_ends_with(path, ".md") && strncmp(path, "docs/", 5) != 0;
}

/* ---- build inputs: compiled, make-read, or data --------------------------------- */

/* The build inputs no manifest read and no depfile lists (want); *hit is
 * the first one the depfile graph cannot answer for. */
static bool fxc_unlisted(struct fxc *c, bool *want, const char **hit)
{
    char(*readers)[256] = zcl_calloc(FXC_READERS_MAX, 256, "facts_consumer.bi");
    if (readers == NULL)
        return false;
    for (size_t k = 0; *hit == NULL && k < c->nfiles; k++) {
        int n;
        if (c->hdrs[k].read || !fxc_build_input(c->files[k]))
            continue;
        n = fxc_readers(c, c->files[k], readers, FXC_READERS_MAX);
        if (n < 0)
            *hit = c->files[k];
        want[k] = n == 0;
    }
    free(readers);
    return true;
}

/* The first build input make reads, or the graph cannot answer for. A build
 * input a depfile lists is a compiled input: the cross-check and the header
 * path decide it, widening when it is unattributable. Any other is data no
 * compile reads; its path's groups stay in scope (fxc_data_groups). */
static bool fxc_make_hit(struct fxc *c, const char **hit)
{
    bool *want = zcl_calloc(2 * c->nfiles + 2, sizeof(*want), "facts_consumer.mk");
    bool *make, any = false;
    if (want == NULL || !fxc_unlisted(c, want, hit)) {
        free(want);
        return false;
    }
    make = want + c->nfiles + 1;
    for (size_t k = 0; k < c->nfiles; k++)
        any |= want[k];
    if (*hit == NULL && any)
        fxm_classify(c->root, c->files, want, make, c->nfiles, c->report);
    for (size_t k = 0; *hit == NULL && any && k < c->nfiles; k++)
        if (make[k])
            *hit = c->files[k];
    free(want);
    return true;
}

/* Every candidate is affected by a build input make reads, or one the
 * graph cannot place: nothing bounds what it changes, so the universe is
 * incomplete and every group is in scope. */
static bool fxc_build_inputs(struct fxc *c)
{
    const char *hit = NULL;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_OUTSIDER)
        return true;
#endif
    if (!fxc_make_hit(c, &hit))
        return false;
    if (hit == NULL)
        return true;
    fxc_incomplete(c, "build-input-changed", hit);
    c->universal = true;
    for (size_t k = 0; k < c->cand.n; k++) {
        struct zcl_devloop_facts_tu_verdict *t = fxc_tu_find(c, c->cand.v[k]);
        if (t == NULL && (t = fxc_tu_new(c, c->cand.v[k])) == NULL)
            return false;
        if (t->affected && !t->compile_only)
            continue;
        t->affected = t->broadened = true;
        t->compile_only = false;
        t->reason = "build-input-changed";
        (void)snprintf(t->detail, sizeof(t->detail), "%s", hit);
    }
    return true;
}

/* ---- the entry point ----------------------------------------------------------- */

static int fxc_tu_cmp(const void *a, const void *b)
{
    return strcmp(((const struct zcl_devloop_facts_tu_verdict *)a)->path,
                  ((const struct zcl_devloop_facts_tu_verdict *)b)->path);
}

static bool fxc_universe(struct fxc *c)
{
    struct zcl_devloop_facts_report *r = c->report;
    bool ok = fxc_scan(c, "", 0);
    if (!ok || c->cand.n >= ZCL_DEVLOOP_FACTS_TU_MAX)
        fxc_incomplete(c, "facts-scan-bounded", c->facts_dir);
    if (c->cand.n > 1)
        qsort(c->cand.v, c->cand.n, sizeof(*c->cand.v), fxc_str_cmp);
    fxc_note_moved(c);
    ok = true;
    for (size_t k = 0; ok && k < c->cand.n; k++)
        ok = fxc_tu_eval(c, c->cand.v[k]);
    ok = ok && fxc_build_inputs(c) && fxc_cross_check(c) &&
         fxc_name_collisions(c);
    if (c->mixed)
        fxc_incomplete(c, "producer-mismatch", "two producers in the universe");
    if (r->ntus > 1)
        qsort(r->tus, r->ntus, sizeof(*r->tus), fxc_tu_cmp);
    for (size_t k = 0; k < r->ntus; k++)
        r->naffected += r->tus[k].affected;
    r->applied = true;
    return ok;
}

static void fxc_free(struct fxc *c)
{
    for (size_t k = 0; c->hdrs != NULL && k < c->nfiles; k++) {
        free(c->hdrs[k].before);
        free(c->hdrs[k].after);
        fxh_free(&c->hdrs[k].diff);
    }
    free(c->hdrs);
    free(c->seeds);
    fxc_strs_free(&c->cand);
    fxc_strs_free(&c->address);
    fxc_strs_free(&c->new_ids);
    fxc_strs_free(&c->new_names);
    fxc_strs_free(&c->checked);
    if (c->ci != NULL)
        codeindex_close(c->ci);
}

/* The .c path's seeds against the declaring headers' readers: each seed is
 * a function of one changed file, found in that file's after manifest. */
static void fxc_c_decls(struct fxc *c, const struct zcl_devloop_facts_tu *tus,
                        const struct zcl_devloop_facts_verdict *v)
{
    for (size_t k = 0; c->seed_reason == NULL && k < c->nfiles; k++) {
        const char *why;
        struct fxi *x = tus[k].after != NULL
                            ? fxi_open(tus[k].after, tus[k].after_len, &why)
                            : NULL;
        for (size_t s = 0; x != NULL && s < v->seeds_len; s++) {
            size_t e;
            if (v->seed_ids[s][0] != '\0' && fxi_find(x, v->seed_ids[s], &e))
                fxc_check_decl(c, x, e);
        }
        fxi_free(x);
    }
}

/* The .c path: the per-function rule chain, then the seed checks only the
 * facts directory can make. A failed check restores the file-seeded plan. */
static bool fxc_c_path(struct fxc *c, const struct zcl_devloop_facts_tu *tus,
                       const struct zcl_devloop_plan *given,
                       struct zcl_devloop_plan *plan,
                       struct zcl_devloop_facts_verdict *v)
{
    struct zcl_devloop_facts_seed *s;
    if (!c->report->complete) /* the universe is not known: as the header path */
        return fxc_fallback(c, given, plan, v);
    if (!zcl_devloop_facts_add_closure_in(c->root, c->files, c->nfiles, tus,
                                          c->nfiles, c->facts_dir, plan, v))
        return false;
    if (!v->narrowed)
        return true;
    s = zcl_calloc(v->seeds_len + 1, sizeof(*s), "facts_consumer.cseeds");
    if (s == NULL)
        return false;
    for (size_t k = 0; k < v->seeds_len; k++) {
        (void)snprintf(s[k].name, sizeof(s[k].name), "%s", v->seeds[k]);
        (void)snprintf(s[k].id, sizeof(s[k].id), "%s", v->seed_ids[k]);
    }
    fxc_check_addresses(c, s, v->seeds_len);
    free(s);
    fxc_c_decls(c, tus, v);
    if (c->seed_reason == NULL)
        return fxc_c_members(c, given, plan, v);
    memcpy(plan, given, sizeof(*plan));
    v->narrowed = false;
    v->reason = c->seed_reason;
    (void)snprintf(v->detail, sizeof(v->detail), "%s", c->seed_detail);
    v->seeds_len = v->seeds_total = 0;
    return zcl_devloop_plan_add_closure(c->root, c->files, c->nfiles, plan);
}

static void fxc_reasons(struct fxc *c, const struct zcl_devloop_plan *plan,
                        const struct zcl_devloop_facts_verdict *v)
{
    struct zcl_devloop_facts_report *r = c->report;
    r->obligations_reason = v->narrowed ? "" : v->reason;
    r->path_reason = "path";
    for (size_t k = 0; k < plan->closure_groups_len; k++)
        if (r->group_reason[k] == NULL)
            r->group_reason[k] = v->narrowed ? "facts-closure" : "plain";
}

static bool fxc_args_ok(const char *const *files, size_t n,
                        const char *facts_dir,
                        const struct zcl_devloop_plan *plan,
                        const struct zcl_devloop_facts_verdict *verdict,
                        const struct zcl_devloop_facts_report *report)
{
    return plan != NULL && verdict != NULL && report != NULL &&
           facts_dir != NULL && (n == 0 || files != NULL);
}

bool zcl_devloop_facts_consume(const char *root, const char *const *files,
                               size_t n, const char *facts_dir,
                               const struct zcl_devloop_facts_tu *tus,
                               struct zcl_devloop_plan *plan,
                               struct zcl_devloop_facts_verdict *verdict,
                               struct zcl_devloop_facts_report *report)
{
    struct fxc c = {.root = root && root[0] ? root : ".", .facts_dir = facts_dir,
                    .files = files, .nfiles = n, .report = report};
    struct zcl_devloop_plan *given = NULL;
    bool ok;
    if (report != NULL)
        memset(report, 0, sizeof(*report));
    if (verdict != NULL)
        memset(verdict, 0, sizeof(*verdict));
    if (!fxc_args_ok(files, n, facts_dir, plan, verdict, report) ||
        (given = zcl_malloc(sizeof(*given), "facts.given")) == NULL)
        return false;
    report->reason = verdict->reason = "";
    report->complete = true;
    memcpy(given, plan, sizeof(*given));
    c.hdrs = zcl_calloc(n + 1, sizeof(*c.hdrs), "facts_consumer.hdrs");
    c.ci = codeindex_open(c.root);
    ok = c.hdrs != NULL && fxc_universe(&c);
    if (ok && tus != NULL)
        ok = fxc_c_path(&c, tus, given, plan, verdict);
    else if (ok)
        ok = fxc_obligations(&c, given, plan, verdict);
    ok = ok && fxc_plain_count(&c, given);
    if (ok)
        fxc_reasons(&c, plan, verdict);
    fxc_free(&c);
    free(given);
    return ok;
}

void zcl_devloop_facts_report_free(struct zcl_devloop_facts_report *report)
{
    if (report == NULL)
        return;
    free(report->tus);
    free(report->guards);
    report->guards = NULL;
    report->nguards = 0;
    memset(&report->make_premise, 0, sizeof(report->make_premise));
    report->tus = NULL;
    report->ntus = 0;
}

#if defined(ZCL_TESTING)
enum zcl_devloop_consumer_mutant zcl_devloop_test_consumer_mutant =
    ZCL_DEVLOOP_MUTANT_NONE;
#endif
