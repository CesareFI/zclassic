/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: one replayed commit. For commit C with parent P:
 *
 *   1. check out P, make every test-fast object, snapshot the objects and
 *      sense the TUs whose depfile names a changed file (before side);
 *   2. check out C, make again (the measured incremental build), snapshot,
 *      and sense the same bound at C (after side);
 *   3. plan the change with dev.change.plan, plain and with the facts;
 *   4. compare: what make recompiled, which object bytes changed, the plain
 *      compile set, the facts compile set, and every changed object the
 *      facts plan left out (a false negative);
 *   5. classify each changed object against its kept before object: code,
 *      or debug information only (the bytes agree after objcopy
 *      --strip-debug). A left-out object with changed code stops the run;
 *      a debug-only one is counted with the header line shifts behind it.
 *
 * The step writes run/<NN>_<C>/result.tsv and the sets behind it. */
#include "sem_replay_step.h"

#include "base/safe_alloc.h"
#include "sem_replay_record.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sem_replay_build.h"
#include "sem_replay_change.h"
#include "sem_replay_classify.h"
#include "sem_replay_plan.h"

#define SR_FACTS_REL "build/sem-replay/facts"

/* ── small helpers ────────────────────────────────────────────────────── */

static char **steal_argv(struct sr_strv *s)
{
    char **v = NULL;
    if (sr_strv_pushn(s, "", 0)) {
        free(s->v[s->n - 1]);
        s->v[s->n - 1] = NULL;
        v = s->v;
        memset(s, 0, sizeof(*s));
    }
    return v;
}

static const char *or_dash(const char *s)
{
    return s && s[0] ? s : "-";
}

static const char *basename_of(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* Words after the compiler words (the leading words without a '-'). */
static size_t first_flag(const struct sr_strv *flags)
{
    size_t i = 0;
    while (i < flags->n && flags->v[i][0] != '-')
        i++;
    return i;
}

static bool set_union(const struct sr_strv *a, const struct sr_strv *b,
                      struct sr_strv *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < a->n; i++)
        ok = sr_strv_push(out, a->v[i]);
    for (size_t i = 0; ok && i < b->n; i++)
        ok = sr_strv_push(out, b->v[i]);
    sr_strv_sort_unique(out);
    return ok;
}

/* out = a ∩ b, or a \ b when minus. */
static bool set_filter(const struct sr_strv *a, const struct sr_strv *b,
                       bool minus, struct sr_strv *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < a->n; i++)
        if (sr_strv_has(b, a->v[i]) != minus)
            ok = sr_strv_push(out, a->v[i]);
    sr_strv_sort_unique(out);
    return ok;
}

static bool snap_tus(const struct sr_snap *s, struct sr_strv *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < s->n; i++)
        ok = sr_strv_push(out, s->v[i].tu);
    sr_strv_sort_unique(out);
    return ok;
}

/* ── make ─────────────────────────────────────────────────────────────── */

/* The value make gives expr at the checked-out tree (one line, maybe
 * empty); false when make fails. */
static bool make_value(const struct sr_cfg *cfg, const char *log, const char *expr,
                       char out[SR_PATH])
{
    char rule[256];
    snprintf(rule, sizeof(rule), "zsr-print: ; @echo ZSR_VALUE=%s", expr);
    char *argv[] = {"make", "-s", "--no-print-directory", "--eval", rule, "zsr-print", NULL};
    char *text = NULL;
    size_t len = 0;
    int rc = sr_capture(argv, cfg->repo, log, &text, &len);
    const char *hit = text ? strstr(text, "ZSR_VALUE=") : NULL;
    bool ok = rc == 0 && hit != NULL;
    out[0] = '\0';
    if (ok) {
        snprintf(out, SR_PATH, "%s", hit + strlen("ZSR_VALUE="));
        out[strcspn(out, "\r\n")] = '\0';
    }
    if (rc != 0)
        fprintf(stderr, "sem-replay: make exited %d printing %s\n", rc, expr);
    free(text);
    return ok;
}

static bool fast_target(const struct sr_cfg *cfg, const char *log, char out[SR_PATH])
{
    bool ok = make_value(cfg, log, "$(TEST_PARALLEL_FAST_CANDIDATE)", out) && out[0] != '\0';
    if (!ok)
        fprintf(stderr, "sem-replay: cannot name the test-fast binary\n");
    return ok;
}

/* The build's toolchain identity (make's BUILD_COMPILER_ID), which `make
 * clang-facts` hands the sensor as --toolchain-id: 64 lowercase hex digits,
 * not all zero. Without it the sensor writes "object-cc unknown" into
 * IDENTITY and the planner broadens every TU that reads a changed file
 * (identity-drift), so the replay would measure a plan no real facts
 * directory produces. out is "" when make names none; the manifests then
 * say unknown, which only widens. */
static void toolchain_id(const struct sr_cfg *cfg, const char *log, char out[65])
{
    char v[SR_PATH];
    bool ok = make_value(cfg, log, "$(BUILD_COMPILER_ID)", v) && strlen(v) == 64;
    bool nonzero = false;
    for (size_t i = 0; ok && i < 64; i++) {
        ok = (v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f');
        nonzero = nonzero || v[i] != '0';
    }
    ok = ok && nonzero;
    snprintf(out, 65, "%s", ok ? v : "");
    if (!ok)
        fprintf(stderr, "sem-replay: make names no toolchain identity; the manifests "
                        "say object-cc unknown\n");
}

bool sr_make_objects(const struct sr_cfg *cfg, const char *log,
                     const struct sr_strv *what_if, struct sr_cost *cost)
{
    char rsp[SR_PATH], jobs[16];
    if (!fast_target(cfg, log, rsp))
        return false;
    snprintf(jobs, sizeof(jobs), "-j%d", cfg->jobs);
    struct sr_strv cmd = {0};
    bool ok = sr_strv_push(&cmd, "make") && sr_strv_push(&cmd, "--no-print-directory") &&
              sr_strv_push(&cmd, "-k") && sr_strv_push(&cmd, jobs);
    for (size_t i = 0; ok && what_if && i < what_if->n; i++)
        ok = sr_strv_push(&cmd, "-W") && sr_strv_push(&cmd, what_if->v[i]);
    ok = ok && sr_strv_push(&cmd, rsp);
    char **argv = ok ? steal_argv(&cmd) : NULL;
    char *env[] = {"ZCC_DISABLE=1", NULL};
    int rc = argv ? sr_run(argv, cfg->repo, log, env, cost) : -1;
    for (size_t i = 0; argv && argv[i]; i++)
        free(argv[i]);
    free(argv);
    sr_strv_free(&cmd);
    if (rc != 0)
        fprintf(stderr, "sem-replay: make exited %d (see %s)\n", rc, log);
    return rc == 0;
}

/* ── sensing and timed compiles ───────────────────────────────────────── */

/* The compiler word of an object's argv (the words before its first flag),
 * past a compile-cache wrapper, as the Makefile's ZCL_OBJECT_CC names it;
 * NULL when there is none. */
static const char *object_cc(const struct sr_strv *flags)
{
    for (size_t i = 0; i < first_flag(flags); i++) {
        const char *b = basename_of(flags->v[i]);
        if (strcmp(b, "zcc") != 0 && strcmp(b, "ccache") != 0 && strcmp(b, "sccache") != 0)
            return flags->v[i];
    }
    return NULL;
}

/* --toolchain-id (when make named one) and --cc (when the argv has a
 * compiler word), as `make clang-facts` passes them. */
static bool push_identity(struct sr_strv *a, const struct sr_strv *flags,
                          const char *toolchain)
{
    const char *cc = object_cc(flags);
    bool ok = true;
    if (toolchain != NULL && toolchain[0] != '\0')
        ok = sr_strv_push(a, "--toolchain-id") && sr_strv_push(a, toolchain);
    if (ok && cc != NULL)
        ok = sr_strv_push(a, "--cc") && sr_strv_push(a, cc);
    return ok;
}

/* The sensor as `make clang-facts` runs it: --cc names the object's
 * compiler and --toolchain-id the build's toolchain, so IDENTITY records
 * the compiler that built the object. */
static char **sensor_argv(const struct sr_cfg *cfg, const char *tu, const char *side,
                          const struct sr_strv *flags, const char *toolchain)
{
    char out[SR_PATH];
    snprintf(out, sizeof(out), "%s/%s/%s.%s.zsm", cfg->repo, SR_FACTS_REL, tu, side);
    if (!sr_mkparent(out))
        return NULL;
    const char *head[] = {cfg->sensor, "emit", "--root", ".", "--source", tu,
                          "--out", out, "--facts"};
    struct sr_strv a = {0};
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(head) / sizeof(head[0]); i++)
        ok = sr_strv_push(&a, head[i]);
    ok = ok && push_identity(&a, flags, toolchain) && sr_strv_push(&a, "--");
    for (size_t i = first_flag(flags); ok && i < flags->n; i++)
        ok = sr_strv_push(&a, flags->v[i]);
    char **v = ok ? steal_argv(&a) : NULL;
    sr_strv_free(&a);
    return v;
}

static char **compile_argv(const struct sr_strv *flags, const char *tu,
                           const char *obj)
{
    char dep[SR_PATH];
    snprintf(dep, sizeof(dep), "%s.d", obj);
    size_t i = flags->n > 0 && strcmp(basename_of(flags->v[0]), "zcc") == 0 ? 1 : 0;
    struct sr_strv a = {0};
    bool ok = true;
    for (; ok && i < flags->n; i++)
        ok = sr_strv_push(&a, flags->v[i]);
    ok = ok && sr_strv_push(&a, "-c") && sr_strv_push(&a, tu) &&
         sr_strv_push(&a, "-o") && sr_strv_push(&a, obj) &&
         sr_strv_push(&a, "-MMD") && sr_strv_push(&a, "-MP") &&
         sr_strv_push(&a, "-MF") && sr_strv_push(&a, dep);
    char **v = ok ? steal_argv(&a) : NULL;
    sr_strv_free(&a);
    return v;
}

struct batch {
    struct sr_task *t;
    char **side; /* "before", "after" or "compile" per task */
    char **obj;  /* compile output per task, or NULL */
    size_t n, cap;
};

static bool batch_add(struct batch *b, const char *tu, char **argv,
                      const char *side, const char *obj, const char *log)
{
    if (argv == NULL)
        return false;
    if (b->n == b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 256;
        struct sr_task *t = zcl_realloc(b->t, cap * sizeof(*t), "sem_replay_batch_t");
        char **s = t ? zcl_realloc(b->side, cap * sizeof(*s), "sem_replay_batch_side") : NULL;
        char **o = s ? zcl_realloc(b->obj, cap * sizeof(*o), "sem_replay_batch_obj") : NULL;
        b->t = t ? t : b->t;
        b->side = s ? s : b->side;
        b->obj = o ? o : b->obj;
        if (o == NULL) {
            fprintf(stderr, "sem-replay: out of memory growing a batch\n");
            return false;
        }
        b->cap = cap;
    }
    b->t[b->n] = (struct sr_task){.tu = tu, .argv = argv, .log = log, .rc = -1};
    b->side[b->n] = (char *)side;
    b->obj[b->n] = obj ? zcl_strdup(obj, "sem_replay_batch_obj_name") : NULL;
    b->n++;
    return true;
}

static void batch_free(struct batch *b)
{
    for (size_t i = 0; i < b->n; i++) {
        sr_task_free(&b->t[i]);
        free(b->obj[i]);
    }
    free(b->t);
    free(b->side);
    free(b->obj);
    memset(b, 0, sizeof(*b));
}

static bool add_sensing(const struct sr_cfg *cfg, struct batch *b,
                        const struct sr_strv *tus, const struct sr_argv_map *m,
                        const char *side, const char *toolchain,
                        const char *log)
{
    for (size_t i = 0; i < tus->n; i++) {
        const struct sr_strv *flags = sr_argv_find(m, tus->v[i]);
        if (flags == NULL) {
            fprintf(stderr, "sem-replay: no compile argv for %s (%s)\n", tus->v[i], side);
            continue; /* the planner sees no manifest and falls back */
        }
        if (!batch_add(b, tus->v[i], sensor_argv(cfg, tus->v[i], side, flags, toolchain),
                       side, NULL, log))
            return false;
    }
    return true;
}

static bool add_compiles(struct batch *b, const struct sr_strv *tus,
                         const struct sr_argv_map *m, const char *tmpdir,
                         const char *log)
{
    for (size_t i = 0; i < tus->n; i++) {
        const struct sr_strv *flags = sr_argv_find(m, tus->v[i]);
        char obj[SR_PATH];
        if (flags == NULL)
            continue;
        snprintf(obj, sizeof(obj), "%s/%zu.o", tmpdir, i);
        if (!batch_add(b, tus->v[i], compile_argv(flags, tus->v[i], obj),
                       "compile", obj, log))
            return false;
    }
    return true;
}

/* ── per-commit state ─────────────────────────────────────────────────── */

struct commit_run {
    char parent[64];
    char dir[SR_PATH];
    char log[SR_PATH];
    struct sr_change ch;
    struct sr_snap snap_p, snap_c;
    struct sr_strv tus_c, bound_p, bound_c;
    struct sr_strv make_set, changed, removed, plain, facts, fn, plain_fn;
    /* Selected but unchanged: TUs a plan picked whose object bytes did not
     * move against the parent's build (make skipped them, or recompiled
     * them byte-identical). fw_facts is facts \ changed, fw_plain is
     * plain \ changed; an over-selection, not a build-breaking miss. */
    struct sr_strv fw_facts, fw_plain;
    /* TUs whose compile argv differs between P and C (a build input such
     * as the source-identity stamp), and the false negatives split by it:
     * fn_flags changed through their argv, fn_source through their source. */
    struct sr_argv_map argv_p, argv_c;
    /* The toolchain identity make names at P and at C ("" when none). */
    char toolchain_p[65], toolchain_c[65];
    struct sr_strv drift, fn_flags, fn_source;
    /* "path\tTU" for each changed path a compile reads (both sides); the
     * changed objects outside drift by kind; fn_source split by kind (an
     * unknown kind counts as code). */
    struct sr_strv pairs, fn_code, fn_debug;
    struct sr_obj_kinds kinds;
    struct sr_sense_split sense;
    size_t inputs_n, inputs_read; /* changed paths other than .c/.h; read by a compile */
    struct sr_plan plain_plan, facts_plan;
    const char *facts_mode;
    struct sr_cost build_c;
    size_t sense_n, sense_fail;
    double sense_cpu, sense_wall;
    size_t repro_rebuilt, repro_mismatch, cold_checked, cold_mismatch;
    double cpu_make, cpu_facts, cpu_changed, saved_make, saved_plain;
    size_t cost_missing;
    /* 1: the after build failed; 2: the before build failed (a commit that
     * does not build its test-fast binary). Misses are then reported, not
     * stopped on. */
    int build_failed;
    /* The same commit planned with only the inputs a compile reads (.c and
     * .h files, and any other changed path some depfile names): what the
     * plan would be if it ignored changed files no compile reads. */
    struct {
        bool run;
        struct sr_strv files, set, fn, fn_source, fn_code, fn_debug;
        struct sr_plan plain, facts;
        const char *mode;
        double cpu_facts, saved_make;
    } cv;
};

static void commit_run_free(struct commit_run *r)
{
    sr_change_free(&r->ch);
    sr_snap_free(&r->snap_p);
    sr_snap_free(&r->snap_c);
    struct sr_strv *sets[] = {&r->tus_c, &r->bound_p, &r->bound_c, &r->make_set,
                              &r->changed, &r->removed, &r->plain, &r->facts,
                              &r->fn, &r->plain_fn, &r->drift, &r->fw_facts, &r->fw_plain,
                              &r->fn_flags, &r->fn_source, &r->pairs, &r->fn_code,
                              &r->fn_debug, &r->cv.fn_code, &r->cv.fn_debug};
    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++)
        sr_strv_free(sets[i]);
    sr_plan_free(&r->plain_plan);
    sr_plan_free(&r->facts_plan);
    sr_argv_free(&r->argv_p);
    sr_argv_free(&r->argv_c);
    sr_strv_free(&r->cv.files);
    sr_strv_free(&r->cv.set);
    sr_strv_free(&r->cv.fn);
    sr_strv_free(&r->cv.fn_source);
    sr_plan_free(&r->cv.plain);
    sr_plan_free(&r->cv.facts);
    sr_obj_kinds_free(&r->kinds);
}

/* ── compile cost table ───────────────────────────────────────────────── */

struct cost_row {
    char *tu;
    double cpu;
};

struct cost_table {
    struct cost_row *v;
    size_t n, cap;
};

static int cmp_cost(const void *a, const void *b)
{
    return strcmp(((const struct cost_row *)a)->tu, ((const struct cost_row *)b)->tu);
}

static bool cost_push(struct cost_table *t, const char *tu, double cpu)
{
    if (t->n == t->cap) {
        if (t->cap > SIZE_MAX / 2 ||
            (t->cap ? t->cap * 2 : 1024) > SIZE_MAX / sizeof(*t->v)) {
            fprintf(stderr, "sem-replay: cost table capacity overflow\n");
            return false;
        }
        size_t cap = t->cap ? t->cap * 2 : 1024;
        struct cost_row *v = zcl_realloc(t->v, cap * sizeof(*v), "sem_replay_cost_row");
        if (v == NULL) {
            fprintf(stderr, "sem-replay: out of memory in the cost table\n");
            return false;
        }
        t->v = v;
        t->cap = cap;
    }
    char *dup = zcl_strdup(tu, "sem_replay_cost_tu");
    if (dup == NULL) {
        fprintf(stderr, "sem-replay: out of memory in the cost table\n");
        return false;
    }
    t->v[t->n].tu = dup;
    t->v[t->n].cpu = cpu;
    t->n++;
    return true;
}

static bool cost_load(struct cost_table *t, const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[SR_PATH + 128], *tu;
    double cpu = 0;
    bool ok = true;
    int record = 0;
    while (fp != NULL && ok && (record = sr_record(fp, line, sizeof line)) > 0)
        ok = sr_record_cost(line, &tu, &cpu) && cost_push(t, tu, cpu);
    if (record < 0)
        ok = false;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    if (!ok)
        fprintf(stderr, "sem-replay: malformed cost record %s\n", path);
    if (t->n > 1)
        qsort(t->v, t->n, sizeof(*t->v), cmp_cost);
    return ok;
}

static const struct cost_row *cost_find(const struct cost_table *t, const char *tu)
{
    struct cost_row key = {.tu = (char *)tu};
    return t->n ? bsearch(&key, t->v, t->n, sizeof(*t->v), cmp_cost) : NULL;
}

static void cost_free(struct cost_table *t)
{
    for (size_t i = 0; i < t->n; i++)
        free(t->v[i].tu);
    free(t->v);
    memset(t, 0, sizeof(*t));
}

/* Sum of the known compile CPU over s; missing counts TUs without a row. */
static double cost_sum(const struct cost_table *t, const struct sr_strv *s,
                       size_t *missing)
{
    double sum = 0;
    for (size_t i = 0; i < s->n; i++) {
        const struct cost_row *row = cost_find(t, s->v[i]);
        if (row)
            sum += row->cpu;
        else if (missing)
            (*missing)++;
    }
    return sum;
}

/* ── the before side ──────────────────────────────────────────────────── */

static void path_in(char *out, size_t n, const struct sr_cfg *cfg, const char *name)
{
    snprintf(out, n, "%s/%s", cfg->state, name);
}

static void repro_compare(const struct sr_snap *prev, const struct sr_snap *now,
                          size_t *rebuilt, size_t *mismatch, FILE *log)
{
    if (strcmp(prev->epoch, now->epoch) != 0)
        return;
    for (size_t i = 0; i < now->n; i++) {
        const struct sr_obj *o = &now->v[i], *p = sr_snap_find(prev, o->tu);
        if (p == NULL || (p->ino == o->ino && p->mtime_ns == o->mtime_ns))
            continue;
        (*rebuilt)++;
        if (memcmp(p->hash, o->hash, 32) != 0) {
            (*mismatch)++;
            if (log)
                fprintf(log, "repro-mismatch\t%s\n", o->tu);
        }
    }
}

static bool sense_batch(const struct sr_cfg *cfg, struct commit_run *r,
                        struct batch *b)
{
    if (b->n == 0)
        return true;
    bool ok = sr_pool_run(b->t, b->n, cfg->jobs, cfg->repo);
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/tasks.tsv", r->dir);
    FILE *fp = fopen(path, "a");
    for (size_t i = 0; i < b->n; i++) {
        bool sense = b->obj[i] == NULL;
        if (fp)
            fprintf(fp, "%s\t%s\t%.4f\t%.4f\t%d\n", b->side[i], b->t[i].tu,
                    b->t[i].wall_s, b->t[i].cpu_s, b->t[i].rc);
        if (!sense)
            continue;
        r->sense_n++;
        r->sense_fail += b->t[i].rc != 0;
        r->sense_cpu += b->t[i].cpu_s;
        r->sense_wall += b->t[i].wall_s;
    }
    if (fp)
        fclose(fp);
    return ok;
}

static bool sense_side(const struct sr_cfg *cfg, struct commit_run *r,
                       const struct sr_strv *tus, const struct sr_argv_map *m,
                       const char *side)
{
    struct batch b = {0};
    const char *toolchain = strcmp(side, "before") == 0 ? r->toolchain_p : r->toolchain_c;
    bool ok = add_sensing(cfg, &b, tus, m, side, toolchain, r->log) && sense_batch(cfg, r, &b);
    batch_free(&b);
    return ok;
}

/* The compile argv of every object of snap, from one make -n. */
static bool argv_all(const struct sr_cfg *cfg, struct commit_run *r,
                     const struct sr_snap *snap, struct sr_argv_map *out)
{
    struct sr_strv tus = {0};
    bool ok = snap_tus(snap, &tus) && sr_make_argv(cfg->repo, snap->epoch, &tus, r->log, out);
    if (ok && out->tus.n != tus.n)
        fprintf(stderr, "sem-replay: make -n named %zu of %zu objects\n", out->tus.n, tus.n);
    sr_strv_free(&tus);
    return ok;
}

static bool save_before_sources(const struct sr_cfg *cfg, struct commit_run *r)
{
    bool ok = true;
    for (size_t i = 0; ok && i < r->ch.files.n; i++) {
        const char *f = r->ch.files.v[i];
        char dest[SR_PATH];
        if (sr_strv_has(&r->ch.added, f))
            continue;
        snprintf(dest, sizeof(dest), "%s/%s/%s.before", cfg->repo, SR_FACTS_REL, f);
        ok = sr_git_blob(cfg->repo, r->parent, f, dest);
    }
    return ok;
}

static bool reset_facts(const struct sr_cfg *cfg)
{
    char dir[SR_PATH];
    snprintf(dir, sizeof(dir), "%s/%s", cfg->repo, SR_FACTS_REL);
    return sr_rmtree(dir) && sr_mkdirs(dir);
}

/* The before objects, kept by link: the after build replaces them. */
static bool keep_before(const struct sr_cfg *cfg, const struct commit_run *r)
{
    char keep[SR_PATH];
    path_in(keep, sizeof(keep), cfg, "keep");
    return sr_keep_objects(cfg->repo, &r->snap_p, keep);
}

/* Check out P, make (a parent that does not build is recorded in
 * build_failed, not fatal), snapshot, and compare the objects the previous
 * step left at P (when it ended at P) as a reproducibility check. */
static bool build_before(const struct sr_cfg *cfg, struct commit_run *r)
{
    char last_snap[SR_PATH], last_commit[SR_PATH], *lc = NULL;
    size_t lcn = 0;
    struct sr_snap prev = {0};
    path_in(last_snap, sizeof(last_snap), cfg, "last.snap");
    path_in(last_commit, sizeof(last_commit), cfg, "last.commit");
    bool have_prev = sr_snap_load(&prev, last_snap) && sr_read_file(last_commit, &lc, &lcn);
    bool ok = sr_git_checkout(cfg->repo, r->parent, r->log);
    r->build_failed |= ok && !sr_make_objects(cfg, r->log, NULL, NULL) ? 2 : 0;
    if (ok)
        toolchain_id(cfg, r->log, r->toolchain_p);
    ok = ok && sr_snap_take(cfg->repo, have_prev ? &prev : NULL, &r->snap_p);
    if (ok && have_prev && strncmp(lc, r->parent, strlen(r->parent)) == 0)
        repro_compare(&prev, &r->snap_p, &r->repro_rebuilt, &r->repro_mismatch, stderr);
    free(lc);
    sr_snap_free(&prev);
    return ok;
}

static bool before_side(const struct sr_cfg *cfg, struct commit_run *r)
{
    size_t missing = 0;
    bool ok = build_before(cfg, r) &&
              sr_deps_hits(cfg->repo, &r->snap_p, &r->ch.files, &r->bound_p, &missing) &&
              sr_deps_pairs(cfg->repo, &r->snap_p, &r->ch.files, &r->pairs) &&
              keep_before(cfg, r) && argv_all(cfg, r, &r->snap_p, &r->argv_p) &&
              reset_facts(cfg) && sense_side(cfg, r, &r->bound_p, &r->argv_p, "before") &&
              save_before_sources(cfg, r);
    if (missing)
        fprintf(stderr, "sem-replay: %zu objects at %s have no depfile\n", missing, r->parent);
    return ok;
}

/* ── the after side ───────────────────────────────────────────────────── */

static bool compare_snaps(struct commit_run *r)
{
    bool epoch_moved = strcmp(r->snap_p.epoch, r->snap_c.epoch) != 0;
    bool ok = true;
    for (size_t i = 0; ok && i < r->snap_c.n; i++) {
        const struct sr_obj *o = &r->snap_c.v[i], *p = sr_snap_find(&r->snap_p, o->tu);
        bool rebuilt = epoch_moved || p == NULL || p->ino != o->ino || p->mtime_ns != o->mtime_ns;
        if (rebuilt)
            ok = sr_strv_push(&r->make_set, o->tu);
        if (ok && (p == NULL || memcmp(p->hash, o->hash, 32) != 0))
            ok = sr_strv_push(&r->changed, o->tu);
    }
    for (size_t i = 0; ok && i < r->snap_p.n; i++)
        if (sr_snap_find(&r->snap_c, r->snap_p.v[i].tu) == NULL)
            ok = sr_strv_push(&r->removed, r->snap_p.v[i].tu);
    if (epoch_moved)
        r->ch.kind = "build-system";
    return ok;
}

static void record_compiles(const struct sr_cfg *cfg, struct commit_run *r,
                            const struct batch *b)
{
    char path[SR_PATH];
    path_in(path, sizeof(path), cfg, "compile_cost.tsv");
    FILE *fp = fopen(path, "a");
    for (size_t i = 0; i < b->n; i++) {
        uint8_t h[32];
        if (b->obj[i] == NULL || b->t[i].rc != 0)
            continue;
        const struct sr_obj *o = sr_snap_find(&r->snap_c, b->t[i].tu);
        bool same = o && sr_hash_file(b->obj[i], h) && memcmp(h, o->hash, 32) == 0;
        r->cold_checked += o != NULL;
        r->cold_mismatch += o != NULL && !same;
        if (o && !same)
            fprintf(stderr, "sem-replay: cold compile differs from make's object: %s\n",
                    b->t[i].tu);
        if (fp)
            fprintf(fp, "%s\t%.4f\t%.4f\t%d\n", b->t[i].tu, b->t[i].cpu_s,
                    b->t[i].wall_s, same ? 1 : 0);
        (void)unlink(b->obj[i]);
    }
    if (fp)
        fclose(fp);
}

static bool after_batch(const struct sr_cfg *cfg, struct commit_run *r,
                        const struct sr_strv *timed)
{
    struct batch b = {0};
    char tmp[SR_PATH];
    snprintf(tmp, sizeof(tmp), "%s/tmp-obj", cfg->state);
    bool ok = sr_mkdirs(tmp) &&
              add_sensing(cfg, &b, &r->plain, &r->argv_c, "after", r->toolchain_c, r->log) &&
              add_compiles(&b, timed, &r->argv_c, tmp, r->log) && sense_batch(cfg, r, &b);
    if (ok)
        record_compiles(cfg, r, &b);
    batch_free(&b);
    return ok;
}

/* TUs that read a changed file only at C need a before manifest too. */
static bool extra_before(const struct sr_cfg *cfg, struct commit_run *r)
{
    struct sr_strv only_c = {0}, tus_p = {0}, extra = {0};
    bool ok = set_filter(&r->bound_c, &r->bound_p, true, &only_c) &&
              snap_tus(&r->snap_p, &tus_p) && set_filter(&only_c, &tus_p, false, &extra);
    if (ok && extra.n > 0) {
        fprintf(stderr, "sem-replay: %zu TUs read a changed file only after; sensing their before side\n",
                extra.n);
        ok = sr_git_checkout(cfg->repo, r->parent, r->log) &&
             sense_side(cfg, r, &extra, &r->argv_p, "before") &&
             sr_git_checkout(cfg->repo, cfg->commit, r->log);
    }
    sr_strv_free(&only_c);
    sr_strv_free(&tus_p);
    sr_strv_free(&extra);
    return ok;
}

static bool same_words(const struct sr_strv *a, const struct sr_strv *b)
{
    if (a->n != b->n)
        return false;
    for (size_t i = 0; i < a->n; i++)
        if (strcmp(a->v[i], b->v[i]) != 0)
            return false;
    return true;
}

/* TUs present on both sides whose compile argv changed. */
static bool find_drift(struct commit_run *r)
{
    bool ok = true;
    for (size_t i = 0; ok && i < r->argv_c.tus.n; i++) {
        const struct sr_strv *before = sr_argv_find(&r->argv_p, r->argv_c.tus.v[i]);
        if (before != NULL && !same_words(before, &r->argv_c.flags[i]))
            ok = sr_strv_push(&r->drift, r->argv_c.tus.v[i]);
    }
    sr_strv_sort_unique(&r->drift);
    return ok;
}

/* Check out C, make (timed), snapshot, and derive make's set, the changed
 * objects, the argv drift and the plain bound. */
static bool build_after(const struct sr_cfg *cfg, struct commit_run *r)
{
    size_t missing = 0;
    struct sr_strv bounds = {0};
    bool ok = sr_git_checkout(cfg->repo, cfg->commit, r->log);
    r->build_failed |= ok && !sr_make_objects(cfg, r->log, NULL, &r->build_c) ? 1 : 0;
    if (ok)
        toolchain_id(cfg, r->log, r->toolchain_c);
    ok = ok && sr_snap_take(cfg->repo, &r->snap_p, &r->snap_c) &&
         snap_tus(&r->snap_c, &r->tus_c) &&
         sr_deps_hits(cfg->repo, &r->snap_c, &r->ch.files, &r->bound_c, &missing) &&
         sr_deps_pairs(cfg->repo, &r->snap_c, &r->ch.files, &r->pairs) &&
         compare_snaps(r) && argv_all(cfg, r, &r->snap_c, &r->argv_c) && find_drift(r) &&
         set_union(&r->bound_p, &r->bound_c, &bounds) &&
         set_filter(&bounds, &r->tus_c, false, &r->plain);
    sr_strv_free(&bounds);
    return ok;
}

static bool after_side(const struct sr_cfg *cfg, struct commit_run *r,
                       const struct cost_table *costs)
{
    struct sr_strv want = {0}, timed = {0};
    bool ok = build_after(cfg, r) && set_union(&r->make_set, &r->plain, &want);
    for (size_t i = 0; ok && i < want.n; i++)
        if (cost_find(costs, want.v[i]) == NULL)
            ok = sr_strv_push(&timed, want.v[i]);
    ok = ok && after_batch(cfg, r, &timed) && extra_before(cfg, r);
    sr_strv_free(&want);
    sr_strv_free(&timed);
    return ok;
}

/* ── plans and the comparison ─────────────────────────────────────────── */

static bool is_c_or_h(const char *f)
{
    size_t n = strlen(f);
    return n > 2 && f[n - 2] == '.' && (f[n - 1] == 'c' || f[n - 1] == 'h');
}

/* A .c or .h file, or a changed path some compile's depfile names. */
static bool compiled_input(const struct commit_run *r, const char *f)
{
    return is_c_or_h(f) || sr_pairs_readers(&r->pairs, f) > 0;
}

static void plan_pair(const struct sr_cfg *cfg, const struct commit_run *r,
                      const struct sr_strv *files, const char *tag,
                      struct sr_plan *plain, struct sr_plan *facts)
{
    char plain_raw[SR_PATH], facts_raw[SR_PATH];
    snprintf(plain_raw, sizeof(plain_raw), "%s/plan-%splain", r->dir, tag);
    snprintf(facts_raw, sizeof(facts_raw), "%s/plan-%sfacts", r->dir, tag);
    bool a = sr_plan_run(cfg->planner, cfg->repo, files, NULL, plain_raw, plain);
    bool b = sr_plan_run(cfg->planner, cfg->repo, files, SR_FACTS_REL, facts_raw, facts);
    if (!a || !b)
        fprintf(stderr, "sem-replay: planner failed (%splain %d, facts %d): %s%s\n", tag,
                a, b, plain->error, facts->error);
}

/* A planner failure is a recorded outcome, not a stop. */
static bool plan_all(const struct sr_cfg *cfg, struct commit_run *r)
{
    plan_pair(cfg, r, &r->ch.files, "", &r->plain_plan, &r->facts_plan);
    for (size_t i = 0; i < r->ch.files.n; i++)
        if (compiled_input(r, r->ch.files.v[i]) && !sr_strv_push(&r->cv.files, r->ch.files.v[i]))
            return false;
    r->cv.run = r->cv.files.n > 0 && r->cv.files.n < r->ch.files.n;
    if (r->cv.run)
        plan_pair(cfg, r, &r->cv.files, "c-", &r->cv.plain, &r->cv.facts);
    return true;
}

/* The facts plan's compile set: the affected TUs of a complete universe;
 * every TU when the plan widens to the whole catalog; else the plain set
 * the plan fell back to. */
static bool compile_set_of(const struct sr_plan *f, const struct commit_run *r,
                           struct sr_strv *out, const char **mode)
{
    if (!f->ok) {
        *mode = "planner-error";
        return set_union(&r->plain, &r->plain, out);
    }
    if (f->uni_applied && f->uni_complete) {
        *mode = "precise";
        return set_filter(&f->tus_affected, &r->tus_c, false, out);
    }
    if (f->obl_plain_universal || f->closure_universal) {
        *mode = "universal";
        return set_union(&r->tus_c, &r->tus_c, out);
    }
    *mode = "fallback";
    return set_union(&r->plain, &r->plain, out);
}

static bool compare_c_variant(const struct cost_table *costs, struct commit_run *r)
{
    struct sr_strv make_minus = {0};
    if (!r->cv.run)
        return true;
    bool ok = compile_set_of(&r->cv.facts, r, &r->cv.set, &r->cv.mode) &&
              set_filter(&r->changed, &r->cv.set, true, &r->cv.fn) &&
              set_filter(&r->cv.fn, &r->drift, true, &r->cv.fn_source) &&
              set_filter(&r->make_set, &r->cv.set, true, &make_minus);
    r->cv.cpu_facts = cost_sum(costs, &r->cv.set, NULL);
    r->cv.saved_make = cost_sum(costs, &make_minus, NULL);
    for (size_t i = 0; i < r->cv.fn.n; i++)
        fprintf(stderr, "sem-replay: compiled-inputs variant leaves out changed object %s (%s, %s, %s)\n",
                r->cv.fn.v[i], r->cv.mode, or_dash(r->cv.facts.reason),
                sr_strv_has(&r->drift, r->cv.fn.v[i]) ? "argv changed" : "source changed");
    sr_strv_free(&make_minus);
    return ok;
}

static bool compare_sets(const struct cost_table *costs, struct commit_run *r)
{
    struct sr_strv make_minus = {0}, plain_minus = {0};
    bool ok = compile_set_of(&r->facts_plan, r, &r->facts, &r->facts_mode) &&
              set_filter(&r->changed, &r->facts, true, &r->fn) &&
              set_filter(&r->changed, &r->plain, true, &r->plain_fn) &&
              set_filter(&r->facts, &r->changed, true, &r->fw_facts) &&
              set_filter(&r->plain, &r->changed, true, &r->fw_plain) &&
              set_filter(&r->make_set, &r->facts, true, &make_minus) &&
              set_filter(&r->plain, &r->facts, true, &plain_minus) &&
              set_filter(&r->fn, &r->drift, false, &r->fn_flags) &&
              set_filter(&r->fn, &r->drift, true, &r->fn_source) &&
              compare_c_variant(costs, r);
    r->cpu_make = cost_sum(costs, &r->make_set, &r->cost_missing);
    r->cpu_facts = cost_sum(costs, &r->facts, NULL);
    r->cpu_changed = cost_sum(costs, &r->changed, NULL);
    r->saved_make = cost_sum(costs, &make_minus, NULL);
    r->saved_plain = cost_sum(costs, &plain_minus, NULL);
    sr_strv_free(&make_minus);
    sr_strv_free(&plain_minus);
    return ok;
}

static void write_set(FILE *fp, const char *name, const struct sr_strv *s)
{
    for (size_t i = 0; i < s->n; i++)
        fprintf(fp, "%s\t%s\n", name, s->v[i]);
}

static bool write_sets(const struct commit_run *r)
{
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/sets.tsv", r->dir);
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "sem-replay: write %s: %s\n", path, strerror(errno));
        return false;
    }
    write_set(fp, "file", &r->ch.files);
    write_set(fp, "make", &r->make_set);
    write_set(fp, "changed", &r->changed);
    write_set(fp, "removed", &r->removed);
    write_set(fp, "plain", &r->plain);
    write_set(fp, "facts", &r->facts);
    write_set(fp, "fn", &r->fn);
    write_set(fp, "fn_source", &r->fn_source);
    write_set(fp, "fn_flags", &r->fn_flags);
    write_set(fp, "drift", &r->drift);
    write_set(fp, "plain_fn", &r->plain_fn);
    write_set(fp, "tu", &r->facts_plan.tu_rows);
    write_set(fp, "plain_group", &r->plain_plan.groups);
    write_set(fp, "facts_group", &r->facts_plan.groups);
    write_set(fp, "obligation_group", &r->facts_plan.obl_groups);
    write_set(fp, "c_file", &r->cv.files);
    write_set(fp, "c_facts", &r->cv.set);
    write_set(fp, "c_fn", &r->cv.fn);
    write_set(fp, "c_fn_source", &r->cv.fn_source);
    write_set(fp, "c_tu", &r->cv.facts.tu_rows);
    write_set(fp, "code", &r->kinds.code);
    write_set(fp, "debug", &r->kinds.debug);
    write_set(fp, "unknown", &r->kinds.unknown);
    write_set(fp, "fn_code", &r->fn_code);
    write_set(fp, "fn_debug", &r->fn_debug);
    write_set(fp, "c_fn_code", &r->cv.fn_code);
    write_set(fp, "c_fn_debug", &r->cv.fn_debug);
    write_set(fp, "fw_facts", &r->fw_facts);
    write_set(fp, "fw_plain", &r->fw_plain);
    return fclose(fp) == 0;
}

const char *const sr_result_header =
    "idx\tcommit\tkind\tfiles\tc\th\tother\tmake\tchanged\tremoved\tplain\tfacts\t"
    "facts_mode\tfn\tplain_fn\tgroups_plain\tgroups_facts\tobl_plain\tobl_facts\t"
    "narrowed\treason\tobl_reason\tuni_complete\tuni_reason\tuni_total\t"
    "uni_affected\tbuild_wall\tbuild_cpu\tsense_n\tsense_fail\tsense_cpu\t"
    "sense_wall\tcpu_make\tcpu_facts\tcpu_changed\tsaved_make\tsaved_plain\tcost_missing\t"
    "repro_rebuilt\trepro_mismatch\tcold_checked\tcold_mismatch\tbuild_failed\tdrift\tfn_source\tfn_flags\t"
    "c_run\tc_files\tc_facts\tc_mode\tc_fn\tc_groups_plain\tc_groups_facts\t"
    "c_obl_facts\tc_narrowed\tc_reason\tc_uni_reason\tc_cpu_facts\tc_saved_make\tc_fn_source\t"
    "code_changed\tdebug_changed\tunknown_changed\tfn_code\tfn_debug\tc_fn_code\tc_fn_debug\t"
    "sense_after_n\tsense_after_cpu\tsense_make_n\tsense_make_cpu\tsense_aff_n\tsense_aff_cpu\t"
    "sense_zsm_n\tsense_zsm_cpu\tinputs_n\tinputs_read\tfw_facts\tfw_plain\n";

/* The compiled-inputs variant's columns (without a separate plan they
 * repeat the whole commit's), then the object kinds, the sensor split and
 * the changed inputs. */
static void write_tail(FILE *fp, const struct commit_run *r)
{
    bool run = r->cv.run;
    const struct sr_plan *p = run ? &r->cv.plain : &r->plain_plan;
    const struct sr_plan *f = run ? &r->cv.facts : &r->facts_plan;
    fprintf(fp, "%d\t%zu\t%zu\t%s\t%zu\t%ld\t%ld\t%ld\t%d\t%s\t%s\t%.3f\t%.3f\t%zu\t", run,
            run ? r->cv.files.n : r->ch.files.n, run ? r->cv.set.n : r->facts.n,
            run ? r->cv.mode : r->facts_mode, run ? r->cv.fn.n : r->fn.n, p->groups_total,
            f->groups_total, f->obl_facts, f->narrowed, or_dash(f->reason),
            or_dash(f->uni_reason), run ? r->cv.cpu_facts : r->cpu_facts,
            run ? r->cv.saved_make : r->saved_make, run ? r->cv.fn_source.n : r->fn_source.n);
    fprintf(fp, "%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t", r->kinds.code.n, r->kinds.debug.n,
            r->kinds.unknown.n, r->fn_code.n, r->fn_debug.n, run ? r->cv.fn_code.n : r->fn_code.n,
            run ? r->cv.fn_debug.n : r->fn_debug.n);
    fprintf(fp, "%zu\t%.3f\t%zu\t%.3f\t%zu\t%.3f\t%zu\t%.3f\t%zu\t%zu\t%zu\t%zu\n", r->sense.after_n,
            r->sense.after_cpu, r->sense.make_n, r->sense.make_cpu, r->sense.affected_n,
            r->sense.affected_cpu, r->sense.manifest_n, r->sense.manifest_cpu, r->inputs_n,
            r->inputs_read, r->fw_facts.n, r->fw_plain.n);
}

static bool write_result(const struct sr_cfg *cfg, const struct commit_run *r)
{
    char path[SR_PATH];
    const struct sr_plan *p = &r->plain_plan, *f = &r->facts_plan;
    snprintf(path, sizeof(path), "%s/result.tsv", r->dir);
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "sem-replay: write %s: %s\n", path, strerror(errno));
        return false;
    }
    fputs(sr_result_header, fp);
    fprintf(fp, "%d\t%.10s\t%s\t%zu\t%zu\t%zu\t%zu\t", cfg->index, cfg->commit,
            r->ch.kind, r->ch.files.n, r->ch.n_c, r->ch.n_h, r->ch.n_other);
    fprintf(fp, "%zu\t%zu\t%zu\t%zu\t%zu\t%s\t%zu\t%zu\t", r->make_set.n, r->changed.n,
            r->removed.n, r->plain.n, r->facts.n, r->facts_mode, r->fn.n, r->plain_fn.n);
    fprintf(fp, "%ld\t%ld\t%ld\t%ld\t%d\t%s\t%s\t%d\t%s\t%ld\t%ld\t", p->groups_total,
            f->groups_total, f->obl_plain, f->obl_facts, f->narrowed, or_dash(f->reason),
            or_dash(f->obl_reason), f->uni_complete, or_dash(f->uni_reason), f->uni_total,
            f->uni_affected);
    fprintf(fp, "%.3f\t%.3f\t%zu\t%zu\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%zu\t",
            r->build_c.wall_s, r->build_c.cpu_s, r->sense_n, r->sense_fail, r->sense_cpu,
            r->sense_wall, r->cpu_make, r->cpu_facts, r->cpu_changed, r->saved_make, r->saved_plain,
            r->cost_missing);
    fprintf(fp, "%zu\t%zu\t%zu\t%zu\t%d\t", r->repro_rebuilt, r->repro_mismatch,
            r->cold_checked, r->cold_mismatch, r->build_failed);
    fprintf(fp, "%zu\t%zu\t%zu\t", r->drift.n, r->fn_source.n, r->fn_flags.n);
    write_tail(fp, r);
    return fclose(fp) == 0;
}

/* ── object kinds, changed inputs and line shifts ────────────────────── */

/* Classify the changed objects outside drift against the kept before
 * objects, then split each plan's source misses by kind. */
static bool classify_misses(const struct sr_cfg *cfg, struct commit_run *r)
{
    struct sr_strv tus = {0};
    char keep[SR_PATH], tmp[SR_PATH];
    path_in(keep, sizeof(keep), cfg, "keep");
    path_in(tmp, sizeof(tmp), cfg, "tmp-obj");
    bool ok = set_filter(&r->changed, &r->drift, true, &tus) &&
              sr_classify_objects(cfg->repo, &r->snap_p, &r->snap_c, keep, tmp, &tus, r->log,
                                  &r->kinds) &&
              set_filter(&r->fn_source, &r->kinds.debug, true, &r->fn_code) &&
              set_filter(&r->fn_source, &r->kinds.debug, false, &r->fn_debug) &&
              set_filter(&r->cv.fn_source, &r->kinds.debug, true, &r->cv.fn_code) &&
              set_filter(&r->cv.fn_source, &r->kinds.debug, false, &r->cv.fn_debug);
    sr_strv_free(&tus);
    return ok;
}

static bool split_sensing(const struct sr_cfg *cfg, struct commit_run *r)
{
    char tasks[SR_PATH], facts[SR_PATH];
    snprintf(tasks, sizeof(tasks), "%s/tasks.tsv", r->dir);
    snprintf(facts, sizeof(facts), "%s/%s", cfg->repo, SR_FACTS_REL);
    return sr_sense_split(tasks, facts, &r->make_set, &r->facts_plan.tus_affected, &r->sense);
}

/* Does the plan's fallback detail name path ("path" or "path: why")? */
static int names(const struct sr_plan *p, const char *path)
{
    size_t n = strlen(path);
    const char *d[] = {p->detail, p->uni_detail};
    for (size_t i = 0; i < 2; i++)
        if (strncmp(d[i], path, n) == 0 && (d[i][n] == '\0' || d[i][n] == ':'))
            return 1;
    return 0;
}

static bool write_tu_shifts(const struct sr_cfg *cfg, const struct commit_run *r,
                            const char *tu, FILE *fp)
{
    struct sr_strv reads = {0};
    bool ok = sr_pairs_reads(&r->pairs, tu, &reads);
    sr_strv_sort_unique(&reads);
    for (size_t j = 0; ok && j < reads.n; j++) {
        char shifts[256];
        ok = sr_line_shifts(cfg->repo, r->parent, cfg->commit, reads.v[j], shifts,
                            sizeof(shifts));
        fprintf(fp, "%s\t%s\t%s\n", tu, reads.v[j], shifts[0] ? shifts : "-");
    }
    sr_strv_free(&reads);
    return ok;
}

/* shifts.tsv: for each debug-only miss, the changed files it reads and the
 * hunks in them that shift the lines below. */
static bool write_shifts(const struct sr_cfg *cfg, const struct commit_run *r)
{
    struct sr_strv tus = {0};
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/shifts.tsv", r->dir);
    FILE *fp = fopen(path, "w");
    bool ok = fp != NULL && set_union(&r->fn_debug, &r->cv.fn_debug, &tus);
    for (size_t i = 0; ok && i < tus.n; i++)
        ok = write_tu_shifts(cfg, r, tus.v[i], fp);
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    sr_strv_free(&tus);
    return ok;
}

/* inputs.tsv: each changed path other than .c and .h, what it is, how many
 * compiles read it, and whether a plan named it as its fallback cause. */
static bool write_inputs(const struct sr_cfg *cfg, const struct commit_run *r)
{
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/inputs.tsv", r->dir);
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "sem-replay: write %s: %s\n", path, strerror(errno));
        return false;
    }
    fputs("file\tclass\treaders\tnamed\tnamed_variant\n", fp);
    for (size_t i = 0; i < r->ch.files.n; i++) {
        const char *f = r->ch.files.v[i];
        if (is_c_or_h(f))
            continue;
        fprintf(fp, "%s\t%s\t%zu\t%d\t%d\n", f, sr_input_class(f),
                sr_pairs_readers(&r->pairs, f), names(&r->facts_plan, f),
                r->cv.run ? names(&r->cv.facts, f) : 0);
    }
    return fclose(fp) == 0 && write_shifts(cfg, r);
}

static size_t count_unread(const struct commit_run *r, size_t *read)
{
    size_t n = 0;
    *read = 0;
    for (size_t i = 0; i < r->ch.files.n; i++) {
        if (is_c_or_h(r->ch.files.v[i]))
            continue;
        n++;
        *read += sr_pairs_readers(&r->pairs, r->ch.files.v[i]) > 0;
    }
    return n;
}

static void log_misses(FILE *fp, const struct sr_cfg *cfg, const struct sr_strv *s,
                       const char *what, const char *mode, const struct sr_plan *p)
{
    for (size_t i = 0; i < s->n; i++) {
        fprintf(stderr, "sem-replay: %s: commit %s TU %s (facts %s, reason %s)\n", what,
                cfg->commit, s->v[i], or_dash(mode), or_dash(p->reason));
        if (fp)
            fprintf(fp, "%s\t%s\t%s\t%s\t%s\n", cfg->commit, s->v[i], what, or_dash(mode),
                    or_dash(p->reason));
    }
}

/* Every miss goes to MISSES.tsv. A code miss of the real plan keeps the
 * facts directory for the reproduction. */
static void report_misses(const struct sr_cfg *cfg, const struct commit_run *r)
{
    char path[SR_PATH], keep[SR_PATH], facts[SR_PATH];
    path_in(path, sizeof(path), cfg, "MISSES.tsv");
    FILE *fp = fopen(path, "a");
    log_misses(fp, cfg, &r->fn_code, "FALSE NEGATIVE (code)", r->facts_mode, &r->facts_plan);
    log_misses(fp, cfg, &r->fn_debug, "debug-only miss", r->facts_mode, &r->facts_plan);
    log_misses(fp, cfg, &r->cv.fn_code, "compiled-inputs variant: code miss", r->cv.mode,
               &r->cv.facts);
    log_misses(fp, cfg, &r->cv.fn_debug, "compiled-inputs variant: debug-only miss",
               r->cv.mode, &r->cv.facts);
    if (fp)
        fclose(fp);
    if (r->fn_code.n == 0)
        return;
    snprintf(facts, sizeof(facts), "%s/%s", cfg->repo, SR_FACTS_REL);
    snprintf(keep, sizeof(keep), "%s/facts", r->dir);
    if (rename(facts, keep) != 0)
        fprintf(stderr, "sem-replay: keep %s: %s\n", facts, strerror(errno));
}

static bool save_last(const struct sr_cfg *cfg, const struct commit_run *r)
{
    char snap[SR_PATH], commit[SR_PATH];
    path_in(snap, sizeof(snap), cfg, "last.snap");
    path_in(commit, sizeof(commit), cfg, "last.commit");
    return sr_snap_save(&r->snap_c, snap) &&
           sr_write_file(commit, cfg->commit, strlen(cfg->commit));
}

static bool step_dirs(const struct sr_cfg *cfg, struct commit_run *r)
{
    snprintf(r->dir, sizeof(r->dir), "%s/run/%03d_%.10s", cfg->state, cfg->index,
             cfg->commit);
    snprintf(r->log, sizeof(r->log), "%s/step.log", r->dir);
    return sr_mkdirs(r->dir);
}

/* Build, sense, plan, compare and write one step; false on a failure. */
static bool step_body(const struct sr_cfg *cfg, struct commit_run *r)
{
    struct cost_table costs = {0};
    char cost_path[SR_PATH];
    path_in(cost_path, sizeof(cost_path), cfg, "compile_cost.tsv");
    bool ok = step_dirs(cfg, r) && sr_git_parent(cfg->repo, cfg->commit, r->parent) &&
              sr_change_load(cfg->repo, r->parent, cfg->commit, &r->ch) &&
              cost_load(&costs, cost_path) && before_side(cfg, r) &&
              after_side(cfg, r, &costs);
    cost_free(&costs); /* after_side appended the TUs it timed */
    ok = ok && cost_load(&costs, cost_path) && plan_all(cfg, r) &&
         compare_sets(&costs, r) && classify_misses(cfg, r) && split_sensing(cfg, r);
    cost_free(&costs);
    r->inputs_n = count_unread(r, &r->inputs_read);
    return ok && write_sets(r) && write_inputs(cfg, r) && write_result(cfg, r) &&
           save_last(cfg, r);
}

int sr_step(const struct sr_cfg *cfg)
{
    struct commit_run r = {0};
    bool ok = step_body(cfg, &r);
    int rc = ok ? SR_STEP_OK : SR_STEP_FAILED;
    if (ok && r.fn_source.n + r.cv.fn_source.n > 0)
        report_misses(cfg, &r);
    if (ok && r.fn_code.n > 0 && !r.build_failed)
        rc = SR_STEP_FALSE_NEGATIVE;
    fprintf(stderr, "sem-replay: step %d %s %s: make %zu changed %zu (code %zu, debug %zu, "
                    "unknown %zu) plain %zu facts %zu (%s) fn code %zu debug %zu argv %zu\n",
            cfg->index, cfg->commit, ok ? r.ch.kind : "FAILED", r.make_set.n, r.changed.n,
            r.kinds.code.n, r.kinds.debug.n, r.kinds.unknown.n, r.plain.n, r.facts.n,
            r.facts_mode ? r.facts_mode : "-", r.fn_code.n, r.fn_debug.n, r.fn_flags.n);
    commit_run_free(&r);
    return rc;
}

/* ── reproducibility: rebuild every object and compare its bytes ─────── */

int sr_repro(const struct sr_cfg *cfg, const char *label)
{
    struct sr_snap a = {0}, b = {0};
    struct sr_strv tus = {0};
    size_t rebuilt = 0, mismatch = 0;
    char log[SR_PATH], out[SR_PATH];
    snprintf(log, sizeof(log), "%s/repro-%s.log", cfg->state, label);
    snprintf(out, sizeof(out), "%s/repro-%s.tsv", cfg->state, label);
    bool ok = sr_snap_take(cfg->repo, NULL, &a) && snap_tus(&a, &tus) &&
              sr_make_objects(cfg, log, &tus, NULL) && sr_snap_take(cfg->repo, &a, &b);
    FILE *fp = ok ? fopen(out, "w") : NULL;
    if (ok)
        repro_compare(&a, &b, &rebuilt, &mismatch, fp);
    if (fp) {
        fprintf(fp, "objects\t%zu\nrebuilt\t%zu\nmismatch\t%zu\n", b.n, rebuilt, mismatch);
        fclose(fp);
    }
    fprintf(stderr, "sem-replay: repro %s: %zu objects, %zu rebuilt, %zu differ\n", label,
            b.n, rebuilt, mismatch);
    sr_snap_free(&a);
    sr_snap_free(&b);
    sr_strv_free(&tus);
    if (!ok)
        return SR_STEP_FAILED;
    return mismatch == 0 && rebuilt == b.n ? SR_STEP_OK : SR_STEP_FAILED;
}

/* ── catalog: every TU compiled cold, timed, against make's object ────── */

static size_t catalog_write(const struct sr_snap *s, const struct batch *b, FILE *fp)
{
    size_t differ = 0;
    for (size_t i = 0; i < b->n; i++) {
        uint8_t h[32];
        const struct sr_obj *o = sr_snap_find(s, b->t[i].tu);
        bool same = b->t[i].rc == 0 && o && sr_hash_file(b->obj[i], h) &&
                    memcmp(h, o->hash, 32) == 0;
        differ += !same;
        if (!same)
            fprintf(stderr, "sem-replay: cold compile differs from the incremental object: %s\n",
                    b->t[i].tu);
        if (fp)
            fprintf(fp, "%s\t%.4f\t%.4f\t%d\n", b->t[i].tu, b->t[i].cpu_s, b->t[i].wall_s,
                    same ? 1 : 0);
        (void)unlink(b->obj[i]);
    }
    return differ;
}

int sr_catalog(const struct sr_cfg *cfg)
{
    struct sr_snap s = {0};
    struct sr_strv tus = {0};
    struct sr_argv_map m = {0};
    struct batch b = {0};
    char log[SR_PATH], tmp[SR_PATH], out[SR_PATH];
    snprintf(log, sizeof(log), "%s/catalog.log", cfg->state);
    snprintf(tmp, sizeof(tmp), "%s/tmp-obj", cfg->state);
    snprintf(out, sizeof(out), "%s/catalog_cost.tsv", cfg->state);
    bool ok = sr_snap_take(cfg->repo, NULL, &s) && snap_tus(&s, &tus) &&
              sr_make_argv(cfg->repo, s.epoch, &tus, log, &m) && sr_mkdirs(tmp) &&
              add_compiles(&b, &tus, &m, tmp, log) &&
              sr_pool_run(b.t, b.n, cfg->jobs, cfg->repo);
    FILE *fp = ok ? fopen(out, "w") : NULL;
    size_t differ = ok ? catalog_write(&s, &b, fp) : 0;
    if (fp)
        fclose(fp);
    fprintf(stderr, "sem-replay: catalog: %zu objects, %zu compiled cold, %zu differ\n", s.n, b.n,
            differ);
    ok = ok && b.n == s.n && differ == 0;
    batch_free(&b);
    sr_argv_free(&m);
    sr_strv_free(&tus);
    sr_snap_free(&s);
    return ok ? SR_STEP_OK : SR_STEP_FAILED;
}
