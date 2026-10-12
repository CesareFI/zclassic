/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run the declaration-identity consumer on one consumer-fixture variant from before/after manifests and compare its universe and obligations with the edit table. */
#include "test/semantic_consumer_fixture.h"

#include "base/safe_alloc.h"

#include "devloop_facts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCX_FACTS "facts"

static bool scx_put_bytes(const char *root, const char *rel,
                          const char *suffix, const uint8_t *b, size_t n)
{
    char path[4096];
    FILE *fp;
    bool ok;
    if (snprintf(path, sizeof(path), "%s/" SCX_FACTS "/%s%s", root, rel,
                 suffix) >= (int)sizeof(path))
        return false;
    for (char *p = path + strlen(root) + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        (void)scx_mkdir(path);
        *p = '/';
    }
    fp = fopen(path, "wb");
    ok = fp != NULL && fwrite(b, 1, n, fp) == n;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    return ok;
}

static bool scx_is_c(const char *path)
{
    size_t n = strlen(path);
    return n > 2 && strcmp(path + n - 2, ".c") == 0;
}

static size_t scx_nchanged(const struct scx_edit *e)
{
    return e->changed[1] != NULL ? 2 : e->changed[0] != NULL ? 1 : 0;
}

/* The facts directory: every TU's before and after manifest the evidence
 * has (but those the variant withholds), and the "before" variant's text of every changed file it has. */
static bool scx_write_facts(const char *root, enum scx_variant v,
                            const struct scx_evidence *ev)
{
    const struct scx_edit *e = &k_scx_edits[v];
    bool ok = true;
    for (size_t k = 0; ok && k < SCX_TU_COUNT; k++) {
        bool held = e->withhold != NULL && strcmp(e->withhold, k_scx_tus[k]) == 0;
        if (ev->before[k] != NULL && !held)
            ok = scx_put_bytes(root, k_scx_tus[k], ".before.zsm",
                               ev->before[k], ev->before_len[k]);
        if (ok && ev->after[k] != NULL && !(held && !e->withhold_before))
            ok = scx_put_bytes(root, k_scx_tus[k], ".after.zsm",
                               ev->after[k], ev->after_len[k]);
    }
    for (size_t k = 0; ok && k < scx_nchanged(e); k++) {
        size_t n = 0;
        char *text = scx_text(e->before, e->changed[k], &n);
        if (text != NULL)
            ok = scx_put_bytes(root, e->changed[k], ".before",
                               (const uint8_t *)text, n);
        free(text);
    }
    return ok;
}

/* The .c path takes each changed file's pair and source texts itself. */
static bool scx_tus(enum scx_variant v, const struct scx_evidence *ev,
                    struct zcl_devloop_facts_tu *tus, char **texts)
{
    const struct scx_edit *e = &k_scx_edits[v];
    for (size_t k = 0; k < scx_nchanged(e); k++) {
        size_t bn = 0, an = 0, t = SCX_TU_COUNT;
        for (size_t i = 0; i < SCX_TU_COUNT; i++)
            if (strcmp(k_scx_tus[i], e->changed[k]) == 0)
                t = i;
        if (t == SCX_TU_COUNT || ev->before[t] == NULL || ev->after[t] == NULL)
            return false;
        texts[2 * k] = scx_text(e->before, e->changed[k], &bn);
        texts[2 * k + 1] = scx_text(v, e->changed[k], &an);
        tus[k] = (struct zcl_devloop_facts_tu){
            .source = e->changed[k], .before = ev->before[t],
            .after = ev->after[t], .before_len = ev->before_len[t],
            .after_len = ev->after_len[t],
            .before_src = (const uint8_t *)texts[2 * k],
            .after_src = (const uint8_t *)texts[2 * k + 1],
            .before_src_len = bn, .after_src_len = an};
        if (texts[2 * k] == NULL || texts[2 * k + 1] == NULL)
            return false;
    }
    return true;
}

bool scx_consume(const char *root, enum scx_variant v,
                 const struct scx_evidence *ev, struct scx_result *out)
{
    const struct scx_edit *e = &k_scx_edits[v];
    struct zcl_devloop_facts_tu tus[2] = {0};
    char *texts[4] = {0};
    bool all_c = scx_nchanged(e) > 0, ok;
    for (size_t k = 0; k < scx_nchanged(e); k++)
        all_c = all_c && scx_is_c(e->changed[k]);
    memset(out, 0, sizeof(*out));
    zcl_devloop_test_reached_reset(); /* no earlier walk answers for this one */
    ok = scx_write_tree(root, v) &&
         (ev->no_depfiles || scx_write_depfiles(root, v)) &&
         scx_write_facts(root, v, ev) &&
         zcl_devloop_plan_files(e->changed, scx_nchanged(e), &out->plan) &&
         (!all_c || scx_tus(v, ev, tus, texts)) &&
         zcl_devloop_facts_consume(root, e->changed, scx_nchanged(e), SCX_FACTS,
                                   all_c ? tus : NULL, &out->plan,
                                   &out->verdict, &out->report);
    for (size_t k = 0; k < 4; k++)
        free(texts[k]);
    return ok;
}

const struct zcl_devloop_facts_tu_verdict *
scx_tu_of(const struct scx_result *r, const char *path)
{
    for (size_t k = 0; k < r->report.ntus; k++)
        if (strcmp(r->report.tus[k].path, path) == 0)
            return &r->report.tus[k];
    return NULL;
}

/* The verdict agrees with the row: absent when the row has no reason, else
 * the same affected flag and reason, and compile-only exactly when the
 * reason is debug-position or the row's own compile_only[k] says so (a
 * "position" row whose moved id is a bare prototype). */
static bool scx_tu_same(const struct scx_edit *e, size_t k,
                        const struct zcl_devloop_facts_tu_verdict *t)
{
    bool want_co;
    if (e->reason[k] == NULL)
        return t == NULL;
    want_co = strcmp(e->reason[k], "debug-position") == 0 ||
             e->compile_only[k];
    return t != NULL && t->affected == e->affected[k] &&
           strcmp(t->reason, e->reason[k]) == 0 &&
           t->compile_only == want_co;
}

/* Unsafe: a TU the row affects left out of the compile set, or one whose
 * tests the row obligates held to the compile set only. */
static bool scx_tu_unsafe(const struct scx_edit *e, size_t k, bool got_aff,
                          const struct zcl_devloop_facts_tu_verdict *t)
{
    bool want_tests = e->affected[k] && e->reason[k] != NULL &&
                      strcmp(e->reason[k], "debug-position") != 0 &&
                      !e->compile_only[k];
    return (e->affected[k] && !got_aff) ||
           (want_tests && (!got_aff || t->compile_only));
}

/* One TU against its row of the edit table: 0 when they agree. */
static size_t scx_compare_tu(const struct scx_edit *e, size_t k,
                             const struct scx_result *r, size_t *unsafe,
                             FILE *why)
{
    const struct zcl_devloop_facts_tu_verdict *t = scx_tu_of(r, k_scx_tus[k]);
    bool got_aff = t != NULL && t->affected;
    const char *got = t != NULL ? t->reason : NULL;
    if (scx_tu_unsafe(e, k, got_aff, t))
        (*unsafe)++;
    if (scx_tu_same(e, k, t))
        return 0;
    if (why != NULL)
        fprintf(why, "  %s %s: want %s/%s, got %s/%s (%s)\n", e->name,
                k_scx_tus[k], e->affected[k] ? "affected" : "unaffected",
                e->reason[k] ? e->reason[k] : "absent",
                got_aff ? "affected" : "unaffected", got ? got : "absent",
                t != NULL ? t->detail : "");
    return 1;
}

static const char *scx_or_empty(const char *s)
{
    return s != NULL ? s : "";
}

/* The universe and the obligations against the edit table: 0 on agreement. */
static size_t scx_compare_whole(const struct scx_edit *e,
                                const struct scx_result *r, FILE *why)
{
    const char *want_ob = scx_or_empty(e->obligations);
    const char *got_ob = r->verdict.narrowed ? "" : scx_or_empty(r->verdict.reason);
    const char *want_u = scx_or_empty(e->incomplete);
    const char *got_u = r->report.complete ? "" : scx_or_empty(r->report.reason);
    if (strcmp(want_u, got_u) == 0 && strcmp(want_ob, got_ob) == 0)
        return 0;
    if (why != NULL)
        fprintf(why, "  %s obligations: want \"%s\", got \"%s\" (%s; universe %s %s)\n",
                e->name, want_ob, got_ob, r->verdict.detail,
                r->report.complete ? "complete" : "incomplete",
                scx_or_empty(r->report.reason));
    return 1;
}

/* The whole catalog is in scope exactly when the table says nothing bounds
 * the change; a missing one is unsafe. */
static size_t scx_compare_universal(const struct scx_edit *e,
                                    const struct scx_result *r, size_t *unsafe,
                                    FILE *why)
{
    if (r->plan.closure_universal == e->universal)
        return 0;
    *unsafe += e->universal;
    if (why != NULL)
        fprintf(why, "  %s universal: want %d, got %d\n", e->name,
                (int)e->universal, (int)r->plan.closure_universal);
    return 1;
}

/* Each function the table says the compile may re-emit must be a seed: a
 * missing one is unsafe (its callers' obligations may go unselected). */
static size_t scx_compare_seeds(const struct scx_edit *e,
                                const struct scx_result *r, size_t *unsafe,
                                FILE *why)
{
    size_t bad = 0;
    for (size_t i = 0; i < sizeof(e->seeds) / sizeof(e->seeds[0]); i++) {
        bool found = e->seeds[i] == NULL;
        for (size_t k = 0; !found && k < r->verdict.seeds_len; k++)
            found = strcmp(r->verdict.seeds[k], e->seeds[i]) == 0;
        if (found)
            continue;
        bad++;
        (*unsafe)++;
        if (why != NULL)
            fprintf(why, "  %s seeds: %s missing (%zu seed(s))\n", e->name,
                    e->seeds[i], r->verdict.seeds_len);
    }
    return bad;
}

/* One changed file or affected TU the narrowed walk did not fold in. */
static size_t scx_unreached(const char *path, size_t *unsafe, FILE *why,
                            const struct scx_edit *e, size_t reached,
                            size_t need)
{
    (*unsafe)++;
    if (why != NULL)
        fprintf(why, "  %s reached: %s missing (%zu file(s) reached, %zu "
                "needed: a count check %s)\n", e->name, path, reached, need,
                reached >= need ? "would pass" : "would fail too");
    return 1;
}

/* A TU in the compile set only (its debug information changed) that the
 * obligations folded into the walk as a test obligation anyway. */
static size_t scx_obligated(const char *path, FILE *why,
                            const struct scx_edit *e)
{
    if (why != NULL)
        fprintf(why, "  %s folded: %s is compile-only, yet the plan folds "
                "its tests\n", e->name, path);
    return 1;
}

/* Each affected TU not already in need[0..*n) joins it, except a
 * compile-only one, which the fold must not name (the walk may still
 * reach it from a seed another TU adds). Returns the
 * disagreements. */
static size_t scx_need_tus(const struct scx_edit *e,
                           const struct scx_result *r, const char **need,
                           size_t *n, FILE *why)
{
    size_t bad = 0;
    for (size_t k = 0; k < SCX_TU_COUNT; k++) {
        const struct zcl_devloop_facts_tu_verdict *t = scx_tu_of(r, k_scx_tus[k]);
        bool listed = false;
        for (size_t i = 0; i < *n; i++)
            listed = listed || strcmp(need[i], k_scx_tus[k]) == 0;
        if (t == NULL || !t->affected || listed)
            continue;
        if (!t->compile_only)
            need[(*n)++] = k_scx_tus[k];
        else if (zcl_devloop_test_folded_has(k_scx_tus[k]))
            bad += scx_obligated(k_scx_tus[k], why, e);
    }
    return bad;
}

/* A narrowed plan reaches every changed file and every affected TU (it
 * compiles them): each must be in the walk's reached set, not merely as
 * many files as there are of them. A missing one is unsafe. A TU the
 * consumer marks compile-only must not be in the fold the walk starts
 * from: it adds no test obligation. */
static size_t scx_compare_reached(const struct scx_edit *e,
                                  const struct scx_result *r, size_t *unsafe,
                                  FILE *why)
{
    const char *need[SCX_TU_COUNT + 2];
    size_t n = 0;
    if (!r->verdict.narrowed)
        return 0;
    for (size_t i = 0; i < sizeof(e->changed) / sizeof(e->changed[0]); i++)
        if (e->changed[i] != NULL)
            need[n++] = e->changed[i];
    size_t bad = scx_need_tus(e, r, need, &n, why);
    for (size_t i = 0; i < n; i++)
        if (!zcl_devloop_test_reached_has(need[i]))
            bad += scx_unreached(need[i], unsafe, why, e,
                                 (size_t)r->verdict.reached_files, n);
    return bad;
}

/* One line per disagreement with the edit table on `why` (when not NULL);
 * *unsafe counts TUs the table says are affected that the consumer calls
 * unaffected or leaves out, and seeds it must start from that it lacks.
 * Returns the number of disagreements. */
size_t scx_compare(enum scx_variant v, const struct scx_result *r,
                   size_t *unsafe, FILE *why)
{
    const struct scx_edit *e = &k_scx_edits[v];
    size_t bad = 0;
    *unsafe = 0;
    for (size_t k = 0; k < SCX_TU_COUNT; k++)
        bad += scx_compare_tu(e, k, r, unsafe, why);
    return bad + scx_compare_whole(e, r, why) +
           scx_compare_seeds(e, r, unsafe, why) +
           scx_compare_universal(e, r, unsafe, why) +
           scx_compare_reached(e, r, unsafe, why);
}

void scx_result_free(struct scx_result *r)
{
    zcl_devloop_facts_report_free(&r->report);
}
