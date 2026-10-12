/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Facts-narrowed change closure: decide from semantic manifests which functions changed, then walk callers from those alone. */
#include "devloop_facts.h"
#include "devloop_facts_index.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/semantic_manifest.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The evidence rules, in order. The first that fails names the fallback;
 * the file-seeded closure then runs unchanged.
 *   0. No changed file is a source compiled into a producer.
 *   1. Every changed file is a .c with a before/after manifest pair.
 *   2. Each manifest is valid, carries the facts extension and is complete,
 *      and names its producer; both name the same one (a different sensor
 *      or front end build is "producer-changed").
 *   3. Each manifest's main file is the changed file and its FILES digest
 *      is the sha3 of the source bytes given with it.
 *   4. Only FILES, FUNCTIONS, SPANS, REFS, UNKNOWNS and FACTS differ; every
 *      other section names the fallback (identity, lookups, macros, decls,
 *      layouts, enums, symbols, probes, truncation).
 *   5. No function was added or removed; no included file changed.
 *   6. The main file's text outside its function definitions is unchanged
 *      (devloop_facts_text.c), and so is each definition's head: the text
 *      before its body, where attributes and storage class live.
 *   7. Every seed resolved to its id; no seed has an unresolved effect other
 *      than an external call, and no seed's address is taken in either
 *      manifest.
 *   8. REFS and UNKNOWNS outside the seeds are identical.
 *   9. The after manifest is the compile of the tree under root: every other
 *      file it read has the same bytes and every include slot it saw absent
 *      is still absent (devloop_facts_bind.c).
 *  10. The compile identity names an optimizer whose re-emitted code the
 *      facts can bound (devloop_facts_codegen.c; else
 *      "inline-closure-unknown").
 *  11. Every main-file function that expands __LINE__ (directly or through
 *      a macro) and whose lines moved or changed joins the seeds; file-
 *      scope code that expands __LINE__, or any use of __COUNTER__, is
 *      "position-dependent".
 * The seeds are the functions whose FUNCTIONS record changed, grown on both
 * sides to every main-file function the compile may re-emit with them. */

#define FX_ID_MAX (ZCL_DEVLOOP_PATH_MAX + ZCL_DEVLOOP_FACTS_NAME_MAX + 8)

struct fx_ctx {
    const char *root; /* the tree rule 9 binds the after manifests to */
    const struct zcl_devloop_facts_tu *tu;
    struct zcl_devloop_facts_verdict *v;
    size_t first_seed; /* this TU's seeds start here in v->seeds */
    char ids[ZCL_DEVLOOP_FACTS_MAX_SEEDS][FX_ID_MAX];
    bool added, removed, outside, overflow;
    uint8_t src_digest[32];
    bool main_seen;
    struct sha3_256_ctx rest; /* records a narrowing must leave unchanged */
    struct zcl_devloop_facts_range *ranges;
    size_t nranges, capranges;
};

static bool fx_fail(struct fx_ctx *c, const char *reason, const char *fmt, ...)
{
    va_list ap;
    if (c->v->reason[0])
        return false;
    c->v->reason = reason;
    va_start(ap, fmt);
    (void)vsnprintf(c->v->detail, sizeof(c->v->detail), fmt, ap);
    va_end(ap);
    return false;
}

static bool fx_eq(const char *t, size_t n, const char *s)
{
    return n == strlen(s) && memcmp(t, s, n) == 0;
}

static void fx_write_text(struct sha3_256_ctx *h, const char *t, size_t n)
{
    uint8_t len[8];
    zcl_write_u64_le(len, (uint64_t)n);
    sha3_256_write(h, len, sizeof(len));
    sha3_256_write(h, (const unsigned char *)t, n);
}

static void fx_write_num(struct sha3_256_ctx *h, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(h, b, sizeof(b));
}

static bool fx_is_seed_id(const struct fx_ctx *c, const char *t, size_t n)
{
    for (size_t k = c->first_seed; k < c->v->seeds_len; k++)
        if (fx_eq(t, n, c->ids[k]))
            return true;
    return false;
}

/* ---- rule 0: not the producer's own change ------------------------------- */

/* The repo sources compiled into the producer: the Makefile's
 * CLANG_MANIFEST_SRCS and every repo header they include (the prefixes
 * below cover each such file). A producer never judges its own change. */
static bool fx_producer_source(const char *f)
{
    static const char *const k[] = {
        "tools/sensors/",
        "contexts/commons/modules/vcs/src/semantic_",
        "contexts/commons/modules/vcs/include/vcs/semantic_",
        "contexts/commons/modules/vcs/include/vcs/vcs_manifest.h",
        "contexts/commons/modules/vcs/src/vcs_path_policy.c",
        "platform/modules/base/src/safe_alloc.c",
        "platform/modules/base/include/base/safe_alloc.h",
        "platform/modules/base/include/base/serialize_le.h",
        "platform/modules/base/include/base/hex.h",
        "platform/modules/platform/src/os_proc.c",
        "platform/modules/platform/include/platform/os_proc.h",
        "platform/modules/sha3/",
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (strncmp(f, k[i], strlen(k[i])) == 0)
            return true;
    return false;
}

/* ---- rules 2-4: validity, binding, sections --------------------------- */

static const char *fx_section_reason(uint32_t changed)
{
    static const struct {
        enum vcs_semantic_section_v1 s;
        const char *reason;
    } k[] = {
        {VCS_SEMANTIC_SECTION_V1_IDENTITY, "identity-changed"},
        {VCS_SEMANTIC_SECTION_V1_LOOKUPS, "include-resolution-changed"},
        {VCS_SEMANTIC_SECTION_V1_MACROS, "macro-changed"},
        {VCS_SEMANTIC_SECTION_V1_DECLS, "declaration-changed"},
        {VCS_SEMANTIC_SECTION_V1_LAYOUTS, "layout-changed"},
        {VCS_SEMANTIC_SECTION_V1_ENUMS, "enum-changed"},
        {VCS_SEMANTIC_SECTION_V1_SYMBOLS, "symbols-changed"},
        {VCS_SEMANTIC_SECTION_V1_PROBES, "namespace-probes-changed"},
        {VCS_SEMANTIC_SECTION_V1_TRUNCATED, "manifest-truncated"},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (changed & (1u << k[i].s))
            return k[i].reason;
    return NULL;
}

static bool fx_manifest_ok(struct fx_ctx *c, const uint8_t *m, size_t n,
                           const char *which, uint8_t producer[32])
{
    static const uint8_t zero[32] = {0};
    struct vcs_semantic_facts_info_v1 info;
    if (m == NULL || !vcs_semantic_facts_v1_info(m, n, &info))
        return fx_fail(c, "invalid-manifest", "%s manifest of %s is invalid",
                       which, c->tu->source);
    if (!info.present)
        return fx_fail(c, "no-facts", "%s manifest of %s has no facts",
                       which, c->tu->source);
    if (!info.complete)
        return fx_fail(c, "manifest-truncated",
                       "%s manifest of %s hit a producer cap", which,
                       c->tu->source);
    if (memcmp(info.producer, zero, 32) == 0)
        return fx_fail(c, "producer-unknown",
                       "%s manifest of %s names no producer", which,
                       c->tu->source);
    memcpy(producer, info.producer, 32);
    return true;
}

/* FILES: the main file binds the given source; every other file is folded
 * into `rest` so an included file's change is caught. */
static bool fx_files_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fx_ctx *c = ctx;
    if (f->ntext < 1 || f->nnum < 1 || f->ndigest < 1)
        return false;
    if (f->num[0] == VCS_SEMANTIC_ORIGIN_V1_MAIN) {
        c->main_seen = fx_eq(f->text[0], f->text_len[0], c->tu->source) &&
                       memcmp(f->digest[0], c->src_digest, 32) == 0;
        return true;
    }
    fx_write_text(&c->rest, f->text[0], f->text_len[0]);
    sha3_256_write(&c->rest, f->digest[0], 32);
    fx_write_num(&c->rest, f->num[0]);
    return true;
}

static void fx_fn_cb(void *ctx, enum vcs_semantic_fn_change_v1 change,
                     const char *path, size_t path_len, const char *name,
                     size_t name_len)
{
    struct fx_ctx *c = ctx;
    struct zcl_devloop_facts_verdict *v = c->v;
    if (change == VCS_SEMANTIC_FN_V1_ADDED)
        c->added = true;
    else if (change == VCS_SEMANTIC_FN_V1_REMOVED)
        c->removed = true;
    else if (!fx_eq(path, path_len, c->tu->source))
        c->outside = true;
    else if (v->seeds_len >= ZCL_DEVLOOP_FACTS_MAX_SEEDS ||
             name_len >= ZCL_DEVLOOP_FACTS_NAME_MAX)
        c->overflow = true;
    else {
        memcpy(v->seeds[v->seeds_len], name, name_len);
        v->seeds[v->seeds_len][name_len] = '\0';
        c->ids[v->seeds_len][0] = '\0';
        v->seed_ids[v->seeds_len][0] = '\0';
        v->seeds_len++;
    }
}

static bool fx_diff(struct fx_ctx *c)
{
    const struct zcl_devloop_facts_tu *t = c->tu;
    struct vcs_semantic_diff_v1 d;
    const char *why;
    if (!vcs_semantic_manifest_v1_diff(t->before, t->before_len, t->after,
                                       t->after_len, &d, fx_fn_cb, c))
        return fx_fail(c, "invalid-manifest", "cannot diff %s", t->source);
    why = fx_section_reason(d.changed_sections);
    if (why != NULL)
        return fx_fail(c, why, "%s", t->source);
    if (c->added || c->removed)
        return fx_fail(c, c->added ? "function-added" : "function-removed",
                       "%s", t->source);
    if (c->outside)
        return fx_fail(c, "seed-outside-source", "%s", t->source);
    if (c->overflow)
        return fx_fail(c, "too-many-seeds", "%s", t->source);
    return true;
}

/* ---- rule 6: file-scope text ------------------------------------------- */

static bool fx_spans_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fx_ctx *c = ctx;
    struct zcl_devloop_facts_range *grown;
    if (f->ntext < 1 || f->nnum < 4)
        return false;
    if (!fx_eq(f->text[0], f->text_len[0], c->tu->source))
        return true;
    if (c->nranges == c->capranges) {
        size_t next = c->capranges ? c->capranges * 2 : 64;
        grown = zcl_realloc(c->ranges, next * sizeof(*grown), "facts.ranges");
        if (grown == NULL)
            return false;
        c->ranges = grown;
        c->capranges = next;
    }
    c->ranges[c->nranges].begin = (size_t)f->num[2];
    c->ranges[c->nranges].end = (size_t)f->num[3];
    c->nranges++;
    return true;
}

static int fx_range_cmp(const void *a, const void *b)
{
    const struct zcl_devloop_facts_range *x = a, *y = b;
    if (x->begin != y->begin)
        return x->begin < y->begin ? -1 : 1;
    return x->end < y->end ? -1 : x->end > y->end;
}

/* What one side of a pair must leave unchanged for a narrowing. */
struct fx_digests {
    uint8_t scope[32]; /* file-scope text outside every definition */
    uint8_t heads[32]; /* each definition's head, in source order */
    uint8_t rest[32];  /* included files, refs and unknowns outside seeds */
};

/* Each definition's head: the text before its body, where storage class,
 * GNU __attribute__ and C23 [[attributes]], return type and declarator live.
 * A constructor, weak, alias, section or visibility attribute changes what
 * the program does without touching the body's tokens, so any head change
 * refuses the narrowing. */
static void fx_heads_digest(const uint8_t *src,
                            const struct zcl_devloop_facts_range *r, size_t n,
                            uint8_t out[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    for (size_t k = 0; k < n; k++) {
        uint8_t d[32];
        zcl_devloop_facts_head_digest(src, r[k].begin, r[k].end, d);
        sha3_256_write(&h, d, sizeof(d));
    }
    sha3_256_finalize(&h, out);
}

static bool fx_scope_digest(struct fx_ctx *c, const uint8_t *m, size_t n,
                            const uint8_t *src, size_t src_len,
                            struct fx_digests *out)
{
    size_t w = 0;
    c->nranges = 0;
    if (!vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_SPANS,
                                      fx_spans_cb, c))
        return fx_fail(c, "invalid-manifest", "spans of %s", c->tu->source);
    if (c->nranges > 1)
        qsort(c->ranges, c->nranges, sizeof(*c->ranges), fx_range_cmp);
    for (size_t k = 0; k < c->nranges; k++) {
        struct zcl_devloop_facts_range r = c->ranges[k];
        if (r.end > src_len || r.begin > r.end)
            return fx_fail(c, "source-mismatch",
                           "a span of %s lies outside its source",
                           c->tu->source);
        if (w > 0 && r.begin <= c->ranges[w - 1].end) {
            if (r.end > c->ranges[w - 1].end)
                c->ranges[w - 1].end = r.end;
            continue;
        }
        c->ranges[w++] = r;
    }
    zcl_devloop_facts_text_digest(src, src_len, c->ranges, w, out->scope);
    fx_heads_digest(src, c->ranges, w, out->heads);
    return true;
}

/* ---- rules 7-8: seed effects and the rest of the facts ------------------ */

#if defined(ZCL_TESTING)
bool zcl_devloop_test_facts_unresolved = false;
#endif

static bool fx_ids_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fx_ctx *c = ctx;
    char path[ZCL_DEVLOOP_PATH_MAX];
    if (f->ntext < 2 || f->nnum < 1)
        return false;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_facts_unresolved)
        return true;
#endif
    if (!fx_eq(f->text[0], f->text_len[0], c->tu->source) ||
        f->text_len[0] >= sizeof(path))
        return true;
    memcpy(path, f->text[0], f->text_len[0]);
    path[f->text_len[0]] = '\0';
    for (size_t k = c->first_seed; k < c->v->seeds_len; k++) {
        if (!fx_eq(f->text[1], f->text_len[1], c->v->seeds[k]))
            continue;
        if (!vcs_semantic_id_v1('f', path, c->v->seeds[k],
                                f->num[0] == 3 || f->num[0] == 4, c->ids[k],
                                sizeof(c->ids[k])))
            return false;
        /* Too wide for the verdict: the walk then filters nothing. */
        if (strlen(c->ids[k]) < sizeof(c->v->seed_ids[k]))
            memcpy(c->v->seed_ids[k], c->ids[k], strlen(c->ids[k]) + 1);
    }
    return true;
}

static bool fx_refs_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fx_ctx *c = ctx;
    if (f->ntext < 2 || f->nnum < 1)
        return false;
    if (f->num[0] == VCS_SEMANTIC_REF_V1_ADDRESS &&
        fx_is_seed_id(c, f->text[1], f->text_len[1]))
        return fx_fail(c, "address-taken", "%.*s names %.*s outside a call",
                       (int)f->text_len[0], f->text[0], (int)f->text_len[1],
                       f->text[1]);
    if (fx_is_seed_id(c, f->text[0], f->text_len[0]))
        return true;
    fx_write_text(&c->rest, f->text[0], f->text_len[0]);
    fx_write_num(&c->rest, f->num[0]);
    fx_write_text(&c->rest, f->text[1], f->text_len[1]);
    return true;
}

static bool fx_unknowns_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fx_ctx *c = ctx;
    if (f->ntext < 2 || f->nnum < 2)
        return false;
    if (fx_is_seed_id(c, f->text[0], f->text_len[0])) {
        if (f->num[0] == VCS_SEMANTIC_UNKNOWN_V1_EXTERNAL_CALL)
            return true;
        return fx_fail(c, "unknown-effect", "%.*s: kind %u (%.*s)",
                       (int)f->text_len[0], f->text[0], (unsigned)f->num[0],
                       (int)f->text_len[1], f->text[1]);
    }
    fx_write_text(&c->rest, f->text[0], f->text_len[0]);
    fx_write_num(&c->rest, f->num[0]);
    fx_write_text(&c->rest, f->text[1], f->text_len[1]);
    fx_write_num(&c->rest, f->num[1]);
    return true;
}

/* One side of the pair: its binding, text digests and `rest` digest. */
static bool fx_side(struct fx_ctx *c, const uint8_t *m, size_t n,
                    const uint8_t *src, size_t src_len, struct fx_digests *out)
{
    zcl_sha3_256(src, src_len, c->src_digest);
    c->main_seen = false;
    sha3_256_init(&c->rest);
    if (!vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_FILES,
                                      fx_files_cb, c))
        return fx_fail(c, "invalid-manifest", "files of %s", c->tu->source);
    if (!c->main_seen)
        return fx_fail(c, "source-mismatch",
                       "a manifest of %s does not bind the given source",
                       c->tu->source);
    if (!vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_REFS,
                                      fx_refs_cb, c) ||
        !vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_UNKNOWNS,
                                      fx_unknowns_cb, c))
        return fx_fail(c, "invalid-manifest", "facts of %s", c->tu->source);
    sha3_256_finalize(&c->rest, out->rest);
    return fx_scope_digest(c, m, n, src, src_len, out);
}

/* Every seed must have resolved to its canonical id; a seed that matched no
 * FUNCTIONS record would exempt nothing and escape rules 7-8 silently. */
static bool fx_seeds_resolved(struct fx_ctx *c)
{
    for (size_t k = c->first_seed; k < c->v->seeds_len; k++)
        if (c->ids[k][0] == '\0')
            return fx_fail(c, "seed-unresolved", "%s: %s", c->tu->source,
                           c->v->seeds[k]);
    return true;
}

static bool fx_compare(struct fx_ctx *c, const struct fx_digests *b,
                       const struct fx_digests *a)
{
    const char *src = c->tu->source;
    if (memcmp(b->scope, a->scope, 32) != 0)
        return fx_fail(c, "file-scope-changed",
                       "%s changed outside its function definitions", src);
    if (memcmp(b->heads, a->heads, 32) != 0)
        return fx_fail(c, "function-head-changed",
                       "%s: a definition's attributes, storage class or "
                       "signature changed", src);
    if (memcmp(b->rest, a->rest, 32) != 0)
        return fx_fail(c, "facts-changed-outside-seeds",
                       "%s: an included file, reference or unknown effect "
                       "outside the changed functions differs",
                       src);
    return true;
}

/* Rules 2-3a: complete facts from one named producer, and source bytes. */
static bool fx_evidence_ok(struct fx_ctx *c)
{
    const struct zcl_devloop_facts_tu *t = c->tu;
    uint8_t producer[2][32];
    if (!fx_manifest_ok(c, t->before, t->before_len, "before", producer[0]) ||
        !fx_manifest_ok(c, t->after, t->after_len, "after", producer[1]))
        return false;
    if (memcmp(producer[0], producer[1], 32) != 0)
        return fx_fail(c, "producer-changed",
                       "the manifests of %s come from different producers",
                       t->source);
    if (t->before_src == NULL || t->after_src == NULL)
        return fx_fail(c, "source-mismatch", "no source bytes for %s",
                       t->source);
    return true;
}

/* Rule 9: the after manifest is the compile of the tree under root. */
static bool fx_bind(struct fx_ctx *c)
{
    const char *reason = NULL;
    char detail[sizeof(c->v->detail)];
    if (zcl_devloop_facts_bind_after(c->root, c->tu, &reason, detail,
                                     sizeof(detail)))
        return true;
    return fx_fail(c, reason != NULL ? reason : "after-stale", "%s", detail);
}

static bool fx_check_tu(struct fx_ctx *c)
{
    const struct zcl_devloop_facts_tu *t = c->tu;
    struct fx_digests side[2];
    if (!fx_evidence_ok(c) || !fx_diff(c))
        return false;
    if (!vcs_semantic_section_v1_each(t->after, t->after_len,
                                      VCS_SEMANTIC_SECTION_V1_FUNCTIONS,
                                      fx_ids_cb, c))
        return fx_fail(c, "invalid-manifest", "functions of %s", t->source);
    return fx_seeds_resolved(c) &&
           fx_side(c, t->before, t->before_len, t->before_src,
                   t->before_src_len, &side[0]) &&
           fx_side(c, t->after, t->after_len, t->after_src, t->after_src_len,
                   &side[1]) &&
           fx_compare(c, &side[0], &side[1]) && fx_bind(c);
}

/* ---- the functions the compile may re-emit -------------------------------- */

static bool fx_has_seed(const struct fx_ctx *c, const char *id)
{
    for (size_t k = c->first_seed; k < c->v->seeds_len; k++)
        if (strcmp(c->ids[k], id) == 0)
            return true;
    return false;
}

static bool fx_seed_push(struct fx_ctx *c, const char *name, const char *id)
{
    struct zcl_devloop_facts_verdict *v = c->v;
    size_t k = v->seeds_len;
    if (k >= ZCL_DEVLOOP_FACTS_MAX_SEEDS ||
        strlen(name) >= ZCL_DEVLOOP_FACTS_NAME_MAX ||
        strlen(id) >= sizeof(c->ids[k]))
        return fx_fail(c, "too-many-seeds",
                       "%s: the code-generation closure", c->tu->source);
    memcpy(v->seeds[k], name, strlen(name) + 1);
    memcpy(c->ids[k], id, strlen(id) + 1);
    v->seed_ids[k][0] = '\0';
    if (strlen(id) < sizeof(v->seed_ids[k]))
        memcpy(v->seed_ids[k], id, strlen(id) + 1);
    v->seeds_len++;
    return true;
}

/* Every main-file function of x in mark joins the seeds; a header
 * definition every reader emits cannot be walked from this TU alone. */
static bool fx_codegen_seeds(struct fx_ctx *c, const struct fxi *x,
                             const uint8_t *mark)
{
    for (size_t e = 0; e < fxi_count(x); e++) {
        if (!mark[e] || !fxi_defined_function(x, e) ||
            fx_has_seed(c, fxi_id(x, e)))
            continue;
        if (!fxi_main_function(x, e) && fxi_root(x, e))
            return fx_fail(c, "inline-closure-unknown",
                           "%s: the closure reaches %s, which every reader "
                           "emits", c->tu->source, fxi_id(x, e));
        if (fxi_main_function(x, e) &&
            !fx_seed_push(c, fxi_bare(x, e), fxi_id(x, e)))
            return false;
    }
    return true;
}

/* One side's closure from the changed functions [first_seed, changed). */
static bool fx_codegen_side(struct fx_ctx *c, const uint8_t *m, size_t n,
                            size_t changed)
{
    const char *why = "", *token;
    struct fxi *x = fxi_open(m, n, &why);
    uint8_t *mark = NULL;
    enum fxi_codegen model;
    bool ok;
    if (x == NULL)
        return fx_fail(c, "invalid-manifest", "%s: %s", c->tu->source, why);
    model = fxi_codegen_model(x, &token);
    ok = model != FXI_CODEGEN_UNBOUNDED ||
         fx_fail(c, "inline-closure-unknown",
                 "%s: the compile identity names %s", c->tu->source, token);
    if (ok)
        mark = zcl_calloc(fxi_count(x) + 1, 1, "facts.codegen");
    ok = ok && mark != NULL;
    for (size_t k = c->first_seed; ok && k < changed; k++) {
        size_t e;
        if (fxi_find(x, c->ids[k], &e))
            mark[e] = 1;
    }
    ok = ok && fxi_codegen_closure(x, model, mark) &&
         fx_codegen_seeds(c, x, mark);
    free(mark);
    fxi_free(x);
    return ok;
}


/* ---- rule 11: positions ------------------------------------------------ */

/* The bytes of lines [lo, hi] (1-based) of src; false when src lacks them. */
static bool fx_line_range(const uint8_t *src, size_t len, uint32_t lo,
                          uint32_t hi, size_t *b, size_t *e)
{
    uint32_t line = 1;
    size_t i = 0;
    if (src == NULL)
        return false;
    while (i < len && line < lo)
        line += src[i++] == '\n';
    if (line != lo)
        return false;
    *b = i;
    while (i < len && line <= hi)
        line += src[i++] == '\n';
    *e = i;
    return true;
}

/* A __LINE__ in function e of xa may now expand to another number: its
 * lines moved, or their bytes changed without its tokens changing (a
 * comment moved across the expansion). */
static bool fx_moved(const struct fx_ctx *c, const struct fxi *xa,
                     const struct fxi *xb, size_t e)
{
    const struct zcl_devloop_facts_tu *t = c->tu;
    const char *main = fxi_main(xa);
    uint32_t alo, ahi, blo, bhi;
    size_t eb, ab, ae, bb, be;
    if (!fxi_find(xb, fxi_id(xa, e), &eb) || !fxi_span(xa, e, main, &alo, &ahi) ||
        !fxi_span(xb, eb, main, &blo, &bhi) || alo != blo || ahi != bhi ||
        !fx_line_range(t->after_src, t->after_src_len, alo, ahi, &ab, &ae) ||
        !fx_line_range(t->before_src, t->before_src_len, blo, bhi, &bb, &be))
        return true;
    return ae - ab != be - bb ||
           memcmp(t->after_src + ab, t->before_src + bb, ae - ab) != 0;
}

/* __COUNTER__ counts expansions across the TU: any change may renumber
 * every later one, so a TU that expands it anywhere is not narrowed. */
static bool fx_counter(struct fx_ctx *c, const struct fxi *x, size_t *via)
{
    if (!fxi_expands_builtin(x, "__COUNTER__", via))
        return fx_fail(c, "out-of-memory", "%s", c->tu->source);
    for (size_t e = 0; e < fxi_count(x); e++)
        if (via[e] != SIZE_MAX &&
            (fxi_defined_function(x, e) || fxi_is_site(x, e, "@")))
            return fx_fail(c, "position-dependent", "%s expands __COUNTER__",
                           fxi_id(x, e));
    return true;
}

/* Every main-file function that expands __LINE__ and whose lines moved
 * joins the seeds; file-scope code that expands it is not narrowed, since
 * no span says where it sits. */
static bool fx_lines(struct fx_ctx *c, const struct fxi *xa,
                     const struct fxi *xb, size_t *via)
{
    if (!fxi_expands_builtin(xa, "__LINE__", via))
        return fx_fail(c, "out-of-memory", "%s", c->tu->source);
    for (size_t e = 0; e < fxi_count(xa); e++) {
        if (via[e] == SIZE_MAX || fx_has_seed(c, fxi_id(xa, e)))
            continue;
        if (fxi_is_site(xa, e, "@scope:"))
            return fx_fail(c, "position-dependent",
                           "file-scope code of %s expands __LINE__",
                           c->tu->source);
        if (fxi_main_function(xa, e) && fx_moved(c, xa, xb, e) &&
            !fx_seed_push(c, fxi_bare(xa, e), fxi_id(xa, e)))
            return false;
    }
    return true;
}

/* __LINE__ and __COUNTER__ expand to where and how often, which no token of
 * a function records: their users join the seeds or refuse the narrowing. */
static bool fx_positions(struct fx_ctx *c)
{
    const char *why = "";
    struct fxi *xa, *xb = NULL;
    size_t *via = NULL, cap;
    bool ok;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_POSITION)
        return true;
#endif
    xa = fxi_open(c->tu->after, c->tu->after_len, &why);
    if (xa != NULL)
        xb = fxi_open(c->tu->before, c->tu->before_len, &why);
    if (xb == NULL) {
        fxi_free(xa);
        return fx_fail(c, "invalid-manifest", "%s: %s", c->tu->source, why);
    }
    cap = fxi_count(xa) > fxi_count(xb) ? fxi_count(xa) : fxi_count(xb);
    via = zcl_calloc(cap + 1, sizeof(*via), "facts.positions");
    ok = via != NULL || fx_fail(c, "out-of-memory", "%s", c->tu->source);
    ok = ok && fx_counter(c, xb, via) && fx_counter(c, xa, via) &&
         fx_lines(c, xa, xb, via);
    free(via);
    fxi_free(xb);
    fxi_free(xa);
    return ok;
}
/* The seeds so far are the functions whose source changed; the compile may
 * re-emit more (their callers inline them, their internal callees take
 * their constants). Both sides' closures join the seeds. */
static bool fx_codegen(struct fx_ctx *c)
{
    size_t changed = c->v->seeds_len;
    return fx_codegen_side(c, c->tu->before, c->tu->before_len, changed) &&
           fx_codegen_side(c, c->tu->after, c->tu->after_len, changed);
}

static bool fx_ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static const struct zcl_devloop_facts_tu *
fx_find_tu(const struct zcl_devloop_facts_tu *tus, size_t n, const char *f)
{
    for (size_t k = 0; k < n; k++)
        if (tus[k].source != NULL && strcmp(tus[k].source, f) == 0)
            return &tus[k];
    return NULL;
}

/* Rules 1-9 over every changed file; fills verdict->seeds. */
static bool fx_decide(const char *root, const char *const *files, size_t n,
                      const struct zcl_devloop_facts_tu *tus, size_t ntus,
                      struct zcl_devloop_facts_verdict *v)
{
    struct fx_ctx *c = zcl_calloc(1, sizeof(*c), "facts.ctx");
    bool ok = c != NULL;
    if (c == NULL) {
        v->reason = "out-of-memory";
        return false;
    }
    c->v = v;
    c->root = root;
    if (n == 0)
        ok = fx_fail(c, "no-changed-files", "%s", "");
    for (size_t k = 0; ok && k < n; k++) {
        c->tu = fx_find_tu(tus, ntus, files[k]);
        c->first_seed = v->seeds_len;
        c->added = c->removed = c->outside = c->overflow = false;
        if (fx_producer_source(files[k]))
            ok = fx_fail(c, "producer-source-changed", "%s", files[k]);
        else if (!fx_ends_with(files[k], ".c"))
            ok = fx_fail(c, "not-c-source", "%s", files[k]);
        else if (c->tu == NULL)
            ok = fx_fail(c, "no-manifest", "%s", files[k]);
        else
            ok = fx_check_tu(c) && fx_positions(c) && fx_codegen(c);
    }
    free(c->ranges);
    free(c);
    return ok;
}

/* ---- the narrowed walk ---------------------------------------------------- */

static bool fx_narrow(const char *root, const char *facts_dir,
                      const char *const *files, size_t n,
                      struct zcl_devloop_plan *plan,
                      struct zcl_devloop_facts_verdict *v)
{
    struct zcl_devloop_facts_seed *seeds =
        zcl_calloc(v->seeds_len + 1, sizeof(*seeds), "facts.seeds");
    bool ok;
    if (seeds == NULL) {
        v->reason = "out-of-memory";
        return false;
    }
    for (size_t k = 0; k < v->seeds_len; k++) {
        (void)snprintf(seeds[k].name, sizeof(seeds[k].name), "%s", v->seeds[k]);
        (void)snprintf(seeds[k].id, sizeof(seeds[k].id), "%s", v->seed_ids[k]);
    }
    v->seeds_total = v->seeds_len;
    ok = zcl_devloop_facts_narrow(root, facts_dir, files, n, seeds,
                                  v->seeds_len, plan, v);
    free(seeds);
    return ok;
}

bool zcl_devloop_facts_add_closure_in(
    const char *repo_root, const char *const *files, size_t file_count,
    const struct zcl_devloop_facts_tu *tus, size_t tu_count,
    const char *facts_dir, struct zcl_devloop_plan *plan,
    struct zcl_devloop_facts_verdict *verdict)
{
    const char *root = repo_root && repo_root[0] ? repo_root : ".";
    struct zcl_devloop_plan *saved;
    if (!plan || !verdict || (file_count > 0 && !files) ||
        (tu_count > 0 && !tus) || file_count > ZCL_DEVLOOP_MAX_FILES)
        return false;
    memset(verdict, 0, sizeof(*verdict));
    verdict->reason = "";
    saved = zcl_malloc(sizeof(*saved), "facts.plan");
    if (saved == NULL)
        return false;
    memcpy(saved, plan, sizeof(*saved));
    verdict->narrowed = fx_decide(root, files, file_count, tus, tu_count,
                                  verdict) &&
                        fx_narrow(root, facts_dir, files, file_count, plan,
                                  verdict);
    if (!verdict->narrowed) {
        /* The file-seeded closure, from the plan exactly as it was given. */
        memcpy(plan, saved, sizeof(*saved));
        verdict->seeds_len = 0;
        verdict->seeds_total = 0;
        free(saved);
        return zcl_devloop_plan_add_closure(root, files, file_count, plan);
    }
    free(saved);
    return true;
}

bool zcl_devloop_plan_add_closure_facts(
    const char *repo_root, const char *const *files, size_t file_count,
    const struct zcl_devloop_facts_tu *tus, size_t tu_count,
    struct zcl_devloop_plan *plan, struct zcl_devloop_facts_verdict *verdict)
{
    return zcl_devloop_facts_add_closure_in(repo_root, files, file_count, tus,
                                            tu_count, NULL, plan, verdict);
}
