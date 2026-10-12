/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Decide one translation unit of the facts universe: its identities, whether a changed declaration, macro, layout or position reaches its code, and why. */
#include "devloop_facts_consumer.h"

#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/semantic_manifest.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One TU's manifest pair and its indexes. */
struct fxc_pair {
    const char *path;
    uint8_t *b, *a;
    size_t blen, alen;
    struct fxi *xb, *xa;
    uint8_t *fb, *fa; /* fxi_dirty bits per entity of each side */
};

static void fxc_pair_free(struct fxc_pair *p)
{
    fxi_free(p->xb);
    fxi_free(p->xa);
    free(p->b);
    free(p->a);
    free(p->fb);
    free(p->fa);
    memset(p, 0, sizeof(*p));
}

static bool fxc_set(struct zcl_devloop_facts_tu_verdict *t, bool affected,
                    bool broadened, const char *reason, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
static bool fxc_set(struct zcl_devloop_facts_tu_verdict *t, bool affected,
                    bool broadened, const char *reason, const char *fmt, ...)
{
    va_list ap;
    t->affected = affected;
    t->broadened = broadened;
    t->compile_only = false;
    t->reason = reason;
    va_start(ap, fmt);
    (void)vsnprintf(t->detail, sizeof(t->detail), fmt, ap);
    va_end(ap);
    return true;
}

static bool fxc_load_pair(struct fxc *c, const char *path, struct fxc_pair *p)
{
    const char *why;
    p->path = path;
    if (!zcl_devloop_facts_read(c->root, c->facts_dir, path, ".after.zsm",
                                VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &p->a,
                                &p->alen))
        return false;
    p->xa = fxi_open(p->a, p->alen, &why);
    if (zcl_devloop_facts_read(c->root, c->facts_dir, path, ".before.zsm",
                               VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &p->b,
                               &p->blen))
        p->xb = fxi_open(p->b, p->blen, &why);
    return p->xa != NULL;
}

/* A lookup of one manifest that names a changed path: its hit, or a slot
 * it saw absent; or a changed path a lookup with no negative claim may now
 * resolve to (fxc_unbound_path). */
struct fxc_probe {
    const struct fxc *c;
    bool hit;
    const char *unbound;
};

static bool fxc_spelled_is(const char *s, size_t n, const char *prefix)
{
    size_t p = strlen(prefix);
    return n >= p && memcmp(s, prefix, p) == 0;
}

/* The sensor spells a conditional lookup it cannot bound from its word on
 * ("__has_embed(...)", "#embed <x>"); see cm_scan_has_include. */
const char *fxc_unbound_path(const struct fxc *c, const char *spelled,
                             size_t len)
{
    bool reads = fxc_spelled_is(spelled, len, "#embed") ||
                 fxc_spelled_is(spelled, len, "__has_embed");
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_UNBOUND)
        return NULL;
#endif
    for (size_t k = 0; c->hdrs != NULL && k < c->nfiles; k++)
        if (reads || c->hdrs[k].moved)
            return c->files[k];
    return NULL;
}

static bool fxc_unbound_cb(void *ctx, const char *dir, size_t dn,
                           const char *name, size_t nn)
{
    struct fxc_probe *q = ctx;
    (void)dn;
    if (dir == NULL && name != NULL)
        q->unbound = fxc_unbound_path(q->c, name, nn);
    return q->unbound == NULL;
}

/* The changed path some lookup of m with no negative claim may now resolve
 * to, or NULL: such a lookup names no slot to compare against the change,
 * so nothing but the change's own shape bounds it. */
static const char *fxc_unbound(const struct fxc *c, const uint8_t *m, size_t n)
{
    struct fxc_probe q = {.c = c};
    if (m != NULL)
        (void)vcs_semantic_absent_v1_each(m, n, fxc_unbound_cb, &q);
    return q.unbound;
}

static bool fxc_probe_names(const struct fxc *c, const char *dir, size_t dn,
                            const char *name, size_t nn)
{
    for (size_t k = 0; k < c->nfiles; k++) {
        const char *f = c->files[k];
        size_t n = strlen(f);
        if (name == NULL ? n == dn && memcmp(f, dir, dn) == 0
                         : n == dn + 1 + nn && memcmp(f, dir, dn) == 0 &&
                               f[dn] == '/' && memcmp(f + dn + 1, name, nn) == 0)
            return true;
    }
    return false;
}

static bool fxc_absent_cb(void *ctx, const char *dir, size_t dn,
                          const char *name, size_t nn)
{
    struct fxc_probe *q = ctx;
    q->hit = q->hit || (dir != NULL && fxc_probe_names(q->c, dir, dn, name, nn));
    return !q->hit;
}

static bool fxc_hit_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct fxc_probe *q = ctx;
    q->hit = q->hit || (f->ntext >= 3 && f->text_len[2] > 0 &&
                        fxc_probe_names(q->c, f->text[2], f->text_len[2],
                                        NULL, 0));
    return !q->hit;
}

/* The TU's include resolution depends on a changed path it need not read:
 * a __has_include or include lookup hit it, or saw its slot empty, or makes
 * no negative claim at all while a path was created or deleted (or, for an
 * embed, any path changed). A file created or deleted there changes the TU
 * with no FILES record to say so. */
static bool fxc_probes(const struct fxc *c, const uint8_t *m, size_t n)
{
    struct fxc_probe q = {.c = c};
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_OUTSIDER)
        return false;
#endif
    if (m == NULL)
        return false;
    (void)vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_LOOKUPS,
                                       fxc_hit_cb, &q);
    if (!q.hit)
        (void)vcs_semantic_absent_v1_each(m, n, fxc_absent_cb, &q);
    return q.hit || fxc_unbound(c, m, n) != NULL;
}

/* A manifest before facts revision 3 on either side of the pair: the
 * changed path its lookups that record no claim at all (such a sensor
 * scanned no conditional lookup) may now resolve to, as for an unbound
 * one, or NULL. */
static const char *fxc_unbound_old(const struct fxc *c, const struct fxc_pair *p)
{
    if ((p->xa == NULL || fxi_revision(p->xa) >= 3) &&
        (p->xb == NULL || fxi_revision(p->xb) >= 3))
        return NULL;
    return fxc_unbound_path(c, "", 0);
}

/* Some side of the pair read a changed file or looked it up. */
static bool fxc_member(const struct fxc *c, const struct fxc_pair *p)
{
    for (size_t k = 0; k < c->nfiles; k++)
        if (fxi_file_digest(p->xa, c->files[k]) != NULL ||
            (p->xb != NULL && fxi_file_digest(p->xb, c->files[k]) != NULL))
            return true;
    return fxc_probes(c, p->a, p->alen) || fxc_probes(c, p->b, p->blen) ||
           fxc_unbound_old(c, p) != NULL;
}

/* Every id a REFS ADDRESS record names, over every manifest here: a seed
 * among them is called through a pointer the name walk cannot follow. */
static bool fxc_collect_addresses(struct fxc *c, const struct fxi *x)
{
    for (size_t k = 0; x != NULL && k < fxi_edge_count(x); k++) {
        size_t from, to;
        uint8_t kind;
        fxi_edge_at(x, k, &from, &to, &kind);
        if (kind == VCS_SEMANTIC_REF_V1_ADDRESS &&
            !fxc_strs_has(&c->address, fxi_id(x, to)) &&
            !fxc_strs_add(&c->address, fxi_id(x, to)))
            return false;
    }
    return true;
}

/* ---- identities ------------------------------------------------------------------ */

static void fxc_identities(struct fxc *c, const struct fxc_pair *p,
                           struct zcl_devloop_facts_tu_verdict *t)
{
    struct fxi_roots r;
    uint8_t *bytes = NULL;
    size_t len = 0;
    char why[128];
    fxi_roots(p->xa, &r);
    memcpy(t->source, r.source, 32);
    memcpy(t->fact, r.fact, 32);
    memcpy(t->interface, r.interface, 32);
    memcpy(t->implementation, r.implementation, 32);
    t->has_roots = true;
    t->action_reason = "action-evidence-absent";
    if (zcl_devloop_facts_read(c->root, c->facts_dir, p->path, ".after.action",
                               1u << 20, &bytes, &len)) {
        t->has_action = vcs_action_root_v2_from_bytes(bytes, len, t->action,
                                                      why, sizeof(why));
        t->action_reason = t->has_action ? "" : "action-evidence-invalid";
        free(bytes);
    }
    if (zcl_devloop_facts_read(c->root, c->facts_dir, p->path, ".after.o",
                               256u << 20, &bytes, &len)) {
        struct sha3_256_ctx h;
        sha3_256_init(&h);
        sha3_256_write(&h, (const unsigned char *)"zcl.semantic.tu.artifact.v1",
                       strlen("zcl.semantic.tu.artifact.v1") + 1);
        sha3_256_write(&h, bytes, len);
        sha3_256_finalize(&h, t->artifact);
        t->has_artifact = true;
        free(bytes);
    }
}

/* ---- coarse evidence -------------------------------------------------------------- */

static bool fxc_same_section(const struct fxc_pair *p, int s)
{
    uint8_t b[32], a[32];
    fxi_section_digest(p->xb, s, b);
    fxi_section_digest(p->xa, s, a);
    return memcmp(b, a, 32) == 0;
}

static bool fxc_same_file_set(const struct fxc_pair *p)
{
    if (fxi_file_count(p->xb) != fxi_file_count(p->xa))
        return false;
    for (size_t k = 0; k < fxi_file_count(p->xa); k++)
        if (fxi_file_digest(p->xb, fxi_file_path(p->xa, k)) == NULL)
            return false;
    return true;
}

/* ---- compile identity ------------------------------------------------------------ */

/* The pair's compile identity: NULL when the IDENTITY records are equal
 * (*sdir false), or differ only in search dirs under which every lookup
 * resolves as before (*sdir true: the lookups' slots moved with the dirs,
 * so fxc_sdir_delta compared LOOKUPS by what each slot names, not by
 * bytes). Else why the TU is affected: "search-dir-resolution-change" when
 * only search dirs differ and a lookup, probe answer or file moved,
 * "identity-drift" for anything else. Any search-dir change leaves the
 * universe incomplete: a plan it narrows stays feedback, never proof. */
static const char *fxc_identity(struct fxc *c, const struct fxc_pair *p,
                                bool *sdir)
{
    enum fxc_sdir d;
    *sdir = false;
    if (!fxi_object_cc_known(p->xa) || !fxi_object_cc_known(p->xb) ||
        strcmp(fxi_main(p->xa), fxi_main(p->xb)) != 0)
        return "identity-drift";
    if (fxc_same_section(p, VCS_SEMANTIC_SECTION_V1_IDENTITY))
        return NULL;
    d = fxc_sdir_delta(p->b, p->blen, p->a, p->alen);
    if (d == FXC_SDIR_DRIFT)
        return "identity-drift";
    c->sdir = true;
    fxc_incomplete(c, "search-dir-delta", p->path);
    *sdir = true;
    return d == FXC_SDIR_CHANGED ? "search-dir-resolution-change" : NULL;
}

static const char *fxc_identity_detail(const char *why)
{
    return strcmp(why, "identity-drift") == 0
               ? "compiler unknown, or it, target, flags or environment changed"
               : "a search-dir change moved an include, a probe answer or a file";
}

/* An include resolved differently or the file set changed; after a
 * search-dir change (sdir) the lookups were compared already. */
static bool fxc_resolution_moved(const struct fxc_pair *p, bool sdir)
{
    return (!sdir && (!fxc_same_section(p, VCS_SEMANTIC_SECTION_V1_LOOKUPS) ||
                      !fxc_same_section(p, VCS_SEMANTIC_SECTION_V1_PROBES))) ||
           !fxc_same_file_set(p);
}

static const char *fxc_producer_check(struct fxc *c, const struct fxc_pair *p)
{
    static const uint8_t zero[32] = {0};
    if (memcmp(fxi_producer(p->xa), zero, 32) == 0 ||
        memcmp(fxi_producer(p->xb), zero, 32) == 0)
        return "producer-unknown";
    if (memcmp(fxi_producer(p->xa), fxi_producer(p->xb), 32) != 0)
        return "producer-mismatch";
    if (!c->have_producer) {
        memcpy(c->producer, fxi_producer(p->xa), 32);
        c->have_producer = true;
    } else if (memcmp(c->producer, fxi_producer(p->xa), 32) != 0) {
        c->mixed = true;
        return "producer-mismatch";
    }
    return NULL;
}

/* The first file this pair read whose bytes changed without being in the
 * request: the plan would then be about a different change. */
static const char *fxc_unrequested(const struct fxc *c, const struct fxc_pair *p)
{
    for (size_t k = 0; k < fxi_file_count(p->xa); k++) {
        const char *f = fxi_file_path(p->xa, k);
        const uint8_t *b = fxi_file_digest(p->xb, f);
        const uint8_t *a = fxi_file_digest(p->xa, f);
        if (b != NULL && memcmp(a, b, 32) != 0 && !fxc_is_changed(c, f))
            return f;
    }
    return NULL;
}

/* The evidence itself: complete, one named producer, one compile identity
 * and one include resolution on both sides. True when it broadened. */
static bool fxc_coarse_evidence(struct fxc *c, const struct fxc_pair *p,
                                struct zcl_devloop_facts_tu_verdict *t)
{
    const char *why;
    bool sdir;
    if (!fxi_complete(p->xa) || !fxi_complete(p->xb))
        return fxc_set(t, true, true, "truncated", "a producer cap cut a section");
    if ((why = fxc_producer_check(c, p)) != NULL)
        return fxc_set(t, true, true, why, "FACTS producer digests");
    if ((why = fxc_identity(c, p, &sdir)) != NULL)
        return fxc_set(t, true, true, why, "%s", fxc_identity_detail(why));
    if (fxc_resolution_moved(p, sdir))
        return fxc_set(t, true, true, "include-resolution-change",
                       "an include resolved differently or the file set changed");
    return false;
}

/* __COUNTER__ numbers its expansions across the whole TU: a changed file
 * it read may add or drop one ahead of every other. True also when memory
 * runs out, so the TU is never narrowed on a guess. */
static bool fxc_counts(const struct fxi *x)
{
    size_t *via;
    bool hit;
    if (x == NULL)
        return false;
    via = zcl_calloc(fxi_count(x) + 1, sizeof(*via), "facts_tu.counter");
    hit = via == NULL || !fxi_expands_builtin(x, "__COUNTER__", via);
    for (size_t e = 0; !hit && e < fxi_count(x); e++)
        hit = via[e] != SIZE_MAX &&
              (fxi_defined_function(x, e) || fxi_is_site(x, e, "@"));
    free(via);
    return hit;
}

/* Everything that broadens the whole TU; true when one did. */
static bool fxc_coarse(struct fxc *c, const struct fxc_pair *p,
                       struct zcl_devloop_facts_tu_verdict *t)
{
    const char *main = fxi_main(p->xa), *reason, *stale;
    char detail[192];
    struct zcl_devloop_facts_tu tu = {.source = p->path, .after = p->a,
                                      .after_len = p->alen};
    if (fxc_coarse_evidence(c, p, t))
        return true;
    if (memcmp(fxi_file_digest(p->xa, main), fxi_file_digest(p->xb, main), 32))
        return fxc_set(t, true, true, "source-changed", "%s", main);
    if (fxc_counts(p->xa) || fxc_counts(p->xb))
        return fxc_set(t, true, true, "position-dependent",
                       "it expands __COUNTER__, which counts across the TU");
    if ((fxi_revision(p->xa) < 2 || fxi_revision(p->xb) < 2) &&
        !fxc_same_section(p, VCS_SEMANTIC_SECTION_V1_MACROS))
        return fxc_set(t, true, true, "macro-unattributed",
                       "a revision-1 manifest cannot attribute a macro change");
    if ((stale = fxc_unrequested(c, p)) != NULL)
        return fxc_set(t, true, true, "unrequested-change", "%s", stale);
    if (!zcl_devloop_facts_bind_after(c->root, &tu, &reason, detail,
                                      sizeof(detail)))
        return fxc_set(t, true, true, reason ? reason : "after-stale", "%s",
                       detail);
    return false;
}

/* ---- the changed files' text ---------------------------------------------------- */

static bool fxc_digest_is(const uint8_t *bytes, size_t n, const uint8_t *want)
{
    uint8_t d[32];
    zcl_sha3_256(bytes, n, d);
    return want != NULL && memcmp(d, want, 32) == 0;
}

/* Load <facts>/<path>.before and the tree's <path> once; reason stays NULL
 * when both exist and diff. */
static struct fxc_hdr *fxc_hdr_load(struct fxc *c, const char *path)
{
    struct fxc_hdr *h = fxc_hdr_of(c, path);
    if (h == NULL || h->loaded)
        return h;
    h->loaded = true;
    h->path = path;
    if (!zcl_devloop_facts_read(c->root, c->facts_dir, path, ".before",
                                16u << 20, &h->before, &h->blen) ||
        !zcl_devloop_facts_read(c->root, NULL, path, "", 16u << 20, &h->after,
                                &h->alen)) {
        h->reason = "position-unknown";
        return h;
    }
    zcl_sha3_256(h->before, h->blen, h->bdigest);
    zcl_sha3_256(h->after, h->alen, h->adigest);
    if (!fxh_diff(h->before, h->blen, h->after, h->alen, &h->diff))
        h->reason = "out-of-memory";
    return h;
}

static bool fxc_name_in(const char *bare, char **names, size_t n)
{
    for (size_t k = 0; k < n; k++)
        if (strcmp(bare, names[k]) == 0)
            return true;
    return false;
}

/* Mark every entity of x that `path` declares and whose name is in names. */
static size_t fxc_mark_names(const struct fxi *x, uint8_t *flags,
                             const char *path, char **names, size_t n)
{
    size_t hits = 0;
    for (size_t e = 0; e < fxi_count(x); e++) {
        if (!fxc_name_in(fxi_bare(x, e), names, n) || !fxi_has_path(x, e, path))
            continue;
        flags[e] |= FXI_DIRTY_CHUNK;
        hits++;
    }
    return hits;
}

/* Attribute the header's changed chunks to ids, or name the broadening. */
static const char *fxc_chunks(const struct fxc_hdr *h, struct fxc_pair *p,
                              char *detail, size_t cap)
{
    for (size_t k = 0; k < h->diff.nchanged; k++) {
        const struct fxh_chunk *ch = &h->diff.changed[k];
        size_t hits;
        if (ch->kind == FXH_COND || ch->kind == FXH_INCLUDE ||
            ch->kind == FXH_OTHER) {
            (void)snprintf(detail, cap, "a %s directive of %s changed",
                           ch->kind == FXH_COND      ? "conditional"
                           : ch->kind == FXH_INCLUDE ? "include"
                                                     : "preprocessor",
                           h->path);
            return ch->kind == FXH_COND      ? "macro-conditional"
                   : ch->kind == FXH_INCLUDE ? "include-resolution-change"
                                             : "header-unattributed";
        }
        hits = fxc_mark_names(p->xa, p->fa, h->path, ch->names, ch->nnames) +
               fxc_mark_names(p->xb, p->fb, h->path, ch->names, ch->nnames);
        if (hits == 0 && ch->kind != FXH_DEFINE) {
            (void)snprintf(detail, cap, "a changed text of %s names no id it "
                           "declares (%s)", h->path,
                           ch->nnames > 0 ? ch->names[0] : "no name");
            return "header-unattributed";
        }
    }
    return NULL;
}

/* -g1 debug information records the declaration line and column of every
 * function and external variable a TU defines or references, and the
 * lines of every header function it emits. */
static void fxc_mark_positions(const struct fxc_hdr *h, const struct fxi *x,
                               uint8_t *flags, bool after)
{
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_POSITION)
        return;
#endif
    for (size_t e = 0; e < fxi_count(x); e++) {
        const char *id = fxi_id(x, e);
        uint32_t lo, hi;
        if (fxi_span(x, e, h->path, &lo, &hi) &&
            fxh_span_dirty(&h->diff, lo, hi, after)) {
            /* Its code, not only its debug lines: __LINE__ in it moves. */
            flags[e] |= FXI_DIRTY_POSITION | FXI_DIRTY_SPAN;
            continue;
        }
        if ((id[0] == 'f' || id[0] == 'v') && id[1] == ':' &&
            fxi_has_path(x, e, h->path) &&
            fxh_position_dirty(&h->diff, fxi_bare(x, e)))
            flags[e] |= FXI_DIRTY_POSITION;
    }
}

/* One changed file this TU read: its text evidence, chunks and positions. */
static const char *fxc_changed_file(struct fxc *c, struct fxc_pair *p,
                                    const char *path, char *detail, size_t cap)
{
    struct fxc_hdr *h = fxc_hdr_load(c, path);
    const char *why;
    if (h == NULL)
        return NULL;
    if (h->reason != NULL ||
        !fxc_digest_is(h->before, h->blen, fxi_file_digest(p->xb, path)) ||
        !fxc_digest_is(h->after, h->alen, fxi_file_digest(p->xa, path))) {
        (void)snprintf(detail, cap, "no before text of %s that binds the "
                       "manifests", path);
        return "position-unknown";
    }
    why = fxc_chunks(h, p, detail, cap);
    if (why != NULL)
        return why;
    fxc_mark_positions(h, p->xb, p->fb, false);
    fxc_mark_positions(h, p->xa, p->fa, true);
    return NULL;
}

/* ---- dirty ids and their reach ------------------------------------------------ */

static void fxc_mark_digests(const struct fxi *x, const struct fxi *other,
                             uint8_t *flags)
{
    for (size_t e = 0; e < fxi_count(x); e++) {
        size_t o;
        if (!fxi_find(other, fxi_id(x, e), &o) ||
            memcmp(fxi_whole_digest(x, e), fxi_whole_digest(other, o),
                   32) != 0)
            flags[e] |= FXI_DIRTY_DIGEST;
    }
}

/* New or removed external ids: the same-name rule's input. */
static bool fxc_new_ids(struct fxc *c, const struct fxi *x,
                        const struct fxi *other)
{
    for (size_t e = 0; e < fxi_count(x); e++) {
        size_t o;
        if (!fxi_external(x, e) || fxi_find(other, fxi_id(x, e), &o) ||
            fxc_strs_has(&c->new_ids, fxi_id(x, e)))
            continue;
        if (!fxc_strs_add(&c->new_ids, fxi_id(x, e)) ||
            (!fxc_strs_has(&c->new_names, fxi_bare(x, e)) &&
             !fxc_strs_add(&c->new_names, fxi_bare(x, e))))
            return false;
    }
    return true;
}

/* A function another file defines with internal linkage: a header's static
 * or static inline, or a static of an included .c. The TU compiles its own
 * copy under the canonical id its manifest gives it, and may emit it though
 * nothing here calls it (gcc emits an unreferenced plain static at -O0; a
 * `used` or `constructor` attribute, which the facts do not record, does
 * at any level). */
static bool fxc_own_copy(const struct fxi *x, size_t e)
{
    return fxi_defined_function(x, e) && !fxi_main_function(x, e) &&
           !fxi_external(x, e);
}

/* The first root of x that reaches an entity with `mask` bits; SIZE_MAX
 * when none does. *dirty names the entity it reaches. A TU's own copy of
 * another file's internal function is a root: its bytes are this TU's. */
static size_t fxc_first_root(const struct fxi *x, const uint8_t *flags,
                             uint8_t mask, size_t *via, size_t *dirty)
{
    uint8_t *m = zcl_calloc(fxi_count(x) + 1, 1, "facts_tu.mask");
    size_t hit = SIZE_MAX;
    if (m == NULL)
        return SIZE_MAX - 1;
    for (size_t e = 0; e < fxi_count(x); e++)
        m[e] = flags[e] & mask;
    if (!fxi_taint(x, m, via))
        hit = SIZE_MAX - 1;
    /* The main file's own #if names the cause best when it moved. */
    for (size_t e = 0; hit != SIZE_MAX - 1 && e < fxi_count(x); e++) {
        bool cond = fxi_is_site(x, e, VCS_SEMANTIC_FACTS_COND_SITE);
        if (!(fxi_root(x, e) || fxc_own_copy(x, e)) || via[e] == SIZE_MAX ||
            (hit != SIZE_MAX && !cond))
            continue;
        hit = e;
        *dirty = via[e];
        if (cond)
            break;
    }
    free(m);
    return hit;
}

/* A function a changed .c defines, compiled here because this TU includes
 * that .c (a unity build, a test reaching its statics): its name, perhaps
 * renamed by a macro, is what this TU's callers call. */
static bool fxc_in_changed_c(const struct fxc *c, const struct fxi *x,
                             size_t e)
{
    for (size_t k = 0; k < c->nfiles; k++) {
        size_t n = strlen(c->files[k]);
        if (n > 2 && strcmp(c->files[k] + n - 2, ".c") == 0 &&
            fxi_has_path(x, e, c->files[k]))
            return true;
    }
    return false;
}

/* Seeds: every function the compile may re-emit. The functions the TU
 * defines that reach a semantic change, grown by fxi_codegen_closure under
 * the optimizer the identity names (unbounded: "inline-closure-unknown");
 * main-file functions among them, and those a changed .c defines, seed the
 * walk, and so does the TU's own copy of another file's internal function
 * (its id names it in every reader, so the walk finds its callers there and
 * a manifest that takes its address refuses). Any other root that reaches a
 * change, or an external definition from another file every reader emits
 * among them, seeds the whole file as well. */
/* The marked functions: seeds, or a broadened TU. */
static bool fxc_seed_marked(struct fxc *c, const struct fxi *x,
                            const uint8_t *mark,
                            struct zcl_devloop_facts_tu_verdict *t)
{
    bool ok = true;
    for (size_t e = 0; ok && e < fxi_count(x); e++) {
        bool main, own;
        if (!mark[e] || !fxi_defined_function(x, e))
            continue;
        main = fxi_main_function(x, e);
        own = fxc_own_copy(x, e);
        if (main || own || fxc_in_changed_c(c, x, e))
            ok = fxc_seed_add(c, x, e);
        if (!main && !own && fxi_root(x, e))
            t->broadened = true;
    }
    return ok;
}

static bool fxc_seeds(struct fxc *c, const struct fxi *x, const size_t *via,
                      struct zcl_devloop_facts_tu_verdict *t)
{
    uint8_t *mark = zcl_calloc(fxi_count(x) + 1, 1, "facts_tu.codegen");
    const char *token;
    enum fxi_codegen model = fxi_codegen_model(x, &token);
    bool ok = mark != NULL;
    for (size_t e = 0; ok && e < fxi_count(x); e++) {
        if (via[e] == SIZE_MAX)
            continue;
        if (fxi_defined_function(x, e))
            mark[e] = 1;
        else if (fxi_root(x, e))
            t->broadened = true;
    }
    if (ok && model == FXI_CODEGEN_UNBOUNDED)
        fxc_refuse(c, "inline-closure-unknown",
                   "the compile identity names", token);
    ok = ok && fxi_codegen_closure(x, model, mark) &&
         fxc_seed_marked(c, x, mark, t);
    free(mark);
    return ok;
}

static const char *fxc_dirty_reason(const struct fxi *x, size_t root,
                                    const uint8_t *flags, size_t dirty)
{
    if (flags[dirty] & FXI_DIRTY_DIGEST)
        return fxi_is_site(x, root, VCS_SEMANTIC_FACTS_COND_SITE)
                   ? "macro-conditional"
                   : "interface";
    if (flags[dirty] & FXI_DIRTY_CHUNK)
        return "header-text";
    return (flags[dirty] & FXI_DIRTY_SPAN) ? "code-moved" : "position";
}

/* Semantic reach on either side; true when the TU is affected by it. */
static bool fxc_semantic(struct fxc *c, struct fxc_pair *p,
                         struct zcl_devloop_facts_tu_verdict *t, bool *ok)
{
    const uint8_t sem = FXI_DIRTY_DIGEST | FXI_DIRTY_CHUNK | FXI_DIRTY_SPAN;
    struct fxi *side[2] = {p->xa, p->xb};
    uint8_t *flags[2] = {p->fa, p->fb};
    bool affected = false;
    for (int s = 0; *ok && s < 2; s++) {
        size_t n = fxi_count(side[s]), dirty = 0, root;
        size_t *via = zcl_calloc(n + 1, sizeof(*via), "facts_tu.via");
        root = via != NULL ? fxc_first_root(side[s], flags[s], sem, via, &dirty)
                           : SIZE_MAX - 1;
        *ok = root != SIZE_MAX - 1;
        if (*ok && root != SIZE_MAX && !affected) {
            affected = true;
            fxc_set(t, true, false,
                    fxc_dirty_reason(side[s], root, flags[s], dirty),
                    "%s reaches %s", fxi_id(side[s], root),
                    fxi_id(side[s], dirty));
        }
        if (*ok && root != SIZE_MAX)
            *ok = fxc_seeds(c, side[s], via, t);
        free(via);
    }
    return affected;
}

/* A position-only hit is safe to admit with no test obligation only for a
 * function (id[0] == 'f') whose own span (wherever this manifest recorded
 * one for it, in any file) is not FXI_DIRTY_SPAN: no changed file's diff
 * region overlaps that span, so the entity's real code -- a body defined
 * here, or nothing at all for a bare prototype -- provably sits outside
 * every edit. A function's FUNCTIONS token hash cannot stand in for this:
 * it hashes token spelling, so a bare "__LINE__" or "__builtin_LINE()"
 * reads the same before and after a pure move even though its expansion
 * changed, and is the reason fxc_mark_positions (line 404) folds a moved
 * span in as "code-moved" (FXI_DIRTY_SPAN, conservative) rather than
 * leaving it for the digest rule to catch. Span-clean is what this check
 * relies on. Every other row this entity has (its DECLS/SYMBOLS/alias
 * text) is still digest-covered: by the time fxc_position runs,
 * fxc_semantic already returned false for this pair, so whole_digest
 * (fxi_whole_digest, devloop_facts_index.c fxi_digests) is identical on
 * both sides, and a second declaration's text (a header prototype, say)
 * does not encode a line number to unsettle that. __COUNTER__ anywhere in
 * either manifest already refuses narrowing outright (fxc_counts, run
 * from fxc_coarse before fxc_fine), so a moved declaration cannot
 * silently reorder someone else's counter.
 *
 * A variable never qualifies, moved or not: it has no span at all (spans
 * come only from cm_emit_span, called for a function definition), so this
 * check is vacuously true for it regardless of what its initializer does.
 * cm_value_facts/cm_walk_site (clang_manifest_ast.c) record which macros a
 * variable definition's initializer names, not the value they expanded
 * to, so a __LINE__ that moves inside `int g = __LINE__;` changes no row
 * and leaves whole_digest identical too -- there is no proof anywhere in
 * the facts that its bytes are unaffected, so id[0] == 'v' is refused
 * outright below (unknown widens). */
static bool fxc_position_safe(const struct fxi *x, size_t dirty,
                              const uint8_t *flags)
{
    return fxi_id(x, dirty)[0] == 'f' && !(flags[dirty] & FXI_DIRTY_SPAN);
}

/* fxc_first_root reports only ONE witness (the first root index, cond
 * sites aside, that fxi_taint's multi-source BFS happens to connect to a
 * dirty entity): a manifest can carry a second, disjoint position-dirty
 * entity that no root examined above ever reaches through THAT witness,
 * so checking fxc_position_safe on the reported witness alone would let
 * an unrelated, unsafe move (a variable, or -- should fxc_semantic somehow
 * have missed it -- a span-dirty function) hide behind a safe one reached
 * by a different root in the same manifest. This re-taints from every
 * UNSAFE position-dirty entity alone and reports whether any root reaches
 * one; compile_only is granted only when this is false, so a mixed
 * manifest never loses a test obligation to the safe witness fxc_position
 * happened to report. */
static bool fxc_position_unsafe_reachable(const struct fxi *x,
                                          const uint8_t *flags)
{
    size_t n = fxi_count(x);
    uint8_t *seed = zcl_calloc(n + 1, 1, "facts_tu.punsafe");
    size_t *via = zcl_calloc(n + 1, sizeof(*via), "facts_tu.puvia");
    bool reached = seed == NULL || via == NULL; /* OOM: never assume safety */
    if (!reached) {
        for (size_t e = 0; e < n; e++)
            seed[e] = (flags[e] & FXI_DIRTY_POSITION) &&
                      !fxc_position_safe(x, e, flags);
        if (!fxi_taint(x, seed, via)) {
            reached = true; /* taint failed: never assume safety */
        } else {
            for (size_t e = 0; !reached && e < n; e++)
                reached = (fxi_root(x, e) || fxc_own_copy(x, e)) &&
                          via[e] != SIZE_MAX;
        }
    }
    free(seed);
    free(via);
    return reached;
}

static bool fxc_position(struct fxc_pair *p,
                         struct zcl_devloop_facts_tu_verdict *t, bool *ok)
{
    struct fxi *side[2] = {p->xa, p->xb};
    uint8_t *flags[2] = {p->fa, p->fb};
    for (int s = 0; *ok && s < 2; s++) {
        size_t n = fxi_count(side[s]), dirty = 0, root;
        size_t *via = zcl_calloc(n + 1, sizeof(*via), "facts_tu.pvia");
        root = via != NULL ? fxc_first_root(side[s], flags[s],
                                            FXI_DIRTY_POSITION, via, &dirty)
                           : SIZE_MAX - 1;
        free(via);
        *ok = root != SIZE_MAX - 1;
        if (*ok && root != SIZE_MAX) {
            fxc_set(t, true, false, "position",
                   "%s reaches %s, whose declaration moved",
                   fxi_id(side[s], root), fxi_id(side[s], dirty));
            if (!fxc_position_unsafe_reachable(side[s], flags[s]))
                t->compile_only = true;
            return true;
        }
    }
    return false;
}

/* The roots differ although no reached id is dirty: never narrowed. */
static bool fxc_roots_differ(const struct fxc_pair *p,
                            struct zcl_devloop_facts_tu_verdict *t)
{
    struct fxi_roots rb, ra;
    fxi_roots(p->xb, &rb);
    fxi_roots(p->xa, &ra);
    if (memcmp(rb.interface, ra.interface, 32) != 0)
        return fxc_set(t, true, true, "interface-changed",
                       "the reached interface differs");
    if (memcmp(rb.implementation, ra.implementation, 32) != 0)
        return fxc_set(t, true, true, "implementation-changed",
                       "a main-file record differs");
    return false;
}

/* The bytes of `path` differ between the sides that read it, or only one
 * side read it. */
static bool fxc_read_changed(const struct fxc_pair *p, const char *path)
{
    const uint8_t *a = fxi_file_digest(p->xa, path);
    const uint8_t *b = p->xb != NULL ? fxi_file_digest(p->xb, path) : NULL;
    if (a == NULL && b == NULL)
        return false;
    return a == NULL || b == NULL || memcmp(a, b, 32) != 0;
}

/* ---- static assertions ---------------------------------------------------------- */

/* The first "@assert:<path>" site of x that reaches a dirty id, or that
 * expands __LINE__ while <path> changed (every line below an edit may move);
 * SIZE_MAX when none does, SIZE_MAX - 1 when memory runs out. *dirty names
 * what it reaches (the site itself for __LINE__). */
static size_t fxc_assert_site(const struct fxc_pair *p, const struct fxi *x,
                              const uint8_t *flags, size_t *dirty)
{
    const size_t n = fxi_count(x), plen = strlen(VCS_SEMANTIC_FACTS_ASSERT_SITE);
    uint8_t *m = zcl_calloc(n + 1, 1, "facts_tu.amask");
    size_t *via = zcl_calloc(n + 1, sizeof(*via), "facts_tu.avia");
    size_t *line = zcl_calloc(n + 1, sizeof(*line), "facts_tu.aline");
    size_t hit = SIZE_MAX - 1;
    if (m != NULL && via != NULL && line != NULL) {
        for (size_t e = 0; e < n; e++)
            m[e] = flags[e] & (FXI_DIRTY_DIGEST | FXI_DIRTY_CHUNK);
        if (fxi_taint(x, m, via) && fxi_expands_builtin(x, "__LINE__", line))
            hit = SIZE_MAX;
    }
    for (size_t e = 0; hit == SIZE_MAX && e < n; e++) {
        if (!fxi_is_site(x, e, VCS_SEMANTIC_FACTS_ASSERT_SITE))
            continue;
        if (via[e] != SIZE_MAX) {
            hit = e;
            *dirty = via[e];
        } else if (line[e] != SIZE_MAX &&
                   fxc_read_changed(p, fxi_id(x, e) + plen)) {
            hit = e;
            *dirty = e;
        }
    }
    free(m);
    free(via);
    free(line);
    return hit;
}

/* No changed id reaches the TU's code, but a static_assert it reads, in a
 * header or at its own file scope, names one: the assertion can stop
 * holding, and the TU stop compiling, though its object would not change.
 * It joins the compile set with no test obligation. */
static bool fxc_static_assert(const struct fxc_pair *p,
                              struct zcl_devloop_facts_tu_verdict *t, bool *ok)
{
    struct fxi *side[2] = {p->xa, p->xb};
    uint8_t *flags[2] = {p->fa, p->fb};
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_ASSERT)
        return false;
#endif
    for (int s = 0; *ok && s < 2; s++) {
        size_t dirty = 0, site = fxc_assert_site(p, side[s], flags[s], &dirty);
        *ok = site != SIZE_MAX - 1;
        if (*ok && site != SIZE_MAX) {
            fxc_set(t, true, false, "static-assert", "%s reaches %s",
                    fxi_id(side[s], site), fxi_id(side[s], dirty));
            t->compile_only = true;
            return true;
        }
    }
    return false;
}

/* A manifest before facts revision 3 records no static_assert: nothing says
 * none of the headers this TU read asserts over what changed, so the TU
 * compiles (an assertion emits no bytes: no test obligation). */
static bool fxc_assert_unattributed(const struct fxc_pair *p,
                                    struct zcl_devloop_facts_tu_verdict *t)
{
    if (fxi_revision(p->xa) >= 3 && fxi_revision(p->xb) >= 3)
        return false;
    fxc_set(t, true, false, "static-assert-unattributed",
            "a revision-%u manifest records no static_assert",
            (unsigned)(fxi_revision(p->xa) < fxi_revision(p->xb)
                           ? fxi_revision(p->xa)
                           : fxi_revision(p->xb)));
    t->compile_only = true;
    return true;
}

/* The debug level either side compiles at. */
static int fxc_debug_level(const struct fxc_pair *p)
{
    int a = fxi_debug_level(p->xa);
    int b = p->xb != NULL ? fxi_debug_level(p->xb) : a;
    return a > b ? a : b;
}

/* The object compiler is known to write no checksum and no text of a file
 * the TU read into its debug information. gcc's line tables carry no
 * checksum; clang's DWARF 5 line tables (its default since clang 14) carry
 * each file's MD5, and -gembed-source (FXI_DEBUG_SOURCE) the text itself.
 * The identity's compiler is the sensor's own clang, not the object
 * compiler, and nothing else names it yet, so it is never known here and
 * every changed file a -g TU read fires fxc_debug_position. */
static bool fxc_debug_unsummed(const struct fxc_pair *p, int level)
{
    bool object_cc_gcc = false; /* unknown until the identity names it */
    (void)p;
    return object_cc_gcc && level < FXI_DEBUG_SOURCE;
}

/* No changed id reaches the TU's code, but it read a changed file and its
 * compile writes debug information (-g1 and above), so its object bytes may
 * change although its code does not: clang's DWARF 5 line tables record the
 * MD5 of every file in the TU's file table, which a comment that keeps the
 * line count changes too; -g2 and above record the line and column of every
 * type, function and variable the TU uses, -g3 of every #define, and
 * -gembed-source every byte. It joins the compile set and adds no test
 * obligation. Only a compile known to write no checksum
 * (fxc_debug_unsummed) may clear a file whose changed region holds no token
 * outside comments, at -g2 and above (-g1 and line tables record only the
 * functions and external variables the position rule names); a text it
 * cannot read never clears. The first file names the reason. */
static bool fxc_debug_position(struct fxc *c, const struct fxc_pair *p,
                               struct zcl_devloop_facts_tu_verdict *t)
{
    int level = fxc_debug_level(p);
    bool unsummed = fxc_debug_unsummed(p, level);
    const struct fxc_hdr *h;
    if (level < FXI_DEBUG_LINES || (unsummed && level < FXI_DEBUG_DECLS))
        return false;
    for (size_t k = 0; k < c->nfiles; k++) {
        if (!fxc_read_changed(p, c->files[k]))
            continue;
        if (unsummed && (h = fxc_hdr_load(c, c->files[k])) != NULL &&
            h->reason == NULL &&
            !fxh_region_has_code(&h->diff, level >= FXI_DEBUG_MACROS))
            continue;
        fxc_set(t, true, false, "debug-position",
                "-g%d debug information records %s, whose bytes changed",
                level, c->files[k]);
        t->compile_only = true;
        return true;
    }
    return false;
}

/* One side of a TU broadened by a changed .c it includes: every function
 * that .c defines here, and every function that reaches one, seeds the walk
 * (grown by the code-generation closure), whatever the dirty flags say. */
static bool fxc_included_c_side(struct fxc *c, const struct fxi *x,
                                const char *path)
{
    struct zcl_devloop_facts_tu_verdict scratch = {0};
    size_t n = x != NULL ? fxi_count(x) : 0;
    uint8_t *flags = zcl_calloc(n + 1, 1, "facts_tu.incflags");
    size_t *via = zcl_calloc(n + 1, sizeof(*via), "facts_tu.incvia");
    bool ok = flags != NULL && via != NULL;
    if (x == NULL || strcmp(fxi_main(x), path) == 0) {
        free(flags); /* no side, or the TU's own file: its rule chain seeds */
        free(via);
        return ok;
    }
    for (size_t e = 0; ok && e < n; e++)
        if (fxi_defined_function(x, e) && fxi_has_path(x, e, path))
            flags[e] = FXI_DIRTY_DIGEST;
    ok = ok && fxi_taint(x, flags, via) && fxc_seeds(c, x, via, &scratch);
    free(flags);
    free(via);
    return ok;
}

/* A changed .c this TU read on either side, whose bytes differ there. */
static bool fxc_changed_c_read(const struct fxc_pair *p, const char *path)
{
    size_t n = strlen(path);
    return n > 2 && strcmp(path + n - 2, ".c") == 0 &&
           fxc_read_changed(p, path);
}

/* A broadened TU that includes changed .c files (a unity build, a test that
 * reaches the statics) compiles their functions under names only its own
 * manifests know (a macro may rename them): for every such file, on either
 * side, they seed the walk, whichever rule broadened the TU. Seeds only;
 * the TU keeps its reason. */
static bool fxc_included_c_seeds(struct fxc *c, const struct fxc_pair *p)
{
    bool ok = true;
    for (size_t k = 0; ok && k < c->nfiles; k++)
        if (fxc_changed_c_read(p, c->files[k]))
            ok = fxc_included_c_side(c, p->xa, c->files[k]) &&
                 fxc_included_c_side(c, p->xb, c->files[k]);
    return ok;
}

/* A member broadened because its own evidence cannot be trusted (a cap cut
 * it, its producer is unknown or differs, or its before side is missing)
 * cannot name the functions a changed .c it includes compiles there: when
 * it read one other than its main file, the universe is incomplete. True
 * when the reason is such a one; the member then seeds nothing. */
static bool fxc_untrusted_includer(struct fxc *c, const struct fxc_pair *p,
                                   const struct zcl_devloop_facts_tu_verdict *t)
{
    static const char *const k_untrusted[] = {
        "truncated", "producer-unknown", "producer-mismatch", "facts-missing"};
    bool untrusted = false;
    for (size_t k = 0; k < sizeof(k_untrusted) / sizeof(k_untrusted[0]); k++)
        untrusted = untrusted || strcmp(t->reason, k_untrusted[k]) == 0;
    for (size_t k = 0; untrusted && k < c->nfiles; k++) {
        if (strcmp(c->files[k], fxi_main(p->xa)) != 0 &&
            fxc_changed_c_read(p, c->files[k])) {
            fxc_incomplete(c, t->reason, p->path);
            break;
        }
    }
    return untrusted;
}

/* The first changed file this TU read whose text broadens it names the
 * reason; true when one did. Its seeds, and those of every other changed .c
 * the TU includes, come from fxc_included_c_seeds. */
static bool fxc_changed_files(struct fxc *c, struct fxc_pair *p,
                              struct zcl_devloop_facts_tu_verdict *t)
{
    char detail[192];
    for (size_t k = 0; k < c->nfiles; k++) {
        const uint8_t *b = fxi_file_digest(p->xb, c->files[k]);
        const uint8_t *a = fxi_file_digest(p->xa, c->files[k]);
        const char *why;
        if (a == NULL || b == NULL || memcmp(a, b, 32) == 0)
            continue;
        why = fxc_changed_file(c, p, c->files[k], detail, sizeof(detail));
        if (why == NULL)
            continue;
        fxc_set(t, true, true, why, "%s", detail);
        return true;
    }
    return false;
}

static bool fxc_fine(struct fxc *c, struct fxc_pair *p,
                     struct zcl_devloop_facts_tu_verdict *t)
{
    bool ok = true;
    p->fa = zcl_calloc(fxi_count(p->xa) + 1, 1, "facts_tu.fa");
    p->fb = zcl_calloc(fxi_count(p->xb) + 1, 1, "facts_tu.fb");
    if (p->fa == NULL || p->fb == NULL)
        return false;
    fxc_mark_digests(p->xa, p->xb, p->fa);
    fxc_mark_digests(p->xb, p->xa, p->fb);
    if (fxc_changed_files(c, p, t))
        return true;
    if (!fxc_new_ids(c, p->xa, p->xb) || !fxc_new_ids(c, p->xb, p->xa))
        return false;
    if (fxc_semantic(c, p, t, &ok) || !ok)
        return ok;
    if (fxc_position(p, t, &ok) || !ok)
        return ok;
    if (fxc_roots_differ(p, t))
        return true;
    if (fxc_static_assert(p, t, &ok) || !ok)
        return ok;
    if (fxc_assert_unattributed(p, t))
        return true;
    if (fxc_debug_position(c, p, t))
        return true;
    return fxc_set(t, false, false, "unaffected",
                   "no changed id reaches its code");
}

/* ---- outsiders: TUs that read no changed file ------------------------------------ */

/* Why a TU that read no changed file still recompiles, or NULL: its compile
 * identity, its include resolution or another file it read changed under
 * it, or its before side is missing so nothing says it did not. */
static const char *fxc_outsider_reason(struct fxc *c, const struct fxc_pair *p)
{
    const char *why;
    bool sdir;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_OUTSIDER)
        return NULL;
#endif
    if (p->xb == NULL)
        return "facts-missing";
    if ((why = fxc_identity(c, p, &sdir)) != NULL)
        return why;
    if (fxc_resolution_moved(p, sdir))
        return "include-resolution-change";
    return fxc_unrequested(c, p) != NULL ? "unrequested-change" : NULL;
}

/* Such a TU is affected whole. When only its search dirs moved one of its
 * lookups, that is all that changed under it: it alone joins the plan.
 * Otherwise no fact bounds the change to the files asked about: the
 * universe is incomplete and every group is in scope. */
static bool fxc_outsider(struct fxc *c, const struct fxc_pair *p)
{
    const char *why = fxc_outsider_reason(c, p);
    struct zcl_devloop_facts_tu_verdict *t;
    bool moved;
    if (why == NULL)
        return true;
    t = fxc_tu_new(c, p->path);
    if (t == NULL)
        return false;
    moved = strcmp(why, "search-dir-resolution-change") == 0;
    fxc_identities(c, p, t);
    fxc_set(t, true, true, why, "it read none of the changed files%s",
            moved ? "; a search-dir change moved a lookup or a file" : "");
    fxc_incomplete(c, why, p->path);
    c->universal = c->universal || !moved;
    return true;
}

/* Mark each changed file some side of this pair read. */
static void fxc_note_reads(struct fxc *c, const struct fxc_pair *p)
{
    for (size_t k = 0; k < c->nfiles; k++)
        if (fxi_file_digest(p->xa, c->files[k]) != NULL ||
            (p->xb != NULL && fxi_file_digest(p->xb, c->files[k]) != NULL))
            c->hdrs[k].read = true;
}

/* Unless another rule already affects the TU as more than a compile: a
 * lookup with no negative claim on either side may now resolve to a
 * changed path: the TU is affected whole whatever its facts say, as the
 * after-bind's "lookup-unbound" says of the after side alone. */
static void fxc_unbound_verdict(const struct fxc *c, const struct fxc_pair *p,
                                struct zcl_devloop_facts_tu_verdict *t)
{
    const char *path;
    if (t->affected && !t->compile_only)
        return;
    path = fxc_unbound(c, p->a, p->alen);
    if (path == NULL)
        path = fxc_unbound(c, p->b, p->blen);
    if (path == NULL)
        path = fxc_unbound_old(c, p);
    if (path != NULL)
        fxc_set(t, true, true, "lookup-unbound",
                "a lookup that makes no negative claim may now resolve to %s",
                path);
}

bool fxc_tu_eval(struct fxc *c, const char *path)
{
    struct fxc_pair p = {0};
    struct zcl_devloop_facts_tu_verdict *t;
    bool ok = true;
    if (!fxc_load_pair(c, path, &p)) {
        fxc_pair_free(&p);
        /* nothing says whether it read a changed file or drifted */
        fxc_incomplete(c, "facts-invalid", path);
        c->universal = true;
        return true;
    }
    if (!fxc_collect_addresses(c, p.xa) || !fxc_collect_addresses(c, p.xb)) {
        fxc_pair_free(&p);
        return false;
    }
    fxc_note_reads(c, &p);
    if (!fxc_member(c, &p)) {
        ok = fxc_outsider(c, &p);
        fxc_pair_free(&p);
        return ok;
    }
    t = fxc_tu_new(c, path);
    ok = t != NULL;
    if (ok)
        fxc_identities(c, &p, t);
    if (ok && p.xb == NULL)
        fxc_set(t, true, true, "facts-missing", "no valid before manifest");
    else if (ok && !fxc_coarse(c, &p, t))
        ok = fxc_fine(c, &p, t);
    if (ok)
        fxc_unbound_verdict(c, &p, t);
    if (ok && t->affected && t->broadened && !fxc_untrusted_includer(c, &p, t))
        ok = fxc_included_c_seeds(c, &p);
    fxc_pair_free(&p);
    return ok;
}

/* ---- pass 2: the same-name rule --------------------------------------------------- */

/* A TU pass 1 left unaffected that has an id with the name of a new or
 * removed external id (a same-name static, macro or variable): its name
 * lookup may now resolve elsewhere, so it is affected. */
static bool fxc_collides(const struct fxc *c, const struct fxi *x,
                         const char **hit)
{
    for (size_t e = 0; x != NULL && e < fxi_count(x); e++) {
        if (fxc_strs_has(&c->new_names, fxi_bare(x, e)) &&
            !fxc_strs_has(&c->new_ids, fxi_id(x, e))) {
            *hit = fxi_id(x, e);
            return true;
        }
    }
    return false;
}

bool fxc_name_collisions(struct fxc *c)
{
    for (size_t k = 0; c->new_names.n > 0 && k < c->report->ntus; k++) {
        struct zcl_devloop_facts_tu_verdict *t = &c->report->tus[k];
        struct fxc_pair p = {0};
        const char *hit = NULL;
        if ((t->affected && !t->compile_only) ||
            !fxc_load_pair(c, t->path, &p)) {
            fxc_pair_free(&p);
            continue;
        }
        if (fxc_collides(c, p.xa, &hit) || fxc_collides(c, p.xb, &hit))
            fxc_set(t, true, true, "name-collision",
                    "%s shares its name with a new or removed external id",
                    hit);
        fxc_pair_free(&p);
    }
    return true;
}
