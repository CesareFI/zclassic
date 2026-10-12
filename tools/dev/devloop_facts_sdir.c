/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Decide whether a TU whose compile identity differs only in its -I/-iquote/-isystem/-idirafter dirs still resolves every include and probe as before, from each side's recorded lookups. */
#include "devloop_facts_consumer.h"

#include "base/serialize_le.h"
#include "base/safe_alloc.h"
#include "vcs/semantic_manifest.h"

#include <stdlib.h>
#include <string.h>

/* The IDENTITY record is compiler, resource dir, target and main file,
 * then argv, the quote, angled and ignored dir lists the front end printed
 * (canonical: repo-relative or "@sys/..."), and the environment. Only the
 * search-dir options of argv and the three lists may differ. The lookups
 * each side's compile recorded are its truth: a TU resolves as before when
 * every lookup has the same key, answer, file and dir on both sides and
 * the file set is the same. A lookup that makes no claim (include_next,
 * a computed or unbound spelling), a probe the replay could not explain,
 * a file no claimed lookup reached, a system header (the sensor records
 * none of the lookups a system header makes) or a search dir spelled other
 * than its canonical path (its opened names, and so __FILE__, may differ)
 * leaves nothing proved: that is drift. */

struct fxs_text {
    const uint8_t *p;
    size_t n;
};

struct fxs_cur {
    const uint8_t *p;
    size_t n, at;
    bool bad;
};

static uint32_t fxs_u32(struct fxs_cur *c)
{
    uint32_t v;
    if (c->bad || c->n - c->at < 4) {
        c->bad = true;
        return 0;
    }
    v = zcl_read_u32_le(c->p + c->at);
    c->at += 4;
    return v;
}

static uint8_t fxs_u8(struct fxs_cur *c)
{
    if (c->bad || c->at >= c->n) {
        c->bad = true;
        return 0;
    }
    return c->p[c->at++];
}

static struct fxs_text fxs_str(struct fxs_cur *c)
{
    uint32_t n = fxs_u32(c);
    struct fxs_text t = {0};
    if (c->bad || c->n - c->at < n) {
        c->bad = true;
        return t;
    }
    t.p = c->p + c->at;
    t.n = n;
    c->at += n;
    return t;
}

static bool fxs_eq(struct fxs_text a, struct fxs_text b)
{
    return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

static bool fxs_is(struct fxs_text a, const char *s)
{
    return fxs_eq(a, (struct fxs_text){.p = (const uint8_t *)s, .n = strlen(s)});
}

static bool fxs_starts(struct fxs_text a, const char *s)
{
    size_t n = strlen(s);
    return a.n >= n && memcmp(a.p, s, n) == 0;
}

/* ---- IDENTITY ---------------------------------------------------------------- */

struct fxs_list {
    struct fxs_text *v;
    uint32_t n;
};

struct fxs_ident {
    struct fxs_text head[4]; /* compiler, resource dir, target, main */
    struct fxs_list argv, quote, angled, ignored;
    struct fxs_text env;     /* the rest of the record, whole */
    size_t records;
    bool bad;
};

static bool fxs_list_read(struct fxs_cur *c, struct fxs_list *l)
{
    l->n = fxs_u32(c);
    if (c->bad || l->n > (c->n - c->at) / 4)
        return false;
    l->v = zcl_calloc((size_t)l->n + 1, sizeof(*l->v), "facts_sdir.list");
    for (uint32_t k = 0; l->v != NULL && k < l->n; k++)
        l->v[k] = fxs_str(c);
    return l->v != NULL && !c->bad;
}

static void fxs_ident_free(struct fxs_ident *d)
{
    free(d->argv.v);
    free(d->quote.v);
    free(d->angled.v);
    free(d->ignored.v);
}

static bool fxs_ident_cb(void *ctx, enum vcs_semantic_section_v1 section,
                         const struct vcs_semantic_fields_v1 *fields,
                         const uint8_t *raw, size_t raw_len)
{
    struct fxs_ident *d = ctx;
    struct fxs_cur c = {.p = raw, .n = raw_len};
    (void)fields;
    if (section != VCS_SEMANTIC_SECTION_V1_IDENTITY)
        return true;
    if (d->records++ > 0)
        return !(d->bad = true);
    for (int k = 0; k < 4; k++)
        d->head[k] = fxs_str(&c);
    d->bad = !fxs_list_read(&c, &d->argv) || !fxs_list_read(&c, &d->quote) ||
             !fxs_list_read(&c, &d->angled) || !fxs_list_read(&c, &d->ignored);
    d->env = (struct fxs_text){.p = raw + c.at, .n = raw_len - c.at};
    return !d->bad;
}

static bool fxs_ident_read(const uint8_t *m, size_t n, struct fxs_ident *d)
{
    return vcs_semantic_manifest_v1_each(m, n, fxs_ident_cb, d) && !d->bad &&
           d->records == 1;
}

/* The search-dir option at argv[k]: its value in *dir and the number of
 * words it spans, else 0. A joined value must not start with '-' ("-I-"
 * and "-isystem-after" are other options). */
static size_t fxs_dir_option(const struct fxs_list *argv, uint32_t k,
                             struct fxs_text *dir)
{
    static const char *const opts[] = {"-I", "-iquote", "-isystem",
                                       "-idirafter"};
    struct fxs_text a = argv->v[k];
    for (size_t o = 0; o < sizeof(opts) / sizeof(opts[0]); o++) {
        size_t n = strlen(opts[o]);
        if (fxs_is(a, opts[o])) {
            if (k + 1 >= argv->n)
                return 0;
            *dir = argv->v[k + 1];
            return 2;
        }
        if (fxs_starts(a, opts[o]) && a.p[n] != '-') {
            *dir = (struct fxs_text){.p = a.p + n, .n = a.n - n};
            return 1;
        }
    }
    return 0;
}

/* An option that reads files through the search dirs without a directive
 * the sensor records (a forced include, a module map), or that hides the
 * file system the probes replayed, or that passes such an option on. */
static bool fxs_opaque(struct fxs_text a)
{
    static const char *const opaque[] = {
        "-include", "-imacros", "-fmodule", "-fimplicit-module-maps",
        "-ivfsoverlay", "-Xclang", "-Xpreprocessor", "-Wp,",
    };
    for (size_t k = 0; k < sizeof(opaque) / sizeof(opaque[0]); k++)
        if (fxs_starts(a, opaque[k]))
            return true;
    return false;
}

static bool fxs_listed(const struct fxs_ident *d, struct fxs_text dir)
{
    const struct fxs_list *lists[] = {&d->quote, &d->angled, &d->ignored};
    for (size_t l = 0; l < 3; l++)
        for (uint32_t k = 0; k < lists[l]->n; k++)
            if (fxs_eq(lists[l]->v[k], dir))
                return true;
    return false;
}

/* The next argv word at or after *k that is no search-dir option; false
 * at the end. *spelled turns false for a dir spelled other than one of
 * the lists' canonical paths. */
static bool fxs_next_word(const struct fxs_ident *d, uint32_t *k,
                          struct fxs_text *out, bool *spelled)
{
    while (*k < d->argv.n) {
        struct fxs_text dir;
        size_t span = fxs_dir_option(&d->argv, *k, &dir);
        if (span == 0) {
            *out = d->argv.v[(*k)++];
            return true;
        }
        *spelled = *spelled && fxs_listed(d, dir);
        *k += (uint32_t)span;
    }
    return false;
}

/* Everything but the search dirs is the same, no option reads files the
 * lookups miss, and every search dir is spelled canonically. */
static bool fxs_argv_same(const struct fxs_ident *b, const struct fxs_ident *a)
{
    uint32_t kb = 0, ka = 0;
    bool spelled = true;
    for (;;) {
        struct fxs_text wb, wa;
        bool hb = fxs_next_word(b, &kb, &wb, &spelled);
        bool ha = fxs_next_word(a, &ka, &wa, &spelled);
        if (hb != ha)
            return false;
        if (!hb)
            return spelled;
        if (!fxs_eq(wb, wa) || fxs_opaque(wb))
            return false;
    }
}

static bool fxs_rest_same(const struct fxs_ident *b, const struct fxs_ident *a)
{
    for (int k = 0; k < 4; k++)
        if (!fxs_eq(b->head[k], a->head[k]))
            return false;
    return fxs_eq(b->env, a->env) && fxs_argv_same(b, a);
}

/* ---- LOOKUPS and FILES ------------------------------------------------------- */

struct fxs_lookup {
    struct fxs_text includer, spelled, hit;
    uint8_t form, kind, evidence;
    uint32_t slot, npresent;
};

struct fxs_file {
    struct fxs_text path;
    uint8_t origin;
};

struct fxs_side {
    struct fxs_ident id;
    struct fxs_lookup *look;
    size_t nlook, caplook;
    struct fxs_file *files;
    size_t nfiles, capfiles;
    bool bad;
};

static bool fxs_grow(void **v, size_t *cap, size_t n, size_t size)
{
    size_t next;
    void *grown;
    if (n < *cap)
        return true;
    next = *cap ? *cap * 2 : 16;
    grown = zcl_realloc(*v, next * size, "facts_sdir.grow");
    if (grown == NULL)
        return false;
    *v = grown;
    *cap = next;
    return true;
}

/* LOOKUPS: includer, spelled, form, kind, hit, hit slot, evidence, the
 * present slots. */
static bool fxs_lookup_add(struct fxs_side *s, const uint8_t *raw, size_t len)
{
    struct fxs_cur c = {.p = raw, .n = len};
    struct fxs_lookup l;
    l.includer = fxs_str(&c);
    l.spelled = fxs_str(&c);
    l.form = fxs_u8(&c);
    l.kind = fxs_u8(&c);
    l.hit = fxs_str(&c);
    l.slot = fxs_u32(&c);
    l.evidence = fxs_u8(&c);
    l.npresent = fxs_u32(&c);
    if (c.bad || !fxs_grow((void **)&s->look, &s->caplook, s->nlook,
                           sizeof(*s->look)))
        return false;
    s->look[s->nlook++] = l;
    return true;
}

/* FILES: path and origin. */
static bool fxs_file_add(struct fxs_side *s,
                         const struct vcs_semantic_fields_v1 *f)
{
    if (f->ntext < 1 || f->nnum < 1 ||
        !fxs_grow((void **)&s->files, &s->capfiles, s->nfiles,
                  sizeof(*s->files)))
        return false;
    s->files[s->nfiles++] = (struct fxs_file){
        .path = {.p = (const uint8_t *)f->text[0], .n = f->text_len[0]},
        .origin = (uint8_t)f->num[0]};
    return true;
}

static bool fxs_side_cb(void *ctx, enum vcs_semantic_section_v1 section,
                        const struct vcs_semantic_fields_v1 *fields,
                        const uint8_t *raw, size_t raw_len)
{
    struct fxs_side *s = ctx;
    bool ok = true;
    if (section == VCS_SEMANTIC_SECTION_V1_LOOKUPS)
        ok = fxs_lookup_add(s, raw, raw_len);
    else if (section == VCS_SEMANTIC_SECTION_V1_FILES)
        ok = fxs_file_add(s, fields);
    s->bad = s->bad || !ok;
    return ok;
}

static bool fxs_side_read(const uint8_t *m, size_t n, struct fxs_side *s)
{
    return m != NULL && fxs_ident_read(m, n, &s->id) &&
           vcs_semantic_manifest_v1_each(m, n, fxs_side_cb, s) && !s->bad;
}

static void fxs_side_free(struct fxs_side *s)
{
    fxs_ident_free(&s->id);
    free(s->look);
    free(s->files);
}

/* The dir a lookup's hit slot names (see vcs_semantic_absent_v1_each):
 * a quoted lookup's slot 0 is its includer's dir, then the quote dirs,
 * then the angled dirs. Past the list: no hit, an empty text. */
static struct fxs_text fxs_slot_dir(const struct fxs_ident *d,
                                    const struct fxs_lookup *l)
{
    uint32_t slot = l->slot;
    if (l->form == VCS_SEMANTIC_FORM_V1_QUOTED) {
        if (slot == 0) {
            struct fxs_text t = l->includer;
            while (t.n > 0 && t.p[t.n - 1] != '/')
                t.n--;
            return t.n > 0 ? (struct fxs_text){.p = t.p, .n = t.n - 1}
                           : (struct fxs_text){.p = (const uint8_t *)".", .n = 1};
        }
        slot -= 1;
        if (slot < d->quote.n)
            return d->quote.v[slot];
        slot -= d->quote.n;
    }
    return slot < d->angled.n ? d->angled.v[slot] : (struct fxs_text){0};
}

/* A claimed lookup of s hit path. */
static bool fxs_reached(const struct fxs_side *s, struct fxs_text path)
{
    for (size_t k = 0; k < s->nlook; k++)
        if (fxs_eq(s->look[k].hit, path))
            return true;
    return false;
}

/* Nothing in s escapes its recorded lookups: every lookup claims its
 * misses, its replay found the compiler's file first and a hit names its
 * dir, and every file but the main one is a repo file one of them
 * reached. */
static bool fxs_side_closed(const struct fxs_side *s)
{
    for (size_t k = 0; k < s->nlook; k++) {
        const struct fxs_lookup *l = &s->look[k];
        if (l->evidence == VCS_SEMANTIC_MISS_V1_NONE || l->npresent != 0 ||
            (l->hit.n > 0 && fxs_slot_dir(&s->id, l).n == 0))
            return false;
    }
    for (size_t k = 0; k < s->nfiles; k++) {
        const struct fxs_file *f = &s->files[k];
        if (f->origin == VCS_SEMANTIC_ORIGIN_V1_MAIN)
            continue;
        if (f->origin != VCS_SEMANTIC_ORIGIN_V1_REPO || !fxs_reached(s, f->path))
            return false;
    }
    return true;
}

static bool fxs_lookup_same(const struct fxs_side *b, const struct fxs_lookup *x,
                            const struct fxs_side *a, const struct fxs_lookup *y)
{
    return fxs_eq(x->includer, y->includer) && fxs_eq(x->spelled, y->spelled) &&
           x->form == y->form && x->kind == y->kind &&
           x->evidence == y->evidence && fxs_eq(x->hit, y->hit) &&
           fxs_eq(fxs_slot_dir(&b->id, x), fxs_slot_dir(&a->id, y));
}

/* By path and origin: what a file the TU reads on both sides now says is
 * the change being planned, which the rest of the TU's decision reads, as
 * it does when the identity is equal. */
static bool fxs_file_in(const struct fxs_side *s, const struct fxs_file *f)
{
    for (size_t k = 0; k < s->nfiles; k++)
        if (fxs_eq(s->files[k].path, f->path) &&
            s->files[k].origin == f->origin)
            return true;
    return false;
}

static bool fxs_resolved_same(const struct fxs_side *b, const struct fxs_side *a)
{
    if (b->nlook != a->nlook || b->nfiles != a->nfiles)
        return false;
    for (size_t k = 0; k < b->nlook; k++)
        if (!fxs_lookup_same(b, &b->look[k], a, &a->look[k]))
            return false;
    for (size_t k = 0; k < a->nfiles; k++)
        if (!fxs_file_in(b, &a->files[k]))
            return false;
    return true;
}

enum fxc_sdir fxc_sdir_delta(const uint8_t *b, size_t blen, const uint8_t *a,
                             size_t alen)
{
    struct fxs_side sb = {0}, sa = {0};
    enum fxc_sdir r = FXC_SDIR_DRIFT;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_SDIR_REPLAY)
        return FXC_SDIR_UNCHANGED;
#endif
    if (fxs_side_read(b, blen, &sb) && fxs_side_read(a, alen, &sa) &&
        fxs_rest_same(&sb.id, &sa.id) && fxs_side_closed(&sb) &&
        fxs_side_closed(&sa))
        r = fxs_resolved_same(&sb, &sa) ? FXC_SDIR_UNCHANGED
                                        : FXC_SDIR_CHANGED;
    fxs_side_free(&sb);
    fxs_side_free(&sa);
    return r;
}
