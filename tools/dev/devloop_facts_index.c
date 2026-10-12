/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Load one semantic manifest into the facts index: attach every record to its canonical id, digest each id's records, and record the TU's files and section digests. */
#include "devloop_facts_index_priv.h"

#include "devloop.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FXI_ID_MAX 8192

/* ---- growable arrays and the id table ------------------------------------ */

static bool fxi_grow(void **items, size_t *cap, size_t n, size_t elem)
{
    size_t next;
    void *grown;
    if (n < *cap)
        return true;
    next = *cap ? *cap * 2 : 64;
    grown = zcl_realloc(*items, next * elem, "facts_index.grow");
    if (grown == NULL)
        return false;
    *items = grown;
    *cap = next;
    return true;
}

static uint64_t fxi_hash(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t k = 0; k < n; k++) {
        h ^= (unsigned char)s[k];
        h *= 1099511628211ULL;
    }
    return h;
}

bool fxi_lookup(const struct fxi *x, const char *id, size_t len, uint32_t *e)
{
    size_t mask, j;
    if (x->nslots == 0)
        return false;
    mask = x->nslots - 1;
    for (j = (size_t)fxi_hash(id, len) & mask; x->slots[j]; j = (j + 1) & mask) {
        const char *t = x->ents[x->slots[j] - 1].id;
        if (strncmp(t, id, len) == 0 && t[len] == '\0') {
            *e = x->slots[j] - 1;
            return true;
        }
    }
    return false;
}

static bool fxi_rehash(struct fxi *x)
{
    size_t n = x->nslots ? x->nslots * 2 : 4096;
    uint32_t *slots = zcl_calloc(n, sizeof(*slots), "facts_index.slots");
    if (slots == NULL)
        return false;
    for (size_t k = 0; k < x->nents; k++) {
        size_t j = (size_t)fxi_hash(x->ents[k].id, strlen(x->ents[k].id)) & (n - 1);
        while (slots[j])
            j = (j + 1) & (n - 1);
        slots[j] = (uint32_t)(k + 1);
    }
    free(x->slots);
    x->slots = slots;
    x->nslots = n;
    return true;
}

static bool fxi_path_is(const char *p, size_t n, const char *s)
{
    return s != NULL && strlen(s) == n && memcmp(p, s, n) == 0;
}

/* A pseudo-site "@scope:<path>" or "@cond:<path>": owned by, and a root
 * of, the main file when <path> is it. A header's sites are reached through
 * the variables it declares (devloop_facts_graph.c). */
static void fxi_site_flags(struct fxi *x, struct fxi_ent *t)
{
    static const char *const k[] = {VCS_SEMANTIC_FACTS_SCOPE_SITE,
                                    VCS_SEMANTIC_FACTS_COND_SITE};
    for (size_t i = 0; i < 2; i++) {
        size_t n = strlen(k[i]);
        if (strncmp(t->id, k[i], n) != 0)
            continue;
        t->main_owned = x->main != NULL && strcmp(t->id + n, x->main) == 0;
        t->root = t->main_owned;
    }
}

bool fxi_ent_get(struct fxi *x, const char *id, size_t len, uint32_t *e)
{
    struct fxi_ent *t;
    size_t j;
    const char *colon;
    if (fxi_lookup(x, id, len, e))
        return true;
    if ((x->nents + 1) * 2 >= x->nslots && !fxi_rehash(x))
        return false;
    if (!fxi_grow((void **)&x->ents, &x->capents, x->nents, sizeof(*x->ents)))
        return false;
    t = &x->ents[x->nents];
    memset(t, 0, sizeof(*t));
    t->id = zcl_malloc(len + 1, "facts_index.id");
    if (t->id == NULL)
        return false;
    memcpy(t->id, id, len);
    t->id[len] = '\0';
    colon = strrchr(t->id, ':');
    t->bare = colon != NULL ? colon + 1 : t->id;
    fxi_site_flags(x, t);
    for (j = (size_t)fxi_hash(id, len) & (x->nslots - 1); x->slots[j];
         j = (j + 1) & (x->nslots - 1))
        ;
    x->slots[j] = (uint32_t)(x->nents + 1);
    *e = (uint32_t)x->nents++;
    return true;
}

/* The entity named by a printf-style id. */
static bool fxi_ent_fmt(struct fxi *x, uint32_t *e, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static bool fxi_ent_fmt(struct fxi *x, uint32_t *e, const char *fmt, ...)
{
    char id[FXI_ID_MAX];
    va_list ap;
    int w;
    va_start(ap, fmt);
    w = vsnprintf(id, sizeof(id), fmt, ap);
    va_end(ap);
    return w > 0 && (size_t)w < sizeof(id) && fxi_ent_get(x, id, (size_t)w, e);
}

bool fxi_edge_add(struct fxi *x, uint32_t from, uint32_t to, uint8_t kind)
{
    if (!fxi_grow((void **)&x->edges, &x->capedges, x->nedges,
                  sizeof(*x->edges)))
        return false;
    x->edges[x->nedges++] = (struct fxi_edge){.from = from, .to = to,
                                              .kind = kind};
    return true;
}

/* ---- records ---------------------------------------------------------------- */

struct fxi_load {
    struct fxi *x;
    uint32_t seq;
    const uint8_t *raw;
    size_t raw_len;
    enum vcs_semantic_section_v1 section;
    struct sha3_256_ctx sec[VCS_SEMANTIC_SECTION_V1_COUNT];
};

/* Attach the current record to entity e. main: 1, 0, or -1 (its entity
 * decides, for a site's REFS and UNKNOWNS). */
static bool fxi_row(struct fxi_load *L, uint32_t e, int8_t main)
{
    struct fxi *x = L->x;
    if (!fxi_grow((void **)&x->rows, &x->caprows, x->nrows, sizeof(*x->rows)))
        return false;
    x->rows[x->nrows++] = (struct fxi_row){
        .ent = e, .seq = L->seq, .section = (uint8_t)L->section,
        .main = main, .raw = L->raw, .len = (uint32_t)L->raw_len};
    if (main == 1)
        x->ents[e].main_owned = true;
    else if (main == 0)
        x->ents[e].other_row = true;
    return true;
}

/* The row's own file decides whether it belongs to the main file. */
static int8_t fxi_main_of(const struct fxi *x, const char *p, size_t n)
{
    return fxi_path_is(p, n, x->main) ? 1 : 0;
}

static bool fxi_on_file(struct fxi *x, const struct vcs_semantic_fields_v1 *f)
{
    struct fxi_file *file;
    if (f->ntext < 1 || f->nnum < 1 || f->ndigest < 1 ||
        !fxi_grow((void **)&x->files, &x->capfiles, x->nfiles, sizeof(*x->files)))
        return false;
    file = &x->files[x->nfiles];
    *file = (struct fxi_file){.path = zcl_malloc(f->text_len[0] + 1,
                                                 "facts_index.file"),
                              .path_len = f->text_len[0],
                              .digest = f->digest[0],
                              .origin = (uint8_t)f->num[0]};
    if (file->path == NULL)
        return false;
    x->nfiles++;
    memcpy(file->path, f->text[0], f->text_len[0]);
    file->path[f->text_len[0]] = '\0';
    if (f->num[0] != VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return true;
    x->main = zcl_malloc(f->text_len[0] + 1, "facts_index.main");
    if (x->main == NULL)
        return false;
    memcpy(x->main, f->text[0], f->text_len[0]);
    x->main[f->text_len[0]] = '\0';
    x->main_digest = f->digest[0];
    return true;
}

static bool fxi_on_facts(struct fxi *x, const struct vcs_semantic_fields_v1 *f)
{
    if (f->ntext < 1 || f->ndigest < 2 || f->nnum < 3)
        return false;
    memcpy(x->producer, f->digest[1], 32);
    x->complete = f->num[2] == 1;
    x->revision =
        fxi_path_is(f->text[0], f->text_len[0], VCS_SEMANTIC_FACTS_V4_NAME)   ? 4
        : fxi_path_is(f->text[0], f->text_len[0], VCS_SEMANTIC_FACTS_V3_NAME) ? 3
        : fxi_path_is(f->text[0], f->text_len[0], VCS_SEMANTIC_FACTS_V2_NAME) ? 2
                                                                              : 1;
    return true;
}

static bool fxi_on_macro(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    struct fxi *x = L->x;
    uint32_t e, g;
    int8_t main;
    if (f->ntext < 3)
        return false;
    main = fxi_main_of(x, f->text[0], f->text_len[0]);
    if (!fxi_ent_fmt(x, &e, "m:%.*s:%.*s", (int)f->text_len[0], f->text[0],
                     (int)f->text_len[1], f->text[1]) ||
        !fxi_ent_fmt(x, &g, "m:%.*s", (int)f->text_len[1], f->text[1]) ||
        !fxi_row(L, e, main) || !fxi_row(L, g, main) ||
        !fxi_grow((void **)&x->macros, &x->capmacros, x->nmacros,
                  sizeof(*x->macros)))
        return false;
    x->macros[x->nmacros++] = (struct fxi_macro){
        .ent = e, .group = g, .body = f->text[2], .len = f->text_len[2]};
    return true;
}

static char fxi_kind_prefix(const char *k, size_t n)
{
    static const struct {
        const char *kind;
        char prefix;
    } t[] = {{"function", 'f'}, {"variable", 'v'}, {"typedef", 't'},
             {"struct", 's'},   {"union", 'u'},    {"enum", 'e'}};
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++)
        if (fxi_path_is(k, n, t[i].kind))
            return t[i].prefix;
    return 0;
}

/* The canonical id of a declaration: prefix:name for a function or
 * variable with external linkage (3 or 4), else prefix:path:name. */
static bool fxi_decl_ent(struct fxi *x, char prefix, const char *path,
                         size_t path_len, const char *name, size_t name_len,
                         uint64_t linkage, uint32_t *e)
{
    bool external = (prefix == 'f' || prefix == 'v') &&
                    (linkage == 3 || linkage == 4);
    if (external)
        return fxi_ent_fmt(x, e, "%c:%.*s", prefix, (int)name_len, name);
    return fxi_ent_fmt(x, e, "%c:%.*s:%.*s", prefix, (int)path_len, path,
                       (int)name_len, name);
}

/* The sensor names a tag with linkage by its bare name (s:N, as REFS and
 * SYMBOLS spell it), while its DECLS, LAYOUTS and ENUMS records live on
 * s:<path>:N: the bare id reaches them, so a function that names the tag
 * only in its body still reaches a change of its layout. */
static bool fxi_tag_alias(struct fxi *x, char prefix, const char *name,
                          size_t name_len, uint64_t linkage, uint32_t e)
{
    uint32_t alias;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant == ZCL_DEVLOOP_MUTANT_NO_TAG_ALIAS)
        return true;
#endif
    if ((prefix != 's' && prefix != 'u' && prefix != 'e') ||
        (linkage != 3 && linkage != 4))
        return true;
    return fxi_ent_fmt(x, &alias, "%c:%.*s", prefix, (int)name_len, name) &&
           fxi_edge_add(x, alias, e, 0);
}

static bool fxi_on_decl(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    uint32_t e;
    char prefix;
    if (f->ntext < 4 || f->nnum < 1)
        return false;
    prefix = fxi_kind_prefix(f->text[1], f->text_len[1]);
    if (prefix == 0)
        return false;
    return fxi_decl_ent(L->x, prefix, f->text[0], f->text_len[0], f->text[2],
                        f->text_len[2], f->num[0], &e) &&
           fxi_row(L, e, fxi_main_of(L->x, f->text[0], f->text_len[0])) &&
           fxi_tag_alias(L->x, prefix, f->text[2], f->text_len[2], f->num[0], e);
}

static bool fxi_on_layout(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    uint32_t e;
    if (f->ntext < 2 || f->nnum < 1)
        return false;
    return fxi_ent_fmt(L->x, &e, "%c:%.*s:%.*s", f->num[0] == 2 ? 'u' : 's',
                       (int)f->text_len[0], f->text[0], (int)f->text_len[1],
                       f->text[1]) &&
           fxi_row(L, e, fxi_main_of(L->x, f->text[0], f->text_len[0]));
}

static bool fxi_on_enum(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    uint32_t k, e;
    int8_t main;
    if (f->ntext < 3)
        return false;
    main = fxi_main_of(L->x, f->text[0], f->text_len[0]);
    return fxi_ent_fmt(L->x, &k, "k:%.*s:%.*s", (int)f->text_len[0],
                       f->text[0], (int)f->text_len[2], f->text[2]) &&
           fxi_ent_fmt(L->x, &e, "e:%.*s:%.*s", (int)f->text_len[0],
                       f->text[0], (int)f->text_len[1], f->text[1]) &&
           fxi_row(L, k, main) && fxi_row(L, e, main);
}

static bool fxi_on_function(struct fxi_load *L,
                            const struct vcs_semantic_fields_v1 *f)
{
    struct fxi *x = L->x;
    uint32_t e;
    int8_t main;
    if (f->ntext < 3 || f->nnum < 1)
        return false;
    main = fxi_main_of(x, f->text[0], f->text_len[0]);
    if (!fxi_decl_ent(x, 'f', f->text[0], f->text_len[0], f->text[1],
                      f->text_len[1], f->num[0], &e) ||
        !fxi_row(L, e, main))
        return false;
    x->ents[e].main_fn |= main == 1;
    x->ents[e].defined_fn = true;
    /* A header definition with external linkage is emitted by every TU
     * that reads it; an internal one is its own copy (fxc_own_copy). */
    x->ents[e].root |= main == 0 && (f->num[0] == 3 || f->num[0] == 4);
    return true;
}

static bool fxi_on_span(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    struct fxi *x = L->x;
    char id[FXI_ID_MAX];
    uint32_t e;
    int w;
    if (f->ntext < 2 || f->nnum < 2)
        return false;
    w = snprintf(id, sizeof(id), "f:%.*s:%.*s", (int)f->text_len[0],
                 f->text[0], (int)f->text_len[1], f->text[1]);
    if (w <= 0 || (size_t)w >= sizeof(id))
        return false;
    if (!fxi_lookup(x, id, (size_t)w, &e)) {
        w = snprintf(id, sizeof(id), "f:%.*s", (int)f->text_len[1], f->text[1]);
        if (!fxi_lookup(x, id, (size_t)w, &e))
            return true;
    }
    x->ents[e].has_span = true;
    x->ents[e].span_path = f->text[0];
    x->ents[e].span_path_len = f->text_len[0];
    x->ents[e].span_lo = (uint32_t)f->num[0];
    x->ents[e].span_hi = (uint32_t)f->num[1];
    return true;
}

static bool fxi_on_symbol(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    struct fxi *x = L->x;
    uint32_t e;
    int8_t main;
    if (f->ntext < 3 || f->nnum < 2)
        return false;
    main = fxi_main_of(x, f->text[1], f->text_len[1]);
    if (!fxi_ent_get(x, f->text[0], f->text_len[0], &e) || !fxi_row(L, e, main))
        return false;
    /* A variable a header defines may be emitted by every reader. */
    x->ents[e].root |= main == 0 && f->num[1] == 1 &&
                       fxi_path_is(f->text[2], f->text_len[2], "variable");
    return true;
}

static bool fxi_on_ref(struct fxi_load *L, const struct vcs_semantic_fields_v1 *f)
{
    uint32_t from, to;
    if (f->ntext < 2 || f->nnum < 1)
        return false;
    return fxi_ent_get(L->x, f->text[0], f->text_len[0], &from) &&
           fxi_ent_get(L->x, f->text[1], f->text_len[1], &to) &&
           fxi_row(L, from, -1) &&
           fxi_edge_add(L->x, from, to, (uint8_t)f->num[0]);
}

static bool fxi_on_unknown(struct fxi_load *L,
                           const struct vcs_semantic_fields_v1 *f)
{
    uint32_t e;
    if (f->ntext < 1 || f->nnum < 1 || f->num[0] > 7)
        return false;
    if (!fxi_ent_get(L->x, f->text[0], f->text_len[0], &e) || !fxi_row(L, e, -1))
        return false;
    L->x->ents[e].unknown_kinds |= (uint8_t)(1u << f->num[0]);
    return true;
}

static bool fxi_on_entity_record(struct fxi_load *L,
                                 const struct vcs_semantic_fields_v1 *f)
{
    switch (L->section) {
    case VCS_SEMANTIC_SECTION_V1_MACROS: return fxi_on_macro(L, f);
    case VCS_SEMANTIC_SECTION_V1_DECLS: return fxi_on_decl(L, f);
    case VCS_SEMANTIC_SECTION_V1_LAYOUTS: return fxi_on_layout(L, f);
    case VCS_SEMANTIC_SECTION_V1_ENUMS: return fxi_on_enum(L, f);
    case VCS_SEMANTIC_SECTION_V1_FUNCTIONS: return fxi_on_function(L, f);
    case VCS_SEMANTIC_SECTION_V1_SPANS: return fxi_on_span(L, f);
    case VCS_SEMANTIC_SECTION_V1_SYMBOLS: return fxi_on_symbol(L, f);
    case VCS_SEMANTIC_SECTION_V1_REFS: return fxi_on_ref(L, f);
    case VCS_SEMANTIC_SECTION_V1_UNKNOWNS: return fxi_on_unknown(L, f);
    default: return true;
    }
}

static bool fxi_on_record(void *ctx, enum vcs_semantic_section_v1 section,
                          const struct vcs_semantic_fields_v1 *f,
                          const uint8_t *raw, size_t raw_len)
{
    struct fxi_load *L = ctx;
    uint8_t len[4];
    zcl_write_u32_le(len, (uint32_t)raw_len);
    sha3_256_write(&L->sec[section], len, sizeof(len));
    sha3_256_write(&L->sec[section], raw, raw_len);
    L->seq++;
    L->raw = raw;
    L->raw_len = raw_len;
    L->section = section;
    if (section == VCS_SEMANTIC_SECTION_V1_IDENTITY) {
        L->x->identity = raw;
        L->x->identity_len = raw_len;
        L->x->compiler = f->ntext > 0 ? f->text[0] : NULL;
        L->x->compiler_len = f->ntext > 0 ? f->text_len[0] : 0;
        L->x->target = f->ntext > 2 ? f->text[2] : NULL;
        L->x->target_len = f->ntext > 2 ? f->text_len[2] : 0;
        return true;
    }
    if (section == VCS_SEMANTIC_SECTION_V1_FILES)
        return fxi_on_file(L->x, f);
    if (section == VCS_SEMANTIC_SECTION_V1_FACTS)
        return fxi_on_facts(L->x, f);
    return fxi_on_entity_record(L, f);
}

/* ---- digests ------------------------------------------------------------------ */

static int fxi_row_cmp(const void *a, const void *b)
{
    const struct fxi_row *x = a, *y = b;
    if (x->ent != y->ent)
        return x->ent < y->ent ? -1 : 1;
    return x->seq < y->seq ? -1 : x->seq > y->seq;
}

static void fxi_hash_row(struct sha3_256_ctx *h, const struct fxi_row *r)
{
    uint8_t len[4];
    zcl_write_u32_le(len, r->len);
    sha3_256_write(h, &r->section, 1);
    sha3_256_write(h, len, sizeof(len));
    sha3_256_write(h, r->raw, r->len);
}

/* Each entity's digest: its records outside the main file, in order. */
static void fxi_digests(struct fxi *x)
{
    for (size_t k = 0; k < x->nrows; k++) {
        struct fxi_row *r = &x->rows[k];
        if (r->main < 0)
            r->main = x->ents[r->ent].main_owned ? 1 : 0;
    }
    if (x->nrows > 1)
        qsort(x->rows, x->nrows, sizeof(*x->rows), fxi_row_cmp);
    for (size_t k = 0; k < x->nrows;) {
        struct fxi_ent *t = &x->ents[x->rows[k].ent];
        struct sha3_256_ctx h, w;
        size_t j = k;
        sha3_256_init(&h);
        sha3_256_write(&h, (const unsigned char *)"zcl.semantic.entity.v1", 22);
        w = h;
        t->first_row = (uint32_t)k;
        for (; j < x->nrows && x->rows[j].ent == x->rows[k].ent; j++) {
            fxi_hash_row(&w, &x->rows[j]);
            if (x->rows[j].main != 0)
                continue;
            fxi_hash_row(&h, &x->rows[j]);
            t->other_row = true;
        }
        t->nrows = (uint32_t)(j - k);
        sha3_256_finalize(&h, t->digest);
        sha3_256_finalize(&w, t->whole);
        k = j;
    }
    for (size_t k = 0; k < x->nents; k++) {
        if (x->ents[k].nrows == 0) {
            zcl_sha3_256((const unsigned char *)"zcl.semantic.entity.v1", 22,
                         x->ents[k].digest);
            memcpy(x->ents[k].whole, x->ents[k].digest, 32);
        }
        x->ents[k].root |= x->ents[k].main_owned;
    }
}

/* ---- debug information level ---------------------------------------------- */

/* -g spellings with a fixed level; a bare -g or -ggdb and a format option
 * raise the level to 2 at least (fxi_g_raises); any other -g option that
 * does not only modify the format (below) is taken at FXI_DEBUG_SOURCE. */
static const struct {
    const char *flag;
    int level;
} k_fxi_g_levels[] = {
    {"-g0", 0},    {"-ggdb0", 0},       {"-g1", 1},
    {"-ggdb1", 1}, {"-gline-tables-only", 1}, {"-gmlt", 1},
    {"-gline-directives-only", 1}, {"-g2", 2},
    {"-ggdb2", 2}, {"-g3", 3},      {"-ggdb3", 3},
};

/* Options that change how debug information is written, not whether nor
 * what it records of the source (-gembed-source copies the text in: see
 * fxi_debug_arg). */
static const char *const k_fxi_g_modifiers[] = {
    "-gno-",          "-gz",            "-gcolumn-info",
    "-gstrict-dwarf", "-grecord-",      "-gpubnames",
    "-ggnu-pubnames", "-gsimple-template-names",
    "-gstatement-frontiers", "-gvariable-location-views",
    "-ginline-points", "-gdescribe-dies", "-gas-loc",
    "-ginternal-reset-location-views",
};

/* Options that turn full debug information on in a given format. */
static const char *const k_fxi_g_formats[] = {
    "-gdwarf", "-gsplit-dwarf", "-gcodeview", "-gbtf", "-gctf",
};

static bool fxi_has_prefix(const uint8_t *t, size_t n, const char *p)
{
    size_t k = strlen(p);
    return n >= k && memcmp(t, p, k) == 0;
}

static bool fxi_prefix_in(const uint8_t *t, size_t n, const char *const *v,
                          size_t nv)
{
    for (size_t k = 0; k < nv; k++)
        if (fxi_has_prefix(t, n, v[k]))
            return true;
    return false;
}

/* A bare -g or -ggdb, or a format option: at least types and declarations,
 * but a level already higher stays (-g3 -g is still -g3 to gcc; clang's
 * last -g wins, and the higher level is the conservative one). */
static bool fxi_g_raises(const uint8_t *t, size_t n)
{
    return fxi_path_is((const char *)t, n, "-g") ||
           fxi_path_is((const char *)t, n, "-ggdb") ||
           fxi_prefix_in(t, n, k_fxi_g_formats,
                         sizeof(k_fxi_g_formats) / sizeof(k_fxi_g_formats[0]));
}

/* The level after one -g option, given the level before it. */
static int fxi_g_option(const uint8_t *t, size_t n, int level)
{
    for (size_t k = 0; k < sizeof(k_fxi_g_levels) / sizeof(k_fxi_g_levels[0]);
         k++)
        if (fxi_path_is((const char *)t, n, k_fxi_g_levels[k].flag))
            return k_fxi_g_levels[k].level;
    if (fxi_prefix_in(t, n, k_fxi_g_modifiers,
                      sizeof(k_fxi_g_modifiers) / sizeof(k_fxi_g_modifiers[0])))
        return level;
    if (fxi_g_raises(t, n))
        return level > FXI_DEBUG_DECLS ? level : FXI_DEBUG_DECLS;
    return FXI_DEBUG_SOURCE;
}

/* One text field of a record body at *at: its bytes and length. */
static bool fxi_text_at(const uint8_t *s, size_t n, size_t *at,
                        const uint8_t **t, size_t *len)
{
    if (n - *at < 4)
        return false;
    *len = zcl_read_u32_le(s + *at);
    *at += 4;
    if (*len > n - *at)
        return false;
    *t = s + *at;
    *at += *len;
    return true;
}

/* What the argv asks the debug information to hold, option by option. */
struct fxi_dbg {
    int level;
    bool macro; /* -fdebug-macro: #defines at any level */
    bool embed; /* -gembed-source: every file's text */
};

static void fxi_debug_arg(const uint8_t *t, size_t n, struct fxi_dbg *d)
{
    if (fxi_path_is((const char *)t, n, "-fdebug-macro"))
        d->macro = true;
    else if (fxi_path_is((const char *)t, n, "-gembed-source"))
        d->embed = true;
    else if (fxi_path_is((const char *)t, n, "-gno-embed-source"))
        d->embed = false;
    else if (fxi_has_prefix(t, n, "-g"))
        d->level = fxi_g_option(t, n, d->level);
}

int fxi_debug_level_of(const uint8_t *identity, size_t len)
{
    size_t at = 0, n = 0;
    const uint8_t *t = NULL;
    uint32_t argc;
    struct fxi_dbg d = {0};
    /* compiler, resource dir, target and main file come before argv */
    for (int k = 0; k < 4; k++)
        if (identity == NULL || !fxi_text_at(identity, len, &at, &t, &n))
            return FXI_DEBUG_SOURCE;
    if (len - at < 4)
        return FXI_DEBUG_SOURCE;
    argc = zcl_read_u32_le(identity + at);
    at += 4;
    for (uint32_t k = 0; k < argc; k++) {
        if (!fxi_text_at(identity, len, &at, &t, &n))
            return FXI_DEBUG_SOURCE;
        fxi_debug_arg(t, n, &d);
    }
    if (d.level > 0 && d.embed)
        return FXI_DEBUG_SOURCE;
    return d.level > 0 && d.macro && d.level < FXI_DEBUG_MACROS
               ? FXI_DEBUG_MACROS
               : d.level;
}

int fxi_debug_level(const struct fxi *x)
{
    return fxi_debug_level_of(x->identity, x->identity_len);
}

struct fxi *fxi_open(const uint8_t *m, size_t n, const char **why)
{
    struct fxi *x = zcl_calloc(1, sizeof(*x), "facts_index");
    struct fxi_load *L = zcl_calloc(1, sizeof(*L), "facts_index.load");
    bool ok = x != NULL && L != NULL;
    *why = "out-of-memory";
    if (ok) {
        x->m = m;
        x->n = n;
        L->x = x;
        for (int t = 0; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++)
            sha3_256_init(&L->sec[t]);
        ok = fxi_rehash(x);
    }
    if (ok && !vcs_semantic_manifest_v1_each(m, n, fxi_on_record, L)) {
        *why = "invalid-manifest";
        ok = false;
    }
    if (ok && (x->main == NULL || x->revision == 0)) {
        *why = x->main == NULL ? "invalid-manifest" : "no-facts";
        ok = false;
    }
    for (int t = 0; L != NULL && t < VCS_SEMANTIC_SECTION_V1_COUNT; t++)
        sha3_256_finalize(&L->sec[t], x ? x->section_digest[t] : (uint8_t[32]){0});
    free(L);
    if (ok) {
        fxi_digests(x);
        ok = fxi_graph_build(x);
    }
    if (!ok) {
        fxi_free(x);
        return NULL;
    }
    *why = "";
    return x;
}

void fxi_free(struct fxi *x)
{
    if (x == NULL)
        return;
    for (size_t k = 0; k < x->nents; k++)
        free(x->ents[k].id);
    free(x->ents);
    free(x->slots);
    free(x->rows);
    free(x->macros);
    free(x->edges);
    for (size_t k = 0; x->files != NULL && k < x->nfiles; k++)
        free(x->files[k].path);
    free(x->files);
    free(x->main);
    free(x->out_off);
    free(x->out_edge);
    free(x->in_off);
    free(x->in_edge);
    free(x);
}
