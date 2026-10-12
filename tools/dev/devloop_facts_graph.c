/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Facts index graph: macro-body, type-text and typedef closure edges, adjacency, the TU's reachable interface, its four identities and dirty-id taint. */
#include "devloop_facts_index_priv.h"

#include "devloop.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "vcs/semantic_manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FXI_ENTITY_DOMAIN "zcl.semantic.entity.v1"
#define ZCL_FXI_SITE_MAX 4200

static bool fxi_ident_start(unsigned char c)
{
    return c == '_' || c == '$' || ((c | 0x20) >= 'a' && (c | 0x20) <= 'z');
}

static bool fxi_ident_byte(unsigned char c)
{
    return fxi_ident_start(c) || (c >= '0' && c <= '9');
}

/* ---- macro bodies: a macro reaches the name group of each identifier ----- */

static bool fxi_macro_edges(struct fxi *x)
{
    char id[4096];
    for (size_t k = 0; k < x->nmacros; k++) {
        const struct fxi_macro m = x->macros[k];
        for (size_t i = 0; i < m.len;) {
            size_t j = i;
            uint32_t g;
            if (!fxi_ident_start((unsigned char)m.body[i]) ||
                (i > 0 && fxi_ident_byte((unsigned char)m.body[i - 1]))) {
                i++;
                continue;
            }
            while (j < m.len && fxi_ident_byte((unsigned char)m.body[j]))
                j++;
            int w = snprintf(id, sizeof(id), "m:%.*s", (int)(j - i), m.body + i);
            if (w > 0 && (size_t)w < sizeof(id) &&
                fxi_lookup(x, id, (size_t)w, &g) &&
                (!fxi_edge_add(x, m.ent, g, 0) || !fxi_edge_add(x, m.group, g, 0)))
                return false;
            i = j;
        }
    }
    return true;
}

/* ---- type texts: a record reaches every tag its canonical types name ------ */

/* Tag entities sorted by (prefix, bare name), for the name lookups below. */
struct fxi_tag {
    const struct fxi_ent *t;
    uint32_t e;
};

struct fxi_tags {
    struct fxi_tag *e;
    size_t n;
};

static int fxi_tag_key_cmp(const struct fxi_tag *a, char p, const char *name,
                           size_t len)
{
    int r;
    if (a->t->id[0] != p)
        return a->t->id[0] < p ? -1 : 1;
    r = strncmp(a->t->bare, name, len);
    if (r != 0)
        return r;
    return a->t->bare[len] == '\0' ? 0 : 1;
}

static int fxi_tag_cmp(const void *a, const void *b)
{
    const struct fxi_ent *x = ((const struct fxi_tag *)a)->t;
    const struct fxi_ent *y = ((const struct fxi_tag *)b)->t;
    int r = (int)(unsigned char)x->id[0] - (int)(unsigned char)y->id[0];
    return r != 0 ? r : strcmp(x->bare, y->bare);
}

static bool fxi_is_tag(const struct fxi_ent *t)
{
    return (t->id[0] == 's' || t->id[0] == 'u' || t->id[0] == 'e') &&
           t->id[1] == ':';
}

static bool fxi_tags_build(const struct fxi *x, struct fxi_tags *tags)
{
    tags->n = 0;
    tags->e = zcl_calloc(x->nents + 1, sizeof(*tags->e), "facts_index.tags");
    if (tags->e == NULL)
        return false;
    for (size_t k = 0; k < x->nents; k++)
        if (fxi_is_tag(&x->ents[k]))
            tags->e[tags->n++] = (struct fxi_tag){.t = &x->ents[k],
                                                  .e = (uint32_t)k};
    qsort(tags->e, tags->n, sizeof(*tags->e), fxi_tag_cmp);
    return true;
}

/* Edges from `from` to every tag entity (prefix, name). */
static bool fxi_tag_edges(struct fxi *x, const struct fxi_tags *tags,
                          uint32_t from, char p, const char *name, size_t len)
{
    size_t lo = 0, hi = tags->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (fxi_tag_key_cmp(&tags->e[mid], p, name, len) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    for (; lo < tags->n && fxi_tag_key_cmp(&tags->e[lo], p, name, len) == 0;
         lo++)
        if (!fxi_edge_add(x, from, tags->e[lo].e, 0))
            return false;
    return true;
}

static bool fxi_word_at(const uint8_t *s, size_t n, size_t i, const char *w)
{
    size_t k = strlen(w);
    return i + k <= n && memcmp(s + i, w, k) == 0 &&
           (i == 0 || !fxi_ident_byte(s[i - 1]));
}

/* One keyword at s[i]: its tag's edges; returns the bytes consumed. */
static size_t fxi_type_word(struct fxi *x, const struct fxi_tags *tags,
                            uint32_t from, uint32_t anon, const uint8_t *s,
                            size_t n, size_t i, bool *ok)
{
    static const struct {
        const char *word;
        char prefix;
    } k[] = {{"struct ", 's'}, {"union ", 'u'}, {"enum ", 'e'}};
    if (fxi_word_at(s, n, i, "(unnamed") || fxi_word_at(s, n, i, "(anonymous")) {
        *ok = fxi_edge_add(x, from, anon, 0);
        return 2;
    }
    for (size_t w = 0; w < sizeof(k) / sizeof(k[0]); w++) {
        size_t at = i + strlen(k[w].word), j;
        if (!fxi_word_at(s, n, i, k[w].word))
            continue;
        for (j = at; j < n && fxi_ident_byte(s[j]); j++)
            ;
        if (j > at)
            *ok = fxi_tag_edges(x, tags, from, k[w].prefix,
                                (const char *)s + at, j - at);
        return j - i;
    }
    return 1;
}

static bool fxi_type_edges(struct fxi *x, const struct fxi_tags *tags,
                           uint32_t anon)
{
    size_t nrows = x->nrows;
    for (size_t k = 0; k < nrows; k++) {
        const struct fxi_row r = x->rows[k];
        bool ok = true;
        if (r.section != VCS_SEMANTIC_SECTION_V1_DECLS &&
            r.section != VCS_SEMANTIC_SECTION_V1_LAYOUTS &&
            r.section != VCS_SEMANTIC_SECTION_V1_FUNCTIONS)
            continue;
        for (size_t i = 0; ok && i < r.len;)
            i += fxi_type_word(x, tags, r.ent, anon, r.raw, r.len, i, &ok);
        if (!ok)
            return false;
    }
    return true;
}

/* The anonymous-tag node: every tag without a name or named by the
 * typedef of the same name (clang names an unnamed tag by its typedef). */
static bool fxi_anon_edges(struct fxi *x, const struct fxi_tags *tags,
                           uint32_t anon)
{
    for (size_t k = 0; k < tags->n; k++) {
        const struct fxi_ent *t = tags->e[k].t;
        char id[4096];
        uint32_t td;
        int w = snprintf(id, sizeof(id), "t%s", t->id + 1);
        bool named_by_typedef = w > 0 && (size_t)w < sizeof(id) &&
                                fxi_lookup(x, id, (size_t)w, &td);
        if ((t->bare[0] == '\0' || named_by_typedef) &&
            !fxi_edge_add(x, anon, tags->e[k].e, 0))
            return false;
    }
    return true;
}

/* t:P:N reaches s:P:N, u:P:N and e:P:N: a typedef-named tag. */
static bool fxi_typedef_edges(struct fxi *x)
{
    size_t n = x->nents;
    for (size_t k = 0; k < n; k++) {
        char id[4096];
        const char *src = x->ents[k].id;
        if (src[0] != 't' || src[1] != ':')
            continue;
        for (const char *p = "sue"; *p; p++) {
            uint32_t tag;
            int w = snprintf(id, sizeof(id), "%c%s", *p, src + 1);
            if (w > 0 && (size_t)w < sizeof(id) &&
                fxi_lookup(x, id, (size_t)w, &tag) &&
                !fxi_edge_add(x, (uint32_t)k, tag, 0))
                return false;
        }
    }
    return true;
}

/* ---- file-scope sites of a header ------------------------------------------------ */

/* A header's file-scope expansions and conditionals shape its declarations,
 * layouts and enumerators, whose own records carry the result; what no record
 * carries is a variable's initializer and attributes. So "@scope:<header>"
 * and "@cond:<header>" are reached through the variables that header
 * declares, not from every reader of it. */
static bool fxi_site_edge(struct fxi *x, uint32_t from, const char *site,
                          const char *p, size_t n)
{
    char id[ZCL_FXI_SITE_MAX];
    uint32_t to;
    int w = snprintf(id, sizeof(id), "%s%.*s", site, (int)n, p);
    if (w <= 0 || (size_t)w >= sizeof(id) || !fxi_lookup(x, id, (size_t)w, &to))
        return true;
    return fxi_edge_add(x, from, to, 0);
}

static bool fxi_site_edges(struct fxi *x)
{
    size_t nents = x->nents;
    for (size_t e = 0; e < nents; e++) {
        const char *id = x->ents[e].id;
        if (id[0] != 'v' || id[1] != ':')
            continue;
        for (size_t k = 0; k < fxi_nrows(x, e); k++) {
            const char *p;
            size_t n;
            if (!fxi_row_path_at(x, e, k, &p, &n) ||
                (strlen(x->main) == n && memcmp(p, x->main, n) == 0))
                continue;
            if (!fxi_site_edge(x, (uint32_t)e, VCS_SEMANTIC_FACTS_SCOPE_SITE,
                               p, n) ||
                !fxi_site_edge(x, (uint32_t)e, VCS_SEMANTIC_FACTS_COND_SITE,
                               p, n))
                return false;
        }
    }
    return true;
}

/* ---- adjacency ------------------------------------------------------------------ */

static bool fxi_csr(struct fxi *x)
{
    size_t n = x->nents, m = x->nedges;
    uint32_t *fill = zcl_calloc(n + 1, sizeof(*fill), "facts_index.fill");
    x->out_off = zcl_calloc(n + 1, sizeof(*x->out_off), "facts_index.out");
    x->in_off = zcl_calloc(n + 1, sizeof(*x->in_off), "facts_index.in");
    x->out_edge = zcl_calloc(m + 1, sizeof(*x->out_edge), "facts_index.oute");
    x->in_edge = zcl_calloc(m + 1, sizeof(*x->in_edge), "facts_index.ine");
    if (!fill || !x->out_off || !x->in_off || !x->out_edge || !x->in_edge) {
        free(fill);
        return false;
    }
    for (size_t k = 0; k < m; k++) {
        x->out_off[x->edges[k].from + 1]++;
        x->in_off[x->edges[k].to + 1]++;
    }
    for (size_t k = 0; k < n; k++) {
        x->out_off[k + 1] += x->out_off[k];
        x->in_off[k + 1] += x->in_off[k];
    }
    for (size_t k = 0; k < m; k++)
        x->out_edge[x->out_off[x->edges[k].from] + fill[x->edges[k].from]++] =
            (uint32_t)k;
    memset(fill, 0, (n + 1) * sizeof(*fill));
    for (size_t k = 0; k < m; k++)
        x->in_edge[x->in_off[x->edges[k].to] + fill[x->edges[k].to]++] =
            (uint32_t)k;
    free(fill);
    return true;
}

bool fxi_graph_build(struct fxi *x)
{
    struct fxi_tags tags = {0};
    uint32_t anon;
    bool ok = fxi_ent_get(x, "@anon", 5, &anon);
    if (ok)
        zcl_sha3_256((const unsigned char *)FXI_ENTITY_DOMAIN,
                     strlen(FXI_ENTITY_DOMAIN), x->ents[anon].digest);
    bool macros = true, types = true;
#if defined(ZCL_TESTING)
    macros = zcl_devloop_test_consumer_mutant !=
             ZCL_DEVLOOP_MUTANT_NO_MACRO_CLOSURE;
    types = zcl_devloop_test_consumer_mutant !=
            ZCL_DEVLOOP_MUTANT_NO_TYPE_CLOSURE;
#endif
    ok = ok && (!macros || fxi_macro_edges(x)) &&
         (!types || (fxi_typedef_edges(x) && fxi_tags_build(x, &tags) &&
                     fxi_anon_edges(x, &tags, anon) &&
                     fxi_type_edges(x, &tags, anon))) &&
         fxi_site_edges(x) && fxi_csr(x);
    free(tags.e);
    return ok;
}

/* ---- accessors -------------------------------------------------------------------- */

const char *fxi_main(const struct fxi *x) { return x->main; }
bool fxi_complete(const struct fxi *x) { return x->complete; }
uint8_t fxi_revision(const struct fxi *x) { return x->revision; }
const uint8_t *fxi_producer(const struct fxi *x) { return x->producer; }
size_t fxi_file_count(const struct fxi *x) { return x->nfiles; }
size_t fxi_count(const struct fxi *x) { return x->nents; }
const char *fxi_id(const struct fxi *x, size_t e) { return x->ents[e].id; }
const char *fxi_bare(const struct fxi *x, size_t e) { return x->ents[e].bare; }
bool fxi_main_owned(const struct fxi *x, size_t e) { return x->ents[e].main_owned; }
bool fxi_root(const struct fxi *x, size_t e) { return x->ents[e].root; }
bool fxi_main_function(const struct fxi *x, size_t e) { return x->ents[e].main_fn; }

const uint8_t *fxi_digest(const struct fxi *x, size_t e)
{
    return x->ents[e].digest;
}

const uint8_t *fxi_whole_digest(const struct fxi *x, size_t e)
{
    return x->ents[e].whole;
}

const char *fxi_file_path(const struct fxi *x, size_t k)
{
    return x->files[k].path;
}

bool fxi_file_repo(const struct fxi *x, size_t k)
{
    return x->files[k].origin != VCS_SEMANTIC_ORIGIN_V1_SYSTEM;
}

const uint8_t *fxi_file_digest(const struct fxi *x, const char *path)
{
    size_t n = strlen(path);
    for (size_t k = 0; k < x->nfiles; k++)
        if (x->files[k].path_len == n && memcmp(x->files[k].path, path, n) == 0)
            return x->files[k].digest;
    return NULL;
}

void fxi_section_digest(const struct fxi *x, int section, uint8_t out[32])
{
    memcpy(out, x->section_digest[section], 32);
}

bool fxi_find(const struct fxi *x, const char *id, size_t *e)
{
    uint32_t k;
    if (!fxi_lookup(x, id, strlen(id), &k))
        return false;
    *e = k;
    return true;
}

bool fxi_external(const struct fxi *x, size_t e)
{
    const char *id = x->ents[e].id;
    return (id[0] == 'f' || id[0] == 'v') && id[1] == ':' &&
           strchr(id + 2, ':') == NULL;
}

bool fxi_is_site(const struct fxi *x, size_t e, const char *prefix)
{
    return strncmp(x->ents[e].id, prefix, strlen(prefix)) == 0;
}

/* The file a record names first: the path field of MACROS, DECLS, LAYOUTS,
 * ENUMS, FUNCTIONS and SPANS, the second field of SYMBOLS. */
static bool fxi_row_path(const struct fxi_row *r, const uint8_t **p, size_t *n)
{
    size_t at = 0;
    uint32_t len;
    if (r->section == VCS_SEMANTIC_SECTION_V1_REFS ||
        r->section == VCS_SEMANTIC_SECTION_V1_UNKNOWNS || r->len < 4)
        return false;
    if (r->section == VCS_SEMANTIC_SECTION_V1_SYMBOLS) {
        at = 4 + zcl_read_u32_le(r->raw);
        if (at + 4 > r->len)
            return false;
    }
    len = zcl_read_u32_le(r->raw + at);
    if (at + 4 + len > r->len)
        return false;
    *p = r->raw + at + 4;
    *n = len;
    return true;
}

bool fxi_has_path(const struct fxi *x, size_t e, const char *path)
{
    const struct fxi_ent *t = &x->ents[e];
    size_t want = strlen(path);
    for (uint32_t k = t->first_row; k < t->first_row + t->nrows; k++) {
        const uint8_t *p;
        size_t n;
        if (fxi_row_path(&x->rows[k], &p, &n) && n == want &&
            memcmp(p, path, n) == 0)
            return true;
    }
    return false;
}

bool fxi_span(const struct fxi *x, size_t e, const char *path, uint32_t *lo,
              uint32_t *hi)
{
    const struct fxi_ent *t = &x->ents[e];
    if (!t->has_span || t->span_path_len != strlen(path) ||
        memcmp(t->span_path, path, t->span_path_len) != 0)
        return false;
    *lo = t->span_lo;
    *hi = t->span_hi;
    return true;
}

bool fxi_refs_to(const struct fxi *x, const char *id, uint8_t kind)
{
    uint32_t e;
    if (!fxi_lookup(x, id, strlen(id), &e))
        return false;
    for (uint32_t k = x->in_off[e]; k < x->in_off[e + 1]; k++) {
        const struct fxi_edge *g = &x->edges[x->in_edge[k]];
        if (g->kind != 0 && (kind == 0 || g->kind == kind))
            return true;
    }
    return false;
}

bool fxi_unknown_effect(const struct fxi *x, size_t e, uint8_t *kind)
{
    uint8_t k = x->ents[e].unknown_kinds &
                (uint8_t)~(1u << VCS_SEMANTIC_UNKNOWN_V1_EXTERNAL_CALL);
    for (uint8_t b = 1; b < 8; b++) {
        if (k & (1u << b)) {
            *kind = b;
            return true;
        }
    }
    return false;
}

/* ---- identities ------------------------------------------------------------------- */

static void fxi_domain(struct sha3_256_ctx *h, const char *domain)
{
    sha3_256_init(h);
    sha3_256_write(h, (const unsigned char *)domain, strlen(domain) + 1);
}

/* Entities every root reaches along out-edges; `seen` has nents slots. */
static bool fxi_reach(const struct fxi *x, bool *seen, uint32_t *queue)
{
    size_t head = 0, tail = 0;
    for (size_t k = 0; k < x->nents; k++) {
        seen[k] = x->ents[k].root;
        if (seen[k])
            queue[tail++] = (uint32_t)k;
    }
    while (head < tail) {
        uint32_t e = queue[head++];
        for (uint32_t k = x->out_off[e]; k < x->out_off[e + 1]; k++) {
            uint32_t to = x->edges[x->out_edge[k]].to;
            if (!seen[to]) {
                seen[to] = true;
                queue[tail++] = to;
            }
        }
    }
    return true;
}

static int fxi_id_cmp(const void *a, const void *b)
{
    return strcmp((*(const struct fxi_ent *const *)a)->id,
                  (*(const struct fxi_ent *const *)b)->id);
}

/* Every reached id with records outside the main file, by id, with its
 * digest. */
static void fxi_interface(const struct fxi *x, uint8_t out[32])
{
    bool *seen = zcl_calloc(x->nents + 1, sizeof(*seen), "facts_index.seen");
    uint32_t *q = zcl_calloc(x->nents + 1, sizeof(*q), "facts_index.queue");
    const struct fxi_ent **list = zcl_calloc(x->nents + 1, sizeof(*list),
                                             "facts_index.iface");
    struct sha3_256_ctx h;
    size_t n = 0;
    fxi_domain(&h, "zcl.semantic.tu.interface.v1");
    if (seen != NULL && q != NULL && list != NULL && fxi_reach(x, seen, q)) {
        for (size_t k = 0; k < x->nents; k++)
            if (seen[k] && x->ents[k].other_row)
                list[n++] = &x->ents[k];
        qsort(list, n, sizeof(*list), fxi_id_cmp);
        for (size_t k = 0; k < n; k++) {
            uint8_t len[4];
            zcl_write_u32_le(len, (uint32_t)strlen(list[k]->id));
            sha3_256_write(&h, len, sizeof(len));
            sha3_256_write(&h, (const unsigned char *)list[k]->id,
                           strlen(list[k]->id));
            sha3_256_write(&h, list[k]->digest, 32);
        }
    } else {
        sha3_256_write(&h, (const unsigned char *)"out-of-memory", 13);
    }
    sha3_256_finalize(&h, out);
    free(seen);
    free(q);
    free(list);
}

static int fxi_raw_cmp(const void *a, const void *b)
{
    const struct fxi_row *x = *(const struct fxi_row *const *)a;
    const struct fxi_row *y = *(const struct fxi_row *const *)b;
    int r;
    if (x->section != y->section)
        return x->section < y->section ? -1 : 1;
    r = memcmp(x->raw, y->raw, x->len < y->len ? x->len : y->len);
    if (r != 0)
        return r;
    return x->len < y->len ? -1 : x->len > y->len;
}

/* The main file's bytes and its records, in canonical order, each once
 * (a macro or enum record is attached to two entities). */
static void fxi_implementation(const struct fxi *x, uint8_t out[32])
{
    const struct fxi_row **r = zcl_calloc(x->nrows + 1, sizeof(*r),
                                          "facts_index.impl");
    struct sha3_256_ctx h;
    size_t n = 0;
    fxi_domain(&h, "zcl.semantic.tu.implementation.v1");
    sha3_256_write(&h, x->main_digest, 32);
    for (size_t k = 0; r != NULL && k < x->nrows; k++)
        if (x->rows[k].main == 1)
            r[n++] = &x->rows[k];
    if (r != NULL)
        qsort(r, n, sizeof(*r), fxi_raw_cmp);
    for (size_t k = 0; k < n; k++) {
        uint8_t len[4];
        if (k > 0 && fxi_raw_cmp(&r[k - 1], &r[k]) == 0)
            continue;
        zcl_write_u32_le(len, r[k]->len);
        sha3_256_write(&h, &r[k]->section, 1);
        sha3_256_write(&h, len, sizeof(len));
        sha3_256_write(&h, r[k]->raw, r[k]->len);
    }
    if (r == NULL)
        sha3_256_write(&h, (const unsigned char *)"out-of-memory", 13);
    sha3_256_finalize(&h, out);
    free(r);
}

void fxi_roots(const struct fxi *x, struct fxi_roots *out)
{
    struct sha3_256_ctx h;
    fxi_domain(&h, "zcl.semantic.tu.source.v1");
    sha3_256_write(&h, x->section_digest[VCS_SEMANTIC_SECTION_V1_FILES], 32);
    sha3_256_finalize(&h, out->source);
    fxi_domain(&h, "zcl.semantic.tu.fact.v1");
    sha3_256_write(&h, x->m, x->n);
    sha3_256_finalize(&h, out->fact);
    fxi_interface(x, out->interface);
    fxi_implementation(x, out->implementation);
}

bool fxi_taint(const struct fxi *x, const uint8_t *flags, size_t *via)
{
    uint32_t *q = zcl_calloc(x->nents + 1, sizeof(*q), "facts_index.taint");
    size_t head = 0, tail = 0;
    if (q == NULL)
        return false;
    for (size_t k = 0; k < x->nents; k++) {
        via[k] = flags[k] ? k : SIZE_MAX;
        if (flags[k])
            q[tail++] = (uint32_t)k;
    }
    while (head < tail) {
        uint32_t e = q[head++];
        for (uint32_t k = x->in_off[e]; k < x->in_off[e + 1]; k++) {
            uint32_t from = x->edges[x->in_edge[k]].from;
            if (via[from] == SIZE_MAX) {
                via[from] = via[e];
                q[tail++] = from;
            }
        }
    }
    free(q);
    return true;
}

size_t fxi_nrows(const struct fxi *x, size_t e)
{
    return x->ents[e].nrows;
}

bool fxi_row_path_at(const struct fxi *x, size_t e, size_t k, const char **p,
                     size_t *n)
{
    const uint8_t *s;
    if (k >= x->ents[e].nrows ||
        !fxi_row_path(&x->rows[x->ents[e].first_row + k], &s, n))
        return false;
    *p = (const char *)s;
    return true;
}

size_t fxi_edge_count(const struct fxi *x)
{
    return x->nedges;
}

void fxi_edge_at(const struct fxi *x, size_t k, size_t *from, size_t *to,
                 uint8_t *kind)
{
    *from = x->edges[k].from;
    *to = x->edges[k].to;
    *kind = x->edges[k].kind;
}
