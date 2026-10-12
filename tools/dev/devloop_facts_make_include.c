/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The facts consumer's make reader, include lines: which files an include line names, and which missing optional includes a conditional of the root makefile provably skips, read under named premises and recorded in the plan. */
#include "devloop_facts_make_guard.h"

#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- make inputs: include lines ------------------------------------------------- */

/* The shape of $(X:.o=.d) or $(X:%.o=%.d). */
static bool fxm_depfile_ref(const char *w, size_t n)
{
    return n >= 8 && w[0] == '$' && (w[1] == '(' || w[1] == '{') &&
           strncmp(w + n - 3, ".d", 2) == 0 && (w[n - 4] == '=' || w[n - 4] == '%');
}

/* w[0..n) (a bracketed reference's '$') is that one reference whole. */
static bool fxm_whole_bracket(const char *w, size_t n)
{
    char close = w[1] == '(' ? ')' : '}';
    int depth = 1;
    size_t k = 2;
    for (; k < n && depth > 0; k++)
        depth += w[k] == w[1] ? 1 : w[k] == close ? -1 : 0;
    return depth == 0 && k == n;
}

/* A depfile an include line names: $(X:.o=.d), $(X:%.o=%.d), or a
 * literal name ending in .d. Its text is a compiler's -MD output, whose
 * prerequisite lines name only what that compile read: the depfiles
 * themselves answer for it (docs/work/SEMANTIC_MANIFEST.md). */
static bool fxm_depfile_word(const char *w, size_t n)
{
    if (n >= 2 && w[n - 2] == '.' && w[n - 1] == 'd' && memchr(w, '$', n) == NULL)
        return true;
    return fxm_depfile_ref(w, n) && fxm_whole_bracket(w, n) &&
           fxm_subst_colon(w + 2, n - 3) < n - 3;
}

/* Where an optional include names a missing file: the guards read it. */
static bool fxm_inc_add(struct fxm *m, const char *w)
{
    struct fxm_inc *g;
    if (m->nincs == m->capincs) {
        size_t next = m->capincs ? m->capincs * 2 : 16;
        g = zcl_realloc(m->incs, next * sizeof(*g), "facts_consumer.mkinc");
        if (g == NULL)
            return false;
        m->incs = g;
        m->capincs = next;
    }
    g = &m->incs[m->nincs];
    g->path = zcl_strdup(w, "facts_consumer.mkincpath");
    g->file = m->cur_file;
    g->at = m->pos[1];
    m->nincs += g->path != NULL;
    return g->path != NULL;
}

/* One word of an include line: a literal repo file is read; a missing one
 * is made by a rule the text holds (UNKNOWN, checked once every rule is
 * read) or read by nobody; a word that is not one literal file (a
 * reference no single definition gives, a glob) is UNKNOWN, optional or
 * not: what it reads can reach any goal. */
static void fxm_include_word(struct fxm *m, const char *w, bool optional)
{
    w = fxm_strip_dot(w); /* make reads ./build/gen.mk as build/gen.mk */
    if (strpbrk(w, FXM_WILDS) != NULL) {
        m->unknown = true;
        return;
    }
    if (w[0] == '/' || strstr(w, "..") != NULL) {
        m->inc_outside = true; /* not a tracked input; a rule may remake it */
        return;
    }
    if (fxm_exists(m->root, w)) {
        m->unknown |= !fxm_load(m, w);
        return;
    }
    if (fxm_depfile_word(w, strlen(w))) {
        m->inc_depfile = true;
        return;
    }
    m->unknown |= !optional || !fxc_strs_add(&m->missing, w) ||
                  !fxm_inc_add(m, w);
}

/* Every whitespace-separated word of an expanded include line's argument
 * text (already macro-expanded by fxm_include). */
static void fxm_include_words(struct fxm *m, char *s, bool optional)
{
    for (; !m->unknown && s != NULL && *s != '\0';) {
        char *w;
        while (fxm_space(*s))
            s++;
        for (w = s; *s != '\0' && !fxm_space(*s); s++)
            ;
        if (*s != '\0')
            *s++ = '\0';
        if (*w != '\0')
            fxm_include_word(m, w, optional);
    }
}

/* The include line's argument text p, less its depfile words (noted in
 * m->inc_depfile), into in. */
static bool fxm_include_text(struct fxm *m, const char *p, struct fxm_buf *in)
{
    in->n = 0;
    if (!fxm_put(in, "", 0))
        return false;
    while (*p != '\0') {
        const char *w;
        int depth = 0;
        bool dep;
        while (fxm_space(*p))
            p++;
        for (w = p; *p != '\0' && (depth > 0 || !fxm_space(*p)); p++)
            depth += (*p == '(' || *p == '{') - (*p == ')' || *p == '}');
        dep = p > w && fxm_depfile_word(w, (size_t)(p - w));
        m->inc_depfile |= dep;
        if (p > w && !dep &&
            (!fxm_put(in, w, (size_t)(p - w)) || !fxm_put(in, " ", 1)))
            return false;
    }
    return true;
}

/* An include line: its words expanded (a many-word value as its words). */
void fxm_include(struct fxm *m, const char *line)
{
    const char *p = line;
    bool optional = *p == '-' || *p == 's';
    bool left = true;
    struct fxm_buf *in = &m->a, *out = &m->b;
    while (*p != '\0' && !fxm_space(*p))
        p++;
    m->unknown |= !fxm_include_text(m, p, in);
    m->lists = true;
    for (int r = 0; !m->unknown && left && r < FXM_ROUNDS; r++) {
        struct fxm_buf *t = in;
        m->unknown |= !fxm_round(m, in->p, out, &left);
        in = out;
        out = t;
    }
    m->lists = false;
    m->unknown |= left;
    if (!m->unknown)
        fxm_include_words(m, in->p, optional);
}

/* ---- make inputs: the conditionals that skip a missing include ----------------- */
/* ---- the root makefile's assignments ---- */

static bool fxg_site_add(struct fxg *g, const char *name, size_t n,
                         uint8_t op, uint32_t line)
{
    struct fxg_site *s;
    if (g->nsites == g->capsites) {
        size_t next = g->capsites ? g->capsites * 2 : 1024;
        s = zcl_realloc(g->sites, next * sizeof(*s), "facts_consumer.mkgsite");
        if (s == NULL)
            return false;
        g->sites = s;
        g->capsites = next;
    }
    s = &g->sites[g->nsites];
    memset(s, 0, sizeof(*s));
    s->name = zcl_malloc(n + 1, "facts_consumer.mkgname");
    if (s->name == NULL)
        return false;
    memcpy(s->name, name, n);
    s->name[n] = '\0';
    s->op = op;
    s->line = line;
    g->nsites++;
    return true;
}

/* A variable a line may set whose name is name[0..n): a literal name a
 * site, a computed one the glob of the names it spells (fxm_name_glob);
 * one it cannot bound opens every variable. */
static bool fxg_open_name(struct fxg *g, const char *name, size_t n,
                          uint8_t op)
{
    char text[FXM_NAME_MAX];
    bool literal;
    while (n > 0 && fxg_blank(name[n - 1]))
        n--;
    while (n > 0 && fxg_blank(*name)) {
        name++;
        n--;
    }
    if (n == 0 || n >= FXM_NAME_MAX) {
        g->open_all = true;
        return true;
    }
    literal = memchr(name, '$', n) == NULL;
    if (literal && !g->sorted)
        return fxg_site_add(g, name, n, op, FXG_NO);
    memcpy(text, name, n);
    text[n] = '\0';
    if (g->npats == g->cappats) {
        size_t next = g->cappats ? g->cappats * 2 : 64;
        char(*p)[FXM_NAME_MAX] =
            zcl_realloc(g->pats, next * sizeof(*p), "facts_consumer.mkgpat");
        if (p == NULL)
            return false;
        g->pats = p;
        g->cappats = next;
    }
    if (literal)
        memcpy(g->pats[g->npats++], text, n + 1);
    else if (fxm_name_glob(text, g->pats[g->npats]))
        g->npats++;
    else
        g->open_all = true;
    return true;
}

/* The operator of a definition at op: its kind and length. */
static size_t fxg_op(const char *op, uint8_t *kind)
{
    static const struct {
        const char *s;
        uint8_t kind;
    } ops[] = {{":::=", FXG_OPEN}, {"::=", FXG_SET}, {":=", FXG_SET},
               {"+=", FXG_OPEN},   {"?=", FXG_DEFAULT}, {"!=", FXG_OPEN},
               {"=", FXG_LAZY}};
    for (size_t k = 0; k < sizeof(ops) / sizeof(ops[0]); k++)
        if (strncmp(op, ops[k].s, strlen(ops[k].s)) == 0) {
            *kind = ops[k].kind;
            return strlen(ops[k].s);
        }
    *kind = FXG_OPEN;
    return 0;
}

/* Where the operator of the definition p starts (p is one: fxm_kind_of). */
static const char *fxg_op_at(const char *p)
{
    const char *q = fxm_top(p, ":=");
    if (q != NULL && *q == '=' && q > p && strchr("+?!", q[-1]) != NULL)
        q--;
    return q;
}

/* The value past the operator, as make keeps it: leading blanks dropped,
 * a comment cut (the blanks before it kept), the reader's joining space
 * at the end dropped. A backslash the reading does not unescape opens it. */
static bool fxg_value(const char *v, const char **out, size_t *n)
{
    const char *hash;
    while (fxm_space(*v))
        v++;
    if (strchr(v, '\\') != NULL)
        return false;
    hash = fxm_top(v, "#");
    *out = v;
    *n = hash != NULL ? (size_t)(hash - v) : strlen(v);
    if (hash == NULL && *n > 0 && v[*n - 1] == ' ')
        (*n)--;
    return true;
}

/* A definition line of the root (line k) or of another file (FXG_NO). */
static bool fxg_def(struct fxg *g, const char *raw, uint32_t k)
{
    const char *p = fxm_skip_prefixes(raw), *op = fxg_op_at(p), *v;
    size_t len, vlen;
    uint8_t kind;
    if (op == NULL) {
        g->open_all = true;
        return true;
    }
    len = fxg_op(op, &kind);
    if (k == FXG_NO || kind == FXG_OPEN || memchr(p, '$', (size_t)(op - p)) ||
        !fxg_value(op + len, &v, &vlen))
        return fxg_open_name(g, p, (size_t)(op - p), FXG_OPEN);
    while (op > p && fxg_blank(op[-1]))
        op--;
    if (op == p || !fxg_site_add(g, p, (size_t)(op - p), kind, k))
        return op != p;
    g->sites[g->nsites - 1].value = v;
    g->sites[g->nsites - 1].vlen = vlen;
    return true;
}

/* A target-specific value (`t: V = x`): V is open. */
static bool fxg_tsv(struct fxg *g, const char *raw, size_t from)
{
    const char *p = fxm_skip_prefixes(raw + from), *op = fxg_op_at(p);
    if (op == NULL) {
        g->open_all = true;
        return true;
    }
    return fxg_open_name(g, p, (size_t)(op - p), FXG_OPEN);
}

/* `define NAME` (with any prefix): NAME holds lines no value reading
 * knows. */
static bool fxg_define_line(struct fxg *g, const char *p, uint32_t k)
{
    size_t n = 0;
    p += 6;
    while (fxm_space(*p))
        p++;
    while (p[n] != '\0' && !fxm_space(p[n]) && p[n] != '=' &&
           !(p[n] == ':' && p[n + 1] == '=') && !(p[n] == '+' && p[n + 1] == '='))
        n++;
    if (n == 0 || memchr(p, '$', n) != NULL)
        return fxg_open_name(g, p, n, FXG_OPEN);
    return fxg_site_add(g, p, n, FXG_DEFINE, k);
}

/* A line of a define an $(eval) reads, as make then reads it: what it can
 * set is open. A line that is only a reference can expand to any line. A
 * tab line after a rule line is that rule's recipe. */
static bool fxg_body(struct fxg *g, const char *raw, bool *in_rule)
{
    size_t colon = 0;
    const char *p = fxm_skip_prefixes(raw);
    enum fxm_kind kind = fxm_kind_of(raw, &colon);
    if (*raw == '\t' && *in_rule)
        return true;
    if (*p != '\0')
        *in_rule = kind == FXM_K_RULE;
    if (kind == FXM_K_DEF)
        return fxg_def(g, raw, FXG_NO);
    if (kind == FXM_K_TSV)
        return fxg_tsv(g, raw, colon + 1);
    if (fxm_starts_word(p, "define") || fxm_starts_word(p, "undefine"))
        return fxg_open_name(g, p + 6 + (*p == 'u') * 2,
                             strcspn(p + 6 + (*p == 'u') * 2, "=\n"), FXG_OPEN);
    if (kind == FXM_K_OTHER && *p == '$')
        g->open_all = true;
    return true;
}

/* Every line of the define name, as an $(eval) of it reads them. */
static void fxg_eval_body(struct fxg *g, const char *name)
{
    bool in_rule = false;
    for (size_t k = 0; k < g->m->nlines && !g->open_all; k++) {
        const struct fxm_line *l = &g->m->lines[k];
        if (l->ctx == FXM_DEF && l->body && strcmp(l->name, name) == 0 &&
            !fxg_body(g, l->raw, &in_rule))
            g->open_all = true;
    }
}

static uint8_t fxg_cond_cls(const char *p)
{
    while (fxm_space(*p))
        p++;
    if (fxm_starts_word(p, "ifeq") || fxm_starts_word(p, "ifneq") ||
        fxm_starts_word(p, "ifdef") || fxm_starts_word(p, "ifndef"))
        return FXG_C_IF;
    if (fxm_starts_word(p, "endif"))
        return FXG_C_ENDIF;
    if (!fxm_starts_word(p, "else"))
        return FXG_C_NONE;
    for (p += 4; fxm_space(*p); p++)
        ;
    return *p == '\0' || *p == '#' ? FXG_C_ELSE : FXG_C_ELSE_IF;
}

/* A directive line: a conditional of the root, a define, an undefine, a
 * load (anything). */
static bool fxg_directive(struct fxg *g, const struct fxm_line *l, uint32_t k)
{
    const char *p = fxm_skip_prefixes(l->raw);
    if (k != FXG_NO && l->ctx == FXM_QUIET)
        g->cls[k] = fxg_cond_cls(l->raw);
    if (fxm_starts_word(p, "define"))
        return fxg_define_line(g, p, k);
    if (fxm_starts_word(p, "undefine"))
        return fxg_open_name(g, p + 8, strlen(p + 8), FXG_OPEN);
    g->open_all |= fxm_starts_word(p, "load") || fxm_starts_word(p, "-load") ||
                   strstr(l->raw, ".RECIPEPREFIX") != NULL;
    return true;
}

static bool fxg_line(struct fxg *g, size_t k)
{
    const struct fxm_line *l = &g->m->lines[k];
    uint32_t at = k < g->m->root_lines ? (uint32_t)k : FXG_NO;
    if (l->ctx == FXM_RECIPE)
        return true;
    /* Text holding the reading's own markers cannot be read by it. */
    g->open_all |= strpbrk(l->raw, "\x06\x07") != NULL;
    if (l->ctx == FXM_DEF && l->body)
        return true; /* read when an $(eval) reads it */
    if (l->ctx == FXM_DEF && l->from > 0)
        return fxg_tsv(g, l->raw, l->from);
    if (l->ctx == FXM_DEF)
        return fxg_def(g, l->raw, at);
    if (l->ctx == FXM_QUIET || l->ctx == FXM_ACTIVE)
        return fxg_directive(g, l, at);
    return true;
}

static int fxg_site_cmp(const void *a, const void *b)
{
    const struct fxg_site *x = a, *y = b;
    int d = strcmp(x->name, y->name);
    if (d != 0)
        return d;
    return x->line < y->line ? -1 : x->line > y->line;
}

/* The sites of name: [*lo, *hi). */
void fxg_range(const struct fxg *g, const char *name, size_t *lo,
               size_t *hi)
{
    size_t a = 0, b = g->nsites;
    while (a < b) {
        size_t mid = a + (b - a) / 2;
        if (strcmp(g->sites[mid].name, name) < 0)
            a = mid + 1;
        else
            b = mid;
    }
    *lo = a;
    for (b = a; b < g->nsites && strcmp(g->sites[b].name, name) == 0; b++)
        ;
    *hi = b;
}
/* ---- $(eval): what its text can set ---- */


static bool fxg_starts(const char *s, size_t n, const char *w)
{
    size_t k = strlen(w);
    return n > k && strncmp(s, w, k) == 0 && fxm_space(s[k]);
}

/* $(eval $(call NAME,...)): NAME must be the one define of that name,
 * whose lines are then read as makefile text. */
static void fxg_eval_call(struct fxg *g, const char *a, size_t n)
{
    char name[FXM_NAME_MAX];
    size_t len = 0, lo, hi;
    while (n > 0 && fxm_space(*a))
        a++, n--;
    while (len < n && len + 1 < sizeof(name) && fxm_ident(a[len]))
        len++;
    memcpy(name, a, len);
    name[len] = '\0';
    fxg_range(g, name, &lo, &hi);
    g->open_all |= len == 0 || hi != lo + 1 || g->sites[lo].op != FXG_DEFINE;
    if (!g->open_all)
        fxg_eval_body(g, name);
}

/* $(eval NAME op value): NAME is open. A value that expands anything but
 * a $(shell) (whose newlines make turns to spaces) can hold more lines. */
static void fxg_eval_def(struct fxg *g, const char *text)
{
    const char *op = fxg_op_at(text), *v;
    size_t refs = 0, shells = 0;
    if (op == NULL) {
        g->open_all = true;
        return;
    }
    for (v = strchr(op, '$'); v != NULL; v = strchr(v + 1, '$')) {
        refs++;
        shells += strncmp(v, "$(shell", 7) == 0 && fxm_space(v[7]);
    }
    g->open_all |= refs != shells;
    if (!g->open_all && !fxg_open_name(g, text, (size_t)(op - text), FXG_OPEN))
        g->open_all = true;
}

/* An $(eval) of a define ($(call NAME,...)) sets what the define's lines
 * set; one of a literal assignment sets its variable; one of a rule sets
 * none; any other can set anything. */
static void fxg_eval_arg(struct fxg *g, const char *a, size_t n)
{
    size_t colon = 0;
    char text[FXG_TEXT];
    enum fxm_kind kind;
    while (n > 0 && fxg_blank(*a))
        a++, n--;
    if (n > 1 && a[0] == '$' && a[1] == '$')
        a++, n--; /* $$(call ...) in a define */
    if (fxg_starts(a, n, "$(call") || fxg_starts(a, n, "${call")) {
        fxg_eval_call(g, a + 7, n - 7);
        return;
    }
    if (n == 0)
        return;
    if (n >= sizeof(text) || *a == '$' || memchr(a, '\n', n) != NULL) {
        g->open_all = true;
        return;
    }
    memcpy(text, a, n);
    text[n] = '\0';
    kind = fxm_kind_of(text, &colon);
    if (kind == FXM_K_DEF)
        fxg_eval_def(g, text);
    else
        g->open_all |= kind == FXM_K_OTHER;
}

/* Every $(eval ...) (${eval}, $$(eval) in a define) a line holds. */
static void fxg_evals(struct fxg *g, const char *s)
{
    size_t n = strlen(s);
    for (const char *p = strstr(s, "eval"); p != NULL && !g->open_all;
         p = strstr(p + 4, "eval")) {
        size_t k = (size_t)(p - s), e;
        if (k < 2 || s[k - 2] != '$' || (s[k - 1] != '(' && s[k - 1] != '{') ||
            !fxm_space(p[4]))
            continue;
        e = fxg_close(s, k - 1, n);
        if (e >= n) {
            g->open_all = true;
            return;
        }
        fxg_eval_arg(g, p + 5, e - (k + 4) - 1);
    }
}

/* Where each root line sits among the conditionals: the branch line that
 * opens its branch (g->up), and for a branch line the one before it in its
 * chain (g->prev). A chain the reading cannot follow (an else or endif
 * with no if, one open at the end, too deep) leaves g->nest_ok false: no
 * branch is then pruned. */
static void fxg_nest(struct fxg *g)
{
    uint32_t head[FXM_COND_MAX], last[FXM_COND_MAX];
    int d = 0;
    g->nest_ok = true;
    for (uint32_t k = 0; g->nest_ok && k < g->m->root_lines; k++) {
        uint8_t c = g->cls[k];
        g->up[k] = d > 0 ? last[d - 1] : FXG_NO;
        g->prev[k] = FXG_NO;
        if (c == FXG_C_IF) {
            g->nest_ok = d < FXM_COND_MAX;
            if (g->nest_ok) {
                head[d] = k;
                last[d++] = k;
            }
        } else if (c != FXG_C_NONE && d == 0) {
            g->nest_ok = false;
        } else if (c == FXG_C_ENDIF) {
            d--;
        } else if (c != FXG_C_NONE) {
            g->up[k] = g->up[head[d - 1]];
            g->prev[k] = last[d - 1];
            last[d - 1] = k;
        }
    }
    g->nest_ok = g->nest_ok && d == 0;
}

/* Read every line: the root's conditionals and assignments, and what
 * other lines can set. */
static bool fxg_collect(struct fxg *g)
{
    struct fxm *m = g->m;
    size_t lo, hi;
    for (size_t k = 0; k < m->nlines && !g->open_all; k++)
        if (!fxg_line(g, k))
            return false;
    fxg_nest(g);
    if (g->nsites > 1)
        qsort(g->sites, g->nsites, sizeof(*g->sites), fxg_site_cmp);
    g->sorted = true;
    for (size_t k = 0; k < g->nsites; k++)
        if (g->sites[k].line != FXG_NO)
            g->site_at[g->sites[k].line] = (uint32_t)k;
    for (size_t k = 0; k < m->nlines && !g->open_all; k++)
        if (m->lines[k].ctx != FXM_RECIPE)
            fxg_evals(g, m->lines[k].raw);
    fxg_range(g, "zcl_compile_epoch", &lo, &hi);
    g->epoch_ok = hi == lo + 1 && g->sites[lo].op == FXG_DEFINE &&
                  g->sites[lo].line != FXG_NO;
    return true;
}

/* ---- the directives ---- */

/* The two sides of `(A,B)` as make reads them (parentheses counted, the
 * blanks after A and before B dropped); false for any other form. */
static bool fxg_sides(const char *p, const char **a, size_t *an,
                      const char **b, size_t *bn)
{
    int count = 0;
    const char *q;
    while (fxm_space(*p))
        p++;
    if (*p++ != '(')
        return false;
    for (q = p; *q != '\0' && !(*q == ',' && count <= 0); q++)
        count += (*q == '(') - (*q == ')');
    if (*q != ',')
        return false;
    *a = p;
    *an = (size_t)(q - p);
    while (*an > 0 && fxm_space(p[*an - 1]))
        (*an)--;
    for (p = q + 1; fxm_space(*p); p++)
        ;
    for (count = 0, q = p; *q != '\0' && !(*q == ')' && count <= 0); q++)
        count += (*q == '(') - (*q == ')');
    if (*q != ')')
        return false;
    *b = p;
    *bn = (size_t)(q - p);
    return true;
}

/* One exact text: a single alternative with no goals or epoch in it. */
static bool fxg_exact(const struct fxg_val *v)
{
    return !v->any && v->n == 1 && strpbrk(v->alt[0], "\x06\x07") == NULL;
}

/* The two sides compare: 1 surely equal, 0 surely not, -1 unknown. A side
 * with one alternative is its exact value; one holding the goals or the
 * epoch stands for many texts. */
static int fxg_same(const struct fxg_val *a, const struct fxg_val *b)
{
    if (fxg_empty(a) && fxg_empty(b))
        return 1;
    if (fxg_exact(a) && fxg_exact(b))
        return strcmp(a->alt[0], b->alt[0]) == 0;
    if (a->any || b->any || a->n == 0 || b->n == 0)
        return -1;
    for (size_t i = 0; i < a->n; i++)
        for (size_t j = 0; j < b->n; j++)
            if (strcmp(a->alt[i], b->alt[j]) == 0 ||
                strpbrk(a->alt[i], "\x06\x07") != NULL ||
                strpbrk(b->alt[j], "\x06\x07") != NULL)
                return -1;
    return 0;
}

/* The condition of root line k: 1 provably holds, 0 provably fails, -1
 * neither. Only ifeq and ifneq decide, by fxg_same. */
static int fxg_cond(struct fxg *g, uint32_t k, int depth)
{
    const char *p = g->m->lines[k].raw, *a, *b;
    size_t an, bn;
    bool neq;
    int same;
    struct fxg_val va, vb;
    while (fxm_space(*p))
        p++;
    if (fxm_starts_word(p, "else"))
        for (p += 4; fxm_space(*p); p++)
            ;
    neq = fxm_starts_word(p, "ifneq");
    if (!neq && !fxm_starts_word(p, "ifeq"))
        return -1;
    if (!fxg_sides(p + (neq ? 5 : 4), &a, &an, &b, &bn))
        return -1;
    fxg_text(g, a, an, k, depth, &va);
    fxg_text(g, b, bn, k, depth, &vb);
    same = fxg_same(&va, &vb);
    return same < 0 ? -1 : neq ? !same : same;
}

/* The branch that branch line b opens is provably not taken: its own
 * condition fails, or one before it in its chain holds. */
static bool fxg_branch_dead(struct fxg *g, uint32_t b, int depth)
{
    if (g->cls[b] != FXG_C_ELSE && fxg_cond(g, b, depth) == 0)
        return true;
    for (uint32_t p = g->prev[b]; p != FXG_NO; p = g->prev[p])
        if (fxg_cond(g, p, depth) == 1)
            return true;
    return false;
}

bool fxg_dead(struct fxg *g, uint32_t line, int depth)
{
    unsigned premises = g->rec.premises;
    size_t nglobs = g->rec.nglobs, mark = g->used;
    bool full = g->rec_full, dead = false;
    if (!g->nest_ok || line >= g->m->root_lines || depth > FXG_DEPTH)
        return false;
    for (uint32_t b = g->up[line]; !dead && b != FXG_NO; b = g->up[b]) {
        dead = fxg_branch_dead(g, b, depth + 1);
        while (g->prev[b] != FXG_NO)
            b = g->prev[b];
    }
    g->used = mark;
    if (!dead) {
        g->rec.premises = premises;
        g->rec.nglobs = nglobs;
        g->rec_full = full;
    }
    return dead;
}

static void fxg_where(const struct fxm *m, uint32_t file, uint32_t at,
                      char *out, size_t n)
{
    (void)snprintf(out, n, "%s:%u", file < m->files.n ? m->files.v[file] : "?",
                   at);
}

/* The directive at root line k reads `want` (1 holds, 0 fails): its
 * record is g->rec. */
static bool fxg_try(struct fxg *g, uint32_t k, int want)
{
    const struct fxm_line *l = &g->m->lines[k];
    size_t mark = g->used, n;
    memset(&g->rec, 0, sizeof(g->rec));
    g->rec_full = false;
    if (fxg_cond(g, k, 0) == want && !g->rec_full) {
        n = strlen(l->raw);
        while (n > 0 && fxg_blank(l->raw[n - 1]))
            n--;
        (void)snprintf(g->rec.guard, sizeof(g->rec.guard), "%.*s", (int)n,
                       l->raw);
        fxg_where(g->m, 0, l->at, g->rec.guard_at, sizeof(g->rec.guard_at));
        g->rec_at = k;
        g->rec.premises |= ZCL_DEVLOOP_PREMISE_BUILD_READS_PLANNED_TREE |
                            ZCL_DEVLOOP_PREMISE_NO_COMMAND_LINE_OVERRIDE;
        g->used = mark;
        return true;
    }
    g->used = mark;
    return false;
}

/* The open branch of chain f is provably not taken: its own condition
 * fails, or one before it holds. */
static bool fxg_skipped(struct fxg *g, const struct fxg_frame *f)
{
    uint32_t before = f->plain ? f->n : f->n - 1;
    if (f->cut || f->n == 0)
        return false;
    if (!f->plain && fxg_try(g, f->cond[f->n - 1], 0))
        return true;
    for (uint32_t j = 0; j < before; j++)
        if (fxg_try(g, f->cond[j], 1))
            return true;
    return false;
}

static void fxg_chain_add(struct fxg_frame *f, uint32_t k)
{
    f->plain = false;
    if (f->n == FXG_CHAIN)
        f->cut = true;
    else
        f->cond[f->n++] = k;
}

/* The conditionals open at root line t, outermost first; -1 when the
 * reading cannot follow them. */
static int fxg_frames(struct fxg *g, uint32_t t)
{
    int d = 0;
    for (uint32_t k = 0; k < t; k++) {
        uint8_t c = g->cls[k];
        if (c == FXG_C_NONE)
            continue;
        if (c == FXG_C_IF) {
            if (d == FXM_COND_MAX)
                return -1;
            g->frames[d].n = 0;
            g->frames[d].cut = false;
            fxg_chain_add(&g->frames[d++], k);
        } else if (d == 0) {
            return -1;
        } else if (c == FXG_C_ENDIF) {
            d--;
        } else if (c == FXG_C_ELSE) {
            g->frames[d - 1].plain = true;
        } else {
            fxg_chain_add(&g->frames[d - 1], k);
        }
    }
    return d;
}

/* The root line of the include line at file line `at`. */
static uint32_t fxg_line_at(const struct fxm *m, uint32_t at)
{
    for (size_t k = 0; k < m->root_lines; k++)
        if (m->lines[k].at == at && m->lines[k].ctx == FXM_ACTIVE)
            return (uint32_t)k;
    return FXG_NO;
}

static bool fxg_report_add(struct fxg *g, const struct fxm_inc *inc)
{
    struct zcl_devloop_facts_report *r = g->m->report;
    struct zcl_devloop_facts_guard *n;
    if (r == NULL)
        return true;
    n = zcl_realloc(r->guards, (r->nguards + 1) * sizeof(*n),
                    "facts_consumer.mkguard");
    if (n == NULL)
        return false;
    r->guards = n;
    n = &r->guards[r->nguards++];
    *n = g->rec;
    (void)snprintf(n->include, sizeof(n->include), "%s", inc->path);
    fxg_where(g->m, inc->file, inc->at, n->include_at, sizeof(n->include_at));
    return true;
}

/* The include read at inc is provably skipped: g->rec holds why. */
static bool fxg_inc_skipped(struct fxg *g, const struct fxm_inc *inc)
{
    uint32_t t = inc->file == 0 ? fxg_line_at(g->m, inc->at) : FXG_NO;
    int d = t != FXG_NO ? fxg_frames(g, t) : -1;
    for (int k = 0; k < d; k++)
        if (fxg_skipped(g, &g->frames[k]))
            return true;
    return false;
}

static bool fxg_literal(const char *s, size_t n)
{
    for (size_t k = 0; k < n; k++)
        if (strchr("*?[{\\", s[k]) != NULL)
            return false;
    return true;
}

/* The last component of a globbed path with no pattern in it, into out;
 * "" when each holds one. */
static void fxg_glob_name(const char *glob, char *out, size_t cap)
{
    const char *end = glob + strlen(glob), *s;
    out[0] = '\0';
    for (; end > glob; end = s > glob ? s - 1 : glob) {
        for (s = end; s > glob && s[-1] != '/'; s--)
            ;
        if (end > s && fxg_literal(s, (size_t)(end - s))) {
            (void)snprintf(out, cap, "%.*s", (int)(end - s), s);
            return;
        }
    }
}

/* The directories of a globbed path before its first component with a
 * pattern (all but the last when none has one), into out: a command that
 * names them may create what the glob matches without naming it. */
static void fxg_glob_dir(const char *glob, char *out, size_t cap)
{
    const char *s = glob, *end = glob;
    for (size_t n; *s != '\0'; s += n + 1) {
        n = strcspn(s, "/");
        if (s[n] != '/' || !fxg_literal(s, n))
            break;
        end = s + n;
    }
    (void)snprintf(out, cap, "%.*s", (int)(end - glob), glob);
}

/* Branch line p tests that MAKE_RESTARTS is empty: ifeq (or else ifeq)
 * with one side $(MAKE_RESTARTS) or $(strip $(MAKE_RESTARTS)), braces
 * too, and the other empty. */
static bool fxg_restarts_test(const char *p)
{
    static const char *const forms[] = {
        "$(MAKE_RESTARTS)", "${MAKE_RESTARTS}", "$(strip $(MAKE_RESTARTS))",
        "${strip ${MAKE_RESTARTS}}"};
    const char *a, *b;
    size_t an, bn;
    while (fxm_space(*p))
        p++;
    if (fxm_starts_word(p, "else"))
        for (p += 4; fxm_space(*p); p++)
            ;
    if (!fxm_starts_word(p, "ifeq") || !fxg_sides(p + 4, &a, &an, &b, &bn))
        return false;
    if (an == 0) {
        a = b;
        an = bn;
        bn = 0;
    }
    for (size_t k = 0; bn == 0 && k < sizeof(forms) / sizeof(*forms); k++)
        if (an == strlen(forms[k]) && strncmp(a, forms[k], an) == 0)
            return true;
    return false;
}

/* Root line t sits in a branch only make's first parse takes: one a
 * MAKE_RESTARTS-is-empty test opens (fxg_restarts_test), while no line
 * can set MAKE_RESTARTS. Make sets it to the restart count on every
 * parse after the first. */
static bool fxg_first_parse(struct fxg *g, uint32_t t)
{
    size_t lo, hi;
    if (t == FXG_NO || !g->nest_ok || fxg_patterned(g, "MAKE_RESTARTS"))
        return false;
    fxg_range(g, "MAKE_RESTARTS", &lo, &hi);
    for (uint32_t b = g->up[t]; hi == lo && b != FXG_NO; b = g->up[b])
        if (g->cls[b] != FXG_C_ELSE && fxg_restarts_test(g->m->lines[b].raw))
            return true;
    return false;
}

/* A command make runs as it reads may create a path the reading in g->rec
 * globbed (it names that path's last literal component or the directories
 * before its first pattern): the reading cannot stand. Only one no later
 * than the deciding directive counts when make reads the include only in
 * its first parse (a later command runs after make read the directive):
 * make restarts on no makefile a rule may remake (g->remade), or only the
 * first parse takes the include's branch (fxg_first_parse). Otherwise a
 * restarted parse reads the directive after every command ran and after
 * the recipes that remade a makefile, which may create any path (their
 * text, a variable a later line sets, a script): the reading cannot
 * stand either. */
static bool fxg_rec_named(struct fxg *g, const struct fxm_inc *inc)
{
    char name[ZCL_DEVLOOP_GUARD_TEXT], dir[ZCL_DEVLOOP_GUARD_TEXT];
    uint32_t t = inc->file == 0 ? fxg_line_at(g->m, inc->at) : FXG_NO;
    if (g->remade && !fxg_first_parse(g, t))
        return true;
    for (size_t k = 0; k < g->rec.nglobs; k++) {
        fxg_glob_name(g->rec.glob[k], name, sizeof(name));
        fxg_glob_dir(g->rec.glob[k], dir, sizeof(dir));
        if (fxm_commands_name_by(g->m, name, g->rec_at) ||
            fxm_commands_name_by(g->m, dir, g->rec_at))
            return true;
    }
    return false;
}

/* Drop path from m->missing when every include line naming it is
 * skipped, recording each reading. */
static void fxg_path(struct fxg *g, const char *path)
{
    struct fxm *m = g->m;
    struct zcl_devloop_facts_report *r = m->report;
    size_t before = r != NULL ? r->nguards : 0, w = 0;
    bool all = true;
    for (size_t k = 0; all && k < m->nincs; k++)
        if (strcmp(m->incs[k].path, path) == 0)
            all = fxg_inc_skipped(g, &m->incs[k]) &&
                  !fxg_rec_named(g, &m->incs[k]) &&
                  fxg_report_add(g, &m->incs[k]);
    if (!all) {
        if (r != NULL)
            r->nguards = before;
        return;
    }
    for (size_t k = 0; k < m->missing.n; k++)
        if (strcmp(m->missing.v[k], path) != 0)
            m->missing.v[w++] = m->missing.v[k];
        else
            free(m->missing.v[k]);
    m->missing.n = w;
}

static void fxg_free(struct fxg *g)
{
    for (size_t k = 0; k < g->nsites; k++)
        free(g->sites[k].name);
    free(g->sites);
    free(g->pats);
    free(g->cls);
    free(g->site_at);
    free(g->up);
    free(g->prev);
    free(g->arena);
    free(g);
}

/* Drop each missing include a conditional provably skips. */
static void fxg_skip_all(struct fxm *m)
{
    struct fxg *g = zcl_calloc(1, sizeof(*g), "facts_consumer.mkguards");
    size_t k = 0, lines = m->root_lines + 1;
    if (g == NULL)
        return;
    g->m = m;
    g->cls = zcl_calloc(lines, 1, "facts_consumer.mkgcls");
    g->site_at = zcl_malloc(lines * sizeof(*g->site_at), "facts_consumer.mkgsiteat");
    g->up = zcl_malloc(lines * sizeof(*g->up), "facts_consumer.mkgup");
    g->prev = zcl_malloc(lines * sizeof(*g->prev), "facts_consumer.mkgprev");
    g->arena = zcl_malloc(FXG_ARENA, "facts_consumer.mkgarena");
    if (g->cls != NULL && g->site_at != NULL && g->up != NULL &&
        g->prev != NULL && g->arena != NULL) {
        memset(g->site_at, 0xff, lines * sizeof(*g->site_at));
        g->remade = fxm_makefiles_remade(m);
        if (fxg_collect(g) && !g->open_all)
            while (k < m->missing.n) {
                size_t n = m->missing.n;
                fxg_path(g, m->missing.v[k]);
                k += m->missing.n == n;
            }
    }
    fxg_free(g);
}

/* The plan rests on parse-commands-no-include-writes when make reads an
 * optional include (missing or not), or a skip rests on what a glob found,
 * and a command make runs as it reads is not provably read-only. */
static void fxg_plan_premise(struct fxm *m)
{
    struct zcl_devloop_facts_report *r = m->report;
    struct zcl_devloop_facts_plan_premise *p = &r->make_premise;
    const char *first = m->missing.n > 0 ? m->missing.v[0] : NULL;
    for (size_t k = 0; k < r->nguards; k++)
        if (r->guards[k].nglobs > 0 && p->nskips++ == 0 && first == NULL)
            first = r->guards[k].include;
    if (first == NULL && m->files.n > 1)
        first = m->files.v[1];
    p->nincludes = m->missing.n;
    p->nexisting = m->files.n > 0 ? m->files.n - 1 : 0;
    if (first != NULL)
        fxm_parse_unproven(m, p);
    if (first == NULL || p->ncommands == 0) {
        memset(p, 0, sizeof(*p));
        return;
    }
    p->premises = ZCL_DEVLOOP_PREMISE_PARSE_COMMANDS_NO_INCLUDE_WRITES;
    (void)snprintf(p->include, sizeof(p->include), "%s", first);
}

/* An include make reads that a command it runs as it reads may create or
 * rewrite: the command names its path or its basename, or (missing) its
 * directory (a root include's directory is any text). */
static bool fxg_include_named(const struct fxm *m, const char *path, bool dir_too)
{
    const char *base = strrchr(path, '/');
    char dir[ZCL_DEVLOOP_GUARD_TEXT];
    (void)snprintf(dir, sizeof(dir), "%.*s",
                   base != NULL ? (int)(base - path) : 0, path);
    return fxm_commands_name(m, path) ||
           fxm_commands_name(m, base != NULL ? base + 1 : path) ||
           (dir_too && fxm_commands_name(m, dir));
}

void fxm_guards(struct fxm *m)
{
    if (m->report != NULL)
        memset(&m->report->make_premise, 0, sizeof(m->report->make_premise));
    if (m->unknown)
        return;
    if (m->missing.n > 0)
        fxg_skip_all(m);
    for (size_t k = 0; !m->unknown && k < m->missing.n; k++)
        m->unknown = fxg_include_named(m, m->missing.v[k], true);
    for (size_t f = 1; !m->unknown && f < m->files.n; f++)
        m->unknown = fxg_include_named(m, m->files.v[f], false);
    if (!m->unknown && m->report != NULL)
        fxg_plan_premise(m);
}
