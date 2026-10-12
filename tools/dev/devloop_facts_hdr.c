/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Compare a changed header's two texts for the facts consumer: top-level chunks with their names, and the line region whose positions moved. */
#include "devloop_facts_hdr.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdlib.h>
#include <string.h>

struct fxh_buf {
    char *s;
    size_t n, cap;
};

struct fxh_names {
    char **v;
    size_t n, cap;
};

struct fxh_piece {
    uint8_t kind;
    uint8_t digest[32];
    struct fxh_names names;
};

struct fxh_pieces {
    struct fxh_piece *v;
    size_t n, cap;
};

struct fxh_lex {
    const char *s;
    size_t i, n;
    bool bol;
    struct fxh_buf text;
    struct fxh_names names;
    int paren, brace;
    char last;
    bool function, have_decl;
    char *last_ident, *decl_name;
    size_t head_names;
    struct fxh_pieces *out;
    bool ok;
};

/* ---- small containers ------------------------------------------------------- */

static bool fxh_grow(void **v, size_t *cap, size_t n, size_t elem)
{
    size_t next;
    void *g;
    if (n < *cap)
        return true;
    next = *cap ? *cap * 2 : 16;
    g = zcl_realloc(*v, next * elem, "facts_hdr.grow");
    if (g == NULL)
        return false;
    *v = g;
    *cap = next;
    return true;
}

static bool fxh_put(struct fxh_buf *b, const char *s, size_t n)
{
    if (b->n + n + 2 > b->cap) {
        size_t next = (b->n + n + 2) * 2;
        char *g = zcl_realloc(b->s, next, "facts_hdr.text");
        if (g == NULL)
            return false;
        b->s = g;
        b->cap = next;
    }
    memcpy(b->s + b->n, s, n);
    b->n += n;
    b->s[b->n] = '\0';
    return true;
}

static char *fxh_dup(const char *s, size_t n)
{
    char *d = zcl_malloc(n + 1, "facts_hdr.name");
    if (d != NULL) {
        memcpy(d, s, n);
        d[n] = '\0';
    }
    return d;
}

static bool fxh_name_push(struct fxh_names *v, const char *s, size_t n)
{
    char *d;
    if (!fxh_grow((void **)&v->v, &v->cap, v->n, sizeof(*v->v)))
        return false;
    d = fxh_dup(s, n);
    if (d == NULL)
        return false;
    v->v[v->n++] = d;
    return true;
}

static void fxh_names_free(struct fxh_names *v)
{
    for (size_t k = 0; k < v->n; k++)
        free(v->v[k]);
    free(v->v);
    memset(v, 0, sizeof(*v));
}

/* ---- lexing ---------------------------------------------------------------------- */

static bool fxh_ident_start(unsigned char c)
{
    return c == '_' || c == '$' || ((c | 0x20) >= 'a' && (c | 0x20) <= 'z');
}

static bool fxh_ident_byte(unsigned char c)
{
    return fxh_ident_start(c) || (c >= '0' && c <= '9');
}

static size_t fxh_splice(const struct fxh_lex *x)
{
    if (x->i >= x->n || x->s[x->i] != '\\')
        return 0;
    if (x->i + 1 < x->n && x->s[x->i + 1] == '\n')
        return 2;
    if (x->i + 2 < x->n && x->s[x->i + 1] == '\r' && x->s[x->i + 2] == '\n')
        return 3;
    return 0;
}

/* Skip one comment at i; true when there was one. */
static bool fxh_comment(struct fxh_lex *x)
{
    if (x->i + 1 >= x->n || x->s[x->i] != '/')
        return false;
    if (x->s[x->i + 1] == '*') {
        size_t k = x->i + 2;
        while (k + 1 < x->n && !(x->s[k] == '*' && x->s[k + 1] == '/'))
            k++;
        x->i = k + 1 < x->n ? k + 2 : x->n;
        return true;
    }
    if (x->s[x->i + 1] != '/')
        return false;
    while (x->i < x->n && x->s[x->i] != '\n')
        x->i += fxh_splice(x) ? fxh_splice(x) : 1;
    return true;
}

/* Skip blanks, splices and comments; a newline sets bol when `lines`,
 * and stops the skip otherwise. */
static void fxh_blanks(struct fxh_lex *x, bool lines)
{
    while (x->i < x->n) {
        char c = x->s[x->i];
        size_t sp = fxh_splice(x);
        if (sp > 0)
            x->i += sp;
        else if (c == '\n' && lines) {
            x->bol = true;
            x->i++;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v')
            x->i++;
        else if (!fxh_comment(x))
            return;
    }
}

/* An identifier or pp-number from i: identifier bytes, and for a number
 * also '.' and digit separators. */
static size_t fxh_word_len(const struct fxh_lex *x, bool ident)
{
    size_t k = x->i;
    while (k < x->n && (fxh_ident_byte((unsigned char)x->s[k]) ||
                        (!ident && (x->s[k] == '.' || x->s[k] == '\''))))
        k++;
    return k - x->i;
}

/* A string or character literal from i, to its close quote or line end. */
static size_t fxh_literal_len(const struct fxh_lex *x, char quote)
{
    size_t k = x->i + 1;
    for (; k < x->n && x->s[k] != quote && x->s[k] != '\n'; k++)
        if (x->s[k] == '\\' && k + 1 < x->n)
            k++;
    return (k < x->n && x->s[k] == quote ? k + 1 : k) - x->i;
}

/* The length of the token at i (identifier, pp-number, literal, or one
 * punctuator byte); *ident says whether it is an identifier. */
static size_t fxh_token(const struct fxh_lex *x, bool *ident)
{
    unsigned char c = (unsigned char)x->s[x->i];
    *ident = fxh_ident_start(c);
    if (*ident || (c >= '0' && c <= '9'))
        return fxh_word_len(x, *ident);
    if (c == '"' || c == '\'')
        return fxh_literal_len(x, (char)c);
    return 1;
}

/* ---- pieces ------------------------------------------------------------------------ */

/* Takes *names on every path: it is zeroed before anything can fail and
 * freed when the piece cannot be stored. */
static bool fxh_emit(struct fxh_lex *x, uint8_t kind, const struct fxh_buf *text,
                     struct fxh_names *names)
{
    struct fxh_names own = *names;
    struct fxh_piece *p;
    struct sha3_256_ctx h;
    memset(names, 0, sizeof(*names));
    if (!fxh_grow((void **)&x->out->v, &x->out->cap, x->out->n,
                  sizeof(*x->out->v))) {
        fxh_names_free(&own);
        return false;
    }
    p = &x->out->v[x->out->n++];
    p->kind = kind;
    sha3_256_init(&h);
    sha3_256_write(&h, &kind, 1);
    sha3_256_write(&h, (const unsigned char *)text->s, text->n);
    sha3_256_finalize(&h, p->digest);
    p->names = own;
    return true;
}

static uint8_t fxh_directive_kind(const char *s, size_t n)
{
    static const struct {
        const char *name;
        uint8_t kind;
    } k[] = {{"define", FXH_DEFINE},  {"if", FXH_COND},
             {"ifdef", FXH_COND},     {"ifndef", FXH_COND},
             {"elif", FXH_COND},      {"elifdef", FXH_COND},
             {"elifndef", FXH_COND},  {"else", FXH_COND},
             {"endif", FXH_COND},     {"include", FXH_INCLUDE},
             {"include_next", FXH_INCLUDE}, {"embed", FXH_INCLUDE}};
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (strlen(k[i].name) == n && memcmp(k[i].name, s, n) == 0)
            return k[i].kind;
    return FXH_OTHER;
}

/* One directive's name records: a #define names its macro only, any other
 * directive every identifier but `defined`. */
static bool fxh_directive_name(struct fxh_names *names, uint8_t kind,
                               const char *s, size_t n, size_t index)
{
    if (kind == FXH_DEFINE && index != 1)
        return true;
    if (n == 7 && memcmp(s, "defined", 7) == 0)
        return true;
    return index == 0 || fxh_name_push(names, s, n);
}

/* A directive, from its '#' to the end of its logical line. */
static bool fxh_directive(struct fxh_lex *x)
{
    struct fxh_buf text = {0};
    struct fxh_names names = {0};
    uint8_t kind = FXH_OTHER;
    size_t index = 0;
    bool ok = fxh_put(&text, "#", 1);
    x->i++;
    for (fxh_blanks(x, false); ok && x->i < x->n && x->s[x->i] != '\n';
         fxh_blanks(x, false)) {
        bool ident;
        size_t len = fxh_token(x, &ident);
        if (ident && index == 0)
            kind = fxh_directive_kind(x->s + x->i, len);
        ok = fxh_put(&text, " ", 1) && fxh_put(&text, x->s + x->i, len) &&
             (!ident || fxh_directive_name(&names, kind, x->s + x->i, len,
                                           index++));
        x->i += len;
    }
    ok = ok && fxh_emit(x, kind, &text, &names);
    free(text.s);
    fxh_names_free(&names);
    return ok;
}

static void fxh_reset(struct fxh_lex *x)
{
    x->text.n = 0;
    fxh_names_free(&x->names);
    x->paren = x->brace = 0;
    x->last = 0;
    x->function = x->have_decl = false;
    free(x->last_ident);
    free(x->decl_name);
    x->last_ident = x->decl_name = NULL;
    x->head_names = 0;
}

/* End the current declaration. A function definition names its declarator
 * (the identifier before the head's first top-level '('), else every
 * identifier of its head. */
static bool fxh_end(struct fxh_lex *x)
{
    struct fxh_names names = {0};
    bool ok = true;
    if (x->function && x->decl_name != NULL) {
        ok = fxh_name_push(&names, x->decl_name, strlen(x->decl_name));
    } else if (x->function) {
        for (size_t k = 0; ok && k < x->head_names; k++)
            ok = fxh_name_push(&names, x->names.v[k], strlen(x->names.v[k]));
    } else {
        names = x->names;
        memset(&x->names, 0, sizeof(x->names));
    }
    ok = ok && (x->text.n == 0 ||
                fxh_emit(x, x->function ? FXH_FUNCTION : FXH_TEXT, &x->text,
                         &names));
    fxh_names_free(&names);
    fxh_reset(x);
    return ok;
}

static bool fxh_ident(struct fxh_lex *x, const char *s, size_t n)
{
    free(x->last_ident);
    x->last_ident = x->paren == 0 && x->brace == 0 ? fxh_dup(s, n) : NULL;
    return fxh_name_push(&x->names, s, n) &&
           (x->last_ident != NULL || x->paren != 0 || x->brace != 0);
}

/* A declaration's name is the identifier before its first top-level '(';
 * a function body is a top-level '{' right after a ')'. */
static void fxh_punct_head(struct fxh_lex *x, char c)
{
    bool top = x->paren == 0 && x->brace == 0;
    if (c == '(' && top && !x->have_decl && x->last_ident != NULL) {
        x->decl_name = fxh_dup(x->last_ident, strlen(x->last_ident));
        x->have_decl = x->decl_name != NULL;
    }
    if (c == '{' && top && x->last == ')') {
        x->function = true;
        x->head_names = x->names.n;
    }
}

/* Bracket depth and the declaration's end, for one punctuator. */
static bool fxh_punct(struct fxh_lex *x, char c)
{
    fxh_punct_head(x, c);
    x->paren += (c == '(' || c == '[') - (c == ')' || c == ']');
    x->brace += (c == '{') - (c == '}');
    x->paren = x->paren < 0 ? 0 : x->paren;
    x->brace = x->brace < 0 ? 0 : x->brace;
    x->last = c;
    if (c == '}' && x->function && x->brace == 0)
        return fxh_end(x);
    if (c == ';' && x->paren == 0 && x->brace == 0)
        return fxh_end(x);
    return true;
}

static bool fxh_step(struct fxh_lex *x)
{
    bool ident;
    size_t len;
    fxh_blanks(x, true);
    if (x->i >= x->n)
        return true;
    if (x->bol && x->s[x->i] == '#') {
        x->bol = false;
        return fxh_directive(x);
    }
    x->bol = false;
    len = fxh_token(x, &ident);
    if (!(x->text.n == 0 || fxh_put(&x->text, " ", 1)) ||
        !fxh_put(&x->text, x->s + x->i, len))
        return false;
    x->i += len;
    if (len == 1 && !ident)
        return fxh_punct(x, x->s[x->i - 1]);
    x->last = 'a';
    return !ident || fxh_ident(x, x->s + x->i - len, len);
}

static bool fxh_split(const uint8_t *s, size_t n, struct fxh_pieces *out)
{
    struct fxh_lex x = {.s = (const char *)s, .n = n, .bol = true, .out = out};
    bool ok = true;
    while (ok && x.i < x.n)
        ok = fxh_step(&x);
    ok = ok && fxh_end(&x);
    fxh_reset(&x);
    free(x.text.s);
    return ok;
}

/* ---- the diff --------------------------------------------------------------------- */

static int fxh_piece_cmp(const void *a, const void *b)
{
    const struct fxh_piece *x = a, *y = b;
    if (x->kind != y->kind)
        return x->kind < y->kind ? -1 : 1;
    return memcmp(x->digest, y->digest, 32);
}

static bool fxh_keep(struct fxh_diff *d, struct fxh_piece *p)
{
    struct fxh_chunk *c = zcl_realloc(d->changed, (d->nchanged + 1) * sizeof(*c),
                                      "facts_hdr.chunks");
    if (c == NULL)
        return false;
    d->changed = c;
    d->changed[d->nchanged++] = (struct fxh_chunk){
        .kind = p->kind, .names = p->names.v, .nnames = p->names.n};
    memset(&p->names, 0, sizeof(p->names));
    return true;
}

/* The multiset difference of the two sides' pieces, both directions. */
static bool fxh_changed(struct fxh_diff *d, struct fxh_pieces *b,
                        struct fxh_pieces *a)
{
    size_t i = 0, j = 0;
    bool ok = true;
    if (b->n > 1)
        qsort(b->v, b->n, sizeof(*b->v), fxh_piece_cmp);
    if (a->n > 1)
        qsort(a->v, a->n, sizeof(*a->v), fxh_piece_cmp);
    while (ok && (i < b->n || j < a->n)) {
        int r = i >= b->n   ? 1
                : j >= a->n ? -1
                            : fxh_piece_cmp(&b->v[i], &a->v[j]);
        if (r == 0) {
            i++;
            j++;
        } else if (r < 0) {
            ok = fxh_keep(d, &b->v[i++]);
        } else {
            ok = fxh_keep(d, &a->v[j++]);
        }
    }
    return ok;
}

static void fxh_pieces_free(struct fxh_pieces *p)
{
    for (size_t k = 0; k < p->n; k++)
        fxh_names_free(&p->v[k].names);
    free(p->v);
}

static size_t fxh_line_end(const uint8_t *s, size_t n, size_t at)
{
    const uint8_t *nl = memchr(s + at, '\n', n - at);
    return nl != NULL ? (size_t)(nl - s) + 1 : n;
}

static uint32_t fxh_count_lines(const uint8_t *s, size_t n)
{
    uint32_t lines = 0;
    for (size_t at = 0; at < n; at = fxh_line_end(s, n, at))
        lines++;
    return lines;
}

/* Common leading lines of the two texts. */
static uint32_t fxh_prefix(const uint8_t *b, size_t bn, const uint8_t *a,
                           size_t an)
{
    size_t i = 0, j = 0;
    uint32_t p = 0;
    while (i < bn && j < an) {
        size_t ie = fxh_line_end(b, bn, i), je = fxh_line_end(a, an, j);
        if (ie - i != je - j || memcmp(b + i, a + j, ie - i) != 0)
            break;
        p++;
        i = ie;
        j = je;
    }
    return p;
}

/* Common trailing lines, at most `limit`. */
static uint32_t fxh_suffix(const uint8_t *b, size_t bn, const uint8_t *a,
                           size_t an, uint32_t limit)
{
    size_t i = bn, j = an;
    uint32_t s = 0;
    while (s < limit && i > 0 && j > 0) {
        size_t is = i - 1, js = j - 1;
        while (is > 0 && b[is - 1] != '\n')
            is--;
        while (js > 0 && a[js - 1] != '\n')
            js--;
        if (i - is != j - js || memcmp(b + is, a + js, i - is) != 0)
            break;
        s++;
        i = is;
        j = js;
    }
    return s;
}

static void fxh_region(struct fxh_diff *d)
{
    uint32_t nb = fxh_count_lines(d->before, d->blen);
    uint32_t na = fxh_count_lines(d->after, d->alen);
    uint32_t p = fxh_prefix(d->before, d->blen, d->after, d->alen);
    uint32_t lim = (nb < na ? nb : na) - p;
    uint32_t s = nb == na ? fxh_suffix(d->before, d->blen, d->after, d->alen,
                                       lim)
                          : 0;
    d->b_lo = d->a_lo = p + 1;
    d->b_hi = nb - s;
    d->a_hi = na - s;
    if (d->blen == d->alen && memcmp(d->before, d->after, d->blen) == 0)
        d->b_hi = d->a_hi = 0;
}

bool fxh_diff(const uint8_t *before, size_t blen, const uint8_t *after,
              size_t alen, struct fxh_diff *out)
{
    struct fxh_pieces b = {0}, a = {0};
    bool ok;
    memset(out, 0, sizeof(*out));
    out->before = before;
    out->blen = blen;
    out->after = after;
    out->alen = alen;
    fxh_region(out);
    ok = fxh_split(before, blen, &b) && fxh_split(after, alen, &a) &&
         fxh_changed(out, &b, &a);
    fxh_pieces_free(&b);
    fxh_pieces_free(&a);
    if (!ok)
        fxh_free(out);
    return ok;
}

void fxh_free(struct fxh_diff *d)
{
    for (size_t k = 0; k < d->nchanged; k++) {
        for (size_t j = 0; j < d->changed[k].nnames; j++)
            free(d->changed[k].names[j]);
        free(d->changed[k].names);
    }
    free(d->changed);
    d->changed = NULL;
    d->nchanged = 0;
}

/* ---- positions ------------------------------------------------------------------ */

/* Scan one text for `name` as an identifier: *seen when it occurs, true
 * when it occurs on a line in [lo, hi]. */
static bool fxh_occurs(const uint8_t *s, size_t n, const char *name,
                       uint32_t lo, uint32_t hi, bool *seen)
{
    size_t k = strlen(name);
    uint32_t line = 1;
    for (size_t i = 0; k > 0 && i + k <= n; i++) {
        if (s[i] == '\n') {
            line++;
            continue;
        }
        if (s[i] != (uint8_t)name[0] || memcmp(s + i, name, k) != 0 ||
            (i > 0 && fxh_ident_byte(s[i - 1])) ||
            (i + k < n && fxh_ident_byte(s[i + k])))
            continue;
        *seen = true;
        if (line >= lo && line <= hi)
            return true;
    }
    return false;
}

bool fxh_position_dirty(const struct fxh_diff *d, const char *name)
{
    bool seen = false;
    if (d->b_lo > d->b_hi && d->a_lo > d->a_hi)
        return false;
    if (fxh_occurs(d->before, d->blen, name, d->b_lo, d->b_hi, &seen) ||
        fxh_occurs(d->after, d->alen, name, d->a_lo, d->a_hi, &seen))
        return true;
    return !seen;
}

bool fxh_span_dirty(const struct fxh_diff *d, uint32_t lo, uint32_t hi,
                    bool after)
{
    uint32_t rlo = after ? d->a_lo : d->b_lo, rhi = after ? d->a_hi : d->b_hi;
    return rlo <= rhi && lo <= rhi && hi >= rlo;
}

/* ---- code in the region ------------------------------------------------------- */

struct fxh_scan {
    const uint8_t *s;
    size_t n, i;
    uint32_t line;
    bool comment;   /* inside a block comment */
    bool fresh;     /* nothing but blanks and comments yet on this line */
    bool directive; /* this line, or the one it continues, is a directive */
};

static void fxh_scan_newline(struct fxh_scan *q)
{
    q->directive = q->directive && q->i > 0 && q->s[q->i - 1] == '\\';
    q->line++;
    q->fresh = true;
    q->i++;
}

/* Inside a block comment: up to its end or the end of the line. */
static void fxh_scan_comment(struct fxh_scan *q)
{
    for (; q->i < q->n && q->s[q->i] != '\n'; q->i++) {
        if (q->s[q->i] == '*' && q->i + 1 < q->n && q->s[q->i + 1] == '/') {
            q->comment = false;
            q->i += 2;
            return;
        }
    }
}

/* A comment opens at q->i: skip a line comment, enter a block comment. */
static bool fxh_scan_comment_open(struct fxh_scan *q)
{
    if (q->s[q->i] != '/' || q->i + 1 >= q->n)
        return false;
    if (q->s[q->i + 1] == '/') {
        while (q->i < q->n && q->s[q->i] != '\n')
            q->i++;
        return true;
    }
    if (q->s[q->i + 1] != '*')
        return false;
    q->comment = true;
    q->i += 2;
    return true;
}

/* A string or character literal from q->i, to its end on this line. */
static void fxh_scan_literal(struct fxh_scan *q)
{
    uint8_t quote = q->s[q->i++];
    for (; q->i < q->n && q->s[q->i] != '\n'; q->i++) {
        if (q->s[q->i] == quote) {
            q->i++;
            return;
        }
        if (q->s[q->i] == '\\' && q->i + 1 < q->n && q->s[q->i + 1] != '\n')
            q->i++;
    }
}

static bool fxh_blank(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}

/* A token outside comments starts at q->i: true when it lies in the region
 * from `lo` and counts; otherwise step over it (a literal whole). */
static bool fxh_scan_token(struct fxh_scan *q, uint32_t lo, bool directives)
{
    uint8_t c = q->s[q->i];
    q->directive = q->directive || (q->fresh && c == '#');
    q->fresh = false;
    if (q->line >= lo && (directives || !q->directive))
        return true;
    if (c == '"' || c == '\'')
        fxh_scan_literal(q);
    else
        q->i++;
    return false;
}

/* A token outside comments on a line in [lo, hi] of one text; directive
 * lines count only when `directives`. */
static bool fxh_region_code(const uint8_t *s, size_t n, uint32_t lo,
                            uint32_t hi, bool directives)
{
    struct fxh_scan q = {.s = s, .n = n, .line = 1, .fresh = true};
    while (q.i < n && q.line <= hi) {
        if (s[q.i] == '\n')
            fxh_scan_newline(&q);
        else if (q.comment)
            fxh_scan_comment(&q);
        else if (fxh_blank(s[q.i]))
            q.i++;
        else if (fxh_scan_comment_open(&q))
            continue;
        else if (fxh_scan_token(&q, lo, directives))
            return true;
    }
    return false;
}

bool fxh_region_has_code(const struct fxh_diff *d, bool directives)
{
    return (d->b_lo <= d->b_hi &&
            fxh_region_code(d->before, d->blen, d->b_lo, d->b_hi,
                            directives)) ||
           (d->a_lo <= d->a_hi &&
            fxh_region_code(d->after, d->alen, d->a_lo, d->a_hi, directives));
}
