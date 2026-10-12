/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Lexical scan of a C source for z23-toolgen. Separates comments,
 *          string literals and character literals from code so a manifest
 *          marker is recognised only inside a real comment. No preprocessing,
 *          no macro expansion, no include resolution. */

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct lexer {
    const char *s;
    size_t n;
    size_t i;
    unsigned depth;
    struct tg_lex *out;
};

static bool is_idc(unsigned char c)
{
    return isalnum(c) || c == '_' || c >= 0x80u;
}

static void blank(char *buf, const char *src, size_t from, size_t to)
{
    for (size_t k = from; k < to; k++)
        buf[k] = (src[k] == '\n' || src[k] == '\r') ? src[k] : ' ';
}

static bool add_comment(struct lexer *L, size_t start, size_t end,
                        enum tg_comment_kind kind)
{
    struct tg_lex *o = L->out;
    if (o->ncomments == o->cap) {
        size_t cap = o->cap ? o->cap * 2u : 16u;
        struct tg_comment *p =
            zcl_realloc(o->comments, cap * sizeof *p, "toolgen.comments");
        if (!p)
            return false;
        o->comments = p;
        o->cap = cap;
    }
    o->comments[o->ncomments++] =
        (struct tg_comment){.start = start, .end = end, .kind = kind, .cond_depth = L->depth};
    blank(o->code, L->s, start, end);
    blank(o->masked, L->s, start, end);
    L->i = end;
    return true;
}

static bool scan_block(struct lexer *L)
{
    size_t j = L->i + 2u;
    while (j + 1u < L->n && !(L->s[j] == '*' && L->s[j + 1u] == '/'))
        j++;
    size_t end;
    if (j + 1u < L->n) {
        end = j + 2u;
    } else {
        L->out->unterminated = true;
        end = L->n;
    }
    return add_comment(L, L->i, end, TG_COMMENT_BLOCK);
}

static bool scan_line(struct lexer *L)
{
    size_t j = L->i + 2u;
    while (j < L->n) {
        if (L->s[j] == '\n') {
            size_t p = (j > 0 && L->s[j - 1u] == '\r') ? j - 1u : j;
            if (p > L->i + 2u && L->s[p - 1u] == '\\') {
                j++;
                continue;
            }
            break;
        }
        j++;
    }
    return add_comment(L, L->i, j, TG_COMMENT_LINE);
}

static void scan_quoted(struct lexer *L, char quote)
{
    size_t j = L->i + 1u;
    while (j < L->n && L->s[j] != quote && L->s[j] != '\n') {
        if (L->s[j] == '\\' && j + 1u < L->n)
            j++;
        j++;
    }
    size_t end = (j < L->n && L->s[j] == quote) ? j + 1u : j;
    blank(L->out->masked, L->s, L->i, end);
    L->i = end;
}

static void scan_number(struct lexer *L)
{
    size_t j = L->i;
    while (j < L->n) {
        unsigned char c = (unsigned char)L->s[j];
        bool digit_sep = c == '\'' && j + 1u < L->n &&
                         is_idc((unsigned char)L->s[j + 1u]);
        bool exp_sign = (c == '+' || c == '-') && j > L->i &&
                        strchr("eEpP", L->s[j - 1u]) != NULL;
        if (!(is_idc(c) || c == '.' || digit_sep || exp_sign))
            break;
        j++;
    }
    L->i = j;
}

static bool at_directive(const struct lexer *L, size_t ident_start)
{
    size_t k = ident_start;
    while (k > 0 && (L->s[k - 1u] == ' ' || L->s[k - 1u] == '\t'))
        k--;
    if (k == 0 || L->s[k - 1u] != '#')
        return false;
    k--;
    while (k > 0 && (L->s[k - 1u] == ' ' || L->s[k - 1u] == '\t'))
        k--;
    return k == 0 || L->s[k - 1u] == '\n';
}

static bool is_include_word(const char *w, size_t len)
{
    static const char *const words[] = {"include", "embed", "include_next"};
    for (size_t i = 0; i < sizeof words / sizeof words[0]; i++)
        if (strlen(words[i]) == len && memcmp(w, words[i], len) == 0)
            return true;
    return false;
}

static void skip_header_name(struct lexer *L, size_t ident_start, size_t j)
{
    if (!is_include_word(L->s + ident_start, j - ident_start) || !at_directive(L, ident_start))
        return;
    while (j < L->n && (L->s[j] == ' ' || L->s[j] == '\t'))
        j++;
    if (j >= L->n || L->s[j] != '<')
        return;
    while (j < L->n && L->s[j] != '>' && L->s[j] != '\n')
        j++;
    L->i = j;
}

static void track_conditional(struct lexer *L, size_t start, size_t end)
{
    static const char *const open[] = {"if", "ifdef", "ifndef"};
    size_t len = end - start;
    if (!at_directive(L, start))
        return;
    for (size_t i = 0; i < sizeof open / sizeof open[0]; i++)
        if (strlen(open[i]) == len && memcmp(L->s + start, open[i], len) == 0)
            L->depth++;
    if (len == 5 && memcmp(L->s + start, "endif", 5) == 0 && L->depth > 0)
        L->depth--;
}

static void scan_ident(struct lexer *L)
{
    size_t j = L->i;
    while (j < L->n && is_idc((unsigned char)L->s[j]))
        j++;
    size_t start = L->i;
    track_conditional(L, start, j);
    L->i = j;
    skip_header_name(L, start, j);
}

static bool step(struct lexer *L)
{
    unsigned char c = (unsigned char)L->s[L->i];
    unsigned char d = L->i + 1u < L->n ? (unsigned char)L->s[L->i + 1u] : 0;
    if (c == '/' && d == '*')
        return scan_block(L);
    if (c == '/' && d == '/')
        return scan_line(L);
    if (c == '"' || c == '\'')
        scan_quoted(L, (char)c);
    else if (isdigit(c) || (c == '.' && isdigit(d)))
        scan_number(L);
    else if (is_idc(c))
        scan_ident(L);
    else
        L->i++;
    return true;
}

bool tg_lex_run(const char *src, size_t n, struct tg_lex *out)
{
    *out = (struct tg_lex){.len = n};
    out->code = zcl_malloc(n + 1u, "toolgen.code");
    out->masked = zcl_malloc(n + 1u, "toolgen.masked");
    if (!out->code || !out->masked) {
        tg_lex_free(out);
        return false;
    }
    memcpy(out->code, src, n);
    memcpy(out->masked, src, n);
    out->code[n] = out->masked[n] = '\0';
    struct lexer L = {.s = src, .n = n, .out = out};
    while (L.i < n)
        if (!step(&L)) {
            tg_lex_free(out);
            return false;
        }
    return true;
}

void tg_lex_free(struct tg_lex *lx)
{
    free(lx->code);
    free(lx->masked);
    free(lx->comments);
    *lx = (struct tg_lex){0};
}

static bool ident_at(const char *t, size_t len, size_t pos, const char *name)
{
    size_t k = strlen(name);
    if (pos + k > len || memcmp(t + pos, name, k) != 0)
        return false;
    bool before = pos == 0 || !is_idc((unsigned char)t[pos - 1u]);
    bool after = pos + k == len || !is_idc((unsigned char)t[pos + k]);
    return before && after;
}

static size_t skip_back_ws(const char *t, size_t pos)
{
    while (pos > 0 && isspace((unsigned char)t[pos - 1u]))
        pos--;
    return pos;
}

static bool opens_body(const char *t, size_t len, size_t pos)
{
    while (pos < len && isspace((unsigned char)t[pos]))
        pos++;
    if (pos >= len || t[pos] != '(')
        return false;
    int depth = 0;
    for (; pos < len; pos++) {
        depth += t[pos] == '(';
        depth -= t[pos] == ')';
        if (depth == 0)
            break;
    }
    pos++;
    while (pos < len && isspace((unsigned char)t[pos]))
        pos++;
    return pos < len && t[pos] == '{';
}

bool tg_has_definition(const struct tg_lex *lx, const char *ret,
                       const char *name)
{
    const char *t = lx->masked;
    size_t rlen = strlen(ret);
    size_t nlen = strlen(name);
    for (size_t pos = 0; pos + nlen <= lx->len; pos++) {
        if (!ident_at(t, lx->len, pos, name))
            continue;
        size_t b = skip_back_ws(t, pos);
        if (b >= rlen && ident_at(t, lx->len, b - rlen, ret) &&
            opens_body(t, lx->len, pos + nlen))
            return true;
    }
    return false;
}

/* Finds TG_MARKER at the start of a comment body. `stars` counts the '*'
 * characters between the delimiter and the marker (a doc-style comment). */
static bool starts_marker(const char *src, size_t from, size_t to, size_t *after,
                          size_t *stars)
{
    size_t k = from;
    *stars = 0;
    while (k < to && (isspace((unsigned char)src[k]) || src[k] == '*')) {
        *stars += src[k] == '*' ? 1u : 0u;
        k++;
    }
    size_t ml = strlen(TG_MARKER);
    if (k + ml > to || memcmp(src + k, TG_MARKER, ml) != 0)
        return false;
    if (k + ml < to && is_idc((unsigned char)src[k + ml]))
        return false;
    *after = k + ml;
    return true;
}

static bool take_body(const char *src, const struct tg_comment *c, size_t after,
                      struct tg_marker *m, struct tg_err *e)
{
    size_t end = c->end - 2u;
    while (after < end && isspace((unsigned char)src[after]))
        after++;
    while (end > after && isspace((unsigned char)src[end - 1u]))
        end--;
    if (after >= end || src[after] != '{')
        return tg_fail(e, "MANIFEST_BAD_JSON",
                       "the %s comment must contain one JSON object", TG_MARKER);
    if (end - after > TG_MANIFEST_MAX)
        return tg_fail(e, "MANIFEST_TOO_LARGE",
                       "manifest is %zu bytes; the limit is %u", end - after,
                       TG_MANIFEST_MAX);
    m->found = true;
    m->body_off = after;
    m->body_len = end - after;
    return true;
}

/* A marker the tool must not silently skip: refuse it by name. */
static bool refuse_shape(const struct tg_comment *c, size_t stars, struct tg_err *e)
{
    if (c->kind == TG_COMMENT_LINE)
        return tg_fail(e, "MARKER_NOT_BLOCK_COMMENT",
                       "%s must open a /* */ comment, not a // comment", TG_MARKER);
    if (stars > 0)
        return tg_fail(e, "MARKER_DOC_COMMENT",
                       "%s must follow \"/*\" directly, not a doc-style \"/**\" comment",
                       TG_MARKER);
    if (c->cond_depth > 0)
        return tg_fail(e, "MARKER_CONDITIONAL",
                       "%s sits inside #if/#ifdef/#ifndef; the generator cannot know "
                       "whether that code is compiled",
                       TG_MARKER);
    return true;
}

bool tg_find_marker(const char *src, const struct tg_lex *lx,
                    struct tg_marker *m, struct tg_err *e)
{
    *m = (struct tg_marker){0};
    if (lx->unterminated)
        return tg_fail(e, "LEX_UNTERMINATED_COMMENT",
                       "the source ends inside a block comment");
    for (size_t i = 0; i < lx->ncomments; i++) {
        const struct tg_comment *c = &lx->comments[i];
        size_t after;
        size_t stars;
        if (!starts_marker(src, c->start + 2u, c->end, &after, &stars))
            continue;
        if (!refuse_shape(c, stars, e))
            return false;
        if (m->found)
            return tg_fail(e, "MARKER_DUPLICATE",
                           "more than one %s comment in one source", TG_MARKER);
        if (!take_body(src, c, after, m, e))
            return false;
    }
    return true;
}
