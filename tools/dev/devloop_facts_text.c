/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: File-scope text digest for facts narrowing: the bytes of a C source outside its function definitions, with comment and whitespace runs collapsed. */
#include "devloop_facts.h"

#include "sha3/sha3.h"

#include <string.h>

/* A function definition's compiled tokens are bound by its FUNCTIONS token
 * hash. Everything else in the main file (declarations, initializers,
 * directives) is bound here: each gap between definitions is transcribed
 * byte for byte except that every maximal run of whitespace and comments
 * becomes one byte, '\n' when the run holds a raw newline and ' ' otherwise.
 * That collapse never changes how the compiler splits tokens or ends a
 * directive; literals, line splices and pp-numbers (C23 digit separators)
 * are copied verbatim so a run inside them is never collapsed. Equal digests
 * therefore mean equal file-scope token sequences, except for positions
 * (__LINE__), which this digest deliberately does not bind. Any lexing doubt
 * copies bytes verbatim, so a doubt can only cause a fallback. */

struct fx_lex {
    const uint8_t *s;
    size_t i, hi;
    struct sha3_256_ctx *h;
    uint8_t pending;
    bool flat; /* a newline run is one space (a definition head, no directive) */
};

/* h is NULL for a scan that only walks tokens (fx_body_start). */
static void fx_emit(struct fx_lex *x, size_t n)
{
    if (x->h == NULL) {
        x->i += n;
        return;
    }
    if (x->pending) {
        sha3_256_write(x->h, &x->pending, 1);
        x->pending = 0;
    }
    sha3_256_write(x->h, x->s + x->i, n);
    x->i += n;
}

static void fx_gap(struct fx_lex *x, bool newline)
{
    if (newline && !x->flat)
        x->pending = '\n';
    else if (!x->pending)
        x->pending = ' ';
}

static size_t fx_splice(const struct fx_lex *x, size_t i)
{
    if (i >= x->hi || x->s[i] != '\\')
        return 0;
    if (i + 1 < x->hi && x->s[i + 1] == '\n')
        return 2;
    if (i + 2 < x->hi && x->s[i + 1] == '\r' && x->s[i + 2] == '\n')
        return 3;
    return 0;
}

static bool fx_ident_byte(uint8_t c)
{
    return c == '_' || c == '$' || c >= 0x80 || (c >= '0' && c <= '9') ||
           ((c | 0x20) >= 'a' && (c | 0x20) <= 'z');
}

static bool fx_digit(uint8_t c)
{
    return c >= '0' && c <= '9';
}

/* A comment is one gap byte; a line comment continues over a splice and
 * leaves its newline for the caller. */
static void fx_comment(struct fx_lex *x)
{
    bool block = x->s[x->i + 1] == '*';
    x->i += 2;
    while (x->i < x->hi) {
        size_t sp = fx_splice(x, x->i);
        if (block && x->s[x->i] == '*' && x->i + 1 < x->hi &&
            x->s[x->i + 1] == '/') {
            x->i += 2;
            break;
        }
        if (!block && x->s[x->i] == '\n')
            break;
        x->i += sp ? sp : 1;
    }
    fx_gap(x, false);
}

/* A character or string literal, verbatim, ending at its quote or at a raw
 * newline (unterminated). */
static void fx_literal(struct fx_lex *x)
{
    uint8_t q = x->s[x->i];
    size_t j = x->i + 1;
    while (j < x->hi && x->s[j] != q && x->s[j] != '\n')
        j += x->s[j] == '\\' && j + 1 < x->hi ? 2 : 1;
    if (j < x->hi && x->s[j] == q)
        j++;
    fx_emit(x, (j > x->hi ? x->hi : j) - x->i);
}

/* A pp-number, verbatim: digits, letters, '_', '.', an exponent sign, and a
 * digit separator followed by a digit or nondigit. */
static void fx_ppnum(struct fx_lex *x)
{
    size_t j = x->i + 1;
    while (j < x->hi) {
        uint8_t c = x->s[j], p = x->s[j - 1];
        uint8_t n = j + 1 < x->hi ? x->s[j + 1] : 0;
        if ((c == '+' || c == '-') && ((p | 0x20) == 'e' || (p | 0x20) == 'p'))
            j++;
        else if (c == '\'' && fx_ident_byte(n))
            j += 2;
        else if (fx_ident_byte(c) || c == '.')
            j++;
        else
            break;
    }
    fx_emit(x, (j > x->hi ? x->hi : j) - x->i);
}

/* An identifier, verbatim; an encoding prefix (L u U u8) keeps its literal. */
static void fx_ident(struct fx_lex *x)
{
    size_t j = x->i;
    size_t n;
    while (j < x->hi && fx_ident_byte(x->s[j]))
        j++;
    n = j - x->i;
    bool prefix = (n == 1 && strchr("LuU", x->s[x->i]) != NULL) ||
                  (n == 2 && memcmp(x->s + x->i, "u8", 2) == 0);
    fx_emit(x, n);
    if (prefix && x->i < x->hi && (x->s[x->i] == '"' || x->s[x->i] == '\''))
        fx_literal(x);
}

static bool fx_space(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == '\r';
}

static void fx_step(struct fx_lex *x)
{
    uint8_t c = x->s[x->i];
    uint8_t n = x->i + 1 < x->hi ? x->s[x->i + 1] : 0;
    size_t sp = fx_splice(x, x->i);
    if (sp)
        fx_emit(x, sp);
    else if (fx_space(c) || c == '\n') {
        fx_gap(x, c == '\n');
        x->i++;
    } else if (c == '/' && (n == '*' || n == '/'))
        fx_comment(x);
    else if (c == '"' || c == '\'')
        fx_literal(x);
    else if (fx_digit(c) || (c == '.' && fx_digit(n)))
        fx_ppnum(x);
    else if (fx_ident_byte(c))
        fx_ident(x);
    else
        fx_emit(x, 1);
}

void zcl_devloop_facts_text_digest(const uint8_t *src, size_t src_len,
                                   const struct zcl_devloop_facts_range *keep,
                                   size_t nkeep, uint8_t out[32])
{
    struct sha3_256_ctx all;
    size_t at = 0;
    sha3_256_init(&all);
    /* Each gap is digested on its own and the gap digests are chained, so a
     * gap boundary can never be forged by bytes inside a gap. */
    for (size_t k = 0; k <= nkeep; k++) {
        size_t hi = k < nkeep ? keep[k].begin : src_len;
        struct sha3_256_ctx h;
        uint8_t gap[32];
        struct fx_lex x = {.s = src, .i = at, .hi = hi, .h = &h};
        sha3_256_init(&h);
        while (x.i < x.hi)
            fx_step(&x);
        if (x.pending)
            sha3_256_write(&h, &x.pending, 1);
        sha3_256_finalize(&h, gap);
        sha3_256_write(&all, gap, sizeof(gap));
        if (k < nkeep)
            at = keep[k].end > at ? keep[k].end : at;
    }
    sha3_256_finalize(&all, out);
}

/* The offset of a function definition's body in src[begin, end): the first
 * '{' outside parentheses, brackets, comments and literals. Returns `end`
 * when there is no such brace, so the whole definition counts as head. */
static size_t fx_body_start(const uint8_t *src, size_t begin, size_t end)
{
    struct fx_lex x = {.s = src, .i = begin, .hi = end, .h = NULL};
    int depth = 0;
    while (x.i < x.hi) {
        uint8_t c = x.s[x.i];
        if (c == '{' && depth == 0)
            return x.i;
        if (c == '(' || c == '[')
            depth++;
        else if ((c == ')' || c == ']') && depth > 0)
            depth--;
        fx_step(&x);
    }
    return end;
}

void zcl_devloop_facts_head_digest(const uint8_t *src, size_t begin,
                                   size_t end, uint8_t out[32])
{
    size_t body = fx_body_start(src, begin, end);
    struct sha3_256_ctx h;
    /* A head holds no directive unless a '#' byte appears in it; only then
     * does a newline end anything, so only then is it kept apart from a
     * space. Any '#' (even inside a comment or literal) keeps the strict
     * transcription, which can only cause a fallback. */
    struct fx_lex x = {.s = src, .i = begin, .hi = body, .h = &h,
                       .flat = memchr(src + begin, '#', body - begin) == NULL};
    sha3_256_init(&h);
    while (x.i < x.hi)
        fx_step(&x);
    if (x.pending)
        sha3_256_write(&h, &x.pending, 1);
    sha3_256_finalize(&h, out);
}
