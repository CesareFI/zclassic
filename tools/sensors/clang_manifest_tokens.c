/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Marks, from clang's own tokens (clang_tokenize under the TU's language options), which lookup words each file holds live, exempt or hidden, and finds the words a ## could paste into one.
 *
 * clang_tokenize re-lexes a file raw, with the TU's LangOpts: a word in a
 * comment or in a string, character or raw string literal is no
 * identifier token, and a trigraph or line splice inside a word is
 * cleaned. Raw lexing also covers the groups the preprocessor skipped. A
 * punctuator's spelling is its raw text, so the walk cleans it
 * (translation phases 1 and 2) before reading it.
 *
 * The marks only ever narrow what the scan records (clang_manifest_lookup.c
 * records every occurrence of a lookup word it finds in the text, less the
 * ones marked exempt, hidden or skipped), so the first two are set only
 * where clang's raw tokens are the preprocessor's: outside the skipped groups
 * (clang_getSkippedRanges, less the directive lines in them
 * the preprocessor evaluates), and only from clang's token kinds (a
 * comment, a literal, a token that is no lookup word) and the #if, #ifdef
 * and defined operands they spell. Two places there differ from raw
 * lexing and are read as the preprocessor does: after an include-like
 * directive, or after __has_include(, __has_include_next( or __has_embed(,
 * a '<' opens one header name up to its '>'; and a #warning or #error line
 * is plain text. The raw tokens inside such a span are not marked (so the
 * scan records any lookup word text there), and when they run past it, or
 * across a skipped group's edge, the file is tokenized again from there.
 * Inside a skipped group nothing is marked exempt or hidden: after the
 * walk the whole group is marked skipped, and the scan records nothing
 * there, since any change that could make it live makes the TU affected
 * and sensed again (docs/work/SEMANTIC_MANIFEST.md). A skipped range holds
 * directive lines the preprocessor evaluates: the one whose '#' opens it,
 * and any #elif inside it (clang reports consecutive skipped groups as one
 * range). The walk reads each such line as live, up to the first newline
 * between clang's tokens, and leaves it out of the mark
 * (cm_tok_keep_line). clang reports a file's ranges for one of its
 * entries, so a file more than one inclusion directive names (or the main
 * file, once any does) is read as skipped whole: nothing in it is marked
 * exempt, hidden or skipped (cm_tok_ranges). The TU is refused where raw
 * tokens run past a '<' ... '>' span on a #pragma line outside a skipped
 * group (some pragmas take a header name), and when a file's tokens stop
 * short of its last non-blank byte.
 *
 * A lookup word the preprocessor pastes with ## has no occurrence of its
 * own. Pasting only joins spellings of tokens that exist: ones a #define
 * body or an #if, #elif or #embed line holds (the only text a conditional
 * expands, with a skipped group's lines taken as live), or a built-in or
 * command-line macro, and the words pasting built from those. So the walk
 * notes every such word whose spelling lies inside __has_include,
 * __has_include_next or __has_embed (the words clang expands), and when
 * two or more of them in a row spell one, cm_core.paste_piece names the
 * first. A lookup word one token spells whole needs no paste: in a #define
 * body, or on a conditional line not followed by its '(', the scan already
 * records it. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest.h"

#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The longest token spelling a paste check reads whole. */
#define CM_PIECE_MAX 64
/* The lookup words clang expands (k_cm_paste_words) and the longest. */
#define CM_PASTE_WORDS 3
#define CM_PASTE_MAX 18
/* cm_tok_walk.keep, per byte. */
enum {
    CM_KEEP_NONE = 0,
    CM_KEEP_LINE = 1,  /* on a directive line the preprocessor may evaluate */
    CM_KEEP_OPENS = 2, /* the '#' a skipped range starts at */
};

/* One tokenization of a file from some offset on. */
struct cm_toks {
    CXToken *t;
    unsigned n;
};

/* A skipped group's text, by offset: [a, b). */
struct cm_span {
    size_t a, b;
};

/* Which parts of each lookup word some token a ## could join is spelled
 * as: have[w][a][b] when one spells word w's bytes [a, b). */
struct cm_piece {
    bool have[CM_PASTE_WORDS][CM_PASTE_MAX + 1][CM_PASTE_MAX + 1];
};

/* The directive the current logical line is. */
enum cm_line_dir {
    CM_DIR_NONE,
    CM_DIR_DEFINE,
    CM_DIR_COND,  /* #if, #elif: expanded */
    CM_DIR_IFDEF, /* #ifdef, #ifndef, #elifdef, #elifndef */
    CM_DIR_EMBED,
    CM_DIR_PRAGMA,
    CM_DIR_OTHER,
};

/* Where an #if line stands in "defined W", "defined ( W )", "!", "&&",
 * "||" and nothing else. */
enum cm_defd {
    CM_DEFD_EXPECT,
    CM_DEFD_KW,    /* after "defined" */
    CM_DEFD_OPEN,  /* after "defined (" */
    CM_DEFD_CLOSE, /* after "defined ( W" */
    CM_DEFD_AFTER, /* after a whole test */
    CM_DEFD_BAD,
};

/* Where the walk over a file stands. */
struct cm_tok_walk {
    CXTranslationUnit tu;
    const char *s;
    size_t n;
    bool trigraphs;
    uint8_t *live;
    const struct cm_span *skip; /* merged, sorted */
    size_t nskip, iskip;        /* iskip: the first not wholly before */
    struct cm_piece *piece;
    size_t prev_end;     /* end of the last token, comments included */
    size_t reach;        /* the furthest token end */
    bool bol;            /* no token but comments since a line began */
    enum cm_line_dir dir; /* the logical line's directive */
    bool expect_name;    /* the last token was a line-start '#' */
    bool first_operand;  /* the next token is an #ifdef's operand */
    bool def_named;      /* a #define line's name was read */
    enum cm_defd defd;   /* an #if line's defined tests */
    int after_defined;   /* 1: after "defined"; 2: after "defined (" */
    int header;          /* 1: the next token may open a header name; 2: a
                          * '(' is due first (after a probe word) */
    size_t restart;      /* nonzero: tokenize again from here */
    bool restart_bol;    /* ... at the start of a line */
    const char *refused; /* why the TU is refused, or NULL */
    uint8_t *keep;       /* per byte, CM_KEEP_*; NULL: no skipped-group drop */
    size_t hash_off;     /* the offset of the line-start '#' last read */
    bool unskip;         /* the rest of this logical line is such a line */
};

static size_t cm_tok_offset(CXSourceLocation l)
{
    unsigned off = 0;
    clang_getSpellingLocation(l, NULL, NULL, NULL, &off);
    return off;
}

/* ---- translation phases 1 and 2 ------------------------------------------ */

/* The character the trigraph at s[i] stands for when the TU has them,
 * else 0. */
static char cm_tok_trigraph(const char *s, size_t n, size_t i, bool trigraphs)
{
    static const char from[] = "=/'()!<>-", to[] = "#\\^[]|{}~";
    const char *p;
    if (!trigraphs || n - i < 3 || s[i] != '?' || s[i + 1] != '?' ||
        s[i + 2] == '\0')
        return 0;
    p = strchr(from, s[i + 2]);
    return p == NULL ? 0 : to[p - from];
}

/* Just past the line splice whose backslash ends before s[j], as clang's
 * getEscapedNewLineSize reads one (blanks, form feeds and vertical tabs,
 * then a newline or carriage return, then the other of the two), or 0. */
static size_t cm_tok_splice_end(const char *s, size_t n, size_t j)
{
    while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\f' ||
                     s[j] == '\v'))
        j++;
    if (j >= n || (s[j] != '\n' && s[j] != '\r'))
        return 0;
    if (j + 1 < n && (s[j + 1] == '\n' || s[j + 1] == '\r') &&
        s[j + 1] != s[j])
        return j + 2;
    return j + 1;
}

/* The character at s[*i] after phases 1 and 2, advancing *i past it; 0 at
 * the end. */
static char cm_tok_char(const char *s, size_t n, size_t *i, bool trigraphs)
{
    while (*i < n) {
        char tri = cm_tok_trigraph(s, n, *i, trigraphs);
        char ch = tri != 0 ? tri : s[*i];
        size_t w = tri != 0 ? 3 : 1;
        size_t end = ch == '\\' ? cm_tok_splice_end(s, n, *i + w) : 0;
        if (end == 0) {
            *i += w;
            return ch;
        }
        *i = end;
    }
    return 0;
}

/* The offset of the first character of the token at s[off], past any line
 * splice it starts with. */
static size_t cm_tok_first(const struct cm_tok_walk *w, size_t off)
{
    size_t i = off, at = off;
    (void)cm_tok_char(w->s, w->n, &i, w->trigraphs);
    while (at < i) {
        char tri = cm_tok_trigraph(w->s, w->n, at, w->trigraphs);
        size_t wd = tri != 0 ? 3 : 1;
        char ch = tri != 0 ? tri : w->s[at];
        size_t end = ch == '\\' ? cm_tok_splice_end(w->s, w->n, at + wd) : 0;
        if (end == 0)
            return at;
        at = end;
    }
    return off;
}

/* Does the whitespace s[a, b) between two tokens hold a newline that ends
 * a logical line (one no splice removes)? */
static bool cm_tok_newline(const struct cm_tok_walk *w, size_t a, size_t b)
{
    size_t i = a;
    while (i < b) {
        char ch = cm_tok_char(w->s, b, &i, w->trigraphs);
        if (ch == '\n' || ch == '\r')
            return true;
    }
    return false;
}

/* The punctuator s[off, end) as phases 1 and 2 leave it; false when it is
 * longer than cap - 1. */
static bool cm_tok_clean(const struct cm_tok_walk *w, size_t off, size_t end,
                         char *out, size_t cap)
{
    size_t i = off, k = 0;
    while (i < end) {
        char ch = cm_tok_char(w->s, end, &i, w->trigraphs);
        if (ch == 0 || k + 1 >= cap)
            return false;
        out[k++] = ch;
    }
    out[k] = '\0';
    return true;
}

/* A punctuation token at s[off, end) spelled `p` once cleaned; with no
 * file text (a built-in macro's), by clang's spelling. */
static bool cm_tok_punct(const struct cm_tok_walk *w, CXToken t, size_t off,
                         size_t end, const char *p)
{
    char c[8];
    CXString sp;
    bool is;
    if (clang_getTokenKind(t) != CXToken_Punctuation)
        return false;
    if (w->s != NULL)
        return cm_tok_clean(w, off, end, c, sizeof(c)) && strcmp(c, p) == 0;
    sp = clang_getTokenSpelling(w->tu, t);
    is = clang_getCString(sp) != NULL && strcmp(clang_getCString(sp), p) == 0;
    clang_disposeString(sp);
    return is;
}

static bool cm_tok_hash(const struct cm_tok_walk *w, CXToken t, size_t off,
                        size_t end)
{
    return cm_tok_punct(w, t, off, end, "#") ||
           cm_tok_punct(w, t, off, end, "%:");
}

/* The end, just past its '>', of the header name whose '<' token starts at
 * s[lt], as clang's LexAngledStringLiteral reads it; 0 when a newline or
 * the end comes first (then the '<' is a lone less-than). */
static size_t cm_tok_header_end(const struct cm_tok_walk *w, size_t lt)
{
    size_t i = lt;
    (void)cm_tok_char(w->s, w->n, &i, w->trigraphs); /* the '<' */
    for (;;) {
        char ch = cm_tok_char(w->s, w->n, &i, w->trigraphs);
        if (ch == '\\')
            ch = cm_tok_char(w->s, w->n, &i, w->trigraphs);
        if (ch == 0 || ch == '\n' || ch == '\r')
            return 0;
        if (ch == '>')
            return i;
    }
}

/* The offset of the newline ending the logical line that holds s[from]. */
static size_t cm_tok_line_end(const char *s, size_t n, size_t from,
                              bool trigraphs)
{
    size_t i = from;
    for (;;) {
        size_t at = i;
        char ch = cm_tok_char(s, n, &i, trigraphs);
        if (ch == 0 || ch == '\n' || ch == '\r')
            return ch == 0 ? n : at;
    }
}

/* ---- spellings ------------------------------------------------------------ */

static bool cm_tok_word(CXToken t)
{
    CXTokenKind k = clang_getTokenKind(t);
    return k == CXToken_Identifier || k == CXToken_Keyword;
}

/* Is the identifier or keyword token t spelled (cleaned) as one of set? */
static bool cm_tok_in(const struct cm_tok_walk *w, CXToken t,
                      const char *const *set, size_t n)
{
    CXString sp = clang_getTokenSpelling(w->tu, t);
    const char *c = clang_getCString(sp);
    bool in = false;
    for (size_t k = 0; c != NULL && k < n && !in; k++)
        in = strcmp(c, set[k]) == 0;
    clang_disposeString(sp);
    return in;
}

static bool cm_tok_is(const struct cm_tok_walk *w, CXToken t, const char *s)
{
    return cm_tok_word(t) && cm_tok_in(w, t, &s, 1);
}

/* A conditional-lookup word; *hdr set when the preprocessor lexes a
 * header name in its operand. */
static bool cm_tok_probe(const struct cm_tok_walk *w, CXToken t, size_t off,
                         size_t end, bool *hdr)
{
    static const char *const hdr_words[] = {
        "__has_include", "__has_include_next", "__has_embed"};
    static const char *const other[] = {"__has_include__",
                                        "__has_include_next__"};
    size_t i = off;
    *hdr = false;
    if (clang_getTokenKind(t) != CXToken_Identifier ||
        (w->s != NULL && cm_tok_char(w->s, end, &i, w->trigraphs) != '_'))
        return false;
    *hdr = cm_tok_in(w, t, hdr_words, 3);
    return *hdr || cm_tok_in(w, t, other, 2);
}

/* ---- skipped groups -------------------------------------------------------- */

static int cm_span_cmp(const void *a, const void *b)
{
    const struct cm_span *x = a, *y = b;
    return x->a < y->a ? -1 : x->a > y->a;
}

/* f's skipped ranges, sorted and merged. Each range runs from the '#' of
 * the directive the preprocessor evaluated to skip it to the name of the
 * one that ends it; keep[a] is set to CM_KEEP_OPENS at each such '#', so
 * the walk reads that directive's logical line, which clang's tokens end,
 * as live (cm_tok_keep_line). */
static bool cm_tok_skipped_ranges(CXTranslationUnit tu, CXFile file, size_t n,
                                  uint8_t *keep, struct cm_span **out,
                                  size_t *nout)
{
    CXSourceRangeList *l = clang_getSkippedRanges(tu, file);
    size_t m = 0;
    *out = NULL;
    *nout = 0;
    if (l == NULL || l->count == 0) {
        clang_disposeSourceRangeList(l);
        return true;
    }
    *out = zcl_calloc(l->count, sizeof(**out), "clang_manifest.skipped");
    for (unsigned k = 0; *out != NULL && k < l->count; k++) {
        size_t a = cm_tok_offset(clang_getRangeStart(l->ranges[k]));
        size_t b = cm_tok_offset(clang_getRangeEnd(l->ranges[k]));
        if (a < b && b <= n) {
            keep[a] = CM_KEEP_OPENS;
            (*out)[m++] = (struct cm_span){a, b};
        }
    }
    clang_disposeSourceRangeList(l);
    if (*out == NULL)
        return false;
    qsort(*out, m, sizeof(**out), cm_span_cmp);
    for (size_t k = 0; k < m; k++) {
        if (*nout > 0 && (*out)[k].a <= (*out)[*nout - 1].b) {
            if ((*out)[k].b > (*out)[*nout - 1].b)
                (*out)[*nout - 1].b = (*out)[k].b;
        } else {
            (*out)[(*nout)++] = (*out)[k];
        }
    }
    return true;
}

/* Is s[off] in a skipped group? Offsets only grow along a walk. */
static bool cm_tok_skipped(struct cm_tok_walk *w, size_t off)
{
    while (w->iskip < w->nskip && w->skip[w->iskip].b <= off)
        w->iskip++;
    return w->iskip < w->nskip && w->skip[w->iskip].a <= off;
}

/* The first skipped-group edge after s[off], or SIZE_MAX. */
static size_t cm_tok_edge(struct cm_tok_walk *w, size_t off)
{
    if (cm_tok_skipped(w, off))
        return w->skip[w->iskip].b;
    return w->iskip < w->nskip ? w->skip[w->iskip].a : SIZE_MAX;
}

/* Token t's spelling into out when it fits in cap; false otherwise. */
static bool cm_tok_spell(CXTranslationUnit tu, CXToken t, char *out,
                         size_t cap)
{
    CXString sp = clang_getTokenSpelling(tu, t);
    const char *c = clang_getCString(sp);
    bool fits = c != NULL && strlen(c) < cap;
    if (fits)
        memcpy(out, c, strlen(c) + 1);
    clang_disposeString(sp);
    return fits;
}

/* ---- words ## could paste into a lookup word -------------------------- */

static const char *const k_cm_paste_words[CM_PASTE_WORDS] = {
    "__has_include", "__has_include_next", "__has_embed"};

/* Note every place spelling s occurs inside a lookup word. */
static void cm_piece_add(struct cm_piece *p, const char *s)
{
    size_t ls = strlen(s);
    for (size_t w = 0; w < CM_PASTE_WORDS && ls > 0; w++) {
        const char *word = k_cm_paste_words[w];
        for (const char *at = strstr(word, s); at != NULL;
             at = strstr(at + 1, s))
            p->have[w][at - word][(size_t)(at - word) + ls] = true;
    }
}

/* Can lookup word w be spelled by two or more noted spellings in a row?
 * Returns the length of the first one, or 0. */
static size_t cm_piece_cover(const struct cm_piece *p, size_t w)
{
    size_t len = strlen(k_cm_paste_words[w]);
    bool to_end[CM_PASTE_MAX + 1] = {0}; /* [a]: a..len is spelled */
    to_end[len] = true;
    for (size_t a = len; a-- > 0;)
        for (size_t b = a + 1; b <= len && !to_end[a]; b++)
            to_end[a] = p->have[w][a][b] && to_end[b] && !(a == 0 && b == len);
    for (size_t b = len - 1; to_end[0] && b > 0; b--)
        if (p->have[w][0][b] && to_end[b])
            return b;
    return 0;
}

/* Token t on a #define body, #if, #elif or #embed line, or in a built-in
 * macro: a word whose spelling a ## could join into a lookup word. */
static void cm_tok_piece(struct cm_tok_walk *w, CXToken t)
{
    char c[CM_PIECE_MAX];
    if (cm_tok_word(t) && cm_tok_spell(w->tu, t, c, sizeof(c)))
        cm_piece_add(w->piece, c);
}

/* ---- directive lines --------------------------------------------------------- */

/* A skipped range holds directive lines the preprocessor evaluates: the
 * one whose '#' opens it, and, since clang reports consecutive groups it
 * skipped as one range, any #elif inside it. The skipping lexer reads the
 * range raw, as clang_tokenize does, so the walk finds the same '#' and
 * name: from the name on, up to the first newline between clang's tokens
 * (never one inside a comment or after a splice), the line is read as
 * live, and none of it is left to the skipped-group drop. */
static void cm_tok_keep_line(struct cm_tok_walk *w, CXToken t, size_t end)
{
    static const char *const elif[] = {"elif", "elifdef", "elifndef"};
    if (w->keep == NULL ||
        (w->keep[w->hash_off] != CM_KEEP_OPENS && !cm_tok_in(w, t, elif, 3)))
        return;
    memset(w->keep + w->hash_off, CM_KEEP_LINE, end - w->hash_off);
    w->unskip = true;
}

/* The directive name after a line-start '#'. */
static void cm_tok_directive(struct cm_tok_walk *w, CXToken t, size_t end,
                             bool skipped)
{
    static const char *const cond[] = {"if", "elif"};
    static const char *const ifdef[] = {"ifdef", "ifndef", "elifdef",
                                        "elifndef"};
    static const char *const hdr[] = {"include", "include_next", "import",
                                      "embed", "__include_macros"};
    static const char *const text[] = {"warning", "error"};
    if (!cm_tok_word(t))
        return;
    w->dir = CM_DIR_OTHER;
    if (cm_tok_is(w, t, "define"))
        w->dir = CM_DIR_DEFINE;
    else if (cm_tok_in(w, t, cond, 2))
        w->dir = CM_DIR_COND;
    else if (cm_tok_in(w, t, ifdef, 4))
        w->dir = CM_DIR_IFDEF;
    else if (cm_tok_is(w, t, "pragma"))
        w->dir = CM_DIR_PRAGMA;
    if (cm_tok_in(w, t, hdr, 5))
        w->header = 1;
    if (cm_tok_is(w, t, "embed"))
        w->dir = CM_DIR_EMBED;
    if (skipped)
        cm_tok_keep_line(w, t, end);
    else if (cm_tok_in(w, t, text, 2))
        w->restart = cm_tok_line_end(w->s, w->n, end, w->trigraphs);
    w->first_operand = w->dir == CM_DIR_IFDEF;
    w->defd = CM_DEFD_EXPECT;
    w->after_defined = 0;
}

/* The next state of an #if line's defined tests after token t. */
static enum cm_defd cm_tok_defd(const struct cm_tok_walk *w, CXToken t,
                                size_t off, size_t end)
{
    bool word = cm_tok_word(t);
    switch (w->defd) {
    case CM_DEFD_EXPECT:
        if (cm_tok_punct(w, t, off, end, "!"))
            return CM_DEFD_EXPECT;
        return cm_tok_is(w, t, "defined") ? CM_DEFD_KW : CM_DEFD_BAD;
    case CM_DEFD_KW:
        if (cm_tok_punct(w, t, off, end, "("))
            return CM_DEFD_OPEN;
        return word ? CM_DEFD_AFTER : CM_DEFD_BAD;
    case CM_DEFD_OPEN:
        return word ? CM_DEFD_CLOSE : CM_DEFD_BAD;
    case CM_DEFD_CLOSE:
        return cm_tok_punct(w, t, off, end, ")") ? CM_DEFD_AFTER
                                                 : CM_DEFD_BAD;
    case CM_DEFD_AFTER:
        return cm_tok_punct(w, t, off, end, "&&") ||
                       cm_tok_punct(w, t, off, end, "||")
                   ? CM_DEFD_EXPECT
                   : CM_DEFD_BAD;
    default:
        return CM_DEFD_BAD;
    }
}

/* A token on an #if or #elif line: whether it is a lookup word only
 * tested for being defined. */
static bool cm_tok_cond(struct cm_tok_walk *w, CXToken t, size_t off,
                        size_t end)
{
    bool operand = w->after_defined != 0 && cm_tok_word(t);
    bool exempt = operand && w->defd != CM_DEFD_BAD &&
                  (w->defd == CM_DEFD_KW || w->defd == CM_DEFD_OPEN);
    if (w->dir == CM_DIR_COND)
        w->defd = cm_tok_defd(w, t, off, end);
    if (cm_tok_is(w, t, "defined"))
        w->after_defined = 1;
    else if (w->after_defined == 1 && cm_tok_punct(w, t, off, end, "("))
        w->after_defined = 2;
    else
        w->after_defined = 0;
    return exempt && w->dir == CM_DIR_COND;
}

/* ---- one token ---------------------------------------------------------------- */

static void cm_tok_line_start(struct cm_tok_walk *w)
{
    w->dir = CM_DIR_NONE;
    w->expect_name = w->first_operand = w->def_named = false;
    w->header = 0;
}

/* Mark the lookup word at s[off] by its line's directive. */
static void cm_tok_mark_word(struct cm_tok_walk *w, size_t off, bool exempt,
                             bool skipped)
{
    uint8_t v = CM_LIVE_WORD;
    if (w->dir == CM_DIR_DEFINE)
        v = CM_LIVE_BODY;
    else if (exempt && !skipped)
        v = CM_LIVE_EXEMPT;
    w->live[cm_tok_first(w, off)] = v;
}

/* The line's directive bookkeeping for one token: whether it is a lookup
 * word only tested for being defined. */
static bool cm_tok_line(struct cm_tok_walk *w, CXToken t, size_t off,
                        size_t end)
{
    bool first = w->first_operand;
    w->first_operand = false;
    if (w->dir == CM_DIR_DEFINE && !w->def_named) {
        w->def_named = cm_tok_word(t);
        return false;
    }
    if (w->dir == CM_DIR_DEFINE || w->dir == CM_DIR_COND ||
        w->dir == CM_DIR_EMBED)
        cm_tok_piece(w, t);
    if (w->dir == CM_DIR_COND || w->dir == CM_DIR_EMBED)
        return cm_tok_cond(w, t, off, end);
    return first && w->dir == CM_DIR_IFDEF;
}

/* One token that is no comment, first on its logical line or not. */
static void cm_tok_one(struct cm_tok_walk *w, CXToken t, size_t off,
                       size_t end, bool line_start, bool skipped)
{
    bool hdr = false, probe, exempt;
    if (line_start)
        cm_tok_line_start(w);
    if (w->expect_name) {
        w->expect_name = false;
        cm_tok_directive(w, t, end, skipped);
        return; /* a directive name: no mark, so an #embed is recorded */
    }
    if (line_start && cm_tok_hash(w, t, off, end)) {
        w->expect_name = true;
        w->hash_off = off;
        if (!skipped)
            memset(w->live + off, CM_LIVE_HIDDEN, end - off);
        return;
    }
    w->header = w->header == 2 && cm_tok_punct(w, t, off, end, "(") ? 1 : 0;
    probe = cm_tok_probe(w, t, off, end, &hdr);
    exempt = cm_tok_line(w, t, off, end);
    if (probe) {
        cm_tok_mark_word(w, off, exempt, skipped);
        w->header = hdr ? 2 : 0;
    } else if (!skipped) {
        memset(w->live + off, CM_LIVE_HIDDEN, end - off);
    }
}

/* ---- spans the preprocessor reads unlike raw lexing ----------------------- */

/* Every token of toks from index i whose start is before `close` ends by
 * it: the raw lexing agrees with the header name or text span there. */
static bool cm_tok_agrees(const struct cm_tok_walk *w,
                          const struct cm_toks *toks, unsigned i, size_t close)
{
    for (; i < toks->n; i++) {
        CXSourceRange r = clang_getTokenExtent(w->tu, toks->t[i]);
        size_t off = cm_tok_offset(clang_getRangeStart(r));
        if (off >= close)
            return true;
        if (cm_tok_offset(clang_getRangeEnd(r)) > close)
            return false;
    }
    return true;
}

/* The index of the first token of toks at or after `close`. */
static unsigned cm_tok_skip(const struct cm_tok_walk *w,
                            const struct cm_toks *toks, unsigned i,
                            size_t close)
{
    while (i < toks->n &&
           cm_tok_offset(clang_getTokenLocation(w->tu, toks->t[i])) < close)
        i++;
    return i;
}

/* A span up to `close` the preprocessor reads as one token or as text
 * (never in a skipped group): left unmarked, so the scan records any
 * lookup word text in it; skip the raw tokens inside it, or
 * tokenize again from `close` when they run past it. Returns the next
 * index. */
static unsigned cm_tok_span(struct cm_tok_walk *w, const struct cm_toks *toks,
                            unsigned i, size_t close)
{
    w->prev_end = close;
    if (close > w->reach)
        w->reach = close;
    if (!cm_tok_agrees(w, toks, i, close)) {
        w->restart = close;
        w->restart_bol = false;
        return toks->n;
    }
    return cm_tok_skip(w, toks, i, close);
}

/* After the token at [off, end): a header name the preprocessor lexes
 * whole, a #warning or #error line it reads as text, or a #pragma '<' the
 * raw tokens may read differently. Returns the next index. */
static unsigned cm_tok_after(struct cm_tok_walk *w, const struct cm_toks *toks,
                             unsigned i, size_t off, size_t end, bool opens)
{
    size_t close = cm_tok_punct(w, toks->t[i - 1], off, end, "<")
                       ? cm_tok_header_end(w, off) : 0;
    if (opens && close != 0) {
        w->header = 0;
        return cm_tok_span(w, toks, i, close);
    }
    if (w->dir == CM_DIR_PRAGMA && close != 0 &&
        !cm_tok_agrees(w, toks, i, close)) {
        w->refused = "a #pragma header name could hide text";
        return toks->n;
    }
    if (w->restart != 0) {
        size_t at = w->restart;
        w->restart = 0;
        i = cm_tok_span(w, toks, i, at);
    }
    return i;
}

/* ---- the walk ------------------------------------------------------------------- */

/* Tokenize again at a skipped group's edge the token [off, end) runs
 * across; false when it runs across none. */
static bool cm_tok_crosses(struct cm_tok_walk *w, size_t off, size_t end)
{
    size_t edge = cm_tok_edge(w, off);
    if (end <= edge)
        return false;
    w->restart = edge;
    w->restart_bol = true;
    w->prev_end = edge;
    return true;
}

/* Place the token [off, end) on its line; whether it lies in a skipped
 * group (and on no #elif line the preprocessor may evaluate there). */
static bool cm_tok_place(struct cm_tok_walk *w, size_t off, size_t end)
{
    if (cm_tok_newline(w, w->prev_end, off)) {
        w->bol = true;
        w->unskip = false;
    }
    w->prev_end = end;
    if (end > w->reach)
        w->reach = end;
    if (w->unskip)
        memset(w->keep + off, CM_KEEP_LINE, end - off);
    return cm_tok_skipped(w, off) && !w->unskip;
}

/* Walk one tokenization. A comment is whitespace: it neither starts a
 * line nor is a token of one. */
static void cm_tok_walk_toks(struct cm_tok_walk *w, const struct cm_toks *toks)
{
    for (unsigned i = 0; i < toks->n && w->restart == 0 && w->refused == NULL;) {
        CXToken t = toks->t[i];
        CXSourceRange r = clang_getTokenExtent(w->tu, t);
        size_t off = cm_tok_offset(clang_getRangeStart(r));
        size_t end = cm_tok_offset(clang_getRangeEnd(r));
        bool opens = w->header == 1, line_start, skipped;
        if (cm_tok_crosses(w, off, end))
            return;
        skipped = cm_tok_place(w, off, end);
        i++;
        if (clang_getTokenKind(t) == CXToken_Comment) {
            if (!skipped)
                memset(w->live + off, CM_LIVE_HIDDEN, end - off);
            continue;
        }
        line_start = w->bol;
        w->bol = false;
        cm_tok_one(w, t, off, end, line_start, skipped);
        if (!skipped)
            i = cm_tok_after(w, toks, i, off, end, opens && !skipped);
    }
}

/* Tokenize f from `from` to its end; false when libclang cannot place the
 * range in the file. */
static bool cm_tok_range(CXTranslationUnit tu, CXFile f, size_t from,
                         size_t n, struct cm_toks *out)
{
    CXSourceLocation a = clang_getLocationForOffset(tu, f, (unsigned)from);
    CXSourceLocation b = clang_getLocationForOffset(tu, f, (unsigned)n);
    CXSourceLocation null = clang_getNullLocation();
    out->t = NULL;
    out->n = 0;
    if (clang_equalLocations(a, null) || clang_equalLocations(b, null))
        return false;
    clang_tokenize(tu, clang_getRange(a, b), &out->t, &out->n);
    return true;
}

/* Do the tokens reach the file's last byte that is not whitespace (a
 * trailing splice or NUL counts as whitespace)? */
static bool cm_tok_covered(const struct cm_tok_walk *w)
{
    for (size_t i = w->reach; i < w->n; i++)
        if (strchr(" \t\n\r\f\v\\", w->s[i]) == NULL)
            return false;
    return true;
}

/* One tokenization pass from `from`; false when the TU is refused. */
static bool cm_tok_pass(struct cm_state *st, struct cm_file *f,
                        struct cm_tok_walk *w, size_t from)
{
    struct cm_toks toks;
    if (!cm_tok_range(st->tu, (CXFile)f->key, from, f->size, &toks))
        return cm_fail(&st->core, "cannot tokenize %s", f->path);
    w->restart = 0;
    w->prev_end = from;
    if (w->restart_bol) {
        w->bol = true;
        w->unskip = false;
    }
    w->restart_bol = false;
    cm_tok_walk_toks(w, &toks);
    clang_disposeTokens(st->tu, toks.t, toks.n);
    if (w->refused != NULL)
        return cm_fail(&st->core,
                       "unsupported translation-unit language: %s in %s",
                       w->refused, f->path);
    if (w->restart != 0 && w->restart <= from)
        return cm_fail(&st->core, "cannot tokenize %s past offset %zu",
                       f->path, w->restart);
    return true;
}

/* Mark each skipped range, less the directive lines the walk kept. */
static void cm_tok_mark_skipped(struct cm_tok_walk *w)
{
    for (size_t k = 0; w->keep != NULL && k < w->nskip; k++)
        for (size_t i = w->skip[k].a; i < w->skip[k].b; i++)
            if (w->keep[i] == CM_KEEP_NONE)
                w->live[i] = CM_LIVE_SKIPPED;
}

/* The skipped ranges the walk reads f by. clang reports one file's ranges
 * for one of its entries only, so a file the TU may have entered more than
 * once (`once` false) is read as one skipped range, whole: nothing in it is
 * marked exempt, hidden or skipped, and every occurrence is recorded. */
static bool cm_tok_ranges(struct cm_state *st, const struct cm_file *f,
                          bool once, struct cm_tok_walk *w,
                          struct cm_span **skip)
{
    if (once) {
        w->keep = zcl_calloc(f->size, 1, "clang_manifest.keep");
        return w->keep != NULL &&
               cm_tok_skipped_ranges(st->tu, (CXFile)f->key, f->size, w->keep,
                                     skip, &w->nskip);
    }
    *skip = zcl_calloc(1, sizeof(**skip), "clang_manifest.skipped");
    if (*skip == NULL)
        return false;
    **skip = (struct cm_span){0, f->size};
    w->nskip = 1;
    return true;
}

static bool cm_tok_file(struct cm_state *st, struct cm_file *f,
                        bool trigraphs, bool once, struct cm_piece *piece)
{
    struct cm_tok_walk w = {.tu = st->tu, .s = f->contents, .n = f->size,
                            .trigraphs = trigraphs, .bol = true,
                            .piece = piece};
    struct cm_span *skip = NULL;
    size_t from = 0;
    bool ok = true;
    free(f->live);
    f->live = NULL;
    if (f->size == 0)
        return true;
    if (f->contents == NULL || f->size >= UINT32_MAX)
        return cm_fail(&st->core, "cannot tokenize %s", f->path);
    w.live = zcl_calloc(f->size, 1, "clang_manifest.live");
    if (w.live == NULL || !cm_tok_ranges(st, f, once, &w, &skip))
        return free(w.live), free(w.keep), free(skip),
               cm_fail(&st->core, "out of memory");
    f->live = w.live;
    w.skip = skip;
    do {
        ok = cm_tok_pass(st, f, &w, from);
        from = w.restart;
    } while (ok && from != 0 && from < f->size);
    cm_tok_mark_skipped(&w);
    free(skip);
    free(w.keep);
    if (ok && !cm_tok_covered(&w))
        ok = cm_fail(&st->core, "cannot tokenize %s: tokens end at %zu",
                     f->path, w.reach);
    return ok;
}

/* ---- built-in and command-line #defines, and inclusion counts ------------- */

struct cm_builtin_visit {
    struct cm_state *st;
    struct cm_piece *piece;
    size_t *entered; /* per file: the inclusion directives that name it */
};

/* An inclusion directive the front end ran, in any file or on the command
 * line (-include), counts toward the file it names: a file is entered at
 * most once per directive (an include guard or #pragma once can only make
 * it less), in a cold parse and a warm one alike. */
static void cm_tok_count_inclusion(struct cm_builtin_visit *v, CXCursor c)
{
    const struct cm_file *f = cm_file_of(v->st, clang_getIncludedFile(c));
    if (f != NULL)
        v->entered[f - v->st->core.files]++;
}

/* A macro no file holds (the front end's built-ins, -D and -U): its
 * tokens are read as a #define line's, by clang's spelling (the buffer
 * that holds them is no file, and phases 1 and 2 leave it as it is). */
static enum CXChildVisitResult cm_tok_builtin_visit(CXCursor c, CXCursor parent,
                                                    CXClientData data)
{
    struct cm_builtin_visit *v = data;
    struct cm_tok_walk w = {.tu = v->st->tu, .piece = v->piece,
                            .dir = CM_DIR_DEFINE};
    CXFile file = NULL;
    CXToken *t = NULL;
    unsigned n = 0;
    (void)parent;
    if (clang_getCursorKind(c) == CXCursor_InclusionDirective)
        cm_tok_count_inclusion(v, c);
    if (clang_getCursorKind(c) != CXCursor_MacroDefinition)
        return CXChildVisit_Continue;
    clang_getSpellingLocation(clang_getCursorLocation(c), &file, NULL, NULL,
                              NULL);
    if (file != NULL)
        return CXChildVisit_Continue;
    clang_tokenize(v->st->tu, clang_getCursorExtent(c), &t, &n);
    for (unsigned k = 0; k < n; k++)
        (void)cm_tok_line(&w, t[k], 0, 0);
    clang_disposeTokens(v->st->tu, t, n);
    return CXChildVisit_Continue;
}

/* The first spelling of a paste that could build a lookup word, into
 * st->core.paste_piece, or NULL. */
static bool cm_piece_report(struct cm_state *st, const struct cm_piece *p)
{
    free(st->core.paste_piece);
    st->core.paste_piece = NULL;
    for (size_t w = 0; w < CM_PASTE_WORDS; w++) {
        size_t b = cm_piece_cover(p, w);
        char first[CM_PASTE_MAX + 1];
        if (b == 0)
            continue;
        memcpy(first, k_cm_paste_words[w], b);
        first[b] = '\0';
        if ((st->core.paste_piece = cm_strdup(first)) == NULL)
            return cm_fail(&st->core, "out of memory");
        return true;
    }
    return true;
}

/* Was f, by the inclusion directives counted, entered at most once? The
 * main file is entered once more, and a file no directive names is taken
 * as entered more than once. */
static bool cm_tok_once(const struct cm_state *st, const size_t *entered,
                        size_t k)
{
    bool main = clang_File_isEqual((CXFile)st->core.files[k].key,
                                   st->main_file) != 0;
    return entered[k] + (main ? 1 : 0) == 1;
}

bool cm_tokenize_files(struct cm_state *st, bool trigraphs)
{
    struct cm_piece *piece = zcl_calloc(1, sizeof(*piece),
                                        "clang_manifest.piece");
    size_t *entered = zcl_calloc(st->core.nfiles + 1, sizeof(*entered),
                                 "clang_manifest.entered");
    struct cm_builtin_visit v = {.st = st, .piece = piece, .entered = entered};
    bool ok = piece != NULL && entered != NULL;
    if (ok)
        clang_visitChildren(clang_getTranslationUnitCursor(st->tu),
                            cm_tok_builtin_visit, &v);
    else
        (void)cm_fail(&st->core, "out of memory");
    for (size_t k = 0; ok && k < st->core.nfiles; k++)
        ok = cm_tok_file(st, &st->core.files[k], trigraphs,
                         cm_tok_once(st, entered, k), piece);
    ok = ok && cm_piece_report(st, piece);
    free(piece);
    free(entered);
    return ok;
}
