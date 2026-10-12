/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Facts revision 2 conditional sites: the identifiers every #if, #elif, #ifdef, #ifndef, #elifdef and #elifndef line of a file the front end read tests. */
#include "clang_manifest_core.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The front end records a conditional's macro only when it is defined, so a
 * consumer could never tell that `#ifdef NAME` starts to matter when a
 * header begins to define NAME. This scan reads the bytes of every file the
 * TU read and names each identifier a conditional directive tests, defined
 * or not, active branch or not. It is lexical and conservative: a name in a
 * dead branch is still named. For a system file only names some repo file
 * of the TU defines are kept, since only those can change under the tree. */

struct cc_scan {
    const char *s;
    size_t i, n;
};

static bool cc_ident_start(unsigned char ch)
{
    return ch == '_' || ch == '$' || ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'z');
}

static bool cc_ident_byte(unsigned char ch)
{
    return cc_ident_start(ch) || (ch >= '0' && ch <= '9');
}

/* Length of a line splice at i (backslash, optional CR, newline), or 0. */
static size_t cc_splice(const struct cc_scan *x, size_t i)
{
    if (i >= x->n || x->s[i] != '\\')
        return 0;
    if (i + 1 < x->n && x->s[i + 1] == '\n')
        return 2;
    if (i + 2 < x->n && x->s[i + 1] == '\r' && x->s[i + 2] == '\n')
        return 3;
    return 0;
}

/* Skip a comment at i; true when one was there. A line comment stops before
 * its newline. */
static bool cc_comment(struct cc_scan *x)
{
    if (x->i + 1 >= x->n || x->s[x->i] != '/')
        return false;
    if (x->s[x->i + 1] == '*') {
        const char *end = NULL;
        for (size_t k = x->i + 2; k + 1 < x->n; k++) {
            if (x->s[k] == '*' && x->s[k + 1] == '/') {
                end = x->s + k + 2;
                break;
            }
        }
        x->i = end != NULL ? (size_t)(end - x->s) : x->n;
        return true;
    }
    if (x->s[x->i + 1] != '/')
        return false;
    while (x->i < x->n && x->s[x->i] != '\n')
        x->i += cc_splice(x, x->i) ? cc_splice(x, x->i) : 1;
    return true;
}

/* Skip a string or character literal starting at i. */
static void cc_literal(struct cc_scan *x)
{
    char quote = x->s[x->i++];
    while (x->i < x->n && x->s[x->i] != quote && x->s[x->i] != '\n')
        x->i += x->s[x->i] == '\\' && x->i + 1 < x->n ? 2 : 1;
    if (x->i < x->n && x->s[x->i] == quote)
        x->i++;
}

/* Skip blanks, comments and splices that stay on the logical line. */
static void cc_blanks(struct cc_scan *x)
{
    while (x->i < x->n) {
        size_t sp = cc_splice(x, x->i);
        if (sp > 0)
            x->i += sp;
        else if (x->s[x->i] == ' ' || x->s[x->i] == '\t' ||
                 x->s[x->i] == '\r' || x->s[x->i] == '\f' ||
                 x->s[x->i] == '\v')
            x->i++;
        else if (!cc_comment(x))
            return;
    }
}

static size_t cc_ident(const struct cc_scan *x)
{
    size_t k = x->i;
    if (k >= x->n || !cc_ident_start((unsigned char)x->s[k]))
        return 0;
    while (k < x->n && cc_ident_byte((unsigned char)x->s[k]))
        k++;
    return k - x->i;
}

static bool cc_is(const char *s, size_t n, const char *lit)
{
    return n == strlen(lit) && memcmp(s, lit, n) == 0;
}

static bool cc_conditional(const char *s, size_t n)
{
    static const char *const k[] = {"if", "elif", "ifdef", "ifndef",
                                    "elifdef", "elifndef"};
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (cc_is(s, n, k[i]))
            return true;
    return false;
}

struct cc_emit {
    struct cm_core *c;
    const struct cm_file *f;
    char **defined; /* sorted repo macro names, for a system file's filter */
    size_t ndefined;
};

static int cc_str_cmp(const void *x, const void *y)
{
    return strcmp(*(const char *const *)x, *(const char *const *)y);
}

static bool cc_name(struct cc_emit *e, const char *s, size_t n)
{
    size_t site_n = strlen(VCS_SEMANTIC_FACTS_COND_SITE) + strlen(e->f->path) + 1;
    char *site, *to;
    bool ok;
    if (cc_is(s, n, "defined"))
        return true;
    to = zcl_malloc(n + 3, "clang_manifest.cond_to");
    if (to == NULL)
        return cm_fail(e->c, "out of memory");
    (void)snprintf(to, n + 3, "m:%.*s", (int)n, s);
    if (e->f->origin == VCS_SEMANTIC_ORIGIN_V1_SYSTEM) {
        const char *key = to + 2;
        if (bsearch(&key, e->defined, e->ndefined, sizeof(*e->defined),
                    cc_str_cmp) == NULL) {
            free(to);
            return true;
        }
    }
    site = zcl_malloc(site_n, "clang_manifest.cond_site");
    if (site == NULL) {
        free(to);
        return cm_fail(e->c, "out of memory");
    }
    (void)snprintf(site, site_n, "%s%s", VCS_SEMANTIC_FACTS_COND_SITE,
                   e->f->path);
    ok = cm_ref(e->c, site, VCS_SEMANTIC_REF_V1_MACRO, to);
    free(site);
    free(to);
    return ok;
}

static void cc_number(struct cc_scan *x)
{
    while (x->i < x->n && (cc_ident_byte((unsigned char)x->s[x->i]) ||
                           x->s[x->i] == '.' || x->s[x->i] == '\''))
        x->i++;
}

/* One token of a logical line; an identifier is named when `emit`. */
static bool cc_token(struct cc_scan *x, struct cc_emit *e, bool emit)
{
    unsigned char ch = (unsigned char)x->s[x->i];
    size_t sp = cc_splice(x, x->i), id = cc_ident(x);
    bool ok = true;
    if (sp > 0)
        x->i += sp;
    else if (cc_comment(x))
        return true;
    else if (ch == '"' || ch == '\'')
        cc_literal(x);
    else if (id > 0) {
        ok = !emit || cc_name(e, x->s + x->i, id);
        x->i += id;
    } else if (ch >= '0' && ch <= '9')
        cc_number(x);
    else
        x->i++;
    return ok;
}

/* The rest of one logical line. */
static bool cc_line(struct cc_scan *x, struct cc_emit *e, bool emit)
{
    bool ok = true;
    while (ok && x->i < x->n && x->s[x->i] != '\n')
        ok = cc_token(x, e, emit);
    return ok;
}

/* One directive, at the '#': its name, then its line. */
static bool cc_directive(struct cc_scan *x, struct cc_emit *e)
{
    size_t id;
    x->i++;
    cc_blanks(x);
    id = cc_ident(x);
    if (id > 0 && cc_conditional(x->s + x->i, id)) {
        x->i += id;
        return cc_line(x, e, true);
    }
    return cc_line(x, e, false);
}

/* Walk a file: a '#' first on a logical line (after blanks and comments)
 * opens a directive; anything else skips to the end of its line. */
static bool cc_file(struct cc_emit *e)
{
    struct cc_scan x = {.s = e->f->contents, .n = e->f->size};
    bool ok = true;
    while (ok && x.i < x.n) {
        cc_blanks(&x);
        if (x.i < x.n && x.s[x.i] == '#')
            ok = cc_directive(&x, e);
        else
            ok = cc_line(&x, e, false);
        if (x.i < x.n)
            x.i++; /* the newline */
    }
    return ok;
}

bool cm_emit_conditionals(struct cm_core *c)
{
    struct cc_emit e = {.c = c};
    bool ok = true;
    if (!c->facts)
        return true;
    e.defined = zcl_calloc(c->nmacros + 1, sizeof(*e.defined),
                           "clang_manifest.cond_defined");
    if (e.defined == NULL)
        return cm_fail(c, "out of memory");
    for (size_t k = 0; k < c->nmacros; k++)
        e.defined[e.ndefined++] = c->macros[k].name;
    qsort(e.defined, e.ndefined, sizeof(*e.defined), cc_str_cmp);
    for (size_t k = 0; ok && k < c->nfiles; k++) {
        e.f = &c->files[k];
        if (e.f->contents != NULL)
            ok = cc_file(&e);
    }
    free(e.defined);
    return ok;
}
