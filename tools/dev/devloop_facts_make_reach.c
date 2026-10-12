/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The reach half of the facts consumer's make reader: which rules can run while an object is built, and which variables their lines use. */
#include "devloop_facts_make.h"

#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fxm_str_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void fxm_strs_seal(struct fxc_strs *s)
{
    size_t w = 0;
    if (s->n > 1)
        qsort(s->v, s->n, sizeof(*s->v), fxm_str_cmp);
    for (size_t k = 0; k < s->n; k++) {
        if (w > 0 && strcmp(s->v[w - 1], s->v[k]) == 0) {
            free(s->v[k]);
            continue;
        }
        s->v[w++] = s->v[k];
    }
    s->n = w;
}

/* name[0..n) is in the sealed set. */
static bool fxm_in(const struct fxc_strs *s, const char *name, size_t n)
{
    size_t lo = 0, hi = s->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int d = strncmp(s->v[mid], name, n);
        if (d == 0 && s->v[mid][n] != '\0')
            d = 1;
        if (d == 0)
            return true;
        if (d < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

/* The variable the reference at d names ($X, $(X...), ${X...}, and
 * $(call X,...) or $(value X)): its length, with its start at *name; 0 for
 * none. A name that starts with '$' is computed. '$$' is not skipped: a
 * definition eval'd later references what it spells after one expansion. */
size_t fxm_ref_name(const char *d, const char **name)
{
    const char *q = d + 1;
    size_t n = 0;
    if (*q != '(' && *q != '{') {
        *name = q;
        return fxm_ident(*q) ? 1 : 0;
    }
    q++;
    while (fxm_ident(q[n]))
        n++;
    if (((n == 4 && strncmp(q, "call", 4) == 0) ||
         (n == 5 && strncmp(q, "value", 5) == 0)) &&
        fxm_space(q[n])) {
        for (q += n; fxm_space(*q); q++)
            ;
        for (n = 0; fxm_ident(q[n]); n++)
            ;
    }
    *name = q;
    return n > 0 ? n : *q == '$';
}

/* fn over every variable s references; whether it held for any. With
 * twice, '$$(X)' references X too (text a later $(eval) or $(call) expands
 * again); without it '$$' is an escaped '$' (a recipe's shell text). */
bool fxm_each_ref(struct fxm *m, const char *s, bool twice,
                  bool (*fn)(struct fxm *, const char *, size_t))
{
    bool any = false;
    for (const char *d = strchr(s, '$'); d != NULL; d = strchr(d + 1, '$')) {
        const char *name;
        size_t n;
        if (!twice && d[1] == '$') {
            d++;
            continue;
        }
        if ((n = fxm_ref_name(d, &name)) > 0)
            any |= fn(m, name, n);
    }
    return any;
}

/* ---- make inputs: the recipe lines that can run make --------------------------- */

/* The glob a computed name ($($(X)_Y)) spells: each inner reference any
 * text, into pat. False when it names no variable by its spelling: one
 * inner reference alone ($($(X)), a name held in a value, which the words
 * of that value spell) or a space outside its references (no variable name
 * holds one). Too long to spell: any variable. */
bool fxm_name_glob(const char *name, char *pat)
{
    size_t n = 0;
    int depth = 0;
    bool literal = false;
    for (const char *p = name; *p != '\0'; p++) {
        if (n + 2 >= FXM_NAME_MAX) {
            memcpy(pat, "\x01", 2);
            return true;
        }
        if (*p == '$' && (p[1] == '(' || p[1] == '{')) {
            if (depth++ == 0)
                pat[n++] = FXM_ANY;
            p++;
        } else if (depth > 0) {
            depth += (*p == '(' || *p == '{') - (*p == ')' || *p == '}');
        } else if (fxm_ident(*p)) {
            pat[n++] = *p;
            literal = true;
        } else if (fxm_space(*p)) {
            return false;
        } else {
            break;
        }
    }
    pat[n] = '\0';
    return literal;
}

/* The command make at p, in any case: make, $(MAKE), gmake, cmake,
 * $(MAKE_COMMAND); not MAKEFLAGS or Makefile. */
static bool fxm_make_at(const char *p)
{
    if ((p[0] | 0x20) != 'm' || (p[1] | 0x20) != 'a' || (p[2] | 0x20) != 'k' ||
        (p[3] | 0x20) != 'e')
        return false;
    return !fxm_ident(p[4]) ||
           (strncmp(p + 4, "_COMMAND", 8) == 0 && !fxm_ident(p[12]));
}

/* Text that may run make by itself: the command make (fxm_make_at),
 * $(eval) or $(file). */
static bool fxm_direct_maker(const char *s)
{
    static const char *const marks[] = {"$(eval", "${eval", "$(file",
                                        "${file"};
    for (const char *p = s; *p != '\0'; p++)
        if (fxm_make_at(p))
            return true;
    for (size_t k = 0; k < sizeof(marks) / sizeof(marks[0]); k++)
        if (strstr(s, marks[k]) != NULL)
            return true;
    return false;
}

/* A maker a glob matches. */
static bool fxm_maker_glob(const struct fxm *m, const char *pat)
{
    for (size_t k = 0; k < m->makers.n; k++)
        if (fxm_glob(pat, m->makers.v[k]))
            return true;
    return false;
}

/* A reference to a variable that may run make. */
static bool fxm_is_maker(struct fxm *m, const char *name, size_t n)
{
    char pat[FXM_NAME_MAX];
    if (*name != '$')
        return fxm_in(&m->makers, name, n);
    return fxm_name_glob(name, pat) && fxm_maker_glob(m, pat);
}

/* A word that spells a variable that may run make (a call argument, a
 * name held in a value). */
static bool fxm_spells_maker(struct fxm *m, const char *t)
{
    if ((t = fxm_word_of(t)) == NULL)
        return false;
    if (strpbrk(t, FXM_WILDS) != NULL)
        return fxm_maker_glob(m, t);
    return fxm_in(&m->makers, t, strlen(t));
}

static int fxm_vname_cmp(const void *a, const void *b)
{
    return strcmp(((const struct fxm_vname *)a)->name,
                  ((const struct fxm_vname *)b)->name);
}

/* Every defined variable, sorted; make's own hooks (.EXTRA_PREREQS adds
 * prerequisites to every rule, VPATH and GPATH resolve them) are live. */
static void fxm_vnames(struct fxm *m)
{
    static const char *const hooks[] = {".EXTRA_PREREQS", ".DEFAULT_GOAL",
                                        "VPATH", "GPATH",
                                        "MAKEFILES", ".LIBPATTERNS"};
    size_t w = 0;
    m->vnames = zcl_calloc(m->nlines + 1, sizeof(*m->vnames), "facts_consumer.mkvn");
    if (m->vnames == NULL) {
        m->unknown = true;
        return;
    }
    for (size_t k = 0; k < m->nlines; k++)
        if (m->lines[k].ctx == FXM_DEF && m->lines[k].name[0] != '\0')
            m->vnames[m->nvnames++].name = m->lines[k].name;
    qsort(m->vnames, m->nvnames, sizeof(*m->vnames), fxm_vname_cmp);
    for (size_t k = 0; k < m->nvnames; k++)
        if (w == 0 || strcmp(m->vnames[w - 1].name, m->vnames[k].name) != 0)
            m->vnames[w++] = m->vnames[k];
    m->nvnames = w;
    /* The first two name goals and prerequisites too. */
    for (size_t k = 0; k < m->nvnames; k++)
        for (size_t h = 0; h < sizeof(hooks) / sizeof(hooks[0]); h++)
            if (strcmp(m->vnames[k].name, hooks[h]) == 0) {
                m->vnames[k].live = true;
                m->vnames[k].goal = h < 2;
            }
}

struct fxm_vname *fxm_vname(struct fxm *m, const char *name, size_t n)
{
    size_t lo = 0, hi = m->nvnames;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int d = strncmp(m->vnames[mid].name, name, n);
        if (d == 0 && m->vnames[mid].name[n] != '\0')
            d = 1;
        if (d == 0)
            return &m->vnames[mid];
        if (d < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/* ---- make inputs: recipe commands that only print ------------------------------ */

/* Characters a value may carry into a recipe as shell syntax. */
#define FXM_SHELL_MARKS "\"'`;|&<>!\\"

/* Value text that may carry shell syntax, a command or make into a recipe:
 * a mark, a command substitution, make, or a call whose value is not the
 * text it is given. */
static bool fxm_shelly_text(const char *s)
{
    static const char *const fns[] = {"shell", "file", "eval", "wildcard",
                                       "realpath"};
    if (strpbrk(s, FXM_SHELL_MARKS) != NULL || fxm_direct_maker(s))
        return true;
    for (const char *d = strchr(s, '$'); d != NULL; d = strchr(d + 1, '$')) {
        if (d[1] == '$' && (d[2] == '(' || d[2] == '{'))
            return true;
        for (size_t k = 0; k < sizeof(fns) / sizeof(fns[0]); k++)
            if ((d[1] == '(' || d[1] == '{') && fxm_starts_word(d + 2, fns[k]))
                return true;
    }
    return false;
}

/* A reference that may carry shell syntax: a computed name, a name no
 * definition gives (an argument, the environment), or a marked variable. */
static bool fxm_ref_shelly(struct fxm *m, const char *name, size_t n)
{
    struct fxm_vname *v;
    return *name == '$' || (v = fxm_vname(m, name, n)) == NULL || v->shelly;
}

/* at[0..n) spells a name a reference can read: every character outside its
 * references is one a variable name holds ('@', ';' and a space are not). */
static bool fxm_plain_spelling(const char *at, size_t n)
{
    int depth = 0;
    for (size_t k = 0; k < n; k++) {
        if (at[k] == '$' && (at[k + 1] == '(' || at[k + 1] == '{'))
            depth++;
        else if (depth > 0)
            depth += (at[k] == '(' || at[k] == '{') - (at[k] == ')' || at[k] == '}');
        else if (!fxm_ident(at[k]))
            return false;
    }
    return true;
}

/* Mark every variable the computed name `at` starts with (up to its
 * operator) may spell; whether one was new. A name no reference can read
 * marks nothing; one that spells no name of its own ($($(X)) :=), or too
 * long a one, marks every variable. */
static bool fxm_shelly_glob(struct fxm *m, const char *at)
{
    char pat[FXM_NAME_MAX], spelled[FXM_NAME_MAX];
    const char *op = fxm_top(at, ":+?!=");
    size_t n = op == NULL ? 0 : (size_t)(op - at);
    bool grew = false;
    while (n > 0 && fxm_space(at[n - 1]))
        n--;
    if (n >= FXM_NAME_MAX || !fxm_plain_spelling(at, n)) {
        m->shelly_any |= n >= FXM_NAME_MAX;
        return false;
    }
    memcpy(spelled, at, n);
    spelled[n] = '\0';
    m->shelly_any |= n == 0 || !fxm_name_glob(spelled, pat);
    for (size_t k = 0; !m->shelly_any && k < m->nvnames; k++)
        if (!m->vnames[k].shelly && fxm_glob(pat, m->vnames[k].name))
            m->vnames[k].shelly = grew = true;
    return grew;
}

/* Mark the variable name, or (computed) what `at` may spell; whether one
 * was new. */
static bool fxm_shelly_name(struct fxm *m, const char *name, const char *at)
{
    struct fxm_vname *v;
    bool grew;
    if (*name == '\0')
        return fxm_shelly_glob(m, at);
    v = fxm_vname(m, name, strlen(name));
    grew = v != NULL && !v->shelly;
    if (v != NULL)
        v->shelly = true;
    return grew;
}
/* One definition line's marks: a define's own variable (its value spans
 * lines), and the variable the line defines when make or $(eval) reads it
 * when its value may carry shell syntax. */
static bool fxm_shelly_line(struct fxm *m, const struct fxm_line *l)
{
    char name[FXM_NAME_MAX];
    size_t colon = 0;
    enum fxm_kind kind = fxm_kind_of(l->raw, &colon);
    const char *at, *eq;
    bool grew = l->body && fxm_shelly_name(m, l->name, "");
    if (kind != FXM_K_DEF && kind != FXM_K_TSV)
        return grew;
    at = fxm_skip_prefixes(l->raw + (kind == FXM_K_TSV ? colon + 1 : 0));
    fxm_def_name(at, name);
    eq = fxm_top(at, "=");
    if (eq != NULL && eq > at && eq[-1] != '!' && !fxm_shelly_text(eq + 1) &&
        !fxm_each_ref(m, eq + 1, true, fxm_ref_shelly))
        return grew;
    return fxm_shelly_name(m, name, at) || grew;
}

/* Mark every variable a definition of which may carry shell syntax into a
 * recipe, closed over references. */
static void fxm_shelly(struct fxm *m)
{
    for (bool grew = true; grew && !m->shelly_any;) {
        grew = false;
        for (size_t k = 0; k < m->nlines && !m->shelly_any; k++)
            if (m->lines[k].ctx == FXM_DEF)
                grew |= fxm_shelly_line(m, &m->lines[k]);
    }
}

/* The bracket that closes the reference at d ("$(" or "${"); NULL for none. */
char *fxm_ref_end(char *d)
{
    int depth = 0;
    for (char *p = d + 1; *p != '\0'; p++)
        if ((depth += (*p == '(' || *p == '{') - (*p == ')' || *p == '}')) == 0)
            return p;
    return NULL;
}

/* p..e (e its last character) names one of make's automatic variables. */
static bool fxm_auto_var(const char *p, const char *e)
{
    return *p != '\0' && strchr("@<*^+?", *p) != NULL &&
           (e == p || (e == p + 1 && (p[1] == 'D' || p[1] == 'F')));
}

static bool fxm_plain_name(struct fxm *m, const char *name, size_t n)
{
    struct fxm_vname *v = fxm_vname(m, name, n);
    return !m->shelly_any && v != NULL && !v->shelly;
}

/* The reference d..e (e its last character) puts no shell syntax into a
 * command: an automatic variable, or $X, $(X) or ${X} of a variable every
 * definition of which is plain text. */
static bool fxm_plain_ref(struct fxm *m, char *d, const char *e)
{
    const char *name;
    size_t n;
    if (e == d + 1)
        return fxm_auto_var(d + 1, e) ||
               (fxm_ident(d[1]) && fxm_plain_name(m, d + 1, 1));
    if (fxm_auto_var(d + 2, e - 1))
        return true;
    n = fxm_ref_name(d, &name);
    return n > 0 && name == d + 2 && name + n == e && fxm_plain_name(m, name, n);
}

/* The last character of the unit at p that a shell quote or separator
 * cannot split: a '$$', a make reference, or a character a backslash
 * escapes; p itself for any other. NULL for a reference that does not
 * close. */
static char *fxm_unit_end(char *p, char quote)
{
    if (p[0] == '$' && p[1] == '$')
        return p + 1;
    if (p[0] == '$' && (p[1] == '(' || p[1] == '{'))
        return fxm_ref_end(p);
    if (p[0] == '\\' && quote != '\'' && p[1] != '\0')
        return p + 1;
    return p;
}

/* p (after s) separates two shell commands: ';', '&' or '|', but not the
 * '&' of a redirection (>&2, <&0, &>). */
static bool fxm_separator(const char *s, const char *p)
{
    if (*p == '&' && (p[1] == '>' || (p > s && (p[-1] == '<' || p[-1] == '>'))))
        return false;
    return *p == ';' || *p == '&' || *p == '|';
}

/* The end of the shell command at p: the first separator outside quotes
 * and references; NULL when one does not close. */
static char *fxm_command_end(char *p)
{
    char quote = '\0';
    for (const char *s = p; *p != '\0'; p++) {
        char *u = fxm_unit_end(p, quote);
        if (u == NULL)
            return NULL;
        if (u != p)
            p = u;
        else if (quote != '\0')
            quote = *p == quote ? '\0' : quote;
        else if (*p == '\'' || *p == '"')
            quote = *p;
        else if (fxm_separator(s, p))
            return p;
    }
    return quote == '\0' ? p : NULL;
}

/* After '>': a redirection that feeds no command and names no file. */
bool fxm_quiet_redirect(const char *p)
{
    while (fxm_space(*p))
        p++;
    return (p[0] == '&' && p[1] >= '0' && p[1] <= '9') ||
           strncmp(p, "/dev/null", 9) == 0;
}

/* Past the @, -, +, (, {, !, then, else, do and elif that lead a command. */
static char *fxm_command_word(char *p, const char *e)
{
    static const char *const kw[] = {"then", "else", "do", "elif"};
    for (bool more = true; more;) {
        while (p < e && (fxm_space(*p) || strchr("@-+({!", *p) != NULL))
            p++;
        more = false;
        for (size_t k = 0; k < sizeof(kw) / sizeof(kw[0]); k++)
            if (fxm_starts_word(p, kw[k])) {
                p += strlen(kw[k]);
                more = true;
            }
    }
    return p;
}

/* The '$' at p in an echo's arguments p..e: the last character of an
 * escaped '$' or a plain reference; NULL for a command substitution or any
 * other reference. */
static char *fxm_quiet_dollar(struct fxm *m, char *p, const char *e)
{
    char *r;
    if (p[1] == '$')
        return p[2] == '(' || p[2] == '{' ? NULL : p + 1;
    r = p[1] == '(' || p[1] == '{' ? fxm_ref_end(p) : p + 1;
    return r != NULL && r < e && fxm_plain_ref(m, p, r) ? r : NULL;
}

/* p..e, an echo's or printf's arguments, runs nothing: no command
 * substitution, no redirection but to a descriptor or /dev/null, and only
 * plain references. */
static bool fxm_quiet_args(struct fxm *m, char *p, const char *e)
{
    for (; p < e; p++) {
        if (*p == '$' && (p = fxm_quiet_dollar(m, p, e)) == NULL)
            return false;
        if (*p == '`' || *p == '<' || (*p == '>' && !fxm_quiet_redirect(p + 1)))
            return false;
    }
    return true;
}

/* p..e is one echo or printf that runs nothing. */
static bool fxm_prints_only(struct fxm *m, char *p, const char *e)
{
    p = fxm_command_word(p, e);
    return (fxm_starts_word(p, "echo") || fxm_starts_word(p, "printf")) &&
           fxm_quiet_args(m, p, e);
}

/* After a group's closing ')' or '}' at p: what the group prints feeds
 * something (a pipe, a redirection, a word it joins) rather than ending
 * with a separator or the line. */
static bool fxm_group_feeds(const char *p)
{
    while (fxm_space(*++p))
        ;
    if (*p == '|')
        return p[1] != '|';
    return *p != '\0' && *p != ';' && *p != '&' && *p != ')' && *p != '}';
}

/* A group or command substitution in s (outside quotes and make
 * references) whose output feeds another command: an echo in it prints
 * into that command. */
static bool fxm_fed_group(char *s)
{
    char quote = '\0';
    for (char *p = s; *p != '\0'; p++) {
        char *u = fxm_unit_end(p, quote);
        if (u == NULL || (p[0] == '$' && p[1] == '$' && p[2] == '('))
            return true;
        if (u != p)
            p = u;
        else if (quote != '\0')
            quote = *p == quote ? '\0' : quote;
        else if (*p == '\'' || *p == '"')
            quote = *p;
        else if ((*p == ')' || *p == '}') && fxm_group_feeds(p))
            return true;
    }
    return false;
}

/* Blank in a recipe line each command that only prints: what it prints is
 * text, never a goal make runs. One piped into another command stays, and
 * so does every one in a line whose group feeds another command. */
static void fxm_quiet_recipe(struct fxm *m, char *s)
{
    if (fxm_fed_group(s))
        return;
    for (char *p = s, *e; *p != '\0'; p = e + 1) {
        if ((e = fxm_command_end(p)) == NULL)
            return;
        if (!(*e == '|' && e[1] != '|') && fxm_prints_only(m, p, e))
            memset(p, ' ', (size_t)(e - p));
        if (*e == '\0')
            return;
    }
}

/* The end of the argument that starts at p (a top-level ',' or the call's
 * closing bracket), or NULL when the call does not close. */
static char *fxm_arg_end(char *p, char close)
{
    int depth = 0;
    for (; *p != '\0'; p++) {
        if (*p == '(' || *p == '{')
            depth++;
        else if ((*p == ')' || *p == '}') && depth-- == 0)
            return *p == close ? p : NULL;
        else if (*p == ',' && depth == 0)
            return p;
    }
    return NULL;
}

/* A call that runs something as it is expanded: its text is not only a
 * value. */
static bool fxm_running_call(const char *name)
{
    static const char *const fns[] = {"shell", "eval", "file", "call", "value"};
    for (size_t k = 0; k < sizeof(fns) / sizeof(fns[0]); k++)
        if (fxm_starts_word(name, fns[k]))
            return true;
    return false;
}

static void fxm_quiet_value(struct fxm *m, char *p, char *e, int depth);

/* Blank the reference at p (in p..e) unless it runs something as it is
 * expanded: a reference to a variable that may run make and a call that
 * runs something stay whole; any other call is blanked around its
 * arguments, which are blanked the same way. Past it; NULL to stop. */
static char *fxm_quiet_ref(struct fxm *m, char *p, char *e, int depth)
{
    char *r, *q;
    if (fxm_ident(p[1])) {
        if (!fxm_is_maker(m, p + 1, 1))
            memset(p, ' ', 2);
        return p + 2;
    }
    if ((r = fxm_ref_end(p)) == NULL || r >= e)
        return NULL;
    for (q = p + 2; fxm_ident(*q); q++)
        ;
    if (q == r && !fxm_is_maker(m, p + 2, (size_t)(q - p - 2))) {
        memset(p, ' ', (size_t)(r + 1 - p));
    } else if (q > p + 2 && fxm_space(*q) && !fxm_running_call(p + 2)) {
        memset(p, ' ', (size_t)(q - p));
        *r = ' ';
        fxm_quiet_value(m, q, r, depth + 1);
    }
    return r + 1;
}

/* Blank p..e, text whose value is only tested or printed, but for what
 * runs as it is expanded (fxm_quiet_ref). Text holding '$$' (a reference
 * a later expansion makes) stays as it is from there on. */
static void fxm_quiet_value(struct fxm *m, char *p, char *e, int depth)
{
    while (p != NULL && p < e && depth < FXM_ROUNDS) {
        if (p[0] == '$' && p[1] == '$')
            return;
        if (p[0] == '$' && (fxm_ident(p[1]) || p[1] == '(' || p[1] == '{'))
            p = fxm_quiet_ref(m, p, e, depth);
        else
            *p++ = ' ';
    }
}

/* How much of the call at d is only tested or printed: 1 its first
 * argument ($(if)'s condition, $(foreach)'s variable name, $(filter)'s and
 * $(filter-out)'s patterns), 2 all of it ($(error), $(info), $(warning),
 * $(origin), $(flavor)), 0 none. */
static int fxm_quiet_call(const char *d)
{
    static const char *const first[] = {"if", "filter", "filter-out", "foreach"};
    static const char *const whole[] = {"error", "info", "warning", "origin",
                                        "flavor"};
    if (d[1] != '(' && d[1] != '{')
        return 0;
    for (size_t k = 0; k < sizeof(whole) / sizeof(whole[0]); k++)
        if (fxm_starts_word(d + 2, whole[k]) && d[2 + strlen(whole[k])] != '(')
            return 2;
    for (size_t k = 0; k < sizeof(first) / sizeof(first[0]); k++)
        if (fxm_starts_word(d + 2, first[k]) && d[2 + strlen(first[k])] != '(')
            return 1;
    return 0;
}

/* Blank what a call can never put in its value (fxm_quiet_call), but for
 * what runs as it is expanded. A word there cannot become a prerequisite
 * or a goal. */
void fxm_blank(struct fxm *m, char *s)
{
    for (char *d = strchr(s, '$'); d != NULL; d = strchr(d + 1, '$')) {
        int quiet = fxm_quiet_call(d);
        char close = d[1] == '(' ? ')' : '}', *a, *e;
        if (quiet == 0)
            continue;
        for (a = d + 2; *a != '\0' && !fxm_space(*a); a++)
            ;
        e = fxm_arg_end(a, close);
        while (quiet == 2 && e != NULL && *e == ',')
            e = fxm_arg_end(e + 1, close);
        if (e != NULL)
            fxm_quiet_value(m, a, e, 0);
    }
}

/* What a line says from its offset on, less what its calls cannot put in
 * their values and (a recipe line) its commands that only print, into
 * m->line; expanded, '%' as shell text in a recipe. NULL when it cannot be
 * held (then the text is UNKNOWN). */
static char *fxm_said(struct fxm *m, const struct fxm_line *l)
{
    char *t;
    m->line.n = 0;
    if (!fxm_put(&m->line, l->raw + l->from, strlen(l->raw + l->from))) {
        m->unknown = true;
        return NULL;
    }
    fxm_blank(m, m->line.p);
    if (l->ctx == FXM_RECIPE)
        fxm_quiet_recipe(m, m->line.p);
    t = (char *)fxm_expand(m, m->line.p, m->line.n);
    for (char *c = t; c != NULL && *c != '\0' && l->ctx == FXM_RECIPE; c++)
        *c = *c == '%' ? FXM_PCT : *c;
    return t;
}

/* The line may run make: by itself, or through a variable it references or
 * spells. A recipe line's commands that only print run nothing. */
static bool fxm_line_makes(struct fxm *m, struct fxm_line *l)
{
    const char *raw = l->raw;
    char *text = l->text;
    if (l->ctx == FXM_RECIPE) {
        if ((text = fxm_said(m, l)) == NULL)
            return true;
        raw = m->line.p;
    }
    return fxm_direct_maker(raw) ||
           fxm_each_ref(m, raw, l->ctx != FXM_RECIPE, fxm_is_maker) ||
           fxm_tokens(m, text, fxm_spells_maker);
}

/* The definition's variable may run make: false when it already did. */
static bool fxm_maker_add(struct fxm *m, const char *name)
{
    if (*name == '\0') {
        m->whole = true; /* a computed variable that may run make */
        return false;
    }
    if (fxm_in(&m->makers, name, strlen(name)))
        return false;
    if (!fxc_strs_add(&m->makers, name)) {
        m->unknown = true;
        return false;
    }
    fxm_strs_seal(&m->makers);
    return true;
}

/* The defined variables and those that may carry shell syntax; the
 * variables whose value may run make, closed over references and
 * spellings; then each recipe line's own verdict. */
void fxm_makers(struct fxm *m)
{
    bool grew = true;
    fxm_vnames(m);
    if (!m->unknown)
        fxm_shelly(m);
    while (grew && !m->unknown) {
        grew = false;
        for (size_t k = 0; k < m->nlines; k++)
            if (m->lines[k].ctx == FXM_DEF &&
                !fxm_in(&m->makers, m->lines[k].name, strlen(m->lines[k].name)) &&
                fxm_line_makes(m, &m->lines[k]))
                grew |= fxm_maker_add(m, m->lines[k].name);
    }
    for (size_t k = 0; k < m->nlines; k++)
        if (m->lines[k].ctx == FXM_RECIPE)
            m->lines[k].runs_make = fxm_line_makes(m, &m->lines[k]);
}

/* ---- make inputs: the rules that can change an object -------------------------- */

static int fxm_pair_cmp(const void *a, const void *b)
{
    return strcmp(((const struct fxm_pair *)a)->name,
                  ((const struct fxm_pair *)b)->name);
}

/* A rule every target of which is a literal .PHONY name waits to be
 * reached, its words (NUL-ended in place when add) joining the pairs; any
 * other rule is reached. */
static bool fxm_rule_words(struct fxm *m, uint32_t r, bool add)
{
    char *s = m->rules[r].targets;
    size_t words = 0;
    while (*s != '\0') {
        char *w = s;
        size_t n;
        while (fxm_space(*w))
            w++;
        for (s = w; *s != '\0' && !fxm_space(*s); s++)
            ;
        if ((n = (size_t)(s - w)) == 0)
            continue;
        if (!add && (!fxm_literal_span(w, n) || !fxm_in(&m->phony, w, n)))
            return false;
        if (add) {
            s += *s != '\0';
            w[n] = '\0';
            m->pairs[m->npairs++] = (struct fxm_pair){.name = w, .rule = r};
        }
        words++;
    }
    return words > 0;
}

static void fxm_pairs(struct fxm *m)
{
    size_t cap = 0;
    for (size_t k = 0; k < m->nrules; k++)
        cap += strlen(m->rules[k].targets) / 2 + 1;
    m->pairs = zcl_calloc(cap + 1, sizeof(*m->pairs), "facts_consumer.mkpairs");
    if (m->pairs == NULL) {
        m->unknown = true;
        return;
    }
    for (uint32_t r = 0; r < m->nrules; r++) {
        m->rules[r].reached |= !fxm_rule_words(m, r, false);
        if (!m->rules[r].reached)
            (void)fxm_rule_words(m, r, true);
    }
    qsort(m->pairs, m->npairs, sizeof(*m->pairs), fxm_pair_cmp);
}

/* A pair's name against name[0..len): <0, 0 or >0 as strcmp would say. */
static int fxm_pair_key(const struct fxm_pair *p, const char *name, size_t len)
{
    int d = strncmp(p->name, name, len);
    return d != 0 ? d : p->name[len] != '\0';
}

/* Reach every rule the .PHONY name name[0..len) belongs to. */
bool fxm_reach_name(struct fxm *m, const char *name, size_t len)
{
    size_t lo = 0, hi = m->npairs;
    bool grew = false;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (fxm_pair_key(&m->pairs[mid], name, len) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    for (; lo < m->npairs && fxm_pair_key(&m->pairs[lo], name, len) == 0; lo++) {
        grew |= !m->rules[m->pairs[lo].rule].reached;
        m->rules[m->pairs[lo].rule].reached = true;
    }
    return grew;
}

/* The .PHONY name a word is (make matches a target by its exact name: a
 * word led by '-', '@' or '+' names only a target spelled so), or
 * every one a glob word matches: reach its rules. */
bool fxm_token_phony(struct fxm *m, const char *t)
{
    bool grew = false;
    if (*t != '-' && *t != '@' && *t != '+' && (t = fxm_word_of(t)) == NULL)
        return false;
    if (strpbrk(t, FXM_WILDS) == NULL)
        return fxm_reach_name(m, t, strlen(t));
    for (size_t k = 0; k < m->npairs; k++)
        if (!m->rules[m->pairs[k].rule].reached && fxm_glob(t, m->pairs[k].name))
            grew |= fxm_reach_name(m, m->pairs[k].name, strlen(m->pairs[k].name));
    return grew;
}

/* Live every variable a glob of a name matches; whether one was new. */
static bool fxm_live_glob(struct fxm *m, const char *pat)
{
    bool grew = false;
    for (size_t k = 0; k < m->nvnames; k++)
        if (!m->vnames[k].live && fxm_glob(pat, m->vnames[k].name)) {
            m->vnames[k].live = true;
            grew = true;
        }
    return grew;
}

/* A computed name ($($(X)_Y)): every variable its spelling can match. */
static bool fxm_live_computed(struct fxm *m, const char *name)
{
    char pat[FXM_NAME_MAX];
    return fxm_name_glob(name, pat) && fxm_live_glob(m, pat);
}

/* A word that spells a variable's name (a call argument, a name held in a
 * value, $(value X)): that variable is live, as its reference would be. */
static bool fxm_token_var(struct fxm *m, const char *t)
{
    struct fxm_vname *v;
    if ((t = fxm_word_of(t)) == NULL)
        return false;
    if (strpbrk(t, FXM_WILDS) != NULL)
        return fxm_live_glob(m, t);
    v = fxm_vname(m, t, strlen(t));
    if (v == NULL || v->live)
        return false;
    v->live = true;
    return true;
}

/* A reference from a line that reaches: its variable is live. */
static bool fxm_live_ref(struct fxm *m, const char *name, size_t n)
{
    struct fxm_vname *v;
    if (*name == '$')
        return fxm_live_computed(m, name);
    v = fxm_vname(m, name, n);
    if (v == NULL || v->live)
        return false;
    v->live = true;
    return true;
}

/* A line whose mentions count: of a reached rule, or of no rule. */
bool fxm_live(const struct fxm *m, const struct fxm_line *l)
{
    if (l->ctx == FXM_ACTIVE || l->ctx == FXM_DEF || l->ctx == FXM_QUIET)
        return true;
    if (l->ctx == FXM_PHONY)
        return false;
    return m->whole || m->rules[l->rule].reached || l->runs_make;
}

static bool fxm_recipe_reaches(struct fxm *m, struct fxm_line *l);

/* A line whose .PHONY names and references reach: a directive (not a
 * conditional: it cannot make a rule run), a definition of a live or
 * computed variable or one that runs make as it is read, the prerequisites
 * of a reached rule, and a recipe line that runs make (only make runs a
 * rule; any other command cannot) as fxm_recipe_reaches says. */
static bool fxm_reaches(struct fxm *m, struct fxm_line *l)
{
    struct fxm_vname *v;
    switch (l->ctx) {
    case FXM_ACTIVE:
        return true;
    case FXM_DEF:
        v = fxm_vname(m, l->name, strlen(l->name));
        return l->name[0] == '\0' || v == NULL || v->live ||
               fxm_direct_maker(l->raw);
    case FXM_RULE:
        return m->whole || m->rules[l->rule].reached;
    case FXM_RECIPE:
        return fxm_recipe_reaches(m, l);
    default:
        return false;
    }
}

/* Reach what a line names from its offset on (a rule's targets name no
 * rule it runs; a target-specific value's targets neither), less what its
 * calls cannot put in their values: .PHONY names, variables it references,
 * and variables it spells. */
static bool fxm_follow(struct fxm *m, const struct fxm_line *l)
{
    bool twice = l->ctx != FXM_RECIPE && (l->ctx != FXM_RULE || m->second);
    char *t = fxm_said(m, l);
    bool grew;
    if (t == NULL)
        return false;
    grew = fxm_tokens(m, t, fxm_token_phony);
    grew |= fxm_tokens(m, t, fxm_token_var);
    grew |= fxm_each_ref(m, m->line.p, twice, fxm_live_ref);
    return grew;
}

/* ---- make inputs: recipe lines that run make and the goals they name ---------- */

/* The make command word at p in s: make, gmake or $(MAKE) (fxm_make_at)
 * as a word of its own, not a part of cmake or remake. */
static bool fxm_make_word(const char *s, const char *p)
{
    if (!fxm_make_at(p))
        return false;
    if (p > s && p[-1] == 'g')
        p--;
    return p == s || !fxm_ident(p[-1]);
}

/* Text that names the make command. */
static bool fxm_make_text(const char *s)
{
    for (const char *p = s; *p != '\0'; p++)
        if (fxm_make_word(s, p))
            return true;
    return false;
}

/* A glob of a name matches a variable whose value may hold make. */
static bool fxm_cmd_glob(const struct fxm *m, const char *pat)
{
    for (size_t k = 0; k < m->nvnames; k++)
        if (m->vnames[k].cmd && fxm_glob(pat, m->vnames[k].name))
            return true;
    return false;
}

/* A reference to a variable whose value may hold the make command (a
 * computed one: one its spelling matches; $($(X)) spells its name in a
 * value, whose words fxm_spells_cmd reads). */
static bool fxm_is_cmd(struct fxm *m, const char *name, size_t n)
{
    char pat[FXM_NAME_MAX];
    struct fxm_vname *v;
    if (*name == '$')
        return fxm_name_glob(name, pat) && fxm_cmd_glob(m, pat);
    v = fxm_vname(m, name, n);
    return v != NULL && v->cmd;
}

/* A word that spells a variable whose value may hold make (a call
 * argument, a name held in a value). */
static bool fxm_spells_cmd(struct fxm *m, const char *t)
{
    struct fxm_vname *v;
    if ((t = fxm_word_of(t)) == NULL)
        return false;
    if (strpbrk(t, FXM_WILDS) != NULL)
        return fxm_cmd_glob(m, t);
    v = fxm_vname(m, t, strlen(t));
    return v != NULL && v->cmd;
}

/* Mark every variable whose value may hold the make command, closed over
 * references and spellings. */
static void fxm_cmds(struct fxm *m)
{
    for (bool grew = true; grew;) {
        grew = false;
        for (size_t k = 0; k < m->nlines; k++) {
            const struct fxm_line *l = &m->lines[k];
            struct fxm_vname *v;
            if (l->ctx != FXM_DEF ||
                (v = fxm_vname(m, l->name, strlen(l->name))) == NULL || v->cmd)
                continue;
            if (fxm_make_text(l->raw) ||
                fxm_each_ref(m, l->raw, true, fxm_is_cmd) ||
                fxm_tokens(m, l->text, fxm_spells_cmd))
                v->cmd = grew = true;
        }
    }
}

/* The shell command at p names make outside its quotes: the make command,
 * or a variable that may hold it. */
static bool fxm_unquoted_make(struct fxm *m, const char *p)
{
    const char *s = p, *name;
    char quote = '\0';
    size_t n;
    for (; *p != '\0'; p++) {
        if (quote == '\0' && (fxm_make_word(s, p) ||
                              (*p == '$' && (n = fxm_ref_name(p, &name)) > 0 &&
                               fxm_is_cmd(m, name, n))))
            return true;
        if (*p == '\\' && quote != '\'' && p[1] != '\0')
            p++;
        else if (quote != '\0')
            quote = *p == quote ? '\0' : quote;
        else if (*p == '\'' || *p == '"')
            quote = *p;
    }
    return false;
}

/* The command word of the shell command at p (past its prefixes and its
 * NAME=value words); its length in *n. */
static char *fxm_command_name(char *p, size_t *n)
{
    p = fxm_command_word(p, p + strlen(p));
    for (;;) {
        size_t k = 0;
        while (fxm_ident(p[k]))
            k++;
        if (k == 0 || p[k] != '=')
            break;
        for (p += k; *p != '\0' && !fxm_space(*p); p++)
            ;
        while (fxm_space(*p))
            p++;
    }
    for (*n = 0; p[*n] != '\0' && !fxm_space(p[*n]); (*n)++)
        ;
    return p;
}

/* The command at p runs what it is given as commands: a shell, eval or
 * xargs. */
static bool fxm_executor(char *p)
{
    static const char *const ex[] = {"sh", "bash", "dash", "zsh", "ksh",
                                     "eval", "xargs", "source", "$(SHELL)",
                                     "${SHELL}"};
    size_t n;
    const char *w = fxm_command_name(p, &n), *base = w;
    for (size_t k = 0; k < n; k++)
        base = w[k] == '/' ? w + k + 1 : base;
    n -= (size_t)(base - w);
    for (size_t k = 0; k < sizeof(ex) / sizeof(ex[0]); k++)
        if (strlen(ex[k]) == n && strncmp(base, ex[k], n) == 0)
            return true;
    return false;
}

/* The shell command at p runs make with its words: it names make outside
 * quotes, its command word does ("$(MAKE)"), or it is a shell or eval
 * given text that names make. */
static bool fxm_runs_make(struct fxm *m, char *p)
{
    size_t n;
    char *w = fxm_command_name(p, &n), save = w[n];
    bool named;
    if (fxm_unquoted_make(m, p))
        return true;
    w[n] = '\0';
    named = fxm_make_text(w) || fxm_each_ref(m, w, false, fxm_is_cmd);
    w[n] = save;
    return named || (fxm_executor(p) && fxm_make_text(p));
}

/* The end of the shell word at p: an unquoted space outside make
 * references; NULL when a quote or reference does not close. */
static char *fxm_word_end(char *p)
{
    char quote = '\0';
    for (; *p != '\0'; p++) {
        char *u = fxm_unit_end(p, quote);
        if (u == NULL)
            return NULL;
        if (u != p)
            p = u;
        else if (quote != '\0')
            quote = *p == quote ? '\0' : quote;
        else if (*p == '\'' || *p == '"')
            quote = *p;
        else if (fxm_space(*p))
            return p;
    }
    return quote == '\0' ? p : NULL;
}

/* A make option whose value is the next word. */
static bool fxm_option_arg(const char *w)
{
    static const char *const opts[] = {
        "-C", "-f", "-o", "-W", "-I", "--file", "--makefile", "--directory",
        "--include-dir", "--old-file", "--assume-old", "--what-if",
        "--new-file", "--assume-new"};
    for (size_t k = 0; k < sizeof(opts) / sizeof(opts[0]); k++)
        if (strcmp(w, opts[k]) == 0)
            return true;
    return false;
}

/* NAME[0..n) is read in a goal position. */
static bool fxm_goal_name(struct fxm *m, const char *name, size_t n)
{
    char buf[FXM_NAME_MAX];
    struct fxm_vname *v = fxm_vname(m, name, n);
    if (v != NULL)
        return v->goal;
    if (n >= sizeof(buf))
        return true;
    memcpy(buf, name, n);
    buf[n] = '\0';
    return fxc_strs_has(&m->goal_names, buf);
}

/* A goal token that may name a file target: one no literal text pins, a
 * glob, or a literal name no .PHONY rule has. */
static bool fxm_file_token(struct fxm *m, const char *t)
{
    const char *w;
    while (*t == '@' || *t == '-' || *t == '+')
        t++;
    if ((w = fxm_word_of(t)) == NULL)
        return strpbrk(t, "\x01\x03*%?[") != NULL;
    return strpbrk(w, FXM_WILDS) != NULL || !fxm_in(&m->phony, w, strlen(w));
}

/* Probe mode: whether the goal word w may name a file target. */
static void fxm_probe_word(struct fxm *m, const char *w)
{
    char *t = (char *)fxm_expand(m, w, strlen(w));
    m->file_goal |= t == NULL || fxm_tokens(m, t, fxm_file_token);
}

/* A shell redirection word (>f, 2>&1, <f): no goal; *skip_next when its
 * file is the next word. */
static bool fxm_redirection(const char *w, bool *skip_next)
{
    const char *p = w;
    while (*p >= '0' && *p <= '9')
        p++;
    if (*p != '<' && *p != '>')
        return false;
    while (*p == '<' || *p == '>' || *p == '&')
        p++;
    *skip_next = *p == '\0';
    return true;
}

static bool fxm_goal_command(struct fxm *m, char *p);

/* A command word that is one $(call F,...): F is read in a goal position,
 * and each argument's words are words of the command (an option among
 * them names no goal wherever the call puts it). */
static bool fxm_goal_call(struct fxm *m, char *w)
{
    char close = w[1] == '(' ? ')' : '}', *end = fxm_ref_end(w), *a, *e;
    const char *name;
    size_t n = fxm_ref_name(w, &name);
    bool grew;
    if (end == NULL || end[1] != '\0' || n == 0) {
        if (m->probe)
            fxm_probe_word(m, w);
        return !m->probe && fxm_goal_words(m, w, false, true);
    }
    grew = !m->probe && fxm_goal_ref(m, name, n);
    for (a = (char *)name + n; *a == ','; a = e) {
        char save;
        if ((e = fxm_arg_end(a + 1, close)) == NULL)
            break;
        save = *e;
        *e = '\0';
        grew |= fxm_goal_command(m, a + 1);
        *e = save;
    }
    return grew;
}

/* NAME=value (its name w[0..*k)): a variable a command sets. */
static bool fxm_assignment(const char *w, size_t *k)
{
    *k = 0;
    while (fxm_ident(w[*k]))
        (*k)++;
    return *k > 0 && w[*k] == '=';
}

/* One word of a command that runs make: an option (and its value) and a
 * redirection name no goal; NAME=value sets a variable the make reads,
 * whose value counts once NAME is read in a goal position (the line is
 * pending until then); any other word is a goal (fxm_goal_words; in probe
 * mode only tested, fxm_probe_word). */
static bool fxm_goal_word(struct fxm *m, char *w, bool *skip_next)
{
    size_t k;
    if (*skip_next) {
        *skip_next = false;
        return false;
    }
    if (*w == '-') {
        *skip_next = fxm_option_arg(w);
        return false;
    }
    if (fxm_redirection(w, skip_next))
        return false;
    while (*w == '@' || *w == '+')
        w++;
    if (w[0] == '$' && (w[1] == '(' || w[1] == '{') &&
        fxm_starts_word(w + 2, "call"))
        return fxm_goal_call(m, w);
    if (!fxm_assignment(w, &k)) {
        if (m->probe)
            fxm_probe_word(m, w);
        return !m->probe && fxm_goal_words(m, w, false, true);
    }
    if (m->probe)
        return false;
    if (fxm_goal_name(m, w, k))
        return fxm_goal_words(m, w + k + 1, false, true);
    m->pending = true;
    return false;
}

/* A word that runs make: the make command, or a variable that may hold
 * it (then the goals are in its value: in probe mode, any may be a
 * file). */
static bool fxm_make_word_of(struct fxm *m, const char *w)
{
    if (fxm_make_text(w))
        return true;
    if (!fxm_each_ref(m, w, false, fxm_is_cmd))
        return false;
    m->file_goal |= m->probe;
    return true;
}

/* The words of a command that runs make, or of one piped into a shell
 * (fxm_goal_word); in probe mode only those after the make word. */
static bool fxm_goal_command(struct fxm *m, char *p)
{
    bool grew = false, skip = false, seen = !m->probe;
    while (*p != '\0') {
        char *e, save;
        while (fxm_space(*p))
            p++;
        if (*p == '\0')
            break;
        if ((e = fxm_word_end(p)) == NULL) {
            m->file_goal |= m->probe;
            grew |= !m->probe && fxm_goal_words(m, p, false, true);
            break;
        }
        save = *e;
        *e = '\0';
        if (seen)
            grew |= fxm_goal_word(m, p, &skip);
        else
            seen = fxm_make_word_of(m, p);
        *e = save;
        p = e;
    }
    return grew;
}

/* The shell command at p is a shell or eval given a script. */
static bool fxm_script_runner(char *p)
{
    static const char *const sh[] = {"sh", "bash", "dash", "zsh", "ksh", "eval"};
    size_t n;
    const char *w = fxm_command_name(p, &n), *base = w;
    for (size_t k = 0; k < n; k++)
        base = w[k] == '/' ? w + k + 1 : base;
    n -= (size_t)(base - w);
    for (size_t k = 0; k < sizeof(sh) / sizeof(sh[0]); k++)
        if (strlen(sh[k]) == n && strncmp(base, sh[k], n) == 0)
            return true;
    return false;
}

static bool fxm_goal_recipe(struct fxm *m, char *s, int depth);

/* A shell or eval command that runs make: its script (the text past the
 * command word, one level of quotes dropped) is read as recipe commands
 * of its own. */
static bool fxm_goal_script(struct fxm *m, char *p, int depth)
{
    size_t n;
    char *w = fxm_command_name(p, &n);
    char *t = zcl_strdup(w + n, "facts_consumer.mkscript"), *o;
    bool grew;
    if (t == NULL) {
        m->unknown = true;
        return false;
    }
    o = t;
    for (const char *c = t; *c != '\0'; c++)
        if (*c != '"' && *c != '\'')
            *o++ = *c;
    *o = '\0';
    grew = fxm_goal_recipe(m, t, depth + 1);
    free(t);
    return grew;
}

/* A recipe line's commands that run make (fxm_runs_make; a shell's script
 * is read for its own), and the commands piped into a shell or xargs:
 * their words are the goals the make takes. */
static bool fxm_goal_recipe(struct fxm *m, char *s, int depth)
{
    bool grew = false;
    for (char *p = s, *e; p != NULL && *p != '\0'; p = *e != '\0' ? e + 1 : NULL) {
        char save;
        bool fed;
        if ((e = fxm_command_end(p)) == NULL)
            e = p + strlen(p);
        fed = *e == '|' && e[1] != '|' && fxm_executor(e + 1);
        save = *e;
        *e = '\0';
        if (!fed && depth < 2 && fxm_script_runner(p) && fxm_runs_make(m, p))
            grew |= fxm_goal_script(m, p, depth);
        else if (fed && m->probe)
            m->file_goal = true;
        else if (fed || fxm_runs_make(m, p))
            grew |= fxm_goal_command(m, p);
        *e = save;
    }
    return grew;
}

/* A recipe line that reaches: under .ONESHELL or .RECIPEPREFIX any; else
 * one that runs make, in a reached rule, or in any rule when a make it
 * runs may name a file target (it can build an object in the same run as
 * the other goals it names; one that names only .PHONY goals builds what
 * a hand-run goal builds). */
static bool fxm_recipe_reaches(struct fxm *m, struct fxm_line *l)
{
    if (m->whole)
        return true;
    if (!l->runs_make)
        return false;
    if (m->rules[l->rule].reached)
        return true;
    if (l->file_goal == 0) {
        m->probe = true;
        m->file_goal = false;
        if (fxm_said(m, l) == NULL)
            m->file_goal = true;
        else
            (void)fxm_goal_recipe(m, m->line.p, 0);
        m->probe = false;
        l->file_goal = m->file_goal ? 2 : 1;
    }
    return l->file_goal == 2;
}

/* A line in a goal position: what it spells may be a goal a make takes or
 * a prerequisite of a rule that runs: a reached rule's prerequisites, a
 * recipe line's commands that run make, an $(eval) directive (the rules it makes), and a definition of a variable
 * those read, or a computed one. */
static bool fxm_goal_line(struct fxm *m, struct fxm_line *l)
{
    struct fxm_vname *v;
    switch (l->ctx) {
    case FXM_ACTIVE:
        return strstr(l->raw, "$(eval") != NULL || strstr(l->raw, "${eval") != NULL;
    case FXM_DEF:
        v = fxm_vname(m, l->name, strlen(l->name));
        return l->name[0] == '\0' || v == NULL || v->goal;
    case FXM_RULE:
        return m->whole || m->rules[l->rule].reached;
    case FXM_RECIPE:
        return fxm_recipe_reaches(m, l);
    default:
        return false;
    }
}

static bool fxm_goal_follow(struct fxm *m, const struct fxm_line *l)
{
    bool twice = l->ctx != FXM_RECIPE && (l->ctx != FXM_RULE || m->second);
    struct fxm_vname *v = fxm_vname(m, l->name, strlen(l->name));
    char *eq;
    if (fxm_said(m, l) == NULL)
        return false;
    if (l->ctx == FXM_RECIPE)
        return fxm_goal_recipe(m, m->line.p, 0);
    /* A recipe line a define holds, and a variable whose value holds make,
     * are recipe text: their own commands that run make take its goals. */
    if (l->ctx == FXM_DEF && l->body && l->raw[0] == '\t')
        return fxm_goal_recipe(m, m->line.p, 0);
    if (l->ctx == FXM_DEF && v != NULL && v->cmd)
        return fxm_goal_recipe(m, l->body || (eq = (char *)fxm_top(m->line.p, "=")) == NULL
                                      ? m->line.p : eq + 1, 0);
    return fxm_goal_words(m, m->line.p, twice, false);
}

/* From every line that reaches, reach the .PHONY rules it names and the
 * variables it references, and from every goal position what it spells,
 * until nothing new is reached. */
void fxm_reach(struct fxm *m)
{
    bool grew = true;
    fxm_strs_seal(&m->phony);
    fxm_pairs(m);
    fxm_cmds(m);
    m->unknown |= fxm_parse_writes(m);
    while (grew && !m->unknown) {
        grew = false;
        for (size_t k = 0; k < m->nlines; k++) {
            struct fxm_line *l = &m->lines[k];
            if (!l->followed && fxm_reaches(m, l)) {
                l->followed = true;
                grew |= fxm_follow(m, l);
            }
            if (!m->unknown && !l->goal_followed && fxm_goal_line(m, l)) {
                l->goal_followed = true;
                m->pending = false;
                grew |= fxm_goal_follow(m, l);
                l->goal_followed = !m->pending;
            }
        }
    }
}
