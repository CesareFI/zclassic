/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The goal half of the facts consumer's make reader: which .PHONY goals a line can name through a value no text spells, and what make may write as it reads the makefiles. */
#include "devloop_facts_make.h"

#include <stdio.h>
#include <string.h>

/* A variable that reaches a goal position: its value may be a goal or a
 * prerequisite. */
static bool fxm_goal_mark(struct fxm_vname *v)
{
    bool grew = !v->goal;
    v->goal = v->live = true;
    return grew;
}

static bool fxm_goal_glob(struct fxm *m, const char *pat)
{
    bool grew = false;
    for (size_t k = 0; k < m->nvnames; k++)
        if (!m->vnames[k].goal && fxm_glob(pat, m->vnames[k].name))
            grew |= fxm_goal_mark(&m->vnames[k]);
    return grew;
}

/* A reference from a goal position (a computed one: every variable its
 * spelling matches; one no text defines is kept by name, for a make
 * command that sets it). */
bool fxm_goal_ref(struct fxm *m, const char *name, size_t n)
{
    char pat[FXM_NAME_MAX];
    struct fxm_vname *v;
    if (*name == '$')
        return fxm_name_glob(name, pat) && fxm_goal_glob(m, pat);
    if ((v = fxm_vname(m, name, n)) != NULL)
        return fxm_goal_mark(v);
    if (n >= sizeof(pat))
        return false;
    memcpy(pat, name, n);
    pat[n] = '\0';
    if (fxc_strs_has(&m->goal_names, pat))
        return false;
    m->unknown |= !fxc_strs_add(&m->goal_names, pat);
    return true;
}

/* A call whose value holds words of its arguments as they stand. */
static bool fxm_passes_words(const char *fn, size_t n)
{
    static const char *const fns[] = {
        "if",       "or",     "and",        "strip",   "sort",
        "firstword", "lastword", "word",    "wordlist", "filter",
        "filter-out", "foreach", "call",    "value",   "eval",
        "wildcard", "patsubst"};
    for (size_t k = 0; k < sizeof(fns) / sizeof(fns[0]); k++)
        if (strlen(fns[k]) == n && strncmp(fn, fns[k], n) == 0)
            return true;
    return false;
}

static bool fxm_goal_refs(struct fxm *m, const char *s, const char *end,
                          bool twice, int depth);

/* One word of a goal position that is one reference d..e (e its last
 * character): its variable's words stand alone in the position (it is in
 * a goal position too); a call that passes its arguments' words on
 * ($(call F,..) and $(value F) F's too) is read for its arguments' own
 * such references. Any other call's value, and a reference joined to
 * other text, is a glob the expansion already spells. */
static bool fxm_goal_unit(struct fxm *m, const char *d, const char *e,
                          bool twice, int depth)
{
    const char *name, *p = d + 2;
    size_t n = fxm_ref_name(d, &name), k = 0;
    bool grew = false;
    if (d[1] != '(' && d[1] != '{')
        return n > 0 && fxm_goal_ref(m, name, n);
    while (fxm_ident(p[k]))
        k++;
    if (k == 0 || !fxm_space(p[k]))
        return n > 0 && fxm_goal_ref(m, name, n);
    if (!fxm_passes_words(p, k) || depth >= FXM_ROUNDS)
        return false;
    if (name != p && n > 0)
        grew = fxm_goal_ref(m, name, n);
    grew |= fxm_goal_refs(m, p + k + 1, e, twice, depth + 1);
    return grew;
}

/* The reference the word w..s is as a whole, past a leading '@', '-' or
 * '+' (with twice, '$$(' is a reference too: text a later $(eval) expands
 * again): its '$'; NULL when the word is not one reference. */
static const char *fxm_whole_ref(const char *w, const char *s, bool twice)
{
    const char *d, *e = NULL;
    while (w < s && (*w == '@' || *w == '-' || *w == '+'))
        w++;
    d = twice && w + 1 < s && w[0] == '$' && w[1] == '$' ? w + 1 : w;
    if (s - d < 2 || d[0] != '$')
        return NULL;
    if (d[1] == '(' || d[1] == '{')
        e = fxm_ref_end((char *)d);
    else if (s - d == 2)
        e = d + 1;
    return e == s - 1 ? d : NULL;
}

/* Every word of s..end (a goal position's text) that is one reference
 * (fxm_whole_ref), read by fxm_goal_unit. */
static bool fxm_goal_refs(struct fxm *m, const char *s, const char *end,
                          bool twice, int depth)
{
    bool grew = false;
    while (s < end) {
        const char *w, *d;
        int nest = 0;
        while (s < end && fxm_sep(*s))
            s++;
        for (w = s; s < end && (nest > 0 || !fxm_sep(*s)); s++)
            nest += (*s == '(' || *s == '{') - (*s == ')' || *s == '}');
        if ((d = fxm_whole_ref(w, s, twice)) != NULL)
            grew |= fxm_goal_unit(m, d, s - 1, twice, depth);
    }
    return grew;
}

/* A word a goal position spells that names a variable (a call argument, a
 * name held in a value). */
static bool fxm_goal_var(struct fxm *m, const char *t)
{
    struct fxm_vname *v;
    if ((t = fxm_word_of(t)) == NULL)
        return false;
    if (strpbrk(t, FXM_WILDS) != NULL)
        return fxm_goal_glob(m, t);
    v = fxm_vname(m, t, strlen(t));
    return v != NULL && fxm_goal_mark(v);
}

/* A word of a goal position no literal text pins: a lone pattern, or a run
 * of values no text spells (an automatic variable's, a call's new words, a
 * join of two values); not one variable's value alone (FXM_ANY), whose
 * definition is followed. Every .PHONY name it can match is reached. */
static bool fxm_open_phony(struct fxm *m, const char *t)
{
    bool grew = false;
    while (*t == '@' || *t == '-' || *t == '+')
        t++;
    if ((t[0] == FXM_ANY && t[1] == '\0') || fxm_word_of(t) != NULL)
        return false;
    for (size_t k = 0; k < m->npairs; k++)
        if (!m->rules[m->pairs[k].rule].reached && fxm_glob(t, m->pairs[k].name))
            grew |= fxm_reach_name(m, m->pairs[k].name, strlen(m->pairs[k].name));
    return grew;
}

/* A shell word a backslash escapes: the name the shell makes of it is not
 * the text. */
static bool fxm_escaped(struct fxm *m, const char *t)
{
    (void)m;
    return strchr(t, '\\') != NULL;
}

/* Every rule is reached: a goal position spells any name. */
static bool fxm_reach_all(struct fxm *m)
{
    bool grew = false;
    for (size_t r = 0; r < m->nrules; r++) {
        grew |= !m->rules[r].reached;
        m->rules[r].reached = true;
    }
    return grew;
}

/* Blank the words a call's value never holds alone (FXM_HIDE_ON ..
 * FXM_HIDE_OFF): the value's own words spell them joined. */
static void fxm_unhide(char *t)
{
    int depth = 0;
    for (; *t != '\0'; t++) {
        depth += (*t == FXM_HIDE_ON) - (*t == FXM_HIDE_OFF);
        if (depth > 0 || *t == FXM_HIDE_OFF)
            *t = ' ';
    }
}

/* One goal position's text (as written, less what only tests or prints):
 * the variables it reads and spells are goal positions too; a word no
 * literal text pins reaches what it can match (fxm_open_phony). In a shell
 * command (shell), '%' is shell text, a backslash-escaped word reaches
 * every rule, and a word joined across quotes (ge"n") is the name it
 * joins to. */
bool fxm_goal_words(struct fxm *m, const char *raw, bool twice,
                    bool shell)
{
    char *t, *w;
    bool grew = fxm_goal_refs(m, raw, raw + strlen(raw), twice, 0);
    if ((t = (char *)fxm_expand(m, raw, strlen(raw))) == NULL)
        return grew;
    for (char *c = t; shell && *c != '\0'; c++)
        *c = *c == '%' ? FXM_PCT : *c;
    grew |= fxm_tokens(m, t, fxm_goal_var);
    fxm_unhide(t);
    grew |= fxm_tokens(m, t, fxm_open_phony);
    if (!shell)
        return grew;
    if (fxm_tokens(m, t, fxm_escaped))
        grew |= fxm_reach_all(m);
    w = t;
    for (const char *c = t; *c != '\0'; c++)
        if (*c != '"' && *c != '\'')
            *w++ = *c;
    *w = '\0';
    grew |= fxm_tokens(m, t, fxm_token_phony);
    return grew;
}

/* ---- make inputs: what make runs as it reads the makefiles ---------------- */

/* The quote state after s[k] of shell text: '\'' or '"' while inside
 * one. A command substitution ($$( or a backquote) inside double quotes
 * ends the tracking: from there every character counts as unquoted. */
static char fxm_quote_after(const char *s, size_t k, size_t n, char q, bool *plain)
{
    if (q == '\'')
        return s[k] == '\'' ? '\0' : q;
    if (q == '"' && (s[k] == '`' || (s[k] == '$' && k + 2 < n && s[k + 1] == '$' &&
                                     s[k + 2] == '('))) {
        *plain = true;
        return '\0';
    }
    if (s[k] == '"')
        return q == '"' ? '\0' : '"';
    return q == '\0' && s[k] == '\'' ? '\'' : q;
}

/* Unquoted shell text at s[k] (of s[0..n)) writes a file: a redirection
 * to anything but a descriptor or /dev/null, or a tee. */
static bool fxm_writes_at(const char *s, size_t k, size_t n)
{
    if (s[k] == '>')
        return k + 1 == n || !fxm_quiet_redirect(s + k + 1);
    return n - k >= 3 && strncmp(s + k, "tee", 3) == 0 &&
           (k == 0 || !fxm_ident(s[k - 1])) && (k + 3 == n || !fxm_ident(s[k + 3]));
}

/* Shell text s[0..n), as written, writes a file outside quotes
 * (fxm_writes_at). */
static bool fxm_redirects(const char *s, size_t n)
{
    char q = '\0';
    bool plain = false;
    for (size_t k = 0; k < n; k++) {
        if (q != '\'' && s[k] == '\\') {
            k++;
            continue;
        }
        if (q == '\0' && fxm_writes_at(s, k, n))
            return true;
        if (!plain)
            q = fxm_quote_after(s, k, n, q, &plain);
    }
    return false;
}

/* The value of a != definition (a target-specific one too); NULL for any
 * other line. */
static const char *fxm_bang_value(const struct fxm_line *l)
{
    size_t colon = 0;
    enum fxm_kind kind;
    const char *at, *eq;
    if (l->ctx != FXM_DEF || l->body)
        return NULL;
    kind = fxm_kind_of(l->raw, &colon);
    if (kind != FXM_K_DEF && kind != FXM_K_TSV)
        return NULL;
    at = fxm_skip_prefixes(l->raw + (kind == FXM_K_TSV ? colon + 1 : 0));
    eq = fxm_top(at, "=");
    return eq != NULL && eq > at && eq[-1] == '!' ? eq + 1 : NULL;
}

enum { FXM_FN_OTHER, FXM_FN_SHELL, FXM_FN_FILE, FXM_FN_EVAL, FXM_FN_ANY };

/* The function name at p (past "call" and its blanks when called):
 * shell, file or eval, and where its arguments start. */
static int fxm_fn_named(const char *p, bool called, const char **arg)
{
    static const struct {
        const char *name;
        int fn;
    } fns[] = {{"shell", FXM_FN_SHELL}, {"file", FXM_FN_FILE}, {"eval", FXM_FN_EVAL}};
    for (size_t k = 0; k < sizeof(fns) / sizeof(*fns); k++) {
        size_t n = strlen(fns[k].name);
        bool comma = called && strncmp(p, fns[k].name, n) == 0 && p[n] == ',';
        if (!comma && !fxm_starts_word(p, fns[k].name))
            continue;
        for (p += n; fxm_space(*p); p++)
            ;
        if (called && *p != ',')
            return FXM_FN_OTHER;
        *arg = p + called;
        return fns[k].fn;
    }
    return FXM_FN_OTHER;
}

/* The function a reference at d runs as make expands it: $(shell X),
 * $(file X) or $(eval X), each also through $(call NAME,X), or any function
 * a $(call) whose name is computed in any part ($(call $(F),X),
 * $(call s$(H)ell,X)) or is call itself ($(call call,shell,X)) names
 * (FXM_FN_ANY). *arg is where X starts and *end the closing bracket (NULL:
 * none). */
/* The name a $(call) at name spells up to its top-level comma (*comma: the
 * comma, or the end) is computed in any part or is call itself: any
 * function may run. */
static bool fxm_call_any(const char *name, const char **comma)
{
    const char *p = name;
    int depth = 0;
    bool computed = false;
    for (; *p != '\0' && !(*p == ',' && depth == 0); p++) {
        computed |= *p == '$';
        depth += (*p == '(' || *p == '{') - (*p == ')' || *p == '}');
    }
    *comma = p;
    return computed || (p - name >= 4 && strncmp(name, "call", 4) == 0 &&
                        (name + 4 == p || fxm_space(name[4])));
}

static int fxm_fn_at(const char *d, const char **arg, const char **end)
{
    const char *p = d + 2, *comma;
    if (d[1] != '(' && d[1] != '{')
        return FXM_FN_OTHER;
    *end = fxm_ref_end((char *)d);
    if (!fxm_starts_word(p, "call"))
        return fxm_fn_named(p, false, arg);
    for (p += 4; fxm_space(*p); p++)
        ;
    if (!fxm_call_any(p, &comma))
        return fxm_fn_named(p, true, arg);
    *arg = *comma == ',' ? comma + 1 : comma;
    return FXM_FN_ANY;
}

/* The text of the call's argument: [arg, end), or to the end of the line
 * when the call has no end. */
static size_t fxm_arg_len(const char *arg, const char *end)
{
    return end != NULL ? (end > arg ? (size_t)(end - arg) : 0) : strlen(arg);
}

/* A call in s make runs as it expands it: a $(shell) whose command, as
 * written, writes a file, a $(file) that is not a read, or a function a
 * computed $(call) names. */
static bool fxm_writing_calls(const char *s)
{
    for (const char *d = strchr(s, '$'); d != NULL; d = strchr(d + 1, '$')) {
        const char *arg = NULL, *e = NULL, *a;
        int fn = fxm_fn_at(d, &arg, &e);
        if (fn == FXM_FN_ANY)
            return true;
        if (fn == FXM_FN_FILE) {
            for (a = arg; fxm_space(*a); a++)
                ;
            if (*a != '<')
                return true;
        } else if (fn == FXM_FN_SHELL &&
                   (e == NULL || fxm_redirects(arg, fxm_arg_len(arg, e)))) {
            return true;
        }
    }
    return false;
}

bool fxm_parse_writes(const struct fxm *m)
{
    for (size_t k = 0; k < m->nlines; k++) {
        const struct fxm_line *l = &m->lines[k];
        const char *v = fxm_bang_value(l);
        /* A recipe line, a define's too, runs as its rule does. */
        if (l->ctx == FXM_RECIPE || (l->body && l->raw[0] == '\t'))
            continue;
        if ((v != NULL && fxm_redirects(v, strlen(v))) || fxm_writing_calls(l->raw))
            return true;
    }
    return false;
}

/* s[0..n) holds one of names (the empty name is in any text). */
static bool fxm_holds(const char *s, size_t n, const struct fxc_strs *names)
{
    for (size_t k = 0; k < names->n; k++) {
        size_t w = strlen(names->v[k]);
        for (size_t i = 0; i + w <= n; i++)
            if (memcmp(s + i, names->v[k], w) == 0)
                return true;
    }
    return false;
}

/* A line make expands as it reads is not a recipe line (a define's too). */
static bool fxm_parse_line(const struct fxm_line *l)
{
    return l->ctx != FXM_RECIPE && !(l->body && l->raw[0] == '\t');
}

/* Line k of m->lines is read by make no later than root line `before`: a
 * root line at or above it, or any line of another makefile (read where
 * its include is, taken as any time). FXM_NONE: every line. */
static bool fxm_read_by(const struct fxm *m, size_t k, uint32_t before)
{
    return before == FXM_NONE || k >= m->root_lines || k <= before;
}

/* Add to names each variable a definition holding one of them sets, until
 * none is new; false when an $(eval) line or a computed name holds one (it
 * may set any variable) or the list cannot grow. Only lines make reads by
 * root line `before` count: a later definition gives no value to what
 * runs before it. */
static bool fxm_taint(const struct fxm *m, struct fxc_strs *names,
                      uint32_t before)
{
    bool grew = true;
    while (grew) {
        grew = false;
        for (size_t k = 0; k < m->nlines; k++) {
            const struct fxm_line *l = &m->lines[k];
            if (!fxm_read_by(m, k, before) ||
                !fxm_holds(l->raw, strlen(l->raw), names))
                continue;
            if (l->ctx != FXM_DEF) {
                if (strstr(l->raw, "eval") != NULL)
                    return false;
                continue;
            }
            if (fxc_strs_has(names, l->name))
                continue;
            if (l->name[0] == '\0' || !fxc_strs_add(names, l->name))
                return false;
            grew = true;
        }
    }
    return true;
}

/* The commands of line l make runs as it reads it (each $(shell) body, the
 * same through $(call), a computed $(call)'s arguments, a != value) hold
 * one of names; true too for such a call with no end. */
static bool fxm_line_runs(const struct fxm_line *l, const struct fxc_strs *names)
{
    const char *v = fxm_bang_value(l);
    if (v != NULL && fxm_holds(v, strlen(v), names))
        return true;
    for (const char *d = strchr(l->raw, '$'); d != NULL; d = strchr(d + 1, '$')) {
        const char *arg = NULL, *e = NULL;
        int fn = fxm_fn_at(d, &arg, &e);
        if (fn != FXM_FN_SHELL && fn != FXM_FN_ANY)
            continue;
        if (e == NULL || fxm_holds(arg, fxm_arg_len(arg, e), names))
            return true;
    }
    return false;
}

bool fxm_commands_name_by(const struct fxm *m, const char *name,
                          uint32_t before)
{
    struct fxc_strs names = {0};
    /* The empty name (a root directory) is in any command's text: no
     * variable needs following. */
    bool named = !fxc_strs_add(&names, name) ||
                 (name[0] != '\0' && !fxm_taint(m, &names, before));
    for (size_t k = 0; !named && k < m->nlines; k++)
        named = fxm_read_by(m, k, before) && fxm_parse_line(&m->lines[k]) &&
                fxm_line_runs(&m->lines[k], &names);
    fxc_strs_free(&names);
    return named;
}

bool fxm_commands_name(const struct fxm *m, const char *name)
{
    return fxm_commands_name_by(m, name, FXM_NONE);
}

/* s[0..n) holds name, or a variable whose definition does (transitively;
 * an $(eval) line or a computed name holding it counts). */
static bool fxm_text_names(const struct fxm *m, const char *s, size_t n,
                           const char *name)
{
    struct fxc_strs names = {0};
    bool named = !fxc_strs_add(&names, name) ||
                 !fxm_taint(m, &names, FXM_NONE) ||
                 fxm_holds(s, n, &names);
    fxc_strs_free(&names);
    return named;
}

/* A rule's target text as written, s[0..n), holds a function call ($(f x),
 * ${f,x}) or a reference whose name is computed or substituted: what make
 * makes of it is text the expansion does not follow. */
static bool fxm_calls_in(const char *s, size_t n)
{
    for (size_t k = 0; k + 1 < n; k++) {
        size_t j = k + 2;
        if (s[k] == '$' && s[k + 1] == '$') {
            k++;
            continue;
        }
        if (s[k] != '$' || (s[k + 1] != '(' && s[k + 1] != '{'))
            continue;
        while (j < n && fxm_ident(s[j]))
            j++;
        if (j < n && s[j] != ')' && s[j] != '}')
            return true;
    }
    return false;
}

/* The expansion t of a rule's targets holds a value no text spells. */
static bool fxm_marked(const char *t)
{
    return strpbrk(t, "\x01\x02\x03\x04\x05") != NULL;
}

/* A word of s[0..n) (split at blanks and , ( ) { } : ; = |) holding a %
 * matches path as a pattern; too long to test, it does. A lone % (the
 * common $(patsubst %,...) or -flag=% argument) counts only when bare. */
static bool fxm_pct_word(const char *s, size_t n, const char *path, bool bare)
{
    char w[ZCL_DEVLOOP_PATH_MAX];
    for (size_t k = 0, j; k < n; k = j + 1) {
        for (j = k; j < n && strchr(" \t,(){}:;=|", s[j]) == NULL; j++)
            ;
        if (memchr(s + k, '%', j - k) == NULL)
            continue;
        if (j - k >= sizeof(w))
            return true;
        memcpy(w, s + k, j - k);
        w[j - k] = '\0';
        if ((bare || strcmp(fxm_strip_dot(w), "%") != 0) &&
            fxm_glob(fxm_strip_dot(w), path))
            return true;
    }
    return false;
}

/* s[0..n) holds a % pattern matching path, or a variable whose definition
 * does (transitively, fxm_taint's reading): the common
 * OBJS := $(patsubst tools/%.in,build/%.mk,...) target list. */
static bool fxm_pct_names(const struct fxm *m, const char *s, size_t n,
                          const char *path)
{
    struct fxc_strs names = {0};
    bool named = fxm_pct_word(s, n, path, true);
    for (size_t k = 0; !named && k < m->nlines; k++) {
        const struct fxm_line *l = &m->lines[k];
        if (l->ctx == FXM_DEF &&
            fxm_pct_word(l->raw, strlen(l->raw), path, false))
            named = l->name[0] == '\0' || !fxc_strs_add(&names, l->name);
    }
    if (!named && names.n > 0)
        named = !fxm_taint(m, &names, FXM_NONE) || fxm_holds(s, n, &names);
    fxc_strs_free(&names);
    return named;
}

/* The end of a static rule's target pattern (targets: pattern: prereqs),
 * past a rule's targets raw[0..n); n when the rule has none. */
static size_t fxm_static_end(const struct fxm_line *l, size_t n)
{
    int depth = 0;
    size_t k = l->from;
    if (k == 0 || k > strlen(l->raw))
        return n;
    k += l->raw[k] == ':';
    for (; l->raw[k] != '\0' && l->raw[k] != ';'; k++) {
        depth += (l->raw[k] == '(' || l->raw[k] == '{') -
                 (l->raw[k] == ')' || l->raw[k] == '}');
        if (depth == 0 && l->raw[k] == '=')
            return n;
        if (depth == 0 && l->raw[k] == ':' && l->raw[k + 1] != '=')
            return k;
    }
    return n;
}

/* A computed rule's text names one of paths (the missing includes, or
 * the makefiles make reads): its targets raw[0..n) the path or basename,
 * directly or through a variable, or its targets with a static rule's
 * target pattern, raw[0..pn), a % pattern matching the path. */
static bool fxm_rule_names(const struct fxm *m, const struct fxm_line *l,
                           size_t n, size_t pn, const struct fxc_strs *paths)
{
    for (size_t k = 0; k < paths->n; k++) {
        const char *path = paths->v[k], *base = strrchr(path, '/');
        if (fxm_text_names(m, l->raw, n, path) ||
            fxm_text_names(m, l->raw, n, base != NULL ? base + 1 : path) ||
            fxm_pct_names(m, l->raw, pn, path))
            return true;
    }
    return false;
}

/* A rule make reads from text a function or a value no text spells
 * computes, raw[0..n) as written: UNKNOWN while it names a missing include
 * (fxm_rule_names); else counted under computed-targets-not-includes. */
static void fxm_computed_rule(struct fxm *m, const struct fxm_line *l,
                              size_t n, size_t pn)
{
    struct zcl_devloop_facts_plan_premise *p;
    if (fxm_rule_names(m, l, n, pn, &m->missing)) {
        m->unknown = true;
        return;
    }
    if (m->report == NULL)
        return;
    p = &m->report->make_premise;
    p->premises |= ZCL_DEVLOOP_PREMISE_COMPUTED_TARGETS_NOT_INCLUDES;
    if (p->include[0] == '\0') {
        (void)snprintf(p->include, sizeof(p->include), "%s", m->missing.v[0]);
        p->nincludes = m->missing.n;
    }
    if (p->ntargets++ > 0)
        return;
    (void)snprintf(p->target, sizeof(p->target), "%.*s", (int)n, l->raw);
    (void)snprintf(p->target_at, sizeof(p->target_at), "%s:%u",
                   l->file < m->files.n ? m->files.v[l->file] : "?", l->at);
}

void fxm_target_computed(struct fxm *m, const struct fxm_line *l, size_t n,
                         const char *t)
{
    if (fxm_calls_in(l->raw, n) || fxm_marked(t))
        fxm_computed_rule(m, l, n, fxm_static_end(l, n));
}

/* A line make reads as neither a definition, a directive nor a rule its
 * text spells, that holds a reference: what the reference expands to (a
 * variable holding "x:", a $(call), $(foreach) or $(if) that spells a rule,
 * an $(eval)) may be a rule. An $(error), $(warning) or $(info) alone
 * expands to nothing. */
static bool fxm_ref_line(const char *raw)
{
    static const char *const directives[] = {
        "include", "-include", "sinclude", "export", "unexport", "vpath",
        "undefine", "define", "endef", "override", "private", "ifeq", "ifneq",
        "ifdef", "ifndef", "else", "endif"};
    static const char *const quiet[] = {"$(error ", "$(warning ", "$(info "};
    const char *p = raw, *end;
    while (fxm_space(*p))
        p++;
    if (strchr(p, '$') == NULL)
        return false;
    for (size_t k = 0; k < sizeof(directives) / sizeof(*directives); k++)
        if (fxm_starts_word(p, directives[k]))
            return false;
    for (size_t k = 0; k < sizeof(quiet) / sizeof(*quiet); k++) {
        if (strncmp(p, quiet[k], strlen(quiet[k])) != 0)
            continue;
        for (end = fxm_ref_end((char *)p); end != NULL && fxm_space(end[1]);)
            end++;
        if (end != NULL && end[1] == '\0')
            return false;
    }
    return true;
}

void fxm_line_computed(struct fxm *m, const struct fxm_line *l)
{
    size_t n = strlen(l->raw);
    if (l->ctx != FXM_ACTIVE || l->body || !fxm_ref_line(l->raw))
        return;
    while (n > 0 && fxm_space(l->raw[n - 1]))
        n--;
    fxm_computed_rule(m, l, n, n);
}

bool fxm_computed_names(const struct fxm *m, const struct fxm_line *l,
                        size_t n, const char *t, const struct fxc_strs *paths)
{
    if (t != NULL)
        return (fxm_calls_in(l->raw, n) || fxm_marked(t)) &&
               fxm_rule_names(m, l, n, fxm_static_end(l, n), paths);
    n = strlen(l->raw);
    if (l->ctx != FXM_ACTIVE || l->body || !fxm_ref_line(l->raw))
        return false;
    while (n > 0 && fxm_space(l->raw[n - 1]))
        n--;
    return fxm_rule_names(m, l, n, n, paths);
}

/* A target word that makes any file: match-anything (%) or .DEFAULT. */
static bool fxm_makes_anything(const char *t)
{
    while (*t != '\0') {
        size_t n = 0;
        while (fxm_space(*t))
            t++;
        while (t[n] != '\0' && !fxm_space(t[n]))
            n++;
        if ((n == 1 && t[0] == '%') || (n == 8 && strncmp(t, ".DEFAULT", 8) == 0))
            return true;
        t += n;
    }
    return false;
}

/* A match-anything rule (%:) or .DEFAULT makes any file: every missing
 * optional include is made by a recipe no rule names it in. */
bool fxm_anything_made(const struct fxm *m)
{
    for (size_t r = 0; m->missing.n > 0 && r < m->nrules; r++)
        if (fxm_makes_anything(m->rules[r].targets))
            return true;
    return false;
}

/* Programs that write no file whatever their arguments. */
static const char *const fxm_readers[] = {
    "printf", "echo", "cat", "uname", "nproc", "pwd", "true", "false",
    "test", "basename", "dirname", "pkg-config"};

/* The command s[0..n) is provably read-only: one simple command of a
 * reader with no reference, substitution, quote, redirection, separator
 * or assignment make or the shell could turn into another command. */
static bool fxm_read_only(const char *s, size_t n)
{
    size_t w;
    while (n > 0 && fxm_space(*s))
        s++, n--;
    for (size_t k = 0; k < n; k++)
        if (strchr(";&|`$()<>{}\\\n'\"=*?[~#", s[k]) != NULL)
            return false;
    for (w = 0; w < n && !fxm_space(s[w]);)
        w++;
    for (size_t k = 0; k < sizeof(fxm_readers) / sizeof(*fxm_readers); k++)
        if (strlen(fxm_readers[k]) == w && memcmp(fxm_readers[k], s, w) == 0)
            return true;
    return false;
}

/* Note the command s[0..n) of line l when it is not provably read-only
 * (never, with any). */
static void fxm_unproven_add(const struct fxm *m, const struct fxm_line *l,
                             const char *s, size_t n, bool any,
                             struct zcl_devloop_facts_plan_premise *p)
{
    if (!any && fxm_read_only(s, n))
        return;
    if (p->ncommands++ > 0)
        return;
    while (n > 0 && fxm_space(*s))
        s++, n--;
    (void)snprintf(p->command, sizeof(p->command), "%.*s", (int)n, s);
    (void)snprintf(p->command_at, sizeof(p->command_at), "%s:%u",
                   l->file < m->files.n ? m->files.v[l->file] : "?", l->at);
}

/* Line text s holds the word export (export X, a bare export, a
 * target-specific one) or .EXPORT_ALL_VARIABLES. */
static bool fxm_exports(const char *s)
{
    for (const char *e = strstr(s, "export"); e != NULL; e = strstr(e + 1, "export"))
        if ((e == s || !fxm_ident(e[-1])) && !fxm_ident(e[6]))
            return true;
    return strstr(s, ".EXPORT_ALL_VARIABLES") != NULL;
}

/* A line assigns SHELL, .SHELLFLAGS or PATH (or a name it computes, or an
 * $(eval) may), or exports a variable (GNU make passes exported variables
 * to $(shell), LD_PRELOAD among them): no command make runs is then
 * provably read-only. */
static bool fxm_shell_set(const struct fxm *m)
{
    static const char *const names[] = {"SHELL", ".SHELLFLAGS", "PATH"};
    for (size_t k = 0; k < m->nlines; k++) {
        const struct fxm_line *l = &m->lines[k];
        if (!fxm_parse_line(l))
            continue;
        if ((l->ctx == FXM_DEF && l->name[0] == '\0') || fxm_exports(l->raw))
            return true;
        for (size_t j = 0; j < sizeof(names) / sizeof(*names); j++)
            if ((l->ctx == FXM_DEF && strcmp(l->name, names[j]) == 0) ||
                (strstr(l->raw, "eval") != NULL && strstr(l->raw, names[j]) != NULL))
                return true;
    }
    return false;
}

/* Note each command of line l make runs as it reads it that is not
 * provably read-only: a $(shell) body (or one through $(call)), a !=
 * value, a computed $(call)'s arguments, an $(eval) of text a reference
 * or $$( computes. */
static void fxm_line_unproven(const struct fxm *m, const struct fxm_line *l,
                              bool any, struct zcl_devloop_facts_plan_premise *p)
{
    const char *v = fxm_bang_value(l);
    if (v != NULL)
        fxm_unproven_add(m, l, v, strlen(v), any, p);
    for (const char *d = strchr(l->raw, '$'); d != NULL; d = strchr(d + 1, '$')) {
        const char *arg = NULL, *e = NULL;
        int fn = fxm_fn_at(d, &arg, &e);
        size_t n = arg != NULL ? fxm_arg_len(arg, e) : 0;
        if (fn == FXM_FN_EVAL && memchr(arg, '$', n) != NULL)
            fxm_unproven_add(m, l, arg, n, true, p);
        else if (fn == FXM_FN_SHELL || fn == FXM_FN_ANY)
            fxm_unproven_add(m, l, arg, n, any || fn == FXM_FN_ANY, p);
    }
}

void fxm_parse_unproven(const struct fxm *m,
                        struct zcl_devloop_facts_plan_premise *p)
{
    bool any = fxm_shell_set(m);
    for (size_t k = 0; k < m->nlines; k++)
        if (fxm_parse_line(&m->lines[k]))
            fxm_line_unproven(m, &m->lines[k], any, p);
}
