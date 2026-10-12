/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The facts consumer's guard reading, values: what a text of the root makefile may expand to at one of its lines, as a bounded set of alternatives or any text, globbing the tree the plan reads. */
#include "devloop_facts_make_guard.h"

#include "util/safe_alloc.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *const fxg_repair_goals[] = {"vendor-ready", "deploy",
                                               "install"};

/* ---- the value domain ---- */

static const char *fxg_dup(struct fxg *g, const char *s, size_t n)
{
    char *p;
    if (n >= FXG_TEXT || n + 1 > FXG_ARENA - g->used)
        return NULL;
    p = g->arena + g->used;
    g->used += n + 1;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static void fxg_any(struct fxg_val *v)
{
    v->n = 0;
    v->any = true;
}

static void fxg_push(struct fxg *g, struct fxg_val *v, const char *s, size_t n)
{
    const char *d;
    if (v->any)
        return;
    for (size_t k = 0; k < v->n; k++)
        if (strlen(v->alt[k]) == n && memcmp(v->alt[k], s, n) == 0)
            return;
    if (v->n == FXG_ALTS || (d = fxg_dup(g, s, n)) == NULL) {
        fxg_any(v);
        return;
    }
    v->alt[v->n++] = d;
}

static void fxg_one(struct fxg *g, struct fxg_val *v, const char *s)
{
    v->n = 0;
    v->any = false;
    fxg_push(g, v, s, strlen(s));
}

static void fxg_union(struct fxg *g, struct fxg_val *v, const struct fxg_val *w)
{
    if (w->any)
        fxg_any(v);
    for (size_t k = 0; !v->any && k < w->n; k++)
        fxg_push(g, v, w->alt[k], strlen(w->alt[k]));
}

/* Every alternative is the empty text. */
bool fxg_empty(const struct fxg_val *v)
{
    for (size_t k = 0; !v->any && k < v->n; k++)
        if (v->alt[k][0] != '\0')
            return false;
    return !v->any;
}

bool fxg_blank(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n';
}

/* The goals marker stands for whole words only: glued to other text it
 * is a word no reading knows. */
static bool fxg_glued(const char *s)
{
    for (const char *p = strchr(s, FXG_GOAL); p != NULL;
         p = strchr(p + 1, FXG_GOAL))
        if ((p > s && !fxg_blank(p[-1])) ||
            (p[1] != '\0' && !fxg_blank(p[1])))
            return true;
    return false;
}

/* v's alternatives, each followed by each of w's. */
static void fxg_cat(struct fxg *g, struct fxg_val *v, const struct fxg_val *w)
{
    struct fxg_val r = {.n = 0};
    char *buf = g->arena + g->used;
    if (v->any || w->any) {
        fxg_any(v);
        return;
    }
    for (size_t a = 0; !r.any && a < v->n; a++)
        for (size_t b = 0; !r.any && b < w->n; b++) {
            size_t x = strlen(v->alt[a]), y = strlen(w->alt[b]);
            if (x + y >= FXG_TEXT || x + y + 1 > FXG_ARENA - g->used) {
                fxg_any(&r);
                break;
            }
            memcpy(buf, v->alt[a], x);
            memcpy(buf + x, w->alt[b], y);
            buf[x + y] = '\0';
            if (fxg_glued(buf))
                fxg_any(&r);
            else
                fxg_push(g, &r, buf, x + y);
            buf = g->arena + g->used;
        }
    *v = r;
}

static void fxg_cat_text(struct fxg *g, struct fxg_val *v, const char *s,
                         size_t n)
{
    struct fxg_val w = {.n = 0};
    fxg_push(g, &w, s, n);
    fxg_cat(g, v, &w);
}


bool fxg_patterned(const struct fxg *g, const char *name)
{
    for (size_t k = 0; k < g->npats; k++)
        if (fxm_glob(g->pats[k], name))
            return true;
    return g->open_all;
}


/* The end of the reference whose bracket is s[k]: its closing bracket, or
 * n for none. */
size_t fxg_close(const char *s, size_t k, size_t n)
{
    char o = s[k], c = o == '(' ? ')' : '}';
    int depth = 0;
    for (; k < n; k++) {
        depth += (s[k] == o) - (s[k] == c);
        if (depth == 0)
            return k;
    }
    return n;
}

/* ---- expansion ---- */


/* One directive of the walk fxg_assigned makes: the new depth, -1 for a
 * conditional the reading cannot follow. */
static int fxg_step(uint8_t c, int d, bool *cur, bool *all, bool *plain)
{
    if (c == FXG_C_IF) {
        if (d == FXM_COND_MAX)
            return -1;
        d++;
        cur[d] = plain[d] = false;
        all[d] = true;
        return d;
    }
    if (c == FXG_C_NONE)
        return d;
    if (d == 0)
        return -1;
    all[d] = all[d] && cur[d];
    cur[d] = false;
    if (c != FXG_C_ENDIF) {
        plain[d] = c == FXG_C_ELSE;
        return d;
    }
    cur[d - 1] = cur[d - 1] || (all[d] && plain[d]);
    return d - 1;
}

/* A site in [lo, hi) runs before root line t on every path to it: at the
 * top level, or in every branch of a chain that ends in a plain else. */
static bool fxg_assigned(const struct fxg *g, size_t lo, size_t hi, uint32_t t)
{
    bool cur[FXM_COND_MAX + 1] = {false}, all[FXM_COND_MAX + 1];
    bool plain[FXM_COND_MAX + 1];
    int d = 0;
    for (uint32_t k = 0; k < t && d >= 0; k++) {
        d = fxg_step(g->cls[k], d, cur, all, plain);
        if (d >= 0 && g->site_at[k] >= lo && g->site_at[k] < hi)
            cur[d] = true;
    }
    while (d >= 0 && !cur[d])
        d--;
    return d >= 0;
}

/* The variables the premise host-target-default-tor names. */
static bool fxg_default_premised(const char *name)
{
    return strcmp(name, "ZCL_TARGET") == 0 || strcmp(name, "ZCL_TOR") == 0;
}

/* A variable host-target-default-tor names whose one site is a ?= line
 * make surely reads before root line t: the value that line gives (make
 * expands it where it is used, as for =). */
static bool fxg_default(struct fxg *g, const char *name, size_t lo, size_t hi,
                        uint32_t t, int depth, struct fxg_val *out)
{
    const struct fxg_site *s = &g->sites[lo];
    if (!fxg_default_premised(name) || hi != lo + 1 || s->op != FXG_DEFAULT ||
        s->line >= t || !fxg_assigned(g, lo, hi, t))
        return false;
    fxg_text(g, s->value, s->vlen, t, depth + 1, out);
    if (!out->any)
        g->rec.premises |= ZCL_DEVLOOP_PREMISE_HOST_TARGET_DEFAULT_TOR;
    return true;
}

/* The union of the values of sites [lo, hi) before root line t (each := at
 * its own line, each = at t), but for a site in a branch make provably does
 * not take (fxg_dead). */
static void fxg_sites_union(struct fxg *g, size_t lo, size_t hi, uint32_t t,
                            int depth, struct fxg_val *out)
{
    out->n = 0;
    out->any = false;
    for (size_t k = lo; k < hi && !out->any && g->sites[k].line < t; k++) {
        const struct fxg_site *s = &g->sites[k];
        struct fxg_val v;
        if (fxg_dead(g, s->line, depth))
            continue;
        fxg_text(g, s->value, s->vlen, s->op == FXG_SET ? s->line : t,
                 depth + 1, &v);
        fxg_union(g, out, &v);
    }
    if (out->n == 0)
        fxg_any(out); /* every site pruned: a line make never reaches */
}

/* The value of the variable name at root line t. */
static void fxg_var(struct fxg *g, const char *name, uint32_t t, int depth,
                    struct fxg_val *out)
{
    size_t lo, hi;
    fxg_range(g, name, &lo, &hi);
    fxg_any(out);
    if (fxg_patterned(g, name))
        return;
    if (lo == hi && strcmp(name, "MAKECMDGOALS") == 0) {
        char goal[2] = {FXG_GOAL, '\0'};
        fxg_one(g, out, goal);
        return;
    }
    if (lo < hi && fxg_default(g, name, lo, hi, t, depth, out))
        return;
    for (size_t k = lo; k < hi; k++)
        if (g->sites[k].op != FXG_SET && g->sites[k].op != FXG_LAZY)
            return;
    if (lo < hi && fxg_assigned(g, lo, hi, t))
        fxg_sites_union(g, lo, hi, t, depth, out);
}

/* A reference whose text is not a call: a variable, maybe computed. */
static void fxg_ref_var(struct fxg *g, const char *s, size_t n, uint32_t t,
                        int depth, struct fxg_val *out)
{
    struct fxg_val names, v;
    struct fxg_val acc = {.n = 0};
    if (fxm_subst_colon(s, n) < n) {
        fxg_any(out);
        return;
    }
    fxg_text(g, s, n, t, depth, &names);
    if (names.any)
        acc.any = true;
    for (size_t k = 0; !acc.any && k < names.n; k++) {
        const char *nm = names.alt[k];
        if (nm[0] == '\0' || strpbrk(nm, " \t\n\x06\x07") != NULL) {
            fxg_any(&acc);
            break;
        }
        fxg_var(g, nm, t, depth, &v);
        fxg_union(g, &acc, &v);
    }
    *out = acc;
}

/* ---- $(wildcard): the tree the plan reads ---- */

struct fxg_found {
    char words[FXG_TEXT]; /* what the glob found, space-separated */
    size_t n, count;
    bool full;
};

/* ch is in the bracket class c[0..e) (past its '[' and any '!' or '^'). */
static bool fxg_class(const char *c, const char *e, char ch)
{
    for (; c < e; c++) {
        if (c + 2 < e && c[1] == '-') {
            if (ch >= c[0] && ch <= c[2])
                return true;
            c += 2;
        } else if (ch == *c) {
            return true;
        }
    }
    return false;
}

/* A pattern character of a glob component: FXG_EPOCH any run too. */
static bool fxg_match(const char *p, const char *s)
{
    const char *e;
    bool neg;
    if (*p == '\0')
        return *s == '\0';
    if (*p == '*' || *p == FXG_EPOCH)
        return fxg_match(p + 1, s) || (*s != '\0' && fxg_match(p, s + 1));
    if (*s == '\0')
        return false;
    if (*p != '[' || (e = strchr(p + 1, ']')) == NULL)
        return (*p == '?' || *p == *s) && fxg_match(p + 1, s + 1);
    neg = p[1] == '!' || p[1] == '^';
    return fxg_class(p + 1 + neg, e, *s) != neg && fxg_match(e + 1, s + 1);
}

static void fxg_found_add(struct fxg_found *f, const char *path)
{
    size_t n = strlen(path);
    if (f->count == FXG_MATCHES || f->n + n + 2 > sizeof(f->words)) {
        f->full = true;
        return;
    }
    if (f->n > 0)
        f->words[f->n++] = ' ';
    memcpy(f->words + f->n, path, n + 1);
    f->n += n;
    f->count++;
}

static void fxg_walk(const char *root, char *path, size_t len,
                     const char *rest, struct fxg_found *f);

/* The next component of rest into path[len..]; false when it does not fit. */
static bool fxg_join(char *path, size_t len, const char *c, size_t n)
{
    if (len + n + 2 > ZCL_DEVLOOP_PATH_MAX)
        return false;
    if (len > 0)
        path[len++] = '/';
    memcpy(path + len, c, n);
    path[len + n] = '\0';
    return true;
}

/* make's glob: a name that starts with '.' (".", ".." too) matches only a
 * component spelled with a leading '.'; the epoch stands for any name but
 * "." and "..". */
static bool fxg_hidden_skip(const char *c, const char *name)
{
    if (c[0] == FXG_EPOCH)
        return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
    return name[0] == '.' && c[0] != '.';
}

/* Every entry of the directory path[0..len) the component c matches. */
static void fxg_list(const char *root, char *path, size_t len, const char *c,
                     const char *next, struct fxg_found *f)
{
    char dir[ZCL_DEVLOOP_PATH_MAX * 2];
    struct dirent *de;
    DIR *d;
    if (snprintf(dir, sizeof(dir), "%s/%s", root, len ? path : ".") >=
        (int)sizeof(dir))
        f->full = true;
    if (f->full || (d = opendir(dir)) == NULL)
        return;
    while (!f->full && (de = readdir(d)) != NULL) {
        size_t n = strlen(de->d_name);
        if (fxg_hidden_skip(c, de->d_name) || !fxg_match(c, de->d_name))
            continue;
        if (!fxg_join(path, len, de->d_name, n))
            f->full = true;
        else
            fxg_walk(root, path, len + (len > 0) + n, next, f);
        path[len] = '\0';
    }
    (void)closedir(d);
}

/* Glob rest under path[0..len): components with no pattern are joined,
 * a pattern lists its directory, the epoch alone also stands for none. */
static void fxg_walk(const char *root, char *path, size_t len,
                     const char *rest, struct fxg_found *f)
{
    char full[ZCL_DEVLOOP_PATH_MAX * 2], comp[ZCL_DEVLOOP_PATH_MAX];
#if !defined(_WIN32)
    struct stat st;
#endif
    size_t n;
    while (*rest == '/')
        rest++;
    if (*rest == '\0') {
        if (snprintf(full, sizeof(full), "%s/%s", root, path) >= (int)sizeof(full))
            f->full = true;
        else if (len > 0) {
#if defined(_WIN32)
            /* No no-follow stat is available here; an unobserved link
             * must leave early reuse unvouched. */
            f->full = true;
#else
            if (lstat(full, &st) == 0)
                fxg_found_add(f, path);
#endif
        }
        return;
    }
    n = strcspn(rest, "/");
    if (n >= sizeof(comp)) {
        f->full = true;
        return;
    }
    memcpy(comp, rest, n);
    comp[n] = '\0';
    if (strcmp(comp, (char[]){FXG_EPOCH, '\0'}) == 0)
        fxg_walk(root, path, len, rest + n, f);
    if (strpbrk(comp, "*?[\x07") != NULL)
        fxg_list(root, path, len, comp, rest + n, f);
    else if (!fxg_join(path, len, comp, n))
        f->full = true;
    else
        fxg_walk(root, path, len + (len > 0) + n, rest + n, f);
    path[len] = '\0';
}

/* Note a path the reading globbed and what it found; a reading whose
 * record would not fit is not used. */
static void fxg_record(struct fxg *g, const char *word, const char *found)
{
    struct zcl_devloop_facts_guard *r = &g->rec;
    char *o;
    size_t k = 0;
    if (r->nglobs == ZCL_DEVLOOP_GUARD_GLOBS ||
        strlen(found) >= sizeof(r->found[0])) {
        g->rec_full = true;
        return;
    }
    o = r->glob[r->nglobs];
    for (; *word != '\0' && k + 8 < sizeof(r->glob[0]); word++)
        if (*word == FXG_EPOCH) {
            memcpy(o + k, "{epoch}", 7);
            k += 7;
        } else {
            o[k++] = *word;
        }
    o[k] = '\0';
    g->rec_full |= *word != '\0';
    memcpy(r->found[r->nglobs++], found, strlen(found) + 1);
}

/* One word of $(wildcard): what it finds under the root; false when the
 * reading cannot glob it (outside the tree, a goal, too many). */
static bool fxg_glob_word(struct fxg *g, const char *w, struct fxg_found *f)
{
    char path[ZCL_DEVLOOP_PATH_MAX] = "";
    f->n = f->count = 0;
    f->full = false;
    f->words[0] = '\0';
    if (*w == '/' || *w == '~' || strstr(w, "..") != NULL ||
        strpbrk(w, "\\\x06") != NULL)
        return false;
    fxg_walk(g->m->root, path, 0, w, f);
    if (!f->full)
        fxg_record(g, w, f->words);
    return !f->full;
}

/* Each word of text, one at a time: its start and length. */
static const char *fxg_word(const char **s, size_t *n)
{
    const char *w;
    while (fxg_blank(**s))
        (*s)++;
    w = *s;
    while (**s != '\0' && !fxg_blank(**s))
        (*s)++;
    *n = (size_t)(*s - w);
    return *n > 0 ? w : NULL;
}

/* $(wildcard): the empty text when no word finds anything; otherwise any
 * text, since what make spells for a match (its order, a trailing '/', a
 * doubled '/') is not read here. */
static void fxg_wildcard(struct fxg *g, struct fxg_val *v)
{
    struct fxg_val r = {.n = 0};
    struct fxg_found *f = zcl_malloc(sizeof(*f), "facts_consumer.mkgfound");
    char w[ZCL_DEVLOOP_PATH_MAX];
    if (f == NULL || v->any)
        r.any = true;
    for (size_t a = 0; !r.any && a < v->n; a++) {
        const char *s = v->alt[a], *p;
        size_t n;
        while (!r.any && (p = fxg_word(&s, &n)) != NULL) {
            memcpy(w, p, n < sizeof(w) ? n : 0);
            w[n < sizeof(w) ? n : 0] = '\0';
            r.any = n >= sizeof(w) || !fxg_glob_word(g, w, f) || f->n > 0;
        }
    }
    if (!r.any)
        fxg_push(g, &r, "", 0);
    free(f);
    *v = r;
}

/* ---- functions ---- */

/* Split the arguments of a call s[0..n) (past its name): at most max, the
 * last taking the rest. */
static size_t fxg_args(const char *s, size_t n, size_t max,
                       const char *arg[FXG_ARGS], size_t len[FXG_ARGS])
{
    size_t count = 0, k = 0, from = 0;
    int depth = 0;
    for (; k < n && count + 1 < max; k++) {
        depth += (s[k] == '(' || s[k] == '{') - (s[k] == ')' || s[k] == '}');
        if (s[k] == ',' && depth == 0) {
            arg[count] = s + from;
            len[count++] = k - from;
            from = k + 1;
        }
    }
    arg[count] = s + from;
    len[count++] = n - from;
    return count;
}

static void fxg_trim(const char **s, size_t *n)
{
    while (*n > 0 && fxg_blank(**s))
        (*s)++, (*n)--;
    while (*n > 0 && fxg_blank((*s)[*n - 1]))
        (*n)--;
}

static void fxg_strip(struct fxg *g, struct fxg_val *v)
{
    struct fxg_val r = {.n = 0};
    char buf[FXG_TEXT];
    if (v->any)
        return;
    for (size_t a = 0; a < v->n; a++) {
        const char *s = v->alt[a], *w;
        size_t n, out = 0;
        while ((w = fxg_word(&s, &n)) != NULL) {
            if (out > 0)
                buf[out++] = ' ';
            memcpy(buf + out, w, n);
            out += n;
        }
        fxg_push(g, &r, buf, out);
    }
    *v = r;
}

/* A make pattern (one '%') matches the word w[0..n). */
static bool fxg_pattern(const char *p, size_t pn, const char *w, size_t n)
{
    const char *pct = memchr(p, '%', pn);
    size_t pre, post;
    if (pct == NULL)
        return pn == n && memcmp(p, w, n) == 0;
    pre = (size_t)(pct - p);
    post = pn - pre - 1;
    return n >= pre + post && memcmp(p, w, pre) == 0 &&
           memcmp(pct + 1, w + n - post, post) == 0;
}

/* The goals word may match patterns: not when each is a goal the premise
 * no-repair-goal rules out. */
static bool fxg_goal_may(struct fxg *g, const char *pats)
{
    const char *s = pats, *p;
    size_t n;
    bool may = false;
    while (!may && (p = fxg_word(&s, &n)) != NULL) {
        bool repair = false;
        for (size_t k = 0; k < sizeof(fxg_repair_goals) / sizeof(*fxg_repair_goals); k++)
            repair = repair || (strlen(fxg_repair_goals[k]) == n &&
                                memcmp(fxg_repair_goals[k], p, n) == 0);
        may = !repair;
    }
    if (!may)
        g->rec.premises |= ZCL_DEVLOOP_PREMISE_NO_REPAIR_GOAL;
    return may;
}

/* w[0..n) holds the goals or the epoch: a word no text spells. */
static bool fxg_marked(const char *w, size_t n)
{
    return memchr(w, FXG_GOAL, n) != NULL || memchr(w, FXG_EPOCH, n) != NULL;
}

enum { FXG_MISS, FXG_MATCH, FXG_UNSURE };

/* What the patterns provably do to the word w[0..n): match it, miss it, or
 * neither (a marker on either side, a '\' escape the reading does not
 * follow). */
static int fxg_matches(struct fxg *g, const char *pats, const char *w, size_t n)
{
    const char *s = pats, *p;
    size_t pn;
    if (n == 1 && *w == FXG_GOAL)
        return fxg_goal_may(g, pats) ? FXG_UNSURE : FXG_MISS;
    if (fxg_marked(w, n) ||
        strpbrk(pats, "\\\x06\x07") != NULL)
        return FXG_UNSURE;
    while ((p = fxg_word(&s, &pn)) != NULL)
        if (fxg_pattern(p, pn, w, n))
            return FXG_MATCH;
    return FXG_MISS;
}

/* The words of s that $(filter) (out false) or $(filter-out) (out true)
 * keeps, into buf; false when one is neither provably kept nor dropped. A
 * word holding a marker is kept as the word it stands for. */
static bool fxg_filter_words(struct fxg *g, const char *pats, const char *s,
                             bool out, char *buf, size_t *len)
{
    const char *w;
    size_t n;
    *len = 0;
    while ((w = fxg_word(&s, &n)) != NULL) {
        int m = fxg_matches(g, pats, w, n);
        bool marked = fxg_marked(w, n);
        if (m == FXG_UNSURE && !marked)
            return false;
        if (m != FXG_UNSURE && (m == FXG_MATCH) == out)
            continue;
        if (*len > 0)
            buf[(*len)++] = ' ';
        memcpy(buf + *len, w, n);
        *len += n;
    }
    return true;
}

/* $(filter P,T) or $(filter-out P,T) of v, with P's alternatives pats. */
static void fxg_filter(struct fxg *g, const struct fxg_val *pats, bool out,
                       struct fxg_val *v)
{
    struct fxg_val r = {.n = 0};
    char buf[FXG_TEXT];
    size_t len;
    if (v->any || pats->any) {
        fxg_any(v);
        return;
    }
    for (size_t a = 0; a < pats->n && !r.any; a++)
        for (size_t b = 0; b < v->n && !r.any; b++)
            if (fxg_filter_words(g, pats->alt[a], v->alt[b], out, buf, &len))
                fxg_push(g, &r, buf, len);
            else
                fxg_any(&r);
    *v = r;
}

/* The literal word w names a file make's $(wildcard) finds (recorded). */
static bool fxg_there(struct fxg *g, const char *w)
{
    char full[ZCL_DEVLOOP_PATH_MAX * 2];
    struct stat st;
    bool there = strpbrk(w, "*?[\\\x06\x07") == NULL && *w != '/' &&
                 *w != '~' && strstr(w, "..") == NULL &&
                 snprintf(full, sizeof(full), "%s/%s", g->m->root, w) <
                     (int)sizeof(full) &&
                 stat(full, &st) == 0;
    fxg_record(g, w, there ? w : "");
    return there;
}

/* The words of s no file answers for, into buf; false when they do not
 * fit. */
static bool fxg_missing_words(struct fxg *g, const char *s, char *buf,
                              size_t cap, size_t *out)
{
    char w[ZCL_DEVLOOP_PATH_MAX];
    const char *p;
    size_t n;
    *out = 0;
    while ((p = fxg_word(&s, &n)) != NULL) {
        if (n >= sizeof(w) || *out + n + 2 > cap)
            return false;
        memcpy(w, p, n);
        w[n] = '\0';
        if (fxg_there(g, w))
            continue;
        if (*out > 0)
            buf[(*out)++] = ' ';
        memcpy(buf + *out, w, n + 1);
        *out += n;
    }
    return true;
}

/* $(filter-out $(wildcard X),X): X's words no file answers for. Another
 * $(filter-out) keeps at most its text's words. */
static void fxg_missing(struct fxg *g, struct fxg_val *v)
{
    struct fxg_val r = {.n = 0};
    char buf[FXG_TEXT];
    for (size_t a = 0; !v->any && !r.any && a < v->n; a++) {
        size_t out;
        if (fxg_missing_words(g, v->alt[a], buf, sizeof(buf), &out))
            fxg_push(g, &r, buf, out);
        else
            fxg_any(&r);
    }
    if (!v->any)
        *v = r;
}

static const char *fxg_last_slash(const char *w, size_t n)
{
    while (n > 0 && w[n - 1] != '/')
        n--;
    return n > 0 ? w + n - 1 : NULL;
}

/* Each word of s with the prefix or suffix x, or past its last '/'
 * (notdir), into buf; false when a word holds the goals or it does not
 * fit. */
static bool fxg_map_words(const char *s, const char *x, bool pre, bool notdir,
                          char *buf, size_t cap, size_t *out)
{
    const char *w;
    size_t n, xn = strlen(x);
    *out = 0;
    while ((w = fxg_word(&s, &n)) != NULL) {
        const char *slash = notdir ? fxg_last_slash(w, n) : NULL;
        if (slash != NULL) {
            n -= (size_t)(slash + 1 - w);
            w = slash + 1;
        }
        if (*out + n + xn + 2 > cap || memchr(w, FXG_GOAL, n) != NULL)
            return false;
        *out += (size_t)snprintf(buf + *out, cap - *out, "%s%s%.*s%s",
                                 *out ? " " : "", pre ? x : "", (int)n, w,
                                 pre ? "" : x);
    }
    return true;
}

/* Each word of v with the prefix or suffix fix (addprefix, addsuffix), or
 * past its last '/' (notdir: fix NULL). */
static void fxg_words_map(struct fxg *g, const struct fxg_val *fix, bool pre,
                          struct fxg_val *v)
{
    struct fxg_val r = {.n = 0};
    char buf[FXG_TEXT];
    bool notdir = fix == NULL;
    if (v->any || (fix != NULL && fix->any)) {
        fxg_any(v);
        return;
    }
    for (size_t a = 0; a < (notdir ? 1 : fix->n) && !r.any; a++)
        for (size_t b = 0; b < v->n && !r.any; b++) {
            size_t out;
            if (fxg_map_words(v->alt[b], notdir ? "" : fix->alt[a], pre,
                              notdir, buf, sizeof(buf), &out))
                fxg_push(g, &r, buf, out);
            else
                fxg_any(&r);
        }
    *v = r;
}

/* An argument's value (at root line t). */
static void fxg_arg(struct fxg *g, const char *s, size_t n, uint32_t t,
                    int depth, struct fxg_val *out)
{
    fxg_text(g, s, n, t, depth, out);
}

/* $(if C,A,B): C (its blanks stripped, as make does) provably empty
 * gives B alone; otherwise A or B. */
static void fxg_if(struct fxg *g, const char **arg, size_t *len, size_t n,
                   uint32_t t, int depth, struct fxg_val *out)
{
    struct fxg_val c, b;
    const char *cs = arg[0];
    size_t cn = len[0];
    fxg_trim(&cs, &cn);
    fxg_arg(g, cs, cn, t, depth, &c);
    if (n < 3)
        fxg_one(g, &b, "");
    else
        fxg_arg(g, arg[2], len[2], t, depth, &b);
    if (fxg_empty(&c)) {
        *out = b;
        return;
    }
    fxg_arg(g, arg[1], len[1], t, depth, out);
    fxg_union(g, out, &b);
}

/* $(and ...) is empty when any argument is; otherwise its last. $(or ...)
 * is one of its arguments. */
static void fxg_and_or(struct fxg *g, bool is_and, const char **arg, size_t *len,
                       size_t n, uint32_t t, int depth, struct fxg_val *out)
{
    struct fxg_val v;
    out->n = 0;
    out->any = false;
    for (size_t k = 0; k < n; k++) {
        fxg_arg(g, arg[k], len[k], t, depth, &v);
        if (is_and && fxg_empty(&v)) {
            fxg_one(g, out, "");
            return;
        }
        if (!is_and || k + 1 == n)
            fxg_union(g, out, &v);
    }
    if (is_and)
        fxg_push(g, out, "", 0);
}

/* $(filter-out A,B): A is $(wildcard X) of B's own text X (the missing-
 * files idiom), or the words of B no pattern of A provably matches. */
static void fxg_filter_out(struct fxg *g, const char **arg, size_t *len,
                           uint32_t t, int depth, struct fxg_val *out)
{
    const char *a = arg[0], *b = arg[1];
    size_t an = len[0], bn = len[1];
    struct fxg_val p;
    fxg_trim(&a, &an);
    fxg_trim(&b, &bn);
    fxg_arg(g, b, bn, t, depth, out);
    if (an > 11 && (strncmp(a, "$(wildcard", 10) == 0 ||
                    strncmp(a, "${wildcard", 10) == 0) &&
        fxg_close(a, 1, an) == an - 1) {
        const char *x = a + 11;
        size_t xn = an - 12;
        fxg_trim(&x, &xn);
        if (xn == bn && memcmp(x, b, bn) == 0) {
            fxg_missing(g, out);
            return;
        }
    }
    fxg_arg(g, a, an, t, depth, &p);
    fxg_filter(g, &p, true, out);
}

/* $(call zcl_compile_epoch,...): the premise epoch-one-component. Any
 * other call is any text. */
static void fxg_call_fn(struct fxg *g, const char **arg, size_t *len,
                        struct fxg_val *out)
{
    const char *name = arg[0];
    size_t n = len[0];
    char epoch[2] = {FXG_EPOCH, '\0'};
    fxg_trim(&name, &n);
    fxg_any(out);
    if (g->epoch_ok && n == 17 && strncmp(name, "zcl_compile_epoch", n) == 0) {
        fxg_one(g, out, epoch);
        g->rec.premises |= ZCL_DEVLOOP_PREMISE_EPOCH_ONE_COMPONENT;
    }
}

enum { FXG_F_STRIP, FXG_F_IF, FXG_F_AND, FXG_F_OR, FXG_F_FILTER,
       FXG_F_FILTER_OUT, FXG_F_WILDCARD, FXG_F_ADDPREFIX, FXG_F_ADDSUFFIX,
       FXG_F_NOTDIR, FXG_F_FINDSTRING, FXG_F_CALL, FXG_F_NONE };

static const struct {
    const char *name;
    size_t args; /* at most; 0 for any number */
} fxg_fns[] = {{"strip", 1},      {"if", 3},         {"and", 0},
               {"or", 0},         {"filter", 2},     {"filter-out", 2},
               {"wildcard", 1},   {"addprefix", 2},  {"addsuffix", 2},
               {"notdir", 1},     {"findstring", 2}, {"call", 0}};

static int fxg_fn(const char *s, size_t n)
{
    for (size_t k = 0; k < sizeof(fxg_fns) / sizeof(fxg_fns[0]); k++)
        if (strlen(fxg_fns[k].name) == n && memcmp(fxg_fns[k].name, s, n) == 0)
            return (int)k;
    return FXG_F_NONE;
}

/* The two-argument word functions. */
static void fxg_pair(struct fxg *g, int fn, const char **arg, size_t *len,
                     uint32_t t, int depth, struct fxg_val *out)
{
    struct fxg_val a;
    fxg_arg(g, arg[0], len[0], t, depth, &a);
    fxg_arg(g, arg[1], len[1], t, depth, out);
    if (fn == FXG_F_FILTER)
        fxg_filter(g, &a, false, out);
    else if (fn == FXG_F_FINDSTRING && !fxg_empty(out)) {
        *out = a;
        fxg_push(g, out, "", 0);
    } else if (fn != FXG_F_FINDSTRING)
        fxg_words_map(g, &a, fn == FXG_F_ADDPREFIX, out);
}

/* strip, wildcard, notdir: one argument, its commas its own. */
static void fxg_one_arg(struct fxg *g, int fn, const char *s, size_t n,
                        uint32_t t, int depth, struct fxg_val *out)
{
    fxg_arg(g, s, n, t, depth, out);
    if (fn == FXG_F_STRIP)
        fxg_strip(g, out);
    else if (fn == FXG_F_WILDCARD)
        fxg_wildcard(g, out);
    else if (fn == FXG_F_NOTDIR)
        fxg_words_map(g, NULL, false, out);
    else
        fxg_any(out);
}

static void fxg_call(struct fxg *g, int fn, const char *s, size_t n,
                     uint32_t t, int depth, struct fxg_val *out)
{
    const char *arg[FXG_ARGS];
    size_t len[FXG_ARGS];
    size_t max = fxg_fns[fn].args ? fxg_fns[fn].args : FXG_ARGS;
    size_t count = fxg_args(s, n, max, arg, len);
    if (count < 2 && fn != FXG_F_STRIP && fn != FXG_F_WILDCARD &&
        fn != FXG_F_NOTDIR && fn != FXG_F_AND && fn != FXG_F_OR) {
        fxg_any(out);
        return;
    }
    if (fn == FXG_F_IF)
        fxg_if(g, arg, len, count, t, depth, out);
    else if (fn == FXG_F_AND || fn == FXG_F_OR)
        fxg_and_or(g, fn == FXG_F_AND, arg, len, count, t, depth, out);
    else if (fn == FXG_F_FILTER_OUT)
        fxg_filter_out(g, arg, len, t, depth, out);
    else if (fn == FXG_F_CALL)
        fxg_call_fn(g, arg, len, out);
    else if (count == 2)
        fxg_pair(g, fn, arg, len, t, depth, out);
    else
        fxg_one_arg(g, fn, arg[0], len[0], t, depth, out);
}

/* The body s[0..n) of one reference: a call, or a variable. */
static void fxg_ref(struct fxg *g, const char *s, size_t n, uint32_t t,
                    int depth, struct fxg_val *out)
{
    size_t w = 0;
    int fn;
    while (w < n && !fxg_blank(s[w]) && s[w] != '$' && s[w] != ':')
        w++;
    if (w < n && fxg_blank(s[w])) {
        fn = fxg_fn(s, w);
        while (w < n && fxg_blank(s[w]))
            w++;
        if (fn == FXG_F_NONE)
            fxg_any(out);
        else
            fxg_call(g, fn, s + w, n - w, t, depth, out);
        return;
    }
    fxg_ref_var(g, s, n, t, depth, out);
}

/* s[0..n) expanded at root line t: literal text, $$, and references. */
void fxg_text(struct fxg *g, const char *s, size_t n, uint32_t t,
              int depth, struct fxg_val *out)
{
    size_t k = 0, lit = 0;
    fxg_one(g, out, "");
    if (depth > FXG_DEPTH)
        fxg_any(out);
    while (k < n && !out->any) {
        struct fxg_val r;
        size_t e;
        if (s[k] != '$') {
            k++;
            continue;
        }
        fxg_cat_text(g, out, s + lit, k - lit);
        if (k + 1 < n && s[k + 1] == '$') {
            fxg_cat_text(g, out, "$", 1);
            k += 2;
        } else if (k + 1 < n && (s[k + 1] == '(' || s[k + 1] == '{') &&
                   (e = fxg_close(s, k + 1, n)) < n) {
            fxg_ref(g, s + k + 2, e - k - 2, t, depth + 1, &r);
            fxg_cat(g, out, &r);
            k = e + 1;
        } else {
            fxg_any(out); /* $@, $X, an unclosed reference */
        }
        lit = k;
    }
    if (!out->any)
        fxg_cat_text(g, out, s + lit, n - lit);
}
