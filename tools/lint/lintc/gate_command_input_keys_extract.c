/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: what one C function body reads, for check-command-input-keys. A
 * key is read when a call names the input object (the member input, or a
 * local assigned from an expression naming it) as an argument followed by a
 * string literal; or when a const char *const array of literals is handed to
 * a call together with the input object. Every blank-separated word of every
 * string literal is kept as a weak signal, and every called name is kept so
 * the gate can follow calls across the indexed functions. A key named by a
 * runtime variable is invisible to this scan.
 */
#include <stdlib.h>
#include <string.h>
#include "gate_command_input_keys_priv.h"

struct cik_cur { const char *p, *end; bool done; };

static bool cik_cur_next(struct cik_cur *c, const char **s, size_t *n)
{
    const char *semi;
    if (c->done)
        return false;
    semi = memchr(c->p, ';', (size_t)(c->end - c->p));
    *s = c->p;
    *n = (size_t)((semi ? semi : c->end) - c->p);
    c->done = semi == NULL;
    c->p = semi ? semi + 1 : c->end;
    return true;
}

static bool cik_has_word(const char *s, size_t n, const char *w, size_t m)
{
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(s + i, w, m) == 0 && (i == 0 || !cik_isid(s[i - 1]))
            && (i + m == n || !cik_isid(s[i + m])))
            return true;
    return false;
}

static bool cik_has_text(const char *s, size_t n, const char *w)
{
    size_t m = strlen(w);
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(s + i, w, m) == 0)
            return true;
    return false;
}

/* Finds `ident [ ]* = c` with c not `=`; reports the identifier. */
static bool cik_find_assign(const char *s, size_t n, size_t *at, size_t *len)
{
    size_t i = 0, j, k;
    while (i < n) {
        if (!cik_isid_start(s[i])) {
            i++;
            continue;
        }
        for (j = i; j < n && cik_isid(s[j]); j++)
            ;
        for (k = j; k < n && s[k] == ' '; k++)
            ;
        if (k + 1 < n && s[k] == '=' && s[k + 1] != '=') {
            *at = i;
            *len = j - i;
            return true;
        }
        i = j;
    }
    return false;
}

static bool cik_iskey(const char *s, size_t n)
{
    if (n == 0 || n > 64 || s[0] < 'a' || s[0] > 'z')
        return false;
    for (size_t i = 1; i < n; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')
              || s[i] == '_' || s[i] == '-'))
            return false;
    return true;
}

static void cik_add_key(struct cik_index *x, struct cik_fn *fn,
                        const char *s, size_t n)
{
    if (cik_iskey(s, n))
        cik_set_add(&fn->keys, cik_intern(&x->dict, s, n));
}

/* The next "..." pair in [*p, end); *s and *n frame its inside. */
static bool cik_quoted(const char **p, const char *end, const char **s,
                       size_t *n)
{
    const char *q = memchr(*p, '"', (size_t)(end - *p)), *e;
    if (!q)
        return false;
    e = memchr(q + 1, '"', (size_t)(end - q - 1));
    if (!e)
        return false;
    *s = q + 1;
    *n = (size_t)(e - q - 1);
    *p = e + 1;
    return true;
}

/* The accessor pattern: any call whose argument list names the input object
 * or one of its aliases right before a string literal. */
static void cik_accessor_pattern(const char *code, struct cik_buf *re)
{
    struct cik_cur c = { code, code + strlen(code), false };
    const char *s;
    size_t n, at, len;
    cik_buf_puts(re, "[A-Za-z_][A-Za-z_0-9]*\\(([^,()\"]*[^A-Za-z_0-9])?(input");
    while (cik_cur_next(&c, &s, &n)) {
        if (memchr(s, '"', n) || !cik_has_word(s, n, "input", 5)
            || !cik_find_assign(s, n, &at, &len))
            continue;
        if (len == 5 && memcmp(s + at, "input", 5) == 0)
            continue;
        cik_buf_putc(re, '|');
        cik_buf_put(re, s + at, len);
    }
    cik_buf_puts(re, ")([^A-Za-z_0-9][^,()\"]*)?,[ ]*\"[^\"]*\"");
}

static void cik_scan_accessors(struct cik_index *x, struct cik_fn *fn,
                               const char *body, const char *code)
{
    struct cik_buf re = { 0 };
    regex_t rx;
    regmatch_t m;
    if (!strchr(body, '"'))
        return;
    cik_accessor_pattern(code, &re);
    if (regcomp(&rx, re.p, REG_EXTENDED) != 0) {
        fputs("check_command_input_keys: FATAL — cannot compile the read"
              " pattern; refusing to report a verdict.\n", stderr);
        exit(2);
    }
    while (regexec(&rx, body, 1, &m, 0) == 0 && m.rm_eo > m.rm_so) {
        const char *hit = body + m.rm_so;
        size_t n = (size_t)(m.rm_eo - m.rm_so);
        const char *q = memchr(hit, '"', n);
        cik_add_key(x, fn, q + 1, (size_t)(hit + n - q) - 2);
        body += m.rm_eo;
    }
    regfree(&rx);
    cik_buf_free(&re);
}

/* True when a statement hands the named array to a call that also names the
 * input object. */
static bool cik_array_used(const char *code, const char *name, size_t nl)
{
    struct cik_cur c = { code, code + strlen(code), false };
    const char *s;
    size_t n;
    while (cik_cur_next(&c, &s, &n))
        if (cik_has_text(s, n, "input") && memchr(s, '(', n)
            && cik_has_word(s, n, name, nl))
            return true;
    return false;
}

static void cik_scan_arrays(struct cik_index *x, struct cik_fn *fn,
                            const char *body, const char *code)
{
    regmatch_t m;
    while (regexec(&x->arr_re, body, 1, &m, 0) == 0) {
        const char *hit = body + m.rm_so, *end = body + m.rm_eo;
        const char *name = hit + sizeof "const char *const " - 1;
        const char *p = (const char *)memchr(hit, '{', (size_t)(end - hit)) + 1;
        const char *s;
        size_t n;
        if (cik_array_used(code, name, strcspn(name, "[")))
            while (cik_quoted(&p, end - 1, &s, &n))
                cik_add_key(x, fn, s, n);
        body = end;
    }
}

static void cik_scan_literals(struct cik_index *x, struct cik_fn *fn,
                              const char *body)
{
    const char *end = body + strlen(body), *s;
    size_t n;
    while (cik_quoted(&body, end, &s, &n)) {
        for (size_t i = 0; i < n;) {
            size_t j = i;
            while (j < n && s[j] != ' ' && s[j] != '\t' && s[j] != '\n')
                j++;
            if (j > i)
                cik_set_add(&fn->lits, cik_intern(&x->dict, s + i, j - i));
            i = j + 1;
        }
    }
}

static void cik_scan_calls(struct cik_index *x, struct cik_fn *fn,
                           const char *code)
{
    size_t i = 0, j, n = strlen(code);
    while (i < n) {
        if (!cik_isid_start(code[i])) {
            i++;
            continue;
        }
        for (j = i; j < n && cik_isid(code[j]); j++)
            ;
        if (j < n && code[j] == '(')
            cik_set_add(&fn->calls, cik_intern(&x->dict, code + i, j - i));
        i = j < n && code[j] == '(' ? j + 1 : j;
    }
}

void cik_extract(struct cik_index *x, const char *name, const char *body,
                 const char *code)
{
    struct cik_fn *fn = cik_index_get(x, cik_intern(&x->dict, name,
                                                    strlen(name)));
    cik_scan_accessors(x, fn, body, code);
    cik_scan_arrays(x, fn, body, code);
    cik_scan_literals(x, fn, body);
    cik_scan_calls(x, fn, code);
}
