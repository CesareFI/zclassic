/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: reads the command-leaf macros out of the engine .def files for
 * check-command-input-keys. One character pass per file, comments skipped,
 * string literals kept, parentheses matched; each handler-binding leaf is
 * kept with its path, input_keys, positional_keys, schemas and handler. A
 * macro whose argument count differs from its known shape is reported as
 * grammar drift instead of reading the wrong slot.
 */
#include <stdlib.h>
#include <string.h>
#include "gate_command_input_keys_priv.h"

enum { CIK_ARGS = 32, CIK_TOK = 64 };
enum { CIK_PATH = 1, CIK_SCHEMA = 8, CIK_OUT = 9, CIK_IN = 10, CIK_POS = 11 };

static const char k_cik_dash[] = "\xE2\x80\x94";

/* Arity of each macro shape and the argument that names its handler (0 when
 * the shape binds none). */
static const struct { const char *name; int arity, slot; } k_cik_macros[] = {
    { "ZCL_COMMAND_READY_READ", 22, 22 },
    { "ZCL_COMMAND_READY_COMMAND", 25, 25 },
    { "ZCL_COMMAND_DEV_READ", 22, 20 },
    { "ZCL_COMMAND_DEV_COMMAND", 26, 24 },
    { "ZCL_COMMAND_PLANNED_READ", 20, 0 },
    { "ZCL_COMMAND_PLANNED_COMMAND", 25, 0 },
    { "ZCL_COMMAND_COMPAT_READ", 21, 0 },
    { "ZCL_COMMAND_COMPAT_COMMAND", 26, 0 }
};

struct cik_dp {
    struct cik_defs *res;
    FILE *err;
    const char *file, *start_file;
    int line, start_line, depth, nargs, macro;
    bool in_comment, in_str, esc, collecting;
    char tok[CIK_TOK];
    size_t toklen;
    struct cik_buf cur, args[CIK_ARGS];
};

static bool cik_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* A string-literal argument without its quotes, escaped quotes or blanks. */
static char *cik_dp_literal(const struct cik_buf *a)
{
    const char *s = cik_buf_str(a);
    struct cik_buf out = { 0 };
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '\\' && s[i + 1] == '"')
            i++;
        else if (s[i] != '"' && !cik_ws(s[i]))
            cik_buf_putc(&out, s[i]);
    }
    return out.p ? out.p : cik_dup("", 0);
}

static char *cik_dp_trim(const struct cik_buf *a)
{
    const char *s = cik_buf_str(a);
    size_t n = a->n;
    while (n && cik_ws(*s)) {
        s++;
        n--;
    }
    while (n && cik_ws(s[n - 1]))
        n--;
    return cik_dup(s, n);
}

static void cik_dp_emit(struct cik_dp *dp, int slot)
{
    struct cik_defs *r = dp->res;
    char *h = cik_dp_trim(&dp->args[slot]);
    if (!h[0] || strcmp(h, "NULL") == 0 || strcmp(h, "0") == 0) {
        free(h);
        return;
    }
    if (r->n == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 256;
        r->leaf = cik_mem(r->leaf, r->cap * sizeof *r->leaf, "cik_leaf");
    }
    r->leaf[r->n++] = (struct cik_leaf){
        .path = cik_dp_literal(&dp->args[CIK_PATH]),
        .file = cik_dup(dp->start_file, strlen(dp->start_file)),
        .in = cik_dp_literal(&dp->args[CIK_IN]),
        .pos = cik_dp_literal(&dp->args[CIK_POS]),
        .handler = h,
        .schema = cik_dp_literal(&dp->args[CIK_SCHEMA]),
        .out = cik_dp_literal(&dp->args[CIK_OUT]),
        .line = dp->start_line };
}

static void cik_dp_finish(struct cik_dp *dp)
{
    int arity = k_cik_macros[dp->macro].arity;
    dp->res->nleaf++;
    if (dp->nargs != arity) {
        dp->res->fatals++;
        fprintf(dp->err, "  %s:%d: %s %s macro grammar drift: expected %d"
                " arguments, parsed %d. This gate reads fixed argument"
                " slots; re-read the macro in"
                " engine/composition/src/command_catalog.c and fix the"
                " arity table here.\n", dp->start_file, dp->start_line,
                k_cik_macros[dp->macro].name, k_cik_dash, arity, dp->nargs);
    } else if (k_cik_macros[dp->macro].slot) {
        cik_dp_emit(dp, k_cik_macros[dp->macro].slot);
    }
}

static void cik_dp_push(struct cik_dp *dp)
{
    dp->nargs++;
    if (dp->nargs < CIK_ARGS) {
        cik_buf_clear(&dp->args[dp->nargs]);
        cik_buf_put(&dp->args[dp->nargs], cik_buf_str(&dp->cur), dp->cur.n);
    }
    cik_buf_clear(&dp->cur);
}

static void cik_dp_collect(struct cik_dp *dp, char c)
{
    if (c == '(') {
        dp->depth++;
    } else if (c == ')') {
        if (--dp->depth == 0) {
            cik_dp_push(dp);
            dp->collecting = false;
            cik_dp_finish(dp);
            return;
        }
    } else if (c == ',' && dp->depth == 1) {
        cik_dp_push(dp);
        return;
    }
    cik_buf_putc(&dp->cur, c);
}

static int cik_dp_macro(const struct cik_dp *dp)
{
    if (dp->toklen >= CIK_TOK)
        return -1;
    for (size_t i = 0; i < sizeof k_cik_macros / sizeof k_cik_macros[0]; i++)
        if (strlen(k_cik_macros[i].name) == dp->toklen
            && memcmp(k_cik_macros[i].name, dp->tok, dp->toklen) == 0)
            return (int)i;
    return -1;
}

static void cik_dp_idle(struct cik_dp *dp, char c)
{
    int m;
    if (cik_isid(c)) {
        if (dp->toklen < CIK_TOK)
            dp->tok[dp->toklen] = c;
        dp->toklen++;
        return;
    }
    m = c == '(' ? cik_dp_macro(dp) : -1;
    if (m >= 0) {
        dp->macro = m;
        dp->collecting = true;
        dp->depth = 1;
        dp->nargs = 0;
        dp->start_line = dp->line;
        dp->start_file = dp->file;
        cik_buf_clear(&dp->cur);
    }
    dp->toklen = 0;
}

static void cik_dp_str(struct cik_dp *dp, char c)
{
    if (dp->collecting)
        cik_buf_putc(&dp->cur, c);
    if (dp->esc)
        dp->esc = false;
    else if (c == '\\')
        dp->esc = true;
    else if (c == '"')
        dp->in_str = false;
}

/* Returns the number of extra characters the step consumed. */
static int cik_dp_step(struct cik_dp *dp, char c, char next)
{
    if (dp->in_comment) {
        dp->in_comment = !(c == '*' && next == '/');
        return dp->in_comment ? 0 : 1;
    }
    if (dp->in_str) {
        cik_dp_str(dp, c);
        return 0;
    }
    if (c == '/' && next == '*') {
        dp->in_comment = true;
        return 1;
    }
    if (c == '"') {
        dp->in_str = true;
        dp->esc = false;
        if (dp->collecting)
            cik_buf_putc(&dp->cur, c);
    } else if (dp->collecting) {
        cik_dp_collect(dp, c);
    } else {
        cik_dp_idle(dp, c);
    }
    return 0;
}

static void cik_dp_scan(struct cik_dp *dp, const char *text, size_t n)
{
    dp->in_comment = dp->in_str = dp->collecting = false;
    dp->toklen = 0;
    dp->line = 1;
    for (size_t i = 0; i < n; i++) {
        i += (size_t)cik_dp_step(dp, text[i], i + 1 < n ? text[i + 1] : '\0');
        if (text[i] == '\n')
            dp->line++;
    }
}

static int cik_dp_file(struct cik_dp *dp, const char *path)
{
    size_t n = 0;
    char *text = cik_slurp(path, &n);
    if (!text) {
        fprintf(dp->err, "check_command_input_keys: FATAL — cannot read %s;"
                " refusing to report a verdict.\n", path);
        return 2;
    }
    dp->file = path;
    if (n)
        cik_dp_scan(dp, text, n);
    free(text);
    return 0;
}

int cik_defs_parse(struct cik_defs *d, char *const *files, size_t nfiles,
                   FILE *err)
{
    struct cik_dp *dp = cik_mem(NULL, sizeof *dp, "cik_dp");
    int rc = 0;
    memset(dp, 0, sizeof *dp);
    dp->res = d;
    dp->err = err;
    for (size_t i = 0; i < nfiles && rc == 0; i++)
        rc = cik_dp_file(dp, files[i]);
    if (rc == 0 && dp->collecting) {
        d->fatals++;
        fprintf(err, "  %s:%d: %s %s unterminated macro invocation: EOF with"
                " an open argument list.\n", dp->start_file, dp->start_line,
                k_cik_macros[dp->macro].name, k_cik_dash);
    }
    cik_buf_free(&dp->cur);
    for (size_t i = 0; i < CIK_ARGS; i++)
        cik_buf_free(&dp->args[i]);
    free(dp);
    return rc;
}

void cik_defs_free(struct cik_defs *d)
{
    for (size_t i = 0; i < d->n; i++) {
        struct cik_leaf *l = &d->leaf[i];
        free(l->path);
        free(l->file);
        free(l->in);
        free(l->pos);
        free(l->handler);
        free(l->schema);
        free(l->out);
    }
    free(d->leaf);
    *d = (struct cik_defs){ 0 };
}
