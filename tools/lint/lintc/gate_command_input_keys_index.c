/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: indexes every C function in the files that name a registered
 * handler for check-command-input-keys. One character pass per file with
 * comments dropped, string literals kept and braces matched. A function body
 * starts at a brace at depth 0 whose previous non-blank character is a
 * closing parenthesis, which tells a definition from a file-scope aggregate
 * initializer. Bodies are handed to cik_extract with their literals kept and
 * with them emptied.
 */
#include <stdlib.h>
#include <string.h>
#include "gate_command_input_keys_priv.h"
#include "lintc_sig.h"

enum { CIK_ID = 256 };

struct cik_ix {
    struct cik_index *x;
    bool in_comment, in_line_comment, in_str, in_chr, esc;
    int bdepth, pdepth;
    size_t toklen;
    char tok[CIK_ID], last_ident[CIK_ID], cand[CIK_ID], fname[CIK_ID];
    char last_ns;
    struct cik_buf body, code;
};

int cik_index_open(struct cik_index *x)
{
    static const char arr[] = "const char \\*const [A-Za-z_][A-Za-z_0-9]*"
                              "\\[\\][ ]*=[ ]*\\{[^}]*\\}";
    *x = (struct cik_index){ 0 };
    x->ready = regcomp(&x->arr_re, arr, REG_EXTENDED) == 0;
    return x->ready ? 0 : 2;
}

void cik_index_close(struct cik_index *x)
{
    for (size_t i = 0; i < x->nfn; i++) {
        cik_set_free(&x->fn[i].keys);
        cik_set_free(&x->fn[i].lits);
        cik_set_free(&x->fn[i].calls);
    }
    free(x->fn);
    free(x->slot);
    cik_dict_free(&x->dict);
    if (x->ready)
        regfree(&x->arr_re);
    *x = (struct cik_index){ 0 };
}

struct cik_fn *cik_index_find(const struct cik_index *x, int id)
{
    if (id < 0 || (size_t)id >= x->nslot || !x->slot[id])
        return NULL;
    return &x->fn[x->slot[id] - 1];
}

struct cik_fn *cik_index_get(struct cik_index *x, int id)
{
    if ((size_t)id >= x->nslot) {
        size_t cap = x->dict.n + 64;
        x->slot = cik_mem(x->slot, cap * sizeof *x->slot, "cik_slot");
        memset(x->slot + x->nslot, 0, (cap - x->nslot) * sizeof *x->slot);
        x->nslot = cap;
    }
    if (!x->slot[id]) {
        if (x->nfn == x->cap) {
            x->cap = x->cap ? x->cap * 2 : 256;
            x->fn = cik_mem(x->fn, x->cap * sizeof *x->fn, "cik_fn");
        }
        x->fn[x->nfn] = (struct cik_fn){ 0 };
        x->slot[id] = (int)++x->nfn;
    }
    return &x->fn[x->slot[id] - 1];
}

static void cik_ix_flush(struct cik_ix *ix)
{
    if (ix->fname[0]) {
        ix->x->defs++;
        cik_extract(ix->x, ix->fname, cik_buf_str(&ix->body),
                    cik_buf_str(&ix->code));
    }
    ix->fname[0] = '\0';
    cik_buf_clear(&ix->body);
    cik_buf_clear(&ix->code);
}

/* Appends to the open function: body keeps the byte, code too unless
 * only_body (the inside of a string literal). */
static void cik_ix_put(struct cik_ix *ix, char c, bool only_body)
{
    if (ix->bdepth <= 0 || !ix->fname[0])
        return;
    cik_buf_putc(&ix->body, c);
    if (!only_body)
        cik_buf_putc(&ix->code, c);
}

static void cik_ix_str(struct cik_ix *ix, char c)
{
    bool quote = c == '"' && !ix->esc;
    cik_ix_put(ix, c, !quote);
    if (ix->esc)
        ix->esc = false;
    else if (c == '\\')
        ix->esc = true;
    else if (c == '"')
        ix->in_str = false;
}

static void cik_ix_chr(struct cik_ix *ix, char c)
{
    if (ix->esc)
        ix->esc = false;
    else if (c == '\\')
        ix->esc = true;
    else if (c == '\'')
        ix->in_chr = false;
}

static void cik_ix_ident(struct cik_ix *ix, char c)
{
    if (cik_isid(c)) {
        if (ix->toklen < CIK_ID - 1)
            ix->tok[ix->toklen++] = c;
    } else if (ix->toklen) {
        ix->tok[ix->toklen] = '\0';
        memcpy(ix->last_ident, ix->tok, ix->toklen + 1);
        ix->toklen = 0;
    }
}

static void cik_ix_open(struct cik_ix *ix)
{
    if (ix->bdepth == 0 && ix->last_ns == ')' && ix->cand[0]) {
        memcpy(ix->fname, ix->cand, strlen(ix->cand) + 1);
        cik_buf_clear(&ix->body);
        cik_buf_clear(&ix->code);
    }
    ix->bdepth++;
}

/* True when the brace closed the outermost block and the function ended. */
static bool cik_ix_close(struct cik_ix *ix)
{
    if (--ix->bdepth > 0)
        return false;
    ix->bdepth = 0;
    cik_ix_flush(ix);
    ix->pdepth = 0;
    ix->cand[0] = '\0';
    return true;
}

static void cik_ix_code(struct cik_ix *ix, char c)
{
    cik_ix_ident(ix, c);
    if (c == '(') {
        if (ix->bdepth == 0 && ix->pdepth == 0)
            memcpy(ix->cand, ix->last_ident, strlen(ix->last_ident) + 1);
        ix->pdepth++;
    } else if (c == ')') {
        if (ix->pdepth > 0)
            ix->pdepth--;
    } else if (c == '{') {
        cik_ix_open(ix);
    } else if (c == '}' && cik_ix_close(ix)) {
        return;
    }
    cik_ix_put(ix, c == '\n' ? ' ' : c, false);
    if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
        ix->last_ns = c;
}

/* Returns the number of extra characters the step consumed. */
static int cik_ix_step(struct cik_ix *ix, char c, char next)
{
    if (ix->in_line_comment) {
        ix->in_line_comment = c != '\n';
    } else if (ix->in_comment) {
        ix->in_comment = !(c == '*' && next == '/');
        return ix->in_comment ? 0 : 1;
    } else if (ix->in_chr) {
        cik_ix_chr(ix, c);
    } else if (ix->in_str) {
        cik_ix_str(ix, c);
    } else if (c == '/' && (next == '*' || next == '/')) {
        ix->in_comment = next == '*';
        ix->in_line_comment = next == '/';
        return 1;
    } else if (c == '\'') {
        ix->in_chr = true;
        ix->esc = false;
    } else if (c == '"') {
        ix->in_str = true;
        ix->esc = false;
        ix->last_ns = c;
        cik_ix_put(ix, c, false);
    } else {
        cik_ix_code(ix, c);
    }
    return 0;
}

static void cik_ix_scan(struct cik_ix *ix, const char *text, size_t n)
{
    ix->in_comment = ix->in_line_comment = ix->in_str = ix->in_chr = false;
    ix->bdepth = ix->pdepth = 0;
    ix->toklen = 0;
    ix->last_ident[0] = ix->cand[0] = ix->fname[0] = '\0';
    ix->last_ns = '\0';
    for (size_t i = 0; i < n; i++)
        i += (size_t)cik_ix_step(ix, text[i], i + 1 < n ? text[i + 1] : '\0');
    cik_ix_flush(ix);
}

int cik_index_files(struct cik_index *x, char *const *files, size_t nfiles,
                    FILE *err)
{
    struct cik_ix *ix = cik_mem(NULL, sizeof *ix, "cik_ix");
    int rc = 0;
    memset(ix, 0, sizeof *ix);
    ix->x = x;
    for (size_t i = 0; i < nfiles && rc == 0 && !lsc_pending(); i++) {
        size_t n = 0;
        char *text = cik_slurp(files[i], &n);
        if (!text) {
            fprintf(err, "check_command_input_keys: FATAL — cannot read %s;"
                    " refusing to report a verdict.\n", files[i]);
            rc = 2;
            continue;
        }
        if (n)
            cik_ix_scan(ix, text, n);
        free(text);
    }
    cik_buf_free(&ix->body);
    cik_buf_free(&ix->code);
    free(ix);
    return rc;
}
