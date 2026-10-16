/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-command-input-keys gate
 * files: growable text, interned words, ordered word sets, the command-leaf
 * records parsed from the .def macros and the per-function read index built
 * from the C sources that define the handlers.
 */
#ifndef GATE_COMMAND_INPUT_KEYS_PRIV_H
#define GATE_COMMAND_INPUT_KEYS_PRIV_H

#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

static inline bool cik_isid(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_';
}

static inline bool cik_isid_start(char c)
{
    return cik_isid(c) && (c < '0' || c > '9');
}

struct cik_buf { char *p; size_t n, cap; };
void *cik_mem(void *old, size_t n, const char *label);
char *cik_dup(const char *s, size_t n);
void cik_buf_put(struct cik_buf *b, const char *s, size_t n);
void cik_buf_putc(struct cik_buf *b, char c);
void cik_buf_puts(struct cik_buf *b, const char *s);
void cik_buf_clear(struct cik_buf *b);
void cik_buf_free(struct cik_buf *b);
const char *cik_buf_str(const struct cik_buf *b);
/* Whole file, NUL-terminated and newline-terminated; NULL when unreadable. */
char *cik_slurp(const char *path, size_t *len);

/* Interned words: a word keeps one id for the life of the dictionary. */
struct cik_dict { char **word; size_t n, cap; int *tab; size_t tcap; };
int cik_intern(struct cik_dict *d, const char *s, size_t n);
void cik_dict_free(struct cik_dict *d);

/* Insertion-ordered set of word ids with constant-time membership. */
struct cik_set { int *v; size_t n, cap; int *tab; size_t tcap; };
bool cik_set_has(const struct cik_set *s, int id);
bool cik_set_add(struct cik_set *s, int id);
void cik_set_clear(struct cik_set *s);
void cik_set_free(struct cik_set *s);

/* One handler-binding leaf, in .def order. */
struct cik_leaf {
    char *path, *file, *in, *pos, *handler, *schema, *out;
    int line, hid;
};
struct cik_defs {
    struct cik_leaf *leaf;
    size_t n, cap;
    long nleaf;
    int fatals;
};
/* Parses every macro in the given files into d; grammar drift is printed to
 * err. Returns 0, or 2 when a file cannot be read. */
int cik_defs_parse(struct cik_defs *d, char *const *files, size_t nfiles,
                   FILE *err);
void cik_defs_free(struct cik_defs *d);

/* Everything the C sources say about one function name. */
struct cik_fn { struct cik_set keys, lits, calls; };
struct cik_index {
    struct cik_dict dict;
    struct cik_fn *fn;
    size_t nfn, cap;
    int *slot;          /* word id -> index into fn, plus one */
    size_t nslot;
    long defs;          /* function definitions seen, duplicates included */
    regex_t arr_re;
    bool ready;
};
int cik_index_open(struct cik_index *x);
void cik_index_close(struct cik_index *x);
int cik_index_files(struct cik_index *x, char *const *files, size_t nfiles,
                    FILE *err);
struct cik_fn *cik_index_find(const struct cik_index *x, int id);
struct cik_fn *cik_index_get(struct cik_index *x, int id);
/* Records one function's reads; body keeps string literals, code has them
 * emptied. */
void cik_extract(struct cik_index *x, const char *name, const char *body,
                 const char *code);

/* Counts and the text of each finding class, in the order found. */
struct cik_report {
    long resolved, unresolved, nmiss, nunread, ngrand, nstale, nshared, ndiv;
    struct cik_buf miss, divg, stale, unread;
};
/* Closes the call graph and judges every leaf against the baseline file.
 * Returns 0, 1 when the baseline cannot be created, 3 when the call closure
 * did not settle. */
int cik_analyze(const char *baseline, struct cik_index *x,
                const struct cik_defs *d, struct cik_report *r, FILE *err);
void cik_report_free(struct cik_report *r);

/* The gate settings; floors stay text so a malformed floor fails the way the
 * script's numeric test did. */
struct cik_cfg {
    const char *def_dir, *baseline, *mode, *verbose;
    const char *leaf_floor, *fn_floor, *bound_floor, *resolved_floor;
};
struct cik_list { char **v; size_t n, cap; };
void cik_list_add(struct cik_list *l, const char *s, size_t n);
void cik_list_free(struct cik_list *l);
/* Fills out with the C files that name one of the "handler(" patterns and
 * returns the exit status of the search: 0 found, 1 none, 2 or more failed. */
typedef int (*cik_find_fn)(void *ctx, const struct cik_list *pats,
                           struct cik_list *out);
/* The whole gate over the given .def files. Findings go to out, diagnostics
 * to err. Returns 0, 1 (findings), 2 (unproven) or -1 when a termination
 * signal was recorded. */
int cik_check(const struct cik_cfg *cfg, const struct cik_list *defs,
              cik_find_fn find, void *fctx, FILE *out, FILE *err);

#endif
