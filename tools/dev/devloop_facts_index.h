/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One semantic manifest as a graph of canonical identities: each id's records and digest, its reference and closure edges, the TU's roots and its four identities. */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A reader-side model of one TU's manifest (facts revision 1 to 4). Every
 * record that belongs to an entity is attached to its canonical id:
 *   MACROS    m:<path>:<name>, and the name group m:<name> (every
 *             definition of that name the TU saw);
 *   LAYOUTS   s:/u:<path>:<name>; ENUMS k:<path>:<constant> and
 *             e:<path>:<enum>; DECLS and FUNCTIONS f:/v:<name> (external)
 *             or f:/v:/t:/s:/u:/e:<path>:<name>; SYMBOLS its id;
 *   REFS and UNKNOWNS their site (the from id), including the pseudo-sites
 *             "@scope:<path>" and "@cond:<path>" of facts revision 2 and
 *             "@assert:<path>" of revision 3 (never a root: the consumer
 *             asks what each reaches, devloop_facts_tu.c).
 * An entity's digest hashes its records outside the main file; the main
 * file's records form the implementation root instead. Edges: every REFS
 * record, a tag named in a record's canonical type text ("struct N",
 * "union N", "enum N"; an unnamed tag reaches every anonymous or
 * typedef-named tag), a typedef to the tag of its name and path, and a
 * macro to the name group of every identifier in its body. */

struct fxi;

enum fxi_dirty {
    FXI_DIRTY_DIGEST = 1,   /* its records differ between the two sides */
    FXI_DIRTY_CHUNK = 2,    /* a changed header text chunk names it */
    FXI_DIRTY_POSITION = 4, /* a declaration the debug info records moved */
    FXI_DIRTY_SPAN = 8,     /* a header function's code moved: __LINE__ may too */
};

struct fxi_roots {
    uint8_t source[32];         /* every file read and its bytes */
    uint8_t fact[32];           /* the manifest's exact bytes */
    uint8_t interface[32];      /* digests of every id the TU reaches */
    uint8_t implementation[32]; /* the main file's bytes and records */
};

/* Index a valid manifest; NULL with *why set when it is invalid, carries no
 * facts extension, or memory runs out. The index points into m, which must
 * outlive it. */
struct fxi *fxi_open(const uint8_t *m, size_t n, const char **why);
void fxi_free(struct fxi *x);

const char *fxi_main(const struct fxi *x);
bool fxi_complete(const struct fxi *x);
uint8_t fxi_revision(const struct fxi *x);
const uint8_t *fxi_producer(const struct fxi *x);
/* The FILES digest of `path` in this TU, NULL when it did not read it. */
const uint8_t *fxi_file_digest(const struct fxi *x, const char *path);
size_t fxi_file_count(const struct fxi *x);
const char *fxi_file_path(const struct fxi *x, size_t k);
bool fxi_file_repo(const struct fxi *x, size_t k);
/* SHA3 of the records of one section (IDENTITY, LOOKUPS, PROBES...). */
void fxi_section_digest(const struct fxi *x, int section, uint8_t out[32]);

size_t fxi_count(const struct fxi *x);
const char *fxi_id(const struct fxi *x, size_t e);
const char *fxi_bare(const struct fxi *x, size_t e);
bool fxi_find(const struct fxi *x, const char *id, size_t *e);
const uint8_t *fxi_digest(const struct fxi *x, size_t e);
/* Every record of e, the main file's included: a main-file entity whose
 * records a header change re-expanded differs here and not in fxi_digest. */
const uint8_t *fxi_whole_digest(const struct fxi *x, size_t e);
bool fxi_main_owned(const struct fxi *x, size_t e);
/* A record of e names `path` as its file (the file that declares it). */
bool fxi_has_path(const struct fxi *x, size_t e, const char *path);
/* The id is external (f:<name> or v:<name>). */
bool fxi_external(const struct fxi *x, size_t e);
/* e is a root: a main-file entity, an @scope/@cond site, or a definition
 * in another file the compile always emits (an external variable or
 * function defined in a header). */
bool fxi_root(const struct fxi *x, size_t e);
bool fxi_is_site(const struct fxi *x, size_t e, const char *prefix);
/* e is a function the main file defines (a FUNCTIONS record in it). */
bool fxi_main_function(const struct fxi *x, size_t e);
/* The line span [*lo, *hi] of e's function definition in `path`. */
bool fxi_span(const struct fxi *x, size_t e, const char *path, uint32_t *lo,
              uint32_t *hi);
/* A REFS record of this manifest names `id` with `kind` (0: any kind). */
bool fxi_refs_to(const struct fxi *x, const char *id, uint8_t kind);
/* An UNKNOWNS record at site e other than an external call. */
bool fxi_unknown_effect(const struct fxi *x, size_t e, uint8_t *kind);

/* Records of e, and the file the k-th one names (false: it names none). */
size_t fxi_nrows(const struct fxi *x, size_t e);
bool fxi_row_path_at(const struct fxi *x, size_t e, size_t k, const char **p,
                     size_t *n);
/* Edges: every REFS record (kind 1..6) and closure edge (kind 0). */
size_t fxi_edge_count(const struct fxi *x);
void fxi_edge_at(const struct fxi *x, size_t k, size_t *from, size_t *to,
                 uint8_t *kind);

void fxi_roots(const struct fxi *x, struct fxi_roots *out);

/* Taint: flags[e] (fxi_dirty bits) marks the dirty entities; on return
 * via[e] is, for every entity that reaches a dirty one along edges, the
 * dirty entity it reaches (SIZE_MAX when it reaches none). via has
 * fxi_count() slots. */
bool fxi_taint(const struct fxi *x, const uint8_t *flags, size_t *via);

/* ---- code generation (devloop_facts_codegen.c) ---------------------------- */

/* e is a function some file of this TU defines (a FUNCTIONS record). */
bool fxi_defined_function(const struct fxi *x, size_t e);
/* How far a compile of this TU may carry a change of some of its
 * functions into the bytes of others, by the optimizer its IDENTITY names. */
enum fxi_codegen {
    /* -O2 and above, LTO, whole-program, IPA clone, merge or profile-
     * feedback flags: the facts cannot bound it. */
    FXI_CODEGEN_UNBOUNDED = 0,
    /* No -O flag or -O0: only always_inline bodies move into callers. */
    FXI_CODEGEN_CALLERS,
    /* -O1, -O and -Og: inlining and callee summaries flow into callers;
     * coldness, constant and dead-argument propagation flow into internal
     * callees; read-only and addressability facts of a static variable
     * flow into every function naming it. */
    FXI_CODEGEN_COMPONENT,
};
/* Whether x's IDENTITY names the compiler that builds the object
 * ("; object-cc <path> ..."), not "object-cc unknown" or nothing: without
 * it an unchanged IDENTITY does not show the object's compiler unchanged. */
bool fxi_object_cc_known(const struct fxi *x);
/* The model for x (unbounded when fxi_object_cc_known fails); *token names
 * what makes it unbounded. */
enum fxi_codegen fxi_codegen_model(const struct fxi *x, const char **token);
/* Same, over raw identity bytes (the test seam). */
enum fxi_codegen fxi_codegen_model_of(const uint8_t *identity, size_t len,
                                      const char **token);
/* Debug information levels, each recording more of the source than the
 * last: none; line tables and function descriptions; types and
 * declarations with their lines; macro definitions too; the text of every
 * file the TU read too. */
enum {
    FXI_DEBUG_NONE = 0,
    FXI_DEBUG_LINES = 1,
    FXI_DEBUG_DECLS = 2,
    FXI_DEBUG_MACROS = 3,
    FXI_DEBUG_SOURCE = 4,
};
/* The debug information level the IDENTITY argv asks for, the last -g
 * option deciding: 0 none (no -g, or -g0 last), 1 line tables and function
 * descriptions (-g1, -gline-tables-only, -gmlt), 2 types and declarations
 * with their lines (-g2; a bare -g, -ggdb or -gdwarf-N keeps a higher
 * level already set), 3 macro definitions too
 * (-g3, or -fdebug-macro with any level), 4 the source text itself
 * (-gembed-source with any level, unless -gno-embed-source follows). A -g
 * spelling it does not know, or an identity it cannot read, is 4. */
int fxi_debug_level(const struct fxi *x);
/* Same, over raw identity bytes (the test seam). */
int fxi_debug_level_of(const uint8_t *identity, size_t len);
/* Grow the set in mark (fxi_count() slots; nonzero: a function whose code
 * may change) to every defined function or static variable of the TU the
 * compile may re-emit under `model`. False only for memory. */
bool fxi_codegen_closure(const struct fxi *x, enum fxi_codegen model,
                         uint8_t *mark);

/* via (fxi_count() slots): for every entity that expands the builtin macro
 * `ident` (__LINE__, __COUNTER__), directly or through the body of a macro
 * it expands, the entity it reaches; SIZE_MAX for every other. A builtin
 * expanded only inside a macro has no id of its own, so each macro whose
 * body names it stands in. False only for memory. */
bool fxi_expands_builtin(const struct fxi *x, const char *ident, size_t *via);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_H */
