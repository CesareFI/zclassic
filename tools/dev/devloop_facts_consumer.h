/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Internal state of the declaration-identity consumer shared by its universe (consumer.c), per-TU decision (tu.c), obligations (obligations.c) and make reader (make.c, make_reach.c). */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_CONSUMER_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_CONSUMER_H

#include "devloop_facts.h"
#include "devloop_facts_hdr.h"
#include "devloop_facts_index.h"

struct codeindex;

/* The text evidence of one changed file, shared by every TU that read it. */
struct fxc_hdr {
    const char *path;
    bool loaded;
    bool read;          /* some candidate manifest read it */
    bool moved;         /* created or deleted: one side has no file there */
    const char *reason; /* NULL when both texts are bound */
    uint8_t *before, *after;
    size_t blen, alen;
    uint8_t bdigest[32], adigest[32];
    struct fxh_diff diff;
};

struct fxc_strs {
    char **v;
    size_t n, cap;
};

struct fxc {
    const char *root, *facts_dir;
    const char *const *files;
    size_t nfiles;
    struct zcl_devloop_facts_report *report;
    struct fxc_strs cand;       /* TUs with an after manifest in facts_dir */
    struct fxc_hdr *hdrs;       /* one per changed file */
    size_t captus;
    uint8_t producer[32];
    bool have_producer;
    bool mixed;                 /* two producers in the universe */
    struct fxc_strs address;    /* ids some manifest takes the address of */
    struct fxc_strs new_ids;    /* external ids one side of a pair lacks */
    struct fxc_strs new_names;  /* ...and their names */
    struct zcl_devloop_facts_seed *seeds;
    size_t nseeds, capseeds;
    const char *seed_reason;    /* a seed the walk cannot bound, or NULL */
    struct fxc_strs checked;    /* declaring headers whose readers were checked */
    bool universal;             /* nothing bounds the change: every group is in scope */
    bool sdir;                  /* a TU's search dirs changed: its broadened
                                   TUs join the file-seeded fallback */
    char seed_detail[192];
    struct codeindex *ci;       /* NULL when the index cannot open */
    int graph;                  /* codeindex_include_dim of the last query */
};

/* consumer.c */
bool fxc_strs_add(struct fxc_strs *s, const char *v);
bool fxc_strs_has(const struct fxc_strs *s, const char *v);
void fxc_strs_free(struct fxc_strs *s);
bool fxc_is_changed(const struct fxc *c, const char *path);
struct fxc_hdr *fxc_hdr_of(struct fxc *c, const char *path);
/* A TU verdict slot for path (new, zeroed). */
struct zcl_devloop_facts_tu_verdict *fxc_tu_new(struct fxc *c,
                                                const char *path);
/* The TUs the depfile graph says read `path`; -1 when the graph cannot
 * answer (c->graph names why). */
int fxc_readers(struct fxc *c, const char *path, char (*out)[256], int cap);
/* The universe is not known: the first reason and path win. */
void fxc_incomplete(struct fxc *c, const char *reason, const char *path);

/* tu.c: the changed path a lookup that makes no negative claim (a computed
 * or include_next directive, or a conditional lookup the sensor could not
 * bound) may now resolve differently because of, or NULL. A created or
 * deleted path can change any such answer; a #embed or __has_embed reads
 * or weighs the file it finds, so any changed path can change its answer. */
const char *fxc_unbound_path(const struct fxc *c, const char *spelled,
                             size_t len);

/* sdir.c: a pair whose IDENTITY records differ. UNCHANGED and CHANGED
 * only when nothing but the -I/-iquote/-isystem/-idirafter dirs differ and
 * both sides' recorded lookups decide the resolution; DRIFT otherwise. */
enum fxc_sdir {
    FXC_SDIR_DRIFT,     /* not only search dirs, or nothing proves which */
    FXC_SDIR_UNCHANGED, /* every lookup, probe answer and file as before */
    FXC_SDIR_CHANGED,   /* some lookup, probe answer or file moved */
};
enum fxc_sdir fxc_sdir_delta(const uint8_t *before, size_t blen,
                             const uint8_t *after, size_t alen);

/* tu.c: decide one candidate TU; false only for memory. */
bool fxc_tu_eval(struct fxc *c, const char *path);
/* tu.c: pass 2, the same-name rule over TUs pass 1 left unaffected. */
bool fxc_name_collisions(struct fxc *c);

/* obligations.c */
/* The first refusal of the narrowed walk wins: reason, "what: path". */
void fxc_refuse(struct fxc *c, const char *reason, const char *what,
                const char *path);
/* Add e of x as a seed; an external seed whose declaring header has a
 * reader without a manifest here sets seed_reason "indirect-unknown". */
bool fxc_seed_add(struct fxc *c, const struct fxi *x, size_t e);
void fxc_check_decl(struct fxc *c, const struct fxi *x, size_t e);
/* A seed whose address some manifest here takes: "address-taken". */
void fxc_check_addresses(struct fxc *c,
                         const struct zcl_devloop_facts_seed *seeds, size_t n);
/* The header path: the narrowed closure, or the file-seeded one. */
bool fxc_obligations(struct fxc *c, const struct zcl_devloop_plan *given,
                     struct zcl_devloop_plan *plan,
                     struct zcl_devloop_facts_verdict *v);
/* The .c path once its rule chain narrowed: the members' seeds (functions
 * another TU compiles from a changed .c it includes) join the walk, which
 * runs again over every changed file and affected TU whenever a member adds
 * a seed or a TU other than a changed file is affected; each broadened
 * member but a changed file's own TU adds its file-seeded plan, as on the
 * header path. */
bool fxc_c_members(struct fxc *c, const struct zcl_devloop_plan *given,
                   struct zcl_devloop_plan *plan,
                   struct zcl_devloop_facts_verdict *v);
/* An incomplete universe: the file-seeded plan, and the whole catalog
 * when nothing bounds the change (c->universal). */
bool fxc_fallback(struct fxc *c, const struct zcl_devloop_plan *given,
                  struct zcl_devloop_plan *plan,
                  struct zcl_devloop_facts_verdict *v);
/* report->plain_groups: the groups of the file-seeded plan. */
bool fxc_plain_count(struct fxc *c, const struct zcl_devloop_plan *given);

/* make.c: for each path asked about (want), whether a makefile names it
 * where make can change an object with it (make), or cannot be read. */
void fxm_classify(const char *root, const char *const *paths, const bool *want,
                  bool *make, size_t n,
                  struct zcl_devloop_facts_report *report);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_FACTS_CONSUMER_H */
