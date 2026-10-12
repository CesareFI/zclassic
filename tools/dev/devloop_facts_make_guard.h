/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Internal state of the facts consumer's guard reading: which missing optional includes a conditional of the root makefile provably skips, shared by its line reader (make_include.c) and its value reading (make_value.c). */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_MAKE_GUARD_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_MAKE_GUARD_H

#include "devloop_facts_make.h"

/* A missing optional include is made (UNKNOWN) only when make reads its
 * include line. One the root makefile reads only inside a branch that is
 * provably not taken is skipped: ifneq (A,B) fails and ifeq (A,B) holds
 * when both sides provably expand to nothing. "Provably" is a reading that
 * only ever errs toward "may expand to something": each text expands to a
 * bounded set of alternatives, or to any text (any) when it holds a
 * function the reading does not model, a variable with a ?= (but
 * ZCL_TARGET and ZCL_TOR, read at their default under
 * host-target-default-tor), +=, != or define, one another file, a
 * target-specific value, an $(eval) or an undefine can set, one no line
 * assigns (the environment's), one that no branch before the directive
 * surely assigned, or a $(shell) other than the compile epoch's. A
 * variable several branches assign holds the union of their values, less
 * those of a branch make provably does not take (fxg_dead). $(wildcard)
 * globs the tree the plan reads (empty, or any text). What the reading
 * rests on beyond the text is a named premise (ZCL_DEVLOOP_PREMISE_*): two
 * on every skip, the goals', the epoch's or the defaults' where it reads
 * them, recorded with the paths it globbed. A reading whose globbed path
 * a command make runs as it reads names is not used; only one no later
 * than the deciding directive counts when make reads the include in its
 * first parse alone, and a reading make may read again after a restart
 * is not used at all (fxg_rec_named). */
#define FXG_ALTS 64
#define FXG_TEXT 4096
#define FXG_DEPTH 24
#define FXG_ARENA (4u << 20)
#define FXG_MATCHES 64
#define FXG_ARGS 16
#define FXG_CHAIN 32
#define FXG_GOAL '\x06'  /* the command line's goals, a word of their own */
#define FXG_EPOCH '\x07' /* the compile epoch: one path component, or none */
#define FXG_NO UINT32_MAX

enum { FXG_C_NONE, FXG_C_IF, FXG_C_ELSE_IF, FXG_C_ELSE, FXG_C_ENDIF };
/* FXG_DEFAULT: a root ?= line, read as its value only for a variable the
 * premise host-target-default-tor names; any text otherwise. */
enum { FXG_SET, FXG_LAZY, FXG_OPEN, FXG_DEFINE, FXG_DEFAULT };

/* What a text may expand to: one of alt[0..n), or anything (any). */
struct fxg_val {
    const char *alt[FXG_ALTS];
    size_t n;
    bool any;
};

/* One assignment of the root makefile, or one that makes its variable
 * open (FXG_OPEN, FXG_DEFINE: another file's, a target-specific one). */
struct fxg_site {
    char *name;
    const char *value; /* into its line's raw text, past the operator */
    size_t vlen;
    uint32_t line;     /* its root line; FXG_NO for another file's */
    uint8_t op;
};

struct fxg_frame {
    uint32_t cond[FXG_CHAIN]; /* the root lines of the chain's conditions */
    uint32_t n;
    bool plain; /* the open branch is a plain else */
    bool cut;   /* a chain longer than cond[] */
};

struct fxg {
    struct fxm *m;
    struct fxg_site *sites; /* sorted by name, then line */
    size_t nsites, capsites;
    char (*pats)[FXM_NAME_MAX]; /* names an $(eval) or a computed name sets */
    size_t npats, cappats;
    bool open_all; /* a line may set any variable */
    bool epoch_ok; /* zcl_compile_epoch is the root's one define */
    bool sorted;   /* sites are sorted: an open name is a pattern */
    uint8_t *cls;       /* per root line: FXG_C_* */
    uint32_t *site_at;  /* per root line: its site, FXG_NO */
    uint32_t *up;       /* per root line: the branch line that opens the
                         * branch it sits in, FXG_NO at the top level */
    uint32_t *prev;     /* per branch line: the one before it in its chain */
    bool nest_ok;       /* up and prev follow every conditional */
    char *arena;
    size_t used;
    struct fxg_frame frames[FXM_COND_MAX];
    struct zcl_devloop_facts_guard rec; /* the reading of one directive */
    uint32_t rec_at; /* ...and its root line */
    bool remade;     /* make may remake a makefile it read and restart */
    bool rec_full;
};


/* make_value.c: what a text may expand to. */
bool fxg_blank(char ch);
/* Every alternative is the empty text. */
bool fxg_empty(const struct fxg_val *v);
/* The end of the reference whose bracket is s[k]: its closing bracket, or
 * n for none. */
size_t fxg_close(const char *s, size_t k, size_t n);
/* s[0..n) expanded as make would at root line t. */
void fxg_text(struct fxg *g, const char *s, size_t n, uint32_t t, int depth,
              struct fxg_val *out);

/* An $(eval), a computed name or a line the reading cannot follow may set
 * name. */
bool fxg_patterned(const struct fxg *g, const char *name);

/* make_include.c: the sites of name, [*lo, *hi). */
void fxg_range(const struct fxg *g, const char *name, size_t *lo, size_t *hi);
/* Root line `line` sits in a branch make provably does not take: the
 * branch's own condition provably fails, or one before it in its chain
 * provably holds, at that branch or any branch around it. A condition the
 * reading cannot decide keeps the line (make may run it). What the
 * deciding reading used is added to g->rec; an undecided one adds
 * nothing. */
bool fxg_dead(struct fxg *g, uint32_t line, int depth);

#endif
