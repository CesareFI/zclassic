/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Internal state of the facts consumer's make reader, shared by its text scanner (make.c) and its reach from objects (make_reach.c). */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_MAKE_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_MAKE_H

#include "devloop_facts_consumer.h"

#include <stdint.h>

/* ---- make inputs: the paths the makefile text names ---------------------------- */

/* Make reads a path when a makefile names it: its own name, a literal path
 * or basename, a directory it lives under (with or without a trailing '/':
 * a bare directory handed to a recipe's tool is as much a mention as one
 * spelled with the slash), or a glob or pattern ('*', '?', '[...]', '%')
 * outside a whole-line comment, also under a root the text cannot expand
 * ($(CURDIR)/x). A path-like variable (one definition, no whitespace) is
 * expanded, any other reference matches anything, and a function call is
 * its arguments. What the text cannot be read for is UNKNOWN, and UNKNOWN
 * is a make input.
 *
 * Only a mention where make can change an object with the path counts
 * (docs/work/SEMANTIC_MANIFEST.md, "Build inputs make reads"): every
 * definition, directive and conditional; the rule line and recipe of a
 * reached rule; and a recipe line that can run make. A rule is reached when
 * a target is not a literal .PHONY name (it can build a file), when it is a
 * makefile's first rule (a bare make's goal), or when a .PHONY name of it
 * is spelled by a line that reaches: a directive, the prerequisites of a
 * reached rule, its recipe lines that run make, and the definition of a
 * live variable (one those lines reference or spell). What a line only
 * tests or prints (an $(if) condition, a $(filter) pattern, an $(error)
 * message, an echo) reaches nothing but what runs as it is expanded. An
 * unreached .PHONY rule runs only as a goal someone asks for, and then in
 * full: what it reads is a prerequisite of no object. '%' is a make pattern
 * only in make's own text: in a recipe line or a $(shell) argument it is
 * shell text and matches nothing. A recipe line a conditional leaves
 * without one rule counts, and so does every recipe line under .ONESHELL
 * or .RECIPEPREFIX. */
#define FXM_FILES_MAX 64
#define FXM_TEXT_MAX (64u << 20)
#define FXM_FILE_MAX (1u << 20) /* a file $(file <) reads */
#define FXM_LINE_MAX (8u << 20)
#define FXM_ROUNDS 8
#define FXM_ANY '\x01'
#define FXM_PCT '\x02' /* a '%' that is shell text */
#define FXM_OPEN '\x03' /* a value no text of the line spells */
#define FXM_HIDE_ON '\x04' /* words a call's value never holds alone... */
#define FXM_HIDE_OFF '\x05' /* ...up to here */
#define FXM_WILDS "*%$?[\x01\x03"
#define FXM_NONE UINT32_MAX
#define FXM_COND_MAX 64
#define FXM_NAME_MAX 256

struct fxm_buf {
    char *p;
    size_t n, cap;
};

struct fxm_var {
    char *name;
    char *value; /* NULL: not one path-like definition */
    bool many;   /* value holds one plain definition's many words */
};

/* Where a logical line sits: when its mentions count. */
enum fxm_ctx {
    FXM_ACTIVE, /* a directive or an unplaceable line: always */
    FXM_DEF,    /* a definition: always; reaches when its variable is live */
    FXM_QUIET,  /* a conditional, or a .PHONY line a definition holds:
                 * always; reaches nothing */
    FXM_PHONY,  /* a .PHONY declaration: never */
    FXM_RULE,   /* a rule line: when its rule is reached */
    FXM_RECIPE, /* a recipe line: when its rule is reached, or it runs make */
};

struct fxm_line {
    char *text;     /* expanded */
    char *raw;      /* as written */
    char *name;     /* FXM_DEF: the variable, "" when computed */
    uint32_t from;  /* where what reaches starts: past a rule's or a target-
                     * specific value's colon */
    uint32_t rule;  /* FXM_RULE, FXM_RECIPE */
    uint8_t ctx;
    bool runs_make; /* FXM_RECIPE: may run make */
    bool followed;  /* what it names was reached */
    bool goal_followed; /* ...and, a goal position, what it spells */
    uint8_t file_goal;  /* FXM_RECIPE: 0 not yet known, 1 its makes name only
                         * .PHONY goals, 2 one may name a file */
    bool body;      /* FXM_DEF: a line a define holds */
    uint32_t at;    /* the line of its file it starts on */
    uint32_t file;  /* ...and that file, an index of files */
};

struct fxm_rule {
    char *targets; /* expanded; its .PHONY words NUL-ended once paired */
    bool reached;  /* can build, or run while building, an object: a
                    * file target, or a makefile's first rule (a bare make
                    * runs it) */
};

/* One target word of a .PHONY-only rule. */
struct fxm_pair {
    const char *name;
    uint32_t rule;
};

/* A defined variable: live when something that reaches references it. */
struct fxm_vname {
    const char *name;
    bool live;
    bool shelly; /* a definition may carry shell syntax into a recipe */
    bool goal;   /* its value may be a goal or a prerequisite */
    bool cmd;    /* its value may hold the make command */
};

/* A word of an optional include line that names a file that does not
 * exist: where it was read. */
struct fxm_inc {
    char *path;
    uint32_t file, at;
};

/* The rule a line belongs to as the text is read. */
struct fxm_place {
    uint32_t rule;
    bool in_define;
    char define_name[FXM_NAME_MAX];
    int depth;
    uint32_t open[FXM_COND_MAX]; /* the rule at each open conditional */
    bool moved[FXM_COND_MAX];    /* a branch changed it */
    bool goal;                   /* the file's first rule (make's default goal) seen */
};

struct fxm {
    const char *root;
    struct fxc_strs files; /* makefiles read, repo-relative */
    char *text[FXM_FILES_MAX];
    struct fxm_var *vars;
    size_t nvars, capvars;
    bool unknown;
    bool whole;  /* .ONESHELL, .RECIPEPREFIX: every recipe line counts */
    bool second; /* .SECONDEXPANSION: a prerequisite list is expanded twice */
    bool body;   /* the placed line is one a define holds */
    bool shelly_any; /* any variable may carry shell syntax */
    bool lists;      /* an include line: a many-word value is its words */
    bool pending;    /* a goal position waits on a variable not yet read in one */
    bool probe;      /* goal words are only tested for a file goal... */
    bool file_goal;  /* ...and one was met */
    const char *const *paths;
    const bool *want; /* the paths asked about */
    bool *make;       /* ...and those the text names */
    size_t npaths;
    struct fxm_buf line, a, b;
    char name[FXM_NAME_MAX]; /* the variable the placed line defines */
    size_t from;             /* ...and where what it reaches with starts */
    struct fxm_line *lines;
    size_t nlines, caplines;
    struct fxm_rule *rules;
    size_t nrules, caprules;
    struct fxc_strs phony;  /* literal .PHONY names, sorted */
    struct fxc_strs missing; /* optional includes that do not exist */
    struct fxc_strs goal_names; /* undefined variables goal positions read */
    struct fxc_strs makers; /* variables whose value may run make, sorted */
    struct fxm_pair *pairs;
    size_t npairs;
    struct fxm_vname *vnames; /* every defined variable, sorted */
    size_t nvnames;
    uint32_t pos[2];   /* lines read of the file being read; this one's */
    uint32_t cur_file; /* ...and that file */
    struct fxm_inc *incs; /* each include line word that names a missing file */
    size_t nincs, capincs;
    size_t root_lines; /* the root makefile's lines come first */
    bool inc_depfile;  /* an include names a depfile (not read here) */
    bool inc_outside;  /* ...or a file outside the tree */
    struct zcl_devloop_facts_report *report; /* guards read not taken */
};

/* make.c: the text scanner. */
bool fxm_put(struct fxm_buf *b, const char *s, size_t n);
bool fxm_ident(char ch);
bool fxm_space(char ch);
bool fxm_starts_word(const char *p, const char *w);
bool fxm_all_space(const char *s, size_t n);
bool fxm_literal_span(const char *w, size_t n);
/* The first character of s from set outside any reference; NULL for none. */
const char *fxm_top(const char *s, const char *set);
/* p matches s: '*', '%', '$' and FXM_ANY a run, '?' and '[...]' one. */
bool fxm_glob(const char *p, const char *s);
/* The word t names past a recipe's @, - and + prefixes; NULL for none. */
const char *fxm_word_of(const char *t);
/* ch splits words: a space or a character a name never holds. */
bool fxm_sep(char ch);
/* fn over each word of s; true when any call returned true. */
bool fxm_tokens(struct fxm *m, char *s, bool (*fn)(struct fxm *, const char *));
/* s[0..n) with its path-like variables expanded; NULL when it cannot be. */
const char *fxm_expand(struct fxm *m, const char *s, size_t n);
/* One expansion round of in into out; *left: a reference remains. */
bool fxm_round(struct fxm *m, const char *in, struct fxm_buf *out, bool *left);
/* The ':' of a substitution reference s[0..n) ($(X:a=b)); n for none. */
size_t fxm_subst_colon(const char *s, size_t n);
/* Read a repo makefile once; false when it cannot be held. */
bool fxm_load(struct fxm *m, const char *rel);
/* rel is a regular file under root. */
bool fxm_exists(const char *root, const char *rel);

enum fxm_kind { FXM_K_OTHER, FXM_K_DEF, FXM_K_RULE, FXM_K_TSV };
/* A definition (its operator first), a rule (*colon at its ':'), a
 * target-specific assignment, or anything else. */
enum fxm_kind fxm_kind_of(const char *s, size_t *colon);
/* The variable p defines into out: "" when computed or too long. */
void fxm_def_name(const char *p, char *out);
/* p past its override, export and private prefixes. */
const char *fxm_skip_prefixes(const char *p);
/* w past its leading ./ (repeated, with the slashes after each), as make
 * reads a file name: ./build/gen.mk is build/gen.mk; build//gen.mk stays. */
const char *fxm_strip_dot(const char *w);

/* Read the makefiles, place their lines and reach from the objects: what
 * fxm_classify asks the lines about next. */
void fxm_analyse(struct fxm *m);

/* make_reach.c: which rules run while an object is built. */
/* Blank in s what its calls can never put in their values (an $(if)
 * condition, a $(filter) pattern, an $(error) message), but for what runs
 * as it is expanded. */
void fxm_blank(struct fxm *m, char *s);
void fxm_makers(struct fxm *m);
void fxm_reach(struct fxm *m);
/* A line whose mentions count (see the rule above). */
bool fxm_live(const struct fxm *m, const struct fxm_line *l);
/* The name of the reference at d ($(NAME...), ${NAME...} or $X); its end. */
size_t fxm_ref_name(const char *d, const char **name);
char *fxm_ref_end(char *d);
/* A computed name as a glob over the names it can spell. */
bool fxm_name_glob(const char *name, char *pat);
struct fxm_vname *fxm_vname(struct fxm *m, const char *name, size_t n);
/* Reach every rule the .PHONY name name[0..len) belongs to. */
bool fxm_reach_name(struct fxm *m, const char *name, size_t len);
/* Reach the .PHONY rule a word names, or every one a glob word matches. */
bool fxm_token_phony(struct fxm *m, const char *t);
/* Call fn on every reference in s (with twice, '$$(' too): whether one did. */
bool fxm_each_ref(struct fxm *m, const char *s, bool twice,
                  bool (*fn)(struct fxm *, const char *, size_t));
/* After '>': a redirection that feeds no command and names no file. */
bool fxm_quiet_redirect(const char *p);

/* make_include.c: an include line's words, read or recorded missing. */
void fxm_include(struct fxm *m, const char *line);
/* A missing optional include that a conditional of the root makefile
 * provably skips is dropped from m->missing, and the reading (the
 * directive, the premises, the paths globbed) is recorded in m->report.
 * The reading only ever skips what make cannot read: what it cannot
 * decide is taken (docs/work/SEMANTIC_MANIFEST.md, "Guarded includes").
 * A missing include left that a command make runs as it reads may create
 * (fxm_commands_name of its path, basename or directory), or an existing
 * optional include one may rewrite (of its path or basename), is UNKNOWN,
 * and m->report->make_premise names what the rest of the reading rests on
 * whenever an optional include is read while an unproven command runs. */
void fxm_guards(struct fxm *m);

/* make_goal.c: the .PHONY goals a line names through a value no text
 * spells. */
bool fxm_goal_ref(struct fxm *m, const char *name, size_t n);
bool fxm_goal_words(struct fxm *m, const char *raw, bool twice, bool shell);
/* A line make expands as it reads the makefiles (any but a recipe line,
 * a define's too) runs a $(shell) (or $(call shell,...)) or != command
 * whose text, as written, writes a file (outside quotes, a redirection to
 * anything but a descriptor or /dev/null, or a tee), a $(file) that is not
 * a read, or a $(call $(F),...) that may run any function: what make then
 * includes may be text no line holds. */
bool fxm_parse_writes(const struct fxm *m);
/* A command make runs as it reads the makefiles (a $(shell) body, the
 * same through $(call shell,...), a computed $(call)'s arguments or a !=
 * value, outside recipes) may name `name`: its text holds it, or the
 * definition of a variable the text holds does, transitively; an $(eval)
 * line or a computed name holding it may set any variable, and counts.
 * The empty name is in every command. */
bool fxm_commands_name(const struct fxm *m, const char *name);
/* The same over what make runs and reads no later than root line
 * `before` (another makefile's lines always count): a command on a later
 * root line runs after make read that line. */
bool fxm_commands_name_by(const struct fxm *m, const char *name,
                          uint32_t before);
/* Count, and name the first of, the commands make runs as it reads the
 * makefiles (those above, and an $(eval) of text a reference or $$(
 * computes) that are not provably read-only: one simple command of a
 * program that writes no file, with nothing make or the shell could turn
 * into another command, while no line assigns SHELL, .SHELLFLAGS or PATH. */
void fxm_parse_unproven(const struct fxm *m,
                        struct zcl_devloop_facts_plan_premise *p);
/* A match-anything rule (%:) or .DEFAULT exists while an optional include
 * is missing: it makes that include by a recipe no rule names it in. */
bool fxm_anything_made(const struct fxm *m);
/* A rule whose targets (raw[0..n) as written, t expanded) hold a function
 * call or a value no text spells: UNKNOWN while its text names a missing
 * include's path or basename (fxm_commands_name's variable reading), or
 * its targets or a static rule's target pattern hold a % pattern matching
 * one (directly or through a variable's definition), else
 * counted under computed-targets-not-includes in m->report->make_premise. */
void fxm_target_computed(struct fxm *m, const struct fxm_line *l, size_t n,
                         const char *t);
/* A line that is no definition, directive or rule its text spells and that
 * holds a reference (what it expands to may be a rule): the same reading as
 * fxm_target_computed over its whole text. */
void fxm_line_computed(struct fxm *m, const struct fxm_line *l);
/* The same readings as a question over paths: rule line l, its targets
 * raw[0..n) expanded to t, is computed and its text names one of paths;
 * or (t NULL) l is a line that may be a rule and names one. */
bool fxm_computed_names(const struct fxm *m, const struct fxm_line *l,
                        size_t n, const char *t, const struct fxc_strs *paths);
/* make.c: a makefile make reads (the root one, an existing include, a
 * depfile, one outside the tree) may be remade by a rule, and make then
 * reads every makefile again after what the first parse ran. */
bool fxm_makefiles_remade(struct fxm *m);

#endif
