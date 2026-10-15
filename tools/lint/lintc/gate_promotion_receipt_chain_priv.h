/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by gate_promotion_receipt_chain.c, its
 * checks and its selftest.
 */
#ifndef GATE_PROMOTION_RECEIPT_CHAIN_PRIV_H
#define GATE_PROMOTION_RECEIPT_CHAIN_PRIV_H

#include <stddef.h>

/* PRC_ROOT_CAP bounds the repository root path; a longer one is refused. */
enum { PRC_PATH = 4096, PRC_ROOT_CAP = 65536, PRC_GRACE_MS = 5000 };

struct prc_cfg {
    const char *root;
    const char *tool;
    const char *ledger;
    const char *signers;
    const char *ship;
    int grace_ms;
};

struct prc_run {
    const struct prc_cfg *cfg;
    int fail;
    int rc;       /* nonzero stops the gate with this status */
};

/* The refusal `init` must print, exactly, when no signing key is configured. */
extern const char k_prc_want_nokey[];

/* Runs `bash tool args...` with the environment edits and returns its status
 * (127 when it cannot start). mode is an lcp_mode; *out receives captured
 * text with NULs and trailing newlines dropped, as command substitution
 * does. A termination signal returns -1 after stopping the child group. Output
 * that could not be kept whole stops the gate with status 2. */
int prc_bash(struct prc_run *g, const char *const *args, const char *const *set,
             const char *const *unset, int mode, char **out);
/* Same for git with a NULL-terminated argv; out may be NULL. */
int prc_git(struct prc_run *g, char *const argv[], int mode, char **out);
/* malloc'd printf result, or NULL when memory runs out. */
char *prc_fmt(const char *fmt, ...);
int prc_say(const char *fmt, ...);

void prc_check_selftest(struct prc_run *g);
void prc_check_anchor(struct prc_run *g);
void prc_check_ledger(struct prc_run *g);
void prc_check_append_only(struct prc_run *g);
void prc_check_no_key(struct prc_run *g);
void prc_check_ship(struct prc_run *g);

/* Count of lines holding at least one byte, like `grep -c .`; -1 unreadable. */
long prc_count_lines(const char *path);

/* Runs the gate for cfg; returns the process exit code. A termination signal
 * stops the running child, removes the scratch directory and is re-raised, so
 * the function does not return then. */
int prc_gate(const struct prc_cfg *cfg);

#endif
