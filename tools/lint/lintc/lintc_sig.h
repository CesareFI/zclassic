/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: termination-signal bookkeeping shared by lint gates that own a
 * scratch directory or a child process. The handler only stores the signal
 * number; the gate main path polls lsc_pending() after each step, cleans up
 * with signals blocked and ends with lsc_finish(), which restores the default
 * disposition, unblocks and re-raises the signal.
 */
#ifndef LINTC_SIG_H
#define LINTC_SIG_H

#include <signal.h>

/* Blocks SIGINT, SIGTERM and SIGHUP, then installs the recording handler
 * without SA_RESTART and without SA_RESETHAND. Returns 0 or -1. The three
 * signals stay blocked until lsc_unblock() so a scratch directory and its
 * registration are never separated by a delivery. */
int lsc_install(void);
void lsc_unblock(void);
void lsc_block(void);
/* The most recent recorded signal number, 0 when none arrived. */
int lsc_pending(void);
/* Child side, after fork and before exec: default dispositions, empty mask. */
void lsc_reset_in_child(void);
/* Restores SIG_DFL, unblocks and raises sig; returns only if raise fails. */
void lsc_finish(int sig);

#endif
