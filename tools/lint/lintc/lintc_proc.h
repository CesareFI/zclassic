/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: run one child process for a lint gate that owns lintc_sig.h
 * signal bookkeeping. The child leads its own process group, so a
 * termination signal, and the SIGKILL that follows once the grace period
 * ends, reach everything it started. Output is captured into a growable
 * buffer with a generous cap.
 */
#ifndef LINTC_PROC_H
#define LINTC_PROC_H

#include <stddef.h>

enum lcp_mode {
    LCP_QUIET, /* stdout and stderr discarded */
    LCP_OUT,   /* stdout captured, stderr discarded */
    LCP_BOTH,  /* stdout and stderr captured as one stream */
    LCP_ERR    /* stderr captured, stdout discarded */
};

/* Captured bytes beyond this size are drained and dropped, and the run is
 * flagged LCP_LOST_TRUNCATED. */
enum { LCP_CAP = 64 * 1024 * 1024 };

enum { LCP_LOST_NONE = 0, LCP_LOST_TRUNCATED = 1, LCP_LOST_NOMEM = 2 };

struct lcp_buf {
    char *data; /* NUL-terminated once a run captured anything */
    size_t len;
    int lost;   /* nonzero: data is incomplete; a gate must report it, not judge it */
};

struct lcp_spec {
    char *const *argv;            /* NULL-terminated; argv[0] is searched in PATH */
    const char *const *setenv;    /* "NAME=value" entries, NULL-terminated, or NULL */
    const char *const *unsetenv;  /* names, NULL-terminated, or NULL */
    enum lcp_mode mode;
    int grace_ms;                 /* wait after a forwarded signal before SIGKILL */
};

/* Requires lsc_install() to have run. Returns 0 with *code set (the exit
 * status, or 128 plus the signal number), 1 when a termination signal was
 * forwarded and the child group reaped (the caller cleans up and calls
 * lsc_finish), -1 when the child could not be started. out may be NULL. */
int lcp_run(const struct lcp_spec *s, struct lcp_buf *out, int *code);

void lcp_buf_free(struct lcp_buf *b);
/* Drops NUL bytes and trailing newlines, as shell command substitution does. */
void lcp_buf_subst(struct lcp_buf *b);

#endif
