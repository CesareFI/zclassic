/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by gate_tor_provenance.c and its
 * selftest.
 */
#ifndef GATE_TOR_PROVENANCE_PRIV_H
#define GATE_TOR_PROVENANCE_PRIV_H

#include <stddef.h>

enum { TP_PATH = 4096, TP_GRACE_MS = 5000 };

/* Runs the gate for the repository at root; returns the process exit code.
 * A termination signal stops the running child, removes the scratch
 * directory and is re-raised, so the function does not return then. */
int tp_gate(const char *root, int grace_ms);

/* The value awk -F= would print as $2 for the first "CC =" line, with its
 * leading blanks removed. Returns 1 when line is such a line. */
int tp_cc_from_line(const char *line, char *out, size_t cap);

#endif
