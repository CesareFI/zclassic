/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by gate_hosted_suite_verdict.c and
 * its self-test.
 */
#ifndef GATE_HOSTED_SUITE_VERDICT_PRIV_H
#define GATE_HOSTED_SUITE_VERDICT_PRIV_H

#include <stdio.h>

/* Diagnostic sink: stderr for the command, NULL while the self-test runs a
 * rejecting mutation. */
extern FILE *g_hsv_err;
void hsv_fail(const char *fmt, ...);
/* 0 when the log is valid cold-suite evidence; a PASS line goes to out. */
int hsv_check_log(const char *path, FILE *out);

#endif
