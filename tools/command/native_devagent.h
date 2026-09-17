/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure, testable primitives behind the dev.agent.* command surface —
 *          checkout-root resolution, SUITE VERDICT parsing, and the
 *          deterministic single-line source mutation used by
 *          dev.agent.mutate. Kept separate from the handlers so a registered
 *          test group can prove them without spawning a build. */

#ifndef ZCL_NATIVE_DEVAGENT_H
#define ZCL_NATIVE_DEVAGENT_H

#include <stdbool.h>
#include <stddef.h>

/* ── SUITE VERDICT ────────────────────────────────────────────────────────
 * test_parallel prints exactly one machine-greppable verdict line:
 *
 *   SUITE VERDICT mode=cold groups_total=N groups_ran=N groups_cached=N
 *     groups_gated=N groups_failed=N self_skips=N env_unobserved=N toolkey=..
 *
 * `groups_ran` is the field that separates "the group passed" from "nothing
 * executed and the runner still printed ALL TESTS PASSED". Every consumer of
 * a test run must read it, so it is parsed once, here. */
#define ZCL_DEVAGENT_MODE_MAX    16
#define ZCL_DEVAGENT_TOOLKEY_MAX 32

struct zcl_devagent_verdict {
    bool present;               /* a SUITE VERDICT line was found at all */
    char mode[ZCL_DEVAGENT_MODE_MAX];       /* "cold" | "cached" */
    char toolkey[ZCL_DEVAGENT_TOOLKEY_MAX];
    long long groups_total;
    long long groups_ran;
    long long groups_cached;
    long long groups_gated;
    long long groups_failed;
    long long self_skips;
    long long env_unobserved;
    bool hotswap;               /* the run executed a hot-swapped module */
};

/* Parse the LAST `SUITE VERDICT` line in `text`. `out` is always initialized;
 * returns out->present. Missing numeric fields stay -1 so an absent field can
 * never be mistaken for a zero. */
bool zcl_devagent_verdict_parse(const char *text,
                                struct zcl_devagent_verdict *out);

/* ── closed completion vocabulary ─────────────────────────────────────────
 * Only an explicit "pass"/"PASS" verdict with a clean exit completes a
 * queue directive: "pass" is the long-standing explicit allowlist entry and
 * "PASS" is what the tree's own receipt producers emit. Anything else —
 * fail words, "completed", unknown strings, case variants, a missing
 * verdict — stays incomplete no matter what rc says, and a pass claim
 * contradicted by a nonzero exit does not complete either. rc == 0 alone
 * is never completion evidence. One shared predicate so the claim refusal,
 * the worker gate, and the gateway evidence paths cannot drift apart. */
bool zcl_devagent_closed_pass(const char *verdict, long long rc);

/* ── the one directive-name grammar ───────────────────────────────────────
 * A queue row is a directory named by its name, and a steer directive names
 * the row it is meant to become. So both must accept exactly the same
 * strings: [A-Za-z0-9_.-], 1..64 bytes, never "." or "..", never empty.
 * A '/' is off the alphabet, so a path-shaped name cannot escape the run
 * directory and cannot reach a second segment.
 *
 * One shared predicate because the two ends drifted once: fleet.steer.send
 * accepted a ref that dev.agent.queue then refused with BAD_INPUT, which
 * wrote mail describing work that could never be dispatched. Anything that
 * names queue work validates here, so that gap cannot reopen. */
#define ZCL_DEVAGENT_NAME_MAX 64u

bool zcl_devagent_name_ok(const char *name);

/* ── resident dev worker ──────────────────────────────────────────────────
 * The dev-only loop that consumes dev.agent.queue continuously. One active
 * job per worker; the queue stays the only ledger (claim/running/outcome
 * rows), mail carries result copies, receipts judge runs. The MODEL
 * EXECUTION SEAM is wkr_executor_fn: the production binary wires "no
 * executor yet" until C's muse_session drops in; tests wire fixtures. A
 * worker terminal of "completed" is never success by itself — only the
 * closed predicate over the gated receipt advances completion. */

/* Bounded drive options. Strings are NUL-terminated on entry; over-long
 * values are refused by the leaf before the drive starts. */
struct wkr_drive_opts {
    char worker[56];      /* resident worker identity, required */
    char session[56];     /* this worker run, required */
    char model[160];      /* model id hint for the executor, may be empty */
    long long deadline_s; /* stop claiming after this many seconds */
    long long idle_start_s; /* first idle wait on an empty queue */
    long long idle_limit_s; /* stop after this much consecutive idle */
    long long max_jobs;   /* stop after this many jobs (0 = deadline only) */
    long long time_cap_s; /* wall clock per executor run */
    long long cpu_s;      /* RLIMIT_CPU per executor run */
    long long mem_mb;     /* RLIMIT_AS per executor run */
    long long token_cap;  /* token budget handed to the executor */
};

/* One claimed unit of work. task is executor-ready text; rundir owns
 * claim.json, receipt.json, run.out and the executor result file. */
struct wkr_job {
    char rundir[4096];
    char name[80];
    char kind[16];
    long long attempt;
    long long seq;
    char task[8192];
    char model[160];
    long long token_cap;
    long long time_cap_s;
};

/* Executor outcome. terminal is the executor's own word ("completed" is
 * NOT success); candidate names the produced diff/artifact for the gate. */
struct wkr_result {
    char terminal[32];
    long long rc;
    char candidate[192];
    char evidence[2048];
    long long tokens_used;
    long long wall_ms;
};

/* Model execution seam. True when the executor ran and filled res (even
 * on executor failure); false when no executor is wired. Production
 * C muse_session integration replaces the wired function, never the
 * loop around it. */
typedef bool (*wkr_executor_fn)(const struct wkr_job *job,
                                struct wkr_result *res);

/* Drive the loop until the deadline, idle limit, or job cap. Returns
 * jobs processed (>= 0), or -1 when the worker lock or state root
 * refuses. Single worker per queue: a second concurrent drive refuses. */
long long zcl_devagent_worker_drive(const struct wkr_drive_opts *opts,
                                    wkr_executor_fn exec);

/* Production executor stub: wired until C's muse_session arrives. Always
 * returns false so a job is never executed without a real executor. */
bool zcl_devagent_worker_no_executor(const struct wkr_job *job,
                                     struct wkr_result *res);

/* Production Muse executor (C): adapts one claimed job to one bounded
 * muse_run_task and maps the structured result back. Declared here
 * beside the seam it implements; defined in
 * tools/command/native_devagent_muse_executor.c. */
bool zcl_devagent_worker_muse_executor(const struct wkr_job *job,
                                       struct wkr_result *res);

/* ── resident mail receiver ───────────────────────────────────────────────
 * The dev-only loop that turns a directive arriving in this box's agent
 * mail into a dev.agent.queue row and answers the sender under the same
 * ref. It never executes anything: dev.agent.worker's own resident loop
 * runs the job and posts the result. Admission is the EXISTING fleet.steer
 * grant store read by label (zcl_fleet_steer_grant_label_live), which means
 * "the owner has named this sender" and NOT "this peer was authenticated" —
 * nothing in this tree signs a peer's mail row today. */

/* Bounded drive options. `receiver` is this box's mail identity. */
struct rcv_drive_opts {
    char receiver[56];
    long long deadline_s; /* stop beating after this many seconds */
    long long wait_ms;    /* idle ceiling for one mail-watch wait */
    long long max_beats;  /* stop after this many beats (0 = deadline only) */
};

/* What one drive (or one read-only survey) observed. Counts only; no row
 * content ever leaves the loop. */
struct rcv_beat_stats {
    long long beats;
    long long seen;          /* directives addressed to this receiver */
    long long admitted;      /* newly queued refs */
    long long reconciled;    /* known refs whose stored brief matched */
    long long refused;        /* typed refusals, conflicts included */
    long long already;        /* rows this receiver had already answered */
    long long intake_failed;  /* beats whose mail pull did not answer */
};

/* Drive the resident loop until SIGTERM, the deadline, or the beat cap.
 * Returns beats completed (>= 0), or -1 when the singleton lock or the
 * state root refuses. Single instance: a second concurrent drive refuses
 * immediately and never waits. `st` may be NULL. */
long long zcl_devagent_receive_drive(const struct rcv_drive_opts *opts,
                                     struct rcv_beat_stats *st);

/* Decide exactly what one beat would decide, and write and post nothing.
 * This is what the status action reports; it creates no directory, no
 * brief, no queue row, no marker and no mail. Returns beats surveyed (1),
 * or -1 on a bad receiver name or an unresolvable state root. */
long long zcl_devagent_receive_survey(const char *receiver,
                                      struct rcv_beat_stats *st);

/* ── single-line source mutation ──────────────────────────────────────────
 * One deterministic edit to one line, chosen by the first applicable rule in
 * a left-to-right scan of the line's CODE regions (string literals, character
 * literals and trailing `//` comments are skipped). A line whose first
 * non-blank character starts a comment is refused outright: from one line
 * alone a block-comment interior is indistinguishable from code. */
#define ZCL_DEVAGENT_RULE_MAX  24
#define ZCL_DEVAGENT_TOKEN_MAX 24

struct zcl_devagent_mutation {
    char rule[ZCL_DEVAGENT_RULE_MAX];   /* e.g. "eq_to_ne" */
    char before[ZCL_DEVAGENT_TOKEN_MAX];
    char after[ZCL_DEVAGENT_TOKEN_MAX];
    size_t column;                      /* 1-based column of the edit */
};

/* Write the mutated form of `line` (which must NOT contain a newline) into
 * `out`. Returns false and leaves `out`/`m` zeroed when no rule applies —
 * that is a refusal the caller must report, never a silent no-op. */
bool zcl_devagent_mutate_line(const char *line, struct zcl_devagent_mutation *m,
                              char *out, size_t out_cap);

/* ── checkout root ────────────────────────────────────────────────────────
 * Walk up from `start` (NULL = current directory) until a directory carries
 * all three checkout markers. Returns false when none does — the caller must
 * then say so rather than guessing a root and writing somewhere else. */
bool zcl_devagent_checkout_root(const char *start, char *out, size_t out_cap);

/* ── bounded process helpers ──────────────────────────────────────────────
 * Not pure: these spawn (never through a shell) and are shared by the
 * dev.agent.* handlers. Both run from `root` and restore the caller's
 * directory before returning. A negative return is a launch failure. */
int zcl_devagent_run_make(const char *root, const char *target, int timeout_ms);

/* Run build/bin/test_parallel with one already-formed selector
 * ("--exact=x" / "--only=x") and --no-cache. `out` is always initialized; a
 * run whose transcript overflowed the capture buffer sets *truncated and
 * leaves out->present false rather than parsing a partial transcript. */
int zcl_devagent_run_group(const char *root, const char *selector,
                           int timeout_ms, struct zcl_devagent_verdict *out,
                           bool *truncated);

#endif /* ZCL_NATIVE_DEVAGENT_H */
