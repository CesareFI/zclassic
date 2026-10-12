/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded Codex goal effect/recovery contract beneath the worker
 * executor seam. Callbacks retain existing storage and process authority. */
#ifndef ZCL_NATIVE_DEVAGENT_CODEX_GOAL_H
#define ZCL_NATIVE_DEVAGENT_CODEX_GOAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "command/native_devagent_codex_observation.h"
#define CGA_REVISION_CAP 65u
enum cga_operation { CGA_SET = 1, CGA_CLEAR, CGA_INTERRUPT };
enum cga_send_result { CGA_SEND_UNCERTAIN, CGA_SEND_APPLIED };

/* Fixed bounded representation, copied by value into durable records. Goal
 * length is authoritative: whitespace and newlines are never trimmed. The
 * executable/environment roots identify preserved external exact objects;
 * a root alone does not establish execution or environment verification.
 * Revision is a receiver-computed exact observation identity, NOT native CAS.
 * The production callback must verify these bindings before any effect. */
struct cga_command {
    char id[CGA_ID_CAP];
    enum cga_operation operation;
    char thread_id[CGA_ID_CAP];
    char turn_id[CGA_ID_CAP];
    char expected_revision[CGA_REVISION_CAP];
    char workspace[4096];
    char job_id[CGA_ID_CAP];
    int64_t attempt;
    char executable[4096];
    char executable_sha256[65];
    char environment_sha256[65];
    char model[160]; /* requested, never substituted */
    char effort[16]; /* requested */
    char effective_model[160]; /* independently qualified native readback */
    char effective_effort[16];
    unsigned char goal[CGA_GOAL_CAP];
    size_t goal_len;
    int64_t token_budget;
};

struct cga_observation {
    char thread_id[CGA_ID_CAP];
    char turn_id[CGA_ID_CAP];
    char revision[CGA_REVISION_CAP];
    char effective_model[160];
    char effective_effort[16];
    bool goal_present;
    unsigned char goal[CGA_GOAL_CAP];
    size_t goal_len;
    int64_t token_budget;
    enum cga_goal_status status;
    bool turn_terminal;
    /* Native goal accounting; absence must be reported, never guessed zero. */
    bool accounting_present;
    int64_t created_at;
    int64_t updated_at;
    int64_t tokens_used;
    int64_t time_used_seconds;
};

struct cga_ack {
    char command_id[CGA_ID_CAP];
    char thread_id[CGA_ID_CAP];
    char turn_id[CGA_ID_CAP];
};

/* The initial state is all-zero. Recovery loads this entire record through
 * the existing action/receipt owner. No serialization of C struct padding.
 * Accepted, applied, readback, terminal and quiescent are independent facts.
 * No goal operation sets quiescent; only the existing process owner may do so.
 * An uncertain send is never automatically retried, even after readback. */
struct cga_record {
    struct cga_command command;
    struct cga_observation observation; /* exact last qualifying readback */
    bool accepted;
    bool uncertain;
    bool applied;
    bool readback;
    bool terminal;
    bool quiescent;
    bool admission_refused; /* durable native exhaustion; no new SET effect */
};

struct cga_caps {
    const char *version;
    bool native_goal_methods;
    bool runtime_qualified;
    bool exclusive_thread;
};

/* save must durably store the entire immutable binding and state, under the
 * existing owner, before returning true. read returns a bounded independently
 * parsed native observation. send never retries internally. It is called only
 * after accepted+uncertain is durable and must preserve the exact command.
 * A callback failure does not establish that an effect was absent.
 * This API creates no runtime, lock, queue, scheduler or publication receipt. */
struct cga_io {
    void *ctx;
    struct cga_caps caps;
    bool (*save)(void *ctx, const struct cga_record *record);
    bool (*read)(void *ctx, struct cga_observation *out);
    enum cga_send_result (*send)(void *ctx, const struct cga_command *command,
        struct cga_ack *ack);
};

/* CGA_OK qualifies this helper step, not proof that this command was applied.
 * Inspect accepted, applied, readback, terminal and quiescent independently.
 * Reconcile is observation-only: even accepted-only intent may already match.
 * It never infers applied or clears uncertainty from a matching observation.
 * SET readback compares objective and budget; a later paused, blocked, limited
 * or complete status is retained verbatim rather than inferred active. */
enum cga_result cga_execute(const struct cga_io *io,
    const struct cga_command *command, struct cga_record *record,
    char *why, size_t why_cap);
enum cga_result cga_reconcile(const struct cga_io *io,
    struct cga_record *record, char *why, size_t why_cap);

/* Exact installed-protocol JSON-RPC request, newline framed. Does not send,
 * journal or establish capability. Unsupported native expected-revision keys
 * are never invented. On failure a writable out is an empty C string (out[0]
 * is zero); remaining buffer bytes are unspecified, not securely erased.
 * Request ID correlates a reply; it is not server-side idempotency evidence. */
enum cga_result cga_wire_request(const struct cga_command *command,
    char *out, size_t out_cap, char *why, size_t why_cap);

#endif
