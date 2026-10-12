/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Build-fabric application records. These tables are each full node's durable
 * requester/executor ledger; compiler outputs remain content-addressed CAS objects. They are
 * operator/development state and are never consulted by consensus. */

#ifndef ZCL_DB_MODEL_BUILD_FABRIC_H
#define ZCL_DB_MODEL_BUILD_FABRIC_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    BUILD_FABRIC_ID_HEX = 64,
    BUILD_FABRIC_KIND_MAX = 63,
    BUILD_FABRIC_TARGET_MAX = 63,
    BUILD_FABRIC_PROFILE_MAX = 31,
    BUILD_FABRIC_STATE_MAX = 23,
    BUILD_FABRIC_OUTCOME_MAX = 23,
    BUILD_FABRIC_ERROR_MAX = 255,
    BUILD_FABRIC_CAPS_MAX = 1023,
    BUILD_FABRIC_CONFINEMENT_MAX = 255,
    BUILD_FABRIC_DESCRIPTOR_MAX = 255,
    BUILD_FABRIC_SIGNATURE_HEX = 128,
    BUILD_FABRIC_TRUST_STATE_MAX = 23,
    BUILD_FABRIC_ATTACH_SCAN_CAP = 256,
    BUILD_FABRIC_PROOF_HEADS_MAX = 256,
    /* Exact v1 signed wire lengths; proof integration must check them against
     * the canonical vcs/proof_ticket.h constants at compile time. */
    BUILD_FABRIC_PROOF_TICKET_WIRE_BYTES = 360,
    BUILD_FABRIC_PROOF_CHECKPOINT_WIRE_BYTES = 224,
};

struct db_build_job {
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    char source_sha256[BUILD_FABRIC_ID_HEX + 1];
    char source_cas_sha3[BUILD_FABRIC_ID_HEX + 1];
    char toolchain_sha3[BUILD_FABRIC_ID_HEX + 1];
    char profile[BUILD_FABRIC_PROFILE_MAX + 1];
    char state[BUILD_FABRIC_STATE_MAX + 1];
    char outcome[BUILD_FABRIC_OUTCOME_MAX + 1];
    int cancel_requested;
    int64_t created_at;
    int64_t updated_at;
};

struct db_build_action {
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    int64_t sequence;
    char kind[BUILD_FABRIC_KIND_MAX + 1];
    char state[BUILD_FABRIC_STATE_MAX + 1];
    char outcome[BUILD_FABRIC_OUTCOME_MAX + 1];
    char input_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char task_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char candidate_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char proof_policy_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char context_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char target[BUILD_FABRIC_TARGET_MAX + 1];
    char flags_sha3[BUILD_FABRIC_ID_HEX + 1];
    char environment_sha3[BUILD_FABRIC_ID_HEX + 1];
    char virtual_workdir[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char declared_outputs[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char resource_policy[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char output_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char lease_id[BUILD_FABRIC_ID_HEX + 1];
    char last_error[BUILD_FABRIC_ERROR_MAX + 1];
    int64_t lease_expires_at;
    int64_t lease_heartbeat_at;
    int64_t attempt_count;
    int64_t claimed_at;
    int64_t started_at;
    int64_t finished_at;
    int64_t created_at;
    int64_t updated_at;
};

struct db_build_worker {
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char signer_pubkey[BUILD_FABRIC_ID_HEX + 1];
    /* Local issuer's latest signed checkpoint's content.v2 blob root.
     * Empty until the first complete ticket/checkpoint publication. */
    char proof_checkpoint_head_sha3[BUILD_FABRIC_ID_HEX + 1];
    char capabilities[BUILD_FABRIC_CAPS_MAX + 1];
    int approved;
    int revoked;
    int64_t approved_at;
    int64_t expires_at;
    int64_t last_seen_at;
};

/* A single SQLite statement snapshots every locally anchored issuer, including
 * revoked workers. Any pending publication refuses as incomplete, including
 * the first one before a head exists. Eligibility belongs to the receiver.
 * The result is volatile: replay CAS and recheck heads before publication. */
struct db_build_worker_proof_head {
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char signer_pubkey[BUILD_FABRIC_ID_HEX + 1];
    char checkpoint_blob_root[BUILD_FABRIC_ID_HEX + 1];
};

/* One transient publication intent on the existing worker authority row.
 * Cleared with the head CAS. These bytes are never proof authority: callers
 * must validate the signed wires and content.v2 CAS before finalization. */
struct db_build_worker_proof_pending {
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char signer_pubkey[BUILD_FABRIC_ID_HEX + 1];
    char expected_head[BUILD_FABRIC_ID_HEX + 1];
    uint8_t ticket_wire[BUILD_FABRIC_PROOF_TICKET_WIRE_BYTES];
    uint8_t checkpoint_wire[BUILD_FABRIC_PROOF_CHECKPOINT_WIRE_BYTES];
};

struct db_build_receipt {
    char receipt_id[BUILD_FABRIC_ID_HEX + 1];
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char lease_id[BUILD_FABRIC_ID_HEX + 1];
    char action_sha3[BUILD_FABRIC_ID_HEX + 1];
    char output_sha3[BUILD_FABRIC_ID_HEX + 1];
    char observation_sha3[BUILD_FABRIC_ID_HEX + 1];
    char work_receipt_sha3[BUILD_FABRIC_ID_HEX + 1];
    char signature[BUILD_FABRIC_SIGNATURE_HEX + 1];
    char confinement[BUILD_FABRIC_CONFINEMENT_MAX + 1];
    char trust_state[BUILD_FABRIC_TRUST_STATE_MAX + 1];
    int exit_status;
    int64_t created_at;
};

struct ar_callbacks *db_build_job_callbacks(void);
struct ar_callbacks *db_build_action_callbacks(void);
struct ar_callbacks *db_build_worker_callbacks(void);
struct ar_callbacks *db_build_receipt_callbacks(void);

bool db_build_job_validate(const struct db_build_job *row,
                           struct ar_errors *errors);
bool db_build_action_validate(const struct db_build_action *row,
                              struct ar_errors *errors);
bool db_build_worker_validate(const struct db_build_worker *row,
                              struct ar_errors *errors);
bool db_build_receipt_validate(const struct db_build_receipt *row,
                               struct ar_errors *errors);

bool db_build_job_save(struct node_db *ndb, const struct db_build_job *row);
bool db_build_action_save(struct node_db *ndb,
                          const struct db_build_action *row);
bool db_build_worker_save(struct node_db *ndb,
                          const struct db_build_worker *row);
/* First-use enrollment only. A conflicting identity is left untouched and
 * reported through already_exists; hooks fire only for an inserted row. */
bool db_build_worker_insert_if_absent(struct node_db *ndb,
    const struct db_build_worker *row, bool *already_exists);
/* Conditional content.v2 checkpoint-blob pointer update. Caller prepares the
 * exact signed ticket and checkpoint wire, handles their crash-safe CAS
 * publication, and never treats a missing anchored blob as empty history.
 * A stale head or changed signer refuses. The SQL update is atomic across
 * handles; callers can wrap it in a transaction with adjacent writes. */
bool db_build_worker_proof_head_cas(struct node_db *ndb,
    const char *worker_id, const char *expected_signer,
    const char *expected_head, const char *next_head);
/* Stage exact signed wires before either immutable CAS put. Read returns 1
 * pending, 0 idle, -1 missing/corrupt/SQL failure; output clears on refusal.
 * Finalize requires the staged bytes, signer, and base head still match.
 * Caller verifies both CAS blobs and checkpoint ancestry first. */
bool db_build_worker_proof_pending_stage(
    struct node_db *ndb, const struct db_build_worker_proof_pending *pending);
int db_build_worker_proof_pending_find_checked(
    struct node_db *ndb, const char *worker_id,
    struct db_build_worker_proof_pending *out);
bool db_build_worker_proof_pending_finalize(
    struct node_db *ndb, const struct db_build_worker_proof_pending *pending,
    const char *next_head);
bool db_build_receipt_save(struct node_db *ndb,
                           const struct db_build_receipt *row);

bool db_build_job_find(struct node_db *ndb, const char *job_id,
                       struct db_build_job *out);
bool db_build_action_find(struct node_db *ndb, const char *action_id,
                          struct db_build_action *out);
bool db_build_worker_find(struct node_db *ndb, const char *worker_id,
                          struct db_build_worker *out);
/* Enrollment needs to distinguish absence from an unreadable trust row.
 * Returns 1 when found, 0 when absent, and -1 on any database failure. */
int db_build_worker_find_checked(struct node_db *ndb, const char *worker_id,
                                 struct db_build_worker *out);
bool db_build_receipt_find(struct node_db *ndb, const char *receipt_id,
                           struct db_build_receipt *out);

int db_build_jobs_recent(struct node_db *ndb, struct db_build_job *out,
                         size_t max);
int db_build_job_actions(struct node_db *ndb, const char *job_id,
                         struct db_build_action *out, size_t max);
/* Error-aware variants for decisions requiring a complete scan. Return -1
 * on any query failure and clear partial rows; call with max+1 to detect
 * truncation. The legacy list APIs retain their zero-on-error behavior. */
int db_build_jobs_recent_checked(struct node_db *ndb,
                                 struct db_build_job *out, size_t max);
int db_build_job_actions_checked(struct node_db *ndb, const char *job_id,
                                 struct db_build_action *out, size_t max);
/* Attachment refuses a partial sibling history and settles only under the
 * caller's BEGIN IMMEDIATE transaction and complete donor-scan fence. */
bool db_build_attach_ledger_version(struct node_db *ndb, sqlite3_int64 *out);
bool db_build_attach_settle_job(struct node_db *ndb,
                                const struct db_build_job *job, int64_t now);
/* Checked form: -1 on any query failure (rows cleared); call with max+1 to
 * detect truncation. Trust decisions must use this one. */
int db_build_workers_list_checked(struct node_db *ndb,
                                  struct db_build_worker *out, size_t max);
int db_build_workers_list(struct node_db *ndb, struct db_build_worker *out,
                          size_t max);
/* Returns the complete ordered head set, -1 on query/corrupt-row failure, or
 * -2 if it exceeds max. Any refusal clears all written rows. max must be in
 * [1, BUILD_FABRIC_PROOF_HEADS_MAX]; a successful count is never truncated. */
int db_build_worker_proof_heads_snapshot(
    struct node_db *ndb, struct db_build_worker_proof_head *out, size_t max);
int db_build_job_receipts(struct node_db *ndb, const char *job_id,
                          struct db_build_receipt *out, size_t max);
int db_build_job_receipts_checked(struct node_db *ndb, const char *job_id,
                                  struct db_build_receipt *out, size_t max);
/* Returns a bounded count, or -1 on invalid input or any query failure.
 * Partial rows are cleared on failure. Request max+1 to detect overflow;
 * a successful LIMIT alone does not establish complete receipt coverage. */
int db_build_candidate_receipts(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_receipt *out, size_t max);
/* Returns a bounded count, or -1 when the query cannot be read completely.
 * A count equal to max does not establish complete candidate coverage;
 * callers requiring it must request one extra row and refuse overflow. */
int db_build_candidate_actions(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_action *out, size_t max);

/* One indexed successor among locally recorded candidate roots for a task.
 * Empty after starts enumeration; duplicate actions do not repeat a root.
 * Returns 1 for a root, 0 for end, -1 for invalid input or query failure.
 * Clears out on end/failure. This is discovery, not acceptance or a snapshot
 * across calls; absent local rows do not establish global completeness. */
int db_build_task_candidate_next(struct node_db *ndb, const char *task,
    const char *after, char out[BUILD_FABRIC_ID_HEX + 1]);

/* Lease writes are compare-and-swap operations. A queued action can be
 * claimed once; every later mutation compares the observed state, lease id,
 * worker, attempt, expiry and heartbeat. Expired reads are bounded and ordered
 * for crash recovery. */
int db_build_actions_queued(struct node_db *ndb,
                            struct db_build_action *out, size_t max);
int db_build_actions_expired(struct node_db *ndb, int64_t now,
                             struct db_build_action *out, size_t max);
bool db_build_action_claim_queued(struct node_db *ndb,
                                  const struct db_build_action *next);
bool db_build_action_save_leased(struct node_db *ndb,
                                 const struct db_build_action *next,
                                 const struct db_build_action *expected);
/* Recovery may clear only the exact expired lease snapshot it observed.
 * A concurrent renewal or new attempt leaves the action untouched. */
bool db_build_action_requeue_expired(struct node_db *ndb,
    const struct db_build_action *next,
    const struct db_build_action *expected, int64_t now);
/* Renewal retains the same lease generation and compares its observed
 * expiry and heartbeat, so a delayed writer cannot replace a newer renewal. */
bool db_build_action_renew_lease(struct node_db *ndb,
    const struct db_build_action *next,
    const struct db_build_action *expected);
/* Bind the request-scoped content carrier after foreground admission. The
 * immutable action identity excludes this root; a nonempty different root is
 * never overwritten while an action is active. */
bool db_build_action_bind_context(struct node_db *ndb, const char *action_id,
                                  const char *context_root_sha3);

#endif /* ZCL_DB_MODEL_BUILD_FABRIC_H */
