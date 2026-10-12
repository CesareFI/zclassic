/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private layout shared by the proof context, issuer and shadow. */

#ifndef ZCL_BUILD_FABRIC_PROOF_CONTEXT_INTERNAL_H
#define ZCL_BUILD_FABRIC_PROOF_CONTEXT_INTERNAL_H

#include "models/build_fabric.h"
#include "services/build_fabric_proof_context.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_proof_issuer_log;

/* Counters and tokens the diagnostics thread reads while the worker thread
 * writes. Tokens are string literals, so a pointer swap is the whole write. */
struct bfpc_live {
    _Atomic(const char *) issuer_state;
    _Atomic(const char *) receiver_state;
    _Atomic(const char *) last_issue_refusal;
    _Atomic(const char *) last_attach;
    _Atomic(const char *) last_ticket_outcome;
    _Atomic(const char *) last_ticket_reason;
    _Atomic uint64_t issuer_leaves;
    _Atomic uint64_t receiver_tickets;
    _Atomic uint64_t receiver_checkpoints;
    _Atomic uint64_t receiver_skipped;
    _Atomic uint64_t receiver_catalog_rows;
    _Atomic uint64_t issued;
    _Atomic uint64_t issue_refused;
    _Atomic uint64_t shadow_decisions;
    _Atomic uint64_t shadow_unavailable;
    _Atomic uint64_t ticket_hit;
    _Atomic uint64_t ticket_hit_fail;
    _Atomic uint64_t ticket_miss;
    _Atomic uint64_t ticket_refuse;
    _Atomic uint64_t attach_hit;
    _Atomic uint64_t attach_miss;
    _Atomic uint64_t attach_refused;
    _Atomic uint64_t agree;
    _Atomic uint64_t disagree;
    _Atomic uint64_t disagree_attach_only;
    _Atomic uint64_t disagree_ticket_only;
};

/* The worker thread is the only writer of everything but `live`. */
struct build_fabric_proof_context {
    struct vcs_package_store *store;
    bool owns_store;
    char worker_id[65];
    char signer_hex[65];
    uint8_t seed[32];
    uint8_t pubkey[32];
    uint32_t quorum;
    struct vcs_proof_issuer_log *issuer;
    struct vcs_proof_receiver *receiver;
    /* The row this issuer staged and has not yet seen finalized: the exact
     * wires its last append signed. Issuance completes it before the next
     * append, so the issuer never runs more than one leaf ahead. */
    bool staged;
    struct db_build_worker_proof_pending staged_row;
    struct bfpc_live live;
};

/* The worker table's current trust: approved, unrevoked, unexpired workers
 * verify; revoked workers are revoked. Heap-owned; free with _free. */
struct bfpc_trust {
    uint8_t (*verifiers)[32];
    size_t verifier_count;
    uint8_t (*revoked)[32];
    size_t revoked_count;
};

struct zcl_result bfpc_trust_load(struct node_db *ndb, int64_t now,
                                  struct bfpc_trust *out);
void bfpc_trust_free(struct bfpc_trust *trust);

/* Drop the in-memory issuer and name why; only worker start restores it. */
void bfpc_issuer_pause(struct build_fabric_proof_context *ctx,
                       const char *state);

#ifdef ZCL_TESTING
/* The armed test fault, BUILD_FABRIC_PROOF_FAULT_NONE when none is. */
enum build_fabric_proof_fault bfpc_test_fault_armed(void);
#define BFPC_FAULT(fault) (bfpc_test_fault_armed() == (fault))
#else
#define BFPC_FAULT(fault) false
#endif

#endif /* ZCL_BUILD_FABRIC_PROOF_CONTEXT_INTERNAL_H */
