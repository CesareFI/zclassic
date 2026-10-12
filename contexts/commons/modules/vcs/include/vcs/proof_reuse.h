/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Issuer ticket logs, the receiver's checkpoint-verified ticket
 *          set, and the exact-key reuse decision over it.
 *
 * Trust flows one way. A producer (issuer) appends signed tickets to its own
 * log and signs checkpoints over the log's MMR root. A receiver syncs a
 * checkpoint plus only the tickets it has not seen, and accepts them when
 * its verified prefix plus that delta reproduces the signed root. Only a
 * ticket covered by such a checkpoint can support reuse.
 *
 * Nothing about AUTHORITY is cached at ingest: verifier membership,
 * revocation, the candidate trust domain and the policy root are all read
 * from the request at decision time. What ingest retains is bytes, roots,
 * coverage and equivocation evidence, all facts about signed data.
 *
 * Contradictions are kept. PASS and FAIL for one key are both retained and
 * refuse reuse with `proof_observation_conflict`; two signed checkpoints
 * that cannot both be true mark their issuer equivocating, keep both, and
 * make every ticket of that issuer ineligible (`issuer_equivocation`).
 */

#ifndef ZCL_VCS_PROOF_REUSE_H
#define ZCL_VCS_PROOF_REUSE_H

#include "vcs/proof_ticket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Issuer log (producer side) ─────────────────────────────────────── */

struct vcs_proof_issuer_log;
struct vcs_package_store;

/* The seed stays in memory for this log's lifetime and is wiped on free. */
struct vcs_proof_issuer_log *vcs_proof_issuer_log_new(const uint8_t seed[32]);
/* Rebuild a writable issuer log from complete signed ticket wires covered by
 * the caller's durable exact checkpoint head. The caller must establish that
 * expected_head_root is the latest published head for this issuer, and must
 * not expose an uncheckpointed tail. A missing page, stale head or replay
 * above max_tickets refuses; no partial log is returned. */
struct vcs_proof_issuer_log *vcs_proof_issuer_log_restore(
    const uint8_t seed[32], const uint8_t *const *tickets,
    const size_t *ticket_lens, size_t count, size_t max_tickets,
    const uint8_t *checkpoint, size_t checkpoint_len,
    const uint8_t expected_head_root[VCS_PROOF_ROOT_BYTES]);
/* Reconstruct a writable issuer from a complete, generation-checked package
 * catalog and the durable content.v2 checkpoint blob head. NULL head means
 * no ticket or checkpoint by this issuer may exist. Refuses signed forks,
 * uncheckpointed tails, stale heads, missing CAS and exhausted work bounds.
 * The caller must fence package-store imports/deletion, its database head,
 * and the local issuer writer across recovery and subsequent issuance. A
 * successful return is a checked snapshot, not a permanent store lock. */
struct vcs_proof_issuer_log *vcs_proof_issuer_log_restore_from_store(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets);
/* Same verified replay, returning the exact catalog generation and selected
 * ticket/head CAS chunk hashes at its guarded publication point. Caller owns
 * *chunk_hashes_out and frees it. All outputs clear on refusal. */
struct vcs_proof_issuer_log *vcs_proof_issuer_log_restore_from_store_at_generation(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets, uint64_t *generation_out,
    uint8_t (**chunk_hashes_out)[32], size_t *chunk_count_out);
/* Reconstruct and replace an in-memory issuer projection while the store
 * generation, catalog, selected issuer ticket chunks and head chunk remain
 * guarded. Failure leaves *live unchanged. The replaced log is freed after
 * the guard releases. The caller fences readers of *live and the local issuer
 * writer across this call; this does not advance any durable database head. */
bool vcs_proof_issuer_log_restore_publish_from_store(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets,
    struct vcs_proof_issuer_log **live);
void vcs_proof_issuer_log_free(struct vcs_proof_issuer_log *log);
void vcs_proof_issuer_log_pubkey(const struct vcs_proof_issuer_log *log,
                                 uint8_t out[VCS_PROOF_PUBKEY_BYTES]);
/* Stamp issuer_seq, sign, encode and append one ticket. */
bool vcs_proof_issuer_log_append(struct vcs_proof_issuer_log *log,
                                 struct vcs_proof_ticket_v1 *ticket,
                                 uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES]);
/* Sign a checkpoint over the whole log, chained to the previous one. */
bool vcs_proof_issuer_log_checkpoint(
    struct vcs_proof_issuer_log *log, uint64_t created_unix,
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES]);
uint64_t vcs_proof_issuer_log_count(const struct vcs_proof_issuer_log *log);
/* The retained wire at `seq`, NULL out of range. */
const uint8_t *vcs_proof_issuer_log_ticket(
    const struct vcs_proof_issuer_log *log, uint64_t seq);

/* ── Receiver ───────────────────────────────────────────────────────── */

struct vcs_proof_receiver;

struct vcs_proof_receiver *vcs_proof_receiver_new(void);
void vcs_proof_receiver_free(struct vcs_proof_receiver *r);

/* Retain a ticket that arrived outside a log sync. It stays ineligible
 * (`not_checkpointed`) until a verified checkpoint covers it. Duplicate
 * observation roots are not appended twice (*added=false). */
bool vcs_proof_receiver_add_ticket(struct vcs_proof_receiver *r,
                                   const uint8_t *wire, size_t len,
                                   bool *added);
/* Retained observations for `input_key` (covered or not), insertion
 * order. Fills at most `cap` wire pointers; returns the total. */
size_t vcs_proof_receiver_lookup(const struct vcs_proof_receiver *r,
                                 const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
                                 const uint8_t **wires, size_t cap);
size_t vcs_proof_receiver_ticket_count(const struct vcs_proof_receiver *r);

enum vcs_proof_sync_outcome {
    VCS_PROOF_SYNC_ADVANCED = 0,  /* delta verified, coverage extended */
    VCS_PROOF_SYNC_CURRENT,       /* already verified this checkpoint */
    VCS_PROOF_SYNC_EQUIVOCATION,  /* issuer signed a contradiction */
    VCS_PROOF_SYNC_REFUSED,       /* could not verify; nothing changed */
};

#define VCS_PROOF_SYNC_WHY_OK "ok"
#define VCS_PROOF_SYNC_WHY_MALFORMED "checkpoint_malformed"
#define VCS_PROOF_SYNC_WHY_SIGNATURE "checkpoint_signature_invalid"
#define VCS_PROOF_SYNC_WHY_GAP "checkpoint_gap"
#define VCS_PROOF_SYNC_WHY_UNVERIFIABLE "checkpoint_unverifiable"
#define VCS_PROOF_SYNC_WHY_COUNT "delta_count_mismatch"
#define VCS_PROOF_SYNC_WHY_DELTA "delta_invalid"
#define VCS_PROOF_SYNC_WHY_EQUIVOCATION "issuer_equivocation"
#define VCS_PROOF_SYNC_WHY_RESOURCES "sync_resources"

struct vcs_proof_sync_report {
    enum vcs_proof_sync_outcome outcome;
    const char *reason;
    uint64_t leaves_before;
    uint64_t leaves_after;
    uint64_t bytes;          /* checkpoint + delta wire bytes consumed */
};

/* Verify `checkpoint` against this receiver's verified prefix for its
 * issuer plus `delta` (the issuer's tickets at seq leaves_before..count-1,
 * in order). Returns false only for caller errors; every verdict about the
 * data, including REFUSED, is a true return with a named reason. */
bool vcs_proof_receiver_sync(struct vcs_proof_receiver *r,
                             const uint8_t *checkpoint, size_t checkpoint_len,
                             const uint8_t *const *delta,
                             const size_t *delta_lens, size_t delta_count,
                             struct vcs_proof_sync_report *out);
/* Verified leaf count for an issuer: where its next delta starts. */
uint64_t vcs_proof_receiver_issuer_leaves(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);
bool vcs_proof_receiver_issuer_equivocating(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);
/* True when a rebuild could not replay this issuer's stored history (a
 * covered ticket, a checkpoint ancestor or a complete ticket branch is
 * missing, or its signed ancestry is invalid) and so isolated it: none of
 * its tickets is eligible, while every other issuer was still rebuilt. */
bool vcs_proof_receiver_issuer_history_incomplete(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);
/* Signed checkpoints retained for an issuer, including every side of an
 * equivocation. */
size_t vcs_proof_receiver_issuer_checkpoints(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);

/* ── Reuse decision ─────────────────────────────────────────────────── */

/* The candidate's own trust domain. Nothing signed by a key in here may
 * authorize reuse for that candidate, whatever else trusts it. */
struct vcs_proof_candidate_domain {
    uint8_t author_pubkey[VCS_PROOF_PUBKEY_BYTES];      /* required */
    bool has_local_signer;
    uint8_t local_signer_pubkey[VCS_PROOF_PUBKEY_BYTES]; /* same-uid key */
    const uint8_t (*extra)[VCS_PROOF_PUBKEY_BYTES];
    size_t extra_count;
};

/* The receiver's CURRENT policy, read at every decision. */
struct vcs_proof_reuse_policy {
    uint8_t policy_root[VCS_PROOF_ROOT_BYTES];
    const uint8_t (*verifiers)[VCS_PROOF_PUBKEY_BYTES];
    size_t verifier_count;
    const uint8_t (*revoked)[VCS_PROOF_PUBKEY_BYTES];
    size_t revoked_count;
    uint32_t quorum;               /* distinct EXECUTED PASS signers, >= 1 */
    uint64_t now_unix;             /* 0 disables freshness checks */
    uint64_t max_age_seconds;      /* 0 = no age bound */
    uint64_t max_future_seconds;   /* allowed clock skew */
};

/* Artifact bytes by artifact_root (SHA3-256 of the bytes). The bytes are
 * borrowed until the next call; the decision re-hashes them. */
struct vcs_proof_artifact_source {
    bool (*fetch)(void *ctx, const uint8_t artifact_root[VCS_PROOF_ROOT_BYTES],
                  const uint8_t **bytes, size_t *len);
    void *ctx;
};

struct vcs_proof_reuse_request {
    const struct vcs_component_proof_key_v1 *local;
    enum vcs_proof_action_class action_class;
    const struct vcs_proof_candidate_domain *domain;
    const struct vcs_proof_reuse_policy *policy;
    const struct vcs_proof_artifact_source *artifacts; /* BUILD reuse */
};

enum vcs_proof_reuse_outcome {
    VCS_PROOF_REUSE_MISS = 0,     /* run fresh */
    VCS_PROOF_REUSE_HIT_PASS,     /* reuse the PASS (artifact verified) */
    VCS_PROOF_REUSE_HIT_FAIL,     /* known failing; still rerunnable */
    VCS_PROOF_REUSE_REFUSE,       /* ambiguous or invalid: named refusal */
};

/* Per-ticket reasons. */
#define VCS_PROOF_TICKET_ELIGIBLE "eligible"
#define VCS_PROOF_TICKET_MALFORMED "ticket_malformed"
#define VCS_PROOF_TICKET_KEY_MISMATCH "key_mismatch"
#define VCS_PROOF_TICKET_PREIMAGE_MISMATCH "key_preimage_mismatch"
#define VCS_PROOF_TICKET_SOURCE_MISMATCH "source_mismatch"
#define VCS_PROOF_TICKET_CLASS_MISMATCH "action_class_mismatch"
#define VCS_PROOF_TICKET_SIGNATURE_INVALID "signature_invalid"
#define VCS_PROOF_TICKET_SIGNER_IN_DOMAIN "signer_in_candidate_domain"
#define VCS_PROOF_TICKET_SIGNER_REVOKED "signer_revoked"
#define VCS_PROOF_TICKET_SIGNER_UNTRUSTED "signer_not_trusted_for_reuse"
#define VCS_PROOF_TICKET_REUSED "reused_not_independent"
#define VCS_PROOF_TICKET_STALE "ticket_stale"
#define VCS_PROOF_TICKET_FUTURE "ticket_from_future"
#define VCS_PROOF_TICKET_EQUIVOCATION "issuer_equivocation"
#define VCS_PROOF_TICKET_NOT_CHECKPOINTED "not_checkpointed"
/* Otherwise eligible, but a rebuild isolated its issuer because that
 * issuer's stored history could not be replayed. Never counts toward a HIT. */
#define VCS_PROOF_TICKET_HISTORY_INCOMPLETE "issuer_history_incomplete"
/* Decision reasons. */
#define VCS_PROOF_REUSE_WHY_HIT "eligible_quorum"
#define VCS_PROOF_REUSE_WHY_KNOWN_FAIL "eligible_failure"
#define VCS_PROOF_REUSE_WHY_NONE "no_observation"
#define VCS_PROOF_REUSE_WHY_INELIGIBLE "no_eligible_observation"
#define VCS_PROOF_REUSE_WHY_QUORUM "quorum_not_met"
#define VCS_PROOF_REUSE_WHY_ARTIFACT_MISMATCH "artifact_bytes_mismatch"
#define VCS_PROOF_REUSE_WHY_ARTIFACT_MISSING "artifact_unavailable"
#define VCS_PROOF_REUSE_WHY_ARGUMENTS "reuse_arguments_invalid"
#define VCS_PROOF_REUSE_WHY_PREIMAGE "key_preimage_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY "reuse_policy_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY_ROOT "policy_root_inconsistent"
#define VCS_PROOF_REUSE_WHY_DOMAIN "candidate_domain_invalid"
#define VCS_PROOF_REUSE_WHY_CAPACITY "classification_capacity"
/* MISS: the only otherwise-eligible observations come from isolated
 * issuers. Nothing contradicts a fresh run, so the key simply runs. */
#define VCS_PROOF_REUSE_WHY_HISTORY_INCOMPLETE "issuer_history_incomplete"
/* REFUSE: the eligible observations would reuse one verdict, but an
 * isolated issuer, otherwise eligible, signed the opposite one. Compaction
 * may be what hid its history, so its dissent is not forgotten. */
#define VCS_PROOF_REUSE_WHY_UNVERIFIED_DISSENT "unverified_dissent"

struct vcs_proof_ticket_class {
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t artifact_root[VCS_PROOF_ROOT_BYTES];
    enum vcs_proof_verdict verdict;  /* 0 when malformed */
    bool eligible;
    const char *reason;              /* one of VCS_PROOF_TICKET_* */
};

#define VCS_PROOF_REUSE_MAX_USED 16u

struct vcs_proof_reuse_decision {
    enum vcs_proof_reuse_outcome outcome;
    const char *reason;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t artifact_root[VCS_PROOF_ROOT_BYTES]; /* verified, BUILD HIT */
    uint32_t tickets_seen;
    uint32_t eligible_pass;
    uint32_t eligible_fail;
    uint32_t distinct_pass_signers;
    /* True when a quorum existed but the artifact bytes did not hash to
     * their root: a false hit caught and refused. */
    bool false_hit_refused;
    /* Observation roots that authorize a HIT or HIT_FAIL, or the
     * conflicting ones on REFUSE. */
    uint8_t used[VCS_PROOF_REUSE_MAX_USED][VCS_PROOF_ROOT_BYTES];
    uint32_t used_count;
};

/* Decide reuse for one obligation over every observation `r` retains for
 * the key derived from req->local. `classes` must hold `class_cap`
 * entries; more observations than that is a REFUSE
 * (classification_capacity), never a silent truncation. Returns false only
 * for caller errors (out->outcome = REFUSE with a named reason). */
bool vcs_proof_reuse_decide(const struct vcs_proof_receiver *r,
                            const struct vcs_proof_reuse_request *req,
                            struct vcs_proof_ticket_class *classes,
                            size_t class_cap,
                            struct vcs_proof_reuse_decision *out);

const char *vcs_proof_reuse_outcome_name(enum vcs_proof_reuse_outcome o);

/* ── CAS placement ──────────────────────────────────────────────────── */

/* Store a ticket, checkpoint or key preimage wire as a content.v2 blob. */
bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES]);
/* Resume an interrupted local transfer without evicting older proof history.
 * A quota refusal keeps the pending head unpublished for later retry. */
bool vcs_proof_ticket_store_put_no_evict(
    struct vcs_package_store *store, const uint8_t *wire, size_t len,
    uint8_t blob_root[VCS_PROOF_ROOT_BYTES]);
/* Resolve a durable content.v2 checkpoint blob head directly. Verify its
 * exact blob root, signed wire and issuer, then return the protocol checkpoint
 * root expected by issuer-log restore. Outputs change only on success. */
bool vcs_proof_checkpoint_store_load(
    struct vcs_package_store *store,
    const uint8_t blob_root[VCS_PROOF_ROOT_BYTES],
    const uint8_t issuer_pubkey[VCS_PROOF_PUBKEY_BYTES],
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES],
    uint8_t checkpoint_root[VCS_PROOF_ROOT_BYTES]);
/* Load one preimage by its CAS root and verify it re-encodes to that root. */
bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                  const uint8_t preimage_root[32],
                                  struct vcs_component_proof_key_v1 *out);
/* Rebuild from ticket and checkpoint blobs in `store`, retaining every ticket
 * and replaying each issuer's signed checkpoints in leaf-count and ancestry
 * order. Issuers are replayed independently: one whose stored history is
 * incomplete (a covered ticket, a checkpoint ancestor or a complete ticket
 * branch missing, or invalid ancestry) is isolated. None of its tickets is
 * eligible (vcs_proof_receiver_issuer_history_incomplete), two of its listed
 * checkpoints that contradict each other still mark it equivocating, and
 * every other issuer is rebuilt and published. When the caller's receiver
 * already verified that issuer (and it is not an anchor), its verified
 * state is kept instead of forgotten. *checkpoints counts replayed
 * checkpoints of kept issuers. A ticket whose signature does not verify
 * is counted in *skipped and never retained, so it cannot widen a branch
 * search. Checking that every retained checkpoint names a complete ticket
 * branch shares one budget of VCS_PROOF_REBUILD_BRANCH_WORK_MAX steps
 * across all issuers: keys cost nothing to mint, so no key earns a budget
 * of its own. Exhausting it refuses the whole rebuild
 * (VCS_PROOF_REBUILD_WHY_BRANCH_WORK). An unreadable listed blob, an
 * incomplete catalog scan or exhausted memory also refuses the whole
 * rebuild. The caller's receiver remains intact on failure and output
 * counts are zero, with one exception that only adds distrust: when a complete
 * scan proved that an issuer the receiver already holds signed a fork, the
 * receiver marks that issuer equivocating even though the rebuilt view is
 * refused. Unrelated blobs count as *skipped. The caller supplies a
 * total catalog-row budget in addition to the per-page limit. Exhaustion
 * refuses; it never publishes a view missing a later contradiction. This
 * variant writes nothing to the store; see _with_policy for evidence pins. */
bool vcs_proof_receiver_rebuild_bounded(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped);

/* Branch-search steps one rebuild may spend across every issuer. */
#define VCS_PROOF_REBUILD_BRANCH_WORK_MAX 1000000u
/* Why the last rebuild into a receiver refused as a whole. */
#define VCS_PROOF_REBUILD_WHY_BRANCH_WORK "rebuild_branch_work_exhausted"
#define VCS_PROOF_REBUILD_WHY_REFUSED "rebuild_refused"
/* The reason the last rebuild into `r` refused, or NULL when it published
 * (or none ran). */
const char *vcs_proof_receiver_rebuild_refusal(
    const struct vcs_proof_receiver *r);

/* The caller supplies each issuer's durable content.v2 checkpoint blob head.
 * A receiver verifies every supplied head as its issuer's latest signed
 * checkpoint before publishing replay. A missing,
 * stale or forked head refuses and leaves the caller's receiver intact. The
 * caller must supply at least one head, obtain roots from durable local
 * authority, and recheck that authority before using the rebuilt projection.
 * An incomplete head enumeration must be refused by the caller. On success,
 * generation_out is the catalog generation at publication; the caller must
 * fence both that generation and the durable head authority before reuse. */
struct vcs_proof_receiver_anchor {
    uint8_t issuer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t checkpoint_blob_root[VCS_PROOF_ROOT_BYTES];
};

bool vcs_proof_receiver_rebuild_anchored_bounded(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    const struct vcs_proof_receiver_anchor *anchors, size_t anchor_count,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped, uint64_t *generation_out);

/* The rebuild above, optionally anchored (anchors may be NULL with a zero
 * count), that also keeps trusted fork evidence. After a complete scan,
 * published or refused, each equivocating issuer that is one of `trust`'s
 * verifiers and not one of its revoked keys has one pair of its signed,
 * conflicting blobs pinned (two tickets at one sequence, else two
 * checkpoints naming one parent) unless such a pair already is. Pins are
 * therefore bounded by 2 * trust->verifier_count fixed-size wires, set by
 * the operator, and every pinned blob is signed by its trusted key.
 * A stranger's fork is never pinned: it can never make a ticket eligible,
 * so forgetting it can never cause a HIT. `trust` NULL pins nothing.
 * With `trust`, only its unrevoked verifiers and the anchored issuers have
 * their checkpoint branches searched and replayed. Every other issuer is
 * still scanned for forks (two signed tickets at one sequence, or two of
 * its listed checkpoints that contradict each other mark it equivocating)
 * but is otherwise treated as isolated, so keys anyone can mint spend no
 * branch work. `trust` NULL replays every issuer.
 * Compaction then cannot erase a trusted fork, and a restarted rebuild
 * re-derives it. A pin never evicts; a full pins pool is logged and leaves
 * that fork known only to this process.
 * Pinning happens after publication and moves the store generation, so
 * *generation_out names the scanned catalog and a caller fencing it sees
 * one stale retry. The retry finds the pair pinned and pins nothing, so
 * it is idempotent. */
bool vcs_proof_receiver_rebuild_with_policy(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    const struct vcs_proof_reuse_policy *trust,
    const struct vcs_proof_receiver_anchor *anchors, size_t anchor_count,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped, uint64_t *generation_out);

#endif /* ZCL_VCS_PROOF_REUSE_H */
