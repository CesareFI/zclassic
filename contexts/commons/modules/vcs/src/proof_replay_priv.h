/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuild internals shared by the CAS scan, the per-issuer
 *          checkpoint replay and issuer isolation units. Not an API. */

#ifndef ZCL_VCS_PROOF_REPLAY_PRIV_H
#define ZCL_VCS_PROOF_REPLAY_PRIV_H

#include "proof_reuse_priv.h"

/* One signed checkpoint listed in the CAS. `parent` and `depth` index the
 * issuer's own checkpoint range while its ancestry is replayed. */
struct pts_cp {
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    struct vcs_proof_checkpoint_v1 decoded;
    size_t parent;
    size_t depth;
};

struct pts_cps {
    struct pts_cp *items;
    size_t count;
    size_t cap;
};

struct pts_counts {
    size_t tickets;
    size_t checkpoints;        /* replayed for issuers that were kept */
    size_t skipped;
    size_t unsigned_tickets;   /* of those, tickets whose signature failed */
    size_t isolated;           /* issuers whose history could not replay */
    size_t carried;            /* of those, kept as the live view had them */
    size_t unreplayed;         /* untrusted issuers only scanned for forks */
    uint64_t branch_work;      /* branch-search steps, all issuers */
    const char *refusal;       /* why the whole rebuild refused, if typed */
};

/* What a rebuild checks beyond the catalog, and whether it may write. With
 * a trust policy it pins the signed fork evidence of that policy's
 * unrevoked verifiers, and only those verifiers and the anchored issuers
 * have their checkpoint branches searched; without one, and always for
 * the issuer-log restore (which publishes against the generation it
 * scanned), it never writes and replays every issuer. */
struct pts_scope {
    const struct vcs_proof_receiver_anchor *anchors;
    size_t anchor_count;
    const struct vcs_proof_reuse_policy *evidence_trust;
};

/* How one issuer's stored history replayed. A data failure isolates only
 * that issuer; running out of memory, or the branch-work budget every
 * issuer shares, fails the whole rebuild. */
enum pts_verdict {
    PTS_KEEP = 0,
    PTS_ISOLATE,
    PTS_FATAL,
    PTS_EXHAUSTED,
};

/* The retained ticket decodes and carries its issuer's valid signature. */
bool pts_entry_signed(const struct pr_entry *e);

/* Replay every issuer's listed checkpoints into `r` (already holding every
 * listed ticket, each one signature-valid), one issuer at a time. An
 * issuer whose history is missing, orphaned or unverifiable is isolated;
 * under a trust policy an untrusted, unanchored issuer is only scanned for
 * forks. `prior` is the live receiver the view will replace. False only
 * when the rebuild itself must refuse (n->refusal names a typed reason). */
bool pts_replay(const struct vcs_proof_receiver *prior,
                struct vcs_proof_receiver *r, struct pts_cps *cps,
                struct pts_counts *n, const struct pts_scope *scope);

/* Isolate the issuer of `items` (its whole listed checkpoint range) in `r`:
 * nothing it signed stays covered and it is marked history_incomplete.
 * When `prior` already holds that issuer and `may_carry`, its prior state
 * is kept instead (*carried). Either way, two of its listed checkpoints
 * that contradict each other or a checkpoint it kept mark it equivocating
 * and are retained as evidence. False only on allocation failure. */
bool pii_isolate(const struct vcs_proof_receiver *prior,
                 struct vcs_proof_receiver *r, struct pts_cp *items,
                 size_t count, bool may_carry, bool *carried);

/* Re-add every ticket `prior` held for the carried issuers `keys` (sorted),
 * with its coverage. False only on allocation failure. */
bool pii_carry_tickets(const struct vcs_proof_receiver *prior,
                       struct vcs_proof_receiver *r,
                       const uint8_t (*keys)[VCS_PROOF_PUBKEY_BYTES],
                       size_t count);

#endif
