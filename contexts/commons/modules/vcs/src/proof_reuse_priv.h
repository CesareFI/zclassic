/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Receiver internals shared by the proof ticket sync, decision
 *          and CAS rebuild translation units. Not an API. */

#ifndef ZCL_VCS_PROOF_REUSE_PRIV_H
#define ZCL_VCS_PROOF_REUSE_PRIV_H

#include "vcs/proof_reuse.h"

#include "chain/mmr.h"

/* One retained observation. `covered` is a fact about signed data: this
 * exact observation root is a leaf of its issuer's checkpoint-verified
 * log. It says nothing about whether the issuer is trusted. */
struct pr_entry {
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer[VCS_PROOF_PUBKEY_BYTES];
    uint64_t issuer_seq;
    bool covered;
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
    size_t next_key;                    /* one-based index, zero ends chain */
    size_t next_seq;
};

struct pr_bucket {
    size_t head;                        /* one-based entry index */
    size_t tail;
};

/* One signature-valid checkpoint: verified (it extended the prefix) or
 * retained as equivocation evidence. */
struct pr_checkpoint {
    bool verified;
    uint64_t leaf_count;
    uint8_t mmr_root[VCS_PROOF_ROOT_BYTES];
    uint8_t prev[VCS_PROOF_ROOT_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
};

struct pr_issuer {
    uint8_t pubkey[VCS_PROOF_PUBKEY_BYTES];
    struct mmr mmr;                        /* verified prefix */
    uint8_t last_root[VCS_PROOF_ROOT_BYTES];
    uint32_t verified_count;
    bool equivocating;
    bool history_incomplete;     /* isolated by a rebuild: never eligible */
    struct pr_checkpoint *cps;
    size_t cp_count;
    size_t cp_cap;
};

struct vcs_proof_receiver {
    struct pr_entry *entries;
    size_t count;
    size_t cap;
    size_t *roots;                      /* observation root -> entry */
    struct pr_bucket *keys;            /* input key -> all entries */
    struct pr_bucket *seqs;            /* issuer and sequence -> all entries */
    size_t index_cap;
    struct pr_issuer *issuers;
    size_t issuer_count;
    size_t issuer_cap;
    const char *rebuild_refusal;       /* last whole-rebuild refusal */
};

struct pr_entry *pr_entry_find(const struct vcs_proof_receiver *r,
                               const uint8_t root[VCS_PROOF_ROOT_BYTES]);
size_t pr_entry_key_first(const struct vcs_proof_receiver *r,
                          const uint8_t key[VCS_PROOF_ROOT_BYTES]);
size_t pr_entry_seq_first(const struct vcs_proof_receiver *r,
                          const uint8_t issuer[32], uint64_t seq);
/* Append (or find) the entry for a decoded ticket; NULL on allocation
 * failure (logged). */
struct pr_entry *pr_entry_put(struct vcs_proof_receiver *r,
                              const uint8_t *wire,
                              const struct vcs_proof_ticket_v1 *t,
                              const uint8_t root[VCS_PROOF_ROOT_BYTES]);
const struct pr_issuer *pr_issuer_find(const struct vcs_proof_receiver *r,
                                       const uint8_t pubkey[32]);
/* Find or append an issuer; NULL on allocation failure (logged). The
 * issuer array is separate from the entries, so entry growth never moves
 * a returned issuer; a later pr_issuer_get may. */
struct pr_issuer *pr_issuer_get(struct vcs_proof_receiver *r,
                                const uint8_t pubkey[32]);

struct vcs_package_store;
/* For each equivocating issuer in `view` that is one of `trust`'s verifiers
 * and not revoked, pin one pair of its signed, mutually conflicting blobs
 * (two tickets at one sequence, else two checkpoints naming one parent)
 * unless such a pair is already pinned. At most two blobs per trusted key,
 * every one signed by that key. A pin never evicts; a refused pin is
 * logged. Returns issuers newly made durable. Pinning advances the store
 * generation. */
size_t pr_fork_evidence_pin(const struct vcs_proof_receiver *view,
                            struct vcs_package_store *store,
                            const struct vcs_proof_reuse_policy *trust);

#endif
