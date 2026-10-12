/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Ed25519 checks for proof tickets and checkpoints, with a
 *          process-local memo of signatures this process already verified.
 *
 * Rebuilding proof history checks each ticket signature in three passes
 * (checkpoint ancestry, delta selection, receiver sync) and admission
 * checks it once more. Each check is a full Ed25519 verification of the
 * same bytes. This memo keeps the checks and removes the repeated work.
 *
 * The memo holds only a true verdict that ed25519_verify returned in this
 * process. Its key is a salted SHA3-256 over the public key, signature and
 * signed message, so a hit means these exact bytes verified here before. A
 * miss, a refused signature, a missing salt or a failed allocation runs the
 * full verification. A refusal is never remembered. Nothing is written to
 * disk: a restarted process verifies every signature again.
 *
 * The table is bounded (2^17 keys, 4 MiB, allocated on first use). At
 * three-quarters full it is cleared, so behavior is exact below that load
 * and never worse than one verification per check above it. */

#ifndef ZCL_VCS_PROOF_SIGNATURE_H
#define ZCL_VCS_PROOF_SIGNATURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Same verdict as ed25519_verify(sig, msg, msg_len, pubkey) on every input. */
bool vcs_proof_signature_verify(const uint8_t sig[64], const uint8_t *msg,
                                size_t msg_len, const uint8_t pubkey[32]);

/* Process-lifetime counts. `verified` and `refused` are full Ed25519
 * verifications; `reused` are checks answered by the memo. */
struct vcs_proof_signature_stats {
    uint64_t verified;
    uint64_t refused;
    uint64_t reused;
};

void vcs_proof_signature_stats(struct vcs_proof_signature_stats *out);

/* Drop every remembered verdict, leaving the state a new process starts
 * with. Counts are kept. */
void vcs_proof_signature_forget(void);

#endif
