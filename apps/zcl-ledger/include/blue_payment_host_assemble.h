/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_HOST_ASSEMBLE_H
#define ZCL_BLUE_PAYMENT_HOST_ASSEMBLE_H

#include "blue_payment_host_verify.h"

/* Replaces every empty transparent input script in a Sapling-v4
 * all-transparent wire with its P2PKH signature and public key.
 * This layout primitive does not verify ECDSA or public-key ownership.
 * Output must not overlap the unsigned wire, signatures, or expected digests.
 * Output length must be disjoint from all input and output buffers. Rejected
 * overlap or oversized input count leaves that length untouched; other
 * failures set it to zero. Callers must never publish output on failure. */
bool blue_payment_host_assemble(const uint8_t *unsigned_wire,
    size_t unsigned_length,
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    uint8_t *output, size_t capacity, size_t *output_length);

/* Requires the unsigned wire to match the SHA-256 recorded before the Blue
 * review. This does not verify ECDSA or public-key ownership. The reviewed
 * hash must be disjoint from output and output length.
 * Rejected overlap or oversized capacity leaves outputs untouched. Other
 * failures erase the full output capacity and set output length to zero.
 * Success also erases unused capacity. Callers must reject any failure. */
bool blue_payment_host_assemble_reviewed(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32], size_t count,
    uint8_t *output, size_t capacity, size_t *output_length);

/* Verifies the reviewed wire, each input's path and public-key hash, and
 * ECDSA over its expected ZIP-243 digest before assembling scripts. The
 * verifier callback must implement secp256k1 ECDSA verification. Output and
 * output length must be disjoint from every input. The reviewed wire and
 * signing inputs are snapshotted; verification and assembly use that copy,
 * while changes to caller storage during verification are rejected.
 * Rejected overlap or output capacity above
 * the 2 MiB transaction limit leaves outputs untouched; after accepted
 * arguments, any failure erases the full output capacity and sets output
 * length to zero. Success erases unused output capacity. A successful
 * result still requires caller-side chain UTXO and broadcast policy checks. */
bool blue_payment_host_assemble_authenticated(const uint8_t *unsigned_wire,
    size_t unsigned_length, const uint8_t reviewed_wire_hash[32],
    const blue_payment_verified_signature *signatures,
    const uint8_t (*expected_digests)[32],
    const uint8_t *expected_paths, const uint8_t (*expected_hashes)[20],
    size_t count, blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    uint8_t *output, size_t capacity, size_t *output_length);

#endif
