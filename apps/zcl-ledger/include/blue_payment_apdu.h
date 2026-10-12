/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_APDU_H
#define ZCL_BLUE_PAYMENT_APDU_H

#include "blue_payment_screen.h"
#include "zcl_tx_previous_stream.h"

typedef struct {
    blue_payment_review review;
    /* Previous-wire upload begins only after every output screen is closed. */
    union {
        blue_payment_screen screen;
        zcl_tx_previous_stream previous;
    };
    /* Outpoint until bound; then ZIP-243 digest plus derivation path byte. */
    uint8_t input_record[ZCL_TX_STREAM_MAX_INPUTS][36];
    uint32_t sequences[ZCL_TX_STREAM_MAX_INPUTS];
    uint64_t input_zat, output_zat, own_output_zat, fee_zat;
    uint32_t input_count, bound_inputs;
    bool active, previous_active, fee_ready, review_confirmed, approved;
    uint8_t input_paths, next_sign_index;
} blue_payment_apdu;

typedef struct {
    uint8_t external[20];
    uint8_t internal[20];
} blue_payment_owned_hashes;

/* Read-only CLA A5 commands 20-28. A physical touch acknowledges each
 * spending output. Previous wires can be uploaded only after a verified
 * three-pass review; each one must match the next captured input outpoint.
 * Touch-confirmed outputs to the two fixed device-derived P2PKH hashes are
 * accumulated for a read-only own-versus-other total after replay verifies.
 * A finished previous wire must pay to one of the device-derived hashes and
 * yields that input's device-derived ZIP-243 digest.
 * Request and reply may share the external APDU buffer. Neither may overlap
 * review state or device-owned hashes; reply length must be disjoint from
 * all buffers. An invalid storage layout aborts before parsing.
 * Successful replies erase unused capacity; rejected commands with valid
 * storage erase the full reply capacity and reset its declared length.
 * No command accesses a key, approves a payment, or signs. */
uint16_t blue_payment_apdu_handle(blue_payment_apdu *state,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t reply_capacity, size_t *reply_length,
    const zcl_zip243_hasher *blake, const zcl_tx_replay_sha256 *sha,
    blue_payment_hash_fn hash, const blue_payment_owned_hashes *owned);

/* Only a physical touchscreen callback may call this function on device.
 * It counts an output as owned only on an exact Blue-derived P2PKH match. */
bool blue_payment_apdu_touch_continue(blue_payment_apdu *state,
    const blue_payment_owned_hashes *owned);
/* Read-only touchscreen confirmation permanently excludes signing for this
 * review session. No APDU may turn it into payment approval. */
bool blue_payment_apdu_touch_confirm(blue_payment_apdu *state);
/* Only the device's final touchscreen callback may arm a verified review.
 * APDU dispatch must never call this function. The signing candidate calls
 * it only from its final touchscreen approval callback. */
bool blue_payment_apdu_touch_approve(blue_payment_apdu *state);
/* Consumes one approved digest in input order. Signing failure must abort. */
bool blue_payment_apdu_take_digest(blue_payment_apdu *state,
    uint32_t index, uint8_t digest[32], uint8_t *path);
void blue_payment_apdu_abort(blue_payment_apdu *state);

#endif
