/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SHIELDED_REVIEW_APDU_H
#define ZCL_BLUE_SHIELDED_REVIEW_APDU_H

#include "zcl_tx_shielded_replay.h"

enum { BLUE_SHIELDED_REVIEW_CHUNK_MAX = 220,
       BLUE_SHIELDED_REVIEW_REPLY_MAX = 108 };

typedef struct {
    zcl_tx_shielded_replay replay;
    zcl_tx_shielded_facts facts;
    uint8_t digest[32];
    uint32_t branch_id;
    bool active, complete;
} blue_shielded_review_state;

/* Read-only CLA A5 protocol v8. INS 20 starts a six-pass replay and retains
 * its known branch ID for the final screen. INS 21 uploads
 * up to 220 bytes, 22 advances a complete pass, 23 finishes and returns a
 * 44-byte public summary, ZIP-243 digest, and full-wire SHA-256 commitment;
 * 24 erases the review.
 * Any rejected command erases the review and full reply capacity. Successful
 * commands erase unused reply capacity. Request and reply may
 * share a buffer; neither may overlap the review state. The reply-length
 * pointer must be disjoint from all three buffers. There is no signing
 * instruction. */
uint16_t blue_shielded_review_handle(blue_shielded_review_state *state,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t capacity, size_t *reply_length,
    const zcl_zip243_hasher *blake);

void blue_shielded_review_abort(blue_shielded_review_state *state);

#endif
