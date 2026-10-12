/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_LIVE_H
#define ZCL_BLUE_PAYMENT_LIVE_H

#include "blue_payment_simulate.h"
#include "zcl_tx_prevout.h"

typedef struct {
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS];
    uint32_t output_end[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS];
    uint8_t wire_hash[32];
    uint32_t count, inputs, branch_id, wire_length;
} blue_payment_live_plan;

typedef bool (*blue_payment_live_exchange)(void *context,
    const uint8_t *apdu, size_t apdu_length,
    uint8_t *reply, size_t capacity, size_t *reply_length);

/* Called while an output is visible. It must return true only after the
 * owner physically taps CONTINUE. The driver queries device state afterward. */
typedef bool (*blue_payment_live_continue)(void *context,
    uint32_t index, const blue_payment_screen *screen);

/* Returns 0 while output index awaits a tap, 1 after that tap, and -1 for
 * any response that does not match this review's output count and full-wire
 * SHA-256 commitment. */
int blue_payment_live_review_status(const uint8_t *reply, size_t length,
    uint32_t index, uint32_t total);

/* End a review and require the device to acknowledge erasure. A transport
 * failure leaves device state unknown, so callers must report failure. */
bool blue_payment_live_abort(blue_payment_live_exchange exchange,
    void *context);

/* The plan accepts only an unsigned all-transparent v4 transaction. It has no
 * signing authority and never treats host screen text as device evidence. */
bool blue_payment_live_prepare(const uint8_t *wire, size_t length,
    uint32_t branch_id, blue_payment_live_plan *plan);

/* Replays a private host copy of at most 2 MiB to Wallet protocol 11 or 12.
 * It recomputes the plan from that copy and rejects changed caller wire or
 * review-relevant plan fields. Every output chunk ends on its final byte;
 * a verified touchscreen callback is required before the next chunk.
 * Failure after BEGIN attempts a read-only review abort. The caller keeps
 * wire and plan alive and prevents concurrent writes for the whole call. */
bool blue_payment_live_run(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context);

/* After a complete read-only output review, streams a private copy of each
 * previous wire to the Blue and checks its independently derived input
 * digests and fee. It freezes the plan, expected digests, and all previous
 * wire identities before the first device exchange. It rejects changes to
 * the caller's unsigned wire, plan, digests, or previous wires before upload
 * and through the final check. The caller keeps all inputs alive and free
 * of concurrent writes. It must first preflight chain provenance; neither
 * this result nor the prior review authorizes signing. */
bool blue_payment_live_run_bound(const uint8_t *wire, size_t length,
    const blue_payment_live_plan *plan,
    const zcl_tx_previous_transaction *previous, size_t previous_count,
    uint64_t expected_fee_zat, const uint8_t (*expected_digests)[32],
    blue_payment_live_exchange exchange,
    blue_payment_live_continue continuation, void *context);

#endif
