/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_review.h"
#include "blue_payment_apdu.h"
#include "blue_payment_screen.h"
#include "blue_payment_simulate.h"
#include "blue_payment_live.h"
#include "blue_payment_sign.h"
#include "blue_payment_host_sign.h"
#include "blue_payment_host_ownership.h"
#include "blue_payment_host_assemble.h"
#include "blue_payment_fixture.h"
#include "zcl_tx_script_facts.h"
#include "zcl_tx_review.h"
#include "zcl_zip243_host.h"
#include "zcl_zip243.h"
#include "zsha256/zsha256.h"

#include "crypto/blake2b.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t bytes[256];
    size_t length, output_end[2], second_amount, previous_hash,
        first_output_hash, second_output_hash;
} fixture;

static void append_u32(fixture *item, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        item->bytes[item->length++] = (uint8_t)(value >> (i * 8));
}

static void append_u64(fixture *item, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        item->bytes[item->length++] = (uint8_t)(value >> (i * 8));
}

static fixture make_fixture(void) {
    fixture item = {0};
    append_u32(&item, 0x80000004);
    append_u32(&item, 0x892f2085);
    item.bytes[item.length++] = 1;
    memset(item.bytes + item.length, 0xaa, 32);
    item.length += 32;
    append_u32(&item, 0);
    item.bytes[item.length++] = 0;
    append_u32(&item, UINT32_MAX - 1);
    item.bytes[item.length++] = 2;
    append_u64(&item, 100000000);
    item.bytes[item.length++] = 25;
    const uint8_t p2pkh[3] = {0x76, 0xa9, 0x14};
    memcpy(item.bytes + item.length, p2pkh, sizeof p2pkh);
    item.length += sizeof p2pkh;
    item.first_output_hash = item.length;
    memset(item.bytes + item.length, 0x11, 20);
    item.length += 20;
    item.bytes[item.length++] = 0x88;
    item.bytes[item.length++] = 0xac;
    item.output_end[0] = item.length;
    item.second_amount = item.length;
    append_u64(&item, 200000000);
    item.bytes[item.length++] = 23;
    item.bytes[item.length++] = 0xa9;
    item.bytes[item.length++] = 0x14;
    item.second_output_hash = item.length;
    memset(item.bytes + item.length, 0x22, 20);
    item.length += 20;
    item.bytes[item.length++] = 0x87;
    item.output_end[1] = item.length;
    append_u32(&item, 100);
    append_u32(&item, 200);
    append_u64(&item, 0);
    item.bytes[item.length++] = 0;
    item.bytes[item.length++] = 0;
    item.bytes[item.length++] = 0;
    return item;
}

static fixture make_previous(void) {
    fixture item = {0};
    append_u32(&item, 1);
    item.bytes[item.length++] = 1;
    memset(item.bytes + item.length, 0, 32);
    item.length += 32;
    append_u32(&item, UINT32_MAX);
    item.bytes[item.length++] = 0;
    append_u32(&item, UINT32_MAX);
    item.bytes[item.length++] = 1;
    append_u64(&item, 400000000);
    item.bytes[item.length++] = 25;
    const uint8_t prefix[] = {0x76, 0xa9, 0x14};
    memcpy(item.bytes + item.length, prefix, sizeof prefix);
    item.length += sizeof prefix;
    item.previous_hash = item.length;
    memset(item.bytes + item.length, 0x33, 20);
    item.length += 20;
    item.bytes[item.length++] = 0x88;
    item.bytes[item.length++] = 0xac;
    append_u32(&item, 0);
    return item;
}

static bool sha_init(void *context) {
    return EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1;
}

static bool sha_update(void *context, const uint8_t *bytes, size_t length) {
    return EVP_DigestUpdate(context, bytes, length) == 1;
}

static bool sha_final(void *context, uint8_t digest[32]) {
    unsigned length = 0;
    return EVP_DigestFinal_ex(context, digest, &length) == 1 && length == 32;
}

static bool screen_hash(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    return SHA256(bytes, length, digest) != NULL;
}

static uint64_t expected_bound_digests(const fixture *spend,
    const zcl_tx_previous_transaction *previous, size_t count,
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32]) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_transparent_facts facts;
    assert(zcl_tx_transparent_bound_digests(spend->bytes, spend->length,
        previous, count, 0x76b809bb, screen_hash, &hasher,
        &facts, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) == 0);
    return facts.fee_zat;
}

static void begin(blue_payment_review *review, const fixture *item,
    struct blake2b_ctx *blake_context, EVP_MD_CTX *sha_context) {
    zcl_zip243_hasher blake = zcl_zip243_host_hasher(blake_context);
    zcl_tx_replay_sha256 sha = {.context = sha_context, .init = sha_init,
        .update = sha_update, .final = sha_final};
    assert(blue_payment_review_begin(review, (uint32_t)item->length, 0,
        0x76b809bb, &blake, &sha));
}

static void first_two_passes(blue_payment_review *review,
    const fixture *item) {
    for (unsigned pass = 0; pass < 2; ++pass) {
        assert(blue_payment_review_feed(review, item->bytes, item->length));
        assert(blue_payment_review_next_pass(review));
    }
    assert(review->total_outputs == 2);
}

static void ready_for_finish(blue_payment_review *review,
    const fixture *item, struct blake2b_ctx *blake_context,
    EVP_MD_CTX *sha_context) {
    begin(review, item, blake_context, sha_context);
    first_two_passes(review, item);
    assert(blue_payment_review_feed(review, item->bytes,
        item->output_end[0]));
    assert(blue_payment_review_acknowledge(review));
    assert(blue_payment_review_feed(review,
        item->bytes + item->output_end[0],
        item->output_end[1] - item->output_end[0]));
    assert(blue_payment_review_acknowledge(review));
    assert(blue_payment_review_feed(review,
        item->bytes + item->output_end[1],
        item->length - item->output_end[1]));
}

static void test_finish_alias(const fixture *item) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    blue_payment_review review;
    ready_for_finish(&review, item, &blake_context, sha_context);
    union {
        zcl_tx_stream_facts facts;
        uint8_t bytes[sizeof(zcl_tx_stream_facts) + 32];
    } aliased;
    memset(&aliased, 0xa5, sizeof aliased);
    assert(!blue_payment_review_finish(&review, NULL, 0, 0,
        &aliased.facts, aliased.bytes + 1));
    assert(review.replay.wire.failed && !review.verified);
    for (size_t i = 0; i < sizeof aliased.bytes; ++i)
        assert(aliased.bytes[i] == 0xa5);
    ready_for_finish(&review, item, &blake_context, sha_context);
    uint8_t digest[32];
    memset(digest, 0xa5, sizeof digest);
    assert(!blue_payment_review_finish(&review, NULL, 0, 0,
        &review.replay.wire.facts, digest));
    assert(review.replay.wire.failed && !review.verified);
    for (size_t i = 0; i < sizeof digest; ++i)
        assert(digest[i] == 0xa5);
    ready_for_finish(&review, item, &blake_context, sha_context);
    zcl_tx_stream_facts facts;
    memset(&facts, 0xa5, sizeof facts);
    assert(!blue_payment_review_finish(&review, review.replay.outputs,
        25, 0, &facts, digest));
    assert(review.replay.wire.failed && !review.verified);
    for (size_t i = 0; i < sizeof facts; ++i)
        assert(((const uint8_t *)&facts)[i] == 0xa5);
    EVP_MD_CTX_free(sha_context);
}

static void test_feed_alias(const fixture *item) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    blue_payment_review review;
    begin(&review, item, &blake_context, sha_context);
    assert(blue_payment_review_feed(&review, item->bytes, 1));
    review.output.hash160[0] = item->bytes[1];
    assert(!blue_payment_review_feed(&review, review.output.hash160, 1));
    assert(review.replay.wire.failed && !review.pending && !review.verified);
    begin(&review, item, &blake_context, sha_context);
    assert(blue_payment_review_feed(&review, item->bytes, 1));
    review.replay.commitment[0] = item->bytes[1];
    assert(!blue_payment_review_feed(&review,
        review.replay.commitment, 1));
    assert(review.replay.wire.failed && !review.pending && !review.verified);
    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    EVP_MD_CTX_free(sha_context);
}

static void test_success(const fixture *item) {
    struct blake2b_ctx blake_context, reference_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    blue_payment_review review;
    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    uint8_t script_code[25] = {0x76, 0xa9, 0x14};
    memset(script_code + 3, 0x33, 20);
    script_code[23] = 0x88;
    script_code[24] = 0xac;
    assert(blue_payment_review_feed(&review, item->bytes,
        item->output_end[0]));
    const blue_payment_output *output = blue_payment_review_pending(&review);
    assert(output && output->index == 0 && output->amount_zat == 100000000);
    assert(output->type == ZCL_TX_STREAM_P2PKH);
    for (size_t i = 0; i < 20; ++i) assert(output->hash160[i] == 0x11);
    blue_payment_screen screen;
    assert(blue_payment_screen_format(output, review.total_outputs,
        screen_hash, &screen));
    assert(strcmp(screen.title, "OUTPUT 1/2") == 0);
    assert(strcmp(screen.amount, "1.00000000 ZCL") == 0);
    assert(blue_payment_review_acknowledge(&review));
    assert(blue_payment_review_feed(&review,
        item->bytes + item->output_end[0],
        item->output_end[1] - item->output_end[0]));
    output = blue_payment_review_pending(&review);
    assert(output && output->index == 1 && output->amount_zat == 200000000);
    assert(output->type == ZCL_TX_STREAM_P2SH);
    for (size_t i = 0; i < 20; ++i) assert(output->hash160[i] == 0x22);
    assert(blue_payment_screen_format(output, review.total_outputs,
        screen_hash, &screen));
    assert(strcmp(screen.title, "OUTPUT 2/2") == 0);
    assert(strcmp(screen.amount, "2.00000000 ZCL") == 0);
    assert(blue_payment_review_acknowledge(&review));
    assert(blue_payment_review_feed(&review,
        item->bytes + item->output_end[1],
        item->length - item->output_end[1]));
    zcl_tx_stream_facts facts;
    uint8_t actual[32], expected[32];
    assert(blue_payment_review_finish(&review, script_code,
        sizeof script_code, 300000001, &facts, actual));
    assert(facts.inputs == 1 && facts.outputs == 2);
    assert(facts.output_zat == 300000000);
    zcl_zip243_hasher reference = zcl_zip243_host_hasher(&reference_context);
    assert(zcl_zip243_transparent_digest(item->bytes, item->length, 0,
        script_code, sizeof script_code, 300000001, 0x76b809bb,
        &reference, expected) == 0);
    assert(memcmp(actual, expected, sizeof actual) == 0);
    uint8_t rebound[32];
    assert(zcl_tx_replay_zip243_bound_digest(&review.replay,
        item->bytes + 9, UINT32_MAX - 1, script_code, 300000001,
        rebound));
    assert(memcmp(rebound, expected, sizeof rebound) == 0);
    uint8_t saved_outputs[32];
    memcpy(saved_outputs, review.replay.outputs, sizeof saved_outputs);
    assert(!zcl_tx_replay_zip243_bound_digest(&review.replay,
        item->bytes + 9, UINT32_MAX - 1, script_code, 300000001,
        review.replay.outputs));
    assert(memcmp(review.replay.outputs, saved_outputs,
        sizeof saved_outputs) == 0);
    uint8_t aliased_outpoint[68] = {0};
    memcpy(aliased_outpoint, item->bytes + 9, 36);
    assert(!zcl_tx_replay_zip243_bound_digest(&review.replay,
        aliased_outpoint, UINT32_MAX - 1, script_code, 300000001,
        aliased_outpoint + 1));
    assert(memcmp(aliased_outpoint, item->bytes + 9, 36) == 0);
    uint8_t aliased_script[57] = {0};
    memcpy(aliased_script, script_code, 25);
    assert(!zcl_tx_replay_zip243_bound_digest(&review.replay,
        item->bytes + 9, UINT32_MAX - 1, aliased_script, 300000001,
        aliased_script + 1));
    assert(memcmp(aliased_script, script_code, 25) == 0);
    assert(zcl_tx_replay_zip243_bound_digest(&review.replay,
        item->bytes + 9, UINT32_MAX - 1, script_code, 300000001,
        rebound));
    assert(memcmp(rebound, expected, sizeof rebound) == 0);
    script_code[0] = 0x6a;
    memset(rebound, 0x5a, sizeof rebound);
    assert(!zcl_tx_replay_zip243_bound_digest(&review.replay,
        item->bytes + 9, UINT32_MAX - 1, script_code, 300000001,
        rebound));
    for (size_t i = 0; i < sizeof rebound; ++i) assert(rebound[i] == 0x5a);
    assert(!blue_payment_review_acknowledge(&review));
    EVP_MD_CTX_free(sha_context);
}

static void test_failures(const fixture *item) {
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context = EVP_MD_CTX_new();
    assert(sha_context);
    blue_payment_review review;
    zcl_tx_stream_facts facts;
    uint8_t digest[32];
    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    assert(blue_payment_review_feed(&review, item->bytes,
        item->output_end[0]));
    assert(!blue_payment_review_feed(&review,
        item->bytes + item->output_end[0], 1));
    assert(!blue_payment_review_pending(&review));
    assert(!blue_payment_review_acknowledge(&review));

    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    assert(!blue_payment_review_feed(&review, item->bytes,
        item->output_end[0] + 1));
    assert(!blue_payment_review_pending(&review));

    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    assert(!blue_payment_review_feed(&review, item->bytes,
        item->output_end[1]));
    assert(!blue_payment_review_pending(&review));

    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    assert(blue_payment_review_feed(&review, item->bytes,
        item->output_end[0]));
    assert(!blue_payment_review_finish(&review, NULL, 0, 0,
        &facts, digest));
    for (size_t i = 0; i < sizeof digest; ++i) assert(!digest[i]);

    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    uint8_t changed[sizeof item->bytes];
    memcpy(changed, item->bytes, item->length);
    changed[item->second_amount] ^= 1;
    assert(blue_payment_review_feed(&review, changed,
        item->output_end[0]));
    assert(blue_payment_review_acknowledge(&review));
    assert(blue_payment_review_feed(&review,
        changed + item->output_end[0],
        item->output_end[1] - item->output_end[0]));
    assert(blue_payment_review_acknowledge(&review));
    assert(blue_payment_review_feed(&review,
        changed + item->output_end[1],
        item->length - item->output_end[1]));
    assert(!blue_payment_review_finish(&review, NULL, 0, 0,
        &facts, digest));
    for (size_t i = 0; i < sizeof digest; ++i) assert(!digest[i]);

    begin(&review, item, &blake_context, sha_context);
    first_two_passes(&review, item);
    blue_payment_review_abort(&review);
    assert(!blue_payment_review_feed(&review, item->bytes, 1));
    EVP_MD_CTX_free(sha_context);
}

static void test_simulation(const fixture *item) {
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS];
    uint32_t count = 0;
    assert(blue_payment_simulate(item->bytes, item->length, 0x76b809bb,
        screens, &count));
    assert(count == 2);
    assert(strcmp(screens[0].title, "OUTPUT 1/2") == 0);
    assert(strcmp(screens[0].amount, "1.00000000 ZCL") == 0);
    assert(strcmp(screens[1].title, "OUTPUT 2/2") == 0);
    assert(strcmp(screens[1].amount, "2.00000000 ZCL") == 0);
    uint8_t changed[sizeof item->bytes];
    memcpy(changed, item->bytes, item->length);
    changed[item->output_end[1] - 1] = 0x86;
    assert(!blue_payment_simulate(changed, item->length, 0x76b809bb,
        screens, &count));
    assert(count == 0 && screens[0].title[0] == 0);
    assert(!blue_payment_simulate(item->bytes, item->length - 1,
        0x76b809bb,
        screens, &count));
    assert(count == 0 && screens[0].title[0] == 0);
}

typedef struct {
    blue_payment_apdu state;
    blue_payment_owned_hashes owned;
    struct blake2b_ctx blake_context;
    EVP_MD_CTX *sha_context;
    zcl_zip243_hasher blake;
    zcl_tx_replay_sha256 sha;
} apdu_fixture;

static void apdu_init(apdu_fixture *session) {
    memset(session, 0, sizeof *session);
    session->sha_context = EVP_MD_CTX_new();
    assert(session->sha_context);
    session->blake = zcl_zip243_host_hasher(&session->blake_context);
    session->sha = (zcl_tx_replay_sha256){.context = session->sha_context,
        .init = sha_init, .update = sha_update, .final = sha_final};
    memset(session->owned.external, 0x33, 20);
    memset(session->owned.internal, 0x44, 20);
}

static uint16_t command(apdu_fixture *session, uint8_t instruction,
    const uint8_t *body, size_t length, uint8_t reply[8],
    size_t *reply_length) {
    assert(length <= 255);
    uint8_t apdu[260] = {0xa5, instruction, 0, 0, (uint8_t)length};
    if (length) memcpy(apdu + 5, body, length);
    return blue_payment_apdu_handle(&session->state, apdu, length + 5,
        reply, 8, reply_length, &session->blake, &session->sha,
        screen_hash, &session->owned);
}

static void apdu_begin(apdu_fixture *session, const fixture *item) {
    uint8_t body[12] = {0};
    uint32_t length = (uint32_t)item->length;
    for (unsigned i = 0; i < 4; ++i)
        body[i] = (uint8_t)(length >> (8 * i));
    const uint8_t branch[4] = {0xbb, 0x09, 0xb8, 0x76};
    memcpy(body + 8, branch, sizeof branch);
    uint8_t reply[8];
    size_t reply_length = 99;
    assert(command(session, 0x20, body, sizeof body, reply,
        &reply_length) == 0x9000);
    assert(reply_length == 0);
}

static void apdu_passes(apdu_fixture *session, const fixture *item) {
    uint8_t reply[8];
    size_t reply_length;
    for (unsigned i = 0; i < 2; ++i) {
        assert(command(session, 0x21, item->bytes, item->length,
            reply, &reply_length) == 0x9000);
        assert(reply_length == 2 && reply[1] == 0);
        assert(command(session, 0x22, NULL, 0,
            reply, &reply_length) == 0x9000);
        assert(reply_length == 2 && reply[0] == i + 2);
    }
    assert(reply[1] == 2);
}

static void test_apdu(const fixture *item) {
    apdu_fixture session;
    apdu_init(&session);
    assert(!blue_payment_apdu_touch_continue(&session.state, &session.owned));
    apdu_begin(&session, item);
    apdu_passes(&session, item);
    uint8_t reply[8];
    size_t reply_length;
    assert(command(&session, 0x21, item->bytes,
        item->output_end[0], reply, &reply_length) == 0x9000);
    assert(reply_length == 2 && reply[0] == 3 && reply[1] == 1);
    assert(strcmp(session.state.screen.title, "OUTPUT 1/2") == 0);
    assert(command(&session, 0x25, NULL, 0,
        reply, &reply_length) == 0x9000);
    assert(reply_length == 6 && reply[0] == 1 && reply[2] == 1);
    assert(!blue_payment_apdu_touch_continue(&session.state, NULL));
    assert(session.state.review.pending && session.state.own_output_zat == 0);
    assert(blue_payment_apdu_touch_continue(&session.state, &session.owned));
    assert(session.state.screen.title[0] == 0);
    assert(command(&session, 0x21, item->bytes + item->output_end[0],
        item->output_end[1] - item->output_end[0],
        reply, &reply_length) == 0x9000);
    assert(reply[1] == 1 &&
        strcmp(session.state.screen.title, "OUTPUT 2/2") == 0);
    assert(blue_payment_apdu_touch_continue(&session.state, &session.owned));
    assert(command(&session, 0x21, item->bytes + item->output_end[1],
        item->length - item->output_end[1],
        reply, &reply_length) == 0x9000);
    assert(reply[1] == 0);
    const uint8_t finish_apdu[5] = {0xa5, 0x23, 0, 0, 0};
    uint8_t finish_reply[40];
    assert(blue_payment_apdu_handle(&session.state, finish_apdu,
        sizeof finish_apdu, finish_reply, sizeof finish_reply,
        &reply_length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x9000);
    uint8_t expected_wire_hash[32];
    zsha256(item->bytes, item->length, expected_wire_hash);
    assert(reply_length == 33 && finish_reply[0] == 2 &&
        memcmp(finish_reply + 1, expected_wire_hash, 32) == 0);
    assert(command(&session, 0x25, NULL, 0,
        reply, &reply_length) == 0x9000);
    assert(reply_length == 6 && reply[0] == 0 && reply[3] == 1 &&
        reply[4] == 2 && reply[5] == 2);
    assert(session.state.own_output_zat == 0);
    assert(!blue_payment_apdu_touch_continue(&session.state, &session.owned));
    EVP_MD_CTX_free(session.sha_context);
}

static void test_apdu_fail_closed(const fixture *item) {
    apdu_fixture session;
    apdu_init(&session);
    uint8_t wrong_branch[12] = {0};
    uint32_t wire_length = (uint32_t)item->length;
    for (unsigned i = 0; i < 4; ++i)
        wrong_branch[i] = (uint8_t)(wire_length >> (i * 8));
    uint8_t reply[8];
    size_t reply_length;
    assert(command(&session, 0x20, wrong_branch, sizeof wrong_branch,
        reply, &reply_length) == 0x6a80);
    assert(reply_length == 0 && !session.state.active);
    apdu_begin(&session, item);
    uint8_t status_frame[] = {0xa5, 0x25, 0, 0, 0};
    assert(blue_payment_apdu_handle(&session.state, status_frame,
        sizeof status_frame, reply, sizeof reply, NULL,
        &session.blake, &session.sha, screen_hash,
        &session.owned) == 0x6f00);
    assert(!session.state.active && !session.state.review.verified);
    apdu_begin(&session, item);
    apdu_passes(&session, item);
    assert(command(&session, 0x21, item->bytes,
        item->output_end[0], reply, &reply_length) == 0x9000);
    assert(command(&session, 0x29, NULL, 0,
        reply, &reply_length) == 0x6d00);
    assert(!session.state.active && !session.state.review.pending);
    assert(session.state.screen.title[0] == 0);

    apdu_begin(&session, item);
    const uint8_t previous_length[4] = {85, 0, 0, 0};
    assert(command(&session, 0x26, previous_length,
        sizeof previous_length, reply, &reply_length) == 0x6985);
    assert(!session.state.active && !session.state.review.verified);

    apdu_begin(&session, item);
    apdu_passes(&session, item);
    assert(command(&session, 0x21, item->bytes,
        item->output_end[0], reply, &reply_length) == 0x9000);
    assert(command(&session, 0x21, item->bytes + item->output_end[0],
        1, reply, &reply_length) == 0x6a80);
    assert(!blue_payment_apdu_touch_continue(&session.state, &session.owned));

    apdu_begin(&session, item);
    apdu_passes(&session, item);
    assert(command(&session, 0x21, item->bytes,
        item->output_end[0] + 1, reply, &reply_length) == 0x6a80);
    assert(!session.state.active && !session.state.review.pending);
    apdu_begin(&session, item);
    assert(command(&session, 0x24, NULL, 0,
        reply, &reply_length) == 0x9000);
    assert(!session.state.active);
    apdu_begin(&session, item);
    uint8_t malformed[] = {0xa5, 0x21, 0, 0, 1};
    assert(blue_payment_apdu_handle(&session.state, malformed,
        sizeof malformed, reply, sizeof reply, &reply_length,
        &session.blake, &session.sha, screen_hash,
        &session.owned) == 0x6700);
    assert(reply_length == 0 && !session.state.active);
    apdu_begin(&session, item);
    apdu_passes(&session, item);
    blue_payment_apdu_abort(&session.state);
    assert(command(&session, 0x21, item->bytes, 1,
        reply, &reply_length) == 0x6985);
    assert(!session.state.active && session.state.screen.title[0] == 0);
    EVP_MD_CTX_free(session.sha_context);
}

typedef struct {
    uint8_t reply[8];
    size_t length;
} aliased_payment_reply;

static_assert(offsetof(aliased_payment_reply, length) == 8);

typedef struct {
    uint8_t prefix[8];
    size_t length;
} aliased_payment_request;

static_assert(offsetof(aliased_payment_request, length) == 8);

static void test_apdu_storage_alias(const fixture *item) {
    apdu_fixture session;
    apdu_init(&session);
    const uint8_t request[5] = {0xa5, 0x25, 0, 0, 0};
    apdu_begin(&session, item);
    aliased_payment_reply shared = {.length = 99};
    assert(blue_payment_apdu_handle(&session.state, request,
        sizeof request, (uint8_t *)&shared, sizeof shared,
        &shared.length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6f00);
    assert(!session.state.active && shared.length == 0);

    apdu_begin(&session, item);
    memcpy(session.state.input_record[0], request, sizeof request);
    uint8_t reply[8];
    size_t length = 99;
    assert(blue_payment_apdu_handle(&session.state,
        session.state.input_record[0], sizeof request, reply,
        sizeof reply, &length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6f00);
    assert(!session.state.active && length == 0);

    apdu_begin(&session, item);
    assert(blue_payment_apdu_handle(&session.state, request,
        sizeof request, session.state.input_record[0],
        sizeof reply, &length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6f00);
    assert(!session.state.active && length == 0);
    EVP_MD_CTX_free(session.sha_context);
}

static void test_apdu_request_and_owned_alias(const fixture *item) {
    apdu_fixture session;
    apdu_init(&session);
    apdu_begin(&session, item);
    aliased_payment_request request = {
        .prefix = {0xa5, 0x21, 0, 0, 11, 4, 0, 0x80},
        .length = 123
    };
    uint8_t original[sizeof request];
    memcpy(original, &request, sizeof original);
    uint8_t reply[8];
    assert(blue_payment_apdu_handle(&session.state,
        (const uint8_t *)&request, sizeof request, reply,
        sizeof reply, &request.length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6f00);
    assert(memcmp(&request, original, sizeof original) == 0);
    assert(!session.state.active);

    apdu_begin(&session, item);
    blue_payment_owned_hashes owned = session.owned;
    size_t length = 99;
    const uint8_t status[5] = {0xa5, 0x25, 0, 0, 0};
    assert(blue_payment_apdu_handle(&session.state, status,
        sizeof status, (uint8_t *)&session.owned, sizeof reply,
        &length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6f00);
    assert(memcmp(&session.owned, &owned, sizeof owned) == 0);
    assert(length == 0 && !session.state.active);

    apdu_begin(&session, item);
    uint8_t shared[32];
    memset(shared, 0xa5, sizeof shared);
    memcpy(shared, status, sizeof status);
    assert(blue_payment_apdu_handle(&session.state, shared, 5,
        shared, sizeof shared, &length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x9000);
    assert(length == 6 && shared[0] == 1);
    for (size_t i = length; i < sizeof shared; ++i) assert(shared[i] == 0);

    memset(shared, 0xa5, sizeof shared);
    shared[0] = 0xa5; shared[1] = 0x25;
    shared[2] = shared[3] = 0; shared[4] = 1;
    assert(blue_payment_apdu_handle(&session.state, shared, 5,
        shared, sizeof shared, &length, &session.blake, &session.sha,
        screen_hash, &session.owned) == 0x6700);
    assert(length == 0);
    for (size_t i = 0; i < sizeof shared; ++i) assert(shared[i] == 0);
    EVP_MD_CTX_free(session.sha_context);
}

static void test_apdu_mutations(void) {
    apdu_fixture session;
    apdu_init(&session);
    uint32_t random = 0x23c1a55u;
    for (unsigned run = 0; run < 10000; ++run) {
        uint8_t apdu[260] = {0xa5, (uint8_t)(0x20 + run % 9), 0, 0, 0};
        random = random * 1664525u + 1013904223u;
        apdu[4] = (uint8_t)(random >> 24);
        for (size_t i = 5; i < sizeof apdu; ++i) {
            random = random * 1664525u + 1013904223u;
            apdu[i] = (uint8_t)(random >> 24);
        }
        random = random * 1664525u + 1013904223u;
        size_t length = run % 3 == 0 ? (size_t)apdu[4] + 5 :
            random % (sizeof apdu + 1);
        uint8_t reply[16];
        memset(reply, 0xa5, sizeof reply);
        size_t reply_length = 99;
        uint16_t status = blue_payment_apdu_handle(&session.state, apdu,
            length, reply, 8, &reply_length, &session.blake,
            &session.sha, screen_hash, &session.owned);
        assert(reply_length <= 8);
        if (status != 0x9000)
            assert(reply_length == 0 && !session.state.active);
        for (size_t i = reply_length; i < 8; ++i)
            assert(reply[i] == 0);
        for (size_t i = 8; i < sizeof reply; ++i)
            assert(reply[i] == 0xa5);
    }
    blue_payment_apdu_abort(&session.state);
    EVP_MD_CTX_free(session.sha_context);
}

typedef struct {
    apdu_fixture apdu;
    unsigned exchanges, continued, reset_after_reply, previous_begins;
    uint8_t interrupted_apdu[260];
    size_t interrupted_length;
    uint8_t *mutate_wire;
    uint8_t *repair_expected;
    uint8_t repair_value;
    blue_payment_live_plan *mutate_plan;
    zcl_tx_previous_transaction *mutate_previous;
    size_t mutate_index;
    uint8_t mutate_instruction;
    bool mutated;
    blue_payment_sign_digest_fn signing;
    blue_payment_pubkey_hash_fn signing_hash;
    void *signer_context;
    blue_payment_verified_signature *poison_signatures;
    size_t poison_count;
    uint8_t last_sign_reply[BLUE_PAYMENT_SIGN_REPLY_MAX];
    size_t last_sign_length;
    bool refuse_touch, wrong_identity, signing_identity, corrupt_wire_reply,
        corrupt_sign_reply,
        corrupt_second_sign_reply,
        fail_previous_chunk, no_owned_hashes,
        connection_lost, reset_on_touch;
} live_fixture;

static bool live_identity_reply(const live_fixture *live, uint8_t *reply,
    size_t capacity, size_t *reply_length) {
    if (capacity < 7) return false;
    const uint8_t identity[7] = {'Z', 'C', 'L',
        live->wrong_identity ? 8 : live->signing_identity ? 12 : 11,
        live->signing_identity ? 31 : 15, 0x90, 0};
    memcpy(reply, identity, sizeof identity);
    *reply_length = sizeof identity;
    return true;
}

static uint16_t live_command_status(live_fixture *live,
    const uint8_t *apdu, size_t apdu_length, uint8_t *reply,
    size_t capacity, size_t *payload) {
    if (apdu[1] != 0x29)
        return blue_payment_apdu_handle(&live->apdu.state,
            apdu, apdu_length, reply, capacity, payload,
            &live->apdu.blake, &live->apdu.sha, screen_hash,
            live->no_owned_hashes ? NULL : &live->apdu.owned);
    uint16_t status = blue_payment_sign_command(&live->apdu.state,
        apdu, apdu_length, &live->apdu.owned, live->signing,
        live->signer_context, live->signing_hash, reply, capacity, payload);
    if (status == 0x9000 && *payload > 36 &&
        (live->corrupt_sign_reply ||
         (live->corrupt_second_sign_reply && apdu[5] == 1)))
        reply[*payload - 1] ^= 1;
    if (status == 0x9000) {
        assert(*payload <= sizeof live->last_sign_reply);
        memcpy(live->last_sign_reply, reply, *payload);
        live->last_sign_length = *payload;
    }
    return status;
}

static void mutate_after_exchange(live_fixture *live, uint8_t instruction) {
    if ((live->mutate_wire || live->mutate_plan ||
            live->mutate_previous) && !live->mutated &&
        instruction == live->mutate_instruction) {
        if (live->mutate_wire)
            live->mutate_wire[live->mutate_index] ^= 1;
        else if (live->mutate_plan)
            live->mutate_plan->screens[0].amount[0] ^= 1;
        else
            ++live->mutate_previous->length;
        live->mutated = true;
    }
}

static void poison_abort_output(live_fixture *live, uint8_t instruction) {
    if (instruction == 0x24 && live->poison_signatures)
        memset(live->poison_signatures, 0xa5,
            live->poison_count * sizeof *live->poison_signatures);
}

static bool live_exchange(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    live_fixture *live = context;
    ++live->exchanges;
    if (apdu_length >= 2 && apdu[1] == 0x26) ++live->previous_begins;
    if (live->connection_lost) return false;
    if (capacity < 2 || apdu_length < 5) return false;
    if (live->fail_previous_chunk && apdu[1] == 0x27) return false;
    if (apdu[1] == 0x01) {
        if (!live_identity_reply(live, reply, capacity, reply_length))
            return false;
        goto exchanged;
    }
    size_t payload = 0;
    uint16_t status = live_command_status(live, apdu, apdu_length,
        reply, capacity - 2, &payload);
    if (apdu[1] == 0x23 && status == 0x9000 && live->corrupt_wire_reply) {
        assert(payload == 33);
        reply[1] ^= 1;
    }
    reply[payload] = (uint8_t)(status >> 8);
    reply[payload + 1] = (uint8_t)status;
    *reply_length = payload + 2;
exchanged:
    mutate_after_exchange(live, apdu[1]);
    poison_abort_output(live, apdu[1]);
    if (live->exchanges == live->reset_after_reply) {
        assert(apdu_length <= sizeof live->interrupted_apdu);
        memcpy(live->interrupted_apdu, apdu, apdu_length);
        live->interrupted_length = apdu_length;
        blue_payment_apdu_abort(&live->apdu.state);
        live->connection_lost = true;
        return false;
    }
    return true;
}

static bool live_continue(void *context, uint32_t index,
    const blue_payment_screen *screen) {
    live_fixture *live = context;
    assert(index == live->continued);
    assert(live->apdu.state.review.pending);
    assert(strcmp(screen->title, live->apdu.state.screen.title) == 0);
    assert(strcmp(screen->amount, live->apdu.state.screen.amount) == 0);
    assert(strcmp(screen->address, live->apdu.state.screen.address) == 0);
    if (live->reset_on_touch) {
        blue_payment_apdu_abort(&live->apdu.state);
        live->connection_lost = true;
        return false;
    }
    if (live->refuse_touch) return false;
    ++live->continued;
    return blue_payment_apdu_touch_continue(&live->apdu.state, &live->apdu.owned);
}

static void expect_bound_digest(blue_payment_apdu *state,
    uint32_t index, const uint8_t expected[32], uint8_t expected_path) {
    uint8_t digest[32] = {0};
    uint8_t path = 0;
    assert(blue_payment_apdu_take_digest(state, index, digest, &path));
    assert(memcmp(digest, expected, sizeof digest) == 0);
    assert(path == expected_path);
}

static void test_live_usb_interruptions(const fixture *spend,
    const blue_payment_live_plan *plan,
    const zcl_tx_previous_transaction *source,
    const uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32],
    unsigned completed_exchanges) {
    blue_payment_apdu cleared = {0};
    blue_payment_apdu_abort(&cleared);
    for (unsigned cut = 1; cut <= completed_exchanges; ++cut) {
        live_fixture live = {.reset_after_reply = cut};
        apdu_init(&live.apdu);
        assert(!blue_payment_live_run_bound(spend->bytes, spend->length,
            plan, source, 1, 100000000, digests,
            live_exchange, live_continue, &live));
        assert(live.connection_lost && live.exchanges >= cut);
        assert(memcmp(&live.apdu.state, &cleared, sizeof cleared) == 0);
        if (live.interrupted_apdu[1] >= 0x21 &&
            live.interrupted_apdu[1] <= 0x28 &&
            live.interrupted_apdu[1] != 0x24 &&
            live.interrupted_apdu[1] != 0x25) {
            uint8_t reply[40] = {0};
            size_t reply_length = 99;
            assert(blue_payment_apdu_handle(&live.apdu.state,
                live.interrupted_apdu, live.interrupted_length,
                reply, sizeof reply, &reply_length, &live.apdu.blake,
                &live.apdu.sha, screen_hash, &live.apdu.owned) != 0x9000);
            assert(reply_length == 0);
            assert(memcmp(&live.apdu.state, &cleared, sizeof cleared) == 0);
        }
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
    live_fixture live = {.reset_on_touch = true};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend->bytes, spend->length,
        plan, source, 1, 100000000, digests,
        live_exchange, live_continue, &live));
    assert(live.connection_lost && live.continued == 0);
    assert(memcmp(&live.apdu.state, &cleared, sizeof cleared) == 0);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(blue_payment_live_run_bound(spend->bytes, spend->length,
        plan, source, 1, 100000000, digests,
        live_exchange, live_continue, &live));
    assert(live.apdu.state.fee_ready && live.apdu.state.bound_inputs == 1);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_live_review_status(void) {
    const uint8_t pending[8] = {1, 3, 1, 0, 2, 0, 0x90, 0};
    const uint8_t acknowledged[8] = {1, 3, 0, 0, 2, 1, 0x90, 0};
    assert(blue_payment_live_review_status(pending, sizeof pending,
                                           0, 2) == 0);
    assert(blue_payment_live_review_status(acknowledged,
                                           sizeof acknowledged, 0, 2) == 1);
    assert(blue_payment_live_review_status(pending, sizeof pending,
                                           0, 1) == -1);
    assert(blue_payment_live_review_status(pending, sizeof pending,
                                           1, 2) == -1);
    assert(blue_payment_live_review_status(acknowledged,
                                           sizeof acknowledged, 0, 0) == -1);
    assert(blue_payment_live_review_status(pending, 7, 0, 2) == -1);
    uint8_t stale[8];
    memcpy(stale, acknowledged, sizeof stale);
    stale[4] = 1;
    assert(blue_payment_live_review_status(stale, sizeof stale,
                                           0, 2) == -1);
    stale[4] = 2;
    stale[3] = 1;
    assert(blue_payment_live_review_status(stale, sizeof stale,
                                           0, 2) == -1);
}

static bool abort_reply(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    const uint8_t *bytes = context;
    assert(apdu_length == 5 && capacity >= 3);
    assert(memcmp(apdu, (const uint8_t[]){0xa5, 0x24, 0, 0, 0}, 5) == 0);
    if (bytes[0] == 0xff) return false;
    *reply_length = bytes[0];
    memcpy(reply, bytes + 1, *reply_length);
    return true;
}

static void test_live_abort_acknowledgement(void) {
    const uint8_t acknowledged[] = {2, 0x90, 0};
    const uint8_t short_reply[] = {1, 0x90};
    const uint8_t rejected[] = {2, 0x69, 0x85};
    const uint8_t extra[] = {3, 0, 0x90, 0};
    const uint8_t transport_error[] = {0xff};
    assert(blue_payment_live_abort(abort_reply, (void *)acknowledged));
    assert(!blue_payment_live_abort(abort_reply, (void *)short_reply));
    assert(!blue_payment_live_abort(abort_reply, (void *)rejected));
    assert(!blue_payment_live_abort(abort_reply, (void *)extra));
    assert(!blue_payment_live_abort(abort_reply, (void *)transport_error));
    assert(!blue_payment_live_abort(NULL, NULL));
}

static void test_live_driver(const fixture *item) {
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(item->bytes, item->length,
        0x76b809bb, &plan));
    assert(plan.count == 2 && plan.wire_length == item->length);
    assert(plan.output_end[0] == item->output_end[0]);
    assert(plan.output_end[1] == item->output_end[1]);
    live_fixture live = {0};
    apdu_init(&live.apdu);
    assert(blue_payment_live_run(item->bytes, item->length, &plan,
        live_exchange, live_continue, &live));
    assert(live.continued == 2 && live.apdu.state.review.verified);
    assert(!live.apdu.state.active);
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    uint8_t unbound_digest[32] = {0};
    uint8_t unbound_path = 0;
    assert(!blue_payment_apdu_take_digest(&live.apdu.state, 0,
        unbound_digest, &unbound_path));
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){.signing_identity = true};
    apdu_init(&live.apdu);
    assert(blue_payment_live_run(item->bytes, item->length, &plan,
        live_exchange, live_continue, &live));
    assert(live.continued == 2 && live.apdu.state.review.verified);
    EVP_MD_CTX_free(live.apdu.sha_context);

    uint8_t changed[sizeof item->bytes];
    memcpy(changed, item->bytes, item->length);
    changed[item->second_amount] ^= 1;
    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run(changed, item->length, &plan,
        live_exchange, live_continue, &live));
    assert(live.exchanges == 0);
    live.wrong_identity = true;
    assert(!blue_payment_live_run(item->bytes, item->length, &plan,
        live_exchange, live_continue, &live));
    assert(live.exchanges == 1 && !live.apdu.state.active);
    live.wrong_identity = false;
    live.refuse_touch = true;
    assert(!blue_payment_live_run(item->bytes, item->length, &plan,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.active && !live.apdu.state.review.pending);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_live_mutable_wire(const fixture *item) {
    union {
        blue_payment_live_plan plan;
        uint8_t bytes[sizeof(blue_payment_live_plan)];
    } aliased = {0};
    memcpy(aliased.bytes, item->bytes, item->length);
    assert(!blue_payment_live_prepare(aliased.bytes, item->length,
        0x76b809bb, &aliased.plan));
    assert(memcmp(aliased.bytes, item->bytes, item->length) == 0);
    blue_payment_live_plan false_screen;
    assert(blue_payment_live_prepare(item->bytes, item->length,
        0x76b809bb, &false_screen));
    false_screen.screens[0].amount[0] = '9';
    live_fixture screen_live = {0};
    apdu_init(&screen_live.apdu);
    assert(!blue_payment_live_run(item->bytes, item->length,
        &false_screen, live_exchange, live_continue, &screen_live));
    assert(screen_live.exchanges == 0);
    EVP_MD_CTX_free(screen_live.apdu.sha_context);
    const uint8_t instructions[] = {0x01, 0x21};
    for (size_t i = 0; i < sizeof instructions; ++i) {
        fixture changed = *item;
        blue_payment_live_plan plan;
        assert(blue_payment_live_prepare(changed.bytes, changed.length,
            0x76b809bb, &plan));
        live_fixture live = {.mutate_wire = changed.bytes,
            .mutate_index = changed.output_end[1],
            .mutate_instruction = instructions[i]};
        apdu_init(&live.apdu);
        assert(!blue_payment_live_run(changed.bytes, changed.length,
            &plan, live_exchange, live_continue, &live));
        assert(live.mutated && !live.apdu.state.review.verified &&
            !live.apdu.state.active);
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
    blue_payment_live_plan changed_plan;
    assert(blue_payment_live_prepare(item->bytes, item->length,
        0x76b809bb, &changed_plan));
    live_fixture plan_live = {.mutate_plan = &changed_plan,
        .mutate_instruction = 0x22};
    apdu_init(&plan_live.apdu);
    assert(!blue_payment_live_run(item->bytes, item->length,
        &changed_plan, live_exchange, live_continue, &plan_live));
    assert(plan_live.mutated && !plan_live.apdu.state.review.verified &&
        !plan_live.apdu.state.active);
    EVP_MD_CTX_free(plan_live.apdu.sha_context);
}

static void test_live_bound_mutable_wire(const fixture *spend,
    const blue_payment_live_plan *plan,
    const zcl_tx_previous_transaction *source,
    const uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32]) {
    fixture changed = *spend;
    live_fixture live = {.mutate_wire = changed.bytes,
        .mutate_index = changed.output_end[1],
        .mutate_instruction = 0x27};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(changed.bytes, changed.length,
        plan, source, 1, 100000000, digests,
        live_exchange, live_continue, &live));
    assert(live.mutated && !live.apdu.state.review.verified &&
        !live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_live_bound_mutable_previous(const fixture *spend,
    const blue_payment_live_plan *plan,
    const uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32]) {
    for (unsigned descriptor = 0; descriptor < 2; ++descriptor) {
        fixture changed = make_previous();
        zcl_tx_previous_transaction source = {
            .wire = changed.bytes, .length = changed.length};
        live_fixture early = {.mutate_instruction = 0x21,
            .mutate_index = changed.length - 1};
        if (descriptor) early.mutate_previous = &source;
        else early.mutate_wire = changed.bytes;
        apdu_init(&early.apdu);
        assert(!blue_payment_live_run_bound(spend->bytes, spend->length,
            plan, &source, 1, 100000000, digests,
            live_exchange, live_continue, &early));
        assert(early.mutated && early.previous_begins == 0 &&
            !early.apdu.state.review.verified &&
            !early.apdu.state.fee_ready);
        EVP_MD_CTX_free(early.apdu.sha_context);
    }
    const uint8_t instructions[] = {0x27, 0x28};
    for (size_t i = 0; i < sizeof instructions; ++i) {
        fixture changed = make_previous();
        zcl_tx_previous_transaction source = {
            .wire = changed.bytes, .length = changed.length};
        live_fixture live = {.mutate_wire = changed.bytes,
            .mutate_index = changed.length - 1,
            .mutate_instruction = instructions[i]};
        apdu_init(&live.apdu);
        assert(!blue_payment_live_run_bound(spend->bytes, spend->length,
            plan, &source, 1, 100000000, digests,
            live_exchange, live_continue, &live));
        assert(live.mutated && !live.apdu.state.review.verified &&
            !live.apdu.state.fee_ready);
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
    fixture unchanged = make_previous();
    zcl_tx_previous_transaction source = {
        .wire = unchanged.bytes, .length = unchanged.length};
    live_fixture descriptor = {.mutate_previous = &source,
        .mutate_instruction = 0x28};
    apdu_init(&descriptor.apdu);
    assert(!blue_payment_live_run_bound(spend->bytes, spend->length,
        plan, &source, 1, 100000000, digests,
        live_exchange, live_continue, &descriptor));
    assert(descriptor.mutated && !descriptor.apdu.state.fee_ready);
    EVP_MD_CTX_free(descriptor.apdu.sha_context);
}

static void test_live_bound(void) {
    fixture spend = make_fixture();
    memset(spend.bytes + spend.first_output_hash, 0x44, 20);
    memset(spend.bytes + spend.second_output_hash, 0x44, 20);
    fixture previous = make_previous();
    uint8_t first[32], txid[32];
    assert(SHA256(previous.bytes, previous.length, first));
    assert(SHA256(first, sizeof first, txid));
    memcpy(spend.bytes + 9, txid, sizeof txid);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        0x76b809bb, &plan));
    assert(plan.inputs == 1);
    zcl_tx_previous_transaction source = {
        .wire = previous.bytes, .length = previous.length};
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, &source, 1, digests) ==
        100000000);
    live_fixture corrupted = {.corrupt_wire_reply = true};
    apdu_init(&corrupted.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000,
        (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &corrupted));
    assert(!corrupted.apdu.state.review.verified &&
        !corrupted.apdu.state.fee_ready);
    EVP_MD_CTX_free(corrupted.apdu.sha_context);
    live_fixture live = {0};
    apdu_init(&live.apdu);
    assert(blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(live.apdu.state.fee_ready &&
        live.apdu.state.bound_inputs == 1 &&
        live.apdu.state.fee_zat == 100000000 &&
        live.apdu.state.own_output_zat == 100000000 &&
        live.apdu.state.output_zat - live.apdu.state.own_output_zat ==
            200000000 &&
        live.apdu.state.input_paths == BLUE_PAYMENT_INPUT_EXTERNAL);
    uint8_t unapproved_digest[32] = {0};
    uint8_t unapproved_path = 0;
    assert(!blue_payment_apdu_take_digest(&live.apdu.state, 0,
        unapproved_digest, &unapproved_path));
    ++live.apdu.state.fee_zat;
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    --live.apdu.state.fee_zat;
    live.apdu.state.input_record[0][32] = 0;
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    live.apdu.state.input_record[0][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    assert(blue_payment_apdu_touch_approve(&live.apdu.state));
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    expect_bound_digest(&live.apdu.state, 0, digests[0],
        BLUE_PAYMENT_INPUT_EXTERNAL);
    uint8_t absent_digest[32] = {0};
    uint8_t absent_path = 0;
    assert(!blue_payment_apdu_take_digest(&live.apdu.state, 1,
        absent_digest, &absent_path));
    assert(!blue_payment_apdu_take_digest(&live.apdu.state, 0,
        absent_digest, &absent_path));
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    test_live_usb_interruptions(&spend, &plan, &source,
        (const uint8_t (*)[32])digests, live.exchanges);
    test_live_bound_mutable_wire(&spend, &plan, &source,
        (const uint8_t (*)[32])digests);
    test_live_bound_mutable_previous(&spend, &plan,
        (const uint8_t (*)[32])digests);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){0};
    apdu_init(&live.apdu);
    memset(live.apdu.owned.external, 0x44, 20);
    memset(live.apdu.owned.internal, 0x33, 20);
    assert(blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(live.apdu.state.fee_ready &&
        live.apdu.state.own_output_zat == 100000000 &&
        live.apdu.state.input_paths == BLUE_PAYMENT_INPUT_INTERNAL);
    assert(blue_payment_apdu_touch_approve(&live.apdu.state));
    expect_bound_digest(&live.apdu.state, 0, digests[0],
        BLUE_PAYMENT_INPUT_INTERNAL);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){0};
    apdu_init(&live.apdu);
    memset(live.apdu.owned.external, 0x55, 20);
    memset(live.apdu.owned.internal, 0x66, 20);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.review.verified &&
        live.apdu.state.input_paths == 0 &&
        live.apdu.state.own_output_zat == 0);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){.no_owned_hashes = true};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.review.verified);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000001, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);

    digests[0][0] ^= 1;
    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000,
        (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);
    digests[0][0] ^= 1;

    live = (live_fixture){.fail_previous_chunk = true};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.review.verified);
    EVP_MD_CTX_free(live.apdu.sha_context);

    previous.bytes[previous.length - 1] ^= 1;
    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.review.verified);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_live_two_inputs(void) {
    fixture spend = make_fixture();
    fixture first = make_previous();
    fixture second = make_previous();
    memset(second.bytes + second.previous_hash, 0x44, 20);
    second.bytes[second.length - 1] = 1;
    assert(spend.length + 41 <= sizeof spend.bytes);
    memmove(spend.bytes + 91, spend.bytes + 50, spend.length - 50);
    memcpy(spend.bytes + 50, spend.bytes + 9, 41);
    spend.bytes[8] = 2;
    spend.length += 41;
    spend.output_end[0] += 41;
    spend.output_end[1] += 41;
    spend.second_amount += 41;
    uint8_t first_hash[32], txid[32];
    assert(SHA256(first.bytes, first.length, first_hash));
    assert(SHA256(first_hash, sizeof first_hash, txid));
    memcpy(spend.bytes + 9, txid, sizeof txid);
    assert(SHA256(second.bytes, second.length, first_hash));
    assert(SHA256(first_hash, sizeof first_hash, txid));
    memcpy(spend.bytes + 50, txid, sizeof txid);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        0x76b809bb, &plan));
    assert(plan.inputs == 2);
    zcl_tx_previous_transaction previous[2] = {
        {.wire = first.bytes, .length = first.length},
        {.wire = second.bytes, .length = second.length}
    };
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, previous, 2, digests) ==
        500000000);
    live_fixture live = {0};
    apdu_init(&live.apdu);
    assert(blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, previous, 2, 500000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(live.apdu.state.fee_ready &&
        live.apdu.state.bound_inputs == 2 &&
        live.apdu.state.input_zat == 800000000 &&
        live.apdu.state.fee_zat == 500000000 &&
        live.apdu.state.input_paths ==
            (BLUE_PAYMENT_INPUT_EXTERNAL | BLUE_PAYMENT_INPUT_INTERNAL));
    assert(blue_payment_apdu_touch_approve(&live.apdu.state));
    uint8_t out_of_order_digest[32] = {0};
    uint8_t out_of_order_path = 0;
    assert(!blue_payment_apdu_take_digest(&live.apdu.state, 1,
        out_of_order_digest, &out_of_order_path));
    expect_bound_digest(&live.apdu.state, 0, digests[0],
        BLUE_PAYMENT_INPUT_EXTERNAL);
    expect_bound_digest(&live.apdu.state, 1, digests[1],
        BLUE_PAYMENT_INPUT_INTERNAL);
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){.mutate_wire = second.bytes,
        .mutate_index = second.length - 1, .mutate_instruction = 0x27};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, previous, 2, 500000000,
        (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(live.mutated && live.previous_begins == 1 &&
        !live.apdu.state.fee_ready && !live.apdu.state.review.verified);
    EVP_MD_CTX_free(live.apdu.sha_context);
    second.bytes[second.length - 1] ^= 1;

    live = (live_fixture){0};
    apdu_init(&live.apdu);
    zcl_tx_previous_transaction reversed[2] = {previous[1], previous[0]};
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, reversed, 2, 500000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);

    memcpy(spend.bytes + 50, spend.bytes + 9, 36);
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        0x76b809bb, &plan));
    live = (live_fixture){0};
    apdu_init(&live.apdu);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, previous, 2, 500000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

typedef struct {
    EVP_PKEY *key;
    uint8_t public_key[33];
    unsigned calls;
} flow_signer;

static void flow_signer_init(flow_signer *signer) {
    static char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group,
                               sizeof group - 1), OSSL_PARAM_END
    };
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    assert(context && EVP_PKEY_keygen_init(context) > 0);
    assert(EVP_PKEY_CTX_set_params(context, params) > 0);
    assert(EVP_PKEY_generate(context, &signer->key) > 0);
    EVP_PKEY_CTX_free(context);
    uint8_t point[65];
    size_t length = 0;
    assert(EVP_PKEY_get_octet_string_param(signer->key,
        OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point, &length) > 0);
    assert(length == sizeof point && point[0] == 4);
    signer->public_key[0] = (uint8_t)(2u | (point[64] & 1u));
    memcpy(signer->public_key + 1, point + 1, 32);
}

static bool flow_public_hash(const uint8_t public_key[33],
    uint8_t hash160[20]) {
    uint8_t digest[32];
    unsigned length = 0;
    return SHA256(public_key, 33, digest) &&
        EVP_Digest(digest, sizeof digest, hash160, &length,
                   EVP_ripemd160(), NULL) == 1 && length == 20;
}

static bool flow_sign_key(flow_signer *signer, const uint8_t digest[32],
    uint8_t public_key[33], uint8_t signature[BLUE_ECDSA_DER_MAX],
    size_t *signature_length) {
    ++signer->calls;
    EVP_PKEY_CTX *operation = EVP_PKEY_CTX_new(signer->key, NULL);
    *signature_length = BLUE_ECDSA_DER_MAX;
    bool valid = operation && EVP_PKEY_sign_init(operation) > 0 &&
        EVP_PKEY_CTX_set_signature_md(operation, EVP_sha256()) > 0 &&
        EVP_PKEY_sign(operation, signature, signature_length,
                      digest, 32) > 0;
    EVP_PKEY_CTX_free(operation);
    if (valid) memcpy(public_key, signer->public_key, 33);
    return valid;
}

static bool flow_sign(void *context, uint8_t path, const uint8_t digest[32],
    uint8_t public_key[33], uint8_t signature[BLUE_ECDSA_DER_MAX],
    size_t *signature_length) {
    return path == BLUE_PAYMENT_INPUT_EXTERNAL &&
        flow_sign_key(context, digest, public_key, signature,
            signature_length);
}

typedef struct { flow_signer keys[2]; } flow_pair;

static bool flow_sign_pair(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    flow_pair *pair = context;
    if (path != BLUE_PAYMENT_INPUT_EXTERNAL &&
        path != BLUE_PAYMENT_INPUT_INTERNAL) return false;
    return flow_sign_key(&pair->keys[path - 1], digest, public_key,
        signature, signature_length);
}

static void flow_verify_signature(const flow_signer *signer,
    const uint8_t reply[BLUE_PAYMENT_SIGN_REPLY_MAX], size_t length,
    const uint8_t digest[32]) {
    assert(length >= 44 && length <= BLUE_PAYMENT_SIGN_REPLY_MAX);
    assert(reply[0] == 0 && reply[1] == BLUE_PAYMENT_INPUT_EXTERNAL);
    assert(memcmp(reply + 2, signer->public_key, 33) == 0);
    assert(reply[35] == length - 36);
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(signer->key, NULL);
    assert(verify && EVP_PKEY_verify_init(verify) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0);
    assert(EVP_PKEY_verify(verify, reply + 36, reply[35],
                           digest, 32) == 1);
    EVP_PKEY_CTX_free(verify);
}

static bool flow_host_verify(void *context, const uint8_t public_key[33],
    const uint8_t digest[32], const uint8_t *der, size_t der_length) {
    flow_signer *signer = context;
    if (memcmp(public_key, signer->public_key, 33) != 0) return false;
    EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(signer->key, NULL);
    bool valid = verify && EVP_PKEY_verify_init(verify) > 0 &&
        EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) > 0 &&
        EVP_PKEY_verify(verify, der, der_length, digest, 32) == 1;
    EVP_PKEY_CTX_free(verify);
    return valid;
}

typedef struct {
    flow_signer *signer;
    uint8_t *changed_byte;
    bool changed;
} mutating_assemble_verify;

static bool flow_mutate_wire_after_verify(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    mutating_assemble_verify *test = context;
    bool valid = flow_host_verify(test->signer, public_key, digest,
        der, der_length);
    if (valid && !test->changed) {
        *test->changed_byte ^= 1;
        test->changed = true;
    }
    return valid;
}

typedef struct {
    flow_signer *signer;
    uint8_t *caller_digest;
    uint8_t expected[32];
    bool observed, stable;
} flow_digest_snapshot_probe;

static bool flow_mutate_digest_during_verify(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    flow_digest_snapshot_probe *probe = context;
    probe->caller_digest[0] ^= 1u;
    probe->observed = true;
    probe->stable = memcmp(digest, probe->expected, 32) == 0;
    return flow_host_verify(probe->signer, public_key, digest,
        der, der_length);
}

static bool flow_reject_signature(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    (void)context;
    (void)public_key;
    (void)digest;
    (void)der;
    (void)der_length;
    return false;
}

static bool flow_host_verify_pair(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    flow_pair *pair = context;
    for (size_t i = 0; i < 2; ++i)
        if (memcmp(public_key, pair->keys[i].public_key, 33) == 0)
            return flow_host_verify(&pair->keys[i], public_key,
                digest, der, der_length);
    return false;
}

typedef struct {
    flow_pair *pair;
    blue_payment_verified_signature *outputs;
    unsigned calls;
} flow_result_mutation;

static bool flow_mutate_prior_result(void *context,
    const uint8_t public_key[33], const uint8_t digest[32],
    const uint8_t *der, size_t der_length) {
    flow_result_mutation *test = context;
    bool valid = flow_host_verify_pair(test->pair, public_key, digest,
        der, der_length);
    if (valid && ++test->calls == 2) test->outputs[0].der_length = 0;
    return valid;
}

static bool flow_approve(void *context) {
    live_fixture *live = context;
    return blue_payment_apdu_touch_approve(&live->apdu.state);
}

static bool flow_approve_repair(void *context) {
    live_fixture *live = context;
    if (!flow_approve(context) || !live->repair_expected) return false;
    *live->repair_expected = live->repair_value;
    return true;
}

static void flow_prepare_minimal(live_fixture *live,
    const uint8_t digest[32], const uint8_t owned_hash[20]) {
    apdu_init(&live->apdu);
    memcpy(live->apdu.owned.external, owned_hash, 20);
    blue_payment_apdu *state = &live->apdu.state;
    state->review.verified = true;
    state->fee_ready = true;
    state->input_count = state->bound_inputs = 1;
    state->input_paths = BLUE_PAYMENT_INPUT_EXTERNAL;
    state->input_zat = 2;
    state->output_zat = state->fee_zat = 1;
    memcpy(state->input_record[0], digest, 32);
    state->input_record[0][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
}

static void flow_host_sign_refusals(flow_signer *signer,
    const uint8_t owned_hash[20]) {
    uint8_t digest[1][32] = {{0x42}};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    blue_payment_verified_signature signatures[1];
    live_fixture live = {.signing = flow_sign,
        .signing_hash = flow_public_hash, .signer_context = signer};
    flow_prepare_minimal(&live, digest[0], owned_hash);
    unsigned calls = signer->calls;
    assert(!blue_payment_host_sign(1, paths, hashes,
        (const uint8_t (*)[32])digest, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, signer, signatures));
    assert(signer->calls == calls && !signatures[0].der_length);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){.signing_identity = true,
        .signing = flow_sign, .signing_hash = flow_public_hash,
        .signer_context = signer, .corrupt_sign_reply = true};
    flow_prepare_minimal(&live, digest[0], owned_hash);
    assert(!blue_payment_host_sign(1, paths, hashes,
        (const uint8_t (*)[32])digest, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, signer, signatures));
    assert(signer->calls == calls + 1 && !signatures[0].der_length &&
        !live.apdu.state.approved && !live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);

    live = (live_fixture){.signing_identity = true,
        .signing = flow_sign, .signing_hash = flow_public_hash,
        .signer_context = signer};
    flow_prepare_minimal(&live, digest[0], owned_hash);
    assert(blue_payment_apdu_touch_approve(&live.apdu.state));
    signatures[0].der_length = 8;
    assert(!blue_payment_host_sign(1, paths, NULL,
        (const uint8_t (*)[32])digest, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, signer, signatures));
    assert(!signatures[0].der_length && !live.apdu.state.approved &&
        !live.apdu.state.fee_ready && signer->calls == calls + 1);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void flow_host_sign_abort_output(flow_signer *signer,
    const uint8_t owned_hash[20]) {
    uint8_t digest[1][32] = {{0x42}};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    for (unsigned invalid_arguments = 0; invalid_arguments < 2;
         ++invalid_arguments) {
        blue_payment_verified_signature signature;
        memset(&signature, 0xa5, sizeof signature);
        live_fixture live = {.signing_identity = invalid_arguments != 0,
            .signing = flow_sign, .signing_hash = flow_public_hash,
            .signer_context = signer, .poison_signatures = &signature,
            .poison_count = 1};
        flow_prepare_minimal(&live, digest[0], owned_hash);
        assert(!blue_payment_host_sign(1, paths,
            invalid_arguments ? NULL : (const uint8_t (*)[20])hashes,
            (const uint8_t (*)[32])digest, live_exchange, flow_approve,
            &live, flow_public_hash, flow_host_verify, signer, &signature));
        assert(live.exchanges == (invalid_arguments ? 1u : 2u));
        const uint8_t *bytes = (const uint8_t *)&signature;
        for (size_t i = 0; i < sizeof signature; ++i)
            assert(bytes[i] == 0);
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
}

static void flow_host_sign_mutated_expectations(flow_signer *signer,
    const uint8_t owned_hash[20]) {
    const uint8_t device_digest[32] = {0x42};
    for (unsigned target = 0; target < 3; ++target) {
        uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
        uint8_t hashes[1][20], digests[1][32];
        memcpy(hashes[0], owned_hash, 20);
        memcpy(digests[0], device_digest, 32);
        uint8_t *changed = target == 0 ? paths :
            target == 1 ? hashes[0] : digests[0];
        uint8_t correct = *changed;
        *changed = target == 0 ? BLUE_PAYMENT_INPUT_INTERNAL :
            (uint8_t)(correct ^ 1u);
        live_fixture live = {.signing_identity = true,
            .signing = flow_sign, .signing_hash = flow_public_hash,
            .signer_context = signer, .repair_expected = changed,
            .repair_value = correct};
        flow_prepare_minimal(&live, device_digest, owned_hash);
        blue_payment_verified_signature signature = {.der_length = 8};
        unsigned calls = signer->calls;
        assert(!blue_payment_host_sign(1, paths,
            (const uint8_t (*)[20])hashes,
            (const uint8_t (*)[32])digests, live_exchange,
            flow_approve_repair, &live, flow_public_hash,
            flow_host_verify, signer, &signature));
        assert(*changed == correct && signer->calls == calls &&
            !signature.der_length && !live.apdu.state.approved &&
            !live.apdu.state.fee_ready);
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
}

static void flow_host_sign_storage_alias(flow_signer *signer,
    const uint8_t owned_hash[20]) {
    const uint8_t digest[32] = {0x42};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    union {
        blue_payment_verified_signature signature;
        uint8_t digest[32];
    } aliased = {0};
    memcpy(aliased.digest, digest, sizeof digest);
    live_fixture live = {.signing_identity = true,
        .signing = flow_sign, .signing_hash = flow_public_hash,
        .signer_context = signer};
    flow_prepare_minimal(&live, digest, owned_hash);
    unsigned calls = signer->calls;
    assert(!blue_payment_host_sign(1, paths, hashes,
        (const uint8_t (*)[32])aliased.digest, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, signer,
        &aliased.signature));
    assert(memcmp(aliased.digest, digest, sizeof digest) == 0);
    assert(signer->calls == calls && !live.apdu.state.approved);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void flow_partial_result_refusal(flow_signer *signer,
    const uint8_t owned_hash[20]) {
    uint8_t digests[2][32] = {{0x41}, {0x42}};
    uint8_t hashes[2][20];
    memcpy(hashes[0], owned_hash, 20);
    memcpy(hashes[1], owned_hash, 20);
    const uint8_t paths[2] = {
        BLUE_PAYMENT_INPUT_EXTERNAL, BLUE_PAYMENT_INPUT_EXTERNAL};
    live_fixture live = {.signing_identity = true,
        .signing = flow_sign, .signing_hash = flow_public_hash,
        .signer_context = signer, .corrupt_second_sign_reply = true};
    flow_prepare_minimal(&live, digests[0], owned_hash);
    live.apdu.state.input_count = live.apdu.state.bound_inputs = 2;
    memcpy(live.apdu.state.input_record[1], digests[1], 32);
    live.apdu.state.input_record[1][32] = BLUE_PAYMENT_INPUT_EXTERNAL;
    blue_payment_verified_signature signatures[2];
    unsigned calls = signer->calls;
    assert(!blue_payment_host_sign(2, paths, hashes,
        (const uint8_t (*)[32])digests, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, signer, signatures));
    assert(signer->calls == calls + 2 &&
        !signatures[0].der_length && !signatures[1].der_length &&
        !live.apdu.state.approved && !live.apdu.state.fee_ready);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static bool capture_signed_input(void *context, const zcl_tx_input *input) {
    zcl_tx_input *captured = context;
    if (input->index != 0) return false;
    *captured = *input;
    return true;
}

typedef struct {
    zcl_tx_input inputs[2];
    uint32_t seen;
} two_script_capture;

static bool capture_two_scripts(void *context, const zcl_tx_input *input) {
    two_script_capture *capture = context;
    if (input->index != capture->seen || capture->seen >= 2) return false;
    capture->inputs[capture->seen++] = *input;
    return true;
}

static void check_two_script_inputs(const uint8_t *wire, size_t length,
    const uint8_t der[8]) {
    two_script_capture captured = {0};
    assert(zcl_tx_inputs_visit(wire, length,
        capture_two_scripts, &captured) == 0 && captured.seen == 2);
    for (uint8_t i = 0; i < 2; ++i) {
        assert(captured.inputs[i].script_length == 44);
        assert(captured.inputs[i].script[0] == 9);
        assert(memcmp(captured.inputs[i].script + 1, der, 8) == 0);
        assert(captured.inputs[i].script[9] == 1 &&
               captured.inputs[i].script[10] == 33 &&
               captured.inputs[i].script[12] == i + 1);
    }
}

static void test_reviewed_wire_binding(const fixture *spend,
    const blue_payment_verified_signature signatures[2],
    const uint8_t expected[2][32]) {
    uint8_t reviewed_hash[32], output[512];
    zsha256(spend->bytes, spend->length, reviewed_hash);
    size_t length = 0;
    memset(output, 0xa5, sizeof output);
    assert(blue_payment_host_assemble_reviewed(spend->bytes, spend->length,
        reviewed_hash, signatures, expected, 2,
        output, sizeof output, &length));
    for (size_t i = length; i < sizeof output; ++i) assert(output[i] == 0);
    fixture changed = *spend;
    changed.bytes[changed.second_amount + 41] ^= 1;
    assert(blue_payment_host_assemble(changed.bytes, changed.length,
        signatures, expected, 2, output, sizeof output, &length));
    memset(output, 0xa5, sizeof output);
    length = 77;
    assert(!blue_payment_host_assemble_reviewed(changed.bytes,
        changed.length, reviewed_hash, signatures, expected, 2,
        output, sizeof output, &length));
    assert(length == 0);
    for (size_t i = 0; i < sizeof output; ++i) assert(output[i] == 0);
    uint8_t aliased_output[512] = {0};
    memcpy(aliased_output, reviewed_hash, sizeof reviewed_hash);
    length = 77;
    assert(!blue_payment_host_assemble_reviewed(spend->bytes,
        spend->length, aliased_output, signatures, expected, 2,
        aliased_output, sizeof aliased_output, &length));
    assert(memcmp(aliased_output, reviewed_hash,
        sizeof reviewed_hash) == 0 && length == 77);
    fixture input_alias = *spend;
    assert(!blue_payment_host_assemble_reviewed(input_alias.bytes,
        input_alias.length, reviewed_hash, signatures, expected, 2,
        input_alias.bytes, sizeof input_alias.bytes, &length));
    assert(memcmp(input_alias.bytes, spend->bytes, spend->length) == 0 &&
        length == 77);
    assert(!blue_payment_host_assemble_reviewed(spend->bytes,
        spend->length, reviewed_hash, signatures, expected, 2,
        output, ZCL_TX_REVIEW_MAX_BYTES + 1u, &length));
    assert(length == 77);
}

static void test_two_input_script_layout(void) {
    fixture spend = make_fixture();
    assert(spend.length + 41 <= sizeof spend.bytes);
    memmove(spend.bytes + 91, spend.bytes + 50, spend.length - 50);
    memcpy(spend.bytes + 50, spend.bytes + 9, 41);
    spend.bytes[50] ^= 1;
    spend.bytes[8] = 2;
    spend.length += 41;
    static const uint8_t der[8] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
    };
    uint8_t expected[2][32] = {{1}, {2}};
    blue_payment_verified_signature signatures[2] = {0};
    for (uint8_t i = 0; i < 2; ++i) {
        signatures[i].index = i;
        signatures[i].path = i ? BLUE_PAYMENT_INPUT_INTERNAL :
                                 BLUE_PAYMENT_INPUT_EXTERNAL;
        memcpy(signatures[i].digest, expected[i], 32);
        signatures[i].public_key[0] = 2;
        signatures[i].public_key[1] = (uint8_t)(i + 1);
        memcpy(signatures[i].der, der, sizeof der);
        signatures[i].der_length = sizeof der;
    }
    uint8_t output[512];
    size_t length = 0;
    assert(blue_payment_host_assemble(spend.bytes, spend.length,
        signatures, (const uint8_t (*)[32])expected, 2,
        output, sizeof output, &length));
    assert(length == spend.length + 88);
    check_two_script_inputs(output, length, der);
    assert(memcmp(output + 91 + 88, spend.bytes + 91,
        spend.length - 91) == 0);
    test_reviewed_wire_binding(&spend, signatures,
        (const uint8_t (*)[32])expected);
    uint8_t overlapping[512];
    memcpy(overlapping, spend.bytes, spend.length);
    size_t rejected = 99;
    assert(!blue_payment_host_assemble(overlapping, spend.length,
        signatures, (const uint8_t (*)[32])expected, 2,
        overlapping, sizeof overlapping, &rejected));
    assert(rejected == 0);
    assert(!blue_payment_host_assemble(overlapping, spend.length,
        signatures, (const uint8_t (*)[32])expected, 2,
        overlapping + 1, sizeof overlapping - 1, &rejected));
    assert(rejected == 0);
    blue_payment_verified_signature swapped[2] = {
        signatures[1], signatures[0]
    };
    assert(!blue_payment_host_assemble(spend.bytes, spend.length,
        swapped, (const uint8_t (*)[32])expected, 2,
        output, sizeof output, &length));
    assert(length == 0);
}

static void flow_check_assembly_rejections(const fixture *spend,
    const uint8_t *signed_wire, size_t signed_length,
    const blue_payment_verified_signature *verified,
    const uint8_t expected_digests[1][32]) {
    uint8_t output[512];
    size_t length = 99;
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        verified, expected_digests, 1, output, signed_length - 1, &length));
    assert(length == 0);
    length = 99;
    assert(!blue_payment_host_assemble(signed_wire, signed_length,
        verified, expected_digests, 1, output, sizeof output, &length));
    assert(length == 0);
    length = 99;
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        verified, expected_digests, 0, output, sizeof output, &length));
    assert(length == 0);
    blue_payment_verified_signature wrong = *verified;
    wrong.index = 1;
    length = 99;
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        &wrong, expected_digests, 1, output, sizeof output, &length));
    assert(length == 0);
    wrong = *verified;
    wrong.digest[0] ^= 1;
    length = 99;
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        &wrong, expected_digests, 1, output, sizeof output, &length));
    assert(length == 0);
}

static void flow_check_assembly_storage(const fixture *spend,
    const blue_payment_verified_signature *verified,
    const uint8_t expected_digests[1][32]) {
    uint8_t output[512];
    union {
        size_t length;
        uint8_t bytes[512];
    } aliased_wire = {0};
    memcpy(aliased_wire.bytes, spend->bytes, spend->length);
    assert(!blue_payment_host_assemble(aliased_wire.bytes, spend->length,
        verified, expected_digests, 1, output, sizeof output,
        &aliased_wire.length));
    assert(memcmp(aliased_wire.bytes, spend->bytes, spend->length) == 0);
    union {
        size_t length;
        uint8_t digest[32];
    } aliased_digest = {0};
    memcpy(aliased_digest.digest, expected_digests[0], 32);
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        verified, (const uint8_t (*)[32])aliased_digest.digest, 1,
        output, sizeof output, &aliased_digest.length));
    assert(memcmp(aliased_digest.digest, expected_digests[0], 32) == 0);
    union {
        size_t length;
        blue_payment_verified_signature signature;
    } aliased_signature = {.signature = *verified};
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        &aliased_signature.signature, expected_digests, 1,
        output, sizeof output, &aliased_signature.length));
    assert(memcmp(&aliased_signature.signature, verified,
        sizeof *verified) == 0);
    union {
        size_t length;
        uint8_t bytes[512];
    } aliased_output = {.length = 99};
    assert(!blue_payment_host_assemble(spend->bytes, spend->length,
        verified, expected_digests, 1, aliased_output.bytes,
        sizeof aliased_output.bytes, &aliased_output.length));
    assert(aliased_output.length == 99);
}

static void flow_check_authentication_mutations(const fixture *spend,
    const uint8_t reviewed_hash[32],
    const blue_payment_verified_signature *verified,
    const uint8_t expected_digests[1][32], const uint8_t paths[1],
    const uint8_t hashes[1][20], flow_signer *signer) {
    assert(spend->length > 51);
    for (unsigned kind = 0; kind < 6; ++kind) {
        fixture changed = *spend;
        uint8_t hash_copy[32], digest_copy[1][32],
            path_copy[1], hashes_copy[1][20];
        blue_payment_verified_signature signature = *verified;
        memcpy(hash_copy, reviewed_hash, sizeof hash_copy);
        memcpy(digest_copy, expected_digests, sizeof digest_copy);
        memcpy(path_copy, paths, sizeof path_copy);
        memcpy(hashes_copy, hashes, sizeof hashes_copy);
        uint8_t *targets[] = {changed.bytes + 51, hash_copy,
            signature.der, digest_copy[0], path_copy, hashes_copy[0]};
        mutating_assemble_verify mutation = {
            .signer = signer, .changed_byte = targets[kind]
        };
        uint8_t output[512];
        memset(output, 0xa5, sizeof output);
        size_t length = 77;
        assert(!blue_payment_host_assemble_authenticated(changed.bytes,
            changed.length, hash_copy, &signature,
            (const uint8_t (*)[32])digest_copy, path_copy,
            (const uint8_t (*)[20])hashes_copy, 1,
            flow_public_hash, flow_mutate_wire_after_verify, &mutation,
            output, sizeof output, &length));
        assert(mutation.changed && length == 0);
        for (size_t i = 0; i < sizeof output; ++i)
            assert(output[i] == 0);
    }
    uint8_t mutable_digest[1][32];
    memcpy(mutable_digest, expected_digests, sizeof mutable_digest);
    flow_digest_snapshot_probe probe = {
        .signer = signer, .caller_digest = mutable_digest[0]
    };
    memcpy(probe.expected, expected_digests[0], sizeof probe.expected);
    uint8_t rejected[512];
    memset(rejected, 0xa5, sizeof rejected);
    size_t rejected_length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, verified,
        (const uint8_t (*)[32])mutable_digest, paths, hashes, 1,
        flow_public_hash, flow_mutate_digest_during_verify, &probe,
        rejected, sizeof rejected, &rejected_length));
    assert(probe.observed && probe.stable && rejected_length == 0);
    for (size_t i = 0; i < sizeof rejected; ++i)
        assert(rejected[i] == 0);
    fixture aliased = *spend;
    size_t length = 77;
    assert(!blue_payment_host_assemble_authenticated(aliased.bytes,
        aliased.length, reviewed_hash, verified, expected_digests,
        paths, hashes, 1, flow_public_hash, flow_host_verify, signer,
        aliased.bytes, sizeof aliased.bytes, &length));
    assert(length == 77 &&
        memcmp(aliased.bytes, spend->bytes, spend->length) == 0);
    static uint8_t oversized_output[512];
    memset(oversized_output, 0xa5, sizeof oversized_output);
    length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, verified, expected_digests,
        paths, hashes, 1, flow_public_hash, flow_host_verify, signer,
        oversized_output, ZCL_TX_REVIEW_MAX_BYTES + 1, &length));
    assert(length == 77);
    for (size_t i = 0; i < sizeof oversized_output; ++i)
        assert(oversized_output[i] == 0xa5);
}

static void flow_check_assembly(const fixture *spend,
    const uint8_t *reply, size_t reply_length, const uint8_t digest[32],
    const uint8_t owned_hash[20],
    const zcl_tx_previous_transaction *source, flow_signer *signer) {
    uint8_t response[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
    memcpy(response, reply, reply_length);
    response[reply_length] = 0x90;
    response[reply_length + 1] = 0;
    blue_payment_verified_signature verified;
    assert(blue_payment_host_verify(response, reply_length + 2, 0,
        BLUE_PAYMENT_INPUT_EXTERNAL, owned_hash, digest, flow_public_hash,
        flow_host_verify, signer, &verified));
    uint8_t expected_digests[1][32];
    memcpy(expected_digests[0], digest, 32);
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    uint8_t reviewed_hash[32];
    zsha256(spend->bytes, spend->length, reviewed_hash);
    uint8_t signed_wire[512];
    size_t signed_length = 0;
    memset(signed_wire, 0xa5, sizeof signed_wire);
    assert(blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    for (size_t i = signed_length; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    uint8_t wrong_reviewed_hash[32];
    memcpy(wrong_reviewed_hash, reviewed_hash, sizeof wrong_reviewed_hash);
    wrong_reviewed_hash[0] ^= 1;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, wrong_reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    assert(signed_length == 0);
    for (size_t i = 0; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    flow_check_authentication_mutations(spend, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, signer);
    blue_payment_verified_signature forged = verified;
    forged.der[forged.der_length - 1] ^= 1;
    memset(signed_wire, 0xa5, sizeof signed_wire);
    signed_length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &forged,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    assert(signed_length == 0);
    for (size_t i = 0; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    memset(signed_wire, 0xa5, sizeof signed_wire);
    signed_length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_reject_signature, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    assert(signed_length == 0);
    for (size_t i = 0; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    hashes[0][0] ^= 1;
    memset(signed_wire, 0xa5, sizeof signed_wire);
    signed_length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    hashes[0][0] ^= 1;
    assert(signed_length == 0);
    for (size_t i = 0; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    reviewed_hash[0] ^= 1;
    memset(signed_wire, 0xa5, sizeof signed_wire);
    signed_length = 77;
    assert(!blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    reviewed_hash[0] ^= 1;
    assert(signed_length == 0);
    for (size_t i = 0; i < sizeof signed_wire; ++i)
        assert(signed_wire[i] == 0);
    assert(blue_payment_host_assemble_authenticated(spend->bytes,
        spend->length, reviewed_hash, &verified,
        (const uint8_t (*)[32])expected_digests, paths,
        (const uint8_t (*)[20])hashes, 1,
        flow_public_hash, flow_host_verify, signer,
        signed_wire, sizeof signed_wire, &signed_length));
    assert(signed_length == spend->length + verified.der_length + 36);
    zcl_tx_review original, assembled;
    assert(zcl_tx_review_parse(spend->bytes, spend->length, &original) == 0);
    assert(zcl_tx_review_parse(signed_wire, signed_length, &assembled) == 0);
    assert(assembled.transparent_inputs == original.transparent_inputs &&
        assembled.transparent_outputs == original.transparent_outputs &&
        assembled.transparent_output_zat == original.transparent_output_zat);
    zcl_tx_input input = {0};
    assert(zcl_tx_inputs_visit(signed_wire, signed_length,
        capture_signed_input, &input) == 0);
    assert(input.script_length == (size_t)verified.der_length + 36 &&
        input.script[0] == verified.der_length + 1 &&
        memcmp(input.script + 1, verified.der, verified.der_length) == 0 &&
        input.script[verified.der_length + 1] == 1 &&
        input.script[verified.der_length + 2] == 33 &&
        memcmp(input.script + verified.der_length + 3,
            verified.public_key, 33) == 0);
    assert(memcmp(signed_wire + 51 + input.script_length,
        spend->bytes + 51, spend->length - 51) == 0);
    struct blake2b_ctx blake_context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake_context);
    zcl_tx_transparent_facts facts;
    uint8_t signed_digest[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    /* Preflight accepts only unsigned inputs. */
    assert(zcl_tx_transparent_bound_digests(signed_wire, signed_length,
        source, 1, 0x76b809bb, screen_hash, &hasher, &facts,
        signed_digest, ZCL_TX_PREFLIGHT_MAX_INPUTS) != 0);
    flow_check_assembly_rejections(spend, signed_wire, signed_length,
        &verified, (const uint8_t (*)[32])expected_digests);
    flow_check_assembly_storage(spend, &verified,
        (const uint8_t (*)[32])expected_digests);
}

static void flow_readonly_never_signs(const fixture *spend,
    const blue_payment_live_plan *plan,
    const zcl_tx_previous_transaction *source,
    const uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32],
    const uint8_t owned_hash[20], flow_signer *signer) {
    live_fixture live = {0};
    apdu_init(&live.apdu);
    memcpy(live.apdu.owned.external, owned_hash, 20);
    assert(blue_payment_live_run_bound(spend->bytes, spend->length,
        plan, source, 1, 100000000, digests,
        live_exchange, live_continue, &live));
    assert(live.apdu.state.fee_ready);
    assert(blue_payment_live_abort(live_exchange, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.approved);
    assert(!blue_payment_apdu_touch_confirm(&live.apdu.state));
    assert(!blue_payment_apdu_touch_approve(&live.apdu.state));
    uint8_t frame[BLUE_PAYMENT_SIGN_REPLY_MAX] = {0xa5, 0x29, 0, 0, 1, 0};
    size_t reply_length = 99;
    unsigned calls = signer->calls;
    assert(blue_payment_sign_command(&live.apdu.state, frame, 6,
        &live.apdu.owned, flow_sign, signer, flow_public_hash,
        frame, sizeof frame, &reply_length) == 0x6985);
    assert(reply_length == 0 && signer->calls == calls);
    for (size_t i = 0; i < sizeof frame; ++i) assert(frame[i] == 0);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_review_to_signature_flow(void) {
    flow_signer signer = {0};
    flow_signer_init(&signer);
    uint8_t owned_hash[20];
    assert(flow_public_hash(signer.public_key, owned_hash));
    blue_payment_fixture built;
    assert(blue_payment_fixture_make(owned_hash, &built));
    fixture previous = {.length = built.previous_length};
    fixture spend = {.length = built.unsigned_length};
    memcpy(previous.bytes, built.previous, previous.length);
    memcpy(spend.bytes, built.unsigned_wire, spend.length);
    assert(previous.length == 85 && spend.length == 136);
    zcl_tx_previous_transaction source = {
        .wire = previous.bytes, .length = previous.length
    };
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, &source, 1, digests) == 100000000);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
                                     0x76b809bb, &plan));
    flow_readonly_never_signs(&spend, &plan, &source,
        (const uint8_t (*)[32])digests, owned_hash, &signer);
    flow_host_sign_refusals(&signer, owned_hash);
    flow_host_sign_abort_output(&signer, owned_hash);
    flow_host_sign_mutated_expectations(&signer, owned_hash);
    flow_host_sign_storage_alias(&signer, owned_hash);
    flow_partial_result_refusal(&signer, owned_hash);
    live_fixture live = {.signing_identity = true,
        .signing = flow_sign, .signing_hash = flow_public_hash,
        .signer_context = &signer};
    apdu_init(&live.apdu);
    memcpy(live.apdu.owned.external, owned_hash, 20);
    assert(blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &source, 1, 100000000, (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(live.continued == 2 && live.apdu.state.fee_ready &&
           live.apdu.state.own_output_zat == 100000000);
    uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    blue_payment_verified_signature signatures[1];
    assert(blue_payment_host_sign(1, paths,
        (const uint8_t (*)[20])hashes,
        (const uint8_t (*)[32])digests, live_exchange, flow_approve,
        &live, flow_public_hash, flow_host_verify, &signer, signatures));
    assert(signer.calls == 4 && !live.apdu.state.approved);
    assert(signatures[0].index == 0 && signatures[0].der_length >= 8);
    flow_verify_signature(&signer, live.last_sign_reply,
        live.last_sign_length, digests[0]);
    flow_check_assembly(&spend, live.last_sign_reply,
        live.last_sign_length, digests[0],
        owned_hash, &source, &signer);
    EVP_MD_CTX_free(live.apdu.sha_context);
    EVP_PKEY_free(signer.key);
}

static void test_two_path_review_to_signed_wire(void) {
    flow_pair pair = {0};
    flow_signer_init(&pair.keys[0]);
    flow_signer_init(&pair.keys[1]);
    uint8_t external[20], internal[20];
    assert(flow_public_hash(pair.keys[0].public_key, external));
    assert(flow_public_hash(pair.keys[1].public_key, internal));
    assert(memcmp(external, internal, 20) != 0);
    blue_payment_fixture first, second;
    assert(blue_payment_fixture_make(external, &first));
    assert(blue_payment_fixture_make(internal, &second));
    fixture spend = {.length = first.unsigned_length + 41};
    memcpy(spend.bytes, first.unsigned_wire, first.unsigned_length);
    memmove(spend.bytes + 91, spend.bytes + 50,
        first.unsigned_length - 50);
    memcpy(spend.bytes + 50, second.unsigned_wire + 9, 41);
    spend.bytes[8] = 2;
    zcl_tx_previous_transaction previous[2] = {
        {.wire = first.previous, .length = first.previous_length},
        {.wire = second.previous, .length = second.previous_length}
    };
    blue_payment_host_ownership owned = {0};
    assert(blue_payment_host_propose_paths(spend.bytes, spend.length,
        previous, 2, screen_hash, external, &owned));
    assert(owned.paths[0] == BLUE_PAYMENT_INPUT_EXTERNAL &&
        owned.paths[1] == BLUE_PAYMENT_INPUT_INTERNAL &&
        owned.facts.fee_zat == 500000000);
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, previous, 2, digests) ==
        owned.facts.fee_zat);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    live_fixture live = {.signing_identity = true,
        .signing = flow_sign_pair, .signing_hash = flow_public_hash,
        .signer_context = &pair};
    apdu_init(&live.apdu);
    memcpy(live.apdu.owned.external, external, 20);
    memcpy(live.apdu.owned.internal, internal, 20);
    assert(blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, previous, 2, owned.facts.fee_zat,
        (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    blue_payment_verified_signature signatures[2];
    flow_result_mutation mutation = {.pair = &pair, .outputs = signatures};
    assert(blue_payment_host_sign(2, owned.paths,
        (const uint8_t (*)[20])owned.hashes,
        (const uint8_t (*)[32])digests, live_exchange, flow_approve,
        &live, flow_public_hash, flow_mutate_prior_result, &mutation,
        signatures));
    assert(pair.keys[0].calls == 1 && pair.keys[1].calls == 1 &&
        mutation.calls == 2 && signatures[0].der_length >= 8 &&
        !live.apdu.state.approved && signatures[0].index == 0 &&
        signatures[1].index == 1);
    uint8_t signed_wire[512];
    size_t signed_length = 0;
    assert(blue_payment_host_assemble_authenticated(spend.bytes,
        spend.length, plan.wire_hash, signatures,
        (const uint8_t (*)[32])digests, owned.paths,
        (const uint8_t (*)[20])owned.hashes, 2,
        flow_public_hash, flow_host_verify_pair, &pair,
        signed_wire, sizeof signed_wire, &signed_length));
    two_script_capture captured = {0};
    assert(zcl_tx_inputs_visit(signed_wire, signed_length,
        capture_two_scripts, &captured) == 0 && captured.seen == 2);
    for (size_t i = 0; i < 2; ++i) {
        const zcl_tx_input *input = &captured.inputs[i];
        assert(input->script_length ==
            (size_t)signatures[i].der_length + 36 &&
            memcmp(input->script + signatures[i].der_length + 3,
                pair.keys[i].public_key, 33) == 0);
    }
    EVP_MD_CTX_free(live.apdu.sha_context);
    EVP_PKEY_free(pair.keys[0].key);
    EVP_PKEY_free(pair.keys[1].key);
}

static void test_unowned_internal_candidate_rejected(void) {
    uint8_t external[20], internal[20], other[20];
    memset(external, 0x33, sizeof external);
    memset(internal, 0x44, sizeof internal);
    memset(other, 0x55, sizeof other);
    blue_payment_fixture built;
    assert(blue_payment_fixture_make(other, &built));
    fixture spend = {.length = built.unsigned_length};
    memcpy(spend.bytes, built.unsigned_wire, spend.length);
    zcl_tx_previous_transaction previous = {
        .wire = built.previous, .length = built.previous_length};
    blue_payment_host_ownership proposed = {0};
    assert(blue_payment_host_propose_paths(spend.bytes, spend.length,
        &previous, 1, screen_hash, external, &proposed));
    assert(proposed.paths[0] == BLUE_PAYMENT_INPUT_INTERNAL &&
        memcmp(proposed.hashes[0], other, 20) == 0);
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, &previous, 1, digests) ==
        proposed.facts.fee_zat);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    live_fixture live = {0};
    apdu_init(&live.apdu);
    memcpy(live.apdu.owned.external, external, 20);
    memcpy(live.apdu.owned.internal, internal, 20);
    assert(!blue_payment_live_run_bound(spend.bytes, spend.length,
        &plan, &previous, 1, proposed.facts.fee_zat,
        (const uint8_t (*)[32])digests,
        live_exchange, live_continue, &live));
    assert(!live.apdu.state.fee_ready && !live.apdu.state.approved);
    EVP_MD_CTX_free(live.apdu.sha_context);
}

static void test_signing_usb_interruptions(void) {
    flow_signer signer = {0};
    flow_signer_init(&signer);
    uint8_t owned_hash[20];
    assert(flow_public_hash(signer.public_key, owned_hash));
    blue_payment_fixture built;
    assert(blue_payment_fixture_make(owned_hash, &built));
    fixture spend = {.length = built.unsigned_length};
    memcpy(spend.bytes, built.unsigned_wire, spend.length);
    zcl_tx_previous_transaction previous = {
        .wire = built.previous, .length = built.previous_length};
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(expected_bound_digests(&spend, &previous, 1, digests) ==
        100000000);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(spend.bytes, spend.length,
        BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    uint8_t hashes[1][20];
    memcpy(hashes[0], owned_hash, 20);
    for (unsigned cut = 1; cut <= 2; ++cut) {
        live_fixture live = {.signing_identity = true,
            .signing = flow_sign, .signing_hash = flow_public_hash,
            .signer_context = &signer};
        apdu_init(&live.apdu);
        memcpy(live.apdu.owned.external, owned_hash, 20);
        assert(blue_payment_live_run_bound(spend.bytes, spend.length,
            &plan, &previous, 1, 100000000,
            (const uint8_t (*)[32])digests,
            live_exchange, live_continue, &live));
        live.reset_after_reply = live.exchanges + cut;
        unsigned calls = signer.calls;
        blue_payment_verified_signature signature = {.der_length = 8};
        assert(!blue_payment_host_sign(1, paths,
            (const uint8_t (*)[20])hashes,
            (const uint8_t (*)[32])digests, live_exchange, flow_approve,
            &live, flow_public_hash, flow_host_verify, &signer,
            &signature));
        assert(!signature.der_length && !live.apdu.state.approved &&
            !live.apdu.state.fee_ready && live.connection_lost &&
            signer.calls == calls + (cut == 2));
        live.connection_lost = false;
        uint8_t request[6] = {0xa5, 0x29, 0, 0, 1, 0};
        uint8_t reply[BLUE_PAYMENT_SIGN_REPLY_MAX + 2];
        size_t reply_length = 0;
        assert(live_exchange(&live, request, sizeof request,
            reply, sizeof reply, &reply_length));
        assert(reply_length == 2 && reply[0] == 0x69 && reply[1] == 0x85 &&
            signer.calls == calls + (cut == 2));
        EVP_MD_CTX_free(live.apdu.sha_context);
    }
    EVP_PKEY_free(signer.key);
}

int main(int argc, char **argv) {
    fixture item = make_fixture();
    test_success(&item);
    test_finish_alias(&item);
    test_feed_alias(&item);
    test_failures(&item);
    test_simulation(&item);
    test_apdu(&item);
    test_apdu_fail_closed(&item);
    test_apdu_storage_alias(&item);
    test_apdu_request_and_owned_alias(&item);
    test_apdu_mutations();
    test_live_review_status();
    test_live_abort_acknowledgement();
    test_live_driver(&item);
    test_live_mutable_wire(&item);
    test_live_bound();
    test_live_two_inputs();
    test_two_input_script_layout();
    test_review_to_signature_flow();
    test_two_path_review_to_signed_wire();
    test_unowned_internal_candidate_rejected();
    test_signing_usb_interruptions();
    if (argc == 2) {
        FILE *file = fopen(argv[1], "wb");
        assert(file);
        assert(fwrite(item.bytes, 1, item.length, file) == item.length);
        assert(fclose(file) == 0);
    }
    return 0;
}
