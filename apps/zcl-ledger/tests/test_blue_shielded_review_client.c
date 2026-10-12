/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_shielded_review_app.h"
#include "blue_shielded_review_client.h"
#include "blue_sapling_fixture.h"
#include "zcl_zip243_host.h"
#include "zsha256/zsha256.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { BRANCH = 0x76b809bb };
enum {
    CORRUPT_SHORT = 1,
    CORRUPT_STATUS,
    CORRUPT_OVERSIZE,
    CORRUPT_BODY
};

typedef struct {
    blue_shielded_review_app app;
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher;
    unsigned calls, fail_at, erases, corrupt_at, corrupt_kind, mutate_at,
        poison_at;
    uint8_t *mutate_wire;
    blue_shielded_review_receipt *poison_receipt;
    bool alter_digest, alter_commitment, alter_progress, old_version;
} simulator;

static void reset_simulator(simulator *sim) {
    memset(sim, 0, sizeof *sim);
    sim->hasher = zcl_zip243_host_hasher(&sim->blake);
    blue_shielded_review_app_reset(&sim->app);
}

static void alter_reply(const simulator *sim, uint8_t *reply,
    size_t body_length, size_t capacity, size_t *reply_length) {
    if (sim->calls != sim->corrupt_at) return;
    if (sim->corrupt_kind == CORRUPT_SHORT)
        *reply_length = body_length + 1;
    else if (sim->corrupt_kind == CORRUPT_STATUS)
        reply[body_length] ^= 1u;
    else if (sim->corrupt_kind == CORRUPT_OVERSIZE)
        *reply_length = capacity + 1;
    else reply[body_length ? body_length - 1 : body_length] ^= 1u;
}

static void alter_wire(simulator *sim) {
    if (sim->calls == sim->mutate_at) sim->mutate_wire[0] ^= 1u;
}

static void poison_outputs(simulator *sim) {
    if (sim->calls != sim->poison_at) return;
    memset(sim->poison_receipt, 0xa5, sizeof *sim->poison_receipt);
}

static void alter_result(simulator *sim, const uint8_t *apdu,
    uint16_t status, uint8_t *reply) {
    if (status != 0x9000) return;
    if (apdu[1] == 0x23 && sim->alter_digest) reply[44] ^= 1u;
    if (apdu[1] == 0x23 && sim->alter_commitment) reply[76] ^= 1u;
    if (apdu[1] == 0x21 && sim->alter_progress) reply[1] ^= 1u;
    if (apdu[1] == 0x01 && sim->old_version) reply[3] = 6;
}

static bool exchange(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    simulator *sim = context;
    ++sim->calls;
    if (apdu_length >= 2 && apdu[1] == 0x24) ++sim->erases;
    if (sim->calls == sim->fail_at || capacity < 2) return false;
    size_t body_length = 0;
    uint16_t status = blue_shielded_review_app_command(&sim->app,
        apdu, apdu_length, reply, capacity - 2,
        &body_length, &sim->hasher);
    if (body_length + 2 > capacity) return false;
    alter_result(sim, apdu, status, reply);
    reply[body_length] = (uint8_t)(status >> 8);
    reply[body_length + 1] = (uint8_t)status;
    *reply_length = body_length + 2;
    alter_reply(sim, reply, body_length, capacity, reply_length);
    alter_wire(sim);
    poison_outputs(sim);
    return true;
}

static void assert_zero(const zcl_tx_review *review,
    const uint8_t digest[32]) {
    const uint8_t *bytes = (const uint8_t *)review;
    for (size_t i = 0; i < sizeof *review; ++i) assert(bytes[i] == 0);
    for (unsigned i = 0; i < 32; ++i) assert(digest[i] == 0);
}

static void assert_receipt_zero(const blue_shielded_review_receipt *receipt) {
    const uint8_t *bytes = (const uint8_t *)receipt;
    for (size_t i = 0; i < sizeof *receipt; ++i) assert(bytes[i] == 0);
}

static void successful_review(const uint8_t *wire) {
    uint8_t mutable_wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    memcpy(mutable_wire, wire, sizeof mutable_wire);
    simulator sim;
    reset_simulator(&sim);
    blue_shielded_review_receipt receipt;
    uint8_t independent[32];
    sim.poison_at = 50;
    sim.poison_receipt = &receipt;
    assert(blue_shielded_review_client_run_receipt(mutable_wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH,
        exchange, &sim, &receipt));
    assert(receipt.facts.sapling_spends == 1 &&
        receipt.facts.sapling_outputs == 1);
    assert(receipt.branch_id == BRANCH &&
        receipt.wire_length == BLUE_SYNTHETIC_SAPLING_BYTES);
    assert(sim.app.transaction.complete && !sim.erases);
    assert(memcmp(receipt.zip243_digest,
        sim.app.transaction.digest, 32) == 0);
    zsha256(wire, BLUE_SYNTHETIC_SAPLING_BYTES, independent);
    assert(memcmp(receipt.wire_sha256, independent, 32) == 0);
    assert(memcmp(receipt.wire_sha256, sim.app.reply + 76, 32) == 0);
    mutable_wire[27 + 320] ^= 1u;
    zsha256(mutable_wire, sizeof mutable_wire, independent);
    assert(memcmp(receipt.wire_sha256, independent, 32) != 0);
    assert(sim.calls == 50);
}

static void rejected_commitment(const uint8_t *wire) {
    simulator sim;
    reset_simulator(&sim);
    sim.alter_commitment = true;
    blue_shielded_review_receipt receipt;
    memset(&receipt, 0xa5, sizeof receipt);
    assert(!blue_shielded_review_client_run_receipt(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH,
        exchange, &sim, &receipt));
    assert_receipt_zero(&receipt);
    assert(sim.erases == 1 && !sim.app.transaction.complete);
}

static void excluded_proof_changes_wire_commitment(const uint8_t *wire) {
    uint8_t changed[BLUE_SYNTHETIC_SAPLING_BYTES];
    memcpy(changed, wire, sizeof changed);
    changed[27 + 320] ^= 1u;
    simulator original, altered;
    reset_simulator(&original);
    reset_simulator(&altered);
    blue_shielded_review_receipt first, second;
    assert(blue_shielded_review_client_run_receipt(wire, sizeof changed,
        BRANCH, exchange, &original, &first));
    assert(blue_shielded_review_client_run_receipt(changed, sizeof changed,
        BRANCH, exchange, &altered, &second));
    assert(memcmp(first.zip243_digest, second.zip243_digest, 32) == 0);
    assert(memcmp(first.wire_sha256, second.wire_sha256, 32) != 0);
    assert(memcmp(original.app.reply + 76,
        altered.app.reply + 76, 32) != 0);
    assert(blue_shielded_review_app_next(&altered.app));
    assert(blue_shielded_review_app_next(&altered.app));
    assert(strcmp(altered.app.lines[0], "FULL WIRE SHA-256") == 0);
}

static void failed_review(const uint8_t *wire,
    unsigned fail_at, bool alter_digest, bool alter_progress,
    bool old_version) {
    simulator sim;
    reset_simulator(&sim);
    sim.fail_at = fail_at;
    sim.alter_digest = alter_digest;
    sim.alter_progress = alter_progress;
    sim.old_version = old_version;
    blue_shielded_review_receipt receipt;
    memset(&receipt, 0xa5, sizeof receipt);
    assert(!blue_shielded_review_client_run_receipt(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH,
        exchange, &sim, &receipt));
    assert_receipt_zero(&receipt);
    assert(sim.erases == 1);
    if (fail_at) assert(sim.calls == fail_at + 1);
    assert(!sim.app.transaction.active && !sim.app.transaction.complete);
}

static void corrupted_reply(const uint8_t *wire,
    unsigned call, unsigned kind) {
    simulator sim;
    reset_simulator(&sim);
    sim.corrupt_at = call;
    sim.corrupt_kind = kind;
    blue_shielded_review_receipt receipt;
    memset(&receipt, 0xa5, sizeof receipt);
    assert(!blue_shielded_review_client_run_receipt(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH,
        exchange, &sim, &receipt));
    assert_receipt_zero(&receipt);
    assert(sim.calls == call + 1 && sim.erases == 1);
    assert(!sim.app.transaction.active && !sim.app.transaction.complete);
}

static void output_aliases(const uint8_t *wire) {
    union {
        zcl_tx_review review;
        uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    } aliased;
    uint8_t original[BLUE_SYNTHETIC_SAPLING_BYTES];
    uint8_t digest[32];
    memset(digest, 0xa5, sizeof digest);
    simulator sim;
    reset_simulator(&sim);
    memcpy(aliased.wire, wire, sizeof aliased.wire);
    memcpy(original, aliased.wire, sizeof original);
    assert(!blue_shielded_review_client_run(aliased.wire,
        sizeof aliased.wire, BRANCH, exchange, &sim,
        &aliased.review, digest));
    assert(sim.calls == 0 &&
        memcmp(aliased.wire, original, sizeof original) == 0);
    for (size_t i = 0; i < sizeof digest; ++i) assert(digest[i] == 0xa5);

    reset_simulator(&sim);
    zcl_tx_review separate_review;
    memset(&separate_review, 0xa5, sizeof separate_review);
    assert(!blue_shielded_review_client_run(aliased.wire,
        sizeof aliased.wire, BRANCH, exchange, &sim,
        &separate_review, aliased.wire + 16));
    assert(sim.calls == 0 &&
        memcmp(aliased.wire, original, sizeof original) == 0);
    const uint8_t *review_bytes = (const uint8_t *)&separate_review;
    for (size_t i = 0; i < sizeof separate_review; ++i)
        assert(review_bytes[i] == 0xa5);

    union {
        zcl_tx_review review;
        uint8_t bytes[sizeof(zcl_tx_review)];
    } outputs;
    static_assert(sizeof outputs.bytes >= 32);
    memset(outputs.bytes, 0xa5, sizeof outputs.bytes);
    reset_simulator(&sim);
    assert(!blue_shielded_review_client_run(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH, exchange, &sim,
        &outputs.review, outputs.bytes));
    assert(sim.calls == 0);
    for (size_t i = 0; i < sizeof outputs.bytes; ++i)
        assert(outputs.bytes[i] == 0xa5);

    union {
        blue_shielded_review_receipt receipt;
        uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    } bound;
    memcpy(bound.wire, wire, sizeof bound.wire);
    reset_simulator(&sim);
    assert(!blue_shielded_review_client_run_receipt(bound.wire,
        sizeof bound.wire, BRANCH, exchange, &sim, &bound.receipt));
    assert(sim.calls == 0 &&
        memcmp(bound.wire, wire, sizeof bound.wire) == 0);
    reset_simulator(&sim);
    assert(!blue_shielded_review_client_run_receipt(bound.wire,
        sizeof bound.wire, BRANCH, exchange, &sim,
        (blue_shielded_review_receipt *)(void *)(bound.wire + 16)));
    assert(sim.calls == 0 &&
        memcmp(bound.wire, wire, sizeof bound.wire) == 0);
}

static void changed_wire_during_review(const uint8_t *wire) {
    for (unsigned at = 1; at <= 50; ++at) {
        uint8_t changed[BLUE_SYNTHETIC_SAPLING_BYTES];
        memcpy(changed, wire, sizeof changed);
        simulator sim;
        reset_simulator(&sim);
        sim.mutate_wire = changed;
        sim.mutate_at = at;
        blue_shielded_review_receipt receipt;
        memset(&receipt, 0xa5, sizeof receipt);
        assert(!blue_shielded_review_client_run_receipt(changed,
            sizeof changed, BRANCH, exchange, &sim, &receipt));
        assert_receipt_zero(&receipt);
        assert(sim.calls == 51 && sim.erases == 1);
        assert(!sim.app.transaction.active && !sim.app.transaction.complete);
    }
}

static void erase_callback_changes_outputs(const uint8_t *wire) {
    simulator sim;
    reset_simulator(&sim);
    sim.alter_digest = true;
    sim.poison_at = 51;
    blue_shielded_review_receipt receipt;
    sim.poison_receipt = &receipt;
    assert(!blue_shielded_review_client_run_receipt(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH, exchange, &sim,
        &receipt));
    assert(sim.calls == 51 && sim.erases == 1);
    assert_receipt_zero(&receipt);
}

static int hex_digit(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[8192]) {
    FILE *file = fopen(path, "r");
    assert(file);
    int ch;
    do {
        ch = fgetc(file);
        if (ch == '#') {
            while (ch != '\n' && ch != EOF) ch = fgetc(file);
        }
    } while (ch == '#' || ch == '\n');
    size_t length = 0;
    while (ch != EOF && ch != '\n') {
        int high = hex_digit(ch);
        int low = hex_digit(fgetc(file));
        assert(high >= 0 && low >= 0 && length < 8192);
        wire[length++] = (uint8_t)((high << 4) | low);
        ch = fgetc(file);
    }
    assert(!ferror(file) && fclose(file) == 0);
    return length;
}

static void published_vector(const char *path) {
    static uint8_t wire[8192];
    size_t length = read_vector(path, wire);
    assert(length == 4118);
    simulator sim;
    reset_simulator(&sim);
    zcl_tx_review review;
    uint8_t digest[32];
    static const uint8_t expected[32] = {
        0x63, 0xd1, 0x85, 0x34, 0xde, 0x5f, 0x2d, 0x1c,
        0x9e, 0x16, 0x9b, 0x73, 0xf9, 0xc7, 0x83, 0x71,
        0x8a, 0xdb, 0xef, 0x5c, 0x8a, 0x7d, 0x55, 0xb5,
        0xe7, 0xa3, 0x7a, 0xff, 0xa1, 0xdd, 0x3f, 0xf3
    };
    assert(blue_shielded_review_client_run(wire, length, BRANCH,
        exchange, &sim, &review, digest));
    assert(review.sapling_spends == 3 && review.sapling_outputs == 3);
    assert(memcmp(digest, expected, sizeof expected) == 0);
}

static void check_consensus_screen(const blue_shielded_review_app *app,
    const char *const expected[ZCL_BLUE_REVIEW_LINES]) {
    for (unsigned i = 0; i < ZCL_BLUE_REVIEW_LINES; ++i) {
        if (strcmp(app->lines[i], expected[i]) != 0)
            fprintf(stderr, "shielded line %u: expected '%s', got '%s'\n",
                i, expected[i], app->lines[i]);
        assert(strcmp(app->lines[i], expected[i]) == 0);
    }
}

static void consensus_spend_vector(const char *path) {
    static uint8_t wire[8192];
    static const uint8_t expected[32] = {
        0xd4, 0x96, 0x7a, 0x82, 0x69, 0x00, 0x77, 0x09,
        0xfd, 0x06, 0x3a, 0x59, 0x2f, 0x73, 0x59, 0xb8,
        0x64, 0xfa, 0x39, 0x0c, 0x76, 0xf4, 0x60, 0x9d,
        0xc9, 0xf9, 0xb9, 0x60, 0x69, 0xc2, 0x7c, 0x8b
    };
    size_t length = read_vector(path, wire);
    assert(length == BLUE_SYNTHETIC_SAPLING_BYTES);
    simulator sim;
    reset_simulator(&sim);
    zcl_tx_review review;
    uint8_t digest[32];
    assert(blue_shielded_review_client_run(wire, length, BRANCH,
        exchange, &sim, &review, digest));
    assert(review.sapling_spends == 1 && review.sapling_outputs == 1);
    assert(sim.app.transaction.complete && sim.calls == 50);
    assert(memcmp(digest, expected, sizeof expected) == 0);
    assert(memcmp(sim.app.transaction.digest, expected,
        sizeof expected) == 0);
    static const char *const summary[ZCL_BLUE_REVIEW_LINES] = {
        "PUBLIC IN/OUT: 0/0",
        "PUB OUT: 0.00000000 ZCL",
        "SHIELDED SPEND/OUT: 1/1",
        "FEE UNKNOWN; SPROUT: 0",
        "SHIELDED HIDDEN; NO SIGNING",
        "ZIP243 PREFIX: d4967a8269007709"
    };
    check_consensus_screen(&sim.app, summary);
    assert(blue_shielded_review_app_next(&sim.app));
    static const char *const digest_page[ZCL_BLUE_REVIEW_LINES] = {
        "ZIP243 BRANCH 0x76B809BB",
        "d4967a8269007709",
        "fd063a592f7359b8",
        "64fa390c76f4609d",
        "c9f9b96069c27c8b",
        "CHAIN UNCHECKED; NO SIGNING"
    };
    check_consensus_screen(&sim.app, digest_page);
    blue_shielded_review_app_toggle_text(&sim.app);
    blue_shielded_review_app_toggle_dark(&sim.app);
    assert(sim.app.large_text && sim.app.dark);
    blue_shielded_review_app_reset(&sim.app);
    assert(!sim.app.transaction.complete);
    assert(strcmp(sim.app.lines[0], "CONNECT Z23") == 0);
}

static void output_ciphertexts_change_receipt(const char *path) {
    enum { OUTPUT_OFFSET = 412, NOTE_OFFSET = 96, MEMO_OFFSET = 52,
        NOTE_CIPHER_BYTES = 580 };
    static const size_t altered_bytes[] = {
        OUTPUT_OFFSET + NOTE_OFFSET + MEMO_OFFSET,
        OUTPUT_OFFSET + NOTE_OFFSET + NOTE_CIPHER_BYTES
    };
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    assert(read_vector(path, wire) == sizeof wire);
    simulator original;
    reset_simulator(&original);
    blue_shielded_review_receipt before;
    assert(blue_shielded_review_client_run_receipt(wire, sizeof wire,
        BRANCH, exchange, &original, &before));
    for (size_t i = 0; i < sizeof altered_bytes / sizeof altered_bytes[0];
         ++i) {
        simulator changed;
        blue_shielded_review_receipt after;
        reset_simulator(&changed);
        wire[altered_bytes[i]] ^= 1u;
        assert(blue_shielded_review_client_run_receipt(wire, sizeof wire,
            BRANCH, exchange, &changed, &after));
        assert(before.facts.sapling_spends == after.facts.sapling_spends &&
            before.facts.sapling_outputs == after.facts.sapling_outputs &&
            before.branch_id == after.branch_id);
        assert(memcmp(before.zip243_digest, after.zip243_digest, 32) != 0);
        assert(memcmp(before.wire_sha256, after.wire_sha256, 32) != 0);
        wire[altered_bytes[i]] ^= 1u;
    }
}

static void alternate_known_branch(const uint8_t *wire) {
    simulator sim;
    reset_simulator(&sim);
    blue_shielded_review_receipt receipt;
    assert(blue_shielded_review_client_run_receipt(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x930b540d,
        exchange, &sim, &receipt));
    assert(receipt.branch_id == 0x930b540d &&
        receipt.wire_length == BLUE_SYNTHETIC_SAPLING_BYTES);
    assert(sim.app.transaction.complete &&
        sim.app.transaction.branch_id == 0x930b540d);
    assert(blue_shielded_review_app_next(&sim.app));
    assert(strcmp(sim.app.lines[0],
        "ZIP243 BRANCH 0x930B540D") == 0);
    assert(strcmp(sim.app.lines[5],
        "CHAIN UNCHECKED; NO SIGNING") == 0);
    assert(memcmp(sim.app.lines[1],
        "d4967a8269007709", 16) != 0);
}

int main(int argc, char **argv) {
    assert(argc == 3);
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    successful_review(wire);
    rejected_commitment(wire);
    excluded_proof_changes_wire_commitment(wire);
    output_aliases(wire);
    changed_wire_during_review(wire);
    erase_callback_changes_outputs(wire);
    for (unsigned call = 1; call <= 50; ++call)
        failed_review(wire, call, false, false, false);
    for (unsigned call = 1; call <= 50; ++call)
        for (unsigned kind = CORRUPT_SHORT;
             kind <= CORRUPT_BODY; ++kind)
            corrupted_reply(wire, call, kind);
    failed_review(wire, 0, true, false, false);
    failed_review(wire, 0, false, true, false);
    failed_review(wire, 0, false, false, true);
    simulator sim;
    reset_simulator(&sim);
    zcl_tx_review review;
    uint8_t digest[32];
    memset(&review, 0xa5, sizeof review);
    memset(digest, 0xa5, sizeof digest);
    assert(!blue_shielded_review_client_run(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0,
        exchange, &sim, &review, digest));
    assert(sim.calls == 0);
    assert_zero(&review, digest);
    memset(&review, 0xa5, sizeof review);
    memset(digest, 0xa5, sizeof digest);
    wire[0] ^= 1u;
    assert(!blue_shielded_review_client_run(wire,
        BLUE_SYNTHETIC_SAPLING_BYTES, BRANCH,
        exchange, &sim, &review, digest));
    assert(sim.calls == 0);
    assert_zero(&review, digest);
    published_vector(argv[1]);
    consensus_spend_vector(argv[2]);
    output_ciphertexts_change_receipt(argv[2]);
    blue_sapling_fixture(wire);
    alternate_known_branch(wire);
    puts("Blue shielded client replay, disconnect and substitutions: passed");
    return 0;
}
