/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_shielded_stream.h"
#include "zcl_tx_shielded_replay.h"
#include "zcl_tx_review.h"
#include "blue_sapling_fixture.h"
#include "zcl_zip243.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"

#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[8192]) {
    FILE *file = fopen(path, "r");
    assert(file);
    static char line[16384];
    while (fgets(line, sizeof line, file) && line[0] == '#') {}
    assert(!ferror(file) && line[0] != '#');
    size_t length = strcspn(line, "\r\n");
    assert(length > 0 && length % 2 == 0 && length < sizeof line);
    for (size_t i = 0; i < length / 2; ++i) {
        int high = nibble(line[2 * i]);
        int low = nibble(line[2 * i + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    assert(fclose(file) == 0);
    return length / 2;
}

typedef struct { size_t lengths[8]; bool reject; } seen_spans;

static bool span_seen(void *context, zcl_tx_shielded_span span,
    const uint8_t *bytes, size_t length) {
    seen_spans *seen = context;
    assert(span <= ZCL_SHIELDED_JOINSPLIT);
    assert(bytes && length == 1);
    if (seen->reject) return false;
    seen->lengths[span] += length;
    return true;
}

static void compare_facts(const zcl_tx_shielded_facts *stream,
    const zcl_tx_review *reference) {
    assert(stream->transparent_inputs == reference->transparent_inputs);
    assert(stream->transparent_outputs == reference->transparent_outputs);
    assert(stream->sapling_spends == reference->sapling_spends);
    assert(stream->sapling_outputs == reference->sapling_outputs);
    assert(stream->sprout_joinsplits == reference->sprout_joinsplits);
    assert(stream->transparent_output_zat ==
        reference->transparent_output_zat);
    assert(stream->value_balance_zat == reference->value_balance_zat);
    assert(stream->lock_time == reference->lock_time);
    assert(stream->expiry_height == reference->expiry_height);
}

static void check_chunks(const uint8_t *wire, size_t length,
    size_t chunk, const zcl_tx_review *reference) {
    zcl_tx_shielded_stream state;
    seen_spans seen = {0};
    assert(zcl_tx_shielded_stream_begin(&state, (uint32_t)length));
    for (size_t offset = 0; offset < length; offset += chunk) {
        size_t take = length - offset < chunk ? length - offset : chunk;
        assert(zcl_tx_shielded_stream_feed(&state, wire + offset,
            take, span_seen, &seen));
    }
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_stream_finish(&state, &facts));
    compare_facts(&facts, reference);
    assert(seen.lengths[ZCL_SHIELDED_HEADER] == 8);
    assert(seen.lengths[ZCL_SHIELDED_TAIL] == 16);
    assert(seen.lengths[ZCL_SHIELDED_SPEND] ==
        320u * reference->sapling_spends);
    assert(seen.lengths[ZCL_SHIELDED_SOUTPUT] ==
        948u * reference->sapling_outputs);
    assert(!zcl_tx_shielded_stream_finish(&state, &facts));
}

static void check_rejections(uint8_t *wire, size_t length) {
    zcl_tx_shielded_stream state;
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_stream_begin(&state, (uint32_t)length));
    assert(zcl_tx_shielded_stream_feed(&state, wire, length - 1,
        NULL, NULL));
    assert(!zcl_tx_shielded_stream_finish(&state, &facts));
    assert(state.failed);
    assert(!zcl_tx_shielded_stream_feed(&state, wire, 1, NULL, NULL));
    wire[0] ^= 1u;
    assert(zcl_tx_shielded_stream_begin(&state, (uint32_t)length));
    assert(!zcl_tx_shielded_stream_feed(&state, wire, length,
        NULL, NULL));
    wire[0] ^= 1u;
    seen_spans seen = {.reject = true};
    assert(zcl_tx_shielded_stream_begin(&state, (uint32_t)length));
    assert(!zcl_tx_shielded_stream_feed(&state, wire, 1,
        span_seen, &seen));
    assert(state.failed);
}

typedef struct {
    struct blake2b_ctx sections[6];
    uint8_t header[8], tail[16];
    size_t header_used, tail_used;
} section_hashes;

static int section_index(zcl_tx_shielded_span span) {
    switch (span) {
    case ZCL_SHIELDED_PREVOUT: return 0;
    case ZCL_SHIELDED_SEQUENCE: return 1;
    case ZCL_SHIELDED_OUTPUT: return 2;
    case ZCL_SHIELDED_JOINSPLIT: return 3;
    case ZCL_SHIELDED_SPEND: return 4;
    case ZCL_SHIELDED_SOUTPUT: return 5;
    default: return -1;
    }
}

static bool hash_span(void *context, zcl_tx_shielded_span span,
    const uint8_t *bytes, size_t length) {
    section_hashes *hashes = context;
    if (span == ZCL_SHIELDED_HEADER) {
        if (length > sizeof hashes->header - hashes->header_used)
            return false;
        memcpy(hashes->header + hashes->header_used, bytes, length);
        hashes->header_used += length;
        return true;
    }
    if (span == ZCL_SHIELDED_TAIL) {
        if (length > sizeof hashes->tail - hashes->tail_used)
            return false;
        memcpy(hashes->tail + hashes->tail_used, bytes, length);
        hashes->tail_used += length;
        return true;
    }
    int index = section_index(span);
    return index >= 0 && blake2b_update(&hashes->sections[index],
        bytes, length) == 0;
}

static void init_sections(section_hashes *hashes) {
    static const uint8_t personal[6][17] = {
        "ZcashPrevoutHash", "ZcashSequencHash", "ZcashOutputsHash",
        "ZcashJSplitsHash", "ZcashSSpendsHash", "ZcashSOutputHash"
    };
    memset(hashes, 0, sizeof *hashes);
    for (unsigned i = 0; i < 6; ++i)
        assert(blake2b_init_salt_personal(&hashes->sections[i], 32,
            NULL, 0, NULL, personal[i]) == 0);
}

static void finish_sections(section_hashes *sections,
    const zcl_tx_shielded_facts *facts, uint32_t branch,
    uint8_t digest[32]) {
    uint8_t parts[6][32];
    for (unsigned i = 0; i < 6; ++i)
        assert(blake2b_final(&sections->sections[i], parts[i], 32) == 0);
    if (!facts->sprout_joinsplits) memset(parts[3], 0, 32);
    if (!facts->sapling_spends) memset(parts[4], 0, 32);
    if (!facts->sapling_outputs) memset(parts[5], 0, 32);
    uint8_t personal[16] = "ZcashSigHash";
    for (unsigned i = 0; i < 4; ++i)
        personal[12 + i] = (uint8_t)(branch >> (8 * i));
    struct blake2b_ctx final;
    assert(blake2b_init_salt_personal(&final, 32, NULL, 0,
        NULL, personal) == 0);
    assert(blake2b_update(&final, sections->header, 8) == 0);
    for (unsigned i = 0; i < 6; ++i)
        assert(blake2b_update(&final, parts[i], 32) == 0);
    assert(blake2b_update(&final, sections->tail, 16) == 0);
    assert(blake2b_update(&final,
        (const uint8_t[]){1, 0, 0, 0}, 4) == 0);
    assert(blake2b_final(&final, digest, 32) == 0);
}

static void check_digest_sections(const uint8_t *wire, size_t length) {
    section_hashes sections;
    init_sections(&sections);
    zcl_tx_shielded_stream state;
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_stream_begin(&state, (uint32_t)length));
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t take = length - offset < 220 ? length - offset : 220;
        assert(zcl_tx_shielded_stream_feed(&state, wire + offset,
            take, hash_span, &sections));
    }
    assert(zcl_tx_shielded_stream_finish(&state, &facts));
    assert(sections.header_used == 8 && sections.tail_used == 16);
    uint8_t streamed[32], full[32];
    finish_sections(&sections, &facts, 0x76b809bb, streamed);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
        &hasher, full) == 0);
    assert(memcmp(streamed, full, 32) == 0);
}

static uint32_t random_word(uint32_t *state) {
    *state = *state * 1664525u + 1013904223u;
    return *state;
}

static bool stream_accepts(const uint8_t *wire, size_t length,
    size_t chunk) {
    zcl_tx_shielded_stream state;
    zcl_tx_shielded_facts facts;
    if (!zcl_tx_shielded_stream_begin(&state, (uint32_t)length))
        return false;
    for (size_t offset = 0; offset < length; offset += chunk) {
        size_t take = length - offset < chunk ? length - offset : chunk;
        if (!zcl_tx_shielded_stream_feed(&state, wire + offset,
            take, NULL, NULL)) return false;
    }
    return zcl_tx_shielded_stream_finish(&state, &facts);
}

static void differential_mutations(uint8_t *wire, size_t length) {
    uint32_t seed = 0x7f4a7c15u;
    zcl_tx_review review;
    for (unsigned trial = 0; trial < 4096; ++trial) {
        size_t offset = random_word(&seed) % length;
        uint8_t change = (uint8_t)(1u << (random_word(&seed) % 8));
        wire[offset] ^= change;
        size_t candidate_length = trial % 11 == 0
            ? random_word(&seed) % length : length;
        bool reference = zcl_tx_review_parse(wire, candidate_length,
            &review) == 0;
        bool streamed = stream_accepts(wire, candidate_length,
            trial % 255 + 1u);
        assert(reference == streamed);
        wire[offset] ^= change;
    }
}

static void joinsplit_fixture(uint8_t wire[1759]) {
    memset(wire, 0, 1759);
    memcpy(wire, (const uint8_t[]){4, 0, 0, 0x80,
        0x85, 0x20, 0x2f, 0x89}, 8);
    wire[28] = 1;
    for (unsigned i = 29; i < 1759; ++i)
        wire[i] = (uint8_t)(i * 13u + 7u);
}

static void check_valid_wire(uint8_t *wire, size_t length,
    size_t chunk) {
    zcl_tx_review reference;
    assert(zcl_tx_review_parse(wire, length, &reference) == 0);
    check_chunks(wire, length, chunk, &reference);
    check_digest_sections(wire, length);
    differential_mutations(wire, length);
}

static void replay_pass(zcl_tx_shielded_replay *state,
    const uint8_t *wire, size_t length, size_t chunk) {
    for (size_t offset = 0; offset < length; offset += chunk) {
        size_t take = length - offset < chunk ? length - offset : chunk;
        assert(zcl_tx_shielded_replay_feed(state, wire + offset, take));
    }
}

static void check_replay(const uint8_t *wire, size_t length,
    size_t chunk, uint32_t branch) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    assert(zcl_tx_shielded_replay_begin(&state, (uint32_t)length,
        branch, &hasher));
    for (unsigned pass = 0; pass < 5; ++pass) {
        replay_pass(&state, wire, length, chunk);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, length, chunk);
    zcl_tx_shielded_facts facts;
    uint8_t actual[32], expected[32];
    assert(zcl_tx_shielded_replay_finish(&state, &facts, actual));
    assert(zcl_zip243_shielded_digest(wire, length, branch,
        &hasher, expected) == 0);
    assert(memcmp(actual, expected, sizeof actual) == 0);
    zcl_tx_review review;
    assert(zcl_tx_review_parse(wire, length, &review) == 0);
    compare_facts(&facts, &review);
    assert(!zcl_tx_shielded_replay_finish(&state, &facts, actual));
}

static void replay_rejects_substitution(uint8_t *wire, size_t length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    for (unsigned changed_pass = 2; changed_pass <= 6;
         ++changed_pass) {
        zcl_tx_shielded_replay state;
        assert(zcl_tx_shielded_replay_begin(&state,
            (uint32_t)length, 0x76b809bb, &hasher));
        for (unsigned pass = 1; pass < changed_pass; ++pass) {
            replay_pass(&state, wire, length, 220);
            assert(zcl_tx_shielded_replay_next(&state));
        }
        wire[length / 2] ^= 1u;
        zcl_tx_review review;
        assert(zcl_tx_review_parse(wire, length, &review) == 0);
        replay_pass(&state, wire, length, 17);
        zcl_tx_shielded_facts facts;
        uint8_t digest[32];
        memset(digest, 0xa5, sizeof digest);
        if (changed_pass < 6)
            assert(!zcl_tx_shielded_replay_next(&state));
        else assert(!zcl_tx_shielded_replay_finish(&state,
            &facts, digest));
        assert(state.failed);
        assert(!zcl_tx_shielded_replay_finish(&state,
            &facts, digest));
        for (unsigned i = 0; i < sizeof digest; ++i)
            assert(digest[i] == 0xa5);
        wire[length / 2] ^= 1u;
    }
}

static void replay_rejects_short_pass(const uint8_t *wire,
    size_t length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    assert(zcl_tx_shielded_replay_begin(&state, (uint32_t)length,
        0x76b809bb, &hasher));
    assert(zcl_tx_shielded_replay_feed(&state, wire, length - 1));
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(state.failed);
}

static void check_replay_rk_capture(size_t chunk) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    uint8_t rk[32], digest[32], expected[32];
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 0, rk));
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(&state, wire, sizeof wire, chunk);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, sizeof wire, chunk);
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_replay_finish(&state, &facts, digest));
    assert(facts.sapling_spends == 1);
    assert(memcmp(rk, wire + 27 + 96, sizeof rk) == 0);
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, expected) == 0);
    assert(memcmp(digest, expected, sizeof digest) == 0);
}

static void check_replay_rk_rejections(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    uint8_t rk[32];
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 1, rk));
    replay_pass(&state, wire, sizeof wire, 220);
    assert(!zcl_tx_shielded_replay_next(&state));
    const uint8_t zero[sizeof rk] = {0};
    assert(memcmp(rk, zero, sizeof rk) == 0);
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 0, rk));
    replay_pass(&state, wire, sizeof wire, 220);
    assert(zcl_tx_shielded_replay_next(&state));
    wire[500] ^= 1u;
    replay_pass(&state, wire, sizeof wire, 17);
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(memcmp(rk, zero, sizeof rk) == 0);
    wire[500] ^= 1u;
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 0, rk));
    assert(zcl_tx_shielded_replay_feed(&state, wire, sizeof wire - 1));
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(memcmp(rk, zero, sizeof rk) == 0);
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 0, rk));
    assert(zcl_tx_shielded_replay_feed(&state, wire, 220));
    assert(memcmp(rk, zero, sizeof rk) != 0);
    zcl_tx_shielded_replay_abort(&state);
    assert(memcmp(rk, zero, sizeof rk) == 0);
    const uint8_t zero_state[sizeof state] = {0};
    assert(memcmp(&state, zero_state, sizeof state) == 0);
}

static void check_replay_rk_second_spend(void) {
    uint8_t original[BLUE_SYNTHETIC_SAPLING_BYTES];
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES + 384];
    blue_sapling_fixture(original);
    memcpy(wire, original, 411);
    wire[26] = 2;
    for (unsigned i = 0; i < 384; ++i)
        wire[411 + i] = (uint8_t)(i * 7u + 9u);
    memcpy(wire + 795, original + 411, sizeof original - 411);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    uint8_t rk[32], digest[32], expected[32];
    assert(zcl_tx_shielded_replay_begin_rk(&state, sizeof wire,
        0x76b809bb, &hasher, 1, rk));
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(&state, wire, sizeof wire, 63);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, sizeof wire, 63);
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_replay_finish(&state, &facts, digest));
    assert(facts.sapling_spends == 2);
    assert(memcmp(rk, wire + 411 + 96, sizeof rk) == 0);
    assert(memcmp(rk, wire + 27 + 96, sizeof rk) != 0);
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, expected) == 0);
    assert(memcmp(digest, expected, sizeof digest) == 0);
}

static void check_output_capture(size_t chunk) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 0, &output));
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(&state, wire, sizeof wire, chunk);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, sizeof wire, chunk);
    zcl_tx_shielded_facts facts;
    uint8_t digest[32], reference[32];
    assert(zcl_tx_shielded_replay_finish(&state, &facts, digest));
    assert(facts.sapling_outputs == 1);
    assert(memcmp(output.cv, wire + 412, 32) == 0);
    assert(memcmp(output.cm, wire + 444, 32) == 0);
    assert(memcmp(output.epk, wire + 476, 32) == 0);
    assert(memcmp(output.enc_ciphertext, wire + 412 + 96, 580) == 0);
    assert(memcmp(output.out_ciphertext, wire + 412 + 676, 80) == 0);
    assert(zcl_zip243_shielded_digest(wire, sizeof wire,
        0x76b809bb, &hasher, reference) == 0);
    assert(memcmp(digest, reference, sizeof digest) == 0);
    zcl_tx_shielded_replay_abort(&state);
    assert(memcmp(output.cv, wire + 412, 32) == 0);
}

static void check_output_capture_rejections(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output, zero = {0};
    assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 1, &output));
    replay_pass(&state, wire, sizeof wire, 220);
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(memcmp(&output, &zero, sizeof output) == 0);
    for (unsigned changed_pass = 2; changed_pass <= 6; ++changed_pass) {
        assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
            0x76b809bb, &hasher, 0, &output));
        for (unsigned pass = 1; pass < changed_pass; ++pass) {
            replay_pass(&state, wire, sizeof wire, 220);
            assert(zcl_tx_shielded_replay_next(&state));
        }
        assert(memcmp(&output, &zero, sizeof output) != 0);
        wire[412 + 96 + 7] ^= 1u;
        replay_pass(&state, wire, sizeof wire, 17);
        if (changed_pass < 6)
            assert(!zcl_tx_shielded_replay_next(&state));
        else {
            zcl_tx_shielded_facts facts;
            uint8_t digest[32];
            assert(!zcl_tx_shielded_replay_finish(&state,
                &facts, digest));
        }
        assert(memcmp(&output, &zero, sizeof output) == 0);
        wire[412 + 96 + 7] ^= 1u;
    }
    assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 0, &output));
    replay_pass(&state, wire, sizeof wire, 220);
    assert(zcl_tx_shielded_replay_next(&state));
    wire[412 + 676 + 7] ^= 1u;
    replay_pass(&state, wire, sizeof wire, 17);
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(memcmp(&output, &zero, sizeof output) == 0);
    wire[412 + 676 + 7] ^= 1u;
    assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 0, &output));
    assert(zcl_tx_shielded_replay_feed(&state, wire, 1100));
    assert(memcmp(&output, &zero, sizeof output) != 0);
    zcl_tx_shielded_replay_abort(&state);
    assert(memcmp(&output, &zero, sizeof output) == 0);
    assert(!zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 4096, &output));
    assert(memcmp(&output, &zero, sizeof output) == 0);
}

static void check_second_output_capture(void) {
    uint8_t original[BLUE_SYNTHETIC_SAPLING_BYTES];
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES + 948];
    blue_sapling_fixture(original);
    memcpy(wire, original, 412 + 948);
    wire[411] = 2;
    for (unsigned i = 0; i < 948; ++i)
        wire[1360 + i] = (uint8_t)(i * 13u + 5u);
    memcpy(wire + 2308, original + 1360,
        sizeof original - 1360);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    assert(zcl_tx_shielded_replay_begin_output(&state, sizeof wire,
        0x76b809bb, &hasher, 1, &output));
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(&state, wire, sizeof wire, 63);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, sizeof wire, 63);
    zcl_tx_shielded_facts facts;
    uint8_t digest[32];
    assert(zcl_tx_shielded_replay_finish(&state, &facts, digest));
    assert(facts.sapling_outputs == 2);
    assert(memcmp(output.cv, wire + 1360, 32) == 0);
    assert(memcmp(output.cm, wire + 1392, 32) == 0);
    assert(memcmp(output.epk, wire + 1424, 32) == 0);
    assert(memcmp(output.enc_ciphertext, wire + 1360 + 96, 580) == 0);
    assert(memcmp(output.out_ciphertext, wire + 1360 + 676, 80) == 0);
    assert(memcmp(output.cv, wire + 412, 32) != 0);
}

static void reject_substituted_spend_rk(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    const uint8_t zero[32] = {0};
    for (unsigned changed_pass = 2; changed_pass <= 6; ++changed_pass) {
        zcl_tx_shielded_replay state;
        uint8_t rk[32], digest[32];
        assert(zcl_tx_shielded_replay_begin_rk(&state,
            sizeof wire, 0x76b809bb, &hasher, 0, rk));
        for (unsigned pass = 1; pass < changed_pass; ++pass) {
            replay_pass(&state, wire, sizeof wire, 220);
            assert(zcl_tx_shielded_replay_next(&state));
        }
        wire[27 + 96 + 7] ^= 1u;
        replay_pass(&state, wire, sizeof wire, 17);
        zcl_tx_shielded_facts facts;
        if (changed_pass < 6)
            assert(!zcl_tx_shielded_replay_next(&state));
        else assert(!zcl_tx_shielded_replay_finish(&state,
            &facts, digest));
        assert(state.failed && memcmp(rk, zero, sizeof rk) == 0);
        wire[27 + 96 + 7] ^= 1u;
    }
}

static void reject_substituted_combined_capture(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    uint8_t rk[32];
    memset(rk, 0xa5, sizeof rk);
    memset(&output, 0xa5, sizeof output);
    assert(!zcl_tx_shielded_replay_begin_captures(&state,
        sizeof wire, 0x76b809bb, &hasher, 0, rk, 4096, &output));
    const uint8_t zero_rk[32] = {0};
    const zcl_tx_shielded_output_capture zero_output = {0};
    assert(memcmp(rk, zero_rk, sizeof rk) == 0);
    assert(memcmp(&output, &zero_output, sizeof output) == 0);
    assert(zcl_tx_shielded_replay_begin_captures(&state,
        sizeof wire, 0x76b809bb, &hasher, 0, rk, 0, &output));
    replay_pass(&state, wire, sizeof wire, 220);
    assert(zcl_tx_shielded_replay_next(&state));
    assert(memcmp(rk, zero_rk, sizeof rk) != 0);
    assert(memcmp(&output, &zero_output, sizeof output) != 0);
    wire[27 + 96 + 7] ^= 1u;
    replay_pass(&state, wire, sizeof wire, 17);
    assert(!zcl_tx_shielded_replay_next(&state));
    assert(state.failed);
    assert(memcmp(rk, zero_rk, sizeof rk) == 0);
    assert(memcmp(&output, &zero_output, sizeof output) == 0);
}

static void reject_overlapping_captures(void) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    union {
        zcl_tx_shielded_replay state;
        zcl_tx_shielded_output_capture output;
        uint8_t bytes[sizeof(zcl_tx_shielded_output_capture)];
    } shared;
    uint8_t original[sizeof shared];
    memset(&shared, 0xa5, sizeof shared);
    memcpy(original, shared.bytes, sizeof original);
    assert(!zcl_tx_shielded_replay_begin_output(&shared.state,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x76b809bb, &hasher,
        0, &shared.output));
    assert(memcmp(shared.bytes, original, sizeof original) == 0);
    assert(!zcl_tx_shielded_replay_begin_rk(&shared.state,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x76b809bb, &hasher,
        0, shared.state.commitment));
    assert(memcmp(shared.bytes, original, sizeof original) == 0);
    assert(!zcl_tx_shielded_replay_begin(&shared.state,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x76b809bb,
        &shared.state.blake));
    assert(memcmp(shared.bytes, original, sizeof original) == 0);
    hasher.context = &shared.state;
    assert(!zcl_tx_shielded_replay_begin(&shared.state,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x76b809bb, &hasher));
    assert(memcmp(shared.bytes, original, sizeof original) == 0);
    hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    memset(&state, 0xa5, sizeof state);
    memset(&output, 0xa5, sizeof output);
    uint8_t *rk = output.cv + 1;
    assert(!zcl_tx_shielded_replay_begin_captures(&state,
        BLUE_SYNTHETIC_SAPLING_BYTES, 0x76b809bb, &hasher,
        0, rk, 0, &output));
    for (size_t i = 0; i < sizeof state; ++i)
        assert(((const uint8_t *)&state)[i] == 0xa5);
    for (size_t i = 0; i < sizeof output; ++i)
        assert(((const uint8_t *)&output)[i] == 0xa5);
}

static void reject_overlapping_feed(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    uint8_t rk[32];
    const uint8_t zero_rk[32] = {0};
    const zcl_tx_shielded_output_capture zero_output = {0};
    for (unsigned trial = 0; trial < 4; ++trial) {
        assert(zcl_tx_shielded_replay_begin_captures(&state,
            sizeof wire, 0x76b809bb, &hasher, 0, rk, 0, &output));
        assert(zcl_tx_shielded_replay_feed(&state, wire, 1));
        rk[0] = output.cv[0] = 0xa5;
        uint8_t *alias = trial == 0 ? state.commitment :
            trial == 1 ? rk :
            trial == 2 ? output.cv : output.cv + 31;
        alias[0] = wire[1];
        if (trial == 3) alias[1] = wire[2];
        assert(!zcl_tx_shielded_replay_feed(&state, alias,
            trial == 3 ? 2 : 1));
        assert(state.failed);
        assert(memcmp(rk, zero_rk, sizeof rk) == 0);
        assert(memcmp(&output, &zero_output, sizeof output) == 0);
    }
    assert(zcl_tx_shielded_replay_begin(&state, sizeof wire,
        0x76b809bb, &hasher));
    assert(zcl_tx_shielded_replay_feed(&state, wire, sizeof wire));
    zcl_tx_shielded_replay_abort(&state);
}

static void replay_six_passes(zcl_tx_shielded_replay *state,
    const uint8_t *wire, size_t length) {
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(state, wire, length, 220);
        assert(zcl_tx_shielded_replay_next(state));
    }
    replay_pass(state, wire, length, 220);
}

static void reject_overlapping_finish(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    zcl_tx_shielded_output_capture output;
    uint8_t rk[32];
    assert(zcl_tx_shielded_replay_begin_captures(&state, sizeof wire,
        0x76b809bb, &hasher, 0, rk, 0, &output));
    replay_six_passes(&state, wire, sizeof wire);
    zcl_tx_shielded_facts facts;
    assert(!zcl_tx_shielded_replay_finish(&state, &facts,
        state.commitment));
    assert(state.failed);
    const uint8_t zero_rk[32] = {0};
    const zcl_tx_shielded_output_capture zero_output = {0};
    assert(memcmp(rk, zero_rk, sizeof rk) == 0);
    assert(memcmp(&output, &zero_output, sizeof output) == 0);
    assert(zcl_tx_shielded_replay_begin(&state, sizeof wire,
        0x76b809bb, &hasher));
    replay_six_passes(&state, wire, sizeof wire);
    union {
        zcl_tx_shielded_facts facts;
        uint8_t digest[32];
    } shared;
    memset(&shared, 0xa5, sizeof shared);
    assert(!zcl_tx_shielded_replay_finish(&state,
        &shared.facts, shared.digest));
    assert(state.failed);
    for (size_t i = 0; i < sizeof shared; ++i)
        assert(((const uint8_t *)&shared)[i] == 0xa5);
}

static void assert_finished_replay_erased(
    const zcl_tx_shielded_replay *state) {
    assert(state->pass == 7);
    const uint8_t *bytes = (const uint8_t *)state;
    for (size_t i = 0; i < sizeof *state; ++i)
        if (i != offsetof(zcl_tx_shielded_replay, pass))
            assert(bytes[i] == 0);
}

static void check_consensus_spend(const char *path) {
    static const uint8_t expected[32] = {
        0xd4, 0x96, 0x7a, 0x82, 0x69, 0x00, 0x77, 0x09,
        0xfd, 0x06, 0x3a, 0x59, 0x2f, 0x73, 0x59, 0xb8,
        0x64, 0xfa, 0x39, 0x0c, 0x76, 0xf4, 0x60, 0x9d,
        0xc9, 0xf9, 0xb9, 0x60, 0x69, 0xc2, 0x7c, 0x8b
    };
    uint8_t wire[8192], rk[32], digest[32];
    zcl_tx_shielded_output_capture output;
    size_t length = read_vector(path, wire);
    assert(length == BLUE_SYNTHETIC_SAPLING_BYTES);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay state;
    assert(zcl_tx_shielded_replay_begin_captures(&state,
        (uint32_t)length, 0x76b809bb, &hasher, 0, rk, 0, &output));
    for (unsigned pass = 1; pass < 6; ++pass) {
        replay_pass(&state, wire, length, 220);
        assert(zcl_tx_shielded_replay_next(&state));
    }
    replay_pass(&state, wire, length, 220);
    zcl_tx_shielded_facts facts;
    assert(zcl_tx_shielded_replay_finish(&state, &facts, digest));
    assert_finished_replay_erased(&state);
    assert(facts.sapling_spends == 1 && facts.sapling_outputs == 1);
    assert(memcmp(rk, wire + 27 + 96, sizeof rk) == 0);
    assert(memcmp(digest, expected, sizeof expected) == 0);
    assert(memcmp(output.cv, wire + 412, 32) == 0);
    assert(memcmp(output.cm, wire + 444, 32) == 0);
    assert(memcmp(output.epk, wire + 476, 32) == 0);
    assert(memcmp(output.enc_ciphertext, wire + 412 + 96, 580) == 0);
    assert(memcmp(output.out_ciphertext, wire + 412 + 676, 80) == 0);
    assert(memcmp(digest, expected, sizeof expected) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 4);
    uint8_t wire[8192];
    size_t length = read_vector(argv[1], wire);
    assert(length == 4118);
    zcl_tx_review reference;
    assert(zcl_tx_review_parse(wire, length, &reference) == 0);
    for (size_t chunk = 1; chunk <= 256; ++chunk)
        check_chunks(wire, length, chunk, &reference);
    check_digest_sections(wire, length);
    check_rejections(wire, length);
    differential_mutations(wire, length);
    check_replay(wire, length, 220, 0x76b809bb);
    check_replay(wire, length, 17, 0x930b540d);
    replay_rejects_substitution(wire, length);
    replay_rejects_short_pass(wire, length);
    check_replay_rk_capture(1);
    check_replay_rk_capture(220);
    check_replay_rk_rejections();
    check_replay_rk_second_spend();
    check_output_capture(1);
    check_output_capture(220);
    check_output_capture_rejections();
    check_second_output_capture();
    reject_substituted_spend_rk();
    reject_substituted_combined_capture();
    reject_overlapping_captures();
    reject_overlapping_feed();
    reject_overlapping_finish();
    length = read_vector(argv[2], wire);
    assert(length == 245);
    check_valid_wire(wire, length, 17);
    check_replay(wire, length, 17, 0x76b809bb);
    uint8_t synthetic[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(synthetic);
    check_valid_wire(synthetic, sizeof synthetic, 220);
    check_replay(synthetic, sizeof synthetic, 220, 0x76b809bb);
    uint8_t join[1759];
    joinsplit_fixture(join);
    check_valid_wire(join, sizeof join, 63);
    check_replay(join, sizeof join, 63, 0x76b809bb);
    check_consensus_spend(argv[3]);
    return 0;
}
