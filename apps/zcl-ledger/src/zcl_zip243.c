/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_zip243.h"
#include "zcl_tx_review.h"

#include <string.h>

typedef struct {
    const uint8_t *wire;
    size_t length;
    size_t offset;
} reader;

static const uint8_t prevouts_personal[] = "ZcashPrevoutHash";
static const uint8_t sequence_personal[] = "ZcashSequencHash";
static const uint8_t outputs_personal[] = "ZcashOutputsHash";
static const uint8_t joinsplits_personal[] = "ZcashJSplitsHash";
static const uint8_t spends_personal[] = "ZcashSSpendsHash";
static const uint8_t shielded_outputs_personal[] = "ZcashSOutputHash";
enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };

typedef struct {
    const uint8_t *outpoint;
    const uint8_t *sequence;
    const uint8_t *script_code;
    size_t script_code_length;
    uint64_t amount_zat;
} transparent_input;

static bool take(reader *input, size_t count, const uint8_t **bytes) {
    if (count > input->length - input->offset) return false;
    *bytes = input->wire + input->offset;
    input->offset += count;
    return true;
}

static bool compact_size(reader *input, uint64_t *value) {
    const uint8_t *bytes;
    if (!take(input, 1, &bytes)) return false;
    uint8_t prefix = bytes[0];
    if (prefix < 0xfd) { *value = prefix; return true; }
    size_t width = prefix == 0xfd ? 2 : prefix == 0xfe ? 4 : 8;
    if (!take(input, width, &bytes)) return false;
    uint64_t result = 0;
    for (size_t i = 0; i < width; ++i) result |= (uint64_t)bytes[i] << (8 * i);
    if ((width == 2 && result < 0xfd) ||
        (width == 4 && result <= UINT16_MAX) ||
        (width == 8 && result <= UINT32_MAX)) return false;
    *value = result;
    return true;
}

static bool read_input(reader *input, const uint8_t **outpoint,
                        const uint8_t **sequence) {
    const uint8_t *script;
    uint64_t script_length;
    return take(input, 36, outpoint) &&
           compact_size(input, &script_length) &&
           script_length <= input->length - input->offset &&
           take(input, (size_t)script_length, &script) &&
           take(input, 4, sequence);
}

static bool hash_input_pass(reader *input, const zcl_zip243_hasher *hasher,
                             const uint8_t personal[16], bool sequence_only,
                             uint8_t digest[32]) {
    uint64_t count;
    if (!compact_size(input, &count) || count > input->length / 41 ||
        !hasher->init(hasher->context, personal)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t *outpoint, *sequence;
        if (!read_input(input, &outpoint, &sequence) ||
            !hasher->update(hasher->context,
                            sequence_only ? sequence : outpoint,
                            sequence_only ? 4 : 36)) return false;
    }
    return hasher->final(hasher->context, digest);
}

static bool input_hashes(reader *input, const zcl_zip243_hasher *hasher,
                          uint8_t prevouts[32], uint8_t sequences[32]) {
    reader second = *input;
    if (!hash_input_pass(input, hasher, prevouts_personal,
                         false, prevouts) ||
        !hash_input_pass(&second, hasher, sequence_personal,
                         true, sequences)) return false;
    return input->offset == second.offset;
}

static bool output_hash(reader *input, const zcl_zip243_hasher *hasher,
                         uint8_t digest[32]) {
    uint64_t count;
    if (!compact_size(input, &count) || count > input->length / 9 ||
        !hasher->init(hasher->context, outputs_personal)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        size_t start = input->offset;
        const uint8_t *bytes;
        uint64_t script_length;
        if (!take(input, 8, &bytes) || !compact_size(input, &script_length) ||
            script_length > input->length - input->offset ||
            !take(input, (size_t)script_length, &bytes) ||
            !hasher->update(hasher->context, input->wire + start,
                            input->offset - start)) return false;
    }
    return hasher->final(hasher->context, digest);
}

static bool fixed_hash(reader *input, const zcl_zip243_hasher *hasher,
                        size_t item_size, size_t hash_size,
                        const uint8_t personal[16], uint8_t digest[32],
                        bool *present) {
    uint64_t count;
    if (!compact_size(input, &count) ||
        count > (input->length - input->offset) / item_size) return false;
    *present = count != 0;
    if (!*present) { memset(digest, 0, 32); return true; }
    if (!hasher->init(hasher->context, personal)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t *item;
        if (!take(input, item_size, &item) ||
            !hasher->update(hasher->context, item, hash_size)) return false;
    }
    return hasher->final(hasher->context, digest);
}

static bool joinsplit_hash(reader *input, const zcl_zip243_hasher *hasher,
                            uint8_t digest[32]) {
    uint64_t count;
    if (!compact_size(input, &count) ||
        count > (input->length - input->offset) / 1634) return false;
    if (!count) { memset(digest, 0, 32); return true; }
    if (!hasher->init(hasher->context, joinsplits_personal)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t *item;
        if (!take(input, 1634, &item) ||
            !hasher->update(hasher->context, item, 1634)) return false;
    }
    const uint8_t *pubkey, *signature;
    return take(input, 32, &pubkey) && take(input, 64, &signature) &&
           hasher->update(hasher->context, pubkey, 32) &&
           hasher->final(hasher->context, digest);
}

static bool collect_hashes(reader *input, const zcl_zip243_hasher *hasher,
                            uint8_t hashes[6][32], const uint8_t **tail) {
    const uint8_t *binding;
    bool spends, outputs;
    return input_hashes(input, hasher, hashes[0], hashes[1]) &&
           output_hash(input, hasher, hashes[2]) &&
           take(input, 16, tail) &&
           fixed_hash(input, hasher, 384, 320,
                      spends_personal, hashes[4], &spends) &&
           fixed_hash(input, hasher, 948, 948,
                      shielded_outputs_personal, hashes[5], &outputs) &&
           joinsplit_hash(input, hasher, hashes[3]) &&
           (!(spends || outputs) || take(input, 64, &binding)) &&
           input->offset == input->length;
}

static bool selected_input(const uint8_t *wire, size_t length,
                           uint32_t index, transparent_input *selected) {
    reader input = {.wire = wire, .length = length, .offset = 8};
    uint64_t count;
    if (!compact_size(&input, &count) || index >= count) return false;
    for (uint64_t i = 0; i <= index; ++i) {
        const uint8_t *outpoint, *sequence;
        if (!read_input(&input, &outpoint, &sequence)) return false;
        if (i == index) {
            selected->outpoint = outpoint;
            selected->sequence = sequence;
        }
    }
    return true;
}

static size_t script_length_prefix(size_t length, uint8_t bytes[9]) {
    if (length < 0xfd) { bytes[0] = (uint8_t)length; return 1; }
    if (length <= UINT16_MAX) {
        bytes[0] = 0xfd;
        bytes[1] = (uint8_t)length;
        bytes[2] = (uint8_t)(length >> 8);
        return 3;
    }
    bytes[0] = 0xfe;
    for (unsigned i = 0; i < 4; ++i)
        bytes[i + 1] = (uint8_t)(length >> (8 * i));
    return 5;
}

static bool append_transparent(const zcl_zip243_hasher *hasher,
                               const transparent_input *selected) {
    uint8_t prefix[9], value[8];
    size_t prefix_length = script_length_prefix(selected->script_code_length,
                                                 prefix);
    for (unsigned i = 0; i < 8; ++i)
        value[i] = (uint8_t)(selected->amount_zat >> (8 * i));
    return hasher->update(hasher->context, selected->outpoint, 36) &&
           hasher->update(hasher->context, prefix, prefix_length) &&
           (!selected->script_code_length ||
            hasher->update(hasher->context, selected->script_code,
                           selected->script_code_length)) &&
           hasher->update(hasher->context, value, sizeof value) &&
           hasher->update(hasher->context, selected->sequence, 4);
}

static bool final_hash(const uint8_t *wire, const uint8_t *tail,
                        const uint8_t hashes[6][32], uint32_t branch_id,
                        const zcl_zip243_hasher *hasher,
                        const transparent_input *selected,
                        uint8_t digest[32]) {
    uint8_t personal[16] = "ZcashSigHash";
    for (unsigned i = 0; i < 4; ++i)
        personal[12 + i] = (uint8_t)(branch_id >> (8 * i));
    if (!hasher->init(hasher->context, personal) ||
        !hasher->update(hasher->context, wire, 8)) return false;
    for (size_t i = 0; i < 6; ++i)
        if (!hasher->update(hasher->context, hashes[i], 32)) return false;
    static const uint8_t sighash_all[4] = {1, 0, 0, 0};
    return hasher->update(hasher->context, tail, 16) &&
           hasher->update(hasher->context, sighash_all, 4) &&
           (!selected || append_transparent(hasher, selected)) &&
           hasher->final(hasher->context, digest);
}

static bool valid_hasher(const zcl_zip243_hasher *hasher) {
    return hasher && hasher->context && hasher->init &&
           hasher->update && hasher->final;
}

int zcl_zip243_shielded_digest(const uint8_t *wire, size_t length,
                                uint32_t branch_id,
                                const zcl_zip243_hasher *hasher,
                                uint8_t digest[32]) {
    if (!wire || !valid_hasher(hasher) || !digest ||
        zcl_tx_review_parse(wire, length, &(zcl_tx_review){0}) < 0)
        return -1;
    reader input = {.wire = wire, .length = length, .offset = 8};
    uint8_t hashes[6][32];
    const uint8_t *tail;
    if (!collect_hashes(&input, hasher, hashes, &tail)) return -1;
    return final_hash(wire, tail, (const uint8_t (*)[32])hashes,
                      branch_id, hasher, NULL, digest) ? 0 : -1;
}

int zcl_zip243_transparent_digest(const uint8_t *wire, size_t length,
                                   uint32_t input_index,
                                   const uint8_t *script_code,
                                   size_t script_code_length,
                                   uint64_t amount_zat, uint32_t branch_id,
                                   const zcl_zip243_hasher *hasher,
                                   uint8_t digest[32]) {
    if (!wire || !valid_hasher(hasher) || !digest ||
        (script_code_length && !script_code) ||
        script_code_length > ZCL_TX_REVIEW_MAX_BYTES ||
        amount_zat > ZCL_MAX_MONEY_ZAT ||
        zcl_tx_review_parse(wire, length, &(zcl_tx_review){0}) < 0)
        return -1;
    transparent_input selected = {
        .script_code = script_code, .script_code_length = script_code_length,
        .amount_zat = amount_zat
    };
    if (!selected_input(wire, length, input_index, &selected)) return -1;
    reader input = {.wire = wire, .length = length, .offset = 8};
    uint8_t hashes[6][32];
    const uint8_t *tail;
    if (!collect_hashes(&input, hasher, hashes, &tail)) return -1;
    return final_hash(wire, tail, (const uint8_t (*)[32])hashes,
                      branch_id, hasher, &selected, digest) ? 0 : -1;
}
