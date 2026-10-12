/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_cm.h"
#include "blue_fr_ct.h"
#include "blue_fs_ct.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_jubjub_encode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_mod256.h"
#include "blue_sapling_group_hash.h"

#include <string.h>

enum { NOTE_BITS = 582, CHUNKS_PER_SEGMENT = 63 };
static_assert(sizeof(blue_sapling_cm_workspace) <= 1024,
    "Sapling commitment workspace exceeds the 1 KiB limit");

static bool overlaps(const void *a, size_t a_len,
    const void *b, size_t b_len) {
    uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;
    return left <= right ? right - left < a_len :
        left - right < b_len;
}

static unsigned note_bit(const uint8_t contents[72], unsigned position) {
    if (position < 6) return 1;
    position -= 6;
    return (contents[position / 8] >> (position % 8)) & 1u;
}

static void select_field(struct fr *destination, const struct fr *source,
    uint64_t mask) {
    volatile uint64_t selected = mask;
    for (unsigned i = 0; i < 4; ++i) {
        uint64_t bits = selected;
        destination->d[i] = (destination->d[i] & ~bits) |
            (source->d[i] & bits);
    }
}

static void select_point(struct jub_point *destination,
    const struct jub_point *source, uint64_t mask) {
    select_field(&destination->x, &source->x, mask);
    select_field(&destination->y, &source->y, mask);
    select_field(&destination->z, &source->z, mask);
    select_field(&destination->t, &source->t, mask);
}

static void add_window(blue_sapling_cm_workspace *workspace,
    unsigned magnitude, bool negative) {
    struct jub_point candidate;
    workspace->term = workspace->base;
    blue_jub_double(&candidate, &workspace->base);
    select_point(&workspace->term, &candidate,
        (uint64_t)0 - (uint64_t)(magnitude == 2));
    blue_jub_add(&candidate, &candidate, &workspace->base);
    select_point(&workspace->term, &candidate,
        (uint64_t)0 - (uint64_t)(magnitude == 3));
    blue_jub_add(&candidate, &candidate, &workspace->base);
    select_point(&workspace->term, &candidate,
        (uint64_t)0 - (uint64_t)(magnitude == 4));
    candidate = workspace->term;
    blue_fr_neg_ct(&candidate.x, &candidate.x);
    blue_fr_neg_ct(&candidate.t, &candidate.t);
    select_point(&workspace->term, &candidate,
        (uint64_t)0 - (uint64_t)negative);
    blue_jub_add(&workspace->sum, &workspace->sum, &workspace->term);
    blue_mod256_wipe(&candidate, sizeof candidate);
}

static bool pedersen_note(blue_sapling_cm_workspace *workspace) {
    static const uint8_t personal[8] =
        {'Z','c','a','s','h','_','P','H'};
    blue_jub_identity(&workspace->sum);
    unsigned bit = 0;
    for (unsigned segment = 0; bit < NOTE_BITS; ++segment) {
        uint8_t tag[4] = {(uint8_t)segment, 0, 0, 0};
        if (!blue_sapling_find_group_hash(&workspace->base,
                &workspace->decode, personal, tag, sizeof tag)) return false;
        for (unsigned chunk = 0;
            chunk < CHUNKS_PER_SEGMENT && bit < NOTE_BITS; ++chunk) {
            unsigned a = note_bit(workspace->scratch.contents, bit++);
            unsigned b = bit < NOTE_BITS ?
                note_bit(workspace->scratch.contents, bit++) : 0;
            bool negative = bit < NOTE_BITS &&
                note_bit(workspace->scratch.contents, bit++);
            add_window(workspace, 1 + a + 2 * b, negative);
            if (chunk + 1 < CHUNKS_PER_SEGMENT && bit < NOTE_BITS)
                for (unsigned i = 0; i < 4; ++i)
                    blue_jub_double(&workspace->base, &workspace->base);
        }
    }
    return true;
}

static bool add_randomness(blue_sapling_cm_workspace *workspace,
    const uint8_t rcm[32]) {
    static const uint8_t personal[8] =
        {'Z','c','a','s','h','_','P','H'};
    static const uint8_t tag = 'r';
    if (!blue_sapling_find_group_hash(&workspace->base,
            &workspace->decode, personal, &tag, 1) ||
        !blue_jubjub_scalar_mul_lowmem(&workspace->term,
            &workspace->base, rcm)) return false;
    blue_jub_add(&workspace->sum, &workspace->sum, &workspace->term);
    return true;
}

static bool compute_cm(const uint8_t note[564], const uint8_t pk_d[32],
    blue_sapling_cm_workspace *workspace) {
    static const uint8_t personal[8] =
        {'Z','c','a','s','h','_','g','d'};
    struct fs scalar;
    bool valid = note[0] == 1 &&
        blue_fs_from_bytes_canonical(&scalar, note + 20) &&
        blue_sapling_group_hash(&workspace->base, &workspace->decode,
            personal, note + 1, 11);
    blue_mod256_wipe(&scalar, sizeof scalar);
    if (!valid) return false;
    memcpy(workspace->scratch.contents, note + 12, 8);
    if (!blue_jubjub_encode(workspace->scratch.contents + 8,
            &workspace->base)) return false;
    memcpy(workspace->scratch.contents + 40, pk_d, 32);
    if (!pedersen_note(workspace) ||
        !add_randomness(workspace, note + 20)) return false;
    valid = blue_fr_inverse_fixed(&workspace->scratch.field.inverse,
        &workspace->sum.z);
    if (valid) {
        blue_fr_mul_ct(&workspace->scratch.field.x, &workspace->sum.x,
            &workspace->scratch.field.inverse);
        blue_fr_to_bytes(workspace->scratch.contents,
            &workspace->scratch.field.x);
    }
    return valid;
}

bool blue_sapling_cm_matches(const uint8_t note[564],
    const uint8_t pk_d[32], const uint8_t expected_cm[32],
    blue_sapling_cm_workspace *workspace) {
    if (!workspace) return false;
    if ((note && overlaps(workspace, sizeof *workspace, note, 564)) ||
        (pk_d && overlaps(workspace, sizeof *workspace, pk_d, 32)) ||
        (expected_cm && overlaps(workspace, sizeof *workspace,
            expected_cm, 32))) return false;
    memset(workspace, 0, sizeof *workspace);
    bool valid = note && pk_d && expected_cm &&
        compute_cm(note, pk_d, workspace);
    if (valid) {
        uint8_t difference = 0;
        for (unsigned i = 0; i < 32; ++i)
            difference |= workspace->scratch.contents[i] ^ expected_cm[i];
        valid = difference == 0;
    }
    blue_mod256_wipe(workspace, sizeof *workspace);
    return valid;
}
