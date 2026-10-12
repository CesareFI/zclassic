/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_kdf.h"

#include "blue_storage.h"

static void clear_key(uint8_t key[32]) {
    volatile uint8_t *bytes = key;
    for (unsigned i = 0; i < 32; ++i) bytes[i] = 0;
}

static bool storage_disjoint(const uint8_t key[32],
    const uint8_t dh[32], const uint8_t epk[32],
    const zcl_zip243_hasher *hasher) {
    if (blue_storage_overlaps(key, 32, dh, 32) ||
        blue_storage_overlaps(key, 32, epk, 32) ||
        blue_storage_overlaps(key, 32, hasher,
            hasher ? sizeof *hasher : 0)) return false;
    return !hasher ||
        !blue_storage_overlaps(key, 32, hasher->context, 1);
}

bool blue_sapling_kdf(uint8_t key[32], const uint8_t dh[32],
    const uint8_t epk[32], const zcl_zip243_hasher *hasher) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','S','a','p','l','i','n','g','K','D','F'
    };
    if (!key) return false;
    if (!storage_disjoint(key, dh, epk, hasher)) return false;
    if (!dh || !epk || !hasher || !hasher->context || !hasher->init ||
        !hasher->update || !hasher->final) {
        clear_key(key);
        return false;
    }
    bool valid = hasher->init(hasher->context, personal) &&
        hasher->update(hasher->context, dh, 32) &&
        hasher->update(hasher->context, epk, 32) &&
        hasher->final(hasher->context, key);
    if (!valid) clear_key(key);
    return valid;
}
