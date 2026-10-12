/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_ock.h"

#include "blue_storage.h"

static void clear_key(uint8_t key[32]) {
    volatile uint8_t *bytes = key;
    for (unsigned i = 0; i < 32; ++i) bytes[i] = 0;
}

static bool storage_disjoint(const uint8_t key[32],
    const uint8_t ovk[32], const uint8_t cv[32],
    const uint8_t cm[32], const uint8_t epk[32],
    const zcl_zip243_hasher *hasher) {
    if (blue_storage_overlaps(key, 32, ovk, 32) ||
        blue_storage_overlaps(key, 32, cv, 32) ||
        blue_storage_overlaps(key, 32, cm, 32) ||
        blue_storage_overlaps(key, 32, epk, 32) ||
        blue_storage_overlaps(key, 32, hasher,
            hasher ? sizeof *hasher : 0)) return false;
    return !hasher ||
        !blue_storage_overlaps(key, 32, hasher->context, 1);
}

static bool complete_inputs(const uint8_t ovk[32], const uint8_t cv[32],
    const uint8_t cm[32], const uint8_t epk[32],
    const zcl_zip243_hasher *hasher) {
    return ovk && cv && cm && epk && hasher && hasher->context &&
        hasher->init && hasher->update && hasher->final;
}

bool blue_sapling_ock(uint8_t key[32], const uint8_t ovk[32],
    const uint8_t cv[32], const uint8_t cm[32], const uint8_t epk[32],
    const zcl_zip243_hasher *hasher) {
    static const uint8_t personal[16] = {
        'Z','c','a','s','h','_','D','e','r','i','v','e','_','o','c','k'
    };
    if (!key) return false;
    if (!storage_disjoint(key, ovk, cv, cm, epk, hasher))
        return false;
    if (!complete_inputs(ovk, cv, cm, epk, hasher)) {
        clear_key(key);
        return false;
    }
    bool valid = hasher->init(hasher->context, personal) &&
        hasher->update(hasher->context, ovk, 32) &&
        hasher->update(hasher->context, cv, 32) &&
        hasher->update(hasher->context, cm, 32) &&
        hasher->update(hasher->context, epk, 32) &&
        hasher->final(hasher->context, key);
    if (!valid) clear_key(key);
    return valid;
}
