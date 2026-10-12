/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "sapling/fr.h"
#include "sapling/jubjub.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static void check_digest(const uint8_t digest[64]) {
    struct fs expected;
    uint8_t actual_bytes[32], expected_bytes[32];
    jubjub_to_scalar(digest, actual_bytes);
    fs_to_uniform(&expected, digest);
    fs_to_bytes(expected_bytes, &expected);
    assert(memcmp(actual_bytes, expected_bytes, 32) == 0);
}

int main(void) {
    uint8_t digest[64] = {0};
    check_digest(digest);
    digest[0] = 1;
    check_digest(digest);
    memset(digest, 0xff, sizeof digest);
    check_digest(digest);
    uint32_t state = 0x9e3779b9u;
    for (unsigned sample = 0; sample < 256; ++sample) {
        for (unsigned i = 0; i < sizeof digest; ++i) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            digest[i] = (uint8_t)state;
        }
        check_digest(digest);
    }
    return 0;
}
