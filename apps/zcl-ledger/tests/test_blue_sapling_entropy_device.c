/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_entropy_device.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

typedef enum {
    RNG_VALID, RNG_ZERO, RNG_NULL, RNG_OTHER_BUFFER, RNG_LOCK
} rng_mode;

static int pin_valid;
static unsigned rng_calls;
static rng_mode mode;
static unsigned char other_buffer[BLUE_SAPLING_ENTROPY_BYTES];

int os_global_pin_is_validated(void) {
    return pin_valid;
}

unsigned char *cx_rng(unsigned char *buffer, unsigned int length) {
    assert(length == BLUE_SAPLING_ENTROPY_BYTES);
    ++rng_calls;
    for (unsigned i = 0; i < length; ++i)
        buffer[i] = mode == RNG_ZERO ? 0 : (unsigned char)(i + 1);
    if (mode == RNG_LOCK) pin_valid = 0;
    if (mode == RNG_NULL) return NULL;
    return mode == RNG_OTHER_BUFFER ? other_buffer : buffer;
}

static void assert_cleared(const uint8_t bytes[BLUE_SAPLING_ENTROPY_BYTES]) {
    for (unsigned i = 0; i < BLUE_SAPLING_ENTROPY_BYTES; ++i)
        assert(bytes[i] == 0);
}

int main(void) {
    uint8_t entropy[BLUE_SAPLING_ENTROPY_BYTES];
    memset(entropy, 0xa5, sizeof entropy);
    assert(!blue_sapling_device_entropy(entropy));
    assert(!rng_calls);
    assert_cleared(entropy);
    pin_valid = 1;
    mode = RNG_VALID;
    assert(blue_sapling_device_entropy(entropy));
    assert(rng_calls == 1);
    for (unsigned i = 0; i < sizeof entropy; ++i)
        assert(entropy[i] == (uint8_t)(i + 1));
    for (unsigned scenario = RNG_ZERO; scenario <= RNG_LOCK; ++scenario) {
        pin_valid = 1;
        mode = (rng_mode)scenario;
        memset(entropy, 0xa5, sizeof entropy);
        assert(!blue_sapling_device_entropy(entropy));
        assert_cleared(entropy);
    }
    assert(!pin_valid && rng_calls == 5);
    assert(!blue_sapling_device_entropy(NULL));
    assert(rng_calls == 5);
    return 0;
}
