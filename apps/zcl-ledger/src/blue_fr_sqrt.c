/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_fr_sqrt.h"
#include "blue_fr_ct.h"
#include "blue_mod256.h"

static const struct fr montgomery_one = {.d = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
}};

static const uint64_t odd_part[4] = {
    0xfffe5bfeffffffffULL, 0x09a1d80553bda402ULL,
    0x299d7d483339d808ULL, 0x0000000073eda753ULL
};

static bool equal(const struct fr *a, const struct fr *b) {
    uint64_t difference = 0;
    for (unsigned i = 0; i < 4; ++i) difference |= a->d[i] ^ b->d[i];
    return difference == 0;
}

static void power(struct fr *result, const struct fr *base,
    const uint64_t exponent[4]) {
    struct fr product = montgomery_one;
    for (int bit = 255; bit >= 0; --bit) {
        blue_fr_mul_ct(&product, &product, &product);
        if ((exponent[bit / 64] >> (bit % 64)) & 1u)
            blue_fr_mul_ct(&product, &product, base);
    }
    *result = product;
    blue_mod256_wipe(&product, sizeof product);
}

static int least_one_power(const struct fr *value, int limit) {
    struct fr power_of_two = *value;
    for (int k = 0; k < limit; ++k) {
        if (equal(&power_of_two, &montgomery_one)) {
            blue_mod256_wipe(&power_of_two, sizeof power_of_two);
            return k;
        }
        blue_fr_mul_ct(&power_of_two, &power_of_two, &power_of_two);
    }
    blue_mod256_wipe(&power_of_two, sizeof power_of_two);
    return -1;
}

bool blue_fr_sqrt_public(struct fr *result, const struct fr *value) {
    if (!result) return false;
    if (!value) {
        *result = (struct fr){0};
        return false;
    }
    struct fr input = *value;
    *result = (struct fr){0};
    const struct fr zero = {0};
    if (equal(&input, &zero)) return true;
    const uint8_t five_bytes[32] = {5};
    struct fr five, w, x, b, y, temporary;
    if (!blue_fr_from_bytes_canonical(&five, five_bytes)) return false;
    power(&w, &five, odd_part);
    uint64_t half[4];
    for (unsigned i = 0; i < 4; ++i)
        half[i] = (odd_part[i] - (i == 0 ? 1u : 0u)) >> 1 |
            (i < 3 ? odd_part[i + 1] << 63 : 0);
    power(&x, &input, half);
    blue_fr_mul_ct(&b, &x, &x);
    blue_fr_mul_ct(&b, &input, &b);
    blue_fr_mul_ct(&y, &input, &x);
    bool valid = true;
    for (int v = 32; v > 1;) {
        int k = least_one_power(&b, v);
        if (k < 0) { valid = false; break; }
        if (k == 0) break;
        temporary = w;
        for (int i = 0; i < v - k - 1; ++i)
            blue_fr_mul_ct(&temporary, &temporary, &temporary);
        v = k;
        blue_fr_mul_ct(&w, &temporary, &temporary);
        blue_fr_mul_ct(&b, &b, &w);
        blue_fr_mul_ct(&y, &y, &temporary);
    }
    blue_fr_mul_ct(&temporary, &y, &y);
    valid = valid && equal(&temporary, &input);
    if (valid) *result = y;
    blue_mod256_wipe(&five, sizeof five);
    blue_mod256_wipe(&w, sizeof w);
    blue_mod256_wipe(&x, sizeof x);
    blue_mod256_wipe(&b, sizeof b);
    blue_mod256_wipe(&y, sizeof y);
    blue_mod256_wipe(&temporary, sizeof temporary);
    blue_mod256_wipe(&input, sizeof input);
    blue_mod256_wipe(half, sizeof half);
    return valid;
}
