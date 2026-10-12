/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Streaming statistics with bounded exact merge-mean arithmetic and
 * exponent-scaled merge variance updates. No allocation or libm. */
#include "zstats/zstats.h"
#include <float.h>

static_assert(sizeof(double) == sizeof(uint64_t) && FLT_RADIX == 2 &&
              DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024 &&
              DBL_MIN_EXP == -1021, "zstats requires IEEE binary64 double");

/* Newton iteration for sqrt: no libm dependency. Correctly rounded to
 * within 1 ulp for the ranges statistics produce. */
static double zsqrt(double x)
{
    if (x <= 0.0) return 0.0;
    /* Initial guess via bit hack, then refine. */
    union { double d; uint64_t u; } v = { x };
    v.u = (v.u >> 1) + 0x1ff7a3bea91d9b1bull;
    double y = v.d;
    for (int i = 0; i < 6; i++)
        y = 0.5 * (y + x / y);
    return y;
}

void zstats_init(zstats *s)
{
    if (!s) return;
    s->n = 0;
    s->mean = 0.0;
    s->m2 = 0.0;
    s->min = 0.0;
    s->max = 0.0;
    s->sum = 0.0L;
}

static bool count_fits(const zstats *s, uint64_t k)
{
    return s && k <= UINT64_MAX - s->n;
}

void zstats_add(zstats *s, double x)
{
    zstats_add_repeated(s, x, 1);
}

void zstats_add_repeated(zstats *s, double x, uint64_t k)
{
    if (!count_fits(s, k) || k == 0) return;
    const zstats block = {
        .n = k, .mean = x, .m2 = 0.0, .min = x, .max = x,
        .sum = (long double)x * (long double)k
    };
    zstats_merge(s, &block);
}

/* A finite binary64 value is an integer multiple of 2^-1074. The
 * weighted numerator needs at most 2098 + 64 bits. Keep it exact until
 * division and a single ties-to-even rounding; in particular, uint64_t
 * counts differing by one must not first collapse to the same double. */
#define MEAN_WORDS 68
#define MEAN_BITS (MEAN_WORDS * 32)
typedef struct { uint32_t word[MEAN_WORDS]; } mean_integer;

static void mean_add_word(mean_integer *v, uint32_t x, unsigned at)
{
    uint64_t carry = x;
    while (carry && at < MEAN_WORDS) {
        carry += v->word[at];
        v->word[at++] = (uint32_t)carry;
        carry >>= 32;
    }
}

static mean_integer mean_product(double x, uint64_t n)
{
    union { double d; uint64_t u; } bits = {x};
    unsigned exponent = (unsigned)((bits.u >> 52) & 2047);
    uint64_t significand = bits.u & UINT64_C(0xfffffffffffff);
    if (exponent) significand |= UINT64_C(1) << 52;
    unsigned shift = exponent ? exponent - 1 : 0;
    mean_integer result = {{0}};
    /* Add each set count bit times the 53-bit significand. The shifted
     * three-word add has no multiplication or carry wider than uint64_t. */
    for (unsigned bit = 0; bit < 64; bit++) {
        if (!((n >> bit) & 1)) continue;
        unsigned at = (shift + bit) / 32;
        unsigned offset = (shift + bit) % 32;
        uint64_t low = (significand & UINT32_MAX) << offset;
        uint64_t high = (significand >> 32) << offset;
        mean_add_word(&result, (uint32_t)low, at);
        mean_add_word(&result, (uint32_t)(low >> 32), at + 1);
        mean_add_word(&result, (uint32_t)high, at + 1);
        mean_add_word(&result, (uint32_t)(high >> 32), at + 2);
    }
    return result;
}

static int mean_compare(const mean_integer *a, const mean_integer *b)
{
    for (unsigned i = MEAN_WORDS; i-- > 0;) {
        if (a->word[i] != b->word[i])
            return a->word[i] > b->word[i] ? 1 : -1;
    }
    return 0;
}

static mean_integer mean_combine(const mean_integer *a,
                                 const mean_integer *b, bool subtract)
{
    mean_integer out;
    uint64_t carry = 0;
    for (unsigned i = 0; i < MEAN_WORDS; i++) {
        if (subtract) {
            uint64_t sub = (uint64_t)b->word[i] + carry;
            out.word[i] = (uint32_t)((uint64_t)a->word[i] - sub);
            carry = a->word[i] < sub;
        } else {
            uint64_t sum = (uint64_t)a->word[i] + b->word[i] + carry;
            out.word[i] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }
    return out;
}

static unsigned mean_bit(const mean_integer *a, unsigned bit)
{
    return (a->word[bit / 32] >> (bit % 32)) & 1;
}

static uint64_t mean_divide(mean_integer *a, uint64_t divisor)
{
    uint64_t remainder = 0;
    for (unsigned bit = MEAN_BITS; bit-- > 0;) {
        bool high = (remainder >> 63) != 0;
        remainder = (remainder << 1) | mean_bit(a, bit);
        bool take = high || remainder >= divisor;
        if (take) remainder -= divisor;
        uint32_t mask = UINT32_C(1) << (bit % 32);
        a->word[bit / 32] &= ~mask;
        if (take) a->word[bit / 32] |= mask;
    }
    return remainder;
}

static double mean_round(mean_integer value, uint64_t divisor, bool negative)
{
    uint64_t remainder = mean_divide(&value, divisor);
    unsigned top = MEAN_BITS - 1;
    while (top && !mean_bit(&value, top)) top--;
    unsigned cut = top > 52 ? top - 52 : 0;
    uint64_t significand = 0;
    for (unsigned bit = top + 1; bit-- > cut;)
        significand = (significand << 1) | mean_bit(&value, bit);
    bool up;
    if (cut) {
        bool sticky = remainder != 0;
        for (unsigned bit = 0; bit + 1 < cut; bit++)
            sticky |= mean_bit(&value, bit) != 0;
        up = mean_bit(&value, cut - 1) && (sticky || (significand & 1));
    } else {
        /* Comparing r with N-r avoids overflow in twice the remainder. */
        up = remainder > divisor - remainder ||
             (remainder == divisor - remainder && (significand & 1));
    }
    significand += up;
    if (significand == (UINT64_C(1) << 53)) {
        significand >>= 1;
        top++;
    }
    uint64_t exponent = top >= 52 ? top - 51 : 0;
    /* Rounding the largest subnormal can produce the smallest normal. */
    if (!exponent && significand == (UINT64_C(1) << 52)) exponent = 1;
    union { uint64_t u; double d; } out = {
        ((uint64_t)negative << 63) | (exponent << 52) |
        (significand & UINT64_C(0xfffffffffffff))
    };
    return out.d;
}

static double merged_mean(double a, double b, uint64_t na, uint64_t nb,
                          uint64_t total)
{
    if (a == b) return a == 0.0 ? a + b : a;
    if (!(a <= DBL_MAX && a >= -DBL_MAX &&
          b <= DBL_MAX && b >= -DBL_MAX)) return a + b;
    mean_integer left = mean_product(a, na), right = mean_product(b, nb);
    bool negative = a < 0.0;
    bool subtract = negative != (b < 0.0);
    if (subtract && mean_compare(&left, &right) < 0) {
        mean_integer swap = left;
        left = right;
        right = swap;
        negative = !negative;
    }
    mean_integer numerator = mean_combine(&left, &right, subtract);
    if (subtract && mean_compare(&left, &right) == 0) negative = false;
    return mean_round(numerator, total, negative);
}

static double stats_nan(void)
{
    union { uint64_t u; double d; } value = {UINT64_C(0x7ff8000000000000)};
    return value.d;
}

static double scale_binary(double value, int exponent)
{
    while (exponent > 512) { value *= 0x1p512; exponent -= 512; }
    while (exponent < -512) { value *= 0x1p-512; exponent += 512; }
    union { uint64_t u; double d; } power = {
        (uint64_t)(exponent + 1023) << 52
    };
    return value * power.d;
}

static int mean_exponent(double value)
{
    union { double d; uint64_t u; } bits = {value};
    unsigned exponent = (unsigned)((bits.u >> 52) & 2047);
    return exponent ? (int)exponent - 1023 : -1022;
}

static double merged_m2(const zstats *a, const zstats *b, uint64_t total)
{
    if (!(a->mean <= DBL_MAX && a->mean >= -DBL_MAX &&
          b->mean <= DBL_MAX && b->mean >= -DBL_MAX)) return stats_nan();
    /* NaN takes precedence over +infinity; negative M2 was refused before
     * entry. Equal finite means contribute zero even with huge counts. */
    double sum = a->m2 + b->m2;
    if (!(sum <= DBL_MAX) || a->mean == b->mean) return sum;
    int exponent = mean_exponent(a->mean);
    int other_exponent = mean_exponent(b->mean);
    if (other_exponent > exponent) exponent = other_exponent;
    double delta = scale_binary(b->mean, -exponent) -
                   scale_binary(a->mean, -exponent);
    /* Normalize the difference before squaring. Scale only after applying
     * nA*nB/N, so a tiny square is not lost before a large count rescues it. */
    uint64_t small = a->n < b->n ? a->n : b->n;
    uint64_t large = a->n < b->n ? b->n : a->n;
    double cross = delta * delta * ((double)large / (double)total) *
                   (double)small;
    return sum + scale_binary(cross, 2 * exponent);
}

void zstats_merge(zstats *s, const zstats *other)
{
    if (!s || !other) return;
    if (other->n > UINT64_MAX - s->n) return;
    if ((s->n && s->m2 < 0.0) || (other->n && other->m2 < 0.0)) return;
    if (!s->n && !other->n) { zstats_init(s); return; }
    if (!other->n) return;
    if (s->n == 0) {
        *s = *other;
        return;
    }
    uint64_t new_n = s->n + other->n;
    double m2 = merged_m2(s, other, new_n);
    s->mean = merged_mean(s->mean, other->mean, s->n, other->n, new_n);
    s->m2 = m2;
    s->n = new_n;
    if (other->min < s->min) s->min = other->min;
    if (other->max > s->max) s->max = other->max;
    s->sum += other->sum;
}

uint64_t zstats_count(const zstats *s)
{
    return s ? s->n : 0;
}

double zstats_mean(const zstats *s)
{
    return (s && s->n > 0) ? s->mean : 0.0;
}

double zstats_variance(const zstats *s)
{
    return (s && s->n > 0) ? s->m2 / (double)s->n : 0.0;
}

double zstats_sample_variance(const zstats *s)
{
    return (s && s->n > 1) ? s->m2 / (double)(s->n - 1) : 0.0;
}

double zstats_stddev(const zstats *s)
{
    return zsqrt(zstats_variance(s));
}

double zstats_min(const zstats *s)
{
    return (s && s->n > 0) ? s->min : 0.0;
}

double zstats_max(const zstats *s)
{
    return (s && s->n > 0) ? s->max : 0.0;
}

long double zstats_total(const zstats *s)
{
    return (s && s->n > 0) ? s->sum : 0.0L;
}
