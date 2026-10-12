/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* zstats — streaming statistics (C23).
 *
 * Count-weighted mean/variance, min/max, long-double totals, and
 * merge of partial accumulators (Chan's parallel algorithm). No
 * allocation, fully deterministic, no wall clock.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZSTATS_H
#define ZSTATS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t n;
    double   mean;
    double   m2;       /* sum of squared deviations from the mean */
    double   min;
    double   max;
    long double sum;   /* exact-ish running sum for total() */
} zstats;

void zstats_init(zstats *s);

/* Add one sample as a constant block through merge. NULL, count overflow,
 * or negative M2 in a nonempty destination are no-ops without mutation.
 * Empty payloads are ignored. The mean/M2 policies below apply. */
void zstats_add(zstats *s, double x);

/* Add the same sample k times as a constant block through merge. NULL,
 * k==0, count overflow, or negative M2 in a nonempty destination are no-ops
 * without mutation. An empty destination receives mean/min/max=x, M2=0
 * and sum=(long double)x*k, including for a non-finite first sample.
 * For a nonempty destination, the mean/M2 policies below apply. */
void zstats_add_repeated(zstats *s, double x, uint64_t k);

/* Merge another accumulator into s (Chan's algorithm).
 * NULL arguments or count overflow are no-ops: every destination field
 * remains unchanged. Negative M2 (including -infinity) in a nonempty
 * operand is also refused without mutation. Empty payloads are ignored;
 * one empty operand is an identity, and two empty operands reset s.
 * For two nonempty operands, the following mean and M2 policies apply.
 * Equal finite means are exact, including identical signed zeros; mixed
 * signed zeros give +0. NaN from a nonempty mean propagates; same-sign
 * infinities stay that infinity; infinity with a finite mean stays that
 * infinity; opposite-sign infinities give NaN.
 * For finite means, the exact count-weighted mean is rounded once to
 * binary64, nearest with ties to even, without intermediate overflow or
 * loss of a minority contribution before final rounding. It lies between
 * the input means and cannot be infinite or NaN.
 * For finite means, NaN M2 propagates before +infinity M2; otherwise M2 is
 * M2a + M2b + (b-a)^2*nA*nB/(nA+nB), with floating-point rounding and
 * possible +infinity. A non-finite nonempty mean makes M2 NaN (undefined
 * variance). Add and add_repeated use these same policies by merging a
 * constant block with M2=0; totals use rounded long-double arithmetic.
 * Requires IEEE binary64 double and default round-to-nearest arithmetic. */
void zstats_merge(zstats *s, const zstats *other);

uint64_t zstats_count(const zstats *s);
double   zstats_mean(const zstats *s);      /* 0 when empty */
double   zstats_variance(const zstats *s);  /* population, 0 when empty */
double   zstats_sample_variance(const zstats *s); /* n-1, 0 when n<2 */
double   zstats_stddev(const zstats *s);    /* population */
double   zstats_min(const zstats *s);       /* 0 when empty */
double   zstats_max(const zstats *s);       /* 0 when empty */
long double zstats_total(const zstats *s);  /* 0 when empty */

#ifdef __cplusplus
}
#endif

#endif /* ZSTATS_H */
