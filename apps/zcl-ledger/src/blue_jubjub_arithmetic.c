/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_jubjub_arithmetic.h"
#include "blue_fr_ct.h"

#include <stddef.h>

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static const struct fr montgomery_one = {.d = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
}};

static const struct fr curve_d = {.d = {
    0x2a522455b974f6b0ULL, 0xfc6cc9ef0d9acab3ULL,
    0x7a08fb94c27628d1ULL, 0x57f8f6a8fe0e262eULL
}};

void blue_jub_identity(struct jub_point *result) {
    *result = (struct jub_point){0};
    result->y = montgomery_one;
    result->z = montgomery_one;
}

void blue_jub_add(struct jub_point *result, const struct jub_point *a,
    const struct jub_point *b) {
    struct fr A, B, C, D, E, F, G, H;
    blue_fr_mul_ct(&A, &a->x, &b->x);
    blue_fr_mul_ct(&B, &a->y, &b->y);
    blue_fr_mul_ct(&C, &a->t, &b->t);
    blue_fr_mul_ct(&C, &C, &curve_d);
    blue_fr_mul_ct(&D, &a->z, &b->z);
    blue_fr_add_ct(&E, &a->x, &a->y);
    blue_fr_add_ct(&F, &b->x, &b->y);
    blue_fr_mul_ct(&E, &E, &F);
    blue_fr_sub_ct(&E, &E, &A);
    blue_fr_sub_ct(&E, &E, &B);
    blue_fr_sub_ct(&F, &D, &C);
    blue_fr_add_ct(&G, &D, &C);
    blue_fr_add_ct(&H, &B, &A);
    blue_fr_mul_ct(&result->x, &E, &F);
    blue_fr_mul_ct(&result->y, &G, &H);
    blue_fr_mul_ct(&result->t, &E, &H);
    blue_fr_mul_ct(&result->z, &F, &G);
    wipe(&A, sizeof A);
    wipe(&B, sizeof B);
    wipe(&C, sizeof C);
    wipe(&D, sizeof D);
    wipe(&E, sizeof E);
    wipe(&F, sizeof F);
    wipe(&G, sizeof G);
    wipe(&H, sizeof H);
}

void blue_jub_double(struct jub_point *result, const struct jub_point *a) {
    struct fr A, B, C, D, E, F, G, H;
    blue_fr_mul_ct(&A, &a->x, &a->x);
    blue_fr_mul_ct(&B, &a->y, &a->y);
    blue_fr_mul_ct(&C, &a->z, &a->z);
    blue_fr_add_ct(&C, &C, &C);
    blue_fr_neg_ct(&D, &A);
    blue_fr_add_ct(&E, &a->x, &a->y);
    blue_fr_mul_ct(&E, &E, &E);
    blue_fr_sub_ct(&E, &E, &A);
    blue_fr_sub_ct(&E, &E, &B);
    blue_fr_add_ct(&G, &D, &B);
    blue_fr_sub_ct(&F, &G, &C);
    blue_fr_sub_ct(&H, &D, &B);
    blue_fr_mul_ct(&result->x, &E, &F);
    blue_fr_mul_ct(&result->y, &G, &H);
    blue_fr_mul_ct(&result->t, &E, &H);
    blue_fr_mul_ct(&result->z, &F, &G);
    wipe(&A, sizeof A);
    wipe(&B, sizeof B);
    wipe(&C, sizeof C);
    wipe(&D, sizeof D);
    wipe(&E, sizeof E);
    wipe(&F, sizeof F);
    wipe(&G, sizeof G);
    wipe(&H, sizeof H);
}
