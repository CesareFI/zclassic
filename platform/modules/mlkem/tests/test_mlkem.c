/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* ML-KEM-768 tests: arithmetic identities, NIST ACVP known-answer vectors,
 * round trips, ciphertext-malleability behaviour, input validation and an
 * optional timing run (--bench). */

#define _POSIX_C_SOURCE 200809L

#include "mlkem/mlkem.h"
#include "mlkem/mlkem_kat.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "../src/mlkem_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "mlkem test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

enum {
    EK = ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE,
    DK = ZCL_MLKEM768_DECAPSULATION_KEY_SIZE,
    CT = ZCL_MLKEM768_CIPHERTEXT_SIZE,
    SS = ZCL_MLKEM768_SHARED_SECRET_SIZE,
    MAX_TOKENS = 8
};

#include "mlkem768_vectors.h"

static char vector_text[300000];

/* Joins the vector strings into one NUL-terminated text. */
static int load_vectors(void)
{
    size_t used = 0;
    for (size_t i = 0; i < sizeof(mlkem768_vector_pieces) /
                               sizeof(mlkem768_vector_pieces[0]); i++) {
        const size_t n = strlen(mlkem768_vector_pieces[i]);
        CHECK(used + n < sizeof(vector_text));
        memcpy(vector_text + used, mlkem768_vector_pieces[i], n);
        used += n;
    }
    vector_text[used] = '\0';
    return 0;
}

static bool all_equal(const uint8_t *p, size_t len, uint8_t v)
{
    for (size_t i = 0; i < len; i++)
        if (p[i] != v)
            return false;
    return true;
}

struct token {
    const char *s;
    size_t n;
};

static uint64_t prng_state;

static void prng_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint64_t z = (prng_state += UINT64_C(0x9e3779b97f4a7c15));
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        const uint64_t w = z ^ (z >> 31);
        const uint8_t byte = (uint8_t)(w >> 24);
        out[i] = byte;
    }
}

static bool prng_callback(void *context, uint8_t *out, size_t len)
{
    (void)context;
    prng_bytes(out, len);
    return true;
}

static bool failing_callback(void *context, uint8_t *out, size_t len)
{
    (void)context;
    (void)out;
    (void)len;
    return false;
}

/* Arithmetic identities ---------------------------------------------- */

static int check_reductions(void)
{
    for (int a = INT16_MIN; a <= INT16_MAX; a++) {
        const int want = ((a % MLKEM_Q) + MLKEM_Q) % MLKEM_Q;
        const int b = mlkem_barrett_reduce((int16_t)a);
        CHECK(b >= -(MLKEM_Q - 1) / 2 && b <= (MLKEM_Q - 1) / 2);
        CHECK(mlkem_canonical((int16_t)a) == want);
    }
    return 0;
}

static int check_compression(void)
{
    static const unsigned widths[] = {1, 4, 10};
    for (unsigned w = 0; w < 3; w++) {
        const unsigned d = widths[w];
        for (unsigned x = 0; x < MLKEM_Q; x++) {
            const unsigned want =
                (((x << (d + 1)) + MLKEM_Q) / (2 * MLKEM_Q)) & ((1u << d) - 1);
            CHECK(mlkem_compress((uint16_t)x, d) == want);
        }
        for (unsigned y = 0; y < (1u << d); y++) {
            const unsigned want = ((y * MLKEM_Q * 2 + (1u << d)) >> (d + 1));
            CHECK(mlkem_decompress((uint16_t)y, d) == want);
        }
    }
    return 0;
}

static void random_poly(struct mlkem_poly *p)
{
    uint8_t b[2 * MLKEM_N];
    prng_bytes(b, sizeof(b));
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = (int16_t)(zcl_read_u16_le(b + 2 * i) % MLKEM_Q);
}

static void negacyclic_product(struct mlkem_poly *r, const struct mlkem_poly *a,
                               const struct mlkem_poly *b)
{
    int32_t acc[MLKEM_N] = {0};
    for (unsigned i = 0; i < MLKEM_N; i++)
        for (unsigned j = 0; j < MLKEM_N; j++) {
            const int32_t t = (int32_t)a->c[i] * b->c[j] % MLKEM_Q;
            if (i + j < MLKEM_N)
                acc[i + j] += t;
            else
                acc[i + j - MLKEM_N] -= t;
        }
    for (unsigned i = 0; i < MLKEM_N; i++)
        r->c[i] = (int16_t)(((acc[i] % MLKEM_Q) + MLKEM_Q) % MLKEM_Q);
}

static int check_ntt_product(void)
{
    for (unsigned round = 0; round < 8; round++) {
        struct mlkem_poly a, b, want, got = {{0}};
        random_poly(&a);
        random_poly(&b);
        negacyclic_product(&want, &a, &b);
        mlkem_ntt(&a);
        mlkem_ntt(&b);
        mlkem_basemul_acc(&got, &a, &b);
        mlkem_invntt(&got);
        mlkem_poly_canonical(&got);
        CHECK(memcmp(&got, &want, sizeof(got)) == 0);
    }
    return 0;
}

static int check_codec(void)
{
    static const unsigned widths[] = {1, 4, 10, 12};
    for (unsigned w = 0; w < 4; w++) {
        struct mlkem_poly a, b;
        uint8_t buf[32 * 12];
        const unsigned d = widths[w];
        random_poly(&a);
        for (unsigned i = 0; i < MLKEM_N; i++)
            a.c[i] = (int16_t)(a.c[i] & ((1 << d) - 1));
        mlkem_poly_encode(&a, d, buf);
        mlkem_poly_decode(&b, d, buf);
        CHECK(memcmp(&a, &b, sizeof(a)) == 0);
    }
    return 0;
}

/* Known-answer vectors ----------------------------------------------- */

static bool hex_decode(struct token t, uint8_t *out, size_t len)
{
    if (t.n != 2 * len)
        return false;
    for (size_t i = 0; i < t.n; i++) {
        const char c = t.s[i];
        const int v = zcl_hex_nibble(c, false);
        if (v < 0)
            return false;
        if (i % 2 == 0)
            out[i / 2] = (uint8_t)(v << 4);
        else
            out[i / 2] |= (uint8_t)v;
    }
    return true;
}

static bool token_is(struct token t, const char *word)
{
    return t.n == strlen(word) && memcmp(t.s, word, t.n) == 0;
}

/* Splits the line starting at *pos into tokens; advances *pos past it. */
static size_t next_line(const char **pos, struct token tok[MAX_TOKENS])
{
    const char *p = *pos;
    size_t count = 0;
    while (*p != '\n' && *p != '\0') {
        while (*p == ' ')
            p++;
        const char *start = p;
        while (*p != ' ' && *p != '\n' && *p != '\0')
            p++;
        if (p > start && count < MAX_TOKENS)
            tok[count++] = (struct token){start, (size_t)(p - start)};
    }
    *pos = *p == '\n' ? p + 1 : p;
    return count;
}

struct tally {
    unsigned keygen, encaps, decaps, reject, dkcheck, ekcheck;
    unsigned dk_valid, dk_invalid, ek_valid, ek_invalid;
};

static int run_keygen(const struct token *t, struct tally *n)
{
    uint8_t seed[64], ek[EK], dk[DK], want_ek[EK], want_dk[DK];
    CHECK(hex_decode(t[2], seed, 32) && hex_decode(t[3], seed + 32, 32));
    CHECK(hex_decode(t[4], want_ek, EK) && hex_decode(t[5], want_dk, DK));
    CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);
    CHECK(memcmp(ek, want_ek, EK) == 0 && memcmp(dk, want_dk, DK) == 0);
    n->keygen++;
    return 0;
}

static int run_encaps(const struct token *t, struct tally *n)
{
    uint8_t ek[EK], m[32], want_c[CT], want_k[SS], c[CT], k[SS];
    CHECK(hex_decode(t[2], ek, EK) && hex_decode(t[3], m, 32));
    CHECK(hex_decode(t[4], want_c, CT) && hex_decode(t[5], want_k, SS));
    CHECK(zcl_mlkem768_encaps_internal(ek, EK, m, c, k) == ZCL_MLKEM_OK);
    CHECK(memcmp(c, want_c, CT) == 0 && memcmp(k, want_k, SS) == 0);
    n->encaps++;
    return 0;
}

static int run_decaps(const struct token *t, struct tally *n)
{
    uint8_t dk[DK], c[CT], want_k[SS], k[SS];
    CHECK(hex_decode(t[3], dk, DK) && hex_decode(t[4], c, CT));
    CHECK(hex_decode(t[5], want_k, SS));
    CHECK(zcl_mlkem768_decaps(dk, DK, c, CT, k) == ZCL_MLKEM_OK);
    CHECK(memcmp(k, want_k, SS) == 0);
    /* Algorithm 18 returns J(z || c) exactly when re-encryption does not
     * reproduce c, so equality with an independently computed J(z || c)
     * separates the implicit-rejection path from the valid path. */
    uint8_t j_in[32 + CT], j[SS];
    memcpy(j_in, dk + DK - 32, 32);
    memcpy(j_in + 32, c, CT);
    CHECK(zcl_shake256(j_in, sizeof(j_in), j, sizeof(j)));
    const bool rejected = token_is(t[2], "reject");
    CHECK((memcmp(k, j, SS) == 0) == rejected);
    if (rejected)
        n->reject++;
    else
        n->decaps++;
    return 0;
}

static int run_check(const struct token *t, struct tally *n, bool is_dk)
{
    uint8_t key[DK];
    const size_t len = is_dk ? DK : EK;
    CHECK(hex_decode(t[3], key, len));
    const bool want = token_is(t[2], "1");
    const enum zcl_mlkem_status st =
        is_dk ? zcl_mlkem768_check_decapsulation_key(key, len)
              : zcl_mlkem768_check_encapsulation_key(key, len);
    CHECK((st == ZCL_MLKEM_OK) == want);
    if (is_dk) {
        n->dkcheck++;
        want ? n->dk_valid++ : n->dk_invalid++;
    } else {
        n->ekcheck++;
        want ? n->ek_valid++ : n->ek_invalid++;
    }
    return 0;
}

static int run_record(const struct token *t, size_t count, struct tally *n)
{
    if (count == 0 || t[0].s[0] == '#')
        return 0;
    CHECK(count >= 4);
    if (token_is(t[0], "keygen"))
        return run_keygen(t, n);
    if (token_is(t[0], "encaps"))
        return run_encaps(t, n);
    if (token_is(t[0], "decaps"))
        return run_decaps(t, n);
    if (token_is(t[0], "dkcheck"))
        return run_check(t, n, true);
    if (token_is(t[0], "ekcheck"))
        return run_check(t, n, false);
    CHECK(!"unknown vector record");
    return 1;
}

static int check_vectors(void)
{
    struct tally n = {0};
    if (load_vectors() != 0)
        return 1;
    const char *pos = vector_text;
    while (*pos != '\0') {
        struct token tok[MAX_TOKENS];
        const size_t count = next_line(&pos, tok);
        if (run_record(tok, count, &n) != 0)
            return 1;
    }
    printf("vectors: keygen %u/12 encaps %u/12 decaps-valid %u/5 "
           "decaps-implicit-rejection %u/5 dk-check %u/10 ek-check %u/10\n",
           n.keygen, n.encaps, n.decaps, n.reject, n.dkcheck, n.ekcheck);
    CHECK(n.keygen == 12 && n.encaps == 12 && n.decaps == 5 && n.reject == 5);
    CHECK(n.dkcheck == 10 && n.ekcheck == 10);
    CHECK(n.dk_valid > 0 && n.dk_invalid > 0);
    CHECK(n.ek_valid > 0 && n.ek_invalid > 0);
    return 0;
}

/* Round trips and malleability --------------------------------------- */

static int check_round_trips(void)
{
    uint8_t ek[EK], dk[DK], ct[CT], k1[SS], k2[SS];
    prng_state = 1;
    for (unsigned i = 0; i < 1000; i++) {
        uint8_t seed[64], m[32];
        prng_bytes(seed, sizeof(seed));
        prng_bytes(m, sizeof(m));
        CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);
        CHECK(zcl_mlkem768_encaps_internal(ek, EK, m, ct, k1) == ZCL_MLKEM_OK);
        CHECK(zcl_mlkem768_decaps(dk, DK, ct, CT, k2) == ZCL_MLKEM_OK);
        CHECK(memcmp(k1, k2, SS) == 0);
    }
    printf("round trips: 1000/1000\n");
    return 0;
}

static int check_public_api(void)
{
    uint8_t ek[EK], dk[DK], ct[CT], k1[SS], k2[SS];
    prng_state = 7;
    CHECK(zcl_mlkem768_keygen(prng_callback, NULL, ek, dk) == ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_encaps(prng_callback, NULL, ek, EK, ct, k1) ==
          ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_decaps(dk, DK, ct, CT, k2) == ZCL_MLKEM_OK);
    CHECK(memcmp(k1, k2, SS) == 0);
    return 0;
}

static int check_bit_flips(void)
{
    uint8_t ek[EK], dk[DK], ct[CT], bad[CT], k[SS], kbad[SS], seed[64], m[32];
    prng_state = 99;
    prng_bytes(seed, sizeof(seed));
    prng_bytes(m, sizeof(m));
    CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_encaps_internal(ek, EK, m, ct, k) == ZCL_MLKEM_OK);
    for (unsigned i = 0; i < 64; i++) {
        const size_t bit = ((size_t)i * 8 * CT) / 64 + i * 7 % 8;
        memcpy(bad, ct, CT);
        bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        CHECK(zcl_mlkem768_decaps(dk, DK, bad, CT, kbad) == ZCL_MLKEM_OK);
        CHECK(memcmp(kbad, k, SS) != 0);
    }
    printf("ciphertext bit flips: 64/64 differ without error\n");
    return 0;
}

static int check_validation(void)
{
    uint8_t ek[EK], dk[DK], ct[CT], ss[SS], seed[64] = {0}, m[32] = {0};
    CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_keygen(failing_callback, NULL, ek, dk) ==
          ZCL_MLKEM_ERR_RANDOM);
    CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_encaps_internal(ek, EK - 1, m, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    CHECK(zcl_mlkem768_encaps_internal(NULL, EK, m, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    ek[0] = 0xff;
    ek[1] |= 0x0f;
    memset(ct, 0x55, CT);
    memset(ss, 0x55, SS);
    CHECK(zcl_mlkem768_encaps_internal(ek, EK, m, ct, ss) ==
          ZCL_MLKEM_ERR_EK_INVALID);
    CHECK(ss[0] == 0 && ss[SS - 1] == 0);
    CHECK(all_equal(ct, CT, 0));
    CHECK(zcl_mlkem768_encaps(failing_callback, NULL, ek, EK, ct, ss) ==
          ZCL_MLKEM_ERR_RANDOM);
    memset(ct, 0, CT);
    CHECK(zcl_mlkem768_decaps(dk, DK - 1, ct, CT, ss) == ZCL_MLKEM_ERR_ARGUMENT);
    CHECK(zcl_mlkem768_decaps(dk, DK, ct, CT + 1, ss) == ZCL_MLKEM_ERR_ARGUMENT);
    dk[2336] ^= 1;
    memset(ss, 0x55, SS);
    CHECK(zcl_mlkem768_decaps(dk, DK, ct, CT, ss) == ZCL_MLKEM_ERR_DK_INVALID);
    CHECK(ss[0] == 0 && ss[SS - 1] == 0);
    return 0;
}

/* Every non-NULL output is zero after each failing call. */
static uint8_t ek[EK], dk[DK], ct[CT], ss[SS], good_ek[EK], good_dk[DK];
static const uint8_t zero_seed[64], zero_m[32];

#define FILL() do { memset(ek, 0xA5, EK); memset(dk, 0xA5, DK); \
                    memset(ct, 0xA5, CT); memset(ss, 0xA5, SS); } while (0)
#define KEYS_ZERO() (all_equal(ek, EK, 0) && all_equal(dk, DK, 0))
#define OUT_ZERO() (all_equal(ct, CT, 0) && all_equal(ss, SS, 0))

static int check_keygen_failures(void)
{

    FILL();
    CHECK(zcl_mlkem768_keygen(failing_callback, NULL, ek, dk) ==
          ZCL_MLKEM_ERR_RANDOM && KEYS_ZERO());
    FILL();
    CHECK(zcl_mlkem768_keygen(NULL, NULL, ek, dk) == ZCL_MLKEM_ERR_ARGUMENT &&
          KEYS_ZERO());
    FILL();
    CHECK(zcl_mlkem768_keygen(prng_callback, NULL, ek, NULL) ==
          ZCL_MLKEM_ERR_ARGUMENT && all_equal(ek, EK, 0));
    FILL();
    CHECK(zcl_mlkem768_keygen_internal(NULL, ek, dk) == ZCL_MLKEM_ERR_ARGUMENT &&
          KEYS_ZERO());
    return 0;
}

static int check_encaps_failures(void)
{
    const uint8_t *m = zero_m;
    FILL();
    CHECK(zcl_mlkem768_encaps_internal(good_ek, EK, NULL, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && OUT_ZERO());
    FILL();
    CHECK(zcl_mlkem768_encaps_internal(NULL, EK, m, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && OUT_ZERO());
    FILL();
    CHECK(zcl_mlkem768_encaps_internal(good_ek, EK, m, ct, NULL) ==
          ZCL_MLKEM_ERR_ARGUMENT && all_equal(ct, CT, 0));
    FILL();
    CHECK(zcl_mlkem768_encaps_internal(good_ek, EK + 1, m, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && OUT_ZERO());

    FILL();
    CHECK(zcl_mlkem768_encaps(NULL, NULL, good_ek, EK, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && OUT_ZERO());
    FILL();
    CHECK(zcl_mlkem768_encaps(prng_callback, NULL, NULL, EK, ct, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && OUT_ZERO());
    FILL();
    CHECK(zcl_mlkem768_encaps(prng_callback, NULL, good_ek, EK, NULL, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && all_equal(ss, SS, 0));
    FILL();
    CHECK(zcl_mlkem768_encaps(failing_callback, NULL, good_ek, EK, ct, ss) ==
          ZCL_MLKEM_ERR_RANDOM && OUT_ZERO());
    return 0;
}

static int check_decaps_failures(void)
{
    FILL();
    CHECK(zcl_mlkem768_decaps(NULL, DK, ct, CT, ss) == ZCL_MLKEM_ERR_ARGUMENT &&
          all_equal(ss, SS, 0));
    FILL();
    CHECK(zcl_mlkem768_decaps(good_dk, DK, NULL, CT, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && all_equal(ss, SS, 0));
    FILL();
    CHECK(zcl_mlkem768_decaps(good_dk, DK, ct, CT, NULL) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    FILL();
    CHECK(zcl_mlkem768_decaps(good_dk, DK - 1, ct, CT, ss) ==
          ZCL_MLKEM_ERR_ARGUMENT && all_equal(ss, SS, 0));
    return 0;
}

#undef FILL
#undef KEYS_ZERO
#undef OUT_ZERO

static int check_failure_zeroing(void)
{
    CHECK(zcl_mlkem768_keygen_internal(zero_seed, good_ek, good_dk) ==
          ZCL_MLKEM_OK);
    if (check_keygen_failures() || check_encaps_failures() ||
        check_decaps_failures())
        return 1;
    printf("failure paths: outputs zeroed\n");
    return 0;
}

/* Section 7.2 coefficient boundary, NULL arguments and the Section 7.3 hash
 * check over the embedded encapsulation key. */
static int check_key_checks(void)
{
    uint8_t ek[EK], dk[DK], ss[SS], seed[64] = {0};
    CHECK(zcl_mlkem768_keygen_internal(seed, ek, dk) == ZCL_MLKEM_OK);

    /* First coefficient: 3328 = 0xd00 is accepted, 3329 = 0xd01 rejected. */
    ek[0] = 0x00;
    ek[1] = (uint8_t)((ek[1] & 0xf0) | 0x0d);
    CHECK(zcl_mlkem768_check_encapsulation_key(ek, EK) == ZCL_MLKEM_OK);
    ek[0] = 0x01;
    CHECK(zcl_mlkem768_check_encapsulation_key(ek, EK) ==
          ZCL_MLKEM_ERR_EK_INVALID);
    /* Second coefficient of the pair uses the high nibble of byte 1. */
    ek[0] = 0x00;
    ek[1] = 0x00;
    ek[2] = 0xd0;
    CHECK(zcl_mlkem768_check_encapsulation_key(ek, EK) == ZCL_MLKEM_OK);
    ek[1] = 0x10;
    CHECK(zcl_mlkem768_check_encapsulation_key(ek, EK) ==
          ZCL_MLKEM_ERR_EK_INVALID);

    CHECK(zcl_mlkem768_check_encapsulation_key(NULL, EK) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    CHECK(zcl_mlkem768_check_encapsulation_key(ek, EK - 1) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    CHECK(zcl_mlkem768_check_decapsulation_key(NULL, DK) ==
          ZCL_MLKEM_ERR_ARGUMENT);
    CHECK(zcl_mlkem768_check_decapsulation_key(dk, DK + 1) ==
          ZCL_MLKEM_ERR_ARGUMENT);

    CHECK(zcl_mlkem768_check_decapsulation_key(dk, DK) == ZCL_MLKEM_OK);
    dk[1152 + 100] ^= 1;
    CHECK(zcl_mlkem768_check_decapsulation_key(dk, DK) ==
          ZCL_MLKEM_ERR_DK_INVALID);
    memset(ss, 0xA5, SS);
    CHECK(zcl_mlkem768_decaps(dk, DK, ek, CT, ss) == ZCL_MLKEM_ERR_DK_INVALID &&
          all_equal(ss, SS, 0));
    printf("key checks: boundary, NULL and embedded-key hash\n");
    return 0;
}
#ifdef ZCL_TESTING
/* Fault injection: the nth matrix-entry sample fails. Each of keygen,
 * encryption and decapsulation re-encryption samples 9 entries (3 rows of 3),
 * so n = 1 is the first row, 4 a middle row and 7 and 9 the last row. The
 * core and the inner key generation are observed before any public wrapper
 * zeroes its outputs; buffers hold a sentinel and must stay untouched. Every
 * failing n is reported, not just the first. */
static const unsigned fault_calls[] = {1, 4, 7, 9};
#define FAULT_CASES (sizeof(fault_calls) / sizeof(fault_calls[0]))

static int check_fault_positive(const uint8_t *fdk, const uint8_t *fct,
                                const uint8_t *fk)
{
    uint8_t out[SS];
    /* Disarmed: the core succeeds and yields the encapsulated secret. */
    mlkem_test_fault_arm(0);
    memset(out, 0xA5, SS);
    CHECK(mlkem_test_decaps_core(fdk, fct, out));
    CHECK(memcmp(out, fk, SS) == 0);
    CHECK(mlkem_test_fault_fired() == 0);
    /* Armed past the 9 samples a re-encryption takes: never fires, so the
     * countdown really counts sampler calls (9 exactly). */
    mlkem_test_fault_arm(10);
    CHECK(mlkem_test_decaps_core(fdk, fct, out));
    CHECK(mlkem_test_fault_fired() == 0);
    mlkem_test_fault_arm(0);
    return 0;
}

static int fault_decaps_at(unsigned n, const uint8_t *fdk, const uint8_t *fct)
{
    uint8_t out[SS];
    memset(out, 0xA5, SS);
    mlkem_test_fault_arm(n);
    CHECK(!mlkem_test_decaps_core(fdk, fct, out));
    CHECK(mlkem_test_fault_fired() == 1);
    CHECK(all_equal(out, SS, 0xA5));
    /* Public wrapper: sampling error and a zeroed output. */
    memset(out, 0xA5, SS);
    mlkem_test_fault_arm(n);
    CHECK(zcl_mlkem768_decaps(fdk, DK, fct, CT, out) == ZCL_MLKEM_ERR_SAMPLING);
    CHECK(mlkem_test_fault_fired() == 1);
    CHECK(all_equal(out, SS, 0));
    mlkem_test_fault_arm(0);
    return 0;
}

static int fault_keygen_at(unsigned n, const uint8_t *seed)
{
    uint8_t pke_ek[MLKEM_PKE_EK_BYTES], pke_dk[MLKEM_POLYVEC_BYTES];
    uint8_t kek[EK], kdk[DK];
    memset(pke_ek, 0xA5, sizeof(pke_ek));
    memset(pke_dk, 0xA5, sizeof(pke_dk));
    mlkem_test_fault_arm(n);
    CHECK(!mlkem_kpke_keygen(seed, pke_ek, pke_dk));
    CHECK(mlkem_test_fault_fired() == 1);
    CHECK(all_equal(pke_dk, sizeof(pke_dk), 0xA5));
    CHECK(all_equal(pke_ek + MLKEM_POLYVEC_BYTES, 32, 0xA5));
    memset(kek, 0xA5, EK);
    memset(kdk, 0xA5, DK);
    mlkem_test_fault_arm(n);
    CHECK(zcl_mlkem768_keygen_internal(seed, kek, kdk) ==
          ZCL_MLKEM_ERR_SAMPLING);
    CHECK(mlkem_test_fault_fired() == 1);
    CHECK(all_equal(kek, EK, 0) && all_equal(kdk, DK, 0));
    mlkem_test_fault_arm(0);
    return 0;
}

static int fault_encrypt_at(unsigned n, const uint8_t *fek, const uint8_t *m)
{
    uint8_t c[MLKEM_CT_BYTES], r[32] = {1};
    uint8_t pub_ct[CT], pub_ss[SS];
    memset(c, 0xA5, sizeof(c));
    mlkem_test_fault_arm(n);
    CHECK(!mlkem_kpke_encrypt(fek, m, r, c));
    CHECK(mlkem_test_fault_fired() == 1);
    /* The v component (c2) is never computed after a failed sample. */
    CHECK(all_equal(c + MLKEM_C1_BYTES, MLKEM_CT_BYTES - MLKEM_C1_BYTES, 0xA5));
    memset(pub_ct, 0xA5, CT);
    memset(pub_ss, 0xA5, SS);
    mlkem_test_fault_arm(n);
    CHECK(zcl_mlkem768_encaps_internal(fek, EK, m, pub_ct, pub_ss) ==
          ZCL_MLKEM_ERR_SAMPLING);
    CHECK(mlkem_test_fault_fired() == 1);
    CHECK(all_equal(pub_ct, CT, 0) && all_equal(pub_ss, SS, 0));
    mlkem_test_fault_arm(0);
    return 0;
}

static int check_fault_injection(void)
{
    uint8_t seed[64], m[32], fek[EK], fdk[DK], fct[CT], fk[SS];
    int bad = 0;
    prng_state = 99;
    prng_bytes(seed, sizeof(seed));
    prng_bytes(m, sizeof(m));
    CHECK(zcl_mlkem768_keygen_internal(seed, fek, fdk) == ZCL_MLKEM_OK);
    CHECK(zcl_mlkem768_encaps_internal(fek, EK, m, fct, fk) == ZCL_MLKEM_OK);
    bad |= check_fault_positive(fdk, fct, fk);
    for (size_t i = 0; i < FAULT_CASES; i++) {
        bad |= fault_decaps_at(fault_calls[i], fdk, fct);
        bad |= fault_keygen_at(fault_calls[i], seed);
        bad |= fault_encrypt_at(fault_calls[i], fek, m);
    }
    mlkem_test_fault_arm(0);
    if (bad)
        return 1;
    /* The seam is disarmed again: the public API still round-trips. */
    CHECK(zcl_mlkem768_decaps(fdk, DK, fct, CT, fk) == ZCL_MLKEM_OK);
    printf("fault injection: failed samples leave caller buffers untouched\n");
    return 0;
}
#endif

int main(void)
{
    prng_state = 42;
    if (check_reductions() || check_compression() || check_ntt_product() ||
        check_codec() || check_vectors() || check_round_trips() ||
        check_public_api() || check_bit_flips() || check_validation() ||
        check_failure_zeroing() || check_key_checks())
        return 1;
#ifdef ZCL_TESTING
    if (check_fault_injection())
        return 1;
#else
    printf("fault injection: skipped (ZCL_TESTING not defined)\n");
#endif
    printf("mlkem test passed\n");
    return 0;
}
