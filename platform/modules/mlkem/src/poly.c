/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: constant-time polynomial arithmetic over Z_3329[X]/(X^256+1) for ML-KEM. */

/* Polynomial arithmetic over R_q = Z_q[X]/(X^256 + 1), q = 3329, for ML-KEM
 * (FIPS 203 Section 4). Every routine has data-independent control flow and
 * memory access; division by q is replaced by fixed multiplications. */

#include "mlkem_internal.h"

#include "base/cleanse.h"

static_assert((-1 >> 1) == -1, "arithmetic right shift of negative int");
static_assert((MLKEM_Q * 62209u & 0xffffu) == 1u, "62209 = q^-1 mod 2^16");

/* 17^BitRev7(i) * 2^16 mod q, centered: the Algorithm 9 zeta table in
 * Montgomery form. */
static const int16_t zetas[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
};

/* Montgomery reduction with R = 2^16: returns a * R^-1 mod q in (-q, q) for
 * |a| < 2^15 * q. */
int16_t mlkem_montgomery_reduce(int32_t a)
{
    const uint32_t u = ((uint32_t)a * 62209u) & 0xffffu;
    const int32_t t = (int32_t)u - (int32_t)((u >> 15) << 16);
    return (int16_t)((a - t * MLKEM_Q) >> 16);
}

/* Barrett reduction: a mod q in [-(q-1)/2, (q-1)/2] for any int16 a. */
int16_t mlkem_barrett_reduce(int16_t a)
{
    const int32_t t = (20159 * (int32_t)a + (1 << 25)) >> 26;
    return (int16_t)(a - t * MLKEM_Q);
}

/* a mod q in [0, q) for any int16 a, without a data-dependent branch. */
uint16_t mlkem_canonical(int16_t a)
{
    const int16_t b = mlkem_barrett_reduce(a);
    const int32_t neg = (int32_t)((uint16_t)b >> 15);
    return (uint16_t)(b + (MLKEM_Q & -neg));
}

static int16_t fqmul(int16_t a, int16_t b)
{
    return mlkem_montgomery_reduce((int32_t)a * b);
}

/* FIPS 203 Algorithm 9, NTT. Input coefficients must satisfy |c| <= q. The
 * output is Barrett-reduced. */
void mlkem_ntt(struct mlkem_poly *p)
{
    unsigned k = 1;
    for (unsigned len = 128; len >= 2; len >>= 1) {
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            const int16_t zeta = zetas[k++];
            for (unsigned j = start; j < start + len; j++) {
                const int16_t t = fqmul(zeta, p->c[j + len]);
                p->c[j + len] = (int16_t)(p->c[j] - t);
                p->c[j] = (int16_t)(p->c[j] + t);
            }
        }
    }
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = mlkem_barrett_reduce(p->c[i]);
}

/* FIPS 203 Algorithm 10, NTT^-1, including the 128^-1 scaling. The output
 * carries an extra factor R = 2^16 that cancels the R^-1 factor introduced
 * by mlkem_basemul_acc. */
void mlkem_invntt(struct mlkem_poly *p)
{
    unsigned k = 127;
    for (unsigned len = 2; len <= 128; len <<= 1) {
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            const int16_t zeta = zetas[k--];
            for (unsigned j = start; j < start + len; j++) {
                const int16_t t = p->c[j];
                p->c[j] = mlkem_barrett_reduce((int16_t)(t + p->c[j + len]));
                p->c[j + len] = fqmul(zeta, (int16_t)(p->c[j + len] - t));
            }
        }
    }
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = fqmul(p->c[i], 1441); /* 2^32 / 128 mod q */
}

/* FIPS 203 Algorithm 12, BaseCaseMultiply, with gamma = +-zeta. */
static void basemul_pair(int16_t r[2], const int16_t a[2], const int16_t b[2],
                         int16_t gamma)
{
    r[0] = (int16_t)(fqmul(fqmul(a[1], b[1]), gamma) + fqmul(a[0], b[0]));
    r[1] = (int16_t)(fqmul(a[0], b[1]) + fqmul(a[1], b[0]));
}

/* FIPS 203 Algorithm 11, MultiplyNTTs, accumulated: r += a * b in the NTT
 * domain. Each product carries a factor R^-1. Callers accumulate at most
 * MLKEM_K products into a zeroed r. */
void mlkem_basemul_acc(struct mlkem_poly *r, const struct mlkem_poly *a,
                       const struct mlkem_poly *b)
{
    int16_t t[2] = {0, 0};
    for (unsigned i = 0; i < MLKEM_N / 4; i++) {
        const int16_t zeta = zetas[64 + i];
        basemul_pair(t, &a->c[4 * i], &b->c[4 * i], zeta);
        r->c[4 * i] = (int16_t)(r->c[4 * i] + t[0]);
        r->c[4 * i + 1] = (int16_t)(r->c[4 * i + 1] + t[1]);
        basemul_pair(t, &a->c[4 * i + 2], &b->c[4 * i + 2], (int16_t)-zeta);
        r->c[4 * i + 2] = (int16_t)(r->c[4 * i + 2] + t[0]);
        r->c[4 * i + 3] = (int16_t)(r->c[4 * i + 3] + t[1]);
    }
    memory_cleanse(t, sizeof(t));
}

/* Multiplies by R = 2^16, undoing the R^-1 factor of mlkem_basemul_acc. */
void mlkem_poly_tomont(struct mlkem_poly *p)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = fqmul(p->c[i], 1353); /* 2^32 mod q */
}

void mlkem_poly_add(struct mlkem_poly *r, const struct mlkem_poly *a)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        r->c[i] = (int16_t)(r->c[i] + a->c[i]);
}

void mlkem_poly_sub(struct mlkem_poly *r, const struct mlkem_poly *a)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        r->c[i] = (int16_t)(r->c[i] - a->c[i]);
}

void mlkem_poly_canonical(struct mlkem_poly *p)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = (int16_t)mlkem_canonical(p->c[i]);
}

/* FIPS 203 Section 4.2.1, Compress_d for 0 <= x < q. The rounding quotient
 * floor((2^d * x + 1664) / q) is computed as a multiplication by
 * ceil(2^35 / q), exact for every numerator below 2^22, so no division
 * instruction touches the (possibly secret) coefficient. */
uint16_t mlkem_compress(uint16_t x, unsigned d)
{
    static const uint64_t magic = ((UINT64_C(1) << 35) + MLKEM_Q - 1) / MLKEM_Q;
    const uint64_t numerator = ((uint64_t)x << d) + (MLKEM_Q - 1) / 2;
    return (uint16_t)(((numerator * magic) >> 35) & ((1u << d) - 1u));
}

/* FIPS 203 Section 4.2.1, Decompress_d: round(q * y / 2^d) by shift. */
uint16_t mlkem_decompress(uint16_t y, unsigned d)
{
    return (uint16_t)(((uint32_t)y * MLKEM_Q + (1u << (d - 1))) >> d);
}

void mlkem_poly_compress(struct mlkem_poly *p, unsigned d)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = (int16_t)mlkem_compress((uint16_t)p->c[i], d);
}

void mlkem_poly_decompress(struct mlkem_poly *p, unsigned d)
{
    for (unsigned i = 0; i < MLKEM_N; i++)
        p->c[i] = (int16_t)mlkem_decompress((uint16_t)p->c[i], d);
}

/* FIPS 203 Algorithm 5, ByteEncode_d (1 <= d <= 12), little-endian bit order.
 * Writes 32 * d bytes. */
void mlkem_poly_encode(const struct mlkem_poly *p, unsigned d, uint8_t *out)
{
    uint32_t acc = 0;
    unsigned bits = 0;
    for (unsigned i = 0; i < MLKEM_N; i++) {
        acc |= (uint32_t)(uint16_t)p->c[i] << bits;
        bits += d;
        while (bits >= 8) {
            *out++ = (uint8_t)acc;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/* FIPS 203 Algorithm 6, ByteDecode_d without the modular reduction of the
 * d = 12 case; see mlkem_poly_reduce12. Reads 32 * d bytes. */
void mlkem_poly_decode(struct mlkem_poly *p, unsigned d, const uint8_t *in)
{
    uint32_t acc = 0;
    unsigned bits = 0;
    for (unsigned i = 0; i < MLKEM_N; i++) {
        while (bits < d) {
            acc |= (uint32_t)*in++ << bits;
            bits += 8;
        }
        p->c[i] = (int16_t)(acc & ((1u << d) - 1u));
        acc >>= d;
        bits -= d;
    }
}

/* The reduction mod q of ByteDecode_12: 12-bit values are below 2q, so one
 * masked subtraction suffices. */
void mlkem_poly_reduce12(struct mlkem_poly *p)
{
    for (unsigned i = 0; i < MLKEM_N; i++) {
        const int32_t diff = (int32_t)p->c[i] - MLKEM_Q;
        const int32_t neg = (int32_t)((uint32_t)diff >> 31);
        p->c[i] = (int16_t)(diff + (MLKEM_Q & -neg));
    }
}
