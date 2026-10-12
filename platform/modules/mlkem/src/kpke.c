/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: K-PKE encryption and decryption for ML-KEM-768 (FIPS 203 Algorithms 13-15). */

/* K-PKE, the public-key encryption component of ML-KEM (FIPS 203 Section
 * 5, Algorithms 13-15). Secret polynomials are wiped before return. */

#include "mlkem_internal.h"

#include "base/cleanse.h"
#include "sha3/sha3.h"

#include <string.h>

struct polyvec {
    struct mlkem_poly v[MLKEM_K];
};

static void polyvec_encode12(const struct polyvec *a, uint8_t *out)
{
    for (unsigned i = 0; i < MLKEM_K; i++)
        mlkem_poly_encode(&a->v[i], 12, out + i * MLKEM_POLY_BYTES);
}

static void polyvec_decode12(struct polyvec *a, const uint8_t *in)
{
    for (unsigned i = 0; i < MLKEM_K; i++) {
        mlkem_poly_decode(&a->v[i], 12, in + i * MLKEM_POLY_BYTES);
        mlkem_poly_reduce12(&a->v[i]);
    }
}

/* r = sum_j a[j] * b[j] in the NTT domain, Barrett-reduced; carries R^-1. */
static void polyvec_dot(struct mlkem_poly *r, const struct polyvec *a,
                        const struct polyvec *b)
{
    memset(r, 0, sizeof(*r));
    for (unsigned j = 0; j < MLKEM_K; j++)
        mlkem_basemul_acc(r, &a->v[j], &b->v[j]);
    for (unsigned i = 0; i < MLKEM_N; i++)
        r->c[i] = mlkem_barrett_reduce(r->c[i]);
}

/* Fills out with CBD noise polynomials for nonces first, first + 1, ...;
 * when ntt is set, each is transformed (Algorithm 9). Returns false if the
 * XOF fails; out is then incomplete and must not be used. */
static bool sample_noise(struct polyvec *out, const uint8_t seed[32],
                         uint8_t first, bool ntt)
{
    for (unsigned i = 0; i < MLKEM_K; i++) {
        if (!mlkem_sample_cbd(&out->v[i], seed, (uint8_t)(first + i)))
            return false;
        if (ntt)
            mlkem_ntt(&out->v[i]);
    }
    return true;
}

/* Row of A (or A^T): entry j is SampleNTT(rho || b0(j) || b1(j)). For
 * Algorithm 13 line 5 (A[i][j] from rho || j || i) pass transpose = false;
 * for Algorithm 14 line 4 (A^T[i][j] = A[j][i]) pass transpose = true. */
static bool sample_row(struct polyvec *row, const uint8_t rho[32],
                       unsigned i, bool transpose)
{
    for (unsigned j = 0; j < MLKEM_K; j++) {
        const uint8_t x = (uint8_t)(transpose ? i : j);
        const uint8_t y = (uint8_t)(transpose ? j : i);
        if (!mlkem_sample_ntt(&row->v[j], rho, x, y))
            return false;
    }
    return true;
}

/* FIPS 203 Algorithm 13, K-PKE.KeyGen. */
bool mlkem_kpke_keygen(const uint8_t d[32], uint8_t ek_pke[MLKEM_PKE_EK_BYTES],
                       uint8_t dk_pke[MLKEM_POLYVEC_BYTES])
{
    uint8_t g_in[33], g_out[SHA3_512_OUTPUT_SIZE];
    struct polyvec s, e, row;
    struct mlkem_poly t;
    memcpy(g_in, d, 32);
    g_in[32] = MLKEM_K;
    sha3_512(g_in, sizeof(g_in), g_out);
    bool ok = sample_noise(&s, g_out + 32, 0, true) &&
              sample_noise(&e, g_out + 32, MLKEM_K, true);
    for (unsigned i = 0; ok && i < MLKEM_K; i++) {
        ok = sample_row(&row, g_out, i, false);
        if (!ok)
            break;
        polyvec_dot(&t, &row, &s);
        mlkem_poly_tomont(&t);
        mlkem_poly_add(&t, &e.v[i]);
        mlkem_poly_canonical(&t);
        mlkem_poly_encode(&t, 12, ek_pke + i * MLKEM_POLY_BYTES);
    }
    /* After a failed sample neither the secret vector nor the seed is written
     * to the caller's buffers. Rows of t encoded before a later-row failure
     * are public key material; the public wrapper zeroes both buffers anyway. */
    if (ok) {
        for (unsigned i = 0; i < MLKEM_K; i++)
            mlkem_poly_canonical(&s.v[i]);
        polyvec_encode12(&s, dk_pke);
        memcpy(ek_pke + MLKEM_POLYVEC_BYTES, g_out, 32);
    }

    memory_cleanse(g_in, sizeof(g_in));
    memory_cleanse(g_out, sizeof(g_out));
    memory_cleanse(&s, sizeof(s));
    memory_cleanse(&e, sizeof(e));
    memory_cleanse(&t, sizeof(t));
    return ok;
}

/* c1 component: u[i] = NTT^-1(A^T[i] . y) + e1[i], compressed to du bits
 * (Algorithm 14 lines 19-22). */
static bool encrypt_u(uint8_t *c1, const uint8_t rho[32],
                      const struct polyvec *y, const uint8_t r[32])
{
    struct polyvec row;
    struct mlkem_poly u, e1;
    bool ok = true;
    for (unsigned i = 0; i < MLKEM_K; i++) {
        ok = sample_row(&row, rho, i, true);
        if (!ok)
            break;
        polyvec_dot(&u, &row, y);
        mlkem_invntt(&u);
        ok = mlkem_sample_cbd(&e1, r, (uint8_t)(MLKEM_K + i));
        if (!ok)
            break;
        mlkem_poly_add(&u, &e1);
        mlkem_poly_canonical(&u);
        mlkem_poly_compress(&u, MLKEM_DU);
        mlkem_poly_encode(&u, MLKEM_DU, c1 + i * 32 * MLKEM_DU);
    }
    memory_cleanse(&u, sizeof(u));
    memory_cleanse(&e1, sizeof(e1));
    return ok;
}

/* c2 component: v = NTT^-1(t . y) + e2 + Decompress_1(m), compressed to dv
 * bits (Algorithm 14 lines 21-23). */
static bool encrypt_v(uint8_t *c2, const struct polyvec *t,
                      const struct polyvec *y, const uint8_t m[32],
                      const uint8_t r[32])
{
    struct mlkem_poly v, e2, mu;
    polyvec_dot(&v, t, y);
    mlkem_invntt(&v);
    const bool ok = mlkem_sample_cbd(&e2, r, 2 * MLKEM_K);
    if (ok) {
        mlkem_poly_add(&v, &e2);
        mlkem_poly_decode(&mu, 1, m);
        mlkem_poly_decompress(&mu, 1);
        mlkem_poly_add(&v, &mu);
        mlkem_poly_canonical(&v);
        mlkem_poly_compress(&v, MLKEM_DV);
        mlkem_poly_encode(&v, MLKEM_DV, c2);
    }
    memory_cleanse(&e2, sizeof(e2));
    memory_cleanse(&mu, sizeof(mu));
    memory_cleanse(&v, sizeof(v));
    return ok;
}

/* FIPS 203 Algorithm 14, K-PKE.Encrypt. */
bool mlkem_kpke_encrypt(const uint8_t ek_pke[MLKEM_PKE_EK_BYTES],
                        const uint8_t m[32], const uint8_t r[32],
                        uint8_t c[MLKEM_CT_BYTES])
{
    struct polyvec t, y;
    polyvec_decode12(&t, ek_pke);
    bool ok = sample_noise(&y, r, 0, true) &&
              encrypt_u(c, ek_pke + MLKEM_POLYVEC_BYTES, &y, r) &&
              encrypt_v(c + MLKEM_C1_BYTES, &t, &y, m, r);
    memory_cleanse(&y, sizeof(y));
    return ok;
}

/* FIPS 203 Algorithm 15, K-PKE.Decrypt. */
void mlkem_kpke_decrypt(const uint8_t dk_pke[MLKEM_POLYVEC_BYTES],
                        const uint8_t c[MLKEM_CT_BYTES], uint8_t m[32])
{
    struct polyvec s, u;
    struct mlkem_poly v, w;

    for (unsigned i = 0; i < MLKEM_K; i++) {
        mlkem_poly_decode(&u.v[i], MLKEM_DU, c + i * 32 * MLKEM_DU);
        mlkem_poly_decompress(&u.v[i], MLKEM_DU);
        mlkem_ntt(&u.v[i]);
    }
    mlkem_poly_decode(&v, MLKEM_DV, c + MLKEM_C1_BYTES);
    mlkem_poly_decompress(&v, MLKEM_DV);
    polyvec_decode12(&s, dk_pke);
    polyvec_dot(&w, &s, &u);
    mlkem_invntt(&w);
    mlkem_poly_sub(&v, &w);
    mlkem_poly_canonical(&v);
    mlkem_poly_compress(&v, 1);
    mlkem_poly_encode(&v, 1, m);

    memory_cleanse(&s, sizeof(s));
    memory_cleanse(&w, sizeof(w));
    memory_cleanse(&v, sizeof(v));
}
