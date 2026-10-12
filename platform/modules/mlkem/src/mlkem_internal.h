/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private ML-KEM-768 parameters and routines shared by the module sources. */
#ifndef ZCL_MLKEM_INTERNAL_H
#define ZCL_MLKEM_INTERNAL_H

/* Private interface shared by the ML-KEM source files and the module tests.
 * Parameters are those of ML-KEM-768 (FIPS 203 Table 2). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    MLKEM_N = 256,
    MLKEM_Q = 3329,
    MLKEM_K = 3,
    MLKEM_DU = 10,
    MLKEM_DV = 4,
    MLKEM_POLY_BYTES = 384,                           /* 32 * 12 */
    MLKEM_POLYVEC_BYTES = MLKEM_K * MLKEM_POLY_BYTES, /* 1152 */
    MLKEM_PKE_EK_BYTES = MLKEM_POLYVEC_BYTES + 32,    /* 1184 */
    MLKEM_C1_BYTES = MLKEM_K * 32 * MLKEM_DU,         /* 960 */
    MLKEM_CT_BYTES = MLKEM_C1_BYTES + 32 * MLKEM_DV   /* 1088 */
};

struct mlkem_poly {
    int16_t c[MLKEM_N];
};

/* Modular arithmetic (poly.c). */
int16_t mlkem_montgomery_reduce(int32_t a);
int16_t mlkem_barrett_reduce(int16_t a);
uint16_t mlkem_canonical(int16_t a);

/* Number-theoretic transform (poly.c), FIPS 203 Algorithms 9-12. */
void mlkem_ntt(struct mlkem_poly *p);
void mlkem_invntt(struct mlkem_poly *p);
void mlkem_basemul_acc(struct mlkem_poly *r, const struct mlkem_poly *a,
                       const struct mlkem_poly *b);

/* Coefficient-wise helpers (poly.c). */
void mlkem_poly_tomont(struct mlkem_poly *p);
void mlkem_poly_add(struct mlkem_poly *r, const struct mlkem_poly *a);
void mlkem_poly_sub(struct mlkem_poly *r, const struct mlkem_poly *a);
void mlkem_poly_canonical(struct mlkem_poly *p);

/* Compression (FIPS 203 Section 4.2.1) and byte coding (Algorithms 5, 6). */
uint16_t mlkem_compress(uint16_t x, unsigned d);
uint16_t mlkem_decompress(uint16_t y, unsigned d);
void mlkem_poly_compress(struct mlkem_poly *p, unsigned d);
void mlkem_poly_decompress(struct mlkem_poly *p, unsigned d);
void mlkem_poly_encode(const struct mlkem_poly *p, unsigned d, uint8_t *out);
void mlkem_poly_decode(struct mlkem_poly *p, unsigned d, const uint8_t *in);
void mlkem_poly_reduce12(struct mlkem_poly *p);

/* Sampling (sample.c), FIPS 203 Algorithms 7 and 8. */
bool mlkem_sample_ntt(struct mlkem_poly *p, const uint8_t rho[32],
                      uint8_t b0, uint8_t b1);
bool mlkem_sample_cbd(struct mlkem_poly *p, const uint8_t sigma[32],
                      uint8_t nonce);

/* K-PKE (kpke.c), FIPS 203 Algorithms 13-15. */
bool mlkem_kpke_keygen(const uint8_t d[32], uint8_t ek_pke[MLKEM_PKE_EK_BYTES],
                       uint8_t dk_pke[MLKEM_POLYVEC_BYTES]);
bool mlkem_kpke_encrypt(const uint8_t ek_pke[MLKEM_PKE_EK_BYTES],
                        const uint8_t m[32], const uint8_t r[32],
                        uint8_t c[MLKEM_CT_BYTES]);
void mlkem_kpke_decrypt(const uint8_t dk_pke[MLKEM_POLYVEC_BYTES],
                        const uint8_t c[MLKEM_CT_BYTES], uint8_t m[32]);

#ifdef ZCL_TESTING
/* Test-only fault seam (compiled out of release builds): the nth call (1-based)
 * to mlkem_sample_ntt after arming fails once; arming with 0 disarms. The
 * fired counter counts injected failures since the last arming. */
void mlkem_test_fault_arm(unsigned nth_sample_ntt);
unsigned mlkem_test_fault_fired(void);
/* The internal decapsulation core, so a test can observe ss before the public
 * wrapper zeroes it. */
bool mlkem_test_decaps_core(const uint8_t *dk, const uint8_t *ct, uint8_t *ss);
#endif

#endif /* ZCL_MLKEM_INTERNAL_H */
