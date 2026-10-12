/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: matrix and noise polynomial sampling for ML-KEM (FIPS 203 Section 4.2.2). */

/* Sampling of matrix entries and noise polynomials (FIPS 203 Section 4.2.2). */

#include "mlkem_internal.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

/* SHAKE128 output requested per attempt: five blocks, then twenty blocks.
 * The first suffices with probability above 1 - 2^-100; the second leaves a
 * failure probability far below 2^-1000. */
enum { XOF_FIRST_BYTES = 840, XOF_RETRY_BYTES = 3360 };

#ifdef ZCL_TESTING
/* Test-only fault seam; see mlkem_internal.h. Absent from release builds. */
static unsigned fault_countdown;
static unsigned fault_fired;

void mlkem_test_fault_arm(unsigned nth_sample_ntt)
{
    fault_countdown = nth_sample_ntt;
    fault_fired = 0;
}

unsigned mlkem_test_fault_fired(void)
{
    return fault_fired;
}

static bool fault_hit(void)
{
    if (fault_countdown == 0 || --fault_countdown != 0)
        return false;
    fault_fired++;
    return true;
}
#endif

/* Parses 3-byte groups into coefficients below q (FIPS 203 Algorithm 7,
 * lines 5-15). The bytes derive from public data only. */
static bool parse_candidates(struct mlkem_poly *p, const uint8_t *buf,
                             size_t len)
{
    unsigned count = 0;
    for (size_t pos = 0; pos + 3 <= len && count < MLKEM_N; pos += 3) {
        const unsigned d1 = buf[pos] | ((unsigned)(buf[pos + 1] & 0x0f) << 8);
        const unsigned d2 = (buf[pos + 1] >> 4) | ((unsigned)buf[pos + 2] << 4);
        if (d1 < MLKEM_Q)
            p->c[count++] = (int16_t)d1;
        if (d2 < MLKEM_Q && count < MLKEM_N)
            p->c[count++] = (int16_t)d2;
    }
    return count == MLKEM_N;
}

/* FIPS 203 Algorithm 7, SampleNTT, over the XOF stream SHAKE128(rho || b0 ||
 * b1). Returns false only if the stream was exhausted. */
bool mlkem_sample_ntt(struct mlkem_poly *p, const uint8_t rho[32],
                      uint8_t b0, uint8_t b1)
{
    uint8_t seed[34];
    uint8_t buf[XOF_RETRY_BYTES];
#ifdef ZCL_TESTING
    if (fault_hit())
        return false;
#endif
    memcpy(seed, rho, 32);
    seed[32] = b0;
    seed[33] = b1;
    bool ok = zcl_shake128(seed, sizeof(seed), buf, XOF_FIRST_BYTES) &&
              parse_candidates(p, buf, XOF_FIRST_BYTES);
    if (!ok)
        ok = zcl_shake128(seed, sizeof(seed), buf, XOF_RETRY_BYTES) &&
             parse_candidates(p, buf, XOF_RETRY_BYTES);
    return ok;
}

/* FIPS 203 Algorithm 8, SamplePolyCBD with eta = 2, applied to
 * PRF_2(sigma, nonce) = SHAKE256(sigma || nonce, 128). Secret-dependent
 * bytes are processed with arithmetic only and wiped afterwards. Returns false,
 * leaving p untouched, if the XOF fails. */
bool mlkem_sample_cbd(struct mlkem_poly *p, const uint8_t sigma[32],
                      uint8_t nonce)
{
    uint8_t seed[33];
    uint8_t buf[128];
    memcpy(seed, sigma, 32);
    seed[32] = nonce;
    if (!zcl_shake256(seed, sizeof(seed), buf, sizeof(buf))) {
        memory_cleanse(seed, sizeof(seed));
        memory_cleanse(buf, sizeof(buf));
        return false;
    }
    for (unsigned i = 0; i < MLKEM_N / 8; i++) {
        const uint32_t t = zcl_read_u32_le(buf + 4 * i);
        const uint32_t s = (t & 0x55555555u) + ((t >> 1) & 0x55555555u);
        for (unsigned j = 0; j < 8; j++) {
            const int a = (int)((s >> (4 * j)) & 3u);
            const int b = (int)((s >> (4 * j + 2)) & 3u);
            p->c[8 * i + j] = (int16_t)(a - b);
        }
    }
    memory_cleanse(seed, sizeof(seed));
    memory_cleanse(buf, sizeof(buf));
    return true;
}
