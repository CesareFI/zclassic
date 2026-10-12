/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ML-KEM-768 key generation, encapsulation and decapsulation (FIPS 203). */

/* ML-KEM-768 key encapsulation (FIPS 203 Sections 6 and 7). */

#include "mlkem/mlkem.h"
#include "mlkem/mlkem_kat.h"
#include "mlkem_internal.h"

#include "base/cleanse.h"
#include "sha3/sha3.h"

#include <string.h>

enum {
    EK = ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE,
    DK = ZCL_MLKEM768_DECAPSULATION_KEY_SIZE,
    CT = ZCL_MLKEM768_CIPHERTEXT_SIZE,
    SS = ZCL_MLKEM768_SHARED_SECRET_SIZE,
    DK_EK_OFFSET = MLKEM_POLYVEC_BYTES,       /* 1152 */
    DK_H_OFFSET = DK_EK_OFFSET + EK,          /* 2336 */
    DK_Z_OFFSET = DK_H_OFFSET + 32            /* 2368 */
};

static_assert((int)MLKEM_PKE_EK_BYTES == (int)EK, "encapsulation key size");
static_assert((int)MLKEM_CT_BYTES == (int)CT, "ciphertext size");
static_assert(DK_Z_OFFSET + 32 == DK, "decapsulation key size");

/* Returns 0xff if a and b differ and 0 if they are equal, in time that
 * depends only on len. */
static uint8_t ct_differs(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint32_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= (uint32_t)(a[i] ^ b[i]);
    const volatile uint32_t folded = acc;
    return (uint8_t)(0u - (((folded | (0u - folded)) >> 31)));
}

/* out = mask ? b : a, byte-wise, without branching on mask. */
static void ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b,
                      size_t len, uint8_t mask)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(a[i] ^ (mask & (a[i] ^ b[i])));
}

static void zero_outputs(uint8_t *ct, uint8_t *ss)
{
    if (ct)
        memory_cleanse(ct, CT);
    if (ss)
        memory_cleanse(ss, SS);
}

static void zero_keys(uint8_t *ek, uint8_t *dk)
{
    if (ek)
        memory_cleanse(ek, EK);
    if (dk)
        memory_cleanse(dk, DK);
}

/* FIPS 203 Section 7.2: every 12-bit field must be below q, which is
 * ByteEncode_12(ByteDecode_12(ek)) == ek. The key is public. */
enum zcl_mlkem_status zcl_mlkem768_check_encapsulation_key(
    const uint8_t *ek, size_t ek_len)
{
    if (!ek || ek_len != EK)
        return ZCL_MLKEM_ERR_ARGUMENT;
    for (size_t i = 0; i < MLKEM_POLYVEC_BYTES; i += 3) {
        const unsigned a = ek[i] | ((unsigned)(ek[i + 1] & 0x0f) << 8);
        const unsigned b = (ek[i + 1] >> 4) | ((unsigned)ek[i + 2] << 4);
        if (a >= MLKEM_Q || b >= MLKEM_Q)
            return ZCL_MLKEM_ERR_EK_INVALID;
    }
    return ZCL_MLKEM_OK;
}

/* FIPS 203 Section 7.3: H(dk[384k : 768k + 32]) must equal the stored hash. */
enum zcl_mlkem_status zcl_mlkem768_check_decapsulation_key(
    const uint8_t *dk, size_t dk_len)
{
    uint8_t h[SHA3_256_OUTPUT_SIZE];
    if (!dk || dk_len != DK)
        return ZCL_MLKEM_ERR_ARGUMENT;
    sha3_256(dk + DK_EK_OFFSET, EK, h);
    return ct_differs(h, dk + DK_H_OFFSET, sizeof(h)) ? ZCL_MLKEM_ERR_DK_INVALID
                                                      : ZCL_MLKEM_OK;
}

/* FIPS 203 Algorithm 16, ML-KEM.KeyGen_internal. */
enum zcl_mlkem_status zcl_mlkem768_keygen_internal(
    const uint8_t seed[ZCL_MLKEM768_KEYGEN_SEED_SIZE],
    uint8_t ek[EK], uint8_t dk[DK])
{
    if (!seed || !ek || !dk) {
        zero_keys(ek, dk);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    if (!mlkem_kpke_keygen(seed, ek, dk)) {
        zero_keys(ek, dk);
        return ZCL_MLKEM_ERR_SAMPLING;
    }
    memcpy(dk + DK_EK_OFFSET, ek, EK);
    sha3_256(ek, EK, dk + DK_H_OFFSET);
    memcpy(dk + DK_Z_OFFSET, seed + 32, 32);
    return ZCL_MLKEM_OK;
}

/* FIPS 203 Algorithm 19, ML-KEM.KeyGen. */
enum zcl_mlkem_status zcl_mlkem768_keygen(
    zcl_mlkem_random_fn random, void *random_context,
    uint8_t ek[EK], uint8_t dk[DK])
{
    uint8_t seed[ZCL_MLKEM768_KEYGEN_SEED_SIZE];
    if (!random || !ek || !dk) {
        zero_keys(ek, dk);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    if (!random(random_context, seed, sizeof(seed))) {
        memory_cleanse(seed, sizeof(seed));
        zero_keys(ek, dk);
        return ZCL_MLKEM_ERR_RANDOM;
    }
    const enum zcl_mlkem_status st = zcl_mlkem768_keygen_internal(seed, ek, dk);
    memory_cleanse(seed, sizeof(seed));
    return st;
}

/* FIPS 203 Algorithm 17, ML-KEM.Encaps_internal. */
enum zcl_mlkem_status zcl_mlkem768_encaps_internal(
    const uint8_t *ek, size_t ek_len, const uint8_t m[32],
    uint8_t ct[CT], uint8_t ss[SS])
{
    uint8_t g_in[64], g_out[SHA3_512_OUTPUT_SIZE];
    if (!ek || !m || !ct || !ss) {
        zero_outputs(ct, ss);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    const enum zcl_mlkem_status st =
        zcl_mlkem768_check_encapsulation_key(ek, ek_len);
    if (st != ZCL_MLKEM_OK) {
        zero_outputs(ct, ss);
        return st;
    }
    memcpy(g_in, m, 32);
    sha3_256(ek, EK, g_in + 32);
    sha3_512(g_in, sizeof(g_in), g_out);
    const bool ok = mlkem_kpke_encrypt(ek, m, g_out + 32, ct);
    if (ok)
        memcpy(ss, g_out, SS);
    else
        zero_outputs(ct, ss);
    memory_cleanse(g_in, sizeof(g_in));
    memory_cleanse(g_out, sizeof(g_out));
    return ok ? ZCL_MLKEM_OK : ZCL_MLKEM_ERR_SAMPLING;
}

/* FIPS 203 Algorithm 20, ML-KEM.Encaps. */
enum zcl_mlkem_status zcl_mlkem768_encaps(
    zcl_mlkem_random_fn random, void *random_context,
    const uint8_t *ek, size_t ek_len, uint8_t ct[CT], uint8_t ss[SS])
{
    uint8_t m[ZCL_MLKEM768_ENCAPS_MESSAGE_SIZE];
    if (!random || !ek || !ct || !ss) {
        zero_outputs(ct, ss);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    if (!random(random_context, m, sizeof(m))) {
        memory_cleanse(m, sizeof(m));
        zero_outputs(ct, ss);
        return ZCL_MLKEM_ERR_RANDOM;
    }
    const enum zcl_mlkem_status st =
        zcl_mlkem768_encaps_internal(ek, ek_len, m, ct, ss);
    memory_cleanse(m, sizeof(m));
    return st;
}

/* FIPS 203 Algorithm 18 with the Section 7.3 checks: re-encryption and
 * implicit rejection. The comparison and the selection between K' and the
 * rejection secret are branch-free. */
static bool decaps_core(const uint8_t *dk, const uint8_t *ct, uint8_t *ss)
{
    uint8_t m[32], g_in[64], g_out[SHA3_512_OUTPUT_SIZE];
    uint8_t j_in[32 + CT], j_out[SS], c2[CT] = {0};

    mlkem_kpke_decrypt(dk, ct, m);
    memcpy(g_in, m, 32);
    memcpy(g_in + 32, dk + DK_H_OFFSET, 32);
    sha3_512(g_in, sizeof(g_in), g_out);
    memcpy(j_in, dk + DK_Z_OFFSET, 32);
    memcpy(j_in + 32, ct, CT);
    const bool ok = zcl_shake256(j_in, sizeof(j_in), j_out, sizeof(j_out)) &&
                    mlkem_kpke_encrypt(dk + DK_EK_OFFSET, m, g_out + 32, c2);
    /* ok is false only if the XOF failed or sampling over the public seed rho
     * failed, so this branch depends on public data. On failure ss is left
     * untouched: neither K' nor the rejection secret reaches the caller. */
    if (ok)
        ct_select(ss, g_out, j_out, SS, ct_differs(ct, c2, CT));

    memory_cleanse(m, sizeof(m));
    memory_cleanse(g_in, sizeof(g_in));
    memory_cleanse(g_out, sizeof(g_out));
    memory_cleanse(j_in, sizeof(j_in));
    memory_cleanse(j_out, sizeof(j_out));
    memory_cleanse(c2, sizeof(c2));
    return ok;
}

#ifdef ZCL_TESTING
bool mlkem_test_decaps_core(const uint8_t *dk, const uint8_t *ct, uint8_t *ss)
{
    return decaps_core(dk, ct, ss);
}
#endif

/* FIPS 203 Algorithm 21, ML-KEM.Decaps. */
enum zcl_mlkem_status zcl_mlkem768_decaps(
    const uint8_t *dk, size_t dk_len, const uint8_t *ct, size_t ct_len,
    uint8_t ss[SS])
{
    if (!dk || !ct || !ss) {
        zero_outputs(NULL, ss);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    if (dk_len != DK || ct_len != CT) {
        zero_outputs(NULL, ss);
        return ZCL_MLKEM_ERR_ARGUMENT;
    }
    const enum zcl_mlkem_status st =
        zcl_mlkem768_check_decapsulation_key(dk, dk_len);
    if (st != ZCL_MLKEM_OK) {
        zero_outputs(NULL, ss);
        return st;
    }
    if (!decaps_core(dk, ct, ss)) {
        zero_outputs(NULL, ss);
        return ZCL_MLKEM_ERR_SAMPLING;
    }
    return ZCL_MLKEM_OK;
}
