/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: known-answer-test-only ML-KEM-768 internal algorithms. */
#ifndef ZCL_MLKEM_MLKEM_KAT_H
#define ZCL_MLKEM_MLKEM_KAT_H

/* ML-KEM-768 internal algorithms for known-answer testing only.
 *
 * FIPS 203 restricts ML-KEM.KeyGen_internal and
 * ML-KEM.Encaps_internal to testing: they take caller-chosen randomness, and
 * a key or ciphertext produced from predictable or reused input is not
 * secure. Production code includes mlkem/mlkem.h and uses the randomized
 * entry points; it does not include this header.
 *
 * The buffer rules of mlkem/mlkem.h apply: outputs must not overlap each
 * other or any input. */

#include "mlkem/mlkem.h"

/* ML-KEM.KeyGen_internal (Algorithm 16): seed is d || z. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_keygen_internal(
    const uint8_t seed[ZCL_MLKEM768_KEYGEN_SEED_SIZE],
    uint8_t ek[ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE],
    uint8_t dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE]);

/* ML-KEM.Encaps_internal (Algorithm 17), including the Section 7.2 check. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_encaps_internal(
    const uint8_t *ek, size_t ek_len,
    const uint8_t m[ZCL_MLKEM768_ENCAPS_MESSAGE_SIZE],
    uint8_t ct[ZCL_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t ss[ZCL_MLKEM768_SHARED_SECRET_SIZE]);

#endif /* ZCL_MLKEM_MLKEM_KAT_H */
