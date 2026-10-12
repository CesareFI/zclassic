/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: public ML-KEM-768 key-encapsulation interface (FIPS 203). */
#ifndef ZCL_MLKEM_MLKEM_H
#define ZCL_MLKEM_MLKEM_H

/* ML-KEM-768 key-encapsulation mechanism, NIST FIPS 203 (August 2024).
 *
 * Randomness: this module never reads an operating-system generator. The
 * randomized entry points take a callback, and the caller must supply
 * cryptographically secure random bytes through it. The deterministic
 * internal algorithms (FIPS 203 Algorithms 16 and 17) are declared in
 * mlkem/mlkem_kat.h for known-answer testing only.
 *
 * Inputs of variable length are length-checked (FIPS 203 Sections 7.1-7.3).
 * On any failure every non-NULL output buffer is zeroed before return.
 * Output buffers (ek and dk of keygen, ct, ss) must not overlap each other or
 * any input buffer (ek, dk, ct). The caller owns the
 * decapsulation key and must wipe it (base/cleanse.h) when it is no longer
 * needed. Secret-dependent operations run in constant time; see README.md. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE = 1184,
    ZCL_MLKEM768_DECAPSULATION_KEY_SIZE = 2400,
    ZCL_MLKEM768_CIPHERTEXT_SIZE = 1088,
    ZCL_MLKEM768_SHARED_SECRET_SIZE = 32,
    ZCL_MLKEM768_KEYGEN_SEED_SIZE = 64,    /* d || z */
    ZCL_MLKEM768_ENCAPS_MESSAGE_SIZE = 32  /* m */
};

enum zcl_mlkem_status {
    ZCL_MLKEM_OK = 0,
    ZCL_MLKEM_ERR_ARGUMENT,    /* NULL pointer or wrong length */
    ZCL_MLKEM_ERR_RANDOM,      /* the random callback reported failure */
    ZCL_MLKEM_ERR_EK_INVALID,  /* encapsulation key fails the modulus check */
    ZCL_MLKEM_ERR_DK_INVALID,  /* decapsulation key fails the hash check */
    ZCL_MLKEM_ERR_SAMPLING     /* matrix-sampling stream exhausted; the
                                  probability is below 2^-1000 */
};

/* Fills out[0..len) with cryptographically secure random bytes and returns
 * true, or returns false on failure. */
typedef bool (*zcl_mlkem_random_fn)(void *context, uint8_t *out, size_t len);

/* FIPS 203 Section 7.2: type and modulus check of an encapsulation key. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_check_encapsulation_key(
    const uint8_t *ek, size_t ek_len);

/* FIPS 203 Section 7.3: type and hash check of a decapsulation key. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_check_decapsulation_key(
    const uint8_t *dk, size_t dk_len);

/* ML-KEM.KeyGen (Algorithm 19). */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_keygen(
    zcl_mlkem_random_fn random, void *random_context,
    uint8_t ek[ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE],
    uint8_t dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE]);

/* ML-KEM.Encaps (Algorithm 20), including the Section 7.2 key check. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_encaps(
    zcl_mlkem_random_fn random, void *random_context,
    const uint8_t *ek, size_t ek_len,
    uint8_t ct[ZCL_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t ss[ZCL_MLKEM768_SHARED_SECRET_SIZE]);

/* ML-KEM.Decaps (Algorithm 21), including the Section 7.3 checks. A
 * ciphertext that fails re-encryption yields the implicit-rejection secret
 * derived from z and returns ZCL_MLKEM_OK; timing and return value do not
 * reveal the rejection. */
[[nodiscard]] enum zcl_mlkem_status zcl_mlkem768_decaps(
    const uint8_t *dk, size_t dk_len, const uint8_t *ct, size_t ct_len,
    uint8_t ss[ZCL_MLKEM768_SHARED_SECRET_SIZE]);

#endif /* ZCL_MLKEM_MLKEM_H */
