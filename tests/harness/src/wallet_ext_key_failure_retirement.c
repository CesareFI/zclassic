/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "test/wallet_ext_key_failure_retirement.h"
#include "support/cleanse.h"
#include "crypto/random_secret.h"
#include "keys/key.h"
#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Compile the actual key owner with a deterministic scalar-add refusal. The
 * observer reads only the live output span passed to the production cleanse. */
static unsigned output_wipes;
static bool output_erased, refuse_scalar, refuse_child;

static void observe_ext_key_cleanse(void *bytes, size_t length)
{
    memory_cleanse(bytes, length);
    if (length != sizeof(struct ext_key)) return;
    ++output_wipes;
    for (size_t i = 0; i < length; ++i)
        if (((const unsigned char *)bytes)[i] != 0) output_erased = false;
}

static bool ext_key_fixture_random(unsigned char *bytes, size_t length,
                                   const char *label)
{
    (void)label;
    memset(bytes, 0x7f, length);
    return true;
}

static int refuse_tweak(const secp256k1_context *context,
                        unsigned char *scalar,
                        const unsigned char *tweak)
{
    if (!refuse_child)
        return secp256k1_ec_seckey_tweak_add(context, scalar, tweak);
    memset(scalar, 0x5a, 32);
    return 0;
}

static int fixture_scalar(const secp256k1_context *context,
                          const unsigned char *scalar)
{
    if (refuse_scalar) return 0;
    return secp256k1_ec_seckey_verify(context, scalar);
}

#define memory_cleanse observe_ext_key_cleanse
#define zcl_random_secret_bytes ext_key_fixture_random
#define secp256k1_ec_seckey_tweak_add refuse_tweak
#define secp256k1_ec_seckey_verify fixture_scalar
#define privkey_make_new ext_retirement_privkey_make_new
#define privkey_range_check ext_retirement_privkey_range_check
#define privkey_get_pubkey ext_retirement_privkey_get_pubkey
#define privkey_sign ext_retirement_privkey_sign
#define privkey_sign_compact ext_retirement_privkey_sign_compact
#define privkey_verify_pubkey ext_retirement_privkey_verify_pubkey
#define privkey_derive ext_retirement_privkey_derive
#define ext_key_encode ext_retirement_ext_key_encode
#define ext_key_decode ext_retirement_ext_key_decode
#define ext_key_derive ext_retirement_ext_key_derive
#define ext_key_set_master ext_retirement_ext_key_set_master
#define ext_key_neuter ext_retirement_ext_key_neuter
#define ecc_init_sanity_check ext_retirement_ecc_init_sanity_check
#define ecc_start ext_retirement_ecc_start
#define ecc_start_once ext_retirement_ecc_start_once
#define ecc_stop ext_retirement_ecc_stop
#include "../../../contexts/wallet/modules/keys/src/key.c"
#undef memory_cleanse

static bool ext_key_is_zero(const struct ext_key *key)
{
    for (size_t i = 0; i < sizeof(*key); ++i)
        if (((const unsigned char *)key)[i] != 0) return false;
    return true;
}

static bool failed_master_is_retired(struct ext_key *invalid,
                                     const unsigned char *seed,
                                     size_t seed_len)
{
    output_wipes = 0;
    output_erased = true;
    refuse_scalar = true;
    memset(invalid, 0xa5, sizeof(*invalid));
    ext_retirement_ext_key_set_master(invalid, seed, (unsigned int)seed_len);
    return output_wipes == 1 && output_erased && ext_key_is_zero(invalid);
}

static bool invalid_decode_is_retired(struct ext_key *invalid,
                                      const unsigned char *encoded)
{
    output_wipes = 0;
    output_erased = true;
    refuse_scalar = true;
    memset(invalid, 0xa5, sizeof(*invalid));
    ext_retirement_ext_key_decode(invalid, encoded);
    return output_wipes == 1 && output_erased && ext_key_is_zero(invalid);
}

static bool failed_child_is_retired(const struct ext_key *parent,
                                    struct ext_key *child)
{
    output_wipes = 0;
    output_erased = true;
    refuse_scalar = false;
    refuse_child = true;
    memset(child, 0xa5, sizeof(*child));
    const bool derived = ext_retirement_ext_key_derive(parent, child, 1);
    return !derived && output_wipes == 1 && output_erased &&
           ext_key_is_zero(child);
}

int wallet_ext_key_failure_retirement_cases(void)
{
    const unsigned char seed[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    struct ext_key parent, child, invalid;
    refuse_scalar = refuse_child = false;
    output_erased = true;
    ext_retirement_ecc_start();
    ext_retirement_ext_key_set_master(&parent, seed, sizeof(seed));

    unsigned char encoded[BIP32_EXTKEY_SIZE];
    memset(encoded, 0x5a, sizeof(encoded));
    bool okay = failed_master_is_retired(&invalid, seed, sizeof(seed));
    okay = invalid_decode_is_retired(&invalid, encoded) && okay;
    okay = failed_child_is_retired(&parent, &child) && okay;

    refuse_child = false;
    output_wipes = 0;
    const bool success = ext_retirement_ext_key_derive(&parent, &child, 1);
    okay = success && output_wipes == 0 && child.key.fValid && okay;
    memory_cleanse(&parent, sizeof(parent));
    memory_cleanse(&child, sizeof(child));
    memory_cleanse(&invalid, sizeof(invalid));
    memory_cleanse(encoded, sizeof(encoded));
    ext_retirement_ecc_stop();
    printf("domain_wallet_key_derivation: failed ext key outputs retire... %s\n",
           okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
}
