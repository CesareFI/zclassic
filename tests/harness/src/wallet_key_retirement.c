/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "support/cleanse.h"
#include "crypto/hmac_sha512.h"
#include "crypto/random_secret.h"
#include "keys/key.h"
#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Observe only live spans, forwarding every wipe to the production primitive.
 * Size tags distinguish the entropy, digest and HMAC-context temporaries. */
static unsigned retired_seed, retired_digest, retired_hmac, retired_private;
static bool erased = true, refuse_scalar;
static void observe_key_cleanse(void *bytes, size_t length)
{
    const unsigned char *span = bytes;
    bool populated = false;
    for (size_t i = 0; i < length; ++i)
        if (span[i] != 0) populated = true;
    memory_cleanse(bytes, length);
    for (size_t i = 0; i < length; ++i)
        if (span[i] != 0) erased = false;
    if (!populated) return;
    if (length == 32) ++retired_seed;
    if (length == 64) ++retired_digest;
    if (length == sizeof(struct hmac_sha512_ctx)) ++retired_hmac;
    if (length == sizeof(struct privkey)) ++retired_private;
}

static bool fixture_random(unsigned char *bytes, size_t length, const char *label)
{
    (void)label;
    memset(bytes, 0x7f, length); /* Public synthetic fixture, never persisted. */
    return true;
}

static int fixture_scalar(const secp256k1_context *context, const unsigned char *scalar)
{
    return refuse_scalar ? 0 : secp256k1_ec_seckey_verify(context, scalar);
}

#define memory_cleanse observe_key_cleanse
#define zcl_random_secret_bytes fixture_random
#define secp256k1_ec_seckey_verify fixture_scalar
#define privkey_make_new retirement_privkey_make_new
#define privkey_range_check retirement_privkey_range_check
#define privkey_get_pubkey retirement_privkey_get_pubkey
#define privkey_sign retirement_privkey_sign
#define privkey_sign_compact retirement_privkey_sign_compact
#define privkey_verify_pubkey retirement_privkey_verify_pubkey
#define privkey_derive retirement_privkey_derive
#define ext_key_encode retirement_ext_key_encode
#define ext_key_decode retirement_ext_key_decode
#define ext_key_derive retirement_ext_key_derive
#define ext_key_set_master retirement_ext_key_set_master
#define ext_key_neuter retirement_ext_key_neuter
#define ecc_init_sanity_check retirement_ecc_init_sanity_check
#define ecc_start retirement_ecc_start
#define ecc_start_once retirement_ecc_start_once
#define ecc_stop retirement_ecc_stop
#include "../../../contexts/wallet/modules/keys/src/key.c"
#undef memory_cleanse

static_assert(sizeof(struct hmac_sha512_ctx) != 32 && sizeof(struct hmac_sha512_ctx) != 64,
              "retirement observer has distinct span sizes");
static_assert(sizeof(struct privkey) != 32 && sizeof(struct privkey) != 64 &&
              sizeof(struct privkey) != sizeof(struct hmac_sha512_ctx),
              "private-key retirement has a distinct span size");

static bool master_scratch(bool refuse)
{
    unsigned char seed[16];
    memset(seed, 0x7f, sizeof(seed));
    struct ext_key master;
    retired_digest = retired_hmac = 0;
    refuse_scalar = refuse;
    retirement_ext_key_set_master(&master, seed, sizeof(seed));
    const bool okay = master.key.fValid == !refuse && retired_digest == 1 &&
        retired_hmac == 1 && erased;
    memory_cleanse(&master, sizeof(master));
    memory_cleanse(seed, sizeof(seed));
    refuse_scalar = false;
    return okay;
}

static bool sanity_key_scratch(void)
{
    retired_private = 0;
    return retirement_ecc_init_sanity_check() && retired_private == 1 && erased;
}

int wallet_key_retirement_cases(void);
int wallet_key_retirement_cases(void)
{
    retired_seed = 0;
    erased = true;
    retirement_ecc_start();
    bool okay = retired_seed == 1 && erased;
    okay = sanity_key_scratch() && okay;
    okay = master_scratch(false) && okay;
    okay = master_scratch(true) && okay;
    retirement_ecc_stop();
    printf("domain_wallet_key_derivation: live key scratch retirement... %s\n",
        okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
}
