/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TEST_WALLET_EXT_KEY_FAILURE_RETIREMENT_H
#define ZCL_TEST_WALLET_EXT_KEY_FAILURE_RETIREMENT_H

#include "keys/key.h"

int wallet_ext_key_failure_retirement_cases(void);

/* Namespaced production owner compiled by the deterministic fixture. */
void ext_retirement_privkey_make_new(struct privkey *k, bool fCompressed);
bool ext_retirement_privkey_get_pubkey(const struct privkey *k, struct pubkey *pk);
bool ext_retirement_privkey_range_check(const struct privkey *k);
bool ext_retirement_privkey_sign(const struct privkey *k, const struct uint256 *hash,
                  unsigned char *sig, size_t *siglen);
bool ext_retirement_privkey_sign_compact(const struct privkey *k, const struct uint256 *hash,
                          unsigned char sig[COMPACT_SIGNATURE_SIZE]);
bool ext_retirement_privkey_verify_pubkey(const struct privkey *k, const struct pubkey *pk);
bool ext_retirement_privkey_derive(const struct privkey *k, struct privkey *child,
                    struct uint256 *cc_child, unsigned int nChild,
                    const struct uint256 *cc);
void ext_retirement_ext_key_encode(const struct ext_key *ek,
                    unsigned char code[BIP32_EXTKEY_SIZE]);
void ext_retirement_ext_key_decode(struct ext_key *ek,
                    const unsigned char code[BIP32_EXTKEY_SIZE]);
bool ext_retirement_ext_key_derive(const struct ext_key *ek, struct ext_key *out,
                    unsigned int nChild);
void ext_retirement_ext_key_set_master(struct ext_key *ek, const unsigned char *seed,
                        unsigned int nSeedLen);
void ext_retirement_ext_key_neuter(const struct ext_key *ek, struct ext_pubkey *epk);
bool ext_retirement_ecc_init_sanity_check(void);
void ext_retirement_ecc_start(void);
void ext_retirement_ecc_stop(void);
bool ext_retirement_ecc_start_once(void);

#endif
