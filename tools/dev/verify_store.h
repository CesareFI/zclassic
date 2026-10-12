/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Bounded receiver for the fixed result.c verifier observation store.
 * This is a dev proof input reader, not an eligible expected-key producer. */
#ifndef ZCL_TOOLS_DEV_VERIFY_STORE_H
#define ZCL_TOOLS_DEV_VERIFY_STORE_H

#include "verify_attest.h"
#include "verify/fixed_result_key_v2.h"

#include <stddef.h>
#include <stdint.h>

enum zcl_verify_store_verdict {
    ZCL_VERIFY_STORE_COLD = 0,
    ZCL_VERIFY_STORE_HIT = 1,
    ZCL_VERIFY_STORE_BLOCK = 2,
};

struct zcl_verify_store_result {
    enum zcl_verify_store_verdict verdict;
    const char *reason;
    uint8_t *object;
    size_t object_len;
    uint8_t *depfile;
    size_t depfile_len;
    uint8_t *stderr_bytes;
    size_t stderr_len;
    char store_key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    char record_sha3[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    uint8_t verifier_pubkey[ZCL_VERIFY_ATTEST_PUBKEY_BYTES];
    /* On HIT, the shared publication lock remains held until release. A
     * caller must materialize the verified object before releasing it. */
    int lock_fd;
};

/* Production paths, signer UID, publisher custody and the pins v2 file come
 * only from root-owned policy. This function reloads the policy, the
 * root-pinned public key and /etc/z23verify/fixed_result.pins on every call,
 * and refuses store_owner_same_uid when the receiver runs as the signer or
 * the publisher. Every observation's launch.bin receipt is bound against
 * those pins (zcl_fr_receipt_bind) before its record can admit.
 * The caller must independently construct `expected` from an eligible input
 * closure; zcl_verify_store_pins_load() gives it the same pins to build
 * that closure from. This reader cannot make a probe-only closure eligible. */
void zcl_verify_store_lookup(const struct zcl_verify_attest_expected *expected,
                             const struct zcl_verify_attest_box_key *box,
                             struct zcl_verify_store_result *out);

/* Load /etc/z23verify/fixed_result.pins by descriptor from "/": every
 * directory root-owned and not group/world writable, the file opened with
 * O_NOFOLLOW, root-owned, regular, nlink 1, mode exactly 0444, then
 * zcl_fr_pins_parse. Refusals: store_pins_path_unsafe, store_pins_missing,
 * store_pins_unsafe, store_pins_changed, or the contract token. On refusal
 * `out` is zeroed. */
bool zcl_verify_store_pins_load(struct zcl_fixed_result_v2_roots *out,
                                const char **why);

void zcl_verify_store_result_release(struct zcl_verify_store_result *result);

#ifdef ZCL_TESTING
/* Deterministic pin-rotation witness after the store scan, before HIT refresh. */
void zcl_verify_store_test_before_refresh(void (*hook)(void *), void *context);
/* Isolated fixture only. Production does not compile a path/UID override.
 * Both fixtures run production's lookup function, including its one
 * same-uid rule: without allow_same_uid, a signer or publisher UID equal to
 * the caller's refuses store_owner_same_uid before any store file is
 * opened. This one names the uids, pins and an absolute store root owned
 * by signer_uid. */
void zcl_verify_store_lookup_fixture(
    const char *root, unsigned signer_uid, unsigned publisher_uid,
    bool allow_same_uid,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_fixed_result_v2_roots *pins,
    const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_store_result *out);

/* Production's exact policy, pins and store walk under an absolute anchor
 * owned by the caller's uid in place of "/" and root:
 * anchor/etc/z23verify/{store.policy,fixed_result.pins} and
 * anchor/var/lib/z23verify/{locks/fixed_result.lock,store/}. The policy's
 * publisher_uid is therefore the caller's uid. */
void zcl_verify_store_lookup_site_fixture(
    const char *anchor, bool allow_same_uid,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_store_result *out);

/* The pins loader's file checks over a fixture directory: dir_path must
 * be owned by dir_owner and not group/world writable, the pins file by
 * file_owner. Production passes 0 for both through the path from "/". */
const char *zcl_verify_store_pins_load_fixture(
    const char *dir_path, unsigned dir_owner, unsigned file_owner,
    struct zcl_fixed_result_v2_roots *out);
#endif

#endif
