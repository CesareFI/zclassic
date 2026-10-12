/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The fixed-result publisher (root, UID 0). It reopens one signed
 *          staging directory written by the signer account, re-verifies it
 *          against root-owned trust and the root launch record, and adds it
 *          no-clobber to the root-owned observation store under
 *          fixed_result.lock.
 *
 * The publisher trusts nothing the signer computed. Its checks, in order:
 *
 *   1. it runs as the policy's publisher UID, distinct from the signer
 *      (publisher_root_required, publisher_uid_mismatch,
 *      publisher_same_uid);
 *   2. the staging directory and each entry are opened with O_NOFOLLOW,
 *      owned by the signer UID, not group- or world-writable, one link
 *      each, and only the store layout's names (publisher_staging_*);
 *   3. attest.bin hashes to the directory's name
 *      (publisher_record_name_mismatch);
 *   4. launch.bin is byte-identical to the root-owned mode-0444 launch
 *      record /var/lib/z23verify/launches/<launch_id>/launch.bin
 *      (publisher_receipt_not_root_launch);
 *   5. key v2 is rebuilt from that receipt and the root-owned pins and
 *      profile; a PASS must admit under the root-pinned verifier key with
 *      its receipt binding and exact artifacts, and a FAIL must be a
 *      verified signed failure bound to its failure receipt (attest_*,
 *      contract_*);
 *   6. under LOCK_EX on fixed_result.lock, taken within a deadline
 *      (publisher_lock_unsafe, publisher_lock_deadline), an existing record
 *      directory is never replaced (publisher_record_exists). A signed
 *      observation of the opposite verdict for the same key is NOT a
 *      refusal: the new record is published beside it, so the receiver's
 *      admit_set sees both and BLOCKs with attest_eligible_conflict, and
 *      the result names the conflict (publisher_conflict_fail_exists,
 *      publisher_conflict_pass_exists) with an audit note in conflicts/;
 *   7. the observation is written to a root-owned temporary directory,
 *      fsynced, renamed with RENAME_NOREPLACE to store/<key>/<record-sha3>,
 *      and the key and store directories are fsynced.
 *
 * It never unlinks or rewrites anything under store/. */
#ifndef Z23_FIXED_RESULT_PUBLISHER_H
#define Z23_FIXED_RESULT_PUBLISHER_H

#include "dev/verify_attest.h"
#include "verify/fixed_result_trust.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FRP_LOCK_DEADLINE_MS 5000u

#define ZCL_FRP_WHY_ARGUMENTS "publisher_arguments_invalid"
#define ZCL_FRP_WHY_NO_MEMORY "publisher_out_of_memory"
#define ZCL_FRP_WHY_ROOT_REQUIRED "publisher_root_required"
#define ZCL_FRP_WHY_UID_MISMATCH "publisher_uid_mismatch"
#define ZCL_FRP_WHY_SAME_UID "publisher_same_uid"
#define ZCL_FRP_WHY_STAGING_MISSING "publisher_staging_missing"
#define ZCL_FRP_WHY_STAGING_UNSAFE "publisher_staging_unsafe"
#define ZCL_FRP_WHY_STAGING_OWNER "publisher_staging_owner_mismatch"
#define ZCL_FRP_WHY_STAGING_ENTRY "publisher_staging_entry_unsafe"
#define ZCL_FRP_WHY_STAGING_CHILD "publisher_staging_child_unknown"
#define ZCL_FRP_WHY_STAGING_INCOMPLETE "publisher_staging_incomplete"
#define ZCL_FRP_WHY_RECORD_NAME "publisher_record_name_mismatch"
#define ZCL_FRP_WHY_ROOT_LAUNCH "publisher_receipt_not_root_launch"
#define ZCL_FRP_WHY_FAILURE_EXIT "publisher_failure_exit_mismatch"
#define ZCL_FRP_WHY_STORE_UNSAFE "publisher_store_unsafe"
#define ZCL_FRP_WHY_LOCK_UNSAFE "publisher_lock_unsafe"
#define ZCL_FRP_WHY_LOCK_DEADLINE "publisher_lock_deadline"
#define ZCL_FRP_WHY_CONFLICT_FAIL "publisher_conflict_fail_exists"
#define ZCL_FRP_WHY_CONFLICT_PASS "publisher_conflict_pass_exists"
#define ZCL_FRP_WHY_RECORD_EXISTS "publisher_record_exists"
#define ZCL_FRP_WHY_CROSS_DEVICE "publisher_cross_device"
#define ZCL_FRP_WHY_WRITE "publisher_write_failed"

struct zcl_frp_result {
    const char *reason;     /* NULL when published */
    bool failure;           /* the observation is a signed FAIL */
    const char *conflict;   /* NULL, or the opposite verdict already held */
    bool conflict_recorded; /* the audit note was written to conflicts/ */
    char store_key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    char record_sha3[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
};

/* The core over already-loaded trust. `state` is the verifier state
 * directory holding store/, locks/, launches/, publish-tmp/ and
 * conflicts/; `staging` holds <record_hex>/. */
void zcl_frp_publish(const struct zcl_frt_trust *trust, int staging,
                     const char *record_hex, int state,
                     unsigned lock_deadline_ms, bool allow_same_uid,
                     struct zcl_frp_result *out);

/* Production: runs only as root; trust from /etc/z23verify, state in
 * /var/lib/z23verify, staging in /var/lib/z23verify/staging. */
void zcl_frp_publish_production(const char *record_hex,
                                struct zcl_frp_result *out);

#ifdef ZCL_TESTING
struct zcl_frp_fixture {
    struct zcl_frt_fixture trust;
    const char *staging_dir; /* absolute */
    const char *state_dir;   /* absolute, trusted by the test */
    unsigned lock_deadline_ms;
    bool allow_same_uid;     /* the only way a test UID may repeat */
};

void zcl_frp_publish_fixture(const struct zcl_frp_fixture *fixture,
                             const char *record_hex,
                             struct zcl_frp_result *out);
#endif

#endif
