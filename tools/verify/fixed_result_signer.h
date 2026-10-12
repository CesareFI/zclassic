/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The fixed-result signer (account z23verify, UID 60092). It takes
 *          one root-written launch receipt v2 (or failure receipt v2) and
 *          the worker's artifacts as descriptors, checks them independently
 *          against the root-owned pins and profile, seals one
 *          z23verify.attest.v2 record bound to the receipt's hash, and
 *          writes a private staging directory for the root publisher.
 *
 * The signer never executes anything: it parses, hashes and signs. It
 * reads its Ed25519 seed only after every input check has passed, and
 * wipes it before it writes staging. Its checks, in order:
 *
 *   1. it runs as the policy's signer UID, distinct from the launcher and
 *      publisher (signer_uid_*, signer_same_uid);
 *   2. the receipt is a root-owned, nlink-1, mode-0444 regular file
 *      (signer_receipt_*), and parses as a launch or failure receipt v2;
 *   3. its twelve roots equal the installed pins (contract_pin_mismatch);
 *   4. every artifact is a root-owned regular file whose size and SHA3
 *      equal the receipt's (signer_artifact_*,
 *      contract_receipt_artifact_mismatch), and the depfile names the
 *      receipt's target (contract_depfile_target_mismatch);
 *   5. both exec-argv hashes equal the ones rederived from the pinned
 *      profile, scratch and target (signer_exec_argv_mismatch);
 *   6. key v2 is rebuilt from the receipt and pins, never copied;
 *   7. the seed is private to the signer (signer_key_*), is not the per-box
 *      proof signer key and is the root-pinned verifier key.
 *
 * A launch receipt seals a PASS record (exit 0). A failure receipt seals a
 * FAIL record whose exit_code is the compile's exit status, so a signed
 * failure is remembered. Every refusal is a stable token. */
#ifndef Z23_FIXED_RESULT_SIGNER_H
#define Z23_FIXED_RESULT_SIGNER_H

#include "dev/verify_attest.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_key_v2.h"
#include "verify/fixed_result_trust.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FRS_KEY_DIR "key"
#define ZCL_FRS_KEY_NAME "signer.seed"
#define ZCL_FRS_STAGING_DIR "staging"

#define ZCL_FRS_WHY_ARGUMENTS "signer_arguments_invalid"
#define ZCL_FRS_WHY_NO_MEMORY "signer_out_of_memory"
#define ZCL_FRS_WHY_UID_NOT_VERIFIER "signer_uid_not_verifier"
#define ZCL_FRS_WHY_UID_MISMATCH "signer_uid_mismatch"
#define ZCL_FRS_WHY_SAME_UID "signer_same_uid"
#define ZCL_FRS_WHY_INPUTS "signer_inputs_invalid"
#define ZCL_FRS_WHY_RECEIPT_OWNER "signer_receipt_not_root_owned"
#define ZCL_FRS_WHY_RECEIPT_UNSAFE "signer_receipt_unsafe"
#define ZCL_FRS_WHY_ARTIFACT_OWNER "signer_artifact_not_root_owned"
#define ZCL_FRS_WHY_ARTIFACT_UNSAFE "signer_artifact_unsafe"
#define ZCL_FRS_WHY_PROFILE "signer_profile_malformed"
#define ZCL_FRS_WHY_EXEC_ARGV "signer_exec_argv_mismatch"
#define ZCL_FRS_WHY_KEY_MISSING "signer_key_missing"
#define ZCL_FRS_WHY_KEY_UNSAFE "signer_key_unsafe"
#define ZCL_FRS_WHY_KEY_ACCESSIBLE "signer_key_group_or_world_accessible"
#define ZCL_FRS_WHY_KEY_MALFORMED "signer_key_malformed"
#define ZCL_FRS_WHY_KEY_IS_BOX "signer_key_is_box_signer"
#define ZCL_FRS_WHY_KEY_NOT_PINNED "signer_key_not_pinned"
#define ZCL_FRS_WHY_STAGING_UNSAFE "signer_staging_unsafe"
#define ZCL_FRS_WHY_STAGING_EXISTS "signer_staging_exists"
#define ZCL_FRS_WHY_STAGING_WRITE "signer_staging_write_failed"

/* Input descriptor slots, in the launch directory's canonical names. */
enum {
    ZCL_FRS_IN_RECEIPT = 0, /* launch.bin */
    ZCL_FRS_IN_OBJECT,      /* object.o, absent (-1) for a failure */
    ZCL_FRS_IN_DEPS,        /* deps.d, absent (-1) for a failure */
    ZCL_FRS_IN_STDERR,      /* stderr.bin */
    ZCL_FRS_IN_PP,          /* preprocessed.i */
    ZCL_FRS_INPUTS
};

/* One parsed launch.bin, either kind. For a launch receipt `failure` is
 * false and `f.compile_exit` is 0. */
struct zcl_frs_launch {
    bool failure;
    struct zcl_fr_failure f;
    uint8_t sha3[32];
};

/* Parse launch.bin as a launch receipt v2, or as a failure receipt v2 when
 * its domain says so. Returns NULL or the contract refusal. */
const char *zcl_frs_launch_parse(const uint8_t *bytes, size_t len,
                                 struct zcl_frs_launch *out);

/* Check the launch's pins, rederive both exec-argv hashes from the pinned
 * profile, scratch and target, and rebuild key v2 with `pp_sha3`. Shared
 * with the publisher, which must not trust the signer's arithmetic. */
const char *zcl_frs_expected_rebuild(const struct zcl_frt_trust *trust,
                                     const struct zcl_frs_launch *launch,
                                     const uint8_t pp_sha3[32],
                                     struct zcl_fixed_result_v2_expected *out);

/* The record a launch seals: the receipt binding, key v2 and the output
 * hashes; exit 0 for a launch receipt, compile_exit for a failure. Text
 * fields borrow from `launch` and `expected`. */
void zcl_frs_record(const struct zcl_frt_trust *trust,
                    const struct zcl_frs_launch *launch,
                    const struct zcl_fixed_result_v2_expected *expected,
                    struct zcl_verify_attest_record *out);

/* Open launch.bin and the four artifacts below a launch directory without
 * following symlinks. A missing object.o or deps.d is -1. */
const char *zcl_frs_inputs_open(int launch_dir, int fds[ZCL_FRS_INPUTS]);
void zcl_frs_inputs_close(int fds[ZCL_FRS_INPUTS]);

/* Read the signer's 32-byte seed: a regular, nlink-1 file owned by
 * `signer_uid` with no group or world permission bits. */
const char *zcl_frs_key_read(int key_dir, const char *name,
                             uint32_t signer_uid, uint8_t seed[32]);

struct zcl_frs_result {
    const char *reason; /* NULL when sealed and staged */
    bool failure;       /* a FAIL record was sealed */
    int32_t exit_code;
    char store_key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    char record_sha3[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
};

/* The core over already-loaded trust. `key_dir` must be the signer-private
 * key directory and `staging` the signer-private staging directory; the
 * sealed observation lands at <staging>/<record-sha3>/ with attest.bin,
 * launch.bin, stderr.bin and, for a PASS, object.o and deps.d.
 * `allow_same_uid` exists for fixtures; production passes false. */
void zcl_frs_seal(const struct zcl_frt_trust *trust,
                  const int inputs[ZCL_FRS_INPUTS], int key_dir,
                  const char *key_name, int staging, bool allow_same_uid,
                  struct zcl_frs_result *out);

/* Production: runs only as UID 60092; trust from /etc/z23verify, the seed
 * from /var/lib/z23verify/key/signer.seed, staging in
 * /var/lib/z23verify/staging. */
void zcl_frs_seal_production(const int inputs[ZCL_FRS_INPUTS],
                             struct zcl_frs_result *out);

/* Production: the hex public key of the installed seed, for root to pin
 * as /etc/z23verify/verifier.pub. Runs only as UID 60092. */
const char *zcl_frs_pubkey_production(char hex[65]);

#ifdef ZCL_TESTING
struct zcl_frs_fixture {
    struct zcl_frt_fixture trust;
    const char *key_dir;     /* absolute, signer-private */
    const char *staging_dir; /* absolute, signer-private */
    bool allow_same_uid;     /* the only way a test UID may repeat */
};

void zcl_frs_seal_fixture(const struct zcl_frs_fixture *fixture,
                          const int inputs[ZCL_FRS_INPUTS],
                          struct zcl_frs_result *out);
#endif

#endif
