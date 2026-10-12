/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: One valid z23verify.fixed_result.v2 world (pins, epoch target,
 *          depfile, launch receipt, receipt binding, expected inputs) for
 *          the verifier tests to mutate one field at a time. */
#ifndef ZCL_TEST_VERIFY_CONTRACT_FIXTURE_H
#define ZCL_TEST_VERIFY_CONTRACT_FIXTURE_H

#include "verify/fixed_result_contract.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEST_VC_OBJ "\x7f" "ELF fixed-result object"
#define TEST_VC_STDERR ""
#define TEST_VC_PP "# 1 \"platform/modules/base/src/result.c\"\nint r;\n"
#define TEST_VC_ARGV "z23verify.fixed_result.argv.v2\n4:-O1<EPOCH_TARGET>"
#define TEST_VC_RECEIPT_CAP 8192u

/* Everything borrows from the struct itself: build it in place with
 * test_vc_fixture_make() and never copy it afterwards. */
struct test_vc_fixture {
    struct zcl_fixed_result_v2_roots pins;
    char target[ZCL_FR_TARGET_LEN + 1u];
    char dep[ZCL_FR_TARGET_LEN + 64u];
    size_t dep_len;
    char toolchain_id[ZCL_FR_TOOLCHAIN_LEN + 1u];
    struct zcl_fr_receipt receipt;
    uint8_t receipt_bytes[TEST_VC_RECEIPT_CAP];
    size_t receipt_len;
    struct zcl_verify_attest_binding binding;
    struct zcl_verify_attest_expected expected;
};

/* Valid pins: every root nonzero and distinct, profile_args the fast
 * profile digest, environment the fixed v2 environment root. */
void test_vc_pins(struct zcl_fixed_result_v2_roots *pins);

/* build/test-obj/epochs/<64 x fill>/platform/modules/base/src/result.o */
void test_vc_target(char out[ZCL_FR_TARGET_LEN + 1u], char fill);

/* A complete consistent world for the epoch named by `fill`. */
bool test_vc_fixture_make(struct test_vc_fixture *f, char fill);

/* Re-encode f->receipt after a mutation and refresh the binding's
 * receipt hash. False (with *why) when the encoder refuses. */
bool test_vc_receipt_reencode(struct test_vc_fixture *f, const char **why);

/* The record a verifier would sign for this world. */
struct zcl_verify_attest_record test_vc_record(const struct test_vc_fixture *f,
                                               int exit_code);

struct zcl_fr_artifact_bytes test_vc_artifacts(const struct test_vc_fixture *f);

/* A private directory for a pinned verifier key fixture. The key loader
 * checks every ancestor up to "/" for group- or world-writable paths, and
 * a checkout's ancestors may be group writable, so it lives in the system
 * temp directory; defined once in test_verify_store.c for every verifier
 * test that needs one. PATH_MAX bytes. */
bool test_vs_key_root_make(char *out);

#endif
