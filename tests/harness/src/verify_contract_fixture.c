/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Build one valid fixed_result.v2 world for the verifier tests. */
#include "test/verify_contract_fixture.h"

#include "base/hex.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

void test_vc_pins(struct zcl_fixed_result_v2_roots *pins)
{
    memset(pins, 0, sizeof(*pins));
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        memset(zcl_fr_root_slot(pins, i), (int)(0x10u + i), 32u);
    (void)zcl_hex_decode_lower(ZCL_FR_PROFILE_SHA3, pins->profile_args, 32u);
    zcl_fr_env_fixed_root(pins->environment);
}

void test_vc_target(char out[ZCL_FR_TARGET_LEN + 1u], char fill)
{
    char hex[65];
    memset(hex, fill, 64u);
    hex[64] = '\0';
    (void)snprintf(out, ZCL_FR_TARGET_LEN + 1u,
                   "build/test-obj/epochs/%s/platform/modules/base/src/"
                   "result.o", hex);
}

static void vc_digest(struct zcl_fr_artifact_digest *d, const char *bytes,
                      size_t len)
{
    d->size = len;
    zcl_sha3_256((const uint8_t *)bytes, len, d->sha3);
}

static void vc_receipt(struct test_vc_fixture *f)
{
    struct zcl_fr_receipt *r = &f->receipt;
    memset(r, 0, sizeof(*r));
    memcpy(r->launch_id, "0123456789abcdef0123456789abcdef", ZCL_FR_ID_LEN);
    memcpy(r->request_nonce, "fedcba9876543210fedcba9876543210",
           ZCL_FR_ID_LEN);
    memcpy(r->target, f->target, sizeof(r->target));
    memcpy(r->toolchain_id, f->toolchain_id, sizeof(r->toolchain_id));
    r->pins = f->pins;
    memcpy(r->scratch, "/work/result.ABC123", ZCL_FR_SCRATCH_LEN);
    memset(r->compile_argv_sha3, 0x61, 32u);
    memset(r->preprocess_argv_sha3, 0x62, 32u);
    r->mount_namespace_dev = 4u;
    r->mount_namespace_ino = 4026531840u;
    vc_digest(&r->artifacts[0], TEST_VC_OBJ, sizeof(TEST_VC_OBJ) - 1u);
    vc_digest(&r->artifacts[1], f->dep, f->dep_len);
    vc_digest(&r->artifacts[2], TEST_VC_STDERR, sizeof(TEST_VC_STDERR) - 1u);
    vc_digest(&r->artifacts[3], TEST_VC_PP, sizeof(TEST_VC_PP) - 1u);
}

bool test_vc_receipt_reencode(struct test_vc_fixture *f, const char **why)
{
    if (!zcl_fr_receipt_encode(&f->receipt, f->receipt_bytes,
                               sizeof(f->receipt_bytes), &f->receipt_len,
                               why))
        return false;
    zcl_sha3_256(f->receipt_bytes, f->receipt_len, f->binding.receipt_sha3);
    return true;
}

bool test_vc_fixture_make(struct test_vc_fixture *f, char fill)
{
    char tool_hex[65];
    memset(f, 0, sizeof(*f));
    test_vc_pins(&f->pins);
    test_vc_target(f->target, fill);
    int n = snprintf(f->dep, sizeof(f->dep), "%s: %s\n", f->target,
                     ZCL_FR_SOURCE);
    if (n <= 0 || (size_t)n >= sizeof(f->dep)) return false;
    f->dep_len = (size_t)n;
    zcl_hex_encode(f->pins.tool_image, 32u, tool_hex);
    (void)snprintf(f->toolchain_id, sizeof(f->toolchain_id), "%s%s",
                   ZCL_FR_TOOLCHAIN_PREFIX, tool_hex);
    vc_receipt(f);
    f->binding.contract = (struct zcl_verify_attest_text){
        ZCL_FR_CONTRACT, sizeof(ZCL_FR_CONTRACT) - 1u};
    memcpy(f->binding.profile_sha3, f->pins.profile_args, 32u);
    f->binding.target = (struct zcl_verify_attest_text){
        f->target, ZCL_FR_TARGET_LEN};
    f->expected.toolchain_id = (struct zcl_verify_attest_text){
        f->toolchain_id, ZCL_FR_TOOLCHAIN_LEN};
    f->expected.argv_norm = (struct zcl_verify_attest_text){
        TEST_VC_ARGV, sizeof(TEST_VC_ARGV) - 1u};
    f->expected.recorded_cwd = (struct zcl_verify_attest_text){
        ZCL_FR_CWD, sizeof(ZCL_FR_CWD) - 1u};
    memcpy(f->expected.pp_sha3, f->receipt.artifacts[3].sha3, 32u);
    memset(f->expected.closure_sha3, 0x72, 32u);
    return test_vc_receipt_reencode(f, NULL);
}

struct zcl_verify_attest_record test_vc_record(const struct test_vc_fixture *f,
                                               int exit_code)
{
    struct zcl_verify_attest_record r;
    memset(&r, 0, sizeof(r));
    r.binding = f->binding;
    r.toolchain_id = f->expected.toolchain_id;
    r.argv_norm = f->expected.argv_norm;
    r.recorded_cwd = f->expected.recorded_cwd;
    memcpy(r.pp_sha3, f->expected.pp_sha3, 32u);
    memcpy(r.closure_sha3, f->expected.closure_sha3, 32u);
    memcpy(r.obj_sha3, f->receipt.artifacts[0].sha3, 32u);
    memcpy(r.dep_sha3, f->receipt.artifacts[1].sha3, 32u);
    memcpy(r.stderr_sha3, f->receipt.artifacts[2].sha3, 32u);
    r.exit_code = exit_code;
    return r;
}

struct zcl_fr_artifact_bytes test_vc_artifacts(const struct test_vc_fixture *f)
{
    return (struct zcl_fr_artifact_bytes){
        (const uint8_t *)TEST_VC_OBJ, sizeof(TEST_VC_OBJ) - 1u,
        (const uint8_t *)f->dep, f->dep_len,
        (const uint8_t *)TEST_VC_STDERR, sizeof(TEST_VC_STDERR) - 1u};
}
