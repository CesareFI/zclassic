/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Canonical key material for the one test-fast, non-LTO result.c compile.
 * This pure formatter does not authenticate roots or authorize reuse. */
#ifndef Z23_FIXED_RESULT_KEY_V2_H
#define Z23_FIXED_RESULT_KEY_V2_H

#include "dev/verify_attest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_fixed_result_v2_roots {
    uint8_t source_content[32];
    uint8_t profile_args[32];
    uint8_t source_image[32];
    uint8_t tool_image[32];
    uint8_t worker[32];
    uint8_t launcher[32];
    uint8_t check_image[32];
    uint8_t environment[32];
    uint8_t policy[32];
    uint8_t seccomp_filter[32];
    uint8_t bwrap[32];
    uint8_t tree_checker[32];
};

/* Text fields in expected borrow from the containing storage. Do not move
 * storage after construction. `current_source_content` is the portable root
 * independently measured by the receiver; `roots->source_content` is its
 * independently loaded root pin. The installed source image is a separate
 * UID-bound root and must never be compared to the developer-owned tree.
 * All twelve roots are the root-owned pins v2 (fixed_result_contract.h),
 * in the same order.
 * `check_image` must cover the signer, publisher, receiver, key constructor,
 * and pinned proof executor implementation bytes. The caller must
 * authenticate every root, the signer/box key separately, actual tool/check
 * images, current source/search namespace, and fresh -E bytes.
 * No caller may infer eligibility from a successful format operation. */
struct zcl_fixed_result_v2_expected {
    char toolchain_id[128];
    char argv_norm[16384];
    struct zcl_verify_attest_expected expected;
};

bool zcl_fixed_result_expected_v2(
    const struct zcl_fixed_result_v2_roots *roots,
    const uint8_t current_source_content[32],
    const uint8_t fresh_pp_sha3[32],
    const char *actual_epoch_target,
    const uint8_t *profile_bytes, size_t profile_len,
    const char *actual_physical_cwd,
    const char *const *actual_argv, size_t actual_argc,
    const char *const *actual_envp, size_t actual_envc,
    int actual_output_dirfd,
    struct zcl_fixed_result_v2_expected *out, const char **why);

#endif
