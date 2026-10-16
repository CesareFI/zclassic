/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: keep validated capture fields private to the comparison core. */
#ifndef UTXO_COPY_CAPTURE_INTERNAL_H
#define UTXO_COPY_CAPTURE_INTERNAL_H
#include "config/utxo_copy_compare.h"
#include "config/utxo_copy_capture_validate.h"
struct utxo_copy_capture_assertion {
    bool manifest_validated;
    enum utxo_copy_capture_binding binding;
    const char *capture_id, *owner_evidence_ref;
    bool generation_present;
    uint64_t authority_generation;
    uint8_t network_genesis[32], expected_network_genesis[32];
    int32_t next_height, last_applied_height;
    uint8_t block_hash[32];
    bool projection_branch_present;
    int32_t projection_branch_height;
    uint8_t projection_branch_hash[32];
    uint8_t authority_file_sha3[32], artifact_digest[32], projection_file_sha3[32];
};
/* Revalidates exact borrowed owners; no caller can provide trust flags via
 * the public capture API. NULL means changed/mismatched input. */
const struct utxo_copy_capture_assertion *utxo_copy_capture_bound_fields(
    const struct utxo_copy_capture *capture,
    const struct consensus_state_artifact_evidence *authority,
    struct utxo_mirror_read_snapshot *projection);
#endif
