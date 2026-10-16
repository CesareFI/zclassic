/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: bounded comparison reports for externally attested offline UTXO copies. */
#ifndef CONFIG_UTXO_COPY_COMPARE_H
#define CONFIG_UTXO_COPY_COMPARE_H
#include "config/consensus_state_snapshot_install.h"
#include "storage/utxo_mirror_read_snapshot.h"
#define UTXO_COPY_COMPARE_EXAMPLE_MAX 32u

enum utxo_copy_compare_status {
    UTXO_COPY_COMPARE_ERROR = 0, UTXO_COPY_COMPARE_EQUAL,
    UTXO_COPY_COMPARE_DIFFERENT, UTXO_COPY_COMPARE_NOT_COMPARABLE,
    UTXO_COPY_COMPARE_CANCELLED
};
enum utxo_copy_capture_binding {
    UTXO_COPY_CAPTURE_UNACCEPTED = 0,
    UTXO_COPY_CAPTURE_EXTERNALLY_ATTESTED
};
enum utxo_copy_compare_failure {
    UTXO_COPY_FAILURE_NONE = 0, UTXO_COPY_FAILURE_INPUT,
    UTXO_COPY_FAILURE_CAPTURE, UTXO_COPY_FAILURE_NETWORK,
    UTXO_COPY_FAILURE_BRANCH, UTXO_COPY_FAILURE_FRONTIER,
    UTXO_COPY_FAILURE_ARTIFACT, UTXO_COPY_FAILURE_AUTHORITY_BEGIN,
    UTXO_COPY_FAILURE_AUTHORITY_NEXT, UTXO_COPY_FAILURE_PROJECTION_NEXT,
    UTXO_COPY_FAILURE_COUNTER, UTXO_COPY_FAILURE_AUTHORITY_FINISH,
    UTXO_COPY_FAILURE_PROJECTION_FINISH, UTXO_COPY_FAILURE_RESULT_BINDING,
    UTXO_COPY_FAILURE_CANCEL, UTXO_COPY_FAILURE_CLEANUP
};
enum utxo_copy_field_mask {
    UTXO_COPY_FIELD_VALUE = 1u, UTXO_COPY_FIELD_SCRIPT = 2u,
    UTXO_COPY_FIELD_HEIGHT = 4u, UTXO_COPY_FIELD_COINBASE = 8u
};
enum utxo_copy_example_kind {
    UTXO_COPY_AUTHORITY_ONLY = 1, UTXO_COPY_PROJECTION_ONLY,
    UTXO_COPY_SHARED_DIFFERENT
};
/* Only the trusted capture constructor can create comparison inputs. */
struct utxo_copy_capture;
struct utxo_copy_compare_inputs {
    const struct consensus_state_artifact_evidence *authority; /* borrowed */
    /* Already-open standalone copied input, constructor must have succeeded.
     * Consumed on every path unless checked close retains cleanup-only owner.
     * Evidence and both readers must be operated on their opening thread. */
    struct utxo_mirror_read_snapshot **projection;
    const struct utxo_copy_capture *capture;
    unsigned example_limit; /* 0..MAX; zero allows totals without examples */
    bool (*cancelled)(void *); /* optional same-thread predicate; no mutation */
    void *cancel_ctx;
};
struct utxo_copy_compare_example {
    enum utxo_copy_example_kind kind;
    uint8_t txid[32]; uint32_t vout, fields;
    int64_t authority_value, projection_value;
    uint64_t authority_script_len, projection_script_len;
    uint8_t authority_script_sha3[32], projection_script_sha3[32];
};
struct utxo_copy_compare_report {
    enum utxo_copy_compare_status status;
    enum utxo_copy_compare_failure failure;
    enum utxo_copy_capture_binding capture_binding;
    bool complete, counts_valid, roots_valid;
    uint64_t authority_count, projection_count;
    uint64_t authority_only, projection_only, shared_equal, shared_different;
    /* Exact projection_only-authority_only, including full uint64 range.
     * magnitude zero is always nonnegative; no signed narrowing. */
    bool count_delta_negative;
    uint64_t count_delta_magnitude;
    uint32_t shared_fields;
    uint8_t authority_root[32], projection_root[32];
    uint8_t authority_file_sha3[32], projection_file_sha3[32], artifact_digest[32];
    int32_t next_height, last_applied_height;
    uint8_t block_hash[32], network_genesis[32];
    uint64_t authority_generation;
    unsigned example_count;
    bool examples_truncated;
    struct utxo_copy_compare_example examples[UTXO_COPY_COMPARE_EXAMPLE_MAX];
};
/* O(n+m) rows plus input/script bytes, fixed bounded memory. Error/cancel/
 * NOT_COMPARABLE reports expose NO partial totals/roots/examples: validity
 * flags false and numeric storage zero (future JSON must serialize null).
 * Equal/different require both DONE and checked iterator/reader finish.
 * Authority evidence remains caller-owned; its outer transaction is NOT
 * ended by this core. Later evidence cleanup/publication belongs to caller.
 * Any retained projection pointer is cleanup-only and MUST be aborted until
 * released. No datadir, global store, capture, repair or activation authority. */
enum utxo_copy_compare_status utxo_copy_compare_run(
    const struct utxo_copy_compare_inputs *inputs,
    struct utxo_copy_compare_report *out);
#endif
