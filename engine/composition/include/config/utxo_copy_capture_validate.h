/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: admit an externally accepted offline capture manifest. */
#ifndef CONFIG_UTXO_COPY_CAPTURE_VALIDATE_H
#define CONFIG_UTXO_COPY_CAPTURE_VALIDATE_H
#include "config/consensus_state_snapshot_install.h"
#include "storage/utxo_mirror_read_snapshot.h"
#include "chain/chainparams.h"
#include <stddef.h>

struct utxo_copy_capture;
enum utxo_copy_capture_status {
    UTXO_COPY_CAPTURE_ERROR = 0,
    UTXO_COPY_CAPTURE_NOT_COMPARABLE,
    UTXO_COPY_CAPTURE_VALIDATED
};
struct utxo_copy_capture_request {
    /* Request bytes and all borrowed inputs remain immutable during calls. */
    const char *manifest;
    size_t manifest_len;
    /* Trusted caller's acceptance of THESE EXACT raw manifest bytes. NULL
     * means no accepted coherent-capture evidence: NOT_COMPARABLE. Never
     * populate this pointer from a field within the manifest itself. The
     * existing owner mechanism authenticates acceptance outside this API.
     * Digest matching is not a mechanical cross-store coherence proof. */
    const uint8_t *accepted_manifest_sha3;
    const struct chain_params *network; /* configured expectation, not JSON */
    const struct consensus_state_artifact_evidence *authority;
    struct utxo_mirror_read_snapshot *projection;
};
/* Neither captures nor opens a database. Borrows admitted owners on their
 * opening thread; authority MUST outlive comparison. Projection MUST remain
 * owned until comparison consumes it; afterward only free this capture.
 * The object owns its parsed
 * strings. Failure leaves *out NULL. Validated means externally attested,
 * never mechanically proven coherent. Equal timestamps/cursors confer no
 * authority. Finished scans and checked outer cleanup remain mandatory. */
enum utxo_copy_capture_status utxo_copy_capture_open(
    const struct utxo_copy_capture_request *request,
    struct utxo_copy_capture **out);
void utxo_copy_capture_free(struct utxo_copy_capture *capture);
#endif
