/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: strict offline node.db mirror traversal and checked retained-input attestation. */
#ifndef STORAGE_UTXO_MIRROR_READ_SNAPSHOT_H
#define STORAGE_UTXO_MIRROR_READ_SNAPSHOT_H
#include "storage/coins_kv_read_snapshot.h"
#include "platform/positioned_file.h"

struct utxo_mirror_read_snapshot;
enum utxo_mirror_byte_order {
    UTXO_MIRROR_LITTLE_ENDIAN = 1,
    UTXO_MIRROR_BIG_ENDIAN = 2
};
/* Structural mirror schema profile, not node_state schema_version or
 * producer identity: real node_state(key,value) and eight-column utxos with
 * exact declared types/nullability/PK order and no hidden columns. */
enum utxo_mirror_schema_profile { UTXO_MIRROR_SCHEMA_V1 = 1 };
struct utxo_mirror_read_attestation {
    struct platform_positioned_file_snapshot file;
    uint8_t file_sha3[32];
    enum utxo_mirror_schema_profile schema_profile;
    bool sidecars_all_absent;
};
struct utxo_mirror_read_result {
    int32_t next_height;
    uint64_t count;
    uint8_t root[32];
    uint8_t file_sha3[32];
    struct utxo_mirror_read_attestation input;
};
/* Offline ONLY: a finalized standalone copied file, made read-only by its
 * producer in an absolute-path, current-user private directory, with no
 * WAL/SHM/journal sidecars. expected_file_sha3 binds the
 * complete input bytes, not chain correctness or common-capture provenance.
 * Producer byte order is REQUIRED: node_state stores native int64_t bytes.
 * No node/global store, migrations, receipts or services are opened.
 * SQLite borrows the retained positioned file through sqlite_pinned_reader;
 * the adapter neither reopens this pathname nor establishes capture trust.
 * This proposal currently refuses Windows input admission.
 * One caller/thread owns the snapshot. No input mutation is permitted. */
/* False leaves height=-1. A non-NULL *out on false is cleanup-only and MUST
 * be passed to abort until *out becomes NULL; it must not yield rows/results. */
bool utxo_mirror_read_snapshot_open(
    const char *path, enum utxo_mirror_byte_order producer_order,
    const uint8_t expected_file_sha3[32],
    struct utxo_mirror_read_snapshot **out, int32_t *next_height);
/* Recheck real schema, retained file snapshot/full digest, and bound sibling
 * absence/path identity. Output comes only from these reader checks. Does NOT
 * establish completed traversal, network, branch or coherent common capture.
 * It is a momentary input attestation; finish independently rechecks it.
 * A failure poisons the reader; output is zeroed. Same owning thread. */
bool utxo_mirror_read_snapshot_attestation(
    struct utxo_mirror_read_snapshot *snapshot,
    struct utxo_mirror_read_attestation *out);
/* ROW script bytes are borrowed until next/finish/abort. DONE is terminal;
 * next after DONE or any invalid row poisons completion. */
enum coins_kv_read_snapshot_step utxo_mirror_read_snapshot_next(
    struct utxo_mirror_read_snapshot *snapshot,
    struct coins_kv_read_snapshot_row *out);
/* finish requires DONE and unchanged retained/path bytes, and zeroes output
 * on failure. Both functions null *owner once released. If checked SQLite
 * close refuses, *owner remains cleanup-only: caller MUST retry abort, not
 * free/reuse the retained file. A retry cannot restore result validity.
 * abort can report false with *owner==NULL when cleanup itself failed but
 * ownership was released. Common capture remains comparator responsibility. */
bool utxo_mirror_read_snapshot_finish(
    struct utxo_mirror_read_snapshot **owner,
    struct utxo_mirror_read_result *out);
bool utxo_mirror_read_snapshot_abort(
    struct utxo_mirror_read_snapshot **owner);
#endif
