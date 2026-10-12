/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The canonical whole-tree walk behind `z23-tree-closure hash`,
 *          exported so the fixed-result image builder hashes its images
 *          with the very same bytes the launcher's preflight rehashes.
 *          It does not attest, sign, or authorize reuse. */
#ifndef ZCL_VERIFY_TREE_CLOSURE_H
#define ZCL_VERIFY_TREE_CLOSURE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct zcl_tree_closure_roots {
    uint8_t tree_sha3[32];    /* owner-bound: includes each entry's UID */
    uint8_t content_sha3[32]; /* owner-independent content */
    unsigned entries;
    uint64_t bytes;
};

/* The absolute, physical root and its ancestors are safe: every ancestor
 * is a directory owned by root (or `owner`) and not group/world writable,
 * and "/" itself is root-owned. This is the CLI's own admission check. */
bool zcl_tree_closure_root_safe(const char *root, uid_t owner);

/* Walk `root` (absolute) and fill both roots. Every entry must be owned by
 * `owner`; special files, writable entries, absolute or escaping links and
 * changes during the walk refuse. When `hash_uid` is non-NULL, that UID is
 * hashed in place of each entry's (still checked) owner: a prediction of the
 * tree root the same bytes will have after `chown -R`, never a measurement.
 * Returns NULL, or the refusal token the CLI prints. The caller checks the
 * ancestors with zcl_tree_closure_root_safe when it needs to. */
const char *zcl_tree_closure_hash(const char *root, uid_t owner,
                                  const uid_t *hash_uid,
                                  struct zcl_tree_closure_roots *out);

#endif
