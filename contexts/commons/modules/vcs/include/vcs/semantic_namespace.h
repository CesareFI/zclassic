/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Immutable namespace evidence for include lookups, read from one ZVCS source snapshot (tree hash). */

#ifndef ZCL_VCS_SEMANTIC_NAMESPACE_H
#define ZCL_VCS_SEMANTIC_NAMESPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A preprocessor only reports hits. "slot k does not hold <name>" is a
 * NEGATIVE claim, and a stat at compile time proves it only for that
 * moment. The snapshot owner, ZVCS, records an immutable namespace: the
 * path-sorted manifest of every captured file (vcs/vcs_manifest.h), named by
 * its structural tree hash (vcs_tree_capture_path). This reader loads that
 * exact object, re-derives its tree hash, and answers absence questions
 * against it. It never builds a snapshot of its own.
 *
 * It depends only on SHA3 and the snapshot exclusion policy
 * (vcs_path_ignored), so an out-of-tree producer such as the libclang
 * sensor can link it without the rest of ZVCS. */

struct vcs_semantic_namespace_v1;

/* Largest tree object this reader loads. */
#define VCS_SEMANTIC_NAMESPACE_V1_MAX_BYTES (64u * 1024u * 1024u)

/* Parse canonical manifest wire bytes and require that their structural
 * tree hash equals `tree`. */
bool vcs_semantic_namespace_v1_from_wire(const uint8_t *wire, size_t len,
                                         const uint8_t tree[32],
                                         struct vcs_semantic_namespace_v1 **out,
                                         char *why, size_t why_len);

/* Read <repo_root>/.zvcs/objects/<hh>/<62 hex> for `tree` (read only) and
 * parse it as above. */
bool vcs_semantic_namespace_v1_load(const char *repo_root,
                                    const uint8_t tree[32],
                                    struct vcs_semantic_namespace_v1 **out,
                                    char *why, size_t why_len);

void vcs_semantic_namespace_v1_free(struct vcs_semantic_namespace_v1 *ns);

const uint8_t *vcs_semantic_namespace_v1_root(
    const struct vcs_semantic_namespace_v1 *ns);
size_t vcs_semantic_namespace_v1_count(
    const struct vcs_semantic_namespace_v1 *ns);

/* True when the snapshot holds `relpath` as a regular file whose ZVCS blob
 * address is SHA3(0x20 || content): the compile read exactly these bytes. */
bool vcs_semantic_namespace_v1_binds(const struct vcs_semantic_namespace_v1 *ns,
                                     const char *relpath, const uint8_t *content,
                                     size_t size);

/* 0 when `dir`/`name` is proved absent from the snapshot namespace. Otherwise
 * a VCS_SEMANTIC_PROBE_V1_* reason why absence is UNKNOWN: no snapshot (ns
 * NULL), a dir outside the checkout ("@sys/..."), a path the snapshot policy
 * excludes, a path the snapshot holds (it disagrees with the compile), a
 * prefix that is a file or link rather than a directory, or a name that
 * escapes the checkout. `dir` is a canonical manifest directory spelling:
 * repo-relative, "." or "@sys/...". */
uint8_t vcs_semantic_namespace_v1_absent(
    const struct vcs_semantic_namespace_v1 *ns, const char *dir,
    const char *name);

#endif /* ZCL_VCS_SEMANTIC_NAMESPACE_H */
