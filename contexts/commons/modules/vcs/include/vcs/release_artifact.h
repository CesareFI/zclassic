/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_VCS_RELEASE_ARTIFACT_H
#define ZCL_VCS_RELEASE_ARTIFACT_H

#include "vcs/package_content.h"

#define VCS_RELEASE_ARTIFACT_SCHEMA "z23.release-artifact/1"
#define VCS_RELEASE_ARTIFACT_METADATA_PATH "release.json"
#define VCS_RELEASE_ARTIFACT_PROGRAM_PATH "bin/program"
#define VCS_RELEASE_ARTIFACT_NAME_MAX 64u
#define VCS_RELEASE_ARTIFACT_VERSION_MAX 32u
#define VCS_RELEASE_ARTIFACT_TARGET_MAX 32u
#define VCS_RELEASE_ARTIFACT_METADATA_MAX 2048u

/* Name/version are nonempty printable ASCII, matching ZIDR capacity.
 * Target labels are declarations, not compatibility qualification: each is
 * 1..32 bytes of [A-Za-z0-9._+-], case-sensitive. Receiver policy owns the
 * supported values. The digest is raw SHA3-256 of the complete program. */
struct vcs_release_artifact {
    char name[VCS_RELEASE_ARTIFACT_NAME_MAX + 1u];
    char version[VCS_RELEASE_ARTIFACT_VERSION_MAX + 1u];
    char os[VCS_RELEASE_ARTIFACT_TARGET_MAX + 1u];
    char arch[VCS_RELEASE_ARTIFACT_TARGET_MAX + 1u];
    char abi[VCS_RELEASE_ARTIFACT_TARGET_MAX + 1u];
    char isa[VCS_RELEASE_ARTIFACT_TARGET_MAX + 1u];
    uint64_t size;
    uint8_t program_digest[32];
};

/* Exact canonical JSON only: fixed key order, no whitespace or trailing
 * bytes. Unknown/duplicate keys, alternate escapes, NUL and non-ASCII labels
 * are refused. Caller owns serialized bytes. Parse zeroes output on failure. */
bool vcs_release_artifact_serialize(const struct vcs_release_artifact *artifact,
    uint8_t **out, size_t *out_len);
bool vcs_release_artifact_parse(const uint8_t *bytes, size_t len,
    struct vcs_release_artifact *out);

/* Pure preparation over caller-owned immutable snapshots. Metadata size and
 * digest are derived from program bytes; neither supplied value is trusted.
 * Produces exactly LICENSE, bin/program and release.json in content.v2.
 * Initializes manifest; caller frees it even after failure. Persists nothing. */
bool vcs_release_artifact_prepare(const struct vcs_release_artifact *labels,
    const uint8_t *program, size_t program_len,
    const uint8_t *license, size_t license_len,
    struct vcs_package_manifest *manifest, uint8_t root[32]);

/* Re-derives the carrier before admitting through the existing CAS. A
 * partial refusal may leave resumable staging; it never grants serving,
 * signing, installation or execution authority. Idempotent exact redelivery. */
bool vcs_release_artifact_admit(struct vcs_package_store *store,
    const struct vcs_release_artifact *labels,
    const uint8_t *program, size_t program_len,
    const uint8_t *license, size_t license_len, uint8_t root[32]);

/* Re-roots the manifest, verifies all three files from CAS, checks canonical
 * metadata, license and whole-program digest. Caller owns *program. Does not
 * verify a ZIDR signature or receiver target policy; D4 must do both. */
bool vcs_release_artifact_verify(struct vcs_package_store *store,
    const uint8_t root[32], struct vcs_release_artifact *out,
    uint8_t **program, size_t *program_len);

#endif
