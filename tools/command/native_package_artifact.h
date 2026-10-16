/* purpose: Define exclusive hex-or-file wire inputs and checked resident forwarding projections. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_NATIVE_PACKAGE_ARTIFACT_H
#define ZCL_NATIVE_PACKAGE_ARTIFACT_H
#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Inert bounded artifact bytes only. Exactly one inline hex or file+expected SHA3
 * representation; fresh outputs become NULL/zero on every refusal. Trusted
 * ancestor ownership is a caller prerequisite, not general path confinement.
 * File reads pin one no-link regular descriptor, require bounded exact EOF,
 * stable existing metadata and the independently supplied exact byte digest.
 * Canonical codec/root/signature validation remains the consumer's obligation. */
bool zcl_native_package_artifact_read(const struct json_value *input,
    const char *hex_key, const char *file_key, const char *digest_key,
    size_t maximum, uint8_t **bytes, size_t *length);
bool zcl_native_package_artifact_absolute(const char *path,
    char *absolute, size_t capacity);
void zcl_native_package_artifact_digest(uint8_t digest[32], const uint8_t *bytes, size_t length);
/* Narrow flat public package-RPC copy proof; rejects partial/degraded clones. */
bool zcl_native_package_artifact_fields_equal(const struct json_value *a, const struct json_value *b);
bool zcl_native_package_artifact_paths_absolute(const struct json_value *input);
#ifdef ZCL_TESTING
/* Narrow command-local persistence refusal seam, absent from production.
 * 1=durable pending-marker directory barrier; 2=post-retirement barrier.
 * Returns prior setting so fixtures restore inherited state on every exit. */
unsigned zcl_native_package_export_test_failure_stage(unsigned stage);
#endif
#endif
