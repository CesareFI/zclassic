/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: verify signed exact source into a private nonhosting store. */
/* Local source admission reuses the package store and install lifecycle. */
#ifndef ZCL_SERVICES_PACKAGE_LOCAL_H
#define ZCL_SERVICES_PACKAGE_LOCAL_H
#include "services/package_lifecycle.h"
#include <stddef.h>
struct package_local_source {
    const char *directory;
    const uint8_t *release_wire;
    size_t release_size;
    const uint8_t *manifest_wire;
    size_t manifest_size;
    const uint8_t *recipe_wire;
    size_t recipe_size;
    uint8_t expected_root[32];
};
struct package_local_plan {
    char datadir[4096];
    uint8_t transport_root[32];
    struct package_lifecycle_plan_report lifecycle;
};
/* Stores verified inert source in a private child of base_datadir. No
 * publication, credit, network, build, install or execution is authorized.
 * Commit and explicit exact-artifact execution remain separate commands. */
struct zcl_result package_local_plan(const char *base_datadir,
    const struct package_local_source *source, int64_t now_unix,
    struct package_local_plan *out);
#endif
