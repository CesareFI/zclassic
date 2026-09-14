/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: bind an explicitly selected installed program to resident_launch. */
#ifndef ZCL_SERVICES_PACKAGE_RESIDENT_H
#define ZCL_SERVICES_PACKAGE_RESIDENT_H

#include "base/result.h"
#include "platform/resident_launch.h"
#include "services/package_lifecycle.h"

/* This is an inert acceptance projection, never an execution grant. The
 * caller must separately authorize the exact package, receipt and output.
 * The digest comes from the verified install receipt, never from whichever
 * bytes happen to occupy the installed pathname today. */
struct package_resident_artifact {
    uint8_t package_root[32];
    uint8_t receipt_id[32];
    uint8_t recipe_root[32];
    char output[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
    char locator[PACKAGE_LIFECYCLE_INSTALL_DIR_MAX +
                 VCS_PACKAGE_BUILD_PATH_MAX + 2u];
    struct resident_launch_accepted accepted;
};

struct zcl_result package_resident_artifact_read(
    const char *datadir, const uint8_t package_root[32],
    const uint8_t receipt_id[32], const char *output,
    struct package_resident_artifact *out);

/* One caller-owned application process. Independent snapshot lifetime ends
 * only after the seam has cancelled/reaped its child. A failed candidate
 * never changes any other instance or a package's active generation. */
struct package_resident {
    struct package_resident_artifact artifact;
    struct resident_launch launch;
    struct resident_receipt receipt;
    char snapshot_directory[128];
    char snapshot_image[160];
};

void package_resident_init(struct package_resident *app);
struct zcl_result package_resident_prepare(struct package_resident *app,
    const struct package_resident_artifact *artifact);
struct zcl_result package_resident_start(struct package_resident *app);
struct zcl_result package_resident_close(struct package_resident *app);


#endif
