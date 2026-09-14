/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: accepted-package receipt to exact resident artifact identity. */
#include "services/package_resident.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PACKAGE_RESIDENT_IMAGE_LIMIT = 64u * 1024u * 1024u };

static struct zcl_result pr_capture(
    const char *path, const struct vcs_package_build_output *expected,
    struct resident_launch_accepted *out)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
        platform_positioned_file_snapshot(&file, &before) &&
        before.size == expected->bytes &&
        before.size <= PACKAGE_RESIDENT_IMAGE_LIMIT;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint64_t offset = 0;
    while (ok && offset < before.size) {
        unsigned char bytes[4096];
        size_t count = before.size - offset < sizeof(bytes)
            ? (size_t)(before.size - offset) : sizeof(bytes);
        int64_t got = platform_positioned_file_read(&file, bytes, count, offset);
        if (got <= 0) { ok = false; break; }
        sha3_256_write(&hash, bytes, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    unsigned char digest[32];
    sha3_256_finalize(&hash, digest);
    if (!ok || memcmp(digest, expected->sha3, sizeof(digest)) != 0)
        return ZCL_ERR(-1, "resident-artifact-changed: installed image does not match accepted receipt");
    *out = (struct resident_launch_accepted){
        .image_volume = before.volume, .image_low = before.file_low,
        .image_high = before.file_high, .image_size = before.size,
    };
    zcl_hex_encode(expected->sha3, sizeof(expected->sha3), out->image_sha3_hex);
    return ZCL_OK;
}

static struct zcl_result pr_read_output(
    const char *datadir, const uint8_t package_root[32],
    const uint8_t receipt_id[32], const char *output,
    struct vcs_package_build_receipt *receipt,
    struct package_resident_artifact *out)
{
    struct package_lifecycle_step step;
    bool installed = false;
    ZCL_CHECK(package_lifecycle_installed_inspect(datadir, package_root,
                                                &step, &installed));
    if (!installed || !step.has_receipt ||
        memcmp(step.receipt_id, receipt_id, 32) != 0)
        return ZCL_ERR(-1, "resident-receipt-stale: exact installed receipt is required");
    ZCL_CHECK(package_lifecycle_receipt_read(datadir, receipt_id, receipt));
    if (memcmp(receipt->package_root, package_root, 32) != 0 ||
        !vcs_package_build_installable(receipt))
        return ZCL_ERR(-1, "resident-receipt-refused: package or build verdict differs");
    const struct vcs_package_build_output *selected = NULL;
    for (size_t i = 0; i < receipt->output_count; ++i)
        if (strcmp(receipt->outputs[i].path, output) == 0)
            selected = &receipt->outputs[i];
    if (!selected || strncmp(output, "bin/", 4) != 0)
        return ZCL_ERR(-1, "resident-output-refused: select an exact installed program");
    struct package_lifecycle_programs *programs =
        zcl_calloc(1, sizeof(*programs), "resident installed programs");
    if (!programs)
        return ZCL_ERR(-1, "resident-output-allocation: installed program projection");
    struct zcl_result result = package_lifecycle_installed_programs(
        datadir, package_root, programs);
    if (result.ok) {
        int n = snprintf(out->locator, sizeof(out->locator), "%s/%s",
                         programs->install_dir, output);
        if (n < 0 || (size_t)n >= sizeof(out->locator))
            result = ZCL_ERR(-1, "resident-locator-bound: installed path is too long");
        else
            result = pr_capture(out->locator, selected, &out->accepted);
    }
    free(programs);
    if (!result.ok) return result;
    memcpy(out->package_root, package_root, 32);
    memcpy(out->receipt_id, receipt_id, 32);
    memcpy(out->recipe_root, receipt->recipe_root, 32);
    (void)snprintf(out->output, sizeof(out->output), "%s", output);
    return ZCL_OK;
}

struct zcl_result package_resident_artifact_read(
    const char *datadir, const uint8_t package_root[32],
    const uint8_t receipt_id[32], const char *output,
    struct package_resident_artifact *out)
{
    if (!out) return ZCL_ERR(-1, "resident-input: artifact output is required");
    memset(out, 0, sizeof(*out));
    if (!datadir || !package_root || !receipt_id || !output ||
        strlen(output) > VCS_PACKAGE_BUILD_PATH_MAX)
        return ZCL_ERR(-1, "resident-input: exact package, receipt and program are required");
    struct vcs_package_build_receipt *receipt =
        zcl_calloc(1, sizeof(*receipt), "resident build receipt");
    if (!receipt) return ZCL_ERR(-1, "resident-receipt-allocation");
    struct zcl_result result = pr_read_output(datadir, package_root, receipt_id,
                                            output, receipt, out);
    free(receipt);
    if (!result.ok) memset(out, 0, sizeof(*out));
    return result;
}
