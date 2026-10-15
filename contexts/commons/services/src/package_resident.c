/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bind accepted-package receipts to exact resident artifact identity. */
#include "services/package_resident.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "platform/supervised_process.h"
#if defined(__linux__)
#include <unistd.h>
#endif

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
    struct package_lifecycle_programs *programs = zcl_calloc(1, sizeof(*programs), "package.resident.programs");
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
    struct vcs_package_build_receipt *receipt = zcl_calloc(1, sizeof(*receipt), "package.resident.receipt");
    if (!receipt) return ZCL_ERR(-1, "resident-receipt-allocation");
    struct zcl_result result = pr_read_output(datadir, package_root, receipt_id,
                                            output, receipt, out);
    free(receipt);
    if (!result.ok) memset(out, 0, sizeof(*out));
    return result;
}

#if defined(__linux__)
static bool pr_host_digest(const struct package_resident_artifact *artifact,
    const uint8_t expected[32])
{
    uint8_t digest[32];
    return zcl_hex_decode(artifact->accepted.image_sha3_hex, digest, sizeof(digest)) &&
        !memcmp(digest, expected, sizeof(digest));
}

static bool pr_host_same(const struct package_resident_artifact *a,
    const struct package_resident_artifact *b)
{
    const struct resident_launch_accepted *x = &a->accepted, *y = &b->accepted;
    bool roots = !memcmp(a->package_root, b->package_root, 32) &&
        !memcmp(a->receipt_id, b->receipt_id, 32) && !memcmp(a->recipe_root, b->recipe_root, 32);
    bool image = x->image_volume == y->image_volume && x->image_low == y->image_low &&
        x->image_high == y->image_high && x->image_size == y->image_size;
    return roots && image && !strcmp(x->image_sha3_hex, y->image_sha3_hex);
}

static struct zcl_result pr_host_capture_bytes(const char *datadir,
    const struct package_resident_artifact *before, const uint8_t digest[32], int *image_fd)
{
    struct package_lifecycle_declared_output *handle = NULL;
    struct zcl_result result = package_lifecycle_declared_output_open(datadir,
        before->package_root, "bin/tunnel", PLATFORM_SUPERVISED_IMAGE_MAX,
        UINT64_C(512) * 1024 * 1024, &handle);
    size_t length = (size_t)before->accepted.image_size, produced = 0;
    uint8_t *bytes = NULL;
    if (result.ok) result = package_lifecycle_declared_output_host_executable(handle);
    if (result.ok) {
        bytes = zcl_malloc(length, "package.resident.host.image");
        if (!bytes) result = ZCL_ERR(-1, "cannot allocate bounded HOST image copy");
    }
    if (result.ok) result = package_lifecycle_declared_output_read_verified(handle, bytes, length, &produced);
    if (result.ok) result = package_lifecycle_declared_output_host_executable(handle);
    if (result.ok && produced != length) result = ZCL_ERR(-1, "HOST image size differs from approved receipt");
    if (result.ok && platform_supervised_image_capture(bytes, length, digest, image_fd) != PLATFORM_SUPERVISED_IMAGE_OK)
        result = ZCL_ERR(-1, "HOST image digest, ELF admission or sealed capture refused");
    free(bytes); package_lifecycle_declared_output_close(&handle);
    return result;
}
#endif

struct zcl_result package_resident_host_image_capture(
    const char *datadir, const uint8_t package_root[32], const uint8_t receipt_id[32],
    const uint8_t artifact_sha3[32], int *image_fd)
{
#if defined(__linux__)
    if (!artifact_sha3 || !image_fd || *image_fd != -1)
        return ZCL_ERR(-1, "HOST image requires exact digest and fresh FD output");
    struct package_resident_artifact before, after;
    ZCL_CHECK(package_resident_artifact_read(datadir, package_root, receipt_id, "bin/tunnel", &before));
    if (!pr_host_digest(&before, artifact_sha3) || !before.accepted.image_size ||
        before.accepted.image_size > PLATFORM_SUPERVISED_IMAGE_MAX)
        return ZCL_ERR(-1, "HOST image approval digest or bounded size differs");
    struct zcl_result result = pr_host_capture_bytes(datadir, &before, artifact_sha3, image_fd);
    if (result.ok) result = package_resident_artifact_read(datadir, package_root, receipt_id, "bin/tunnel", &after);
    if (result.ok && !pr_host_same(&before, &after))
        result = ZCL_ERR(-1, "HOST installed artifact changed during capture");
    if (!result.ok && *image_fd >= 0) { close(*image_fd); *image_fd = -1; }
    return result;
#else
    (void)datadir; (void)package_root; (void)receipt_id; (void)artifact_sha3; (void)image_fd;
    return ZCL_ERR(-1, "HOST installed image admission is Linux-only");
#endif
}
