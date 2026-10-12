/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: admit signed local source through the existing private install lifecycle. */
#include "services/package_local.h"
#include "base/hex.h"
#include "crypto/random_secret.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "vcs/package_store.h"
#include "vcs/package_transport.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char local_marker_content[] = "z23-local-only-v1\n";

/* Existing names are inspected, never tightened or adopted. */
static bool local_marker_valid(const char *marker)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    char actual[sizeof(local_marker_content)] = {0}; uint64_t size = 0;
    bool valid = platform_positioned_file_open(&file, marker) &&
        platform_positioned_file_is_private(&file) &&
        platform_positioned_file_is_current_user_only(&file) &&
        platform_positioned_file_size(&file, &size) && size == sizeof(local_marker_content)-1 &&
        platform_positioned_file_read(&file, actual, sizeof(local_marker_content)-1, 0) == (int64_t)(sizeof(local_marker_content)-1) &&
        memcmp(actual, local_marker_content, sizeof(local_marker_content)-1) == 0;
    platform_positioned_file_close(&file);
    return valid;
}

static bool local_store_valid(const char *directory)
{
    char zcode[4096], marker[4096];
    uintptr_t handle;
    if (!platform_private_directory_open_validated(directory, &handle)) return false;
    platform_private_directory_close(handle);
    int n = snprintf(zcode, sizeof(zcode), "%s/zcode", directory);
    if (n < 0 || (size_t)n >= sizeof(zcode) ||
        !platform_private_directory_open_validated(zcode, &handle)) return false;
    platform_private_directory_close(handle);
    n = snprintf(marker, sizeof(marker), "%s/local-only", zcode);
    if (n < 0 || (size_t)n >= sizeof(marker)) return false;
    return local_marker_valid(marker);
}

struct local_staging {
    char directory[4096], zcode[4096], marker[4096];
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    bool owned, zcode_owned, marker_owned, identified;
};

static struct zcl_result local_store_parent(const char *base, char out[4096],
                                            char parent[4096])
{
    char requested[4096];
    if (!base || !base[0])
        return ZCL_ERR(-1, "local-store-parent: explicit owner-private directory required");
    int n = snprintf(requested, sizeof(requested), "%s/local-apps", base);
    if (n < 0 || (size_t)n >= sizeof(requested) ||
        !platform_private_path_resolve(requested, out, 4096, parent, 4096))
        return ZCL_ERR(-1, "local-store-path: absolute controlled parent required");
    uintptr_t parent_handle;
    if (!platform_private_directory_open_validated(parent, &parent_handle))
        return ZCL_ERR(-1, "local-store-parent: existing owner-private parent required");
    platform_private_directory_close(parent_handle);
    return ZCL_OK;
}

static struct zcl_result local_stage_create(const char *parent, struct local_staging *stage)
{
    /* Only this invocation's exclusive random staging name may be cleaned.
     * A crash leaves inert staging; it never leaves a partial public name. */
    for (unsigned attempt = 0; attempt < 4 && !stage->owned; ++attempt) {
        uint8_t random[16]; char hex[33];
        if (!zcl_random_secret_bytes(random, sizeof(random), "package-local-staging"))
            return ZCL_ERR(-1, "local-store-stage: random name unavailable");
        zcl_hex_encode(random, sizeof(random), hex);
        int n = snprintf(stage->directory, sizeof(stage->directory), "%s/.local-apps-stage-%s", parent, hex);
        if (n < 0 || (size_t)n >= sizeof(stage->directory))
            return ZCL_ERR(-1, "local-store-stage: path exceeds bound");
        stage->owned = platform_private_directory_create(stage->directory);
        if (!stage->owned && errno != EEXIST)
            return ZCL_ERR(-1, "local-store-stage: exclusive directory creation failed");
    }
    if (!stage->owned) return ZCL_ERR(-1, "local-store-stage: name collision budget exhausted");
    return ZCL_OK;
}

static bool local_stage_initialize(struct local_staging *stage)
{
    int n = snprintf(stage->zcode, sizeof(stage->zcode), "%s/zcode", stage->directory);
    if (n < 0 || (size_t)n >= sizeof(stage->zcode)) return false;
    stage->zcode_owned = platform_private_directory_create(stage->zcode);
    if (!stage->zcode_owned) return false;
    n = snprintf(stage->marker, sizeof(stage->marker), "%s/local-only", stage->zcode);
    if (n < 0 || (size_t)n >= sizeof(stage->marker)) return false;
    stage->marker_owned = platform_private_file_create(stage->marker, &stage->file);
    if (!stage->marker_owned) return false;
    stage->identified = platform_private_file_identity(&stage->file, &stage->identity);
    return stage->identified &&
        platform_private_file_write_at(&stage->file, local_marker_content, sizeof(local_marker_content)-1, 0) &&
        platform_private_file_flush(&stage->file) && platform_private_parent_flush(stage->zcode) &&
        platform_private_parent_flush(stage->directory);
}

static struct zcl_result local_stage_publish(struct local_staging *stage,
                                             const char *out, const char *parent)
{
    /* Close before directory publication for Windows handle sharing. */
    platform_private_file_close(&stage->file);
    if (platform_private_directory_publish_no_clobber(stage->directory, out)) {
        stage->owned = stage->zcode_owned = stage->marker_owned = false;
        return platform_private_parent_flush(parent) && local_store_valid(out) ? ZCL_OK :
            ZCL_ERR(-1, "local-store-publish: directory published but durability or validation failed");
    }
    if (local_store_valid(out) && platform_private_parent_flush(parent))
        return ZCL_OK; /* Another initializer published a complete winner. */
    return ZCL_ERR(-1, "local-store-publish: destination refused; existing object preserved");
}

static struct zcl_result local_stage_cleanup(struct local_staging *stage,
                                             const char *parent, struct zcl_result result)
{
    bool cleaned = true;
    if (stage->marker_owned) {
        platform_private_file_close(&stage->file);
        bool opened = platform_private_file_open_locked(stage->marker, &stage->file);
        cleaned = stage->identified && opened &&
            platform_private_file_retire_if_identity(&stage->file, stage->marker, &stage->identity);
    }
    platform_private_file_close(&stage->file);
    if (stage->zcode_owned && !platform_private_directory_remove_empty(stage->zcode)) cleaned = false;
    if (stage->owned && !platform_private_directory_remove_empty(stage->directory)) cleaned = false;
    if (stage->owned && !platform_private_parent_flush(parent)) cleaned = false;
    if (!cleaned)
        return ZCL_ERR(-1, "local-store-cleanup: exact owned staging retained at %s", stage->directory);
    return result;
}

static struct zcl_result local_store_directory(const char *base, char out[4096])
{
    char parent[4096];
    ZCL_CHECK(local_store_parent(base, out, parent));
    if (!platform_private_path_absent(out))
        return local_store_valid(out) && platform_private_parent_flush(parent) ? ZCL_OK :
            ZCL_ERR(-1, "local-store-marker: existing destination is not explicitly private");
    struct local_staging stage = {0};
    platform_private_file_init(&stage.file);
    ZCL_CHECK(local_stage_create(parent, &stage));
    struct zcl_result result = ZCL_ERR(-1, "local-store-stage: initialization failed");
    if (local_stage_initialize(&stage)) result = local_stage_publish(&stage, out, parent);
    return local_stage_cleanup(&stage, parent, result);
}

struct zcl_result package_local_plan(const char *base,
    const struct package_local_source *source, int64_t now_unix,
    struct package_local_plan *out)
{
    if (!source || !out || !source->directory)
        return ZCL_ERR(-1, "local-plan-input: exact local source and output required");
    memset(out, 0, sizeof(*out));
    struct vcs_package_transport transport;
    vcs_package_transport_init(&transport);
    enum vcs_package_transport_result built = vcs_package_transport_build(
        source->release_wire, source->release_size, source->recipe_wire,
        source->recipe_size, source->manifest_wire, source->manifest_size, &transport);
    struct zcl_result result = ZCL_OK;
    if (built != VCS_PACKAGE_TRANSPORT_OK)
        result = ZCL_ERR(-1, "local-source-binding: %s", vcs_package_transport_result_string(built));
    if (result.ok && memcmp(transport.package_root, source->expected_root, 32))
        result = ZCL_ERR(-1, "local-source-root: expected root differs from signed source");
    if (result.ok) result = local_store_directory(base, out->datadir);
    struct vcs_package_store *store = NULL;
    if (result.ok) {
        store = vcs_package_store_open(out->datadir, vcs_package_store_quota_bytes());
        if (!store || vcs_package_store_network_allowed(store))
            result = ZCL_ERR(-1, "local-store-open: private nonhosting store required");
    }
    if (result.ok) {
        built = vcs_package_transport_store(store, &transport, source->directory);
        if (built != VCS_PACKAGE_TRANSPORT_OK)
            result = ZCL_ERR(-1, "local-source-admission: %s", vcs_package_transport_result_string(built));
        else memcpy(out->transport_root, transport.transport_root, 32);
    }
    vcs_package_store_close(store);
    vcs_package_transport_free(&transport);
    if (!result.ok) return result;
    char root[65]; zcl_hex_encode(source->expected_root, 32, root);
    return package_lifecycle_plan(out->datadir, root, now_unix, &out->lifecycle);
}
