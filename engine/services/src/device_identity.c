/* purpose: Create and reopen owner-private device identities with truthful durability outcomes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_identity.h"
#include "models/device_profile.h"
#include "crypto/curve25519.h"
#include "base/bytes.h"
#include "platform/private_directory.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"
#include "support/cleanse.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef ZCL_TESTING
static _Thread_local unsigned interruption_stage;
void device_identity_test_interrupt(unsigned stage) { interruption_stage = stage; }
#endif

static bool checkpoint(unsigned stage)
{
#ifdef ZCL_TESTING
    if (interruption_stage == stage) {
        interruption_stage = 0;
        LOG_FAIL("device_identity", "injected initialization interruption at %u", stage);
    }
#else
    (void)stage;
#endif
    return true;
}

void device_identity_close(struct device_identity *identity)
{
    if (identity) memory_cleanse(identity, sizeof(*identity));
}

static bool identity_path(const char *directory, const char *leaf, char path[1200])
{
    int n = snprintf(path, 1200, "%s/%s", directory, leaf);
    return n > 0 && n < 1200;
}

static bool pending_absent(const char *directory)
{
    char path[1200];
    return identity_path(directory, DEVICE_PROFILE_PENDING, path) &&
        platform_private_path_absent(path);
}

static bool load_existing(struct device_identity *identity, const char *directory)
{
    uint8_t expected[32];
    if (!pending_absent(directory) || !db_device_profile_read(directory, expected)) return false;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open_beneath(&file, directory, "v2_identity.key") &&
        platform_positioned_file_is_private(&file) &&
        platform_positioned_file_snapshot(&file, &before) && before.size == 32 &&
        platform_positioned_file_read(&file, identity->private_key, 32, 0) == 32 &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    return ok && curve25519_scalarmult_base(identity->public_key, identity->private_key) &&
        !memcmp(identity->public_key, expected, 32) && pending_absent(directory);
}

static bool publish_key(const char *directory, const uint8_t key[32])
{
    char path[1200];
    if (!identity_path(directory, "v2_identity.key", path)) return false;
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create_locked(path, &file) &&
        platform_private_file_write_at(&file, key, 32, 0) &&
        platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    if (!ok) LOG_ERROR("device_identity", "exclusive key publication failed; preserve and reconcile");
    return ok;
}

static bool begin_intent(const char *directory, const char *parent,
                         const char *path, struct platform_private_file *intent)
{
    static const uint8_t pending[] = "zcl.owner-device.initializing.v1";
    return platform_private_parent_flush(parent) &&
        platform_private_file_create_locked(path, intent) &&
        platform_private_file_write_at(intent, pending, sizeof(pending), 0) &&
        platform_private_file_authority_flush(intent) &&
        platform_private_parent_flush(directory) && checkpoint(1);
}

static bool publish_initial(struct device_identity *identity, const char *directory,
                            const char *parent, struct device_identity_publication_report *report)
{
    char path[1200];
    if (!identity_path(directory, DEVICE_PROFILE_PENDING, path)) return false;
    struct platform_private_file intent;
    platform_private_file_init(&intent);
    bool ok = begin_intent(directory, parent, path, &intent);
    if (ok) ok = rng_fill(identity->private_key, sizeof(identity->private_key)) &&
        zcl_bytes_any_set(identity->private_key, sizeof(identity->private_key)) &&
        curve25519_scalarmult_base(identity->public_key, identity->private_key);
    if (ok) {
        report->public_key_known = true;
        memcpy(report->public_key, identity->public_key, 32);
        ok = publish_key(directory, identity->private_key) &&
            db_device_profile_publish(directory, identity->public_key) &&
            platform_private_parent_flush(directory) && checkpoint(2);
    }
    if (ok) ok = platform_private_file_retire(&intent, path) && checkpoint(3) &&
        platform_private_parent_flush(directory);
    platform_private_file_close(&intent);
    if (ok) report->state = DEVICE_IDENTITY_DURABLE;
    else LOG_ERROR("device_identity", "initialization durability unknown; preserve artifacts and reconcile");
    return ok;
}

static bool open_directory(struct device_identity *identity, const char *directory,
                           bool create, struct device_identity_publication_report *report)
{
    char resolved[1024], parent[1200];
    if (!platform_private_destination_resolve(directory, resolved, sizeof(resolved),
                                              parent, sizeof(parent))) {
        int error = errno;
        LOG_RETURN((errno = error, false), "device_identity", "owner identity destination resolution failed");
    }
    bool created = create && platform_private_directory_create(resolved);
    if (create && !created) {
        LOG_ERROR("device_identity", "initialization requires an absent directory; existing profiles are read-only");
        return false;
    }
    uintptr_t handle;
    if (created) report->state = DEVICE_IDENTITY_DURABILITY_UNKNOWN;
    if (!platform_private_directory_open_validated(resolved, &handle)) return false;
    platform_private_directory_close(handle);
    bool ok = created ? publish_initial(identity, resolved, parent, report)
                      : load_existing(identity, resolved);
    if (ok) {
        memcpy(identity->directory, resolved, strlen(resolved) + 1);
        report->public_key_known = true;
        memcpy(report->public_key, identity->public_key, 32);
    }
    return ok;
}

struct zcl_result device_identity_open(struct device_identity *identity,
    const char *directory, bool create, struct device_identity_publication_report *report)
{
    device_identity_close(identity);
    if (report) memset(report, 0, sizeof(*report));
    if (!identity || !directory || !report || !directory[0])
        return ZCL_ERR(1, "identity, explicit trusted profile directory and publication report required");
#if defined(_WIN32)
    if (create)
        return ZCL_ERR(1, "Windows directory publication durability is unsupported; identity creation refused before mutation");
#endif
    if (!open_directory(identity, directory, create, report)) {
        device_identity_close(identity);
        return ZCL_ERR(1, "device identity refused; preserve unknown initialization, do not retry or repair on read");
    }
    return ZCL_OK;
}
struct zcl_result device_identity_pair_store(const struct device_identity *identity,
                                             const uint8_t peer[32],
                                             struct device_pairing_store *store)
{
    if (!identity || !peer || !store)
        return ZCL_ERR(1, "missing device pairing identity");
    static const uint8_t domain[] = "zcl.owner-device.profile.v1";
    bool first = memcmp(identity->public_key, peer, 32) < 0;
    uint8_t profile[32];
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, first ? identity->public_key : peer, 32);
    sha3_256_write(&hash, first ? peer : identity->public_key, 32);
    sha3_256_finalize(&hash, profile);
    if (!device_pairing_store_open(store, identity->directory, profile,
                                   identity->public_key))
        return ZCL_ERR(1, "device pairing profile unavailable");
    return ZCL_OK;
}
