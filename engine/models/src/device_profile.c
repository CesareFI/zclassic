/* purpose: Publish and validate owner-private device profiles without adopting incomplete identity state. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "models/device_profile.h"
#include "models/activerecord.h"
#include "platform/private_file.h"
#include "platform/positioned_file.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

static const uint8_t profile_magic[8] = {'Z','2','3','O','W','N',1,0};
struct device_profile_row { uint8_t public_key[32]; };

static bool profile_validate(const struct device_profile_row *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    uint8_t bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= row->public_key[i];
    validates_custom(errors, bits != 0, "identity", "must be nonzero");
    return !ar_errors_any(errors);
}

bool db_device_profile_publish(const char *directory, const uint8_t public_key[32])
{
    if (!directory || !public_key) LOG_FAIL("device_profile", "missing identity");
    struct device_profile_row row;
    memcpy(row.public_key, public_key, 32);
    struct ar_callbacks callbacks = {0};
    AR_BEGIN_SAVE(&callbacks, "device_profile", &row, profile_validate);
    char path[1200];
    int n = snprintf(path, sizeof(path), "%s/owner-device.profile", directory);
    if (n < 0 || (size_t)n >= sizeof(path)) LOG_FAIL("device_profile", "path too long");
    uint8_t wire[40];
    memcpy(wire, profile_magic, 8);
    memcpy(wire + 8, row.public_key, 32);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create_locked(path, &file) &&
        platform_private_file_write_at(&file, wire, sizeof(wire), 0) &&
        platform_private_file_authority_flush(&file) &&
        platform_private_parent_flush(directory);
    platform_private_file_close(&file);
    if (!ok) LOG_ERROR("device_profile", "profile publication incomplete; reconcile");
    AR_FINISH_SAVE(&callbacks, &row, ok);
}

bool db_device_profile_read(const char *directory, uint8_t public_key[32])
{
    if (!directory || !public_key) LOG_FAIL("device_profile", "missing identity");
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    struct platform_positioned_file_snapshot before, after;
    uint8_t wire[40];
    bool ok = platform_positioned_file_open_beneath(&file, directory, "owner-device.profile") &&
        platform_positioned_file_is_private(&file) &&
        platform_positioned_file_snapshot(&file, &before) && before.size == sizeof(wire) &&
        platform_positioned_file_read(&file, wire, sizeof(wire), 0) == sizeof(wire) &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok || memcmp(wire, profile_magic, 8))
        LOG_FAIL("device_profile", "not a stable initialized owner-device profile");
    struct device_profile_row row;
    memcpy(row.public_key, wire + 8, 32);
    struct ar_errors errors;
    if (!profile_validate(&row, &errors))
        LOG_FAIL("device_profile", "invalid public identity: %s", ar_errors_full(&errors));
    memcpy(public_key, row.public_key, 32);
    return true;
}
