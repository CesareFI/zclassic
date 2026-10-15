/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: trusted private-profile initialization and read-only qualification. */
#include "test/test_core.h"
#include "services/device_identity.h"
#include "models/device_profile.h"
#include "platform/private_file.h"
#include "support/cleanse.h"
#include <stdio.h>
#include <string.h>

struct identity_fixture {
    char base[1024], profile[1200];
    struct device_identity identity;
    struct platform_private_file file;
};
static void fixture_init(struct identity_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    platform_private_file_init(&fixture->file);
}
static void fixture_close(struct identity_fixture *fixture)
{
    device_identity_test_interrupt(0);
    platform_private_file_close(&fixture->file);
    device_identity_close(&fixture->identity);
    if (fixture->base[0]) test_rm_rf(fixture->base);
}
static bool fixture_directory(struct identity_fixture *fixture)
{
    if (!test_mkdtemp(fixture->base, sizeof(fixture->base), "device-identity")) return false;
    int n = snprintf(fixture->profile, sizeof(fixture->profile), "%s/profile", fixture->base);
    return n > 0 && (size_t)n < sizeof(fixture->profile);
}
static bool identity_erased(const struct device_identity *identity)
{
    const uint8_t *bytes = (const uint8_t *)identity;
    uint8_t bits = 0;
    for (size_t i = 0; i < sizeof(*identity); ++i) bits |= bytes[i];
    return bits == 0;
}
#if !defined(_WIN32)
static bool fixture_file(struct identity_fixture *fixture, const char *leaf,
                          char path[1300])
{
    int n = snprintf(path, 1300, "%s/%s", fixture->profile, leaf);
    return n > 0 && n < 1300 && platform_private_file_open_locked(path, &fixture->file);
}

static int identity_create_and_reopen(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: durable initialization, observed reopen and create-only refusal") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_DURABLE);
        ASSERT(report.public_key_known);
        ASSERT(!memcmp(report.public_key, fixture.identity.public_key, 32));
        uint8_t expected[32];
        memcpy(expected, report.public_key, 32);
        device_identity_close(&fixture.identity);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(!memcmp(expected, fixture.identity.public_key, 32));
        struct zcl_result retry = device_identity_open(&fixture.identity, fixture.profile, true, &report);
        ASSERT(!retry.ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(!memcmp(expected, fixture.identity.public_key, 32));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_interrupted(unsigned stage)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: interrupted initialization preserves public facts, not secret output") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        device_identity_test_interrupt(stage);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_DURABILITY_UNKNOWN);
        ASSERT_EQ(report.public_key_known, stage != 1);
        ASSERT(identity_erased(&fixture.identity));
        uint8_t expected[32];
        memcpy(expected, report.public_key, 32);
        char pending[1300];
        int n = snprintf(pending, sizeof(pending), "%s/%s", fixture.profile, DEVICE_PROFILE_PENDING);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof(pending));
        ASSERT_EQ(platform_private_path_absent(pending), stage == 3);
        struct device_identity_publication_report observed;
        struct zcl_result read = device_identity_open(&fixture.identity, fixture.profile, false, &observed);
        ASSERT_EQ(read.ok, stage == 3);
        ASSERT_EQ(observed.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        if (stage == 3) ASSERT(!memcmp(expected, observed.public_key, 32));
        else ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_foreign_directory(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: foreign directory stays untouched and invalid arguments erase prior secrets") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(!device_identity_open(&fixture.identity, fixture.base, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        char key[1300];
        int n = snprintf(key, sizeof(key), "%s/v2_identity.key", fixture.base);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof(key));
        ASSERT(platform_private_path_absent(key));
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        ASSERT(!device_identity_open(&fixture.identity, NULL, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(!report.public_key_known);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(fixture.profile));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_profile_refusals(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: profile publication never replaces and zero or changed bytes refuse reads") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        uint8_t expected[32], wrong[32] = {9}, observed[32];
        memcpy(expected, report.public_key, 32);
        ASSERT(!db_device_profile_publish(fixture.profile, wrong));
        ASSERT(db_device_profile_read(fixture.profile, observed));
        ASSERT(!memcmp(expected, observed, 32));
        char path[1300];
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        uint8_t zero[32] = {0};
        ASSERT(platform_private_file_write_at(&fixture.file, zero, 32, 8));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        ASSERT(platform_private_file_write_at(&fixture.file, wrong, 32, 8));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        uint8_t extra = 1;
        ASSERT(platform_private_file_write_at(&fixture.file, &extra, 1, 40));
        platform_private_file_close(&fixture.file);
        ASSERT(!db_device_profile_read(fixture.profile, observed));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_missing_key(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: missing key is never recreated by read or initialization retry") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        char path[1300];
        ASSERT(fixture_file(&fixture, "v2_identity.key", path));
        ASSERT(platform_private_file_retire(&fixture.file, path));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(path));
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT(platform_private_path_absent(path));
        ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}
#else
static int identity_windows_creation_refused(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: Windows unsupported durability refuses creation without files or secret output") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        struct zcl_result result = device_identity_open(&fixture.identity, fixture.profile, true, &report);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "unsupported") != NULL);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(!report.public_key_known);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(platform_private_path_absent(fixture.profile));
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(fixture.profile));
        ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}
#endif

int test_device_identity(void);
int test_device_identity(void)
{
#if defined(_WIN32)
    return identity_windows_creation_refused();
#else
    return identity_create_and_reopen() + identity_interrupted(1) +
        identity_interrupted(2) + identity_interrupted(3) + identity_foreign_directory() +
        identity_profile_refusals() + identity_missing_key();
#endif
}
