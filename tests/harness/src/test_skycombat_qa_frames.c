/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: verify bounded QA frame arguments and unchanged output on refusal. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "sky_combat/qa_frames.h"
#include <string.h>

#if defined(_WIN32)
#define QA_ENTRY "build/bin/skycombat-qa-entrypoint.exe"
#else
#define QA_ENTRY "build/bin/skycombat-qa-entrypoint"
#endif

static int skycombat_qa_launch(const char *arg, const char *fixture,
                               unsigned frames, int status, unsigned windows)
{
    int failures = 0;
    const char *argv[4] = {QA_ENTRY, NULL, NULL, NULL};
    unsigned next = 1;
    if (fixture) argv[next++] = fixture;
    if (arg) argv[next] = arg;
    char output[2048] = {0}, expected[128];
    int length = snprintf(expected, sizeof(expected),
        "QA_TEST status=%d windows=%u frames=%u closed=%u destroyed=%u unloads=%u",
        status, windows, frames,
        fixture && strcmp(fixture, "--fixture-window-fails") == 0 ? 0u : windows,
        frames ? 127u : 0u, frames ? 1u : 0u);
    TEST("QA launch: actual entrypoint refuses before window or ends at exact frame bound") {
        ASSERT(length > 0 && (size_t)length < sizeof(expected));
        int rc = test_host_tool_capture(argv, output, sizeof(output), 5000);
        if (rc != status || !strstr(output, expected)) fprintf(stderr, "%s", output);
        ASSERT_EQ(rc, status); ASSERT(strstr(output, expected) != NULL);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "QA launch argument=%s fixture=%s\n",
        arg ? arg : "interactive", fixture ? fixture : "none");
    return failures;
}

int test_skycombat_qa_frames(void);
int test_skycombat_qa_frames(void)
{
    int failures = 0;
    TEST("QA frames: absent argument preserves interactive selection") {
        char *args[] = {"skycombat", NULL};
        unsigned out = 99;
        ASSERT(sky_combat_qa_frames_parse(1, args, &out));
        ASSERT_EQ(out, 0u);
    }
    TEST("QA frames: canonical lower, ordinary and upper bounds") {
        const struct { char *arg; unsigned expected; } valid[] = {
            {"--qa-frames=1", 1}, {"--qa-frames=60", 60},
            {"--qa-frames=3599", 3599}, {"--qa-frames=3600", 3600}
        };
        for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
            char *args[] = {"skycombat", valid[i].arg};
            unsigned out = 99;
            ASSERT(sky_combat_qa_frames_parse(2, args, &out));
            ASSERT_EQ(out, valid[i].expected);
        }
    }
    TEST("QA frames: malformed, noncanonical and overflowing spans refuse unchanged") {
        char *invalid[] = {
            "--qa-frames=", "--qa-frames=0", "--qa-frames=01",
            "--qa-frames=-1", "--qa-frames=+1", "--qa-frames= 1", "--qa-frames=1 ",
            "--qa-frames=1x", "--qa-frames=1.0", "--qa-frames=3601",
            "--qa-frames=4294967296", "--qa-frames=99999999999999999999999999",
            "--qa-frames", "--help", "", "--qa-frames=1\n"
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            char *args[] = {"skycombat", invalid[i]};
            unsigned out = 99;
            ASSERT(!sky_combat_qa_frames_parse(2, args, &out));
            ASSERT_EQ(out, 99u);
        }
    }
    TEST("QA frames: duplicate, missing and invalid call shape refuse unchanged") {
        char *args[] = {"skycombat", "--qa-frames=1", "--qa-frames=2"};
        unsigned out = 99;
        ASSERT(!sky_combat_qa_frames_parse(3, args, &out));
        ASSERT_EQ(out, 99u);
        ASSERT(!sky_combat_qa_frames_parse(2, args, NULL));
        ASSERT(!sky_combat_qa_frames_parse(0, args, &out));
        ASSERT_EQ(out, 99u);
        args[1] = NULL;
        ASSERT(!sky_combat_qa_frames_parse(2, args, &out));
        ASSERT_EQ(out, 99u);
        ASSERT(!sky_combat_qa_frames_parse(1, NULL, &out));
        ASSERT_EQ(out, 99u);
    }
_test_next:;
    const char *invalid_launch[] = {"--qa-frames=0", "--qa-frames=-1",
        "--qa-frames=word", "--qa-frames=4294967296",
        "--qa-frames=99999999999999999999999999", "--qa-frames=3601"};
    for (size_t i = 0; i < sizeof(invalid_launch) / sizeof(invalid_launch[0]); ++i)
        failures += skycombat_qa_launch(invalid_launch[i], NULL, 0, 2, 0);
    failures += skycombat_qa_launch("--qa-frames=1", NULL, 1, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=2", NULL, 2, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=60", NULL, 60, 0, 1);
    failures += skycombat_qa_launch(NULL, "--fixture-close=2", 2, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=3", "--fixture-close=2", 2, 1, 1);
    failures += skycombat_qa_launch("--qa-frames=1", "--fixture-window-fails", 0, 1, 1);
    return failures;
}
