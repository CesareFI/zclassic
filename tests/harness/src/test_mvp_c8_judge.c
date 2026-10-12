/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mvp_c8_judge — executes the C8 genesis-canary judge lifted from
 * tools/mvp_gate.sh against fixture verdict files
 * (tests/harness/mvp_c8_judge_cases.sh) and asserts the exact status token
 * and refusal marker for each case: absent, stale, wrong source id, wrong
 * artifact hash, FAIL verdict, height skew beyond TIP_GAP_OK, and valid. */

#include "test/test_core.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "platform/os_proc.h"
#include <sys/stat.h>

/* Walk UP from the test binary to the tree holding Makefile and the judge. */
static const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached = 0;
    if (cached) return root[0] ? root : NULL;
    cached = 1; root[0] = '\0';
    char exe[PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe))) return NULL;
    for (int depth = 0; depth < 8; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';
        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe) >= (int)sizeof(probe)) break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/tools/mvp_gate.sh", exe) >= (int)sizeof(probe)) break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(root, sizeof(root), "%s", exe) >= (int)sizeof(root)) root[0] = '\0';
        break;
    }
    return root[0] ? root : NULL;
}


static int test_c8_judge_cases(void)
{
    int failures = 0;
    TEST("mvp gate: C8 judge verdict mapping over fixture verdict files") {
        const char *root = repo_root();
        ASSERT(root != NULL);
        char script[PATH_MAX];
        ASSERT(snprintf(script, sizeof(script),
                        "%s/tests/harness/mvp_c8_judge_cases.sh", root) <
               (int)sizeof(script));
        const char *argv[] = {"bash", script, root, NULL};
        char out[2048];
        int rc = zcl_spawn_capture(argv, out, sizeof(out), 60000);
        if (rc != 0) fprintf(stderr, "c8 judge cases rc=%d output=%s\n", rc, out);
        ASSERT(rc == 0);
        ASSERT(strstr(out, "CASE absent VERDICT=BLOCKED FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE stale VERDICT=BLOCKED FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE wrong_source VERDICT=BLOCKED FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE wrong_artifact VERDICT=BLOCKED FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE verdict_fail VERDICT=FAIL FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE height_skew VERDICT=FAIL FULL=0\n") != NULL);
        ASSERT(strstr(out, "CASE height_edge VERDICT=PASS FULL=1\n") != NULL);
        ASSERT(strstr(out, "CASE valid VERDICT=PASS FULL=1\n") != NULL);
        ASSERT(strstr(out, "mvp_c8_judge: ALL CASES OK\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_mvp_c8_judge(void)
{
    int failures = 0;
    printf("\n=== MVP C8 judge verdict tests ===\n");
    failures += test_c8_judge_cases();
    printf("MVP C8 judge: %d failures\n", failures);
    return failures;
}
