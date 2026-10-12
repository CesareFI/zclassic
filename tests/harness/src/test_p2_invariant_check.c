/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_p2_invariant_check — regressions for the P2 self-heal invariant
 * diagnostic (tools/p2_invariant_check.c -> build/bin/p2_invariant_check).
 *
 * The tool asserts coins_applied_height (LE int64 blob in progress_meta)
 * equals the stage_cursor('utxo_apply') frontier, on a datadir (preferring
 * consensus.db over legacy progress.kv) or a direct store path, read-only.
 * Exit contract: 0 HOLDS, 1 MISMATCH (drift, malformed blob, missing
 * cursor), 2 ABSENT frontier (pre-P2, not a violation), 3 usage/open/read
 * error. These cases pin that contract and the LE wire encoding. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
#define P2_BIN "build/bin/p2_invariant_check.exe"
#else
#define P2_BIN "build/bin/p2_invariant_check"
#endif

static int p2_run(const char *path, const char *flags, char *buf, size_t cap)
{
    const char *argv[] = {P2_BIN, path, flags && flags[0] ? flags : NULL, NULL};
    return test_host_tool_capture(argv, buf, cap, 10000);
}

/* Create a store file with the given utxo_apply cursor and an
 * coins_applied_height blob (8-byte LE when frontier >= 0, a malformed
 * 4-byte blob when frontier < 0, omitted when frontier == -2). */
static bool p2_fixture(const char *store_path, int64_t cursor, int64_t frontier)
{
    (void)unlink(store_path);
    sqlite3 *db = NULL;
    if (sqlite3_open(store_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db,
        "CREATE TABLE stage_cursor(name TEXT PRIMARY KEY, cursor INTEGER);"
        "CREATE TABLE progress_meta(key TEXT PRIMARY KEY, value BLOB);",
        NULL, NULL, NULL) == SQLITE_OK;
    if (ok && cursor >= -1) {
        char sql[160];
        (void)snprintf(sql, sizeof(sql),
            "INSERT INTO stage_cursor VALUES('utxo_apply', %lld);",
            (long long)(cursor < 0 ? 0 : cursor));
        ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
        if (ok && cursor < 0)
            ok = sqlite3_exec(db, "DELETE FROM stage_cursor;", NULL, NULL,
                              NULL) == SQLITE_OK;
    }
    if (ok && frontier != -2) {
        if (frontier < 0) {
            ok = sqlite3_exec(db,
                "INSERT INTO progress_meta VALUES('coins_applied_height', "
                "x'01020304');",
                NULL, NULL, NULL) == SQLITE_OK;
        } else {
            uint8_t blob[8] = {0};
            uint64_t v = (uint64_t)frontier;
            for (int i = 0; i < 8; i++) blob[i] = (uint8_t)(v >> (8 * i));
            char sql[160];
            (void)snprintf(sql, sizeof(sql),
                "INSERT INTO progress_meta VALUES('coins_applied_height', "
                "?1);");
            sqlite3_stmt *st = NULL;
            ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                 sqlite3_bind_blob(st, 1, blob, 8, SQLITE_TRANSIENT) ==
                     SQLITE_OK &&
                 sqlite3_step(st) == SQLITE_DONE;
            if (st) sqlite3_finalize(st);
        }
    }
    sqlite3_close(db);
    return ok;
}

static int test_p2_verdicts(void)
{
    int failures = 0;
    char dir[4096], store[4608], buf[2048] = {0};
    test_make_tmpdir(dir, sizeof(dir), "p2_invariant", "verdicts");
    (void)snprintf(store, sizeof(store), "%s/progress.kv", dir);
    TEST("p2_invariant_check: HOLDS, drift, malformed, absent, missing cursor") {
        ASSERT(p2_fixture(store, 5, 5));
        ASSERT(p2_run(store, NULL, buf, sizeof(buf)) == 0);
        ASSERT(strstr(buf, "HOLDS") != NULL);

        ASSERT(p2_fixture(store, 5, 7));
        buf[0] = 0;
        ASSERT(p2_run(store, NULL, buf, sizeof(buf)) == 1);
        ASSERT(strstr(buf, "stage_cursor('utxo_apply') = 5") != NULL);

        ASSERT(p2_fixture(store, 5, -1)); /* malformed 4-byte blob */
        buf[0] = 0;
        ASSERT(p2_run(store, NULL, buf, sizeof(buf)) == 1);

        ASSERT(p2_fixture(store, 5, -2)); /* frontier row absent */
        buf[0] = 0;
        ASSERT(p2_run(store, NULL, buf, sizeof(buf)) == 2);
        ASSERT(strstr(buf, "ABSENT (pre-P2)") != NULL);

        ASSERT(p2_fixture(store, -1, 5)); /* cursor row absent */
        buf[0] = 0;
        ASSERT(p2_run(store, NULL, buf, sizeof(buf)) == 1);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_p2_encoding_and_dirs(void)
{
    int failures = 0;
    char dir[4096], kv[4608], cdb[4608], buf[2048] = {0};
    test_make_tmpdir(dir, sizeof(dir), "p2_invariant", "dirs");
    (void)snprintf(kv, sizeof(kv), "%s/progress.kv", dir);
    (void)snprintf(cdb, sizeof(cdb), "%s/consensus.db", dir);
    TEST("p2_invariant_check: LE wire, consensus.db preference, refusals") {
        /* A big-endian blob decodes as a huge LE value: drift, not HOLDS. */
        ASSERT(p2_fixture(kv, 5, 0));
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(kv, &db) == SQLITE_OK);
        ASSERT(sqlite3_exec(db,
            "UPDATE progress_meta SET value = x'0000000000000005' WHERE "
            "key='coins_applied_height';", NULL, NULL, NULL) == SQLITE_OK);
        sqlite3_close(db);
        buf[0] = 0;
        ASSERT(p2_run(kv, NULL, buf, sizeof(buf)) == 1);

        /* A datadir prefers consensus.db over legacy progress.kv. */
        ASSERT(p2_fixture(kv, 1, 99));   /* drift if wrongly read */
        ASSERT(p2_fixture(cdb, 5, 5));   /* HOLDS in the preferred store */
        buf[0] = 0;
        ASSERT(p2_run(dir, NULL, buf, sizeof(buf)) == 0);
        ASSERT(strstr(buf, "consensus.db") != NULL);

        /* --immutable reads a plain committed store fine. */
        ASSERT(p2_fixture(kv, 3, 3));
        buf[0] = 0;
        ASSERT(p2_run(kv, "--immutable", buf, sizeof(buf)) == 0);

        /* Missing store: exit 3. */
        (void)test_rm_rf_recursive(dir);
        test_make_tmpdir(dir, sizeof(dir), "p2_invariant", "missing");
        ASSERT(p2_run(dir, NULL, buf, sizeof(buf)) == 3);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

int test_p2_invariant_check(void)
{
    int failures = 0;
    struct stat st;
    if (stat(P2_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        printf("p2_invariant_check: build/bin/p2_invariant_check missing "
               "(run: make p2_invariant_check) — skipped\n");
        return 0;
    }
    failures += test_p2_verdicts();
    failures += test_p2_encoding_and_dirs();
    return failures;
}
