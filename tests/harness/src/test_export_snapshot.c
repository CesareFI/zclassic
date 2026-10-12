/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_export_snapshot — regressions for the consensus snapshot exporter
 * (tools/export_snapshot.c -> build/bin/export_snapshot via `make
 * export_snapshot`).
 *
 * The exporter copies only the public consensus tables out of node.db
 * into consensus_snapshot.db. These cases pin its contract:
 *   - a normal datadir exports all seven public tables with their rows;
 *   - a datadir path containing an apostrophe does not break the ATTACH
 *     statement (the filename is parameter-bound);
 *   - a read-only node.db still exports (the source attaches mode=ro);
 *   - a datadir without node.db refuses with exit 1. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include "platform/directory_compat.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#define EXPORT_SNAPSHOT_BIN "build/bin/export_snapshot.exe"
#else
#define EXPORT_SNAPSHOT_BIN "build/bin/export_snapshot"
#endif

static int snapshot_run(const char *datadir, char *buf, size_t cap)
{
    const char *argv[] = {EXPORT_SNAPSHOT_BIN, datadir, NULL};
    return test_host_tool_capture(argv, buf, cap, 30000);
}

/* Create a node.db holding the seven public tables, one row each. */
static bool fixture_node_db(const char *datadir)
{
    char path[4608];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    static const char *const tables[] = {
        "blocks", "transactions", "utxos", "addresses",
        "chain_stats", "zslp_tokens", "zslp_balances", NULL};
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = true;
    for (size_t i = 0; ok && tables[i]; i++) {
        char sql[128];
        (void)snprintf(sql, sizeof(sql),
                       "CREATE TABLE %s(x); INSERT INTO %s VALUES(1);",
                       tables[i], tables[i]);
        ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    }
    sqlite3_close(db);
    return ok;
}

/* Verify the snapshot beside node.db holds every public table with its row. */
static bool snapshot_has_rows(const char *datadir, int value)
{
    char path[4608];
    int n = snprintf(path, sizeof(path), "%s/consensus_snapshot.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    static const char *const tables[] = {
        "blocks", "transactions", "utxos", "addresses",
        "chain_stats", "zslp_tokens", "zslp_balances", NULL};
    bool ok = true;
    for (size_t i = 0; ok && tables[i]; i++) {
        char sql[128];
        (void)snprintf(sql, sizeof(sql), "SELECT count(*), min(x), max(x) FROM %s",
                       tables[i]);
        sqlite3_stmt *st = NULL;
        ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_int(st, 0) == 1 &&
             sqlite3_column_int(st, 1) == value &&
             sqlite3_column_int(st, 2) == value;
        if (st) sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return ok;
}

static bool snapshot_has_tables(const char *datadir)
{
    return snapshot_has_rows(datadir, 1);
}

/* Compare the closed source's exact bytes around a real CLI invocation. */
static unsigned char *snapshot_read_file(const char *path, long *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    bool ok = fseek(f, 0, SEEK_END) == 0;
    *size = ok ? ftell(f) : -1;
    unsigned char *before = *size > 0 ? malloc((size_t)*size) : NULL;
    ok = before && fseek(f, 0, SEEK_SET) == 0 &&
         fread(before, 1, (size_t)*size, f) == (size_t)*size;
    if (fclose(f) != 0) ok = false;
    if (!ok) { free(before); return NULL; }
    return before;
}

static bool snapshot_file_equals(const char *path, const unsigned char *before,
                                 long size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = true;
    for (long i = 0; ok && i < size; i++)
        ok = fgetc(f) == before[i];
    if (ok) ok = fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool snapshot_preserves_source(const char *datadir, char *buf, size_t cap)
{
    char path[4608];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    long size = -1;
    unsigned char *before = snapshot_read_file(path, &size);
    bool ok = before && snapshot_run(datadir, buf, cap) == 0 &&
              snapshot_file_equals(path, before, size);
    free(before);
    return ok;
}

static bool fixture_set_blocks(const char *datadir, int value)
{
    char path[4608], sql[128];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    (void)snprintf(sql, sizeof(sql), "UPDATE blocks SET x=%d", value);
    bool ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static bool snapshot_block_value(const char *datadir, int value)
{
    char path[4608];
    int n = snprintf(path, sizeof(path), "%s/consensus_snapshot.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, "SELECT x FROM blocks", -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == value &&
              sqlite3_step(st) == SQLITE_DONE;
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

static int test_export_snapshot_paths(void)
{
    int failures = 0;
    char dir[4096], quoted[4608], buf[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "export_snapshot", "run");
    TEST("export_snapshot: normal, quoted, and read-only datadirs export") {
        ASSERT(fixture_node_db(dir));
        ASSERT(snapshot_run(dir, buf, sizeof(buf)) == 0);
        ASSERT(strstr(buf, "Exported 7 tables") != NULL);
        ASSERT(snapshot_has_tables(dir));

        /* An apostrophe in the datadir path must not break the ATTACH. */
        int n = snprintf(quoted, sizeof(quoted), "%s/it's-here", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        ASSERT(platform_directory_ensure(quoted, 0700));
        ASSERT(fixture_node_db(quoted));
        buf[0] = 0;
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 0);
        ASSERT(strstr(buf, "Exported 7 tables") != NULL);
        ASSERT(snapshot_has_tables(quoted));

        /* A UTF-8 directory with spaces must select its own source/output. */
        n = snprintf(quoted, sizeof(quoted), "%s/space \xc3\xa9 \xe6\xbc\xa2#%%41", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        ASSERT(platform_directory_ensure(quoted, 0700));
        ASSERT(fixture_node_db(quoted));
        ASSERT(fixture_set_blocks(quoted, 83));
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 0);
        ASSERT(snapshot_block_value(quoted, 83));
        ASSERT(snapshot_block_value(dir, 1));

        /* Direct argv capture must keep shell metacharacters literal. */
        n = snprintf(quoted, sizeof(quoted), "%s/argv$'%%41", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        ASSERT(platform_directory_ensure(quoted, 0700));
        ASSERT(fixture_node_db(quoted));
        ASSERT(fixture_set_blocks(quoted, 47));
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 0);
        ASSERT(snapshot_block_value(quoted, 47));

        /* %41 must select the literal directory, not its sibling A. */
        char sibling[4608];
        n = snprintf(quoted, sizeof(quoted), "%s/%%41", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        n = snprintf(sibling, sizeof(sibling), "%s/A", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(sibling));
        ASSERT(platform_directory_ensure(quoted, 0700));
        ASSERT(platform_directory_ensure(sibling, 0700));
        ASSERT(fixture_node_db(quoted));
        ASSERT(fixture_node_db(sibling));
        ASSERT(fixture_set_blocks(quoted, 41));
        ASSERT(fixture_set_blocks(sibling, 65));
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 0);
        ASSERT(snapshot_block_value(quoted, 41));

        /* URI-reserved characters (? # %) must survive as literal path
         * bytes, not be read as URI syntax. */
#if defined(_WIN32)
        /* '?' is not a Windows filename byte; '#' and '%' are literal. */
        n = snprintf(quoted, sizeof(quoted), "%s/uri#%%chars", dir);
#else
        n = snprintf(quoted, sizeof(quoted), "%s/uri?#%%chars", dir);
#endif
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        ASSERT(platform_directory_ensure(quoted, 0700));
        ASSERT(fixture_node_db(quoted));
        buf[0] = 0;
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 0);
        ASSERT(strstr(buf, "Exported 7 tables") != NULL);
        ASSERT(snapshot_has_tables(quoted));

#if defined(_WIN32)
        n = snprintf(quoted, sizeof(quoted), "%s/uri?chars", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(quoted));
        ASSERT(!platform_directory_ensure(quoted, 0700));
        ASSERT(snapshot_run(quoted, buf, sizeof(buf)) == 1);
#endif

        /* A read-only source still exports: the ATTACH is mode=ro. */
        char db_path[4608];
        (void)snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        ASSERT(chmod(db_path, 0444) == 0);
        char snap_path[4608];
        (void)snprintf(snap_path, sizeof(snap_path),
                       "%s/consensus_snapshot.db", dir);
        ASSERT(unlink(snap_path) == 0);
        buf[0] = 0;
        ASSERT(snapshot_preserves_source(dir, buf, sizeof(buf)));
        ASSERT(snapshot_has_tables(dir));
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_export_snapshot_live_wal(void)
{
    int failures = 0;
    char dir[4096], path[4608], buf[4096] = {0};
    sqlite3 *writer = NULL;
    test_make_tmpdir(dir, sizeof(dir), "export_snapshot", "wal");
    TEST("export_snapshot: committed live WAL rows are visible") {
        ASSERT(fixture_node_db(dir));
        int n = snprintf(path, sizeof(path), "%s/node.db", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(path));
        ASSERT(sqlite3_open(path, &writer) == SQLITE_OK);
        ASSERT(sqlite3_exec(writer, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
                           "UPDATE blocks SET x=73;", NULL, NULL, NULL) == SQLITE_OK);
        n = snprintf(path, sizeof(path), "%s/node.db-wal", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(path));
        struct stat wal;
        ASSERT(stat(path, &wal) == 0 && wal.st_size > 0);
        ASSERT(snapshot_run(dir, buf, sizeof(buf)) == 0);
        ASSERT(snapshot_block_value(dir, 73));
        PASS();
    } _test_next:;
    if (writer) sqlite3_close(writer);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

#ifndef _WIN32
static int test_export_snapshot_file_prefix(void)
{
    int failures = 0;
    char path[128], buf[4096] = {0};
    /* Windows forbids ':' in a directory component; this is a POSIX name. */
    (void)snprintf(path, sizeof(path), "file:export-snapshot-%ld", (long)getpid());
    TEST("export_snapshot: relative file: destination stays a literal path") {
        ASSERT(platform_directory_ensure(path, 0700));
        ASSERT(fixture_node_db(path));
        ASSERT(fixture_set_blocks(path, 91));
        ASSERT(snapshot_run(path, buf, sizeof(buf)) == 0);
        ASSERT(snapshot_block_value(path, 91));
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(path);
    return failures;
}
#endif

static int test_export_snapshot_refusals(void)
{
    int failures = 0;
    char dir[4096], buf[1024] = {0};
    test_make_tmpdir(dir, sizeof(dir), "export_snapshot", "refuse");
    TEST("export_snapshot: a datadir without node.db refuses with exit 1") {
        ASSERT(snapshot_run(dir, buf, sizeof(buf)) == 1);
        ASSERT(strstr(buf, "Exported") == NULL);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_export_snapshot_overlong(void)
{
    int failures = 0;
    char dir[4096], buf[1024] = {0};
    test_make_tmpdir(dir, sizeof(dir), "export_snapshot", "overlong");
    TEST("export_snapshot: overlong datadir refuses before deleting output") {
        ASSERT(fixture_node_db(dir));
        ASSERT(snapshot_run(dir, buf, sizeof(buf)) == 0);
        /* Redundant separators resolve to the same directory, while exceeding
         * every exporter path buffer. A refusal must preserve the snapshot. */
        char longdir[1024];
        size_t len = strlen(dir);
        ASSERT(len < sizeof(longdir) - 1);
        memcpy(longdir, dir, len);
        memset(longdir + len, '/', sizeof(longdir) - len - 1);
        longdir[sizeof(longdir) - 1] = 0;
        buf[0] = 0;
        ASSERT(snapshot_run(longdir, buf, sizeof(buf)) == 1);
        ASSERT(strstr(buf, "Source:") == NULL);
        ASSERT(snapshot_has_tables(dir));
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_export_snapshot_arguments(void)
{
    int failures = 0;
    char dir[4096], buf[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "export_snapshot", "arguments");
    TEST("export_snapshot: malformed arguments preserve existing output") {
        ASSERT(fixture_node_db(dir));
        ASSERT(snapshot_run(dir, buf, sizeof(buf)) == 0);
        ASSERT(fixture_set_blocks(dir, 29));
        const char *extra[] = {EXPORT_SNAPSHOT_BIN, dir, "unexpected", NULL};
        ASSERT(test_host_tool_capture(extra, buf, sizeof(buf), 30000) == 1);
        ASSERT(strstr(buf, "Exported") == NULL);
        ASSERT(snapshot_block_value(dir, 1));
        ASSERT(snapshot_run("", buf, sizeof(buf)) == 1);
        ASSERT(snapshot_run("--unknown", buf, sizeof(buf)) == 1);
        ASSERT(snapshot_block_value(dir, 1));
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

int test_export_snapshot(void)
{
    int failures = 0;
    struct stat st;
    if (stat(EXPORT_SNAPSHOT_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "export_snapshot: required build/bin/export_snapshot missing "
                        "(run: make export_snapshot)\n");
        return 1;
    }
    failures += test_export_snapshot_paths();
    failures += test_export_snapshot_refusals();
    failures += test_export_snapshot_overlong();
    failures += test_export_snapshot_arguments();
    failures += test_export_snapshot_live_wal();
#ifndef _WIN32
    failures += test_export_snapshot_file_prefix();
#endif
    return failures;
}
