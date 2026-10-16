/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: hermetic retained-object SQLite reader qualification. */
#define _DEFAULT_SOURCE
#include "test/test_core.h"
#include "storage/sqlite_pinned_reader.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>

static bool fixture(const char *path, int value)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) rc = sqlite3_exec(db,
        "CREATE TABLE item(value INTEGER);", NULL, NULL, NULL);
    sqlite3_stmt *s = NULL;
    if (rc == SQLITE_OK) rc = sqlite3_prepare_v2(db,
        "INSERT INTO item VALUES(?1)", -1, &s, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(s, 1, value);
    if (rc == SQLITE_OK) rc = sqlite3_step(s) == SQLITE_DONE
        ? SQLITE_OK : SQLITE_ERROR;
    int final = sqlite3_finalize(s);
    int close = sqlite3_close(db);
    return rc == SQLITE_OK && final == SQLITE_OK && close == SQLITE_OK;
}
static bool value_is(sqlite3 *db, int expected)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT value FROM item", -1, &s, NULL);
    bool ok = rc == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW &&
        sqlite3_column_int(s, 0) == expected && sqlite3_step(s) == SQLITE_DONE;
    int final = sqlite3_finalize(s);
    return ok && final == SQLITE_OK;
}
static bool callback_checks(sqlite3 *db, uint64_t size)
{
    sqlite3_file *file = NULL;
    if (sqlite3_file_control(db, "main", SQLITE_FCNTL_FILE_POINTER,
                            &file) != SQLITE_OK || !file) return false;
    unsigned char bytes[16];
    memset(bytes, 0xab, sizeof(bytes));
    int short_rc = file->pMethods->xRead(file, bytes, sizeof(bytes),
                                       (sqlite3_int64)size - 3);
    bool zero = true;
    for (size_t i = 3; i < sizeof(bytes); ++i) zero &= bytes[i] == 0;
    return short_rc == SQLITE_IOERR_SHORT_READ && zero &&
        file->pMethods->xRead(file, bytes, 1, -1) == SQLITE_IOERR_READ &&
        file->pMethods->xRead(file, bytes, 2, INT64_MAX) == SQLITE_IOERR_READ &&
        file->pMethods->xWrite(file, bytes, 1, 0) == SQLITE_READONLY &&
        file->pMethods->xTruncate(file, 0) == SQLITE_READONLY &&
        file->pMethods->xLock(file, SQLITE_LOCK_EXCLUSIVE) == SQLITE_READONLY &&
        file->pMethods->xFileControl(file, -12345, bytes) == SQLITE_NOTFOUND;
}
static bool namespace_checks(sqlite3 *db, char **saved_token)
{
    const char *token = sqlite3_db_filename(db, "main");
    if (!token) return false;
    *saved_token = sqlite3_mprintf("%s", token);
    sqlite3 *other = NULL;
    int rc = sqlite3_open_v2(token, &other, SQLITE_OPEN_READONLY,
                            "zcl-pinned-reader-v1");
    int close = sqlite3_close(other);
    if (rc == SQLITE_OK || close != SQLITE_OK) return false;
    rc = sqlite3_open_v2("unknown-token", &other, SQLITE_OPEN_READONLY,
                         "zcl-pinned-reader-v1");
    close = sqlite3_close(other);
    if (rc == SQLITE_OK || close != SQLITE_OK) return false;
    return sqlite3_exec(db, "ATTACH 'untrusted-sidecar' AS bad", NULL,
                        NULL, NULL) != SQLITE_OK;
}
static bool capacity_checks(const struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *snapshot)
{
    struct sqlite_pinned_reader *held[64] = {0};
    struct sqlite_pinned_reader *excess = NULL;
    size_t count = 0;
    while (count < 64 && sqlite_pinned_reader_open(file, snapshot, &held[count]))
        ++count;
    bool ok = count == 64 &&
        !sqlite_pinned_reader_open(file, snapshot, &excess) && excess == NULL;
    if (excess && !sqlite_pinned_reader_close(&excess)) ok = false;
    while (count > 0) {
        --count;
        if (!sqlite_pinned_reader_close(&held[count])) ok = false;
    }
    return ok;
}
struct reader_fixture {
    char root[128], directory[512], moved[512], path[512], retained[512];
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot expected;
};
static bool setup_fixture(struct reader_fixture *f)
{
    platform_positioned_file_init(&f->file);
    if (!test_mkdtemp(f->root, sizeof(f->root), "sqlite_pinned_reader"))
        return false;
    snprintf(f->directory, sizeof(f->directory), "%s/current", f->root);
    snprintf(f->moved, sizeof(f->moved), "%s/retained", f->root);
    snprintf(f->path, sizeof(f->path), "%s/current/input.db", f->root);
    snprintf(f->retained, sizeof(f->retained), "%s/retained/input.db", f->root);
    return mkdir(f->directory, 0700) == 0 && fixture(f->path, 17) &&
        platform_positioned_file_open(&f->file, f->path) &&
        platform_positioned_file_snapshot(&f->file, &f->expected) &&
        rename(f->directory, f->moved) == 0 &&
        mkdir(f->directory, 0700) == 0 && fixture(f->path, 29);
}
static bool close_reader(struct sqlite_pinned_reader **r, bool ok)
{
    bool closed = !*r || sqlite_pinned_reader_close(r);
    return ok && closed;
}
static bool selected_object(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    bool selected = value_is(sqlite_pinned_reader_db(r), 17);
    bool callbacks = callback_checks(sqlite_pinned_reader_db(r), f->expected.size);
    bool ok = selected && callbacks;
    if (!ok) printf("selected_object: select=%d callbacks=%d SQLite=%s\n",
                    selected, callbacks, sqlite3_errmsg(sqlite_pinned_reader_db(r)));
    return close_reader(&r, ok);
}
static bool query_julian_day(sqlite3 *db, double *out)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT julianday('now')", -1, &stmt, NULL);
    bool row = rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW;
    if (row) *out = sqlite3_column_double(stmt, 0);
    bool done = row && sqlite3_step(stmt) == SQLITE_DONE;
    int final = sqlite3_finalize(stmt);
    return done && final == SQLITE_OK;
}
/* Compare two implementations of SQLite's time interface, not a runtime
 * deadline: the VFS v1 callback must preserve the host's Julian-day units. */
static bool time_interface(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    sqlite3 *reference = NULL;
    int opened = sqlite3_open(":memory:", &reference);
    double actual = 0, expected = 0;
    bool queried = opened == SQLITE_OK &&
        query_julian_day(sqlite_pinned_reader_db(r), &actual) &&
        query_julian_day(reference, &expected);
    int closed = sqlite3_close(reference);
    double difference = actual - expected;
    bool units_match = difference >= -1.0 / 86400.0 &&
                       difference <= 1.0 / 86400.0;
    return close_reader(&r, queried && closed == SQLITE_OK && units_match);
}
/* Test-only SQLite auto-extension: keep a statement alive, then reject the
 * adapter's configuration PRAGMA. This forces checked failed-open close BUSY
 * without production fault hooks or changing the SQLite allocator globally. */
static sqlite3_stmt *failed_open_statement;
static int refuse_configuration(void *context, int action, const char *first,
    const char *second, const char *database, const char *trigger)
{
    (void)context; (void)first; (void)second; (void)database; (void)trigger;
    return action == SQLITE_PRAGMA ? SQLITE_DENY : SQLITE_OK;
}
static int retain_failed_open_statement(sqlite3 *db, char **error,
                                        const sqlite3_api_routines *api)
{
    (void)error; (void)api;
    int rc = sqlite3_prepare_v2(db, "SELECT 1", -1, &failed_open_statement, NULL);
    if (rc != SQLITE_OK) return rc;
    return sqlite3_set_authorizer(db, refuse_configuration, NULL);
}
static bool failed_open_ownership(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    failed_open_statement = NULL;
    int registered = sqlite3_auto_extension(
        (void (*)(void))retain_failed_open_statement);
    bool opened = registered == SQLITE_OK &&
        sqlite_pinned_reader_open(&f->file, &f->expected, &r);
    (void)sqlite3_cancel_auto_extension(
        (void (*)(void))retain_failed_open_statement);
    bool retained = !opened && r != NULL && failed_open_statement != NULL &&
        sqlite_pinned_reader_db(r) == NULL;
    /* Finalize and checked close precede every assertion by the caller. */
    int finalized = sqlite3_finalize(failed_open_statement);
    failed_open_statement = NULL;
    bool closed = r && sqlite_pinned_reader_close(&r);
    (void)sqlite3_cancel_auto_extension(
        (void (*)(void))retain_failed_open_statement);
    return registered == SQLITE_OK && retained && finalized == SQLITE_OK &&
        closed && r == NULL;
}
static bool busy_lifetime(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    sqlite3_stmt *stmt = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    int rc = sqlite3_prepare_v2(sqlite_pinned_reader_db(r),
        "SELECT value FROM item", -1, &stmt, NULL);
    bool ok = rc == SQLITE_OK && !sqlite_pinned_reader_close(&r) && r != NULL;
    int final = sqlite3_finalize(stmt);
    return close_reader(&r, ok && final == SQLITE_OK);
}
static bool token_lifetime(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL, *second = NULL;
    char *token = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    bool ok = namespace_checks(sqlite_pinned_reader_db(r), &token);
    if (!close_reader(&r, ok)) ok = false;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) ok = false;
    sqlite3 *stale = NULL;
    int rc = sqlite3_open_v2(token ? token : "absent", &stale,
        SQLITE_OPEN_READONLY, "zcl-pinned-reader-v1");
    int closed = sqlite3_close(stale);
    if (rc == SQLITE_OK || closed != SQLITE_OK) ok = false;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &second)) ok = false;
    if (second && !value_is(sqlite_pinned_reader_db(second), 17)) ok = false;
    sqlite3_free(token);
    bool second_closed = close_reader(&second, true);
    return close_reader(&r, ok && second_closed);
}
/* Exercise the real registered VFS entry at the precise pre-claim boundary.
 * A temporary callback interposer is a fixture use of SQLite's existing VFS
 * interface, not a production test hook. The test group owns this VFS. */
static int (*real_open)(sqlite3_vfs *, const char *, sqlite3_file *, int, int *);
struct competing_open {
    sqlite3_vfs *vfs;
    const char *token;
    int flags;
    int result;
};
static void *try_competing_open(void *context)
{
    struct competing_open *c = context;
    sqlite3_file *file = calloc(1, (size_t)c->vfs->szOsFile);
    if (!file) { c->result = SQLITE_NOMEM; return NULL; }
    c->result = real_open(c->vfs, c->token, file, c->flags, NULL);
    if (file->pMethods) TEST_DISCARD(file->pMethods->xClose(file));
    free(file);
    return NULL;
}
static int contention_result;
static int contended_open(sqlite3_vfs *vfs, const char *name,
    sqlite3_file *file, int flags, int *out)
{
    struct competing_open c = {vfs, name, flags, SQLITE_ERROR};
    pthread_t thread;
    if (pthread_create(&thread, NULL, try_competing_open, &c) != 0)
        return SQLITE_ERROR;
    if (pthread_join(thread, NULL) != 0) return SQLITE_ERROR;
    contention_result = c.result;
    return real_open(vfs, name, file, flags, out);
}
static bool opening_capability(struct reader_fixture *f)
{
    sqlite3_vfs *vfs = sqlite3_vfs_find("zcl-pinned-reader-v1");
    if (!vfs) return false;
    struct sqlite_pinned_reader *r = NULL;
    real_open = vfs->xOpen;
    contention_result = SQLITE_OK;
    vfs->xOpen = contended_open;
    bool opened = sqlite_pinned_reader_open(&f->file, &f->expected, &r);
    vfs->xOpen = real_open;
    bool ok = opened && contention_result == SQLITE_CANTOPEN;
    if (r && !value_is(sqlite_pinned_reader_db(r), 17)) ok = false;
    return close_reader(&r, ok);
}
static bool retained_callback_identity(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    sqlite3_file *file = NULL;
    int rc = sqlite3_file_control(sqlite_pinned_reader_db(r), "main",
                                  SQLITE_FCNTL_FILE_POINTER, &file);
    int fd = open(f->path, O_WRONLY);
    unsigned char zero = 0;
    ssize_t wrote = fd >= 0 ? pwrite(fd, &zero, 1, 0) : -1;
    int closed = fd >= 0 ? close(fd) : -1;
    bool ok = rc == SQLITE_OK && file && wrote == 1 && closed == 0;
    if (ok) {
        unsigned char first = 0;
        ok = file->pMethods->xRead(file, &first, 1, 0) == SQLITE_OK &&
            first == 'S';
    }
    return close_reader(&r, ok);
}
static bool replace_same_bytes(struct reader_fixture *f)
{
    /* Copy A to B using retained positioned reads. The SQL result can no
     * longer distinguish them. Change only B afterward, then force a direct
     * callback read of its changed byte: A's byte must still be returned. */
    unsigned char bytes[4096];
    int out = open(f->path, O_WRONLY | O_TRUNC);
    if (out < 0) return false;
    uint64_t offset = 0;
    bool ok = true;
    while (offset < f->expected.size) {
        int64_t got = platform_positioned_file_read(&f->file, bytes,
                                                    sizeof(bytes), offset);
        if (got <= 0) { ok = false; break; }
        if (write(out, bytes, (size_t)got) != got) { ok = false; break; }
        offset += (uint64_t)got;
    }
    if (close(out) != 0) ok = false;
    struct platform_positioned_file replacement;
    platform_positioned_file_init(&replacement);
    struct platform_positioned_file_snapshot other;
    if (!platform_positioned_file_open(&replacement, f->path)) return false;
    bool identity = platform_positioned_file_snapshot(&replacement, &other) &&
        (other.volume != f->expected.volume ||
         other.file_low != f->expected.file_low ||
         other.file_high != f->expected.file_high);
    platform_positioned_file_close(&replacement);
    return ok && identity && selected_object(f) && retained_callback_identity(f);
}
static bool mutation_refusal(struct reader_fixture *f)
{
    struct sqlite_pinned_reader *r = NULL;
    if (!sqlite_pinned_reader_open(&f->file, &f->expected, &r)) return false;
    sqlite3_file *file = NULL;
    int rc = sqlite3_file_control(sqlite_pinned_reader_db(r), "main",
                                  SQLITE_FCNTL_FILE_POINTER, &file);
    int fd = open(f->retained, O_WRONLY);
    unsigned char changed = 0;
    ssize_t wrote = fd >= 0 ? pwrite(fd, &changed, 1, 0) : -1;
    int closed = fd >= 0 ? close(fd) : -1;
    bool ok = rc == SQLITE_OK && file && wrote == 1 && closed == 0;
    if (ok) {
        unsigned char byte;
        sqlite3_int64 size = -1;
        ok = file->pMethods->xRead(file, &byte, 1, 0) == SQLITE_IOERR_READ &&
            file->pMethods->xFileSize(file, &size) == SQLITE_IOERR_FSTAT;
    }
    return close_reader(&r, ok);
}
/* All adapters/statements created by earlier scenarios are closed here.
 * Match the existing isolated agent-posture fixture's shutdown/init rail. */
static bool shutdown_reopen(struct reader_fixture *f)
{
    if (sqlite3_shutdown() != SQLITE_OK) return false;
    bool ok = selected_object(f);
    /* Leave the test runner's SQLite runtime initialized on all outcomes. */
    int initialized = sqlite3_initialize();
    return ok && initialized == SQLITE_OK;
}
static bool wal_refusal(struct reader_fixture *f)
{
    int fd = open(f->retained, O_WRONLY);
    if (fd < 0) return false;
    unsigned char header[20] = "SQLite format 3";
    header[16] = 0x10; header[17] = 0;
    header[18] = 2; header[19] = 2;
    ssize_t wrote = pwrite(fd, header, sizeof(header), 0);
    int closed = close(fd);
    if (wrote != sizeof(header) || closed != 0) return false;
    if (!platform_positioned_file_snapshot(&f->file, &f->expected)) return false;
    struct sqlite_pinned_reader *r = NULL;
    bool refused = !sqlite_pinned_reader_open(&f->file, &f->expected, &r);
    return close_reader(&r, refused && r == NULL);
}
int test_sqlite_pinned_reader(void)
{
    int failures = 0;
    struct reader_fixture f = {0};
    TEST_CASE("sqlite pinned reader: object, namespace and failure lifetime") {
        ASSERT(setup_fixture(&f));
        ASSERT(selected_object(&f));
        ASSERT(time_interface(&f));
        ASSERT(failed_open_ownership(&f));
        ASSERT(busy_lifetime(&f));
        ASSERT(token_lifetime(&f));
        ASSERT(opening_capability(&f));
        ASSERT(capacity_checks(&f.file, &f.expected));
        ASSERT(replace_same_bytes(&f));
        ASSERT(shutdown_reopen(&f));
        ASSERT(mutation_refusal(&f));
        ASSERT(wal_refusal(&f));
    } TEST_END;
    platform_positioned_file_close(&f.file);
    if (f.root[0]) {
        TEST_DISCARD(unlink(f.path)); TEST_DISCARD(unlink(f.retained));
        TEST_DISCARD(rmdir(f.directory)); TEST_DISCARD(rmdir(f.moved));
        TEST_DISCARD(rmdir(f.root));
    }
    return failures;
}
#else
int test_sqlite_pinned_reader(void)
{
    printf("sqlite_pinned_reader: SKIP (Windows): POSIX fixtures unavailable\n");
    return 0;
}
#endif
