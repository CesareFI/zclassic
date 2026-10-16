/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded read-only SQLite namespace over already-retained files. */
#include "storage/sqlite_pinned_reader.h"
#include "util/log_macros.h"
#include <sqlite3.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PINNED_LIMIT 64u
#define PINNED_NAME_MAX 48
#define PINNED_VFS_NAME "zcl-pinned-reader-v1"
struct sqlite_pinned_reader {
    sqlite3 *db;
    const struct platform_positioned_file *file;
    struct platform_positioned_file_snapshot expected;
    char token[PINNED_NAME_MAX];
    bool reserved;
    bool opened;
    bool ready;
};
struct pinned_file {
    sqlite3_file base;
    struct sqlite_pinned_reader *owner;
    int lock;
};
static struct sqlite_pinned_reader slots[PINNED_LIMIT];
static uint64_t next_token;
static sqlite3_vfs pinned_vfs;
static sqlite3_vfs *host_vfs;
static bool vfs_initialized;
/* Only the wrapper thread may claim its reserved main-file token. A token
 * names a binding but is never itself an opening capability. */
static _Thread_local struct sqlite_pinned_reader *opening_reader;
static const sqlite3_io_methods pinned_methods;

static sqlite3_mutex *registry_mutex(void)
{
    return sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_APP1);
}
static bool stable(const struct sqlite_pinned_reader *reader)
{
    struct platform_positioned_file_snapshot now;
    return platform_positioned_file_snapshot(reader->file, &now) &&
        platform_positioned_file_snapshot_equal(&now, &reader->expected);
}
static struct sqlite_pinned_reader *lookup(const char *token)
{
    if (!token) return NULL;
    for (size_t i = 0; i < PINNED_LIMIT; ++i) {
        if (slots[i].reserved && strcmp(slots[i].token, token) == 0)
            return &slots[i];
    }
    return NULL;
}
static int file_close(sqlite3_file *file)
{
    struct pinned_file *p = (struct pinned_file *)file;
    sqlite3_mutex_enter(registry_mutex());
    p->owner->opened = false;
    p->owner = NULL;
    p->base.pMethods = NULL;
    sqlite3_mutex_leave(registry_mutex());
    return SQLITE_OK;
}
static int file_read(sqlite3_file *file, void *buffer, int amount,
                     sqlite3_int64 offset)
{
    struct pinned_file *p = (struct pinned_file *)file;
    if (amount < 0 || offset < 0 ||
        (uint64_t)offset > (uint64_t)INT64_MAX - (uint64_t)amount)
        return SQLITE_IOERR_READ;
    if (!stable(p->owner)) return SQLITE_IOERR_READ;
    size_t done = 0;
    while (done < (size_t)amount) {
        int64_t got = platform_positioned_file_read(p->owner->file,
            (unsigned char *)buffer + done, (size_t)amount - done,
            (uint64_t)offset + done);
        if (got < 0) return SQLITE_IOERR_READ;
        if (got == 0) {
            memset((unsigned char *)buffer + done, 0, (size_t)amount - done);
            return SQLITE_IOERR_SHORT_READ;
        }
        if ((uint64_t)got > (size_t)amount - done) return SQLITE_IOERR_READ;
        done += (size_t)got;
    }
    return stable(p->owner) ? SQLITE_OK : SQLITE_IOERR_READ;
}
static int file_write(sqlite3_file *file, const void *data, int n,
                      sqlite3_int64 offset)
{
    (void)file; (void)data; (void)n; (void)offset;
    return SQLITE_READONLY;
}
static int file_truncate(sqlite3_file *file, sqlite3_int64 size)
{
    (void)file; (void)size; return SQLITE_READONLY;
}
static int file_sync(sqlite3_file *file, int flags)
{
    (void)file; (void)flags; return SQLITE_READONLY;
}
static int file_size(sqlite3_file *file, sqlite3_int64 *size)
{
    struct pinned_file *p = (struct pinned_file *)file;
    if (!stable(p->owner) || p->owner->expected.size > INT64_MAX)
        return SQLITE_IOERR_FSTAT;
    *size = (sqlite3_int64)p->owner->expected.size;
    return SQLITE_OK;
}
static int file_lock(sqlite3_file *file, int lock)
{
    struct pinned_file *p = (struct pinned_file *)file;
    if (lock != SQLITE_LOCK_NONE && lock != SQLITE_LOCK_SHARED)
        return SQLITE_READONLY;
    p->lock = lock;
    return SQLITE_OK;
}
static int file_reserved(sqlite3_file *file, int *out)
{
    (void)file; *out = 0; return SQLITE_OK;
}
static int file_control(sqlite3_file *file, int op, void *argument)
{
    struct pinned_file *p = (struct pinned_file *)file;
    if (op == SQLITE_FCNTL_LOCKSTATE) {
        *(int *)argument = p->lock; return SQLITE_OK;
    }
    if (op == SQLITE_FCNTL_VFSNAME) {
        char *name = sqlite3_mprintf("%s", PINNED_VFS_NAME);
        if (!name) return SQLITE_NOMEM;
        *(char **)argument = name; return SQLITE_OK;
    }
    if (op == SQLITE_FCNTL_HAS_MOVED) {
        *(int *)argument = 0; return SQLITE_OK;
    }
    return SQLITE_NOTFOUND;
}
static int file_sector(sqlite3_file *file)
{
    (void)file; return 4096;
}
static int file_characteristics(sqlite3_file *file)
{
    (void)file; return SQLITE_IOCAP_IMMUTABLE;
}
static const sqlite3_io_methods pinned_methods = {
    .iVersion = 1, .xClose = file_close, .xRead = file_read,
    .xWrite = file_write, .xTruncate = file_truncate, .xSync = file_sync,
    .xFileSize = file_size, .xLock = file_lock, .xUnlock = file_lock,
    .xCheckReservedLock = file_reserved, .xFileControl = file_control,
    .xSectorSize = file_sector, .xDeviceCharacteristics = file_characteristics
};
static int vfs_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file,
                    int flags, int *out_flags)
{
    (void)vfs;
    struct pinned_file *p = (struct pinned_file *)file;
    memset(p, 0, sizeof(*p));
    int required = SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READONLY;
    int forbidden = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
        SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_TEMP_DB |
        SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_MAIN_JOURNAL |
        SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_SUBJOURNAL |
        SQLITE_OPEN_SUPER_JOURNAL | SQLITE_OPEN_WAL;
    if ((flags & required) != required || (flags & forbidden))
        return SQLITE_CANTOPEN;
    sqlite3_mutex_enter(registry_mutex());
    struct sqlite_pinned_reader *reader = lookup(name);
    int result = SQLITE_CANTOPEN;
    if (reader && opening_reader == reader && !reader->opened && stable(reader)) {
        reader->opened = true;
        p->owner = reader;
        p->base.pMethods = &pinned_methods;
        if (out_flags) *out_flags = SQLITE_OPEN_READONLY;
        result = SQLITE_OK;
    }
    sqlite3_mutex_leave(registry_mutex());
    return result;
}
static int vfs_delete(sqlite3_vfs *vfs, const char *name, int sync)
{
    (void)vfs; (void)name; (void)sync; return SQLITE_READONLY;
}
static int vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *out)
{
    (void)vfs;
    sqlite3_mutex_enter(registry_mutex());
    *out = lookup(name) != NULL && flags != SQLITE_ACCESS_READWRITE;
    sqlite3_mutex_leave(registry_mutex());
    return SQLITE_OK;
}
static int vfs_fullpath(sqlite3_vfs *vfs, const char *name, int n, char *out)
{
    (void)vfs;
    sqlite3_mutex_enter(registry_mutex());
    bool valid = lookup(name) != NULL;
    if (valid && n > 0 && strlen(name) < (size_t)n)
        memcpy(out, name, strlen(name) + 1);
    else valid = false;
    sqlite3_mutex_leave(registry_mutex());
    return valid ? SQLITE_OK : SQLITE_CANTOPEN;
}
static int vfs_random(sqlite3_vfs *vfs, int n, char *out)
{
    (void)vfs; return host_vfs->xRandomness(host_vfs, n, out);
}
static int vfs_sleep(sqlite3_vfs *vfs, int micros)
{
    (void)vfs; return host_vfs->xSleep(host_vfs, micros);
}
static int vfs_time(sqlite3_vfs *vfs, double *out)
{
    (void)vfs;
    if (host_vfs->xCurrentTime) return host_vfs->xCurrentTime(host_vfs, out);
    sqlite3_int64 milliseconds = 0;
    int rc = host_vfs->xCurrentTimeInt64(host_vfs, &milliseconds);
    if (rc == SQLITE_OK) *out = (double)milliseconds / 86400000.0;
    return rc;
}
/* Called only with the registry mutex. Static method bytes are never freed
 * or unregistered: sqlite3_vfs_find callers cannot race a freed vtable. */
static bool register_vfs(void)
{
    sqlite3_vfs *existing = sqlite3_vfs_find(PINNED_VFS_NAME);
    if (existing) return existing == &pinned_vfs;
    /* sqlite3_shutdown drops registrations but not our static bytes. Never
     * overwrite a published vtable; re-register the same object after init. */
#if defined(_WIN32)
    host_vfs = sqlite3_vfs_find("win32");
#else
    host_vfs = sqlite3_vfs_find("unix");
#endif
    if (!host_vfs) {
        LOG_WARN("sqlite_pinned_reader", "built-in host VFS missing");
        return false;
    }
    bool time_available = host_vfs->xCurrentTime != NULL ||
        (host_vfs->iVersion >= 2 && host_vfs->xCurrentTimeInt64 != NULL);
    if (!host_vfs->xRandomness || !host_vfs->xSleep || !time_available) {
        LOG_WARN("sqlite_pinned_reader",
                 "host VFS callbacks unavailable: random=%d sleep=%d time=%d",
                 host_vfs->xRandomness != NULL, host_vfs->xSleep != NULL,
                 time_available);
        return false;
    }
    LOG_INFO("sqlite_pinned_reader", "host VFS time callbacks: legacy=%d int64=%d",
             host_vfs->xCurrentTime != NULL,
             host_vfs->iVersion >= 2 && host_vfs->xCurrentTimeInt64 != NULL);
    if (!vfs_initialized) {
        pinned_vfs = (sqlite3_vfs){
        .iVersion = 1, .szOsFile = sizeof(struct pinned_file),
        .mxPathname = PINNED_NAME_MAX, .zName = PINNED_VFS_NAME,
        .xOpen = vfs_open, .xDelete = vfs_delete, .xAccess = vfs_access,
        .xFullPathname = vfs_fullpath, .xRandomness = vfs_random,
        .xSleep = vfs_sleep, .xCurrentTime = vfs_time
        };
        vfs_initialized = true;
    }
    return sqlite3_vfs_register(&pinned_vfs, 0) == SQLITE_OK;
}
static struct sqlite_pinned_reader *reserve(
    const struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *expected)
{
    if (!register_vfs() || next_token == UINT64_MAX) return NULL;
    for (size_t i = 0; i < PINNED_LIMIT; ++i) {
        if (slots[i].reserved) continue;
        struct sqlite_pinned_reader *r = &slots[i];
        memset(r, 0, sizeof(*r));
        r->file = file;
        r->expected = *expected;
        int n = snprintf(r->token, sizeof(r->token), "pinned-%" PRIu64,
                         ++next_token);
        if (n <= 0 || (size_t)n >= sizeof(r->token)) return NULL;
        r->reserved = true;
        return r;
    }
    return NULL;
}
static bool standalone_header(const struct platform_positioned_file *file)
{
    unsigned char header[100];
    static const unsigned char magic[16] = "SQLite format 3";
    int64_t n = platform_positioned_file_read(file, header, sizeof(header), 0);
    return n == (int64_t)sizeof(header) &&
        memcmp(header, magic, sizeof(magic)) == 0 &&
        header[18] == 1 && header[19] == 1;
}
static bool configure(sqlite3 *db)
{
    int enabled = 0;
    if (sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0,
                         &enabled) != SQLITE_OK || enabled != 0) return false;
    if (sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1,
                         &enabled) != SQLITE_OK || enabled != 1) return false;
    return sqlite3_exec(db,
        "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;"
        "PRAGMA temp_store=MEMORY;", NULL, NULL, NULL) == SQLITE_OK;
}
/* Resolve failed-open ownership without invalidating any live callbacks. */
static void release_failed_open(struct sqlite_pinned_reader *r,
                                struct sqlite_pinned_reader **out)
{
    /* SQLite auto-extensions may retain a statement even when wrapper open
     * fails. Keep the slot and borrowed-file owner until checked close. */
    if (!r->db || sqlite3_close(r->db) == SQLITE_OK) {
        sqlite3_mutex_enter(registry_mutex());
        memset(r, 0, sizeof(*r));
        sqlite3_mutex_leave(registry_mutex());
    } else {
        /* Failed cleanup still owns callbacks borrowing the retained file.
         * Return a cleanup-only owner rather than hiding its lifetime. */
        *out = r;
    }
}
bool sqlite_pinned_reader_open(
    const struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *expected,
    struct sqlite_pinned_reader **out)
{
    if (out) *out = NULL;
    if (!file || !expected || !out || expected->size > INT64_MAX)
        return false;
    if (!standalone_header(file)) {
        LOG_WARN("sqlite_pinned_reader", "standalone header refused");
        return false;
    }
    if (sqlite3_initialize() != SQLITE_OK) return false;
    struct platform_positioned_file_snapshot now;
    if (!platform_positioned_file_snapshot(file, &now) ||
        !platform_positioned_file_snapshot_equal(expected, &now)) {
        LOG_WARN("sqlite_pinned_reader", "retained snapshot changed");
        return false;
    }
    sqlite3_mutex_enter(registry_mutex());
    struct sqlite_pinned_reader *r = reserve(file, expected);
    sqlite3_mutex_leave(registry_mutex());
    if (!r) {
        LOG_WARN("sqlite_pinned_reader", "registration/reservation refused");
        return false;
    }
    struct sqlite_pinned_reader *previous = opening_reader;
    opening_reader = r;
    int rc = sqlite3_open_v2(r->token, &r->db,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, PINNED_VFS_NAME);
    opening_reader = previous;
    bool configured = rc == SQLITE_OK && configure(r->db);
    bool unchanged = stable(r);
    if (configured && unchanged) {
        r->ready = true;
        *out = r; return true;
    }
    LOG_WARN("sqlite_pinned_reader", "open refused rc=%d configured=%d stable=%d: %s",
            rc, configured, unchanged, r->db ? sqlite3_errmsg(r->db) : "no connection");
    release_failed_open(r, out);
    return false;
}
sqlite3 *sqlite_pinned_reader_db(struct sqlite_pinned_reader *reader)
{
    return reader && reader->ready ? reader->db : NULL;
}
bool sqlite_pinned_reader_close(struct sqlite_pinned_reader **reader)
{
    if (!reader || !*reader) return false;
    struct sqlite_pinned_reader *r = *reader;
    if (sqlite3_close(r->db) != SQLITE_OK) return false;
    sqlite3_mutex_enter(registry_mutex());
    memset(r, 0, sizeof(*r));
    sqlite3_mutex_leave(registry_mutex());
    *reader = NULL;
    return true;
}
