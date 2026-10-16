/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: strict read-only traversal of a finalized copied node.db UTXO mirror. */
#include "storage/utxo_mirror_read_snapshot.h"
#include "platform/positioned_file.h"
#include "storage/sqlite_pinned_reader.h"
#include "crypto/sha3.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "script/script.h"
#include "storage/utxo_mirror_schema.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct utxo_mirror_read_snapshot {
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot identity;
    struct sqlite_pinned_reader *reader;
    sqlite3 *db; /* borrowed from reader; never close directly */
    sqlite3_stmt *rows;
    char parent_path[4096], leaf[256];
    int parent_fd;
    struct stat parent_identity;
    uint8_t expected[32], last_txid[32];
    uint32_t last_vout;
    int32_t next_height;
    uint64_t count;
    struct sha3_256_ctx root;
    bool transaction, have_last, exhausted, failed, cleanup_failed;
};

static bool umrs_exec(sqlite3 *db, const char *sql)
{
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) LOG_WARN("utxo_copy", "read transaction operation failed rc=%d", rc);
    return rc == SQLITE_OK;
}

static bool umrs_metadata(const struct utxo_mirror_read_snapshot *s)
{
    struct platform_positioned_file_snapshot now;
    return platform_positioned_file_snapshot(&s->file, &now) &&
        platform_positioned_file_snapshot_equal(&s->identity, &now);
}

/* All siblings and the DB are inspected relative to one retained private
 * parent. Re-resolving the input's parent is only a replacement check; no
 * query or sibling inspection uses that potentially substituted directory. */
static bool umrs_parent_equal(const struct stat *a, const struct stat *b)
{
    if (a->st_dev != b->st_dev || a->st_ino != b->st_ino ||
        a->st_uid != b->st_uid || a->st_mode != b->st_mode) return false;
#if defined(__APPLE__)
    return a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}
static bool umrs_siblings_absent(const struct utxo_mirror_read_snapshot *s)
{
    static const char *const suffix[] = {"-wal", "-shm", "-journal"};
    char name[272];
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
        int n = snprintf(name, sizeof(name), "%s%s", s->leaf, suffix[i]);
        struct stat st;
        if (n < 0 || (size_t)n >= sizeof(name) ||
            fstatat(s->parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
            return false;
    }
    return true;
}
static bool umrs_named_object(const struct utxo_mirror_read_snapshot *s)
{
    struct stat parent, named_parent;
    if (s->parent_fd < 0 || fstat(s->parent_fd, &parent) != 0 ||
        !umrs_parent_equal(&s->parent_identity, &parent)) return false;
    int parent_check = open(s->parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_check < 0) return false;
    bool same = fstat(parent_check, &named_parent) == 0 &&
        umrs_parent_equal(&s->parent_identity, &named_parent);
    if (close(parent_check) != 0) same = false;
    if (!same) return false;
    if (!umrs_siblings_absent(s)) return false;
    struct platform_positioned_file named;
    struct platform_positioned_file_snapshot identity;
    platform_positioned_file_init(&named);
    int fd = openat(s->parent_fd, s->leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    named.native = (uintptr_t)fd;
    bool ok = platform_positioned_file_snapshot(&named, &identity) &&
        platform_positioned_file_snapshot_equal(&s->identity, &identity) &&
        fstat(s->parent_fd, &parent) == 0 &&
        umrs_parent_equal(&s->parent_identity, &parent);
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool umrs_split_path(struct utxo_mirror_read_snapshot *s, const char *path)
{
    /* Absolute spelling avoids a mutable process cwd. A private copy parent
     * is an explicit offline-input invariant, not canonical capture authority. */
    const char *slash = strrchr(path, '/');
    if (path[0] != '/' || !slash || !slash[1]) return false;
    size_t parent_n = (size_t)(slash - path);
    if (!parent_n) parent_n = 1;
    size_t leaf_n = strlen(slash + 1);
    if (parent_n >= sizeof(s->parent_path) || leaf_n >= sizeof(s->leaf) ||
        strcmp(slash + 1, ".") == 0 || strcmp(slash + 1, "..") == 0) return false;
    memcpy(s->parent_path, path, parent_n); s->parent_path[parent_n] = '\0';
    memcpy(s->leaf, slash + 1, leaf_n + 1);
    return true;
}
static bool umrs_admit_file(struct utxo_mirror_read_snapshot *s, const char *path)
{
    if (!umrs_split_path(s, path)) return false;
    s->parent_fd = open(s->parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (s->parent_fd < 0 || fstat(s->parent_fd, &s->parent_identity) != 0 ||
        !S_ISDIR(s->parent_identity.st_mode) || s->parent_identity.st_uid != geteuid() ||
        (s->parent_identity.st_mode & 0077) != 0) return false;
    int fd = openat(s->parent_fd, s->leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    s->file.native = (uintptr_t)fd;
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0222) == 0 &&
        platform_positioned_file_snapshot(&s->file, &s->identity) &&
        s->identity.size <= INT64_MAX && umrs_named_object(s);
}

/* SQLite's adapter reads the retained positioned file directly. Digest only
 * that object; byte equality is not used as a substitute for OS binding. */
static bool umrs_bytes(const struct utxo_mirror_read_snapshot *s)
{
    if (!umrs_metadata(s) || !umrs_named_object(s)) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint8_t chunk[65536];
    uint64_t offset = 0;
    while (offset < s->identity.size) {
        size_t n = sizeof(chunk);
        if ((uint64_t)n > s->identity.size - offset)
            n = (size_t)(s->identity.size - offset);
        int64_t got = platform_positioned_file_read(&s->file, chunk, n, offset);
        if (got != (int64_t)n) return false;
        sha3_256_write(&hash, chunk, n);
        offset += n;
    }
    uint8_t digest[32];
    sha3_256_finalize(&hash, digest);
    return memcmp(digest, s->expected, 32) == 0 &&
        umrs_metadata(s) && umrs_named_object(s);
}

static bool umrs_open_sqlite(struct utxo_mirror_read_snapshot *s)
{
    if (!umrs_bytes(s) ||
        !sqlite_pinned_reader_open(&s->file, &s->identity, &s->reader)) return false;
    s->db = sqlite_pinned_reader_db(s->reader);
    if (!s->db) return false;
    int defensive = 0, trusted = 1;
    if (sqlite3_db_config(s->db, SQLITE_DBCONFIG_DEFENSIVE, 1, &defensive) != SQLITE_OK ||
        sqlite3_db_config(s->db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, &trusted) != SQLITE_OK ||
        defensive != 1 || trusted != 0 || sqlite3_db_readonly(s->db, "main") != 1)
        return false;
    (void)sqlite3_limit(s->db, SQLITE_LIMIT_LENGTH, 2000000);
    (void)sqlite3_limit(s->db, SQLITE_LIMIT_SQL_LENGTH, 65536);
    (void)sqlite3_limit(s->db, SQLITE_LIMIT_COLUMN, 64);
    if (!umrs_exec(s->db, "PRAGMA query_only=ON") || !umrs_exec(s->db, "BEGIN")) return false;
    s->transaction = true;
    return umrs_bytes(s);
}

/* These schema, cursor and row statements only inspect the retained copied
 * node.db mirror. The adapter is read-only and query_only is enabled before
 * any step; this storage boundary never writes or opens the retired event ledger. */
struct umrs_column { const char *name, *type; int notnull, pk; };
static bool umrs_columns(sqlite3 *db, const char *sql,
                          const struct umrs_column *columns, size_t count)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return false;
    size_t i = 0;
    int rc;
    bool ok = true;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const unsigned char *name = sqlite3_column_text(st, 1);
        const unsigned char *type = sqlite3_column_text(st, 2);
        if (i >= count || !name || !type || sqlite3_column_int(st, 0) != (int)i ||
            strcmp((const char *)name, columns[i].name) != 0 ||
            sqlite3_stricmp((const char *)type, columns[i].type) != 0 ||
            sqlite3_column_int(st, 3) != columns[i].notnull ||
            sqlite3_column_int(st, 5) != columns[i].pk || sqlite3_column_int(st, 6) != 0) {
            ok = false; break;
        }
        i++;
    }
    ok = ok && rc == SQLITE_DONE && i == count;
    int finalized = sqlite3_finalize(st);
    return ok && finalized == SQLITE_OK;
}
static bool umrs_schema(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT count(*) FROM sqlite_schema WHERE type='table' "
                      "AND rootpage>0 AND name IN('node_state','utxos')";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 2 && // raw-sql-ok:read-only-introspection
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    int rc = sqlite3_finalize(st);
    static const struct umrs_column node[] = {
        {"key", "TEXT", 0, 1}, {"value", "BLOB", 0, 0}
    };
    static const struct umrs_column utxo[] = {
        {"txid", "BLOB", 1, 1}, {"vout", "INTEGER", 1, 2},
        {"value", "INTEGER", 1, 0}, {"script", "BLOB", 1, 0},
        {"script_type", "INTEGER", 1, 0}, {"address_hash", "BLOB", 0, 0},
        {"height", "INTEGER", 1, 0}, {"is_coinbase", "INTEGER", 1, 0}
    };
    /* Producer shape and primary keys are required. Exact DDL text/defaults/
     * CHECK spelling are immaterial for a reader that validates every value;
     * unrelated node.db tables and indexes are deliberately not rejected. */
    return ok && rc == SQLITE_OK &&
        umrs_columns(db, "PRAGMA main.table_xinfo('node_state')", node, 2) &&
        umrs_columns(db, "PRAGMA main.table_xinfo('utxos')", utxo, 8);
}

static bool umrs_attestation_posix(
    struct utxo_mirror_read_snapshot *s,
    struct utxo_mirror_read_attestation *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!s) return false;
    if (!out || s->failed || !s->reader || !s->db ||
        !umrs_schema(s->db) || !umrs_bytes(s)) {
        s->failed = true;
        return false;
    }
    out->file = s->identity;
    memcpy(out->file_sha3, s->expected, 32);
    out->schema_profile = UTXO_MIRROR_SCHEMA_V1;
    out->sidecars_all_absent = true;
    return true;
}

static bool umrs_cursor(struct utxo_mirror_read_snapshot *s,
                         enum utxo_mirror_byte_order order)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT value FROM node_state WHERE key COLLATE BINARY=?";
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(st, 1, UTXO_MIRROR_SYNC_CURSOR_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_BLOB && // raw-sql-ok:read-only-introspection
        sqlite3_column_bytes(st, 0) == 8;
    const uint8_t *blob = ok ? sqlite3_column_blob(st, 0) : NULL;
    uint64_t cursor = 0;
    if (!blob) ok = false;
    if (ok) for (unsigned i = 0; i < 8; i++) {
        unsigned at = order == UTXO_MIRROR_LITTLE_ENDIAN ? 7u - i : i;
        cursor = (cursor << 8) | blob[at];
    }
    ok = ok && cursor <= INT32_MAX && sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    int rc = sqlite3_finalize(st);
    if (ok && rc == SQLITE_OK) s->next_height = (int32_t)cursor;
    return ok && rc == SQLITE_OK;
}

static bool umrs_end_read(struct utxo_mirror_read_snapshot *s, bool complete)
{
    bool ok = !s->cleanup_failed;
    if (s->rows) {
        int rc = sqlite3_finalize(s->rows);
        s->rows = NULL;
        ok = ok && rc == SQLITE_OK;
    }
    if (s->transaction) {
        bool ended = umrs_exec(s->db, complete && ok ? "COMMIT" : "ROLLBACK");
        if (!ended) (void)umrs_exec(s->db, "ROLLBACK");
        ok = ok && ended;
        s->transaction = false;
    }
    return ok;
}

static bool umrs_release(struct utxo_mirror_read_snapshot **owner, bool complete)
{
    if (!owner || !*owner) return false;
    struct utxo_mirror_read_snapshot *s = *owner;
    bool ok = umrs_end_read(s, complete);
    /* A failed checked wrapper close keeps its callback's borrowed file live.
     * Never force-close SQLite or free that file owner on this path. All our
     * statements have been finalized, so BUSY indicates an ownership defect.
     * Refuse completion and retain this bounded allocation/handle for safety. */
    if (s->reader && !sqlite_pinned_reader_close(&s->reader)) {
        LOG_WARN("utxo_copy", "checked close refused; retained owner not freed");
        s->failed = true; s->cleanup_failed = true;
        return false;
    }
    s->db = NULL;
    if ((int)s->file.native >= 0 && close((int)s->file.native) != 0) ok = false;
    if (s->parent_fd >= 0 && close(s->parent_fd) != 0) ok = false;
    free(s); *owner = NULL;
    return ok;
}

static bool umrs_prepare_rows(struct utxo_mirror_read_snapshot *s,
    const char *path, enum utxo_mirror_byte_order order)
{
    bool ok = umrs_admit_file(s, path) && umrs_open_sqlite(s);
    /* Schema is pinned/validated before selecting any producer cursor data. */
    ok = ok && umrs_schema(s->db) && umrs_cursor(s, order);
    const char *sql = "SELECT txid,vout,value,script,height,is_coinbase FROM utxos ORDER BY txid,vout";
    ok = ok && sqlite3_prepare_v2(s->db, sql, -1, &s->rows, NULL) == SQLITE_OK;
    return ok;
}

static bool umrs_open_posix(
    const char *path, enum utxo_mirror_byte_order order,
    const uint8_t expected[32], struct utxo_mirror_read_snapshot **out,
    int32_t *next_height)
{
    if (out) *out = NULL;
    if (next_height) *next_height = -1;
    if (!path || !expected || !out || !next_height || strlen(path) >= 4096 ||
        (order != UTXO_MIRROR_LITTLE_ENDIAN && order != UTXO_MIRROR_BIG_ENDIAN)) return false;
    struct utxo_mirror_read_snapshot *s = zcl_calloc(1, sizeof(*s), "utxo mirror reader");
    if (!s) return false;
    platform_positioned_file_init(&s->file); s->parent_fd = -1;
    memcpy(s->expected, expected, 32);
    bool ok = umrs_prepare_rows(s, path, order);
    if (!ok) {
        LOG_WARN("utxo_copy", "mirror copy admission refused");
        s->failed = true;
        (void)umrs_release(&s, false);
        *out = s; /* NULL, or an explicit cleanup-only owner for abort retry. */
        return false;
    }
    sha3_256_init(&s->root); *next_height = s->next_height; *out = s;
    return true;
}

static bool umrs_scalar_domain(int64_t vout, int64_t value, int64_t height,
                                int32_t frontier, int64_t coinbase)
{
    return vout >= 0 && vout <= UINT32_MAX && MoneyRange(value) &&
        height >= 0 && height < frontier && coinbase >= 0 && coinbase <= 1;
}
static bool umrs_row(sqlite3_stmt *st, int32_t frontier,
                      struct coins_kv_read_snapshot_row *r)
{
    for (int i = 0; i < 6; i++)
        if (sqlite3_column_type(st, i) != (i == 0 || i == 3 ? SQLITE_BLOB : SQLITE_INTEGER)) return false;
    const uint8_t *txid = sqlite3_column_blob(st, 0);
    const uint8_t *script = sqlite3_column_blob(st, 3);
    int n = sqlite3_column_bytes(st, 3);
    int64_t vout = sqlite3_column_int64(st, 1), value = sqlite3_column_int64(st, 2);
    int64_t height = sqlite3_column_int64(st, 4), cb = sqlite3_column_int64(st, 5);
    if (!txid || sqlite3_column_bytes(st, 0) != 32 ||
        !umrs_scalar_domain(vout, value, height, frontier, cb) ||
        n < 0 || n > MAX_SCRIPT_SIZE || (n && !script)) return false;
    memcpy(r->txid, txid, 32); r->vout = (uint32_t)vout; r->value = value;
    r->script = n ? script : NULL; r->script_len = (size_t)n;
    r->height = (int32_t)height; r->is_coinbase = cb != 0;
    return true;
}

static bool umrs_next_ready(struct utxo_mirror_read_snapshot *s,
                              struct coins_kv_read_snapshot_row *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!s || !out || s->failed || s->exhausted) {
        if (s) s->failed = true;
        return false;
    }
    return true;
}

static enum coins_kv_read_snapshot_step umrs_next_posix(
    struct utxo_mirror_read_snapshot *s, struct coins_kv_read_snapshot_row *out)
{
    if (!umrs_next_ready(s, out)) return COINS_KV_READ_SNAPSHOT_ERROR;
    int rc = umrs_metadata(s) ? sqlite3_step(s->rows) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) { s->exhausted = true; return COINS_KV_READ_SNAPSHOT_DONE; }
    struct coins_kv_read_snapshot_row row = {0};
    if (rc != SQLITE_ROW || !umrs_row(s->rows, s->next_height, &row)) {
        s->failed = true; return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    int order = s->have_last ? memcmp(row.txid, s->last_txid, 32) : 1;
    if ((s->have_last && (order < 0 || (order == 0 && row.vout <= s->last_vout))) || s->count == UINT64_MAX) {
        s->failed = true; return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    utxo_commitment_sha3_write_record(&s->root, row.txid, row.vout, row.value,
        row.script, (uint32_t)row.script_len, (uint32_t)row.height, (uint8_t)row.is_coinbase);
    memcpy(s->last_txid, row.txid, 32); s->last_vout = row.vout;
    s->have_last = true; s->count++; *out = row;
    return COINS_KV_READ_SNAPSHOT_ROW;
}

static bool umrs_finish_posix(struct utxo_mirror_read_snapshot **owner,
                                           struct utxo_mirror_read_result *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!owner || !*owner) return false;
    struct utxo_mirror_read_snapshot *s = *owner;
    struct utxo_mirror_read_attestation input;
    bool ok = out && s->exhausted && !s->failed &&
        utxo_mirror_read_snapshot_attestation(s, &input);
    struct utxo_mirror_read_result result = {0};
    if (ok) {
        result.next_height = s->next_height; result.count = s->count;
        result.input = input;
        sha3_256_finalize(&s->root, result.root); memcpy(result.file_sha3, s->expected, 32);
    }
    s->failed = true; /* A retained owner is cleanup-only after any finish. */
    bool closed = umrs_release(owner, ok);
    if (ok && closed) *out = result;
    return ok && closed;
}
static bool umrs_abort_posix(struct utxo_mirror_read_snapshot **owner)
{
    return umrs_release(owner, false);
}
#endif

bool utxo_mirror_read_snapshot_open(
    const char *path, enum utxo_mirror_byte_order order, const uint8_t expected[32],
    struct utxo_mirror_read_snapshot **out, int32_t *height)
{
#ifndef _WIN32
    return umrs_open_posix(path, order, expected, out, height);
#else
    (void)path; (void)order; (void)expected;
    if (out) *out = NULL;
    if (height) *height = -1;
    return false;
#endif
}
bool utxo_mirror_read_snapshot_attestation(
    struct utxo_mirror_read_snapshot *s, struct utxo_mirror_read_attestation *out)
{
#ifndef _WIN32
    return umrs_attestation_posix(s, out);
#else
    (void)s;
    if (out) memset(out, 0, sizeof(*out));
    return false;
#endif
}
enum coins_kv_read_snapshot_step utxo_mirror_read_snapshot_next(
    struct utxo_mirror_read_snapshot *s, struct coins_kv_read_snapshot_row *out)
{
#ifndef _WIN32
    return umrs_next_posix(s, out);
#else
    (void)s;
    if (out) memset(out, 0, sizeof(*out));
    return COINS_KV_READ_SNAPSHOT_ERROR;
#endif
}
bool utxo_mirror_read_snapshot_finish(struct utxo_mirror_read_snapshot **s,
                                           struct utxo_mirror_read_result *out)
{
#ifndef _WIN32
    return umrs_finish_posix(s, out);
#else
    (void)s;
    if (out) memset(out, 0, sizeof(*out));
    return false;
#endif
}
bool utxo_mirror_read_snapshot_abort(struct utxo_mirror_read_snapshot **s)
{
#ifndef _WIN32
    return umrs_abort_posix(s);
#else
    (void)s;
    return false;
#endif
}
