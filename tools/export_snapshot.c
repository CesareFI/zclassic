/* Minimal consensus snapshot exporter.
 * Copies only public tables from node.db to consensus_snapshot.db.
 * Usage: build/bin/export_snapshot [datadir] */

#include "platform/time_compat.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(_WIN32)
#include "platform/windows_path.h"
#include <shellapi.h>
#endif

static bool snapshot_file_size(const char *path, int64_t *size)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!platform_windows_wide_path(path, wide) ||
        !GetFileAttributesExW(wide, GetFileExInfoStandard, &data) ||
        (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) return false;
    *size = ((int64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
#else
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    *size = st.st_size;
#endif
    return true;
}

static int snapshot_unlink(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    return platform_windows_wide_path(path, wide) && DeleteFileW(wide) ? 0 : -1;
#else
    return unlink(path);
#endif
}

static const char *snapshot_uri_escape(char c)
{
    switch (c) {
    case '%': return "%25";
    case '?': return "%3F";
    case '#': return "%23";
    case '/': return "%2F";
    default: return NULL;
    }
}

/* Attach the source node.db read-only: percent-encode the characters
 * SQLite's URI parser reserves (% ? # /) into the file: URI, then bind the
 * filename as a statement parameter — no SQL string is built from the
 * path at all. False only on allocation/statement failure or when the
 * URI buffer cannot hold the encoding. */
static bool attach_src_readonly(sqlite3 *dst, const char *src_path,
                                char *uri, size_t cap)
{
    int n = snprintf(uri, cap, "file:");
    if (n < 0 || (size_t)n >= cap) return false;
    size_t an = (size_t)n;
    for (const char *p = src_path; *p; p++) {
        const char *enc = snapshot_uri_escape(*p);
        size_t need = enc ? 3u : 1u;
        if (an + need + sizeof("?mode=ro") > cap) return false;
        if (enc) {
            memcpy(uri + an, enc, 3);
            an += 3;
        } else {
            uri[an++] = *p;
        }
    }
    int t = snprintf(uri + an, cap - an, "?mode=ro");
    if (t < 0 || (size_t)t >= cap - an) return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(dst, "ATTACH DATABASE ?1 AS src", -1, &st,
                           NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(st, 1, uri, -1, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:standalone-dev-tool
    sqlite3_finalize(st);
    return ok && sqlite3_db_readonly(dst, "src") == 1;
}

/* Copy each public consensus table from the attached src schema; missing
 * tables are skipped, not fatal. Returns the number copied. */
static int snapshot_copy_tables(sqlite3 *dst)
{
    static const char *tables[] = {
        "blocks", "transactions", "utxos", "addresses",
        "chain_stats", "zslp_tokens", "zslp_balances",
        NULL
    };
    int copied = 0;
    for (int i = 0; tables[i]; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "CREATE TABLE %s AS SELECT * FROM src.%s",
            tables[i], tables[i]);
        char *err = NULL;
        int rc = sqlite3_exec(dst, sql, NULL, NULL, &err);
        if (rc == SQLITE_OK) {
            char cnt[128];
            snprintf(cnt, sizeof(cnt), "SELECT count(*) FROM %s", tables[i]);
            sqlite3_stmt *s = NULL;
            sqlite3_prepare_v2(dst, cnt, -1, &s, NULL);
            int rows = 0;
            if (s && sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:standalone-dev-tool
                rows = sqlite3_column_int(s, 0);
            if (s) sqlite3_finalize(s);
            printf("  %-20s %d rows\n", tables[i], rows);
            copied++;
        } else {
            printf("  %-20s skipped (%s)\n", tables[i],
                   err ? err : "not found");
            if (err) sqlite3_free(err);
        }
    }
    return copied;
}

enum { SNAPSHOT_PATH_CAP = 576 };

static bool snapshot_datadir_paths(const char *datadir,
                                    char src_path[SNAPSHOT_PATH_CAP],
                                    char dst_path[SNAPSHOT_PATH_CAP],
                                    char manifest_path[SNAPSHOT_PATH_CAP])
{
    int ns = snprintf(src_path, SNAPSHOT_PATH_CAP, "%s/node.db", datadir);
    int nd = snprintf(dst_path, SNAPSHOT_PATH_CAP, "%s%s/consensus_snapshot.db",
                      strncmp(datadir, "file:", 5) == 0 ? "./" : "", datadir);
    int nm = snprintf(manifest_path, SNAPSHOT_PATH_CAP, "%s/file_manifest.bin",
                      datadir);
    return ns >= 0 && (size_t)ns < SNAPSHOT_PATH_CAP &&
           nd >= 0 && (size_t)nd < SNAPSHOT_PATH_CAP &&
           nm >= 0 && (size_t)nm < SNAPSHOT_PATH_CAP;
}

#if defined(_WIN32)
static bool snapshot_windows_argument(const wchar_t *command_line, int argc,
                                      char utf8_datadir[SNAPSHOT_PATH_CAP],
                                      const char **datadir)
{
    *datadir = NULL;
    utf8_datadir[0] = '\0';
    int wide_argc = 0;
    wchar_t **wide_argv = CommandLineToArgvW(command_line, &wide_argc);
    if (!wide_argv) return false;
    bool ok = argc == 2 && wide_argc == argc && wide_argv[1][0] &&
              wide_argv[1][0] != L'-' &&
              WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_argv[1],
                  -1, utf8_datadir, SNAPSHOT_PATH_CAP, NULL, NULL) != 0;
    if (LocalFree(wide_argv) != NULL) ok = false;
    if (ok) *datadir = utf8_datadir;
    return ok;
}
#endif

static bool snapshot_argument(int argc, char *argv[],
                               char utf8_datadir[SNAPSHOT_PATH_CAP],
                               const char **datadir)
{
    if (argc > 2 || (argc == 2 && (!argv[1][0] || argv[1][0] == '-'))) {
        fprintf(stderr, "Usage: export_snapshot [datadir]\n");
        return false;
    }
#if defined(_WIN32)
    /* SQLite filenames are UTF-8; CRT argv uses the ANSI code page. Parse
     * the native wide command line without wildcard expansion instead. */
    if (argc == 2) {
        if (!snapshot_windows_argument(GetCommandLineW(), argc, utf8_datadir,
                                        datadir)) {
            fprintf(stderr, "Invalid or overlong datadir argument\n");
            return false;
        }
        return true;
    }
#else
    (void)utf8_datadir;
#endif
    *datadir = argc == 2 ? argv[1] : NULL;
    return true;
}

int main(int argc, char *argv[])
{
    char utf8_datadir[SNAPSHOT_PATH_CAP];
    const char *datadir = NULL;
    if (!snapshot_argument(argc, argv, utf8_datadir, &datadir)) return 1;
    char default_dd[256] = "./.zclassic-c23";
    const char *home = getenv("HOME");
    if (argc < 2 && home && *home) {
        int n = snprintf(default_dd, sizeof(default_dd), "%s/.zclassic-c23", home);
        if (n < 0 || (size_t)n >= sizeof(default_dd)) return 1;
    }
    if (!datadir) datadir = default_dd;

    char src_path[SNAPSHOT_PATH_CAP], dst_path[SNAPSHOT_PATH_CAP];
    char manifest_path[SNAPSHOT_PATH_CAP];
    if (!snapshot_datadir_paths(datadir, src_path, dst_path, manifest_path))
        return 1;

    int64_t src_size;
    if (!snapshot_file_size(src_path, &src_size)) {
        fprintf(stderr, "No node.db at %s\n", src_path);
        return 1;
    }
    printf("Source: %s (%.0f MB)\n", src_path,
           (double)src_size / (1024.0*1024.0));

    snapshot_unlink(dst_path);

    /* The connection is opened with SQLITE_OPEN_URI so the ATTACH below can
     * carry mode=ro: this tool's contract is READ-ONLY against the source
     * node.db (it must never hold a write-capable handle on the node's
     * database). Normal WAL locking remains; -shm/-wal sidecars may be
     * created or updated. Never use immutable=1 for a possibly live node.db. */
    sqlite3 *dst = NULL;
    if (sqlite3_open_v2(dst_path, &dst,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI,
        NULL) != SQLITE_OK) {
        fprintf(stderr, "Can't create %s\n", dst_path);
        if (dst) sqlite3_close(dst);
        return 1;
    }

    sqlite3_exec(dst, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(dst, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
    sqlite3_exec(dst, "PRAGMA cache_size=-262144", NULL, NULL, NULL);

    char uri[sizeof(src_path) * 3 + 16];
    if (!attach_src_readonly(dst, src_path, uri, sizeof(uri))) {
        fprintf(stderr, "ATTACH failed: %s\n", sqlite3_errmsg(dst));
        sqlite3_close(dst);
        return 1;
    }

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    sqlite3_exec(dst, "BEGIN", NULL, NULL, NULL);

    int copied = snapshot_copy_tables(dst);

    sqlite3_exec(dst, "COMMIT", NULL, NULL, NULL);
    sqlite3_exec(dst, "DETACH DATABASE src", NULL, NULL, NULL);

    sqlite3_exec(dst, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    printf("Compacting...\n");
    sqlite3_exec(dst, "VACUUM", NULL, NULL, NULL);
    sqlite3_close(dst);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    int64_t dst_size = 0;
    if (!snapshot_file_size(dst_path, &dst_size)) {
        fprintf(stderr, "Can't inspect %s\n", dst_path);
        return 1;
    }
    printf("\nExported %d tables to %s (%.0f MB) in %llds\n",
           copied, dst_path, (double)dst_size / (1024.0*1024.0),
           (long long)elapsed);

    /* Delete stale manifest so it rebuilds with the new snapshot */
    if (snapshot_unlink(manifest_path) == 0)
        printf("Deleted stale file_manifest.bin (will rebuild)\n");

    return 0;
}
