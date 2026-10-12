/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves native wallet restore refuses before mutation on Windows --
 * the datadir query, the datadir hold and the restore run all fail, the
 * backup sentinel is byte-unchanged, and neither node.db nor the recovery
 * lock is created.
 *
 * Adopted from tools/tests/test_wallet_restore_windows_refusal.c, which the
 * deleted tools/scripts/winacceptance.sh only ever compiled — and compiled
 * NATIVELY, so the arm below (the whole assertion) was never read by a
 * compiler at all. The catalog cross-links it for Windows, which is the first
 * time these lines are checked. The refusal also requires a completely zero
 * report. File checks live in private helpers; the non-Windows arm uses
 * the not-built typedef its catalog siblings use. */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "base/log_level.h"
#include "services/wallet_restore_service.h"
#include "test/windows_compat.h"
#include "test/test_core.h"

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_OFF; }
void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

static bool write_sentinel(const char *path, const char *bytes)
{
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    bool ok = file != INVALID_HANDLE_VALUE &&
              WriteFile(file, bytes, (DWORD)strlen(bytes), &written, NULL) &&
              written == strlen(bytes);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return ok;
}

static bool format_path(char *out, size_t capacity, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int written = vsnprintf(out, capacity, format, args);
    va_end(args);
    return written >= 0 && (size_t)written < capacity;
}

static const char expected[] = "synthetic-wallet-restore-sentinel";

static bool file_missing(const char *path)
{
    DWORD attributes = GetFileAttributesA(path);
    DWORD error = GetLastError();
    return attributes == INVALID_FILE_ATTRIBUTES &&
        (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
}

static bool files_unchanged(const char *sentinel, const char *node_db,
                            const char *lock_path)
{
    char actual[sizeof(expected)] = {0};
    HANDLE file = CreateFileA(sentinel, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
        ReadFile(file, actual, (DWORD)sizeof(expected) - 1, &read, NULL) &&
        read == sizeof(expected) - 1 &&
        memcmp(actual, expected, sizeof(expected) - 1) == 0;
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file))
        unchanged = false;
    return unchanged &&
        file_missing(node_db) && file_missing(lock_path);
}

int main(void)
{
    char dir[MAX_PATH + 64];
    char sentinel[MAX_PATH + 96], node_db[MAX_PATH + 80];
    char lock_path[MAX_PATH + 96];
    if (!test_mkdtemp(dir, sizeof(dir), "wallet_restore_refusal"))
        return 2;
    if (!format_path(sentinel, sizeof(sentinel), "%s/sentinel.sqlite", dir) ||
        !format_path(node_db, sizeof(node_db), "%s/node.db", dir) ||
        !format_path(lock_path, sizeof(lock_path),
                     "%s/wallet-recovery.lock", dir)) {
        RemoveDirectoryA(dir);
        return 2;
    }
    if (!write_sentinel(sentinel, expected)) {
        (void)DeleteFileA(sentinel);
        (void)RemoveDirectoryA(dir);
        return 4;
    }

    struct wallet_restore_datadir_lock lock = {0};
    struct wallet_restore_report report;
    const unsigned char zero_report[sizeof(report)] = {0};
    memset(&report, 0xA5, sizeof(report));
    struct wallet_restore_request request = {
        .backup_path = sentinel,
        .datadir = dir,
        .password = NULL,
        .dry_run = false,
    };
    struct zcl_result queried = wallet_restore_datadir_free(dir);
    struct zcl_result held = wallet_restore_datadir_hold(dir, &lock);
    struct zcl_result restored = wallet_restore_run(&request, &report);
    wallet_restore_datadir_release(&lock);

    bool unchanged = files_unchanged(sentinel, node_db, lock_path);

    if (!DeleteFileA(sentinel) || !RemoveDirectoryA(dir))
        return 2;
    if (queried.ok || held.ok || restored.ok || !unchanged ||
        memcmp(&report, zero_report, sizeof(report)) != 0)
        return 1;
    puts("wallet_restore_windows_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int wallet_restore_windows_refusal_not_built;
#endif
