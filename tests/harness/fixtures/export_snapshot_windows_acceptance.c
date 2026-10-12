/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Focused native Windows SQLite qualification, independent of the full node.
 * Includes the exporter so the real ATTACH and copy implementation is tested. */
#if defined(_WIN32)
#define main snapshot_tool_main
#include "../../../tools/export_snapshot.c"
#undef main

#include <windows.h>

static bool same_rows(sqlite3 *db, const char *schema, int value)
{
    const char *tables[] = {"blocks", "transactions", "utxos", "addresses",
                           "chain_stats", "zslp_tokens", "zslp_balances"};
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
        char sql[160];
        snprintf(sql, sizeof(sql), "SELECT count(*), min(x), max(x) FROM %s.%s",
                 schema, tables[i]);
        sqlite3_stmt *st = NULL;
        bool ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int(st, 0) == 1 &&
                  sqlite3_column_int(st, 1) == value &&
                  sqlite3_column_int(st, 2) == value &&
                  sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
        if (!ok) return false;
    }
    return true;
}

static bool read_bytes(const wchar_t *path, unsigned char *bytes, DWORD *size)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER length;
    bool ok = GetFileSizeEx(h, &length) && length.QuadPart <= 65536 &&
              ReadFile(h, bytes, 65536, size, NULL) &&
              *size == (DWORD)length.QuadPart;
    return CloseHandle(h) && ok;
}

struct snapshot_fixture_paths {
    wchar_t dir[MAX_PATH], source[MAX_PATH], output[MAX_PATH];
    char src_utf8[MAX_PATH * 4], dst_utf8[MAX_PATH * 4];
};

static bool fixture_paths(struct snapshot_fixture_paths *p,
                           const wchar_t *root, const wchar_t *name, int value)
{
    swprintf(p->dir, MAX_PATH, L"%ls/%ls", root, name);
    swprintf(p->source, MAX_PATH, L"%ls/node %ls.db", p->dir, name);
    swprintf(p->output, MAX_PATH, L"%ls/output %ls.db", p->dir, name);
    if (!CreateDirectoryW(p->dir, NULL)) return false;
    /* Exercise native drive-qualified paths and backslash separators too. */
    if (value == 32 || value == 33) {
        wchar_t absolute[MAX_PATH];
        DWORD n = GetFullPathNameW(p->source, MAX_PATH, absolute, NULL);
        if (!n || n >= MAX_PATH) return false;
        wcscpy(p->source, absolute);
        n = GetFullPathNameW(p->output, MAX_PATH, absolute, NULL);
        if (!n || n >= MAX_PATH) return false;
        wcscpy(p->output, absolute);
    }
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, p->source, -1,
                                p->src_utf8, sizeof(p->src_utf8), NULL, NULL) &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, p->output, -1,
                                p->dst_utf8, sizeof(p->dst_utf8), NULL, NULL);
}

static bool fixture_create_db(const char *path, int value)
{
    sqlite3 *src = NULL;
    bool ok = sqlite3_open(path, &src) == SQLITE_OK;
    const char *tables[] = {"blocks", "transactions", "utxos", "addresses",
                           "chain_stats", "zslp_tokens", "zslp_balances"};
    for (size_t i = 0; ok && i < sizeof(tables) / sizeof(tables[0]); ++i) {
        char sql[160];
        snprintf(sql, sizeof(sql), "CREATE TABLE %s(x); INSERT INTO %s VALUES(%d)",
                 tables[i], tables[i], value);
        ok = sqlite3_exec(src, sql, NULL, NULL, NULL) == SQLITE_OK;
    }
    if (src && sqlite3_close(src) != SQLITE_OK) ok = false;
    return ok;
}

static bool fixture_copy(const struct snapshot_fixture_paths *p, int value)
{
    char uri[MAX_PATH * 12];
    sqlite3 *dst = NULL;
    bool ok = sqlite3_open_v2(p->dst_utf8, &dst,
                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI,
                   NULL) == SQLITE_OK &&
              attach_src_readonly(dst, p->src_utf8, uri, sizeof(uri));
    if (ok) ok = sqlite3_exec(dst, "UPDATE src.blocks SET x=999", NULL, NULL,
                              NULL) == SQLITE_READONLY &&
                 same_rows(dst, "src", value) && snapshot_copy_tables(dst) == 7 &&
                 same_rows(dst, "main", value);
    if (ok) ok = sqlite3_exec(dst, "DETACH DATABASE src", NULL, NULL, NULL) == SQLITE_OK;
    if (dst && sqlite3_close(dst) != SQLITE_OK) ok = false;
    return ok;
}

static bool fixture_persisted_rows(const char *path, int value)
{
    sqlite3 *dst = NULL;
    /* Reopen the persisted output, then prove Windows handles are released. */
    bool ok = sqlite3_open_v2(path, &dst, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
              same_rows(dst, "main", value);
    if (dst && sqlite3_close(dst) != SQLITE_OK) ok = false;
    return ok;
}

static int qualify(const wchar_t *root, const wchar_t *name, int value)
{
    struct snapshot_fixture_paths p = {0};
    unsigned char before[65536], after[65536];
    DWORD before_size = 0, after_size = 0;
    bool ok = fixture_paths(&p, root, name, value) &&
              fixture_create_db(p.src_utf8, value) &&
              read_bytes(p.source, before, &before_size) && fixture_copy(&p, value) &&
              read_bytes(p.source, after, &after_size) && before_size == after_size &&
              memcmp(before, after, before_size) == 0 &&
              fixture_persisted_rows(p.dst_utf8, value);
    int failed = !ok;
    if (!DeleteFileW(p.source) || !DeleteFileW(p.output) || !RemoveDirectoryW(p.dir))
        failed = 1;
    printf("native filename case %d: %s (cleanup checked)\n", value,
           failed ? "FAIL" : "PASS");
    return failed;
}

/* Observe the production GetCommandLineW path in a real child, with quoted
 * non-ASCII text that cannot be recovered from ANSI argv on every host. */
static bool fixture_native_argument(void)
{
    wchar_t exe[32768], command[32768];
    DWORD n = GetModuleFileNameW(NULL, exe, 32768);
    if (!n || n >= 32768) return false;
    int written = swprintf(command, 32768, L"\"%ls\" \"caf\u00e9 \u03a9 %%41#here\"", exe);
    if (written < 0 || written >= 32768) return false;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(exe, command, NULL, NULL, FALSE, 0, NULL, NULL,
                         &startup, &process)) return false;
    DWORD waited = WaitForSingleObject(process.hProcess, 10000), exit_code = 1;
    bool ok = waited == WAIT_OBJECT_0 &&
              GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0;
    if (waited != WAIT_OBJECT_0) {
        if (!TerminateProcess(process.hProcess, 1) ||
            WaitForSingleObject(process.hProcess, 2000) != WAIT_OBJECT_0)
            fprintf(stderr, "argument fixture child cleanup failed\n");
    }
    if (!CloseHandle(process.hThread)) ok = false;
    if (!CloseHandle(process.hProcess)) ok = false;
    return ok;
}

static bool fixture_argument_refusals(void)
{
    char utf8[SNAPSHOT_PATH_CAP];
    const char *datadir = NULL;
    wchar_t overlong[SNAPSHOT_PATH_CAP + 64];
    wcscpy(overlong, L"export_snapshot.exe ");
    for (size_t i = wcslen(overlong); i < SNAPSHOT_PATH_CAP + 63; i++)
        overlong[i] = L'x';
    overlong[SNAPSHOT_PATH_CAP + 63] = L'\0';
    return !snapshot_windows_argument(L"export_snapshot.exe a b", 2, utf8, &datadir) &&
           !datadir &&
           !snapshot_windows_argument(L"export_snapshot.exe \"\"", 2, utf8, &datadir) &&
           !datadir &&
           !snapshot_windows_argument(L"export_snapshot.exe -bad", 2, utf8, &datadir) &&
           !datadir &&
           !snapshot_windows_argument(overlong, 2, utf8, &datadir) && !datadir;
}

int main(int argc, char *argv[])
{
    if (argc > 1) {
        char utf8[SNAPSHOT_PATH_CAP];
        const char *datadir = NULL;
        return snapshot_argument(argc, argv, utf8, &datadir) && datadir &&
               strcmp(datadir, "caf\xc3\xa9 \xce\xa9 %41#here") == 0 ? 0 : 1;
    }
    printf("SQLite %s; native Win32 ATTACH/copy qualification\n", sqlite3_libversion());
    wchar_t root[MAX_PATH], invalid[MAX_PATH];
    swprintf(root, MAX_PATH, L"build/export-snapshot-fixture-%lu",
             (unsigned long)GetCurrentProcessId());
    if (!CreateDirectoryW(root, NULL)) return 1;
    const wchar_t *names[] = {L"space here", L"caf\u00e9 \u03a9", L"literal%41", L"hash#here"};
    bool arguments_ok = fixture_native_argument() && fixture_argument_refusals();
    printf("native quoted UTF-8 argument and refusal cases: %s\n",
           arguments_ok ? "PASS" : "FAIL");
    int failures = !arguments_ok;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        failures += qualify(root, names[i], (int)i + 31);
    swprintf(invalid, MAX_PATH, L"%ls/question?mark", root);
    SetLastError(ERROR_SUCCESS);
    bool refused = !CreateDirectoryW(invalid, NULL) &&
                   GetLastError() == ERROR_INVALID_NAME;
    printf("question mark: %s (Win32 ERROR_INVALID_NAME; no fixture possible)\n",
           refused ? "PASS explicit refusal" : "FAIL");
    if (!refused) { RemoveDirectoryW(invalid); ++failures; }
    if (!RemoveDirectoryW(root)) ++failures;
    return failures ? 1 : 0;
}
#else
typedef int export_snapshot_windows_acceptance_not_built;
#endif
