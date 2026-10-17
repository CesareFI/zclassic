/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Pure platform policy for the terminal worker: which shell paths
 * each platform's grammar accepts, and whether the terminal lane may
 * activate on a platform at all. No I/O, no platform headers, so one
 * Linux-hosted test covers both grammars. */

#include "session/mesh_terminal_worker.h"

#include <string.h>

/* Bounds-check requested terminal geometry against the proto's wire limits.
 * Shared by the Linux and Windows arms; non-static so the stub-only build
 * (neither arm) does not trip -Wunused-function. */
bool geometry_in_bounds(uint16_t cols, uint16_t rows)
{
    return cols != 0 && cols <= MESH_TERMINAL_MAX_COLS && rows != 0 &&
           rows <= MESH_TERMINAL_MAX_ROWS;
}

static bool tw_win_separator(char c)
{
    return c == '\\' || c == '/';
}

/* One path byte: control bytes and the characters Windows reserves are
 * refused; ':' is the drive designator and is judged by the caller. */
static bool tw_win_char_ok(unsigned char c)
{
    return c >= 0x20u && c != '<' && c != '>' && c != ':' && c != '"' &&
           c != '|' && c != '?' && c != '*';
}

/* One component after the drive root: non-empty, not "." or "..", and no
 * trailing dot or space (Windows silently strips those, which would make
 * the checked name differ from the executed one), and not a reserved device
 * name (nul, con, aux, prn, com1-9, lpt1-9) with or without an extension. */
static char tw_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static bool tw_win_reserved_stem(const char *seg, size_t len)
{
    size_t n = 0;
    while (n < len && seg[n] != '.')
        n++;
    if (n != 3u && n != 4u)
        return false;
    char stem[5] = { 0 };
    for (size_t i = 0; i < n; i++)
        stem[i] = tw_lower(seg[i]);
    if (n == 3u)
        return !strcmp(stem, "nul") || !strcmp(stem, "con") ||
               !strcmp(stem, "aux") || !strcmp(stem, "prn");
    return stem[3] >= '1' && stem[3] <= '9' &&
           (!strncmp(stem, "com", 3) || !strncmp(stem, "lpt", 3));
}

static bool tw_win_segment_ok(const char *seg, size_t len)
{
    return len != 0 && seg[len - 1] != '.' && seg[len - 1] != ' ' &&
           !tw_win_reserved_stem(seg, len);
}

static bool tw_win_has_exe_suffix(const char *path, size_t len)
{
    static const char suffix[] = ".exe";
    if (len < sizeof(suffix) - 1u)
        return false;
    for (size_t i = 0; i < sizeof(suffix) - 1u; i++) {
        char c = path[len - sizeof(suffix) + 1u + i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (c != suffix[i])
            return false;
    }
    return true;
}

static bool tw_win_shell_path_valid(const char *path)
{
    size_t len = strnlen(path, MESH_TERMINAL_SHELL_PATH_MAX_WINDOWS);
    if (len < 4u || len >= MESH_TERMINAL_SHELL_PATH_MAX_WINDOWS)
        return false;
    bool letter = (path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z');
    if (!letter || path[1] != ':' || !tw_win_separator(path[2]))
        return false;
    if (!tw_win_has_exe_suffix(path, len))
        return false;
    size_t start = 3;
    for (size_t i = 3; i <= len; i++) {
        if (i < len && !tw_win_separator(path[i])) {
            if (!tw_win_char_ok((unsigned char)path[i]))
                return false;
            continue;
        }
        if (!tw_win_segment_ok(path + start, i - start))
            return false;
        start = i + 1u;
    }
    return true;
}

bool mesh_terminal_shell_path_valid(enum mesh_terminal_platform platform,
                                    const char *path)
{
    if (!path)
        return false;
    if (platform == MESH_TERMINAL_PLATFORM_WINDOWS)
        return tw_win_shell_path_valid(path);
    return path[0] == '/' &&
           strnlen(path, MESH_TERMINAL_SHELL_PATH_MAX_POSIX) <
               MESH_TERMINAL_SHELL_PATH_MAX_POSIX;
}

const char *mesh_terminal_confinement_refusal(
    enum mesh_terminal_platform platform, bool accept_unconfined)
{
    bool windows = platform == MESH_TERMINAL_PLATFORM_WINDOWS;
    if (accept_unconfined && !windows)
        return "unconfined-opt-in-windows-only";
    if (windows && !accept_unconfined)
        return "windows-shell-identity-unconfined";
    return NULL;
}

const char *mesh_terminal_confinement_marker(
    enum mesh_terminal_platform platform, bool accept_unconfined)
{
    if (accept_unconfined && platform == MESH_TERMINAL_PLATFORM_WINDOWS)
        return MESH_TERMINAL_CONFINEMENT_UNCONFINED;
    return "confined";
}

