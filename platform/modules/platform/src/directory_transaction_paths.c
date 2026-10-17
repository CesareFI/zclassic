/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: retained private-directory path entry and durable file publication.
 * Native namespace primitives remain owned by directory_transaction.c. */
#include "platform/directory_transaction.h"
#if defined(_WIN32)
#include "platform/private_file.h"
#include "platform/windows_path.h"
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
bool platform_directory_transaction_parent(
    const char *path, struct platform_directory_transaction *parent,
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u]) {
    if (!parent || !leaf) {
        errno = EINVAL;
        return false;
    }
    char resolved[4096], directory[4096];
    if (!path || !platform_private_destination_resolve(path, resolved, sizeof(resolved),
                                                       directory, sizeof(directory))) {
        errno = EINVAL;
        return false;
    }
    const char *base = strrchr(resolved, '/'), *back = strrchr(resolved, '\\');
    if (!base || (back && back > base))
        base = back;
    base = base ? base + 1 : resolved;
    size_t len = strlen(base);
    if (!len || len > PLATFORM_DIRECTORY_CHILD_LEAF_MAX) {
        errno = EINVAL;
        return false;
    }
    memcpy(leaf, base, len + 1u);
    if (!platform_directory_transaction_open(parent, directory)) {
        errno = EPERM;
        return false;
    }
    return true;
}

int platform_directory_result_errno(enum platform_directory_result result) {
    switch (result) {
    case PLATFORM_DIRECTORY_OK:
        return 0;
    case PLATFORM_DIRECTORY_MISSING:
        return ENOENT;
    case PLATFORM_DIRECTORY_EXISTS:
        return EEXIST;
    case PLATFORM_DIRECTORY_REFUSED:
        return EPERM;
    case PLATFORM_DIRECTORY_INVALID:
        return EINVAL;
    case PLATFORM_DIRECTORY_IO:
    case PLATFORM_DIRECTORY_OUTCOME_UNKNOWN:
        return EIO;
    }
    return EIO;
}
int platform_directory_child_duplicate_fd(uintptr_t native, int flags) {
    HANDLE copy = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)native, GetCurrentProcess(),
                         &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        errno = EIO;
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)copy, flags | _O_BINARY | _O_NOINHERIT);
    if (fd < 0)
        CloseHandle(copy);
    return fd;
}

int platform_directory_transaction_read_fd(const char *path, bool private_owner_only) {
    struct platform_directory_transaction parent;
    struct platform_directory_child child;
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&child);
    int fd = -1;
    if (private_owner_only) {
        char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
        if (!platform_directory_transaction_parent(path, &parent, leaf))
            return -1;
        enum platform_directory_result result = platform_directory_child_open_result(
            &parent, leaf, false, false, &child, NULL);
        if (result == PLATFORM_DIRECTORY_OK)
            fd = platform_directory_child_duplicate_fd(child.native, _O_RDONLY);
        else
            errno = platform_directory_result_errno(result);
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&parent);
        return fd;
    }
    wchar_t wide[32768];
    if (!platform_windows_wide_path(path, wide)) {
        errno = EINVAL;
        return -1;
    }
    HANDLE h = CreateFileW(wide, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        errno = e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ? ENOENT : EIO;
        return -1;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
        errno = EPERM;
    else
        fd = platform_directory_child_duplicate_fd((uintptr_t)h, _O_RDONLY);
    CloseHandle(h);
    return fd;
}

bool platform_directory_transaction_write_atomic(const char *path, const void *data,
                                                 size_t size) {
    struct platform_directory_transaction parent;
    struct platform_directory_child child;
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&child);
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char temporary[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    bool ok = platform_directory_transaction_parent(path, &parent, leaf);
    int count = ok ? snprintf(temporary, sizeof(temporary), "%s.tmp.%lu", leaf,
                              (unsigned long)GetCurrentProcessId())
                   : -1;
    if (ok && (count <= 0 || (size_t)count >= sizeof(temporary))) {
        errno = ENAMETOOLONG;
        ok = false;
    }
    if (ok) {
        enum platform_directory_result opened = platform_directory_child_open_result(
            &parent, temporary, true, false, &child, NULL);
        ok = opened == PLATFORM_DIRECTORY_OK;
        if (!ok)
            errno = platform_directory_result_errno(opened);
    }
    if (ok && (!platform_directory_child_write_exact(&child, data, size, 0) ||
               !platform_directory_child_flush(&child))) {
        errno = EIO;
        ok = false;
    }
    if (ok) {
        enum platform_directory_result moved = platform_directory_child_move_between(
            &parent, &child, &parent, leaf, false);
        ok = moved == PLATFORM_DIRECTORY_OK;
        if (!ok)
            errno = platform_directory_result_errno(moved);
        /* Unknown publication leaves both spellings observational. No cleanup. */
    }
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&parent);
    return ok;
}

bool platform_directory_transaction_remove_tree(const char *path) {
    struct platform_directory_transaction parent, dir;
    struct platform_directory_child file;
    platform_directory_transaction_init(&parent);
    platform_directory_transaction_init(&dir);
    platform_directory_child_init(&file);
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    bool ok = platform_directory_transaction_parent(path, &parent, leaf);
    enum platform_directory_result opened =
        ok ? platform_directory_transaction_open_child_namespace(&parent, leaf, false,
                                                                 &dir)
           : PLATFORM_DIRECTORY_REFUSED;
    if (opened == PLATFORM_DIRECTORY_MISSING)
        ok = true;
    else if (opened == PLATFORM_DIRECTORY_OK)
        ok = platform_directory_transaction_remove_retained(&dir, 0) &&
             platform_directory_transaction_flush(&parent);
    else if (ok) {
        opened = platform_directory_child_open_result(&parent, leaf, false, false,
                                                      &file, NULL);
        ok = opened == PLATFORM_DIRECTORY_MISSING ||
             (opened == PLATFORM_DIRECTORY_OK &&
              platform_directory_child_unlink(&parent, leaf, false));
    }
    platform_directory_child_close(&file);
    platform_directory_transaction_close(&dir);
    platform_directory_transaction_close(&parent);
    return ok;
}

bool platform_directory_transaction_replace_path(const char *staging,
                                                 const char *destination) {
    struct platform_directory_transaction from, to;
    struct platform_directory_child child;
    platform_directory_transaction_init(&from);
    platform_directory_transaction_init(&to);
    platform_directory_child_init(&child);
    char source[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u],
        target[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    bool ok = platform_directory_transaction_parent(staging, &from, source) &&
              platform_directory_transaction_parent(destination, &to, target) &&
              platform_directory_child_open(&from, source, &child);
    if (ok)
        ok = platform_directory_child_move_between(&from, &child, &to, target, false) ==
             PLATFORM_DIRECTORY_OK;
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&from);
    platform_directory_transaction_close(&to);
    return ok;
}
#else
typedef int platform_directory_transaction_paths_nonempty_translation_unit;
#endif
