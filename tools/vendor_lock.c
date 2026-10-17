/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Vendor bootstrap lock: preserve kernel ownership across build exec. */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "platform/clock.h"

#if defined(__MSYS__)
#include "private_acl_internal.h"
#include <io.h>
#include <stdint.h>
#include <sys/cygwin.h>

static_assert(sizeof(long) >= sizeof(intptr_t), "MSYS HANDLE bridge must retain pointer width");

static bool native_acl_valid(int fd)
{
    long raw = _get_osfhandle(fd);
    return raw != -1 && platform_private_acl_validate_handle(
        (HANDLE)(intptr_t)raw, false);
}

/* CREATE_NEW installs private authority atomically. Existing files are never
 * repaired here; identity() validates their retained handle's actual ACL. */
static int native_create_private(const char *path)
{
    wchar_t wide[32768];
    if (cygwin_conv_path(CCP_POSIX_TO_WIN_W, path, wide, sizeof(wide)))
        return -1;
    struct platform_private_acl acl;
    if (!platform_private_acl_create(&acl)) {
        errno = EACCES;
        return -1;
    }
    SECURITY_ATTRIBUTES attributes = {
        .nLength = sizeof(attributes),
        .lpSecurityDescriptor = platform_private_acl_descriptor(&acl),
        .bInheritHandle = FALSE};
    HANDLE created = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &attributes,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD error = GetLastError();
    bool valid = created != INVALID_HANDLE_VALUE &&
        platform_private_acl_validate_handle(created, false);
    bool closed = created == INVALID_HANDLE_VALUE || CloseHandle(created);
    platform_private_acl_destroy(&acl);
    if (created == INVALID_HANDLE_VALUE &&
        (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)) return 0;
    if (!valid || !closed) {
        errno = EACCES;
        return -1;
    }
    return 0;
}
#endif

#ifndef VENDOR_LOCK_BUILD_KEY
#define VENDOR_LOCK_BUILD_KEY "unqualified"
#endif
#define LOCK_FD 8

static int refuse(const char *reason, const char *path)
{
    fprintf(stderr, "[vendor] %s: %s (%s)\n", reason, path, strerror(errno));
    return 75;
}

static int identity(int fd, const char *path)
{
    struct stat opened, named;
    if (fstat(fd, &opened) || lstat(path, &named))
        return refuse("vendor_lock_identity_unavailable", path);
    if (!S_ISREG(opened.st_mode) || !S_ISREG(named.st_mode) ||
        opened.st_uid != geteuid() || named.st_uid != geteuid() ||
        (opened.st_mode & 0022) || (named.st_mode & 0022) ||
        opened.st_dev != named.st_dev || opened.st_ino != named.st_ino) {
        errno = EPERM;
        return refuse("vendor_lock_identity_refused", path);
    }
#if defined(__MSYS__)
    if (!native_acl_valid(fd)) {
        errno = EACCES;
        return refuse("vendor_lock_native_acl_refused", path);
    }
#endif
    return 0;
}

static int acquire(int fd, const char *path, long timeout)
{
    int64_t start = clock_now_monotonic_ns();
    if (start <= 0)
        return refuse("vendor_lock_clock_unavailable", path);
    for (;;) {
        if (!flock(fd, LOCK_EX | LOCK_NB))
            return identity(fd, path);
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR)
            return refuse("vendor_lock_acquire_failed", path);
        int64_t now = clock_now_monotonic_ns();
        if (now <= 0 || now < start)
            return refuse("vendor_lock_clock_unavailable", path);
        if (now - start >= (int64_t)timeout * 1000000000LL) {
            errno = ETIMEDOUT;
            return refuse("vendor_lock_timeout", path);
        }
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000};
        (void)nanosleep(&pause, NULL);
    }
}

static int run_command(char **argv)
{
    char *end = NULL;
    errno = 0;
    long timeout = strtol(argv[2], &end, 10);
    if (errno || !end || *end || timeout < 0 || timeout > 86400) {
        errno = EINVAL;
        return refuse("vendor_lock_timeout_invalid", argv[2]);
    }
    struct stat existing;
    if (!lstat(argv[1], &existing) && S_ISDIR(existing.st_mode)) {
        errno = EISDIR;
        return refuse("vendor_lock_legacy_directory_refused", argv[1]);
    }
#if defined(__MSYS__)
    if (native_create_private(argv[1]))
        return refuse("vendor_lock_private_create_refused", argv[1]);
    int fd = open(argv[1], O_RDWR | O_NOFOLLOW);
#else
    int fd = open(argv[1], O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
#endif
    if (fd < 0) return refuse("vendor_lock_open_refused", argv[1]);
    if (identity(fd, argv[1]) || acquire(fd, argv[1], timeout)) {
        close(fd);
        return 75;
    }
    if (fd != LOCK_FD) {
        if (dup2(fd, LOCK_FD) < 0) {
            close(fd);
            return refuse("vendor_lock_descriptor_failed", argv[1]);
        }
        close(fd);
    }
    execvp(argv[3], &argv[3]);
    return refuse("vendor_lock_exec_failed", argv[3]);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--build-key")) {
        puts(VENDOR_LOCK_BUILD_KEY);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--owns")) {
        if (identity(LOCK_FD, argv[2])) return 75;
        if (flock(LOCK_FD, LOCK_EX | LOCK_NB))
            return refuse("vendor_lock_inherited_not_owned", argv[2]);
        return identity(LOCK_FD, argv[2]);
    }
    if (argc < 4) {
        errno = EINVAL;
        return refuse("vendor_lock_usage: LOCK TIMEOUT COMMAND [ARGS...]", "argv");
    }
    return run_command(argv);
}
