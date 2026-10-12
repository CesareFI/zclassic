/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_signed_output.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

static int fault_directory_fd = -1;
static bool fail_directory_sync, fail_rollback_unlink;

int __real_fsync(int fd);
int __real_unlinkat(int directory_fd, const char *path, int flags);

int __wrap_fsync(int fd) {
    if (fail_directory_sync && fd == fault_directory_fd) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

int __wrap_unlinkat(int directory_fd, const char *path, int flags) {
    if (fail_rollback_unlink && directory_fd == fault_directory_fd &&
        strcmp(path, "uncertain.bin") == 0) {
        errno = EIO;
        return -1;
    }
    return __real_unlinkat(directory_fd, path, flags);
}

static void path_in(char output[256], const char *directory,
    const char *leaf) {
    int length = snprintf(output, 256, "%s/%s", directory, leaf);
    assert(length > 0 && length < 256);
}

static void check_crash_before_commit(const char *path) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
        if (!blue_signed_output_begin(path, &stage) ||
            write(stage.file_fd, "partial", 7) != 7) _exit(2);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(access(path, F_OK) != 0);
}

static void check_published(const char *path) {
    static const uint8_t payload[] = {'Z', 'C', 'L', 0, 0xff};
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    assert(blue_signed_output_begin(path, &stage));
    assert(access(path, F_OK) != 0);
    assert(blue_signed_output_commit(&stage, payload, sizeof payload));
    assert(!blue_signed_output_commit(&stage, payload, sizeof payload));
    blue_signed_output_discard(&stage);
    struct stat info;
    assert(stat(path, &info) == 0);
    assert(S_ISREG(info.st_mode) && (info.st_mode & 0777) == 0600 &&
        info.st_size == (off_t)sizeof payload);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    uint8_t observed[sizeof payload];
    assert(fd >= 0 && read(fd, observed, sizeof observed) ==
        (ssize_t)sizeof observed);
    assert(close(fd) == 0 && memcmp(payload, observed, sizeof payload) == 0);
    assert(!blue_signed_output_begin(path, &stage));
}

static void check_existing_race(const char *path) {
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    assert(blue_signed_output_begin(path, &stage));
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, "other", 5) == 5 && close(fd) == 0);
    assert(!blue_signed_output_commit(&stage, (const uint8_t *)"signed", 6));
    assert(!blue_signed_output_commit(&stage, (const uint8_t *)"signed", 6));
    blue_signed_output_discard(&stage);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    char observed[5];
    assert(fd >= 0 && read(fd, observed, sizeof observed) ==
        (ssize_t)sizeof observed);
    assert(close(fd) == 0 && memcmp(observed, "other", 5) == 0);
}

static void check_refusals(const char *path, const char *link) {
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    assert(!blue_signed_output_begin(NULL, &stage));
    assert(!blue_signed_output_begin("/", &stage));
    assert(!blue_signed_output_begin(path, NULL));
    assert(symlink(path, link) == 0);
    assert(!blue_signed_output_begin(link, &stage));
    assert(unlink(link) == 0);
    assert(blue_signed_output_begin(link, &stage));
    assert(!blue_signed_output_commit(&stage, (const uint8_t *)"x",
        2 * 1024 * 1024 + 1));
    assert(access(link, F_OK) != 0);
    blue_signed_output_discard(&stage);
    assert(access(link, F_OK) != 0);
}

static void check_directory_replacement(const char *root) {
    char original[256], moved[256], expected[256], misplaced[256];
    path_in(original, root, "original");
    path_in(moved, root, "moved");
    assert(mkdir(original, 0700) == 0);
    path_in(expected, original, "signed.bin");
    path_in(misplaced, moved, "signed.bin");
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    assert(blue_signed_output_begin(expected, &stage));
    assert(rename(original, moved) == 0);
    assert(mkdir(original, 0700) == 0);
    assert(!blue_signed_output_commit(&stage, (const uint8_t *)"signed", 6));
    blue_signed_output_discard(&stage);
    assert(access(expected, F_OK) != 0 &&
        access(misplaced, F_OK) != 0);
    assert(rmdir(original) == 0 && rmdir(moved) == 0);
}

static void check_failed_rollback_can_leave_complete_file(
    const char *root) {
    static const uint8_t payload[] = {'s', 'i', 'g', 'n', 'e', 'd'};
    char path[256];
    path_in(path, root, "uncertain.bin");
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    assert(blue_signed_output_begin(path, &stage));
    fault_directory_fd = stage.directory_fd;
    fail_directory_sync = true;
    fail_rollback_unlink = true;
    assert(!blue_signed_output_commit(&stage, payload, sizeof payload));
    fail_directory_sync = false;
    fail_rollback_unlink = false;
    fault_directory_fd = -1;
    blue_signed_output_discard(&stage);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    uint8_t observed[sizeof payload] = {0};
    assert(fd >= 0 && read(fd, observed, sizeof observed) ==
        (ssize_t)sizeof observed);
    assert(close(fd) == 0 && memcmp(observed, payload,
        sizeof payload) == 0);
    assert(unlink(path) == 0);
}

int main(void) {
    mode_t previous_umask = umask(0077);
    char directory[] = "/tmp/zcl-blue-signed-output-XXXXXX";
    assert(mkdtemp(directory));
    char crashed[256], published[256], raced[256], linked[256];
    path_in(crashed, directory, "crashed.bin");
    path_in(published, directory, "published.bin");
    path_in(raced, directory, "raced.bin");
    path_in(linked, directory, "linked.bin");
    check_crash_before_commit(crashed);
    check_published(published);
    check_existing_race(raced);
    check_refusals(published, linked);
    check_directory_replacement(directory);
    check_failed_rollback_can_leave_complete_file(directory);
    assert(unlink(published) == 0 && unlink(raced) == 0);
    assert(rmdir(directory) == 0);
    (void)umask(previous_umask);
    return 0;
}
