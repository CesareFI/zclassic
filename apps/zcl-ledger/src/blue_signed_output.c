/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _GNU_SOURCE
#include "blue_signed_output.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { BLUE_SIGNED_OUTPUT_MAX_BYTES = 2 * 1024 * 1024 };

static char *parent_path(const char *path, const char **leaf) {
    const char *slash = strrchr(path, '/');
    *leaf = slash ? slash + 1 : path;
    size_t length = slash ? (size_t)(slash - path) : 1;
    if (slash == path) length = 1;
    char *parent = malloc(length + 1);
    if (!parent) return NULL;
    if (slash) memcpy(parent, path, length);
    else parent[0] = '.';
    parent[length] = 0;
    return parent;
}

static bool target_absent(int directory_fd, const char *leaf) {
    struct stat info;
    if (fstatat(directory_fd, leaf, &info, AT_SYMLINK_NOFOLLOW) == 0)
        return false;
    return errno == ENOENT;
}

bool blue_signed_output_begin(const char *path, blue_signed_output *result) {
    if (!path || !result) return false;
    const char *leaf;
    char *parent = parent_path(path, &leaf);
    if (!parent) return false;
    bool valid = *leaf && strcmp(leaf, ".") != 0 &&
        strcmp(leaf, "..") != 0;
    int directory_fd = valid ? open(parent,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (directory_fd < 0) {
        free(parent);
        return false;
    }
    valid = target_absent(directory_fd, leaf);
    int file_fd = valid ? openat(directory_fd, ".",
        O_TMPFILE | O_RDWR | O_CLOEXEC, 0600) : -1;
    char *copy = file_fd >= 0 ? strdup(leaf) : NULL;
    if (!copy) {
        if (file_fd >= 0) (void)close(file_fd);
        (void)close(directory_fd);
        free(parent);
        return false;
    }
    *result = (blue_signed_output){.directory_fd = directory_fd,
        .file_fd = file_fd, .directory_path = parent, .leaf = copy};
    return true;
}

static bool same_directory(const blue_signed_output *stage) {
    struct stat opened, named;
    return stage->directory_path &&
        fstat(stage->directory_fd, &opened) == 0 &&
        stat(stage->directory_path, &named) == 0 &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

static bool write_all(int fd, const uint8_t *bytes, size_t length) {
    size_t position = 0;
    while (position < length) {
        ssize_t sent = write(fd, bytes + position, length - position);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return false;
        position += (size_t)sent;
    }
    return true;
}

static void remove_published_inode(const blue_signed_output *stage) {
    struct stat open_file, named_file;
    if (fstat(stage->file_fd, &open_file) == 0 &&
        fstatat(stage->directory_fd, stage->leaf, &named_file,
            AT_SYMLINK_NOFOLLOW) == 0 &&
        open_file.st_dev == named_file.st_dev &&
        open_file.st_ino == named_file.st_ino) {
        (void)unlinkat(stage->directory_fd, stage->leaf, 0);
        (void)fsync(stage->directory_fd);
    }
}

static bool publish_synced(blue_signed_output *stage) {
    if (linkat(stage->file_fd, "", stage->directory_fd, stage->leaf,
        AT_EMPTY_PATH) != 0) return false;
    if (fsync(stage->directory_fd) == 0 && same_directory(stage))
        return true;
    remove_published_inode(stage);
    return false;
}

bool blue_signed_output_commit(blue_signed_output *stage,
    const uint8_t *bytes, size_t length) {
    if (!stage || stage->file_fd < 0 || stage->directory_fd < 0 ||
        !stage->leaf || stage->published || stage->attempted ||
        !bytes || !length ||
        length > BLUE_SIGNED_OUTPUT_MAX_BYTES) return false;
    stage->attempted = true;
    if (!same_directory(stage) ||
        !write_all(stage->file_fd, bytes, length) ||
        fsync(stage->file_fd) != 0 || !publish_synced(stage)) return false;
    stage->published = true;
    return true;
}

void blue_signed_output_discard(blue_signed_output *stage) {
    if (!stage) return;
    if (stage->file_fd >= 0) (void)close(stage->file_fd);
    if (stage->directory_fd >= 0) (void)close(stage->directory_fd);
    free(stage->directory_path);
    free(stage->leaf);
    *stage = (blue_signed_output){.directory_fd = -1, .file_fd = -1};
}
