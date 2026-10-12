/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The one reader behind the source_content pin: files beneath a
 *          root, no link followed, hashed by zcl_fr_source_content_v2.
 *          See fixed_result_source.h. */
#define _POSIX_C_SOURCE 200809L
#include "verify/fixed_result_source.h"

#include "verify/fixed_result_contract.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRS_DEPTH_MAX 32u

const char *const zcl_fr_source_chain[ZCL_FR_SOURCE_CHAIN_COUNT] = {
    "platform/modules/base/include/base/format_attribute.h",
    "platform/modules/base/include/base/result.h",
    "platform/modules/base/src/result.c",
};

int zcl_fr_open_beneath(int root_fd, const char *rel)
{
    char path[PATH_MAX];
    if (root_fd < 0 || !rel || rel[0] == '/' ||
        snprintf(path, sizeof(path), "%s", rel) >= (int)sizeof(path))
        return -1;
    int dir = dup(root_fd);
    char *save = NULL, *part = strtok_r(path, "/", &save);
    unsigned depth = 0;
    while (dir >= 0 && part && depth++ < FRS_DEPTH_MAX) {
        char *next = strtok_r(NULL, "/", &save);
        if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) break;
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                    (next ? O_DIRECTORY : O_NONBLOCK);
        int child = openat(dir, part, flags);
        (void)close(dir);
        if (!next) return child;
        dir = child;
        part = next;
    }
    if (dir >= 0) (void)close(dir);
    return -1;
}

static bool frs_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime;
}

/* A regular file beneath the root within the budget; its stat in `st`. */
static const char *frs_open(int root_fd, const char *rel, size_t budget,
                            int *fd, struct stat *st)
{
    *fd = zcl_fr_open_beneath(root_fd, rel);
    if (*fd < 0) return "source_content_unreadable";
    if (fstat(*fd, st) != 0 || !S_ISREG(st->st_mode))
        return "source_content_unsafe";
    if (st->st_size < 0 || (uint64_t)st->st_size > ZCL_FR_SOURCE_FILE_MAX ||
        (size_t)st->st_size > budget)
        return "source_content_limit";
    return NULL;
}

static bool frs_read_all(int fd, uint8_t *p, size_t n)
{
    size_t at = 0;
    while (at < n) {
        ssize_t got = read(fd, p + at, n - at);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        at += (size_t)got;
    }
    return true;
}

/* One regular file, read whole and unchanged across the read. */
static const char *frs_read(int root_fd, const char *rel, size_t budget,
                            uint8_t **out, size_t *len)
{
    struct stat before, after;
    int fd = -1;
    const char *why = frs_open(root_fd, rel, budget, &fd, &before);
    size_t n = why ? 0u : (size_t)before.st_size;
    uint8_t *p = why ? NULL : zcl_malloc(n + 1u, "fixed result source file");
    if (!why && !p) why = "source_content_out_of_memory";
    if (!why && (!frs_read_all(fd, p, n) || fstat(fd, &after) != 0 ||
                 !frs_same(&before, &after)))
        why = "source_content_changed";
    if (fd >= 0) (void)close(fd);
    if (why) {
        free(p);
        return why;
    }
    *out = p;
    *len = n;
    return NULL;
}

const char *zcl_fr_source_content_at(int root_fd, const char *const *paths,
                                     size_t count, uint8_t out[32])
{
    if (root_fd < 0 || !paths || count == 0 || count > ZCL_FR_SOURCE_FILES_MAX)
        return ZCL_FR_WHY_ARGUMENTS;
    uint8_t **bytes = zcl_calloc(count, sizeof(*bytes), "fixed result sources");
    size_t *lens = zcl_calloc(count, sizeof(*lens), "fixed result lengths");
    const char *why = bytes && lens ? NULL : "source_content_out_of_memory";
    size_t budget = ZCL_FR_SOURCE_TOTAL_MAX;
    for (size_t i = 0; !why && i < count; i++) {
        why = frs_read(root_fd, paths[i], budget, &bytes[i], &lens[i]);
        if (!why) budget -= lens[i];
    }
    if (!why &&
        !zcl_fr_source_content_v2(paths, (const uint8_t *const *)bytes, lens,
                                  count, out, &why))
        why = why ? why : ZCL_FR_WHY_ARGUMENTS;
    for (size_t i = 0; bytes && i < count; i++) free(bytes[i]);
    free(bytes);
    free(lens);
    return why;
}

const char *zcl_fr_source_chain_root(int root_fd, uint8_t out[32])
{
    return zcl_fr_source_content_at(root_fd, zcl_fr_source_chain,
                                    ZCL_FR_SOURCE_CHAIN_COUNT, out);
}
