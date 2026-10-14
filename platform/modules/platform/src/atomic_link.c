/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: platform_atomic_symlink, see platform/atomic_link.h. */
#include "platform/atomic_link.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(_WIN32)
enum { ATOMIC_LINK_PATH_MAX = 4096 };

static int atomic_link_temp_name(const char *link_path, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.new.%ld", link_path, (long)getpid());
    if (n < 0 || (size_t)n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Make the rename durable by syncing the directory that holds the link. */
static int atomic_link_sync_parent(const char *link_path)
{
    char dir[ATOMIC_LINK_PATH_MAX];
    const char *slash = strrchr(link_path, '/');
    size_t len = slash ? (size_t)(slash - link_path) : 0;
    if (len >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (slash && len > 0)
        memcpy(dir, link_path, len);
    else if (slash)
        len = 1, dir[0] = '/';
    else
        len = 1, dir[0] = '.';
    dir[len] = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int rc = fsync(fd) == 0 || errno == EINVAL ? 0 : -1;
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}
#endif

int platform_atomic_symlink(const char *target, const char *link_path)
{
#if defined(_WIN32)
    (void)target;
    (void)link_path;
    errno = ENOTSUP;
    return -1;
#else
    char tmp[ATOMIC_LINK_PATH_MAX];
    if (!target || !link_path || !target[0] || !link_path[0]) {
        errno = EINVAL;
        return -1;
    }
    if (atomic_link_temp_name(link_path, tmp, sizeof(tmp)) != 0)
        return -1;
    if (unlink(tmp) != 0 && errno != ENOENT)
        return -1;
    if (symlink(target, tmp) != 0)
        return -1;
    if (rename(tmp, link_path) != 0) {
        int saved = errno;
        (void)unlink(tmp);
        errno = saved;
        return -1;
    }
    return atomic_link_sync_parent(link_path);
#endif
}
