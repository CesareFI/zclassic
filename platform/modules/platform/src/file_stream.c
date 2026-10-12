/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Open read-only stdio streams without an inheritable descriptor
 * window on POSIX or Windows. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/file_stream.h"

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

FILE *platform_file_stream_open_read(const char *path)
{
    if (!path || !path[0])
        return NULL;
#ifdef _WIN32
    int fd = _open(path, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
    if (fd < 0)
        return NULL;
    FILE *stream = _fdopen(fd, "rb");
    if (!stream)
        (void)_close(fd);
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    FILE *stream = fdopen(fd, "r");
    if (!stream)
        (void)close(fd);
#endif
    return stream;
}
