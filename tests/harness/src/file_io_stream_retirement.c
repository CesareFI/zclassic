/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: prove whole-file readers acquire their stream through the portable
 * no-inherit opener before any file bytes enter an owned allocation. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/file_stream.h"
#include "test/test_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>

static unsigned file_io_observed_opens;
static bool file_io_observed_cloexec;

static FILE *file_io_observe_open(const char *path)
{
    FILE *stream = platform_file_stream_open_read(path);
    ++file_io_observed_opens;
    int fd = stream ? fileno(stream) : -1;
    file_io_observed_cloexec = file_io_observed_cloexec && fd >= 0 &&
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
    return stream;
}

#define platform_file_stream_open_read file_io_observe_open
#define zcl_read_whole_file file_io_observed_read
#define zcl_read_whole_file_text file_io_observed_read_text
#include "../../../platform/modules/util/src/file_io.c"
#undef zcl_read_whole_file_text
#undef zcl_read_whole_file
#undef platform_file_stream_open_read
#endif

int file_io_stream_retirement_cases(void);
int file_io_stream_retirement_cases(void)
{
#ifdef _WIN32
    puts("path_check: whole-file stream refuses inheritance... UNOBSERVED (Windows runtime required)");
    return 0;
#else
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "file_io_stream");
    bool prepared = false;
    if (fd >= 0) {
        bool wrote = write(fd, "read", 4) == 4;
        bool closed = close(fd) == 0;
        prepared = wrote && closed;
    }
    file_io_observed_opens = 0;
    file_io_observed_cloexec = true;
    uint8_t *bytes = NULL;
    size_t length = 0;
    bool read_ok = prepared && file_io_observed_read(
        path, 4, &bytes, &length, "file_io_stream_test");
    bool binary_ok = read_ok && length == 4 && memcmp(bytes, "read", 4) == 0;
    free(bytes);
    char *text = NULL;
    length = 0;
    bool text_ok = prepared && file_io_observed_read_text(
        path, 4, &text, &length, "file_io_stream_test") && length == 4 &&
        strcmp(text, "read") == 0;
    free(text);
    bool okay = binary_ok && text_ok && file_io_observed_opens == 2 &&
        file_io_observed_cloexec;
    if (fd >= 0)
        (void)unlink(path);
    printf("path_check: whole-file stream refuses inheritance... %s\n",
        okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
#endif
}
