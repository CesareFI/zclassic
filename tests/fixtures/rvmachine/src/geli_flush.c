/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Fixed PUBLIC acceptance fixture; no credential or arbitrary device input. */
#include <fcntl.h>
#include <libgeom.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = open("/dev/vtbd0", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("PUBLIC_GELI_FLUSH_OPEN"); return 1; }
    int rc = 0;
    if (g_mediasize(fd) != (INT64_C(16) << 20)) {
        fprintf(stderr, "PUBLIC_GELI_FLUSH_SIZE_REFUSED\n");
        rc = 2;
    } else if (g_flush(fd) != 0) {
        perror("PUBLIC_GELI_FLUSH_IOCTL");
        rc = 3;
    }
    if (close(fd) != 0) { perror("PUBLIC_GELI_FLUSH_CLOSE"); rc = 4; }
    return rc;
}
