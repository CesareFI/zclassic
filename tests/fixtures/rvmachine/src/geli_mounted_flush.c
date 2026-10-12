/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Check a fixed PUBLIC attached-GELI provider barrier after unmount.
 * No credential input or arbitrary device path. */
#include <fcntl.h>
#include <libgeom.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = open("/dev/vtbd0.eli", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("PUBLIC_GELI_FLUSH_OPEN"); return 1; }
    int rc = 0;
    /* (16MiB - 512-byte metadata) / 4608 * 4096, pinned authenticated mode. */
    if (g_mediasize(fd) != INT64_C(14909440)) {
        fprintf(stderr, "PUBLIC_GELI_FLUSH_SIZE_REFUSED\n");
        rc = 2;
    } else if (g_flush(fd) != 0) {
        perror("PUBLIC_GELI_FLUSH_IOCTL");
        rc = 3;
    }
    if (close(fd) != 0) { perror("PUBLIC_GELI_FLUSH_CLOSE"); rc = 4; }
    return rc;
}
