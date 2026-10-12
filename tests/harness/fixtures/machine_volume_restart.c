/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Native process-boundary witness using only a fixed nonsecret fixture. */
#include "config/mesh_guest_private_volume.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "read") != 0))
        return 2;
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked(argv[2], &file)) return 3;
    struct zcl_machine_private_volume volume;
    struct rvmachine_disk *disk = NULL;
    bool ok = zcl_machine_private_volume_bind(&volume, &file, &disk);
    uint8_t expected[512], got[512];
    for (size_t i = 0; i < sizeof expected; i++) expected[i] = (uint8_t)(i ^ 0xa7u);
    if (ok && strcmp(argv[1], "write") == 0)
        ok = rvmachine_disk_write(disk, 512, expected, sizeof expected) &&
             rvmachine_disk_flush(disk);
    else if (ok)
        ok = rvmachine_disk_read(disk, 512, got, sizeof got) &&
             memcmp(expected, got, sizeof expected) == 0;
    rvmachine_disk_close(disk);
    platform_private_file_close(&file);
    if (ok) puts(strcmp(argv[1], "write") == 0 ? "VOLUME_WRITER_DURABLE" : "VOLUME_RESTART_READ_MATCH");
    return ok ? 0 : 4;
}
