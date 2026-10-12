/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves file_copy() produces a private, byte-identical, bounded
 * copy and refuses a directory destination.
 *
 * The `_WIN32` arm (dir_copy() refuses without creating the tree;
 * block_files_clean() spares blk*.dat) lives on as the `file_ops_copy` entry
 * in platform/modules/platform/tests/windows_acceptance.mk, which
 * cross-links it for Windows with a no-op zcl_tree_remove() stub. */
#include "test/test_core.h"

#include "config/file_ops.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <string.h>

static int file_ops_copy_probe(const char *datadir)
{
    if (!platform_private_directory_ensure(datadir))
        return 2;
    char source[1024], target[1024], directory_target[1024];
    if (snprintf(source, sizeof(source), "%s/source.bin", datadir) <= 0 ||
        snprintf(target, sizeof(target), "%s/target.bin", datadir) <= 0 ||
        snprintf(directory_target, sizeof(directory_target), "%s/directory",
                 datadir) <= 0)
        return 3;
    struct platform_private_file file;
    platform_private_file_init(&file);
    static const char payload[] = "stable-copy-payload";
    if (!platform_private_file_create(source, &file) ||
        !platform_private_file_write_at(&file, payload, sizeof(payload), 0) ||
        !platform_private_file_flush(&file))
        return 4;
    platform_private_file_close(&file);
    if (!platform_private_directory_ensure(directory_target) ||
        file_copy(source, directory_target) || !file_copy(source, target))
        return 5;
    struct platform_positioned_file copied;
    char actual[sizeof(payload)];
    platform_positioned_file_init(&copied);
    bool ok = platform_positioned_file_open(&copied, target) &&
              platform_positioned_file_is_private(&copied) &&
              platform_positioned_file_read(&copied, actual, sizeof(actual),
                                             0) == (int64_t)sizeof(actual) &&
              memcmp(actual, payload, sizeof(payload)) == 0;
    platform_positioned_file_close(&copied);
    return ok ? 0 : 8;
}

int test_file_ops_copy(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "file_ops_copy", "private");
    printf("file_ops_copy: private byte-identical copy, directory "
           "destination refused... ");
    int rc = file_ops_copy_probe(dir);
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    test_rm_rf_recursive(dir);
    return failures;
}
