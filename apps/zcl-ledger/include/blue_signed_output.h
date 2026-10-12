/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_SIGNED_OUTPUT_H
#define ZCL_BLUE_SIGNED_OUTPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int directory_fd;
    int file_fd;
    char *directory_path;
    char *leaf;
    bool published;
    bool attempted;
} blue_signed_output;

/* Opens an unnamed output file with mode no broader than 0600. The
 * destination must be absent. A crash before commit cannot expose bytes under
 * the requested name. Failure leaves result untouched. */
bool blue_signed_output_begin(const char *path, blue_signed_output *result);

/* Requires the destination path to resolve to the opened directory before
 * and after publication. Syncs complete bytes, creates the final name
 * without replacement, then syncs the directory. A failed call does not
 * publish a partial file. A complete file can remain if directory sync or
 * rollback fails after linkat succeeds; callers must inspect the path before
 * retrying after any commit failure.
 * The owner must discard the stage after either result. */
bool blue_signed_output_commit(blue_signed_output *stage,
    const uint8_t *bytes, size_t length);

/* Closes the stage. Published output remains; unpublished bytes disappear. */
void blue_signed_output_discard(blue_signed_output *stage);

#endif
