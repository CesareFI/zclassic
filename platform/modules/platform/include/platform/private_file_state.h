/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: stat metadata of a private path or held private file, for
 * callers that revalidate an earlier authority check cheaply. Kept apart
 * from private_file.c so its consumers do not widen that file's users. */
#ifndef ZCL_PLATFORM_PRIVATE_FILE_STATE_H
#define ZCL_PLATFORM_PRIVATE_FILE_STATE_H

#include "platform/private_file.h"

#include <stdbool.h>
#include <stdint.h>

/* Metadata of one path or held file. Equal states taken under the caller's
 * serialization mean the same inode with unchanged size and timestamps. */
struct platform_private_path_state {
  uint64_t volume, file, size, mode, owner, links;
  int64_t modified_ns, changed_ns;
};

/* lstat / fstat metadata. POSIX only: Windows refuses so callers fall back. */
bool platform_private_path_state(const char *path,
                                 struct platform_private_path_state *state);
bool platform_private_file_state(struct platform_private_file *file,
                                 struct platform_private_path_state *state);

#endif
