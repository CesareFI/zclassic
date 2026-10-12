/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Read source files beneath a root without following any link
 *          and hash them as the source content root v2
 *          (zcl_fr_source_content_v2). The root launcher's preflight and
 *          the proof receiver both measure through this one reader. */
#ifndef ZCL_TOOLS_VERIFY_FIXED_RESULT_SOURCE_H
#define ZCL_TOOLS_VERIFY_FIXED_RESULT_SOURCE_H

#include <stddef.h>
#include <stdint.h>

/* The files result.c's -E reads with the pinned profile, sorted: the chain
 * the launcher pins. The receiver hashes whatever its own -E read, so the
 * two agree exactly when the include chain is still these three files. */
#define ZCL_FR_SOURCE_CHAIN_COUNT 3u
extern const char *const zcl_fr_source_chain[ZCL_FR_SOURCE_CHAIN_COUNT];

#define ZCL_FR_SOURCE_FILE_MAX (4u * 1024u * 1024u)
#define ZCL_FR_SOURCE_TOTAL_MAX (64u * 1024u * 1024u)
#define ZCL_FR_SOURCE_FILES_MAX 4096u

/* Open `rel` beneath `root_fd` one component at a time with O_NOFOLLOW;
 * -1 on refusal. The caller closes the result. */
int zcl_fr_open_beneath(int root_fd, const char *rel);

/* Source content root v2 over `paths` beneath `root_fd`. Each file must be
 * regular, within the limits, and unchanged while read. Returns NULL or a
 * token: source_content_unreadable, source_content_unsafe,
 * source_content_limit, source_content_changed,
 * source_content_out_of_memory, or a zcl_fr_source_content_v2 refusal. */
const char *zcl_fr_source_content_at(int root_fd, const char *const *paths,
                                     size_t count, uint8_t out[32]);

/* The launcher's source_content pin value: zcl_fr_source_content_at over
 * zcl_fr_source_chain. */
const char *zcl_fr_source_chain_root(int root_fd, uint8_t out[32]);

#endif
