/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#ifndef SKY_PART_OPEN_H
#define SKY_PART_OPEN_H
#include "macho_load.h"
#include "macho_admit.h"
enum sky_open_verdict {SKY_OPEN_OK,SKY_OPEN_ARGUMENT,SKY_OPEN_MEMORY,
 SKY_OPEN_DIGEST,SKY_OPEN_ADMISSION,SKY_OPEN_LOADER};
struct sky_open_result {enum sky_open_verdict verdict;
 enum sky_macho_verdict admission;enum sky_load_verdict loader;};
/* Serialized valid host, same ownership/borrow/platform authority as loader.
 * Caller keeps bytes and expected digest stable/readable while copied.
 * Private snapshot is hashed, admitted, then passed unchanged to native loader.
 * Digest/admission refusals never call the loader and cannot map anything.
 * Loader refusals retain their typed reason. No candidate function is invoked.
 */
struct sky_open_result sky_part_open(struct sky_part_host *,const void *,size_t,
 const uint8_t expected[32]);
#endif
