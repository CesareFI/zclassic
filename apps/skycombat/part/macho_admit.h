/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#ifndef SKY_PART_ADMIT_MACHO_H
#define SKY_PART_ADMIT_MACHO_H
#include <stddef.h>
#include <stdint.h>
enum sky_macho_verdict {
 SKY_MACHO_ADMIT, SKY_MACHO_ARGUMENT, SKY_MACHO_DIGEST, SKY_MACHO_FORMAT,
 SKY_MACHO_TARGET, SKY_MACHO_BOUNDS, SKY_MACHO_OVERLAP, SKY_MACHO_UNDEFINED,
 SKY_MACHO_INDIRECT, SKY_MACHO_RESOLVER, SKY_MACHO_LINKER_OPTION,
 SKY_MACHO_STARTUP, SKY_MACHO_TLS, SKY_MACHO_MISSING, SKY_MACHO_DUPLICATE,
 SKY_MACHO_ABI, SKY_MACHO_RELOCATION
};
/* Immutable borrowed inert bytes <=16MiB, raw SHA256. Thin little-endian
 * arm64-all MH_OBJECT only. No IO/loading/execution; checked host allocation; not a sandbox
 * or machine-code safety proof. Caller prevents mutation throughout call.
 * Shared strict profile with PAGE21/PAGEOFF12; ADDEND and unlisted forms refuse.
 */
enum sky_macho_verdict sky_part_admit_macho(const void *, size_t,
                                           const uint8_t expected_sha256[32]);
#endif
