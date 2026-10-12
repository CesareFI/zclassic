/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: expose the bounded ELF-only admission and serialized loader contract. */
#ifndef SKY_ELF_PART_ADMIT_H
#define SKY_ELF_PART_ADMIT_H
#include <stddef.h>
#include <stdint.h>
#define SKY_ELF_PART_MAX_RELOCATIONS 4096u
/* Shared inert relocation write policy; address-dependent 32/32S refuse. */
static inline unsigned sky_elf_part_relocation_width(uint32_t type)
{
    switch(type){case 1:return 8;case 2:case 4:return 4;default:return 0;}
}
enum sky_elf_part_verdict {
    SKY_ELF_PART_ADMIT, SKY_ELF_PART_ARGUMENT, SKY_ELF_PART_DIGEST, SKY_ELF_PART_FORMAT,
    SKY_ELF_PART_TARGET, SKY_ELF_PART_BOUNDS, SKY_ELF_PART_OVERLAP, SKY_ELF_PART_UNDEFINED,
    SKY_ELF_PART_STARTUP, SKY_ELF_PART_TLS, SKY_ELF_PART_IFUNC, SKY_ELF_PART_MISSING,
    SKY_ELF_PART_DUPLICATE, SKY_ELF_PART_ABI, SKY_ELF_PART_ABSOLUTE_RELOCATION,
    SKY_ELF_PART_EXEC_STACK, SKY_ELF_PART_RELOCATION_TARGET, SKY_ELF_PART_RELOCATION_FORMAT
};
/* Borrowed immutable inert bytes, bounded to 16 MiB; SHA256 is 32 raw bytes.
 * ADMIT establishes only this ELF structural policy, never code safety,
 * permission to link/execute, recipe correctness or machine-code purity.
 * ELF64 little-endian ET_REL, x86-64 only. No IO, allocation or loading.
 * The mandatory ELF null symbol is not an import; every other UNDEF refuses.
 * No mutable input may race the call. No extended section/symbol indices.
 * Executable GNU stack notes and address-dependent 32/32S absolute relocations
 * refuse. RELA only; types 64/PC32/PLT32 with valid ordinary allocated
 * references, bounded disjoint writes, and no descriptor ABI/size write.
 * At most 4096 relocations bound the disjointness scan's quadratic work.
 * Ordinary symbols fit their section; special address indices refuse.
 * Only local STT_FILE, ABS, value=size=0 is non-address file metadata.
 * Allocated types/flags are restricted; all alignment is power-of-two/zero,
 * and object W+X requests refuse. Page padding/resources remain loader policy.
 */
enum sky_elf_part_verdict sky_elf_part_admit(const void *bytes, size_t length,
                                    const uint8_t expected_sha256[32]);
#endif
