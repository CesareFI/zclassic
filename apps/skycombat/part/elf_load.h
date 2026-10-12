/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: expose the bounded ELF-only admission and serialized loader contract. */
#ifndef SKY_ELF_PART_LOAD_H
#define SKY_ELF_PART_LOAD_H
#include "recipe_abi.h"
#include "elf_admit.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct sky_elf_part_generation {
    uint64_t id;
    const struct sky_hud_part_v1 *part;
    void *mapping;
    size_t mapping_bytes;
};
struct sky_elf_part_host {
    struct sky_elf_part_generation current;
    uint64_t last_id;
    bool in_call;
};
enum sky_elf_load_verdict {
    SKY_ELF_LOAD_OK, SKY_ELF_LOAD_ARGUMENT, SKY_ELF_LOAD_ADMISSION, SKY_ELF_LOAD_PLATFORM,
    SKY_ELF_LOAD_MEMORY, SKY_ELF_LOAD_LAYOUT, SKY_ELF_LOAD_RELOCATION, SKY_ELF_LOAD_DESCRIPTOR,
    SKY_ELF_LOAD_BUSY, SKY_ELF_LOAD_ID_EXHAUSTED, SKY_ELF_LOAD_CLEANUP
};
/* Single externally serialized host owner; initialize with {0}. No threads,
 * signals, constructors, implicit init or dlopen. Candidate bytes are copied
 * before admission. Admitted Linux x86-64 RELA supports 64/PC32/PLT32, no imports;
 * admission refuses address-dependent absolute 32/32S and executable-stack notes.
 * Pages are RW/non-X during preparation, then R or RX/non-W; gaps PROT_NONE.
 * Failed swap leaves current and last_id unchanged. IDs never wrap or reuse.
 * Old mapping retired only between calls; raw pointers must not escape a call.
 * CLEANUP reports a failed candidate munmap with address/span diagnostics;
 * cleanup is not claimed successful, and the host still retains current.
 * Not a sandbox: executing an admitted native function requires caller trust.
 */
enum sky_elf_load_verdict sky_elf_part_load(struct sky_elf_part_host *,const void *,size_t,
                                   const uint8_t expected_sha256[32],
                                   enum sky_elf_part_verdict *admission);
/* Borrow pins current until end; swap/dispose refuse while borrowed. */
const struct sky_elf_part_generation *sky_elf_part_call_begin(struct sky_elf_part_host *);
bool sky_elf_part_call_end(struct sky_elf_part_host *);
bool sky_elf_part_host_dispose(struct sky_elf_part_host *);
#endif
