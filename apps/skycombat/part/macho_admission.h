/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#ifndef SKY_MACHO_ADMISSION_H
#define SKY_MACHO_ADMISSION_H
#include "macho_admit.h"
#include <stdbool.h>
#define SLOT (1024u*1024u)
#define MAX_SECTIONS 64u
#define MAX_FIXUPS 4096u
struct region {size_t off,size;};
struct section {uint64_t old,size;size_t mapped;uint32_t off,rel,nrel,type;bool keep,text;};
struct fixup {size_t off;uint64_t value;unsigned width;};
struct image {
 const uint8_t *b;size_t n,total;uint64_t base;
 struct section sec[MAX_SECTIONS];unsigned ns;
 struct region reg[2*MAX_SECTIONS+8];unsigned nr;
 uint32_t sym,nsyms,str,nstr;bool syms,dysym,segment_seen;uint32_t partitions[6];
 uint64_t vmaddr,vmsize,fileoff,filesize;
 unsigned descriptor;uint64_t desc_offset;
 enum sky_macho_verdict failure;
 struct fixup plan[MAX_FIXUPS];unsigned np;
};
/* Preparation performs digest, parse and complete mapping-bound write planning.
 * It never writes candidate data to executable memory or invokes candidate code.
 * Intended base must be 16KiB aligned and base+SLOT fit signed64 address space.
 * Caller owns initialized storage, freezes input through application of plan,
 * and must not treat inert success as permission to execute the candidate. */
enum sky_macho_verdict sky_macho_prepare(struct image *,const void *,size_t,
 const uint8_t expected[32],uint64_t base);
bool sky_macho_rebase(struct image *,uint64_t base);
#endif
