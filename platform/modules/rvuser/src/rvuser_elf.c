/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fail-closed ELF64 riscv64 loader for static ET_EXEC and static-PIE (ET_DYN) programs. Reads
 * the file only through bounds-checked little-endian helpers. */
#include "rvuser_internal.h"
#include "base/serialize_le.h"
#include "base/log_macros.h"
#include <string.h>

#define EHDR_SIZE 64u
#define PHDR_SIZE 56u
#define PHNUM_MAX 64u
#define PT_LOAD 1u
#define PT_DYNAMIC 2u
#define PT_INTERP 3u
#define PF_X 1u
#define EM_RISCV 243u
#define ET_EXEC 2u
#define ET_DYN 3u
#define DT_NULL 0u
#define DT_NEEDED 1u
#define DT_TEXTREL 22u
#define DT_FLAGS 30u
#define DF_TEXTREL 4u
#define DYN_SIZE 16u
/* e_flags (RISC-V psABI): float ABI field is bits 1..2: 0 soft, 2 single, 4 double (lp64d,
 * the FreeBSD riscv64 userland ABI), 6 quad. Soft, single and double run on the IMAFDC hart;
 * quad and RVE are refused. */
#define EF_RISCV_FLOAT_ABI_MASK 0x6u
#define EF_RISCV_FLOAT_ABI_QUAD 0x6u
#define EF_RISCV_RVE 0x8u

static enum rvuser_error ru_check_ident(const uint8_t *e)
{
    if (e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F') return RVUSER_ERR_MAGIC;
    if (e[4] != 2) return RVUSER_ERR_CLASS;
    if (e[5] != 1) return RVUSER_ERR_ENDIAN;
    if (e[6] != 1) return RVUSER_ERR_VERSION;
    return RVUSER_ERR_NONE;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return zcl_read_u32_le(p); }
static uint64_t rd64(const uint8_t *p) { return zcl_read_u64_le(p); }

static enum rvuser_error ru_check_header(const uint8_t *e)
{
    enum rvuser_error err = ru_check_ident(e);
    if (err != RVUSER_ERR_NONE) return err;
    uint16_t type = rd16(e + 16);
    if (type != ET_EXEC && type != ET_DYN) return RVUSER_ERR_TYPE;
    if (rd16(e + 18) != EM_RISCV) return RVUSER_ERR_MACHINE;
    if (rd32(e + 20) != 1) return RVUSER_ERR_VERSION;
    uint32_t flags = rd32(e + 48);
    if ((flags & EF_RISCV_FLOAT_ABI_MASK) == EF_RISCV_FLOAT_ABI_QUAD || (flags & EF_RISCV_RVE) != 0)
        return RVUSER_ERR_FLAGS;
    if (rd16(e + 54) != PHDR_SIZE) return RVUSER_ERR_PHDR;
    uint16_t phnum = rd16(e + 56);
    return (phnum == 0 || phnum > PHNUM_MAX) ? RVUSER_ERR_PHDR : RVUSER_ERR_NONE;
}

static int ru_range_ok(uint64_t off, uint64_t n, size_t len)
{
    return off <= len && n <= len - off;
}

static enum rvuser_error ru_add_load(struct ru_image *img, const uint8_t *ph, size_t len)
{
    if (rd64(ph + 16) > UINT64_MAX - img->bias) return RVUSER_ERR_SEGMENT;
    struct ru_segment s = {rd64(ph + 16) + img->bias, rd64(ph + 40), rd64(ph + 32), rd64(ph + 8),
                           rd32(ph + 4)};
    if (s.filesz > s.memsz || !ru_range_ok(s.offset, s.filesz, len)) return RVUSER_ERR_SEGMENT;
    if (s.vaddr + s.memsz < s.vaddr || s.vaddr + s.memsz > (UINT64_MAX - RU_PAGE))
        return RVUSER_ERR_SEGMENT;
    if (s.memsz == 0) return RVUSER_ERR_NONE;
    if (img->nload >= RU_MAX_LOADS) return RVUSER_ERR_PHDR;
    for (unsigned i = 0; i < img->nload; i++) {
        const struct ru_segment *o = &img->seg[i];
        if (s.vaddr < o->vaddr + o->memsz && o->vaddr < s.vaddr + s.memsz)
            return RVUSER_ERR_OVERLAP;
    }
    img->seg[img->nload++] = s;
    return RVUSER_ERR_NONE;
}

/* PT_DYNAMIC policy. ET_EXEC: refused. A static non-PIE executable has no dynamic section, so a
 * PT_DYNAMIC there is a dynamically linked program that needs a run-time linker and relocations
 * this loader never applies. ET_DYN (static PIE): the table is scanned and the image refused
 * when it names a shared library (DT_NEEDED) or asks for text relocations (DT_TEXTREL, or
 * DT_FLAGS with DF_TEXTREL); no DT_NULL inside the file is malformed. RELATIVE relocations are
 * the program's own startup code's job, as for a FreeBSD static PIE. */
static enum rvuser_error ru_dynamic(const uint8_t *elf, size_t len, const uint8_t *ph,
                                    const struct ru_image *img)
{
    if (!img->pie) return RVUSER_ERR_DYNAMIC;
    uint64_t off = rd64(ph + 8), n = rd64(ph + 32);
    if (!ru_range_ok(off, n, len)) return RVUSER_ERR_DYNAMIC;
    for (uint64_t at = 0; at + DYN_SIZE <= n; at += DYN_SIZE) {
        uint64_t tag = rd64(elf + off + at), val = rd64(elf + off + at + 8);
        if (tag == DT_NULL) return RVUSER_ERR_NONE;
        if (tag == DT_NEEDED) return RVUSER_ERR_SHARED;
        if (tag == DT_TEXTREL || (tag == DT_FLAGS && (val & DF_TEXTREL))) return RVUSER_ERR_TEXTREL;
    }
    return RVUSER_ERR_DYNAMIC;
}

static enum rvuser_error ru_scan_phdrs(const uint8_t *elf, size_t len, struct ru_image *img)
{
    uint64_t phoff = rd64(elf + 32);
    if (!ru_range_ok(phoff, (uint64_t)img->phnum * PHDR_SIZE, len)) return RVUSER_ERR_TRUNCATED;
    for (unsigned i = 0; i < img->phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * PHDR_SIZE;
        uint32_t type = rd32(ph);
        enum rvuser_error err = RVUSER_ERR_NONE;
        if (type == PT_INTERP) err = RVUSER_ERR_INTERP;
        else if (type == PT_DYNAMIC) err = ru_dynamic(elf, len, ph, img);
        else if (type == PT_LOAD) err = ru_add_load(img, ph, len);
        if (err != RVUSER_ERR_NONE) return err;
    }
    return img->nload == 0 ? RVUSER_ERR_NO_LOAD : RVUSER_ERR_NONE;
}

static void ru_find_extent(struct ru_image *img, uint64_t phoff)
{
    img->lo = UINT64_MAX;
    img->hi = 0;
    for (unsigned i = 0; i < img->nload; i++) {
        const struct ru_segment *s = &img->seg[i];
        if (s->vaddr < img->lo) img->lo = s->vaddr;
        if (s->vaddr + s->memsz > img->hi) img->hi = s->vaddr + s->memsz;
        if (phoff >= s->offset && phoff - s->offset < s->filesz && img->phdr_addr == 0)
            img->phdr_addr = s->vaddr + (phoff - s->offset);
    }
    img->lo &= ~(RU_PAGE - 1u);
    img->hi = (img->hi + RU_PAGE - 1u) & ~(RU_PAGE - 1u);
}

static enum rvuser_error ru_check_entry(const struct ru_image *img)
{
    for (unsigned i = 0; i < img->nload; i++) {
        const struct ru_segment *s = &img->seg[i];
        if ((s->flags & PF_X) && img->entry >= s->vaddr && img->entry < s->vaddr + s->filesz &&
            (img->entry & 1u) == 0)
            return RVUSER_ERR_NONE;
    }
    return RVUSER_ERR_ENTRY;
}

enum rvuser_error ru_elf_parse(const uint8_t *elf, size_t len, struct ru_image *img)
{
    memset(img, 0, sizeof(*img));
    if (!elf || len < EHDR_SIZE) return RVUSER_ERR_TRUNCATED;
    enum rvuser_error err = ru_check_header(elf);
    if (err != RVUSER_ERR_NONE) return err;
    img->pie = rd16(elf + 16) == ET_DYN;
    img->bias = img->pie ? RU_PIE_BIAS : 0;
    if (rd64(elf + 24) > UINT64_MAX - img->bias) return RVUSER_ERR_ENTRY;
    img->entry = rd64(elf + 24) + img->bias;
    img->phnum = rd16(elf + 56);
    err = ru_scan_phdrs(elf, len, img);
    if (err != RVUSER_ERR_NONE) return err;
    ru_find_extent(img, rd64(elf + 32));
    return ru_check_entry(img);
}

enum rvuser_error ru_elf_map(const uint8_t *elf, const struct ru_image *img,
                             const struct rvemu_mem *mem)
{
    for (unsigned i = 0; i < img->nload; i++) {
        const struct ru_segment *s = &img->seg[i];
        if (s->vaddr < mem->base || s->vaddr - mem->base > mem->size ||
            s->memsz > mem->size - (s->vaddr - mem->base))
            LOG_RETURN(RVUSER_ERR_SEGMENT_RANGE, "rvuser",
                       "segment %u [%#llx,+%#llx) outside guest memory", i,
                       (unsigned long long)s->vaddr, (unsigned long long)s->memsz);
        memcpy(mem->bytes + (s->vaddr - mem->base), elf + s->offset, (size_t)s->filesz);
    }
    return RVUSER_ERR_NONE;
}
