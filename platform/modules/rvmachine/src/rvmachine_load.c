/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: kernel loader. Places an ELF64 RISC-V image by its program headers
 * (physical addresses when they are usable, otherwise relative to the lowest
 * virtual address) or a flat binary at the kernel base, zeroes the bss, and
 * refuses anything that leaves RAM, passes the size limit or reaches the
 * device tree. Every field read from the image is bounds-checked, and guest
 * memory is written only once nothing can refuse the load any more. Chooses
 * the entry: the firmware one, or with a boot seed source the loader one. */
#include "rvmachine_priv.h"

#include "base/serialize_le.h"

#include <string.h>

#define ELF_HEADER_SIZE 64u
#define ELF_PHDR_SIZE 56u
#define ELF_PT_LOAD 1u
#define ELF_PF_X 1u
#define ELF_MACHINE_RISCV 243u
#define ELF_PHNUM_MAX 64u

struct seg {
    uint64_t offset, vaddr, paddr, filesz, memsz;
    uint32_t flags;
};

struct plan {
    struct seg segs[ELF_PHNUM_MAX];
    size_t n;
    uint64_t low_vaddr;
    uint64_t low_paddr;
    bool use_paddr;
    uint64_t image_end; /* first address above every placed segment */
    uint64_t entry;     /* e_entry */
};

static bool has_elf_magic(const uint8_t *image, size_t len)
{
    static const uint8_t magic[4] = {0x7f, 'E', 'L', 'F'};
    return len >= sizeof magic && memcmp(image, magic, sizeof magic) == 0;
}

static bool is_elf64_riscv(const uint8_t *image, size_t len)
{
    static const uint8_t magic[6] = {0x7f, 'E', 'L', 'F', 2 /* 64-bit */, 1 /* LE */};
    if (len < ELF_HEADER_SIZE || memcmp(image, magic, sizeof magic) != 0)
        return false;
    return zcl_read_u16_le(image + 18) == ELF_MACHINE_RISCV;
}

/* First address a kernel may not reach: the size limit or the device tree. */
static uint64_t image_ceiling(const struct rvmachine *m)
{
    uint64_t limit = RVMACHINE_RAM_BASE + RVMACHINE_IMAGE_LIMIT;
    return limit < m->dtb_addr ? limit : m->dtb_addr;
}

/* True when [addr, addr + size) lies in [kernel base, ceiling). */
static bool span_ok(const struct rvmachine *m, uint64_t addr, uint64_t size)
{
    uint64_t ceiling = image_ceiling(m);
    if (addr < RVMACHINE_KERNEL_BASE || addr > ceiling) return false;
    return size <= ceiling - addr;
}

static bool read_segment(size_t len, const uint8_t *ph,
                         struct seg *s)
{
    s->flags = zcl_read_u32_le(ph + 4);
    s->offset = zcl_read_u64_le(ph + 8);
    s->vaddr = zcl_read_u64_le(ph + 16);
    s->paddr = zcl_read_u64_le(ph + 24);
    s->filesz = zcl_read_u64_le(ph + 32);
    s->memsz = zcl_read_u64_le(ph + 40);
    if (s->filesz > s->memsz) return false;
    return s->offset <= len && s->filesz <= len - s->offset;
}

static enum rvmachine_status read_plan(const uint8_t *image, size_t len,
                                       struct plan *p)
{
    uint64_t phoff = zcl_read_u64_le(image + 32);
    unsigned phentsize = zcl_read_u16_le(image + 54);
    unsigned phnum = zcl_read_u16_le(image + 56);
    if (phentsize != ELF_PHDR_SIZE || phnum == 0 || phnum > ELF_PHNUM_MAX)
        return RVMACHINE_ERR_IMAGE;
    if (phoff > len || (uint64_t)phnum * ELF_PHDR_SIZE > len - phoff)
        return RVMACHINE_ERR_IMAGE;
    p->n = 0;
    p->low_vaddr = UINT64_MAX;
    p->low_paddr = UINT64_MAX;
    p->entry = zcl_read_u64_le(image + 24);
    for (unsigned i = 0; i < phnum; i++) {
        const uint8_t *ph = image + phoff + (uint64_t)i * ELF_PHDR_SIZE;
        struct seg *s = &p->segs[p->n];
        if (zcl_read_u32_le(ph) != ELF_PT_LOAD) continue;
        if (!read_segment(len, ph, s)) return RVMACHINE_ERR_IMAGE;
        if (s->memsz == 0) continue;
        if (s->vaddr < p->low_vaddr) p->low_vaddr = s->vaddr;
        if (s->paddr < p->low_paddr) p->low_paddr = s->paddr;
        p->n++;
    }
    return p->n != 0 ? RVMACHINE_OK : RVMACHINE_ERR_IMAGE;
}

/* Physical addresses are usable when the lowest segment starts at the kernel
 * base and every segment lies inside the loadable span. */
static bool paddr_usable(const struct rvmachine *m, const struct plan *p)
{
    if (p->low_paddr != RVMACHINE_KERNEL_BASE) return false;
    for (size_t i = 0; i < p->n; i++)
        if (!span_ok(m, p->segs[i].paddr, p->segs[i].memsz)) return false;
    return true;
}

static uint64_t seg_dest(const struct plan *p, const struct seg *s)
{
    if (p->use_paddr) return s->paddr;
    return RVMACHINE_KERNEL_BASE + (s->vaddr - p->low_vaddr);
}

static enum rvmachine_status check_plan(const struct rvmachine *m, struct plan *p)
{
    p->use_paddr = paddr_usable(m, p);
    p->image_end = RVMACHINE_KERNEL_BASE;
    for (size_t i = 0; i < p->n; i++) {
        const struct seg *s = &p->segs[i];
        uint64_t rel = s->vaddr - p->low_vaddr;
        uint64_t dest = seg_dest(p, s);
        if (!p->use_paddr && rel > RVMACHINE_IMAGE_LIMIT)
            return RVMACHINE_ERR_IMAGE_RANGE;
        if (!span_ok(m, dest, s->memsz)) return RVMACHINE_ERR_IMAGE_RANGE;
        if (dest + s->memsz > p->image_end) p->image_end = dest + s->memsz;
    }
    return RVMACHINE_OK;
}

/* The firmware entry: the start of the image, with the device tree in a1. */
static void firmware_entry(struct rvmachine *m)
{
    m->entry_pc = RVMACHINE_KERNEL_BASE;
    m->entry_a0 = 0; /* hart id */
    m->entry_a1 = m->dtb_addr;
}

/* True when every segment lies as far above the kernel base as its p_vaddr
 * lies above the lowest one, so that one offset turns any loaded address
 * into the virtual address the kernel was linked for. */
static bool one_offset(const struct plan *p)
{
    for (size_t i = 0; i < p->n; i++) {
        const struct seg *s = &p->segs[i];
        if (seg_dest(p, s) - RVMACHINE_KERNEL_BASE != s->vaddr - p->low_vaddr)
            return false;
    }
    return true;
}

/* Where e_entry was loaded: inside the file bytes of an executable segment.
 * The address the hart would start at must itself be even: the hart has the
 * compressed extension, so an instruction starts on any 2-byte boundary and
 * the engine faults a fetch from an odd pc. The parity of e_entry says
 * nothing about it when the image is linked at an odd address. */
static bool entry_address(const struct plan *p, uint64_t *pc)
{
    for (size_t i = 0; i < p->n; i++) {
        const struct seg *s = &p->segs[i];
        if ((s->flags & ELF_PF_X) == 0 || p->entry < s->vaddr) continue;
        if (p->entry - s->vaddr >= s->filesz) continue;
        *pc = seg_dest(p, s) + (p->entry - s->vaddr);
        return (*pc & 1u) == 0;
    }
    return false;
}

/* Everything the loader entry needs, decided before guest memory is touched:
 * the entry address, room for what is written above the image, and the seed
 * itself, asked for last so that an unusable image costs the source nothing. */
static enum rvmachine_status seeded_entry(struct rvmachine *m, const struct plan *p,
                                          struct rvmachine_preload *pre, uint64_t *pc)
{
    enum rvmachine_status st;
    if (!one_offset(p) || !entry_address(p, pc)) return RVMACHINE_ERR_ENTRY;
    st = rvmachine_preload_plan(m, p->image_end, p->low_vaddr, image_ceiling(m), pre);
    if (st != RVMACHINE_OK) return st;
    return rvmachine_preload_seed(m);
}

static void place_segments(struct rvmachine *m, const uint8_t *image, const struct plan *p)
{
    for (size_t i = 0; i < p->n; i++) {
        const struct seg *s = &p->segs[i];
        uint8_t *host = m->mem.bytes + (seg_dest(p, s) - RVMACHINE_RAM_BASE);
        memcpy(host, image + s->offset, (size_t)s->filesz);
        memset(host + s->filesz, 0, (size_t)(s->memsz - s->filesz));
    }
    m->image_end = p->image_end;
}

static enum rvmachine_status load_elf(struct rvmachine *m, const uint8_t *image,
                                      size_t len)
{
    struct plan p;
    struct rvmachine_preload pre;
    uint64_t pc = 0;
    bool seeded = m->boot_seed != NULL;
    enum rvmachine_status st = read_plan(image, len, &p);
    if (st == RVMACHINE_OK) st = check_plan(m, &p);
    if (st == RVMACHINE_OK && seeded) st = seeded_entry(m, &p, &pre, &pc);
    if (st != RVMACHINE_OK) return st;
    place_segments(m, image, &p);
    if (seeded)
        rvmachine_preload_write(m, &pre, pc);
    else
        firmware_entry(m);
    return RVMACHINE_OK;
}

static enum rvmachine_status load_flat(struct rvmachine *m, const uint8_t *image,
                                       size_t len)
{
    if (m->boot_seed != NULL) return RVMACHINE_ERR_ENTRY; /* no loader entry */
    if (len < 4u) return RVMACHINE_ERR_IMAGE;
    if (!span_ok(m, RVMACHINE_KERNEL_BASE, len)) return RVMACHINE_ERR_IMAGE_RANGE;
    memcpy(m->mem.bytes + (RVMACHINE_KERNEL_BASE - RVMACHINE_RAM_BASE), image, len);
    m->image_end = RVMACHINE_KERNEL_BASE + len;
    firmware_entry(m);
    return RVMACHINE_OK;
}

enum rvmachine_status rvmachine_load_kernel(struct rvmachine *m,
                                            const uint8_t *image, size_t len)
{
    enum rvmachine_status st;
    if (m == NULL || image == NULL) return RVMACHINE_ERR_ARG;
    if (m->loaded) return RVMACHINE_ERR_STATE; /* one kernel per machine */
    if (has_elf_magic(image, len) && !is_elf64_riscv(image, len))
        return RVMACHINE_ERR_IMAGE; /* an ELF for another machine is not flat */
    st = is_elf64_riscv(image, len) ? load_elf(m, image, len)
                                    : load_flat(m, image, len);
    if (st != RVMACHINE_OK) return st;
    rvmachine_enter(m);
    return RVMACHINE_OK;
}
