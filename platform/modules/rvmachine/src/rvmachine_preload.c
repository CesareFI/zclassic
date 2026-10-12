/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the loader entry that hands a kernel its boot seed. A FreeBSD
 * kernel seeds its random device, before the first use, only from a module
 * its boot loader preloaded; this file writes what that loader would: a copy
 * of the device tree, the seed and the list that describes both, above the
 * image. The list format and every name in it are the guest's contract
 * (FreeBSD sys/sys/linker.h, sys/riscv/include/metadata.h, sys/sys/random.h,
 * read as a specification); they are data here, and this is the one file
 * that knows them. Nothing here runs unless the embedder gave a seed source. */
#include "rvmachine_priv.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"

#include <string.h>

#define PAGE UINT64_C(4096)
/* A kernel entered this way maps this much from its load address while it
 * boots; the list, the tree and the seed are read through that mapping. */
#define BOOT_MAP (UINT64_C(1) << 30)

/* Record types. A record is a 32-bit type, a 32-bit payload size and the
 * payload; the next record starts on an 8-byte boundary; a name record opens
 * a module; type 0 with size 0 ends the list. */
#define REC_END 0x0000u
#define REC_NAME 0x0001u /* string with its NUL */
#define REC_TYPE 0x0002u /* string with its NUL */
#define REC_ADDR 0x0003u /* 64-bit kernel virtual address */
#define REC_SIZE 0x0004u /* 64-bit byte count */
#define REC_HOWTO 0x8007u     /* 32-bit boot flags */
#define REC_KERNEND 0x8008u   /* 64-bit: first address above all that was loaded */
#define REC_DTB 0x9001u       /* 64-bit: the device tree */
#define REC_BOOT_HART 0x9004u /* 64-bit hart number */
#define HOWTO_VERBOSE 0x800u /* what the kernel sets itself at the firmware entry */

static const char KERNEL_NAME[] = "kernel";
static const char KERNEL_TYPE[] = "elf kernel";
static const char SEED_NAME[] = "entropy";
static const char SEED_TYPE[] = "boot_entropy_platform";

static uint64_t page_up(uint64_t v)
{
    return (v + (PAGE - 1u)) & ~(PAGE - 1u);
}

static uint8_t *host(const struct rvmachine *m, uint64_t addr)
{
    return m->mem.bytes + (addr - RVMACHINE_RAM_BASE);
}

/* The kernel virtual address of a physical one at or above the kernel base. */
static uint64_t kva(const struct rvmachine_preload *p, uint64_t addr)
{
    return p->va_base + (addr - RVMACHINE_KERNEL_BASE);
}

enum rvmachine_status rvmachine_preload_plan(const struct rvmachine *m, uint64_t image_end,
                                             uint64_t va_base, uint64_t ceiling,
                                             struct rvmachine_preload *plan)
{
    const uint64_t mapped = RVMACHINE_KERNEL_BASE + BOOT_MAP;
    const uint64_t top = ceiling < mapped ? ceiling : mapped;
    const uint64_t need = page_up(m->dtb_len) + 2u * PAGE;
    uint64_t start;
    /* Record payloads are read as machine words by the guest. Physical
     * page alignment cannot compensate for an unaligned virtual offset. */
    if ((va_base & 7u) != 0u) return RVMACHINE_ERR_ENTRY;
    if (image_end > top || top - image_end < PAGE) return RVMACHINE_ERR_IMAGE_RANGE;
    start = page_up(image_end);
    if (need > top - start) return RVMACHINE_ERR_IMAGE_RANGE;
    plan->image_end = image_end;
    plan->dtb = start;
    plan->seed = start + page_up(m->dtb_len);
    plan->list = plan->seed + PAGE;
    plan->end = plan->list + PAGE;
    plan->va_base = va_base;
    /* every address the list names must exist as a kernel virtual address */
    if (va_base > UINT64_MAX - (plan->end - RVMACHINE_KERNEL_BASE))
        return RVMACHINE_ERR_ENTRY;
    return RVMACHINE_OK;
}

static bool all_zero(const uint8_t *bytes, size_t n)
{
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) any |= bytes[i];
    return any == 0;
}

/* The buffer was zeroed before the source ran, so a source that claims the
 * bytes and wrote none of them is caught as all zero. A buffer the source
 * wrote only in part is not told from a full one. */
static enum rvmachine_status seed_verdict(bool ok, size_t got, const uint8_t *seed)
{
    if (!ok || got > RVMACHINE_BOOT_SEED_BYTES) return RVMACHINE_ERR_SEED_SOURCE;
    if (got == 0) return RVMACHINE_ERR_SEED_ABSENT;
    if (got < RVMACHINE_BOOT_SEED_BYTES) return RVMACHINE_ERR_SEED_SHORT;
    return all_zero(seed, RVMACHINE_BOOT_SEED_BYTES) ? RVMACHINE_ERR_SEED_SOURCE
                                                     : RVMACHINE_OK;
}

enum rvmachine_status rvmachine_preload_seed(struct rvmachine *m)
{
    uint8_t *seed = m->seed_scratch;
    size_t got = 0;
    enum rvmachine_status st;
    bool ok;
    memset(seed, 0, RVMACHINE_BOOT_SEED_BYTES);
    ok = m->boot_seed(m->boot_seed_ctx, seed, RVMACHINE_BOOT_SEED_BYTES, &got);
    st = seed_verdict(ok, got, seed);
    if (st != RVMACHINE_OK) memory_cleanse(seed, RVMACHINE_BOOT_SEED_BYTES);
    return st;
}

/* Appends one record; the page under `at` is zero, so the padding is too. */
static uint8_t *put(uint8_t *at, uint32_t type, const void *payload, uint32_t size)
{
    zcl_write_u32_le(at, type);
    zcl_write_u32_le(at + 4, size);
    if (size != 0) memcpy(at + 8, payload, size);
    return at + 8u + ((size + 7u) & ~7u);
}

static uint8_t *put_u64(uint8_t *at, uint32_t type, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    return put(at, type, le, sizeof le);
}

static uint8_t *put_u32(uint8_t *at, uint32_t type, uint32_t value)
{
    uint8_t le[4];
    zcl_write_u32_le(le, value);
    return put(at, type, le, sizeof le);
}

/* 224 bytes: far inside the page the plan gave the list. */
static void write_list(uint8_t *at, const struct rvmachine_preload *p)
{
    at = put(at, REC_NAME, KERNEL_NAME, sizeof KERNEL_NAME);
    at = put(at, REC_TYPE, KERNEL_TYPE, sizeof KERNEL_TYPE);
    at = put_u64(at, REC_ADDR, p->va_base);
    at = put_u64(at, REC_SIZE, p->image_end - RVMACHINE_KERNEL_BASE);
    at = put_u64(at, REC_DTB, kva(p, p->dtb));
    at = put_u64(at, REC_KERNEND, kva(p, p->end));
    at = put_u32(at, REC_HOWTO, HOWTO_VERBOSE);
    at = put_u64(at, REC_BOOT_HART, 0);
    at = put(at, REC_NAME, SEED_NAME, sizeof SEED_NAME);
    at = put(at, REC_TYPE, SEED_TYPE, sizeof SEED_TYPE);
    at = put_u64(at, REC_ADDR, kva(p, p->seed));
    at = put_u64(at, REC_SIZE, RVMACHINE_BOOT_SEED_BYTES);
    (void)put(at, REC_END, NULL, 0);
}

void rvmachine_preload_write(struct rvmachine *m, const struct rvmachine_preload *plan,
                             uint64_t entry_pc)
{
    memset(host(m, plan->image_end), 0, (size_t)(plan->end - plan->image_end));
    memcpy(host(m, plan->dtb), host(m, m->dtb_addr), m->dtb_len);
    memcpy(host(m, plan->seed), m->seed_scratch, RVMACHINE_BOOT_SEED_BYTES);
    memory_cleanse(m->seed_scratch, RVMACHINE_BOOT_SEED_BYTES);
    write_list(host(m, plan->list), plan);
    m->seed_addr = plan->seed;
    m->entry_pc = entry_pc;
    m->entry_a0 = kva(plan, plan->list);
    m->entry_a1 = 0; /* this entry takes the tree from the list */
}

bool rvmachine_boot_seed_cleared(const struct rvmachine *m)
{
    if (m == NULL || m->seed_addr == 0) return false;
    return all_zero(host(m, m->seed_addr), RVMACHINE_BOOT_SEED_BYTES);
}
