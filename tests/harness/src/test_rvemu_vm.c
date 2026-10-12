/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvemu Sv39 known answers through the real step: every page size,
 * the SUM and MXR permission bits, hardware A and D update, page-crossing
 * loads, stores and instruction fetches with exact fault addresses, the
 * physical lr/sc reservation, MPRV, devices behind a mapping, and stale
 * translations dropped by sfence.vma and by a satp write. */
#include "test/test_core.h"
#include "rvemu/rvemu.h"
#include "base/serialize_le.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RVV_BASE 0x80000000ull
#define RVV_SIZE ((size_t)1 << 20)
#define RVV_ROOT (RVV_BASE + 0x1000u)
#define RVV_ROOT2 (RVV_BASE + 0x8000u) /* a second address space */
#define RVV_SATP ((8ull << 60) | (RVV_ROOT >> 12))
#define RVV_SCODE 0x10000ull /* supervisor code page, at RVV_SCODE_PA */
#define RVV_UCODE 0x12000ull /* user code page */
#define RVV_SCODE_PA (RVV_BASE + 0x10000u)
#define RVV_UCODE_PA (RVV_BASE + 0x12000u)
#define RVV_STVEC 0x7000ull
#define RVV_DATA 0x20000ull /* two data pages, backed by PAGE_A and PAGE_B */
#define RVV_PAGE_A (RVV_BASE + 0x20000u)
#define RVV_PAGE_B (RVV_BASE + 0x30000u) /* not adjacent to PAGE_A */
#define RVV_PAGE_C (RVV_BASE + 0x40000u)
#define RVV_DEV_VA 0x50000ull
#define RVV_DEV_PA 0x10000000ull
#define RVV_V 1u
#define RVV_R 2u
#define RVV_W 4u
#define RVV_X 8u
#define RVV_U 16u
#define RVV_A 64u
#define RVV_D 128u
#define RVV_SUM (1ull << 18)
#define RVV_MXR (1ull << 19)
#define RVV_MPRV (1ull << 17)
#define RVV_MPP_S (1ull << 11)
#define RVV_SFENCE 0x12000073u
#define RVV_ADDI_X5_0X123 0x12300293u
#define RVV_C_NOP 0x0001u
#define RVV_PAT_A 0x1111111122222222ull
#define RVV_PAT_B 0x3333333344444444ull
#define RVV_LOOP_TURNS 40u

/* Records a failed known answer with its line; ok is the case verdict. */
#define RVV_CHECK(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL rvemu sv39 known answer at line %d\n", __LINE__); \
            ok = 0; \
        } \
    } while (0)

static uint8_t rvv_ram[RVV_SIZE];
static uint8_t rvv_ram_ref[RVV_SIZE]; /* RAM after the reference run of the invisibility case */
static uint64_t rvv_next_table;

struct rvv_dev {
    unsigned loads, stores;
    uint64_t last_addr, last_val;
};

static int rvv_dev_load(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out)
{
    struct rvv_dev *d = ctx;
    (void)nbytes;
    d->loads++;
    d->last_addr = paddr;
    *out = 0x77u;
    return 0;
}

static int rvv_dev_store(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val)
{
    struct rvv_dev *d = ctx;
    (void)nbytes;
    d->stores++;
    d->last_addr = paddr;
    d->last_val = val;
    return 0;
}

static struct rvemu_hart *rvv_live;

static uint64_t rvv_rd64(uint64_t pa) { return zcl_read_u64_le(&rvv_ram[pa - RVV_BASE]); }
static void rvv_wr64(uint64_t pa, uint64_t v)
{
    zcl_write_u64_le(&rvv_ram[pa - RVV_BASE], v);
    rvemu_icache_note_store(rvv_live, pa, 8u);
}
static void rvv_wr32(uint64_t pa, uint32_t v)
{
    zcl_write_u32_le(&rvv_ram[pa - RVV_BASE], v);
    rvemu_icache_note_store(rvv_live, pa, 4u);
}
static void rvv_wr16(uint64_t pa, uint16_t v)
{
    zcl_write_u16_le(&rvv_ram[pa - RVV_BASE], v);
    rvemu_icache_note_store(rvv_live, pa, 2u);
}

static unsigned rvv_index(uint64_t va, unsigned level) { return (va >> (12u + 9u * level)) & 511u; }

/* The address of the PTE that maps va at the given level (0 = 4 KiB, 1 = 2 MiB,
 * 2 = 1 GiB), allocating the intermediate tables from RAM. */
static uint64_t rvv_pte_addr(uint64_t root, uint64_t va, unsigned level)
{
    uint64_t table = root;
    for (unsigned l = 2; l > level; l--) {
        uint64_t slot = table + 8u * rvv_index(va, l), pte = rvv_rd64(slot);
        if (!(pte & RVV_V)) {
            pte = ((rvv_next_table >> 12) << 10) | RVV_V;
            rvv_next_table += 0x1000u;
            rvv_wr64(slot, pte);
        }
        table = (pte >> 10) << 12;
    }
    return table + 8u * rvv_index(va, level);
}

static void rvv_map_in(uint64_t root, uint64_t va, uint64_t pa, unsigned level, uint64_t flags)
{
    rvv_wr64(rvv_pte_addr(root, va, level), ((pa >> 12) << 10) | flags | RVV_V);
}

static void rvv_map(uint64_t va, uint64_t pa, uint64_t flags) { rvv_map_in(RVV_ROOT, va, pa, 0, flags); }
static uint64_t rvv_flags(uint64_t va) { return rvv_rd64(rvv_pte_addr(RVV_ROOT, va, 0)) & 0xffu; }

/* A fresh SBI hart with Sv39 on and the two code pages mapped. */
static void rvv_boot(struct rvemu_hart *h)
{
    memset(rvv_ram, 0, sizeof(rvv_ram));
    rvv_next_table = RVV_ROOT + 0x1000u;
    rvemu_hart_init_sbi(h, RVV_SCODE);
    rvv_live = h;
    h->csr.satp = RVV_SATP;
    h->csr.stvec = RVV_STVEC;
    rvv_map(RVV_SCODE, RVV_SCODE_PA, RVV_X | RVV_A);
    rvv_map(RVV_UCODE, RVV_UCODE_PA, RVV_X | RVV_U | RVV_A);
    rvv_wr64(RVV_PAGE_A + 8u, RVV_PAT_A);
    rvv_wr64(RVV_PAGE_B + 8u, RVV_PAT_B);
}

static enum rvemu_stop rvv_step(struct rvemu_hart *h, struct rvv_dev *d)
{
    struct rvemu_mem mem = {.base = RVV_BASE, .size = RVV_SIZE, .bytes = rvv_ram, .io_ctx = d,
                            .io_load = d ? rvv_dev_load : NULL, .io_store = d ? rvv_dev_store : NULL};
    return rvemu_step(h, &mem);
}

/* Runs one instruction from the start of the code page of the hart's privilege. */
static enum rvemu_stop rvv_run(struct rvemu_hart *h, uint32_t insn)
{
    int user = h->priv == RVEMU_PRIV_U;
    rvv_live = h;
    h->pc = user ? RVV_UCODE : RVV_SCODE;
    rvv_wr32(user ? RVV_UCODE_PA : RVV_SCODE_PA, insn);
    return rvv_step(h, NULL);
}

/* ld x5, off(x6) and sd x7, off(x6), then the same shapes at other widths. */
static uint32_t rvv_load(unsigned f3, unsigned off) { return (off << 20) | (6u << 15) | (f3 << 12) | (5u << 7) | 0x03u; }
static uint32_t rvv_store(unsigned f3, unsigned off)
{
    return ((off >> 5) << 25) | (7u << 20) | (6u << 15) | (f3 << 12) | ((off & 31u) << 7) | 0x23u;
}
/* lr.d x5, (x6); sc.d x5, x7, (x6); amoadd.d x5, x7, (x6). */
static uint32_t rvv_amo(unsigned f5, unsigned rs2) { return (f5 << 27) | (rs2 << 20) | (6u << 15) | (3u << 12) | (5u << 7) | 0x2fu; }
static uint32_t rvv_csrw(unsigned csr) { return (csr << 20) | (6u << 15) | (1u << 12) | 0x73u; }

static uint64_t rvv_ld(struct rvemu_hart *h, uint64_t va)
{
    h->x[6] = va;
    h->x[5] = 0;
    return rvv_run(h, rvv_load(3, 0)) == RVEMU_STOP_NONE && h->pc == RVV_SCODE + 4u ? h->x[5] : UINT64_MAX;
}

static int rvv_sd(struct rvemu_hart *h, uint64_t va, uint64_t val)
{
    h->x[6] = va;
    h->x[7] = val;
    return rvv_run(h, rvv_store(3, 0)) == RVEMU_STOP_NONE && h->pc == RVV_SCODE + 4u;
}

/* The last step trapped to S with this cause, stval and sepc. */
static int rvv_trapped(const struct rvemu_hart *h, uint64_t cause, uint64_t tval, uint64_t epc)
{
    return h->priv == RVEMU_PRIV_S && h->pc == RVV_STVEC && h->csr.scause == cause &&
           h->csr.stval == tval && h->csr.sepc == epc && h->csr.mcause == 0;
}

/* 4 KiB, 2 MiB and 1 GiB leaves reach the same physical bytes, and the first
 * use sets A (and a store D) in the leaf through the compare-exchange path. */
static int rvv_sizes_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map_in(RVV_ROOT, 0x200000ull, RVV_BASE, 1, RVV_R | RVV_W);
    rvv_map_in(RVV_ROOT, 0x40000000ull, RVV_BASE, 2, RVV_R);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W));
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A && h.instret == 1 && h.retired == 1);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A));
    RVV_CHECK(rvv_sd(&h, RVV_DATA + 16u, 0xabcdu) && rvv_rd64(RVV_PAGE_A + 16u) == 0xabcdu);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    RVV_CHECK(rvv_ld(&h, 0x200000ull + 0x20008u) == RVV_PAT_A);
    RVV_CHECK(rvv_sd(&h, 0x200000ull + 0x30008u, 0x99u) && rvv_rd64(RVV_PAGE_B + 8u) == 0x99u);
    RVV_CHECK((rvv_rd64(rvv_pte_addr(RVV_ROOT, 0x200000ull, 1)) & 0xffu) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    RVV_CHECK(rvv_ld(&h, 0x40000000ull + 0x20008u) == RVV_PAT_A);
    RVV_CHECK((rvv_rd64(rvv_pte_addr(RVV_ROOT, 0x40000000ull, 2)) & 0xffu) == (RVV_V | RVV_R | RVV_A));
    RVV_CHECK(!rvv_sd(&h, 0x40000000ull + 0x20008u, 1) && rvv_trapped(&h, 15, 0x40020008ull, RVV_SCODE));
    RVV_CHECK(rvv_rd64(RVV_PAGE_A + 8u) == RVV_PAT_A);
    RVV_CHECK(rvv_ld(&h, 0x8000000000ull) == UINT64_MAX && rvv_trapped(&h, 13, 0x8000000000ull, RVV_SCODE));
    if (!ok) printf("FAIL rvemu sv39 page sizes and A/D update\n");
    return ok ? 0 : 1;
}

/* SUM gates S access to a U page, MXR lets a load read an execute-only page,
 * S never executes a U page, and U sees only U pages. */
static int rvv_perm_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W | RVV_U);
    rvv_map(RVV_DATA + 0x1000u, RVV_PAGE_B, RVV_X);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == UINT64_MAX && rvv_trapped(&h, 13, RVV_DATA + 8u, RVV_SCODE));
    RVV_CHECK(!rvv_sd(&h, RVV_DATA + 8u, 1) && rvv_trapped(&h, 15, RVV_DATA + 8u, RVV_SCODE));
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_U)); /* a refused access sets nothing */
    h.csr.mstatus |= RVV_SUM;
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A && rvv_sd(&h, RVV_DATA + 24u, 5));
    h.csr.mstatus &= ~RVV_SUM;
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == UINT64_MAX && rvv_trapped(&h, 13, RVV_DATA + 8u, RVV_SCODE));
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 0x1008u) == UINT64_MAX && rvv_trapped(&h, 13, RVV_DATA + 0x1008u, RVV_SCODE));
    h.csr.mstatus |= RVV_MXR;
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 0x1008u) == RVV_PAT_B);
    h.csr.mstatus &= ~RVV_MXR;
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 0x1008u) == UINT64_MAX && rvv_trapped(&h, 13, RVV_DATA + 0x1008u, RVV_SCODE));
    h.csr.mstatus |= RVV_SUM; /* SUM never lets S execute a U page */
    h.pc = RVV_UCODE;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, RVV_UCODE, RVV_UCODE));
    h.priv = RVEMU_PRIV_U;
    h.x[6] = RVV_DATA + 8u;
    RVV_CHECK(rvv_run(&h, rvv_load(3, 0)) == RVEMU_STOP_NONE && h.x[5] == RVV_PAT_A && h.priv == RVEMU_PRIV_U);
    rvv_map(RVV_DATA + 0x2000u, RVV_PAGE_C, RVV_R | RVV_W);
    h.x[6] = RVV_DATA + 0x2000u;
    RVV_CHECK(rvv_run(&h, rvv_load(3, 0)) == RVEMU_STOP_NONE && rvv_trapped(&h, 13, RVV_DATA + 0x2000u, RVV_UCODE));
    h.priv = RVEMU_PRIV_U;
    h.pc = RVV_SCODE;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, RVV_SCODE, RVV_SCODE));
    if (!ok) printf("FAIL rvemu sv39 SUM, MXR and U permissions\n");
    return ok ? 0 : 1;
}

/* A load and a store that cross into a non-adjacent physical page; with the
 * second page missing or read-only nothing is written and stval names the
 * first byte of that page. */
static int rvv_cross_kat(void)
{
    struct rvemu_hart h;
    const uint64_t edge = RVV_DATA + 0xffcu, edge2 = RVV_DATA + 0x1ffcu;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map(RVV_DATA + 0x1000u, RVV_PAGE_B, RVV_R | RVV_W);
    rvv_wr32(RVV_PAGE_A + 0xffcu, 0xa1a2a3a4u);
    rvv_wr32(RVV_PAGE_B, 0xb1b2b3b4u);
    RVV_CHECK(rvv_ld(&h, edge) == 0xb1b2b3b4a1a2a3a4ull);
    RVV_CHECK(rvv_sd(&h, edge, 0x0807060504030201ull));
    RVV_CHECK(rvv_rd64(RVV_PAGE_A + 0xff8u) == 0x0403020100000000ull && rvv_rd64(RVV_PAGE_B) == 0x08070605ull);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    RVV_CHECK(rvv_flags(RVV_DATA + 0x1000u) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    rvv_wr32(RVV_PAGE_B + 0xffcu, 0xc1c2c3c4u); /* the page after PAGE_B's mapping is absent */
    RVV_CHECK(!rvv_sd(&h, edge2, UINT64_MAX) && rvv_trapped(&h, 15, RVV_DATA + 0x2000u, RVV_SCODE));
    RVV_CHECK(rvv_rd64(RVV_PAGE_B + 0xff8u) == 0xc1c2c3c400000000ull && h.instret == 2);
    RVV_CHECK(rvv_ld(&h, edge2) == UINT64_MAX && rvv_trapped(&h, 13, RVV_DATA + 0x2000u, RVV_SCODE));
    rvv_map(RVV_DATA + 0x2000u, RVV_PAGE_C, RVV_R); /* present but read-only */
    RVV_CHECK(!rvv_sd(&h, edge2, UINT64_MAX) && rvv_trapped(&h, 15, RVV_DATA + 0x2000u, RVV_SCODE));
    RVV_CHECK(rvv_rd64(RVV_PAGE_B + 0xff8u) == 0xc1c2c3c400000000ull && rvv_rd64(RVV_PAGE_C) == 0);
    RVV_CHECK(rvv_ld(&h, edge2) == 0xc1c2c3c4ull);
    h.x[6] = RVV_DATA + 0xfffu; /* a one-byte store at the last byte does not touch the next page */
    h.x[7] = 0x5au;
    RVV_CHECK(rvv_run(&h, rvv_store(0, 0)) == RVEMU_STOP_NONE && rvv_ram[RVV_PAGE_A + 0xfffu - RVV_BASE] == 0x5au);
    if (!ok) printf("FAIL rvemu sv39 page-crossing load and store\n");
    return ok ? 0 : 1;
}

/* A 32-bit instruction whose halves lie on two pages is fetched through two
 * translations; a missing second page is an instruction page fault at that
 * page with sepc on the instruction. A compressed instruction in the last two
 * bytes of a page never looks at the next page. */
static int rvv_fetch_kat(void)
{
    struct rvemu_hart h;
    const uint64_t at = RVV_SCODE + 0xffeu, next = RVV_SCODE + 0x1000u;
    int ok = 1;
    rvv_boot(&h);
    rvv_wr16(RVV_SCODE_PA + 0xffeu, (uint16_t)RVV_ADDI_X5_0X123);
    rvv_wr16(RVV_PAGE_C, (uint16_t)(RVV_ADDI_X5_0X123 >> 16));
    h.pc = at;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, next, at) && h.x[5] == 0);
    rvv_map(next, RVV_PAGE_C, RVV_X);
    h.pc = at;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.x[5] == 0x123u && h.pc == at + 4u);
    RVV_CHECK(rvv_flags(next) == (RVV_V | RVV_X | RVV_A));
    rvv_map(next, RVV_PAGE_C, RVV_R | RVV_W); /* present, not executable */
    RVV_CHECK(rvv_run(&h, RVV_SFENCE) == RVEMU_STOP_NONE);
    h.pc = at;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, next, at));
    rvv_wr64(rvv_pte_addr(RVV_ROOT, next, 0), 0);
    RVV_CHECK(rvv_run(&h, RVV_SFENCE) == RVEMU_STOP_NONE);
    rvv_wr16(RVV_SCODE_PA + 0xffeu, RVV_C_NOP);
    h.pc = at;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.pc == next && h.priv == RVEMU_PRIV_S);
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, next, next));
    if (!ok) printf("FAIL rvemu sv39 instruction fetch across a page boundary\n");
    return ok ? 0 : 1;
}

/* Turning paging on the way a kernel does: the write to satp takes effect for
 * the very next fetch, which has no mapping at the physical pc and so faults
 * into S through stvec with sepc = stval = that pc. */
static int rvv_enable_kat(void)
{
    struct rvemu_hart h;
    const uint64_t pc = RVV_BASE + 0x100u;
    int ok = 1;
    rvv_boot(&h);
    h.csr.satp = 0;
    h.pc = pc;
    h.x[6] = RVV_SATP | (0xffffull << 44); /* the ASID bits do not stick */
    rvv_wr32(pc, rvv_csrw(0x180));
    rvv_wr32(pc + 4u, RVV_ADDI_X5_0X123);
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.pc == pc + 4u && h.csr.satp == RVV_SATP);
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, pc + 4u, pc + 4u) && h.x[5] == 0);
    h.x[6] = (9ull << 60) | 1u; /* an unsupported mode leaves satp as it was */
    RVV_CHECK(rvv_run(&h, rvv_csrw(0x180)) == RVEMU_STOP_NONE && h.csr.satp == RVV_SATP);
    rvemu_hart_init(&h, pc); /* the user-runner profile has no translation */
    h.x[6] = RVV_SATP;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.csr.satp == 0);
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.x[5] == 0x123u);
    if (!ok) printf("FAIL rvemu sv39 enable through satp\n");
    return ok ? 0 : 1;
}

/* A changed PTE and a changed satp are seen after sfence.vma and after the
 * satp write. Without the flush the old page would still answer. */
static int rvv_stale_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A && rvv_sd(&h, RVV_DATA + 16u, 1));
    rvv_map(RVV_DATA, RVV_PAGE_B, RVV_R | RVV_W);
    RVV_CHECK(rvv_run(&h, RVV_SFENCE) == RVEMU_STOP_NONE && h.pc == RVV_SCODE + 4u);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_B);
    RVV_CHECK(rvv_sd(&h, RVV_DATA + 16u, 2) && rvv_rd64(RVV_PAGE_B + 16u) == 2 && rvv_rd64(RVV_PAGE_A + 16u) == 1);
    rvv_map(RVV_DATA, RVV_PAGE_B, RVV_R); /* write permission withdrawn */
    RVV_CHECK(rvv_run(&h, RVV_SFENCE | (6u << 15)) == RVEMU_STOP_NONE); /* sfence.vma x6 */
    RVV_CHECK(!rvv_sd(&h, RVV_DATA + 16u, 3) && rvv_trapped(&h, 15, RVV_DATA + 16u, RVV_SCODE));
    RVV_CHECK(rvv_rd64(RVV_PAGE_B + 16u) == 2);
    h.priv = RVEMU_PRIV_U; /* sfence.vma is illegal in U */
    RVV_CHECK(rvv_run(&h, RVV_SFENCE) == RVEMU_STOP_NONE && rvv_trapped(&h, 2, RVV_SFENCE, RVV_UCODE));
    rvv_map_in(RVV_ROOT2, RVV_SCODE, RVV_SCODE_PA, 0, RVV_X | RVV_A);
    rvv_map_in(RVV_ROOT2, RVV_DATA, RVV_PAGE_A, 0, RVV_R);
    h.x[6] = (8ull << 60) | (RVV_ROOT2 >> 12);
    RVV_CHECK(rvv_run(&h, rvv_csrw(0x180)) == RVEMU_STOP_NONE && h.pc == RVV_SCODE + 4u);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A);
    if (!ok) printf("FAIL rvemu sv39 sfence.vma and satp drop stale translations\n");
    return ok ? 0 : 1;
}

/* A store through a page that was only read so far still sets D, and a page
 * table outside RAM is an access fault, not a page fault. */
static int rvv_dirty_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A && rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A));
    RVV_CHECK(rvv_sd(&h, RVV_DATA + 8u, 4) && rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    rvv_wr64(rvv_pte_addr(RVV_ROOT, RVV_DATA, 0), ((RVV_PAGE_A >> 12) << 10) | RVV_V | RVV_R | RVV_W | RVV_A);
    RVV_CHECK(rvv_run(&h, RVV_SFENCE) == RVEMU_STOP_NONE); /* the guest cleared D and flushed */
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == 4 && rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A));
    RVV_CHECK(rvv_sd(&h, RVV_DATA + 8u, 5) && rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    h.csr.satp = (8ull << 60) | ((RVV_BASE + RVV_SIZE) >> 12);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == UINT64_MAX && h.csr.scause == 1 && h.csr.stval == RVV_SCODE);
    h.csr.satp = RVV_SATP;
    rvv_map_in(RVV_ROOT, 0x40000000ull, RVV_BASE + RVV_SIZE, 2, RVV_V); /* a table outside RAM */
    RVV_CHECK(rvv_ld(&h, 0x40000008ull) == UINT64_MAX && rvv_trapped(&h, 5, 0x40000008ull, RVV_SCODE));
    RVV_CHECK(!rvv_sd(&h, 0x40000008ull, 1) && rvv_trapped(&h, 7, 0x40000008ull, RVV_SCODE));
    if (!ok) printf("FAIL rvemu sv39 D after a read and page tables outside RAM\n");
    return ok ? 0 : 1;
}

/* An AMO or an lr aimed at a device faults and the device is never called. */
static int rvv_atomic_device_ok(struct rvemu_hart *h)
{
    struct rvv_dev d = {0};
    int ok = 1;
    h->x[6] = RVV_DEV_VA;
    h->pc = RVV_SCODE;
    rvv_wr32(RVV_SCODE_PA, rvv_amo(0, 7));
    RVV_CHECK(rvv_step(h, &d) == RVEMU_STOP_NONE && rvv_trapped(h, 7, RVV_DEV_VA, RVV_SCODE));
    h->pc = RVV_SCODE;
    rvv_wr32(RVV_SCODE_PA, rvv_amo(2, 0));
    RVV_CHECK(rvv_step(h, &d) == RVEMU_STOP_NONE && rvv_trapped(h, 5, RVV_DEV_VA, RVV_SCODE));
    RVV_CHECK(d.loads == 0 && d.stores == 0);
    return ok;
}

/* The reservation is on the physical address (two mappings of one page share
 * it); an AMO needs write permission before it reads, sets D, and is refused
 * on a device without touching it. */
static int rvv_atomic_kat(void)
{
    struct rvemu_hart h;
    const uint64_t alias = RVV_DATA + 0x3000u;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map(alias, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map(RVV_DATA + 0x1000u, RVV_PAGE_B, RVV_R);
    rvv_map(RVV_DEV_VA, RVV_DEV_PA, RVV_R | RVV_W);
    h.x[6] = RVV_DATA + 8u;
    RVV_CHECK(rvv_run(&h, rvv_amo(2, 0)) == RVEMU_STOP_NONE && h.x[5] == RVV_PAT_A);
    RVV_CHECK(h.resv_addr == RVV_PAGE_A + 8u && rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A));
    h.x[6] = alias + 8u;
    h.x[7] = 0x66u;
    RVV_CHECK(rvv_run(&h, rvv_amo(3, 7)) == RVEMU_STOP_NONE && h.x[5] == 0 && rvv_rd64(RVV_PAGE_A + 8u) == 0x66u);
    RVV_CHECK(rvv_run(&h, rvv_amo(3, 7)) == RVEMU_STOP_NONE && h.x[5] == 1); /* no reservation left */
    h.x[6] = RVV_DATA + 0x1008u; /* read-only: store/AMO page fault, nothing read into rd */
    h.x[5] = 0x55u;
    RVV_CHECK(rvv_run(&h, rvv_amo(0, 7)) == RVEMU_STOP_NONE && rvv_trapped(&h, 15, RVV_DATA + 0x1008u, RVV_SCODE));
    RVV_CHECK(h.x[5] == 0x55u && rvv_rd64(RVV_PAGE_B + 8u) == RVV_PAT_B);
    RVV_CHECK(rvv_run(&h, rvv_amo(2, 0)) == RVEMU_STOP_NONE && h.x[5] == RVV_PAT_B); /* lr only needs R */
    h.x[6] = RVV_DATA + 16u;
    RVV_CHECK(rvv_run(&h, rvv_amo(0, 7)) == RVEMU_STOP_NONE && h.x[5] == 0 && rvv_rd64(RVV_PAGE_A + 16u) == 0x66u);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    RVV_CHECK(rvv_atomic_device_ok(&h));
    if (!ok) printf("FAIL rvemu sv39 atomics\n");
    return ok ? 0 : 1;
}

/* A device behind a mapping gets the physical address; a device access that
 * would cross a page is refused. In the MACHINE profile MPRV with MPP = S
 * translates loads and stores but never the fetch. */
static int rvv_device_mprv_kat(void)
{
    struct rvemu_hart h;
    struct rvv_dev d = {0};
    const uint64_t pc = RVV_BASE + 0x100u;
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DEV_VA, RVV_DEV_PA, RVV_R | RVV_W);
    rvv_map(RVV_DEV_VA + 0x1000u, RVV_DEV_PA + 0x1000u, RVV_R | RVV_W);
    h.x[6] = RVV_DEV_VA + 0x10u;
    h.x[7] = 0x31u;
    rvv_wr32(RVV_SCODE_PA, rvv_load(2, 0));
    RVV_CHECK(rvv_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == 0x77u && d.last_addr == RVV_DEV_PA + 0x10u);
    h.pc = RVV_SCODE;
    rvv_wr32(RVV_SCODE_PA, rvv_store(2, 0));
    RVV_CHECK(rvv_step(&h, &d) == RVEMU_STOP_NONE && d.stores == 1 && d.last_val == 0x31u && d.loads == 1);
    h.pc = RVV_SCODE;
    h.x[6] = RVV_DEV_VA + 0xffeu;
    RVV_CHECK(rvv_step(&h, &d) == RVEMU_STOP_NONE && rvv_trapped(&h, 7, RVV_DEV_VA + 0xffeu, RVV_SCODE));
    RVV_CHECK(d.stores == 1);
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvemu_hart_init_machine(&h, pc);
    h.csr.satp = RVV_SATP;
    h.x[6] = RVV_DATA + 8u;
    rvv_wr32(pc, rvv_load(3, 0));
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.csr.mcause == 5 && h.csr.mtval == RVV_DATA + 8u);
    h.pc = pc; /* M without MPRV is untranslated: that address is not RAM */
    h.priv = RVEMU_PRIV_M;
    h.csr.mstatus = (h.csr.mstatus & ~(3ull << 11)) | RVV_MPRV | RVV_MPP_S;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.x[5] == RVV_PAT_A && h.pc == pc + 4u);
    if (!ok) printf("FAIL rvemu sv39 devices and MPRV\n");
    return ok ? 0 : 1;
}

/* The translation cache: keyed by privilege, RAM pages only (a device is
 * walked and called every time), a hit still bounds-checked by the bus, and
 * emptied by rvemu_tlb_flush. */
static int rvv_cache_kat(void)
{
    struct rvemu_hart h;
    struct rvv_dev d = {0};
    struct rvemu_mem small = {.base = RVV_BASE, .size = 0x20000u, .bytes = rvv_ram};
    int ok = 1;
    rvv_boot(&h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map(RVV_DEV_VA, RVV_DEV_PA, RVV_R | RVV_W);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A && rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A);
    h.priv = RVEMU_PRIV_U; /* the supervisor's cached page is not the user's */
    h.x[6] = RVV_DATA + 8u;
    RVV_CHECK(rvv_run(&h, rvv_load(3, 0)) == RVEMU_STOP_NONE && rvv_trapped(&h, 13, RVV_DATA + 8u, RVV_UCODE));
    h.x[6] = RVV_DEV_VA;
    rvv_wr32(RVV_SCODE_PA, rvv_load(2, 0));
    for (unsigned k = 0; k < 3u; k++) {
        h.pc = RVV_SCODE;
        RVV_CHECK(rvv_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == 0x77u && d.loads == k + 1u);
    }
    h.x[6] = RVV_DATA + 8u; /* RAM now ends below the cached page: the hit must fault */
    h.pc = RVV_SCODE;
    rvv_wr32(RVV_SCODE_PA, rvv_load(3, 0));
    RVV_CHECK(rvemu_step(&h, &small) == RVEMU_STOP_NONE && rvv_trapped(&h, 5, RVV_DATA + 8u, RVV_SCODE));
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_A);
    rvv_map(RVV_DATA, RVV_PAGE_B, RVV_R | RVV_W); /* the host edits the table and says so */
    rvemu_tlb_flush(&h);
    RVV_CHECK(rvv_ld(&h, RVV_DATA + 8u) == RVV_PAT_B);
    if (!ok) printf("FAIL rvemu sv39 translation cache\n");
    return ok ? 0 : 1;
}

/* A guest loop whose 8-byte load and store walk over a page boundary: ld, addi,
 * sd, add, xor, addi x6 += 8, addi x9 -= 1, bnez, then an ecall for the host. */
static enum rvemu_stop rvv_loop(struct rvemu_hart *h, int flush_each_step)
{
    static const uint32_t code[9] = {0x00033283u, 0x00128293u, 0x00533023u, 0x005383b3u, 0x00744433u,
                                     0x00830313u, 0xfff48493u, 0xfe0492e3u, 0x00000073u};
    enum rvemu_stop s = RVEMU_STOP_NONE;
    rvv_boot(h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    rvv_map(RVV_DATA + 0x1000u, RVV_PAGE_B, RVV_R | RVV_W);
    for (unsigned k = 0; k < 9u; k++) rvv_wr32(RVV_SCODE_PA + 4u * k, code[k]);
    h->x[6] = RVV_DATA + 0xfc4u;
    h->x[9] = RVV_LOOP_TURNS;
    for (unsigned n = 0; n < 16u * RVV_LOOP_TURNS && s == RVEMU_STOP_NONE; n++) {
        if (flush_each_step) rvemu_tlb_flush(h);
        s = rvv_step(h, NULL);
    }
    return s;
}

/* The cache is architecturally invisible: the same program run with the cache
 * and with it emptied before every step ends with the same registers, CSRs,
 * counters and RAM, page-table A and D bits included. */
static int rvv_cache_invisible_kat(void)
{
    struct rvemu_hart cached, walked;
    int ok = 1;
    RVV_CHECK(rvv_loop(&cached, 0) == RVEMU_STOP_ECALL && cached.retired == 8u * RVV_LOOP_TURNS);
    RVV_CHECK(cached.pc == RVV_SCODE + 32u && cached.x[9] == 0 && cached.x[8] != 0);
    RVV_CHECK(rvv_flags(RVV_DATA + 0x1000u) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    memcpy(rvv_ram_ref, rvv_ram, sizeof(rvv_ram));
    RVV_CHECK(rvv_loop(&walked, 1) == RVEMU_STOP_ECALL && walked.retired == cached.retired);
    RVV_CHECK(memcmp(&cached, &walked, offsetof(struct rvemu_hart, tlb_satp)) == 0);
    RVV_CHECK(memcmp(rvv_ram_ref, rvv_ram, sizeof(rvv_ram)) == 0);
    if (!ok) printf("FAIL rvemu sv39 translation cache is invisible to the guest\n");
    return ok ? 0 : 1;
}

/* A load of the given funct3 at off from x6. */
static uint64_t rvv_ld_width(struct rvemu_hart *h, unsigned f3, unsigned off)
{
    h->x[5] = 0xdeadull;
    return rvv_run(h, rvv_load(f3, off)) == RVEMU_STOP_NONE ? h->x[5] : UINT64_MAX;
}

/* The page behind RVV_DATA holds the byte pattern 0x80, 0x81, ... from offset
 * 0x100, and x6 points at it. */
static void rvv_width_boot(struct rvemu_hart *h)
{
    rvv_boot(h);
    rvv_map(RVV_DATA, RVV_PAGE_A, RVV_R | RVV_W);
    for (unsigned i = 0; i < 32u; i++) rvv_ram[RVV_PAGE_A + 0x100u + i - RVV_BASE] = (uint8_t)(0x80u + i);
    h->x[6] = RVV_DATA + 0x100u;
}

/* Loads of every width inside one page, aligned or not, extended by sign or
 * by zero. The expected values are written out by hand from the pattern. */
static int rvv_width_load_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_width_boot(&h);
    RVV_CHECK(rvv_ld_width(&h, 0, 1) == 0xffffffffffffff81ull);
    RVV_CHECK(rvv_ld_width(&h, 4, 1) == 0x81u);
    RVV_CHECK(rvv_ld_width(&h, 1, 3) == 0xffffffffffff8483ull);
    RVV_CHECK(rvv_ld_width(&h, 5, 3) == 0x8483u);
    RVV_CHECK(rvv_ld_width(&h, 2, 5) == 0xffffffff88878685ull);
    RVV_CHECK(rvv_ld_width(&h, 6, 5) == 0x88878685u);
    RVV_CHECK(rvv_ld_width(&h, 3, 7) == 0x8e8d8c8b8a898887ull);
    RVV_CHECK(rvv_ld_width(&h, 3, 8) == 0x8f8e8d8c8b8a8988ull);
    if (!ok) printf("FAIL rvemu sv39 load widths inside one page\n");
    return ok ? 0 : 1;
}

/* Byte and halfword stores inside one page, with the bytes around each store
 * left alone. */
static int rvv_width_store_kat(void)
{
    struct rvemu_hart h;
    const uint64_t pa = RVV_PAGE_A + 0x100u - RVV_BASE;
    int ok = 1;
    rvv_width_boot(&h);
    h.x[7] = 0x1122334455667788ull;
    RVV_CHECK(rvv_run(&h, rvv_store(0, 0x11)) == RVEMU_STOP_NONE && rvv_ram[pa + 0x11] == 0x88u &&
              rvv_ram[pa + 0x10] == 0x90u && rvv_ram[pa + 0x12] == 0x92u);
    RVV_CHECK(rvv_run(&h, rvv_store(1, 0x13)) == RVEMU_STOP_NONE && rvv_ram[pa + 0x13] == 0x88u &&
              rvv_ram[pa + 0x14] == 0x77u && rvv_ram[pa + 0x12] == 0x92u && rvv_ram[pa + 0x15] == 0x95u);
    if (!ok) printf("FAIL rvemu sv39 store widths inside one page\n");
    return ok ? 0 : 1;
}

/* Word and doubleword stores inside one page, unaligned, with the bytes
 * around each store left alone. */
static int rvv_width_store_wide_kat(void)
{
    struct rvemu_hart h;
    const uint64_t pa = RVV_PAGE_A + 0x100u - RVV_BASE;
    int ok = 1;
    rvv_width_boot(&h);
    h.x[7] = 0x1122334455667788ull;
    RVV_CHECK(rvv_run(&h, rvv_store(2, 0x17)) == RVEMU_STOP_NONE && rvv_ram[pa + 0x17] == 0x88u &&
              rvv_ram[pa + 0x1a] == 0x55u && rvv_ram[pa + 0x16] == 0x96u && rvv_ram[pa + 0x1b] == 0x9bu);
    RVV_CHECK(rvv_run(&h, rvv_store(3, 0x03)) == RVEMU_STOP_NONE && rvv_ram[pa + 0x03] == 0x88u &&
              rvv_ram[pa + 0x0a] == 0x11u && rvv_ram[pa + 0x02] == 0x82u && rvv_ram[pa + 0x0b] == 0x8bu);
    RVV_CHECK(rvv_ld_width(&h, 3, 3) == 0x1122334455667788ull);
    RVV_CHECK(rvv_flags(RVV_DATA) == (RVV_V | RVV_R | RVV_W | RVV_A | RVV_D));
    if (!ok) printf("FAIL rvemu sv39 wide store widths inside one page\n");
    return ok ? 0 : 1;
}

/* Self-modifying code runs as rewritten, with no fence.i: a cached decode is
 * used only while RAM holds the same bits. The first rewrite changes only the
 * upper parcel of a 32-bit instruction, the next turns it into a compressed
 * one. */
static int rvv_smc_kat(void)
{
    struct rvemu_hart h;
    const uint32_t addi_7 = 0x00700293u, c_li_x5_3 = 0x428du;
    int ok = 1;
    rvv_boot(&h);
    RVV_CHECK(rvv_run(&h, RVV_ADDI_X5_0X123) == RVEMU_STOP_NONE && h.x[5] == 0x123u && h.pc == RVV_SCODE + 4u);
    RVV_CHECK(rvv_run(&h, RVV_ADDI_X5_0X123) == RVEMU_STOP_NONE && h.x[5] == 0x123u); /* cached */
    RVV_CHECK(rvv_run(&h, addi_7) == RVEMU_STOP_NONE && h.x[5] == 7u && h.pc == RVV_SCODE + 4u);
    RVV_CHECK(rvv_run(&h, c_li_x5_3) == RVEMU_STOP_NONE && h.x[5] == 3u && h.pc == RVV_SCODE + 2u);
    RVV_CHECK(rvv_run(&h, RVV_ADDI_X5_0X123) == RVEMU_STOP_NONE && h.x[5] == 0x123u && h.pc == RVV_SCODE + 4u);
    if (!ok) printf("FAIL rvemu rewritten instruction executes as rewritten\n");
    return ok ? 0 : 1;
}

/* A guest store into the page of the next fetch. */
static int rvv_smc_store_kat(void)
{
    struct rvemu_hart h;
    const uint32_t addi_7 = 0x00700293u;
    int ok = 1;
    rvv_boot(&h);
    h.priv = RVEMU_PRIV_U;
    RVV_CHECK(rvv_run(&h, RVV_ADDI_X5_0X123) == RVEMU_STOP_NONE && h.x[5] == 0x123u && h.pc == RVV_UCODE + 4u);
    h.priv = RVEMU_PRIV_S;
    rvv_map(0x60000ull, RVV_UCODE_PA, RVV_R | RVV_W);
    RVV_CHECK(rvv_sd(&h, 0x60000ull, addi_7));
    h.priv = RVEMU_PRIV_U;
    h.pc = RVV_UCODE;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && h.x[5] == 7u && h.pc == RVV_UCODE + 4u);
    if (!ok) printf("FAIL rvemu rewritten instruction executes as rewritten\n");
    return ok ? 0 : 1;
}

/* A page made non-executable and flushed faults on its next fetch with the
 * cause and stval of a first fault, sepc on the instruction. */
static int rvv_fetch_remap_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvv_boot(&h);
    RVV_CHECK(rvv_run(&h, RVV_ADDI_X5_0X123) == RVEMU_STOP_NONE && h.x[5] == 0x123u);
    rvv_map(RVV_SCODE, RVV_SCODE_PA, RVV_R | RVV_A);
    rvemu_tlb_flush(&h);
    h.pc = RVV_SCODE;
    RVV_CHECK(rvv_step(&h, NULL) == RVEMU_STOP_NONE && rvv_trapped(&h, 12, RVV_SCODE, RVV_SCODE));
    if (!ok) printf("FAIL rvemu fetch after a page lost execute permission\n");
    return ok ? 0 : 1;
}

/* One instruction at a physical pc with paging off. */
static enum rvemu_stop rvv_phys(struct rvemu_hart *h, uint64_t pc, uint32_t insn)
{
    if ((insn & 3u) == 3u) rvv_wr32(pc, insn);
    else rvv_wr16(pc, (uint16_t)insn);
    h->pc = pc;
    return rvv_step(h, NULL);
}

/* At the end of RAM: an 8-byte load at size - 8 succeeds, at size - 4 is a
 * load access fault at that address, and a compressed instruction in the last
 * two bytes executes. */
static int rvv_ramend_kat(void)
{
    struct rvemu_hart h;
    const uint64_t end = RVV_BASE + RVV_SIZE;
    int ok = 1;
    rvv_boot(&h);
    h.csr.satp = 0;
    rvv_wr64(end - 8u, RVV_PAT_A);
    h.x[6] = end - 8u;
    RVV_CHECK(rvv_phys(&h, RVV_SCODE_PA, rvv_load(3, 0)) == RVEMU_STOP_NONE && h.x[5] == RVV_PAT_A);
    h.x[6] = end - 4u;
    RVV_CHECK(rvv_phys(&h, RVV_SCODE_PA, rvv_load(3, 0)) == RVEMU_STOP_NONE &&
              h.pc == RVV_STVEC && h.csr.scause == 5u && h.csr.stval == end - 4u);
    RVV_CHECK(rvv_phys(&h, end - 2u, 0x428du) == RVEMU_STOP_NONE && h.x[5] == 3u && h.pc == end);
    if (!ok) printf("FAIL rvemu loads and fetches at the end of RAM\n");
    return ok ? 0 : 1;
}

/* Part of the test_rvemu group: called from test_rvemu(), not a group itself. */
int rvemu_vm_known_answers(void)
{
    return rvv_sizes_kat() + rvv_perm_kat() + rvv_cross_kat() + rvv_fetch_kat() + rvv_enable_kat() +
           rvv_stale_kat() + rvv_dirty_kat() + rvv_atomic_kat() + rvv_device_mprv_kat() +
           rvv_cache_kat() + rvv_cache_invisible_kat() + rvv_width_load_kat() + rvv_width_store_kat() + rvv_width_store_wide_kat() +
           rvv_smc_kat() + rvv_smc_store_kat() + rvv_fetch_remap_kat() + rvv_ramend_kat();
}
