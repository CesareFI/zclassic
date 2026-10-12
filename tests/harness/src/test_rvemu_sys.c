/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvemu system-level known answers that the official images do not
 * isolate: the SBI (firmware-in-host) profile and the device callbacks of the
 * physical bus. */
#include "test/test_core.h"
#include "rvemu/rvemu.h"
#include "base/serialize_le.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RVS_BASE 0x80000000ull
#define RVS_SIZE ((size_t)1 << 16)
#define RVS_PC (RVS_BASE + 0x100u)
#define RVS_STVEC (RVS_BASE + 0x400u)
#define RVS_DEV 0x10000000ull
#define RVS_DEV_REFUSED 0x10001000ull
#define RVS_DEV_VALUE 0xa1b2c3d4e5f60718ull
#define RVS_SENTINEL 0x5a5a5a5a5a5a5a5aull
#define RVS_SIE_BIT (1ull << 1)
#define RVS_SPP_BIT (1ull << 8)
#define RVS_IRQ_BIT (1ull << 63)
#define RVS_ECALL 0x00000073u
#define RVS_EBREAK 0x00100073u
#define RVS_MRET 0x30200073u
#define RVS_WFI 0x10500073u
#define RVS_NOP 0x00000013u
#define RVS_ADDI_X5 0x00128293u /* addi x5, x5, 1 */

/* Records a failed known answer with its line; ok is the case verdict. */
#define RVS_CHECK(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL rvemu system known answer at line %d\n", __LINE__); \
            ok = 0; \
        } \
    } while (0)

static uint8_t rvs_ram[RVS_SIZE];

struct rvs_dev {
    unsigned loads, stores, last_bytes;
    uint64_t last_addr, last_val;
};

static int rvs_dev_load(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t *out)
{
    struct rvs_dev *d = ctx;
    d->loads++;
    d->last_addr = paddr;
    d->last_bytes = nbytes;
    if (paddr >= RVS_DEV_REFUSED) return -1;
    *out = RVS_DEV_VALUE; /* wider than asked: the bus truncates */
    return 0;
}

static int rvs_dev_store(void *ctx, uint64_t paddr, unsigned nbytes, uint64_t val)
{
    struct rvs_dev *d = ctx;
    d->stores++;
    d->last_addr = paddr;
    d->last_bytes = nbytes;
    d->last_val = val;
    return paddr >= RVS_DEV_REFUSED ? -1 : 0;
}

static uint32_t rvs_csr_insn(unsigned f3, unsigned csr, unsigned rd, unsigned rs1)
{
    return (csr << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x73u;
}

/* load: rd = x5, base = x6. store: source = x7, base = x6. */
static uint32_t rvs_load_insn(unsigned f3) { return (6u << 15) | (f3 << 12) | (5u << 7) | 0x03u; }
static uint32_t rvs_store_insn(unsigned f3) { return (7u << 20) | (6u << 15) | (f3 << 12) | 0x23u; }

static void rvs_put(uint32_t insn)
{
    memset(rvs_ram, 0, sizeof(rvs_ram));
    zcl_write_u32_le(&rvs_ram[RVS_PC - RVS_BASE], insn);
}

static enum rvemu_stop rvs_step(struct rvemu_hart *h)
{
    struct rvemu_mem mem = {.base = RVS_BASE, .size = RVS_SIZE, .bytes = rvs_ram};
    return rvemu_step(h, &mem);
}

static void rvs_sbi(struct rvemu_hart *h, unsigned priv, uint32_t insn)
{
    rvs_put(insn);
    rvemu_hart_init_sbi(h, RVS_PC);
    h->priv = priv;
    h->csr.stvec = RVS_STVEC;
}

/* The step trapped to S through stvec and nothing reached M. */
static int rvs_trapped(const struct rvemu_hart *h, uint64_t cause, uint64_t tval, int spp)
{
    return h->priv == RVEMU_PRIV_S && h->pc == RVS_STVEC && h->csr.scause == cause &&
           h->csr.stval == tval && h->csr.sepc == RVS_PC &&
           ((h->csr.mstatus & RVS_SPP_BIT) != 0) == spp && h->csr.mcause == 0 &&
           h->csr.mepc == 0;
}

/* addi, then an S-mode ecall: the addi counts once and the ecall stops for the
 * host, again on every further step, counting nothing. */
static int rvs_ecall_stops(struct rvemu_hart *h)
{
    int ok = 1;
    RVS_CHECK(h->priv == RVEMU_PRIV_S && h->profile == RVEMU_PROFILE_SBI);
    RVS_CHECK(rvs_step(h) == RVEMU_STOP_NONE && h->instret == 1 && h->retired == 1 && h->cycle == 1);
    RVS_CHECK(rvs_step(h) == RVEMU_STOP_ECALL && h->pc == RVS_PC + 4u && h->csr.scause == 0);
    RVS_CHECK(rvs_step(h) == RVEMU_STOP_ECALL && h->pc == RVS_PC + 4u); /* stopped until answered */
    RVS_CHECK(h->instret == 1 && h->retired == 1 && h->cycle == 1);
    return ok;
}

/* The host answers: pc moves past the ecall, nothing retires, and the addi
 * that follows counts once. */
static int rvs_ecall_resumes(struct rvemu_hart *h)
{
    int ok = 1;
    rvemu_ecall_return(h, 7, 9);
    RVS_CHECK(h->x[10] == 7 && h->x[11] == 9 && h->pc == RVS_PC + 8u && h->priv == RVEMU_PRIV_S);
    RVS_CHECK(h->instret == 1 && h->retired == 1 && h->cycle == 1);
    RVS_CHECK(rvs_step(h) == RVEMU_STOP_NONE && h->x[5] == 2 && h->pc == RVS_PC + 12u);
    RVS_CHECK(h->instret == 2 && h->retired == 2 && h->cycle == 2);
    return ok;
}

/* An S-mode ecall stops for the host and rvemu_ecall_return resumes it without
 * retiring anything (an ecall is a trap); the addi on each side counts once. A
 * U-mode ecall traps to S, which retires nothing either. */
static int rvs_sbi_ecall_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, RVS_ADDI_X5);
    zcl_write_u32_le(&rvs_ram[RVS_PC + 4u - RVS_BASE], RVS_ECALL);
    zcl_write_u32_le(&rvs_ram[RVS_PC + 8u - RVS_BASE], RVS_ADDI_X5);
    RVS_CHECK(rvs_ecall_stops(&h));
    RVS_CHECK(rvs_ecall_resumes(&h));
    rvs_sbi(&h, RVEMU_PRIV_U, RVS_ECALL);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 8, 0, 0) && h.instret == 0);
    RVS_CHECK(h.retired == 0 && h.cycle == 1);
    if (!ok) printf("FAIL rvemu sbi ecall\n");
    return ok ? 0 : 1;
}

/* Nothing enters M: machine CSRs and mret are illegal in S, ebreak and access
 * faults land in S, and the counters are readable. */
static int rvs_sbi_trap_kat(void)
{
    const uint32_t rd_mstatus = rvs_csr_insn(2, 0x300, 5, 0), wr_medeleg = rvs_csr_insn(1, 0x302, 0, 6);
    const uint32_t rd_time = rvs_csr_insn(2, 0xc01, 5, 0);
    struct rvemu_hart h;
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, rd_mstatus);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 2, rd_mstatus, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, wr_medeleg);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 2, wr_medeleg, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, RVS_MRET);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 2, RVS_MRET, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, RVS_EBREAK);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 3, RVS_PC, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(3));
    h.x[6] = RVS_BASE + RVS_SIZE;
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 5, RVS_BASE + RVS_SIZE, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, rd_time);
    h.time = 777;
    h.csr.mcounteren = 0; /* no M-mode to trap to: S reads time regardless */
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.x[5] == 777 && h.pc == RVS_PC + 4u);
    rvs_sbi(&h, RVEMU_PRIV_U, rd_time); /* U is gated by scounteren */
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 2, rd_time, 0));
    rvs_sbi(&h, RVEMU_PRIV_U, rd_time);
    h.csr.scounteren = 2;
    h.time = 778;
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.x[5] == 778 && h.priv == RVEMU_PRIV_U);
    if (!ok) printf("FAIL rvemu sbi traps stay in S\n");
    return ok ? 0 : 1;
}

/* wfi retires once, idles without retiring, and wakes without trapping when
 * SEIP is raised with SIE clear. */
static int rvs_wfi_idles(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, RVS_WFI);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.pc == RVS_PC + 4u);
    RVS_CHECK(h.retired == 1 && h.instret == 1); /* wfi itself retires once */
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_WFI && rvs_step(&h) == RVEMU_STOP_WFI);
    RVS_CHECK(h.retired == 1 && h.instret == 1); /* idling retires nothing */
    h.csr.mie = 1ull << RVEMU_IRQ_SEIP;
    rvemu_set_irq(&h, RVEMU_IRQ_SEIP, 1); /* SIE clear: wakes without trapping */
    zcl_write_u32_le(&rvs_ram[RVS_PC + 4u - RVS_BASE], RVS_NOP);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.pc == RVS_PC + 8u && h.idle == 0);
    RVS_CHECK(h.retired == 2 && h.instret == 2);
    return ok;
}

/* The host's STIP is enabled by the guest through sie and sstatus and taken in
 * S; a machine-level line is never taken; wfi idles until SEIP is raised. */
static int rvs_sbi_irq_kat(void)
{
    struct rvemu_hart h;
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_csr_insn(1, 0x104, 0, 6)); /* csrw sie, x6 */
    h.x[6] = (1ull << RVEMU_IRQ_STIP) | (1ull << RVEMU_IRQ_SEIP) | (1ull << RVEMU_IRQ_MTIP);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE);
    RVS_CHECK(h.csr.mie == ((1ull << RVEMU_IRQ_STIP) | (1ull << RVEMU_IRQ_SEIP)));
    h.csr.mstatus |= RVS_SIE_BIT;
    RVS_CHECK(rvemu_set_irq(&h, RVEMU_IRQ_MTIP, 1) == 0);
    zcl_write_u32_le(&rvs_ram[RVS_PC + 4u - RVS_BASE], RVS_NOP);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.pc == RVS_PC + 8u && h.priv == RVEMU_PRIV_S);
    RVS_CHECK(h.retired == 2 && h.instret == 2);
    RVS_CHECK(rvemu_set_irq(&h, RVEMU_IRQ_STIP, 1) == 0);
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && h.pc == RVS_STVEC && h.priv == RVEMU_PRIV_S);
    RVS_CHECK(h.csr.scause == (RVS_IRQ_BIT | RVEMU_IRQ_STIP) && h.csr.sepc == RVS_PC + 8u);
    RVS_CHECK(h.csr.mcause == 0 && (h.csr.mstatus & RVS_SIE_BIT) == 0);
    RVS_CHECK(h.retired == 2 && h.instret == 2); /* interrupt entry retires nothing */
    RVS_CHECK(rvs_wfi_idles());
    if (!ok) printf("FAIL rvemu sbi interrupts and wfi\n");
    return ok ? 0 : 1;
}

static enum rvemu_stop rvs_dev_step(struct rvemu_hart *h, struct rvs_dev *d)
{
    struct rvemu_mem mem = {.base = RVS_BASE, .size = RVS_SIZE, .bytes = rvs_ram, .io_ctx = d,
                            .io_load = rvs_dev_load, .io_store = rvs_dev_store};
    return rvemu_step(h, &mem);
}

/* A data access outside RAM reaches the device callbacks once, unsplit, with
 * the access width; the value is truncated to that width both ways. */
static int rvs_device_ok_kat(void)
{
    struct rvemu_hart h;
    struct rvs_dev d = {0};
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(2)); /* lw x5, 0(x6) */
    h.x[6] = RVS_DEV;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == 0xffffffffe5f60718ull);
    RVS_CHECK(d.loads == 1 && d.last_addr == RVS_DEV && d.last_bytes == 4 && h.pc == RVS_PC + 4u);
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(3)); /* ld */
    h.x[6] = RVS_DEV + 8u;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == RVS_DEV_VALUE && d.last_bytes == 8);
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_store_insn(0)); /* sb x7, 0(x6) */
    h.x[6] = RVS_DEV + 3u;
    h.x[7] = 0x1234u;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && d.stores == 1 && d.last_addr == RVS_DEV + 3u);
    RVS_CHECK(d.last_bytes == 1 && d.last_val == 0x34u);
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_store_insn(3)); /* sd */
    h.x[6] = RVS_DEV;
    h.x[7] = RVS_SENTINEL;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && d.stores == 2 && d.last_bytes == 8);
    RVS_CHECK(d.last_val == RVS_SENTINEL && d.loads == 2);
    if (!ok) printf("FAIL rvemu device load and store\n");
    return ok ? 0 : 1;
}

/* Every access width on both lines of the bus: the device returns and is
 * handed a full 64-bit value, and each side sees only the low 1, 2, 4 or 8
 * bytes. The loads are the zero-extending ones so the narrowing shows. */
static int rvs_device_width_kat(void)
{
    static const struct { unsigned f3, bytes; uint64_t want; } loads[] = {
        {4, 1, 0x18ull}, {5, 2, 0x0718ull}, {6, 4, 0xe5f60718ull}, {3, 8, RVS_DEV_VALUE}};
    static const struct { unsigned f3, bytes; uint64_t want; } stores[] = {
        {0, 1, 0xffull}, {1, 2, 0xeeffull}, {2, 4, 0xccddeeffull}, {3, 8, 0x8899aabbccddeeffull}};
    struct rvemu_hart h;
    struct rvs_dev d = {0};
    int ok = 1;
    for (unsigned i = 0; i < 4; i++) {
        rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(loads[i].f3));
        h.x[6] = RVS_DEV;
        RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == loads[i].want);
        RVS_CHECK(d.loads == i + 1u && d.last_bytes == loads[i].bytes);
    }
    for (unsigned i = 0; i < 4; i++) {
        rvs_sbi(&h, RVEMU_PRIV_S, rvs_store_insn(stores[i].f3));
        h.x[6] = RVS_DEV;
        h.x[7] = 0x8899aabbccddeeffull;
        RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && d.last_val == stores[i].want);
        RVS_CHECK(d.stores == i + 1u && d.last_bytes == stores[i].bytes);
    }
    if (!ok) printf("FAIL rvemu device access widths\n");
    return ok ? 0 : 1;
}

/* A refusing device, a missing callback and an instruction fetch outside RAM
 * are access faults with the address in stval; the STOP profile stops. */
static int rvs_device_fault_kat(void)
{
    struct rvemu_hart h;
    struct rvs_dev d = {0};
    int ok = 1;
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(2));
    h.x[6] = RVS_DEV_REFUSED + 4u;
    h.x[5] = RVS_SENTINEL;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && rvs_trapped(&h, 5, RVS_DEV_REFUSED + 4u, 1));
    RVS_CHECK(d.loads == 1 && h.x[5] == RVS_SENTINEL && h.instret == 0);
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_store_insn(2));
    h.x[6] = RVS_DEV_REFUSED;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && rvs_trapped(&h, 7, RVS_DEV_REFUSED, 1));
    RVS_CHECK(d.stores == 1);
    rvs_sbi(&h, RVEMU_PRIV_S, rvs_load_insn(2)); /* no callbacks: the access faults */
    h.x[6] = RVS_DEV;
    RVS_CHECK(rvs_step(&h) == RVEMU_STOP_NONE && rvs_trapped(&h, 5, RVS_DEV, 1));
    rvs_sbi(&h, RVEMU_PRIV_S, RVS_NOP); /* instructions come from RAM only */
    h.pc = RVS_DEV;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && h.csr.scause == 1 && h.csr.stval == RVS_DEV);
    RVS_CHECK(h.csr.sepc == RVS_DEV && d.loads == 1);
    rvs_put(rvs_load_insn(2));
    rvemu_hart_init(&h, RVS_PC);
    h.x[6] = RVS_DEV;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_NONE && h.x[5] == 0xffffffffe5f60718ull);
    h.pc = RVS_PC;
    h.x[6] = RVS_DEV_REFUSED;
    RVS_CHECK(rvs_dev_step(&h, &d) == RVEMU_STOP_OUT_OF_RANGE && h.pc == RVS_PC);
    if (!ok) printf("FAIL rvemu device refusal is an access fault\n");
    return ok ? 0 : 1;
}

/* Part of the test_rvemu group: called from test_rvemu(), not a group itself. */
int rvemu_sys_known_answers(void)
{
    return rvs_sbi_ecall_kat() + rvs_sbi_trap_kat() + rvs_sbi_irq_kat() +
           rvs_device_ok_kat() + rvs_device_width_kat() + rvs_device_fault_kat();
}
