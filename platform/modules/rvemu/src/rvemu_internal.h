/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: internal seams between the rvemu translation units. */
#ifndef ZCL_RVEMU_INTERNAL_H
#define ZCL_RVEMU_INTERNAL_H

#include "rvemu/rvemu.h"
#include "base/serialize_le.h"
#include <string.h>

/* Memory: 1 when [addr, addr + len) lies wholly inside mem, else 0. */
static inline int rvemu_mem_contains(const struct rvemu_mem *mem, uint64_t addr, uint64_t len)
{
    if (addr < mem->base) return 0;
    uint64_t off = addr - mem->base;
    if (off > (uint64_t)mem->size) return 0;
    return len <= (uint64_t)mem->size - off;
}

/* The host bytes of [addr, addr + len) when that lies wholly inside RAM, else null. */
static inline uint8_t *rvemu_ram_ptr(const struct rvemu_mem *mem, uint64_t addr, uint64_t len)
{
    return rvemu_mem_contains(mem, addr, len) ? mem->bytes + (addr - mem->base) : NULL;
}

/* Little-endian n-byte (n in 1..8) RAM-only load/store; -1 when not wholly in
 * RAM. The widths a guest access uses (1, 2, 4, 8) are single host accesses. */
static inline int rvemu_ram_load(const struct rvemu_mem *mem, uint64_t addr, unsigned n,
                                 uint64_t *out)
{
    if (n == 0 || n > 8 || !rvemu_mem_contains(mem, addr, n)) return -1;
    const uint8_t *p = mem->bytes + (addr - mem->base);
    switch (n) {
    case 1: *out = p[0]; return 0;
    case 2: *out = zcl_read_u16_le(p); return 0;
    case 4: *out = zcl_read_u32_le(p); return 0;
    case 8: *out = zcl_read_u64_le(p); return 0;
    default: break;
    }
    uint8_t wide[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(wide, p, n);
    *out = zcl_read_u64_le(wide);
    return 0;
}

static inline int rvemu_ram_store(struct rvemu_mem *mem, uint64_t addr, unsigned n, uint64_t val)
{
    if (n == 0 || n > 8 || !rvemu_mem_contains(mem, addr, n)) return -1;
    uint8_t *p = mem->bytes + (addr - mem->base);
    switch (n) {
    case 1: p[0] = (uint8_t)val; return 0;
    case 2: zcl_write_u16_le(p, (uint16_t)val); return 0;
    case 4: zcl_write_u32_le(p, (uint32_t)val); return 0;
    case 8: zcl_write_u64_le(p, val); return 0;
    default: break;
    }
    uint8_t wide[8];
    zcl_write_u64_le(wide, val);
    memcpy(p, wide, n);
    return 0;
}

/* The same over the whole bus: RAM, else the device callbacks; -1 is an access
 * fault. A device value is truncated to n bytes in both directions. */
int rvemu_mem_load(const struct rvemu_mem *mem, uint64_t addr, unsigned n, uint64_t *out);
int rvemu_mem_store(struct rvemu_mem *mem, uint64_t addr, unsigned n, uint64_t val);

/* rvemu_vm.c: guest-virtual access for the executing hart. Each translates
 * through Sv39 when satp selects it below M (loads and stores at the MPRV
 * privilege), then uses RAM or the device callbacks. On failure the cause and
 * the faulting virtual address are recorded in the hart (fault_set) and the
 * result is RVEMU_STOP_OUT_OF_RANGE. fetch reads the instruction at pc from
 * RAM: a 16-bit parcel, plus the second one when the low two bits are 0b11.
 * atomic translates an aligned n-byte RAM access (as a store unless it is lr)
 * to its physical address. */
enum rvemu_stop rvemu_vm_load(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                              uint64_t *out);
enum rvemu_stop rvemu_vm_store(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                               uint64_t val);
enum rvemu_stop rvemu_vm_fetch(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t pc,
                               uint32_t *raw);

/* Decoded-instruction cache. lookup returns 1 and writes *raw when the line
 * matches pc, satp and privilege. A line whose store epoch equals the hart's
 * skips the parcel re-read; every other hit confirms the bits still sit at pa.
 * fill counts one miss and installs the line when len is 2 or 4.
 * note_store is declared on the public hart header: it drops any line whose
 * parcel overlaps [pa, pa + n) and advances the store epoch.
 * flush drops every line and keeps the hit and miss counts. */
int rvemu_icache_lookup(struct rvemu_hart *h, const struct rvemu_mem *mem, uint64_t pc,
                        uint32_t *raw);
void rvemu_icache_fill(struct rvemu_hart *h, uint64_t pc, uint64_t pa, uint32_t raw,
                       unsigned len);
void rvemu_icache_note_store(struct rvemu_hart *h, uint64_t pa, unsigned n);
void rvemu_icache_flush(struct rvemu_hart *h);
enum rvemu_stop rvemu_vm_atomic(struct rvemu_hart *h, struct rvemu_mem *m, uint64_t va, unsigned n,
                                int store, uint64_t *pa);

/* Integer ALU for OP / OP-IMM (word = 0) and OP-32 / OP-IMM-32 (word = 1).
 * f7 is the funct7 field. Returns -1 for an encoding that is not an
 * RV64IM or supported Zbb register operation. Encoded zext.h rs2 is checked
 * by the instruction executor before reaching this value-level seam. */
int rvemu_alu(unsigned f3, unsigned f7, int word, uint64_t a, uint64_t b, uint64_t *out);
/* Exact RV64 Zbb immediate forms; -1 leaves the output untouched. */
int rvemu_zbb_imm(unsigned imm, unsigned f3, int word, uint64_t a, uint64_t *out);

/* A-extension executor for OP-AMO. Returns the stop reason, RVEMU_STOP_NONE
 * on success. */
enum rvemu_stop rvemu_exec_amo(struct rvemu_hart *hart, struct rvemu_mem *mem, uint32_t insn);
/* Drops the lr reservation when a store of bytes at physical addr overlaps it. */
void rvemu_resv_note_store(struct rvemu_hart *hart, uint64_t addr, unsigned bytes);

/* CSR file. Read returns -1 for an unimplemented CSR; write also returns -1
 * for a read-only one. */
int rvemu_csr_read(struct rvemu_hart *hart, unsigned addr, uint64_t *out);
int rvemu_csr_write(struct rvemu_hart *hart, unsigned addr, uint64_t val);

/* F and D extensions (rvemu_fpu.c). Execute one LOAD-FP, STORE-FP, FMADD-family or
 * OP-FP instruction; ILLEGAL while mstatus.FS is Off or for a reserved
 * encoding. The CSR hooks return 1 for a CSR that is not fflags, frm or fcsr,
 * 0 when handled and -1 when the access is illegal. */
void rvemu_fpu_reset(struct rvemu_hart *h);
enum rvemu_stop rvemu_fpu_exec(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t insn);
int rvemu_fpu_csr_read(struct rvemu_hart *h, unsigned addr, uint64_t *out);
int rvemu_fpu_csr_write(struct rvemu_hart *h, unsigned addr, uint64_t val);


/* mstatus fields (RV64). */
#define MSTATUS_SIE (1ull << 1)
#define MSTATUS_MIE (1ull << 3)
#define MSTATUS_SPIE (1ull << 5)
#define MSTATUS_MPIE (1ull << 7)
#define MSTATUS_SPP (1ull << 8)
#define MSTATUS_MPP (3ull << 11)
#define MSTATUS_FS (3ull << 13)
#define MSTATUS_MPRV (1ull << 17)
#define MSTATUS_SUM (1ull << 18)
#define MSTATUS_MXR (1ull << 19)
#define MSTATUS_TVM (1ull << 20)
#define MSTATUS_TW (1ull << 21)
#define MSTATUS_TSR (1ull << 22)
#define MSTATUS_UXL (3ull << 32)
#define MSTATUS_SXL (3ull << 34)
#define MSTATUS_SD (1ull << 63)
/* UXL and SXL are fixed at 2 (64-bit). */
#define MSTATUS_XL_FIXED ((2ull << 32) | (2ull << 34))
#define MSTATUS_MPP_SHIFT 11u
#define CAUSE_IRQ (1ull << 63)

/* mip/mie bit groups: the S-level interrupts (SSI, STI, SEI), the M-level ones
 * (MSI, MTI, MEI), and every implemented bit. */
#define IRQ_S_MASK 0x222ull
#define IRQ_M_MASK 0x888ull
#define IRQ_ALL_MASK (IRQ_S_MASK | IRQ_M_MASK)

/* What one fetch/decode/execute pass learned, for trap reporting. */
struct rvemu_ctx {
    uint32_t insn;    /* the 32-bit (expanded) instruction */
    uint32_t raw;     /* the bits as fetched: halfword when compressed */
    int executed;     /* 1 once the instruction was fetched and decoded */
};

/* One step without trap handling: the shared fetch/decode/execute core. */
enum rvemu_stop rvemu_step_core(struct rvemu_hart *hart, struct rvemu_mem *mem,
                                struct rvemu_ctx *ctx);

/* Counters: call once per executed step. retired is 1 when it retired. */
#define RVEMU_INHIBIT_CY 1ull
#define RVEMU_INHIBIT_IR 4ull
static inline void rvemu_count(struct rvemu_hart *h, int retired)
{
    unsigned written = h->cnt_written;
    h->cnt_written = 0;
    if (!(written & 1u) && !(h->csr.mcountinhibit & RVEMU_INHIBIT_CY)) h->cycle++;
    if (retired && !(written & 2u) && !(h->csr.mcountinhibit & RVEMU_INHIBIT_IR)) h->instret++;
    if (retired) h->retired++;
}

/* rvemu_priv.c: mret, sret, wfi, sfence.vma for the trapping profiles. Returns 1
 * and writes *stop (and maybe *next) when insn is one of them, else 0. */
int rvemu_priv_exec(struct rvemu_hart *h, uint32_t insn, uint64_t *next, enum rvemu_stop *stop);

/* rvemu_trap.c: architectural trap entry and the MACHINE-profile step.
 * cause carries CAUSE_IRQ for an interrupt. */
void rvemu_trap_take(struct rvemu_hart *h, uint64_t cause, uint64_t tval);
enum rvemu_stop rvemu_step_machine(struct rvemu_hart *h, struct rvemu_mem *mem);
/* mip as software sees it: the writable bits plus the platform lines. */
uint64_t rvemu_mip_effective(const struct rvemu_hart *h);

#endif
