/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RV64A atomics for a single hart: the lr/sc reservation and the
 * AMO read-modify-write ops, word (.w, sign-extended result) and doubleword
 * (.d) forms. The aq and rl ordering bits are ignored: one hart has no other
 * observer to order against. Every access is alignment-checked, translated and
 * range-checked before any hart state changes, so a faulting AMO leaves the
 * registers and the reservation untouched. */
#include "rvemu_internal.h"

#define F3_AMO_W 2u
#define F3_AMO_D 3u
#define F5_AMOADD 0x00u
#define F5_AMOSWAP 0x01u
#define F5_LR 0x02u
#define F5_SC 0x03u
#define F5_AMOXOR 0x04u
#define F5_AMOOR 0x08u
#define F5_AMOAND 0x0cu
#define F5_AMOMIN 0x10u
#define F5_AMOMAX 0x14u
#define F5_AMOMINU 0x18u
#define F5_AMOMAXU 0x1cu

static unsigned rd_of(uint32_t i) { return (i >> 7) & 31u; }
static unsigned rs1_of(uint32_t i) { return (i >> 15) & 31u; }
static unsigned rs2_of(uint32_t i) { return (i >> 20) & 31u; }

/* Sign-extends the low bits of v (bits is 8, 16, 32 or 64). */
static uint64_t sext_bits(uint64_t v, unsigned bits)
{
    unsigned sh = 64u - bits;
    return (uint64_t)((int64_t)(v << sh) >> sh);
}

/* 1 when a < b as signed values of the given width. The sign-extended
 * operands are cast back to int64_t: an unsigned compare would be wrong. */
static int sgn_less(uint64_t a, uint64_t b, unsigned bits)
{
    return (int64_t)sext_bits(a, bits) < (int64_t)sext_bits(b, bits);
}

static uint64_t width_mask(unsigned bytes)
{
    return bytes == 4u ? (uint64_t)UINT32_MAX : UINT64_MAX;
}

/* The access width in bytes for the AMO funct3 field, or 0 when it is not
 * the word or doubleword form. */
static unsigned amo_width(uint32_t i)
{
    unsigned f3 = (i >> 12) & 7u;
    if (f3 == F3_AMO_W) return 4u;
    if (f3 == F3_AMO_D) return 8u;
    return 0u;
}

static int amo_known(uint32_t f5)
{
    switch (f5) {
    case F5_AMOADD: case F5_AMOSWAP: case F5_LR: case F5_SC:
    case F5_AMOXOR: case F5_AMOOR: case F5_AMOAND: case F5_AMOMIN:
    case F5_AMOMAX: case F5_AMOMINU: case F5_AMOMAXU:
        return 1;
    default:
        return 0;
    }
}

static void amo_set_rd(struct rvemu_hart *h, uint32_t i, uint64_t v)
{
    unsigned rd = rd_of(i);
    if (rd != 0) h->x[rd] = v;
}

/* The new memory value for a read-modify-write op. old and src are both
 * zero-extended to the access width; min and max compare them as signed,
 * minu and maxu as unsigned. */
static uint64_t amo_combine(uint32_t f5, unsigned bytes, uint64_t old, uint64_t src)
{
    unsigned bits = 8u * bytes;
    switch (f5) {
    case F5_AMOSWAP: return src;
    case F5_AMOADD: return (old + src) & width_mask(bytes);
    case F5_AMOXOR: return old ^ src;
    case F5_AMOAND: return old & src;
    case F5_AMOOR: return old | src;
    case F5_AMOMIN: return sgn_less(old, src, bits) ? old : src;
    case F5_AMOMAX: return sgn_less(src, old, bits) ? old : src;
    case F5_AMOMINU: return old < src ? old : src;
    case F5_AMOMAXU: return old > src ? old : src;
    default: return old;
    }
}

void rvemu_resv_note_store(struct rvemu_hart *h, uint64_t addr, unsigned bytes)
{
    if (h->resv_bytes == 0) return;
    if (addr < h->resv_addr + h->resv_bytes && h->resv_addr < addr + bytes)
        h->resv_bytes = 0;
}

/* pa is the translated RAM address in all three: the reservation is held on
 * the physical address, so two mappings of one page share it. */
static enum rvemu_stop exec_lr(struct rvemu_hart *h, const struct rvemu_mem *m,
                               uint32_t i, uint64_t pa, unsigned bytes)
{
    uint64_t v = 0;
    if (rvemu_ram_load(m, pa, bytes, &v) != 0) return RVEMU_STOP_OUT_OF_RANGE;
    h->resv_addr = pa;
    h->resv_bytes = bytes;
    amo_set_rd(h, i, sext_bits(v, 8u * bytes));
    return RVEMU_STOP_NONE;
}

/* sc always drops the reservation, whether or not it succeeds. It writes rd
 * 0 on success and 1 on failure, and stores only on success. */
static enum rvemu_stop exec_sc(struct rvemu_hart *h, struct rvemu_mem *m,
                               uint32_t i, uint64_t pa, unsigned bytes)
{
    int ok = h->resv_bytes == bytes && h->resv_addr == pa;
    uint64_t src = h->x[rs2_of(i)] & width_mask(bytes);
    h->resv_bytes = 0;
    if (ok && rvemu_ram_store(m, pa, bytes, src) != 0) return RVEMU_STOP_OUT_OF_RANGE;
    if (ok) rvemu_icache_note_store(h, pa, bytes);
    amo_set_rd(h, i, ok ? 0u : 1u);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_rmw(struct rvemu_hart *h, struct rvemu_mem *m,
                                uint32_t i, uint32_t f5, uint64_t pa, unsigned bytes)
{
    uint64_t old = 0;
    uint64_t src = h->x[rs2_of(i)] & width_mask(bytes);
    if (rvemu_ram_load(m, pa, bytes, &old) != 0) return RVEMU_STOP_OUT_OF_RANGE;
    if (rvemu_ram_store(m, pa, bytes, amo_combine(f5, bytes, old, src)) != 0)
        return RVEMU_STOP_OUT_OF_RANGE;
    rvemu_resv_note_store(h, pa, bytes);
    rvemu_icache_note_store(h, pa, bytes);
    amo_set_rd(h, i, sext_bits(old, 8u * bytes));
    return RVEMU_STOP_NONE;
}

/* Decode, then alignment, then translation: lr as a load, sc and the AMOs as a
 * store, so write permission is known (and D set) before anything is read.
 * The target must be RAM; a device is refused with an access fault and its
 * callbacks are never called. */
enum rvemu_stop rvemu_exec_amo(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    unsigned bytes = amo_width(i);
    uint32_t f5 = i >> 27;
    if (bytes == 0 || !amo_known(f5)) return RVEMU_STOP_ILLEGAL;
    if (f5 == F5_LR && rs2_of(i) != 0) return RVEMU_STOP_ILLEGAL;
    uint64_t addr = h->x[rs1_of(i)], pa = 0;
    if ((addr & (uint64_t)(bytes - 1u)) != 0) return RVEMU_STOP_MISALIGNED;
    enum rvemu_stop s = rvemu_vm_atomic(h, m, addr, bytes, f5 != F5_LR, &pa);
    if (s != RVEMU_STOP_NONE) return s;
    if (f5 == F5_LR) return exec_lr(h, m, i, pa, bytes);
    if (f5 == F5_SC) return exec_sc(h, m, i, pa, bytes);
    return exec_rmw(h, m, i, f5, pa, bytes);
}
