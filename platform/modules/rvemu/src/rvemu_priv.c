/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the privileged instructions of the MACHINE profile (mret, sret, wfi,
 * sfence.vma) and the platform interrupt lines. */
#include "rvemu_internal.h"

#define INSN_SRET 0x10200073u
#define INSN_MRET_PRIV 0x30200073u
#define INSN_WFI 0x10500073u
#define SFENCE_VMA_MASK 0xfe007fffu
#define SFENCE_VMA_BITS 0x12000073u

static uint64_t with_bit(uint64_t v, uint64_t bit, int on)
{
    return on ? (v | bit) : (v & ~bit);
}

/* mret: privilege from MPP, MIE from MPIE, MPIE set, MPP back to U, and MPRV
 * cleared when the target is below M. */
static void do_mret(struct rvemu_hart *h, uint64_t *next)
{
    uint64_t m = h->csr.mstatus;
    unsigned mpp = (unsigned)((m & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT);
    m = with_bit(m, MSTATUS_MIE, (m & MSTATUS_MPIE) != 0);
    m |= MSTATUS_MPIE;
    m &= ~MSTATUS_MPP;
    if (mpp != RVEMU_PRIV_M) m &= ~MSTATUS_MPRV;
    h->csr.mstatus = m;
    h->priv = mpp;
    *next = h->csr.mepc & ~(uint64_t)1;
}

/* sret: privilege from SPP, SIE from SPIE, SPIE set, SPP back to U, MPRV
 * cleared (the target is S or U, always below M). */
static void do_sret(struct rvemu_hart *h, uint64_t *next)
{
    uint64_t m = h->csr.mstatus;
    unsigned spp = (m & MSTATUS_SPP) ? RVEMU_PRIV_S : RVEMU_PRIV_U;
    m = with_bit(m, MSTATUS_SIE, (m & MSTATUS_SPIE) != 0);
    m |= MSTATUS_SPIE;
    m &= ~(MSTATUS_SPP | MSTATUS_MPRV);
    h->csr.mstatus = m;
    h->priv = spp;
    *next = h->csr.sepc & ~(uint64_t)1;
}

static enum rvemu_stop exec_mret(struct rvemu_hart *h, uint64_t *next)
{
    if (h->priv != RVEMU_PRIV_M) return RVEMU_STOP_ILLEGAL;
    do_mret(h, next);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_sret(struct rvemu_hart *h, uint64_t *next)
{
    if (h->priv == RVEMU_PRIV_U) return RVEMU_STOP_ILLEGAL;
    if (h->priv == RVEMU_PRIV_S && (h->csr.mstatus & MSTATUS_TSR)) return RVEMU_STOP_ILLEGAL;
    do_sret(h, next);
    return RVEMU_STOP_NONE;
}

/* wfi is illegal in U, and below M when TW is set (the time limit is zero). A
 * permitted wfi retires and marks the hart idle until an interrupt is pending. */
static enum rvemu_stop exec_wfi(struct rvemu_hart *h)
{
    if (h->priv == RVEMU_PRIV_U) return RVEMU_STOP_ILLEGAL;
    if (h->priv != RVEMU_PRIV_M && (h->csr.mstatus & MSTATUS_TW)) return RVEMU_STOP_ILLEGAL;
    h->idle = 1;
    return RVEMU_STOP_NONE;
}

/* sfence.vma: illegal in U, and in S while TVM is set. Every form (any rs1,
 * any rs2) drops the whole translation cache. */
static enum rvemu_stop exec_sfence(struct rvemu_hart *h)
{
    if (h->priv == RVEMU_PRIV_U) return RVEMU_STOP_ILLEGAL;
    if (h->priv == RVEMU_PRIV_S && (h->csr.mstatus & MSTATUS_TVM)) return RVEMU_STOP_ILLEGAL;
    rvemu_tlb_flush(h);
    return RVEMU_STOP_NONE;
}

int rvemu_priv_exec(struct rvemu_hart *h, uint32_t insn, uint64_t *next, enum rvemu_stop *stop)
{
    if (insn == INSN_MRET_PRIV) *stop = exec_mret(h, next);
    else if (insn == INSN_SRET) *stop = exec_sret(h, next);
    else if (insn == INSN_WFI) *stop = exec_wfi(h);
    else if ((insn & SFENCE_VMA_MASK) == SFENCE_VMA_BITS) *stop = exec_sfence(h);
    else return 0;
    return 1;
}

int rvemu_set_irq(struct rvemu_hart *hart, unsigned cause, int level)
{
    if (!hart || cause > 63u) return -1;
    uint64_t bit = 1ull << cause;
    if (bit & IRQ_S_MASK) hart->csr.mip = with_bit(hart->csr.mip, bit, level != 0);
    else if (bit & IRQ_M_MASK) hart->irq_in = with_bit(hart->irq_in, bit, level != 0);
    else return -1;
    return 0;
}

void rvemu_ecall_return(struct rvemu_hart *hart, uint64_t a0, uint64_t a1)
{
    if (!hart) return;
    hart->x[10] = a0;
    hart->x[11] = a1;
    hart->pc += 4u;
}
