/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the step of the trapping profiles (MACHINE and SBI). Takes
 * interrupts at instruction boundaries (priority and global-enable rules per
 * mode), turns the stop reasons of the shared execution core into
 * architectural synchronous exceptions (cause and tval), and enters the trap
 * through medeleg/mideleg and mtvec/stvec in direct or vectored mode. The SBI
 * profile has no M-mode: everything is taken in S, and an S-mode ecall is
 * handed to the host instead of trapping. */
#include "rvemu_internal.h"

#define CAUSE_FETCH_MISALIGNED 0u
#define CAUSE_FETCH_ACCESS 1u
#define CAUSE_ILLEGAL 2u
#define CAUSE_BREAKPOINT 3u
#define CAUSE_LOAD_MISALIGNED 4u
#define CAUSE_LOAD_ACCESS 5u
#define CAUSE_STORE_MISALIGNED 6u
#define CAUSE_STORE_ACCESS 7u
#define CAUSE_ECALL_BASE 8u /* + privilege: U 8, S 9, M 11 */

#define OPC_LOAD 0x03u
#define OPC_LOAD_FP 0x07u
#define OPC_STORE 0x23u
#define OPC_STORE_FP 0x27u
#define OPC_AMO 0x2fu
#define AMO_F5_LR 0x02u

/* Interrupt priority, highest first: MEI, MSI, MTI, SEI, SSI, STI. */
static const uint8_t IRQ_PRIORITY[6] = {11, 3, 7, 9, 1, 5};

uint64_t rvemu_mip_effective(const struct rvemu_hart *h)
{
    return (h->csr.mip & IRQ_S_MASK) | (h->irq_in & IRQ_M_MASK);
}

static int pick_irq(uint64_t set)
{
    for (unsigned k = 0; k < 6u; k++)
        if ((set >> IRQ_PRIORITY[k]) & 1u) return (int)IRQ_PRIORITY[k];
    return -1;
}

/* Interrupts destined for M are enabled below M, or in M when MIE is set; those
 * delegated to S are enabled below S, or in S when SIE is set, never in M. */
static int m_irq_enabled(const struct rvemu_hart *h)
{
    return h->priv != RVEMU_PRIV_M || (h->csr.mstatus & MSTATUS_MIE) != 0;
}

static int s_irq_enabled(const struct rvemu_hart *h)
{
    if (h->priv == RVEMU_PRIV_M) return 0;
    return h->priv == RVEMU_PRIV_U || (h->csr.mstatus & MSTATUS_SIE) != 0;
}

/* The interrupt to take now, or -1. Machine-destined ones come first. The SBI
 * profile has only the supervisor interrupts, all taken in S. */
static int irq_next(const struct rvemu_hart *h)
{
    uint64_t pend = rvemu_mip_effective(h) & h->csr.mie;
    if (pend == 0) return -1;
    if (h->profile == RVEMU_PROFILE_SBI) return s_irq_enabled(h) ? pick_irq(pend & IRQ_S_MASK) : -1;
    int c = m_irq_enabled(h) ? pick_irq(pend & ~h->csr.mideleg) : -1;
    if (c >= 0) return c;
    return s_irq_enabled(h) ? pick_irq(pend & h->csr.mideleg) : -1;
}

static uint64_t tvec_target(uint64_t tvec, uint64_t cause)
{
    uint64_t base = tvec & ~(uint64_t)3;
    if ((cause & CAUSE_IRQ) && (tvec & 3u) == 1u) base += 4u * (cause & 63u);
    return base;
}

static void enter_m(struct rvemu_hart *h, uint64_t cause, uint64_t tval)
{
    uint64_t m = h->csr.mstatus;
    h->csr.mepc = h->pc;
    h->csr.mcause = cause;
    h->csr.mtval = tval;
    m = (m & MSTATUS_MIE) ? (m | MSTATUS_MPIE) : (m & ~MSTATUS_MPIE);
    m &= ~(MSTATUS_MIE | MSTATUS_MPP);
    m |= (uint64_t)h->priv << MSTATUS_MPP_SHIFT;
    h->csr.mstatus = m;
    h->priv = RVEMU_PRIV_M;
    h->pc = tvec_target(h->csr.mtvec, cause);
}

static void enter_s(struct rvemu_hart *h, uint64_t cause, uint64_t tval)
{
    uint64_t m = h->csr.mstatus;
    h->csr.sepc = h->pc;
    h->csr.scause = cause;
    h->csr.stval = tval;
    m = (m & MSTATUS_SIE) ? (m | MSTATUS_SPIE) : (m & ~MSTATUS_SPIE);
    m &= ~(MSTATUS_SIE | MSTATUS_SPP);
    if (h->priv == RVEMU_PRIV_S) m |= MSTATUS_SPP;
    h->csr.mstatus = m;
    h->priv = RVEMU_PRIV_S;
    h->pc = tvec_target(h->csr.stvec, cause);
}

void rvemu_trap_take(struct rvemu_hart *h, uint64_t cause, uint64_t tval)
{
    uint64_t code = cause & ~CAUSE_IRQ;
    uint64_t deleg = (cause & CAUSE_IRQ) ? h->csr.mideleg : h->csr.medeleg;
    int to_s = h->priv != RVEMU_PRIV_M && code < 64u && ((deleg >> code) & 1u) != 0;
    if (h->profile == RVEMU_PROFILE_SBI) to_s = 1; /* no guest M-mode */
    if (to_s) enter_s(h, cause, tval);
    else enter_m(h, cause, tval);
}

static uint64_t sext12(uint32_t v12)
{
    uint64_t v = v12 & 0xfffu;
    return (v & 0x800u) ? (v | ~(uint64_t)0xfff) : v;
}

/* Effective address of the faulting load, store or AMO, recomputed from the
 * decoded instruction: the failed access wrote no register. */
static uint64_t access_addr(const struct rvemu_hart *h, uint32_t insn)
{
    uint64_t base = h->x[(insn >> 15) & 31u];
    unsigned opc = insn & 0x7fu;
    if (opc == OPC_STORE || opc == OPC_STORE_FP)
        return base + sext12(((insn >> 25) << 5) | ((insn >> 7) & 31u));
    if (opc == OPC_AMO) return base;
    return base + sext12(insn >> 20);
}

static int is_load_like(uint32_t insn)
{
    unsigned opc = insn & 0x7fu;
    if (opc == OPC_LOAD || opc == OPC_LOAD_FP) return 1;
    return opc == OPC_AMO && (insn >> 27) == AMO_F5_LR;
}

/* Cause and tval of a stop reason; the caller passes only reasons that trap. A
 * failed memory access recorded its own cause and virtual address in the hart
 * (rvemu_vm.c); the address is rebuilt from the instruction only for the
 * misaligned atomics. */
static uint64_t stop_cause(const struct rvemu_hart *h, enum rvemu_stop s,
                           const struct rvemu_ctx *ctx, uint64_t *tval)
{
    *tval = 0;
    switch (s) {
    case RVEMU_STOP_ECALL: return CAUSE_ECALL_BASE + h->priv;
    case RVEMU_STOP_EBREAK: *tval = h->pc; return CAUSE_BREAKPOINT;
    case RVEMU_STOP_ILLEGAL: *tval = ctx->raw; return CAUSE_ILLEGAL;
    default: break;
    }
    if (s == RVEMU_STOP_OUT_OF_RANGE && h->fault_set) {
        *tval = h->fault_tval;
        return h->fault_cause;
    }
    if (!ctx->executed) {
        *tval = h->pc;
        return s == RVEMU_STOP_MISALIGNED ? CAUSE_FETCH_MISALIGNED : CAUSE_FETCH_ACCESS;
    }
    *tval = access_addr(h, ctx->insn);
    if (s == RVEMU_STOP_MISALIGNED)
        return is_load_like(ctx->insn) ? CAUSE_LOAD_MISALIGNED : CAUSE_STORE_MISALIGNED;
    return is_load_like(ctx->insn) ? CAUSE_LOAD_ACCESS : CAUSE_STORE_ACCESS;
}

/* An S-mode ecall in the SBI profile is a call to the host firmware: the step
 * stops on it untouched, and rvemu_ecall_return resumes past it. */
static int is_host_call(const struct rvemu_hart *h)
{
    return h->profile == RVEMU_PROFILE_SBI && h->priv == RVEMU_PRIV_S;
}

enum rvemu_stop rvemu_step_machine(struct rvemu_hart *h, struct rvemu_mem *mem)
{
    int irq = irq_next(h);
    if (irq >= 0) {
        h->idle = 0;
        rvemu_trap_take(h, CAUSE_IRQ | (uint64_t)irq, 0);
        return RVEMU_STOP_NONE;
    }
    if (h->idle) {
        if ((rvemu_mip_effective(h) & h->csr.mie) == 0) return RVEMU_STOP_WFI;
        h->idle = 0;
    }
    struct rvemu_ctx ctx;
    enum rvemu_stop s = rvemu_step_core(h, mem, &ctx);
    if (s == RVEMU_STOP_NONE) return RVEMU_STOP_NONE;
    if (s == RVEMU_STOP_ECALL && is_host_call(h)) return RVEMU_STOP_ECALL;
    uint64_t tval = 0;
    uint64_t cause = stop_cause(h, s, &ctx, &tval);
    rvemu_count(h, 0);
    rvemu_trap_take(h, cause, tval);
    return RVEMU_STOP_NONE;
}
