/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: instruction decode and execution for RV64IM, Zbb and Zicsr. Each
 * opcode family has its own small executor; rvemu_step retires one
 * instruction and writes pc only after the executor succeeded. */
#include "rvemu_internal.h"
#include <string.h>

#define OP_LOAD 0x03u
#define OP_MISC_MEM 0x0fu
#define OP_IMM 0x13u
#define OP_AUIPC 0x17u
#define OP_IMM32 0x1bu
#define OP_STORE 0x23u
#define OP_REG 0x33u
#define OP_LUI 0x37u
#define OP_REG32 0x3bu
#define OP_BRANCH 0x63u
#define OP_JALR 0x67u
#define OP_JAL 0x6fu
#define OP_SYSTEM 0x73u
#define OP_AMO 0x2fu

#define INSN_ECALL 0x00000073u
#define INSN_EBREAK 0x00100073u
#define INSN_MRET 0x30200073u

#define F3_LOAD_MAX 6u
#define F3_STORE_MAX 3u
#define F6_SRAI 0x10u
#define F7_SRA 0x20u

struct load_shape {
    unsigned bytes;
    int is_signed;
};

static const struct load_shape LOAD_SHAPE[F3_LOAD_MAX + 1u] = {
    {1, 1}, {2, 1}, {4, 1}, {8, 1}, {1, 0}, {2, 0}, {4, 0},
};

static unsigned rd_of(uint32_t i) { return (i >> 7) & 31u; }
static unsigned f3_of(uint32_t i) { return (i >> 12) & 7u; }
static unsigned rs1_of(uint32_t i) { return (i >> 15) & 31u; }
static unsigned rs2_of(uint32_t i) { return (i >> 20) & 31u; }
static unsigned f7_of(uint32_t i) { return (i >> 25) & 0x7fu; }

/* Immediates are sign-extended from the instruction's own bit layout. */
static int64_t signed_word(uint32_t i) { return (int64_t)(int32_t)i; }
static int64_t imm_i(uint32_t i) { return signed_word(i) >> 20; }
static int64_t imm_s(uint32_t i)
{
    return (signed_word(i) >> 25) * 32 + (int64_t)((i >> 7) & 31u);
}
static int64_t imm_b(uint32_t i)
{
    return (signed_word(i) >> 31) * 4096 + (int64_t)((i >> 7) & 1u) * 2048 +
           (int64_t)((i >> 25) & 63u) * 32 + (int64_t)((i >> 8) & 15u) * 2;
}
static int64_t imm_u(uint32_t i) { return (int64_t)(int32_t)(i & 0xfffff000u); }
static int64_t imm_j(uint32_t i)
{
    return (signed_word(i) >> 31) * 1048576 + (int64_t)((i >> 12) & 255u) * 4096 +
           (int64_t)((i >> 20) & 1u) * 2048 + (int64_t)((i >> 21) & 1023u) * 2;
}

static void set_rd(struct rvemu_hart *h, uint32_t i, uint64_t v)
{
    unsigned rd = rd_of(i);
    if (rd != 0) h->x[rd] = v;
}

static enum rvemu_stop exec_lui(struct rvemu_hart *h, uint32_t i)
{
    set_rd(h, i, (uint64_t)imm_u(i));
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_auipc(struct rvemu_hart *h, uint32_t i)
{
    set_rd(h, i, h->pc + (uint64_t)imm_u(i));
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_jal(struct rvemu_hart *h, uint32_t i, unsigned len, uint64_t *next)
{
    set_rd(h, i, h->pc + len);
    *next = h->pc + (uint64_t)imm_j(i);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_jalr(struct rvemu_hart *h, uint32_t i, unsigned len, uint64_t *next)
{
    if (f3_of(i) != 0) return RVEMU_STOP_ILLEGAL;
    uint64_t target = (h->x[rs1_of(i)] + (uint64_t)imm_i(i)) & ~(uint64_t)1;
    set_rd(h, i, h->pc + len);
    *next = target;
    return RVEMU_STOP_NONE;
}

static int branch_taken(unsigned f3, uint64_t a, uint64_t b, int *taken)
{
    switch (f3) {
    case 0: *taken = a == b; return 0;
    case 1: *taken = a != b; return 0;
    case 4: *taken = (int64_t)a < (int64_t)b; return 0;
    case 5: *taken = (int64_t)a >= (int64_t)b; return 0;
    case 6: *taken = a < b; return 0;
    case 7: *taken = a >= b; return 0;
    default: return -1;
    }
}

static enum rvemu_stop exec_branch(struct rvemu_hart *h, uint32_t i, uint64_t *next)
{
    int taken = 0;
    if (branch_taken(f3_of(i), h->x[rs1_of(i)], h->x[rs2_of(i)], &taken) != 0)
        return RVEMU_STOP_ILLEGAL;
    if (taken) *next = h->pc + (uint64_t)imm_b(i);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_load(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    unsigned f3 = f3_of(i);
    if (f3 > F3_LOAD_MAX) return RVEMU_STOP_ILLEGAL;
    struct load_shape s = LOAD_SHAPE[f3];
    uint64_t v = 0;
    enum rvemu_stop stop = rvemu_vm_load(h, m, h->x[rs1_of(i)] + (uint64_t)imm_i(i), s.bytes, &v);
    if (stop != RVEMU_STOP_NONE) return stop;
    if (s.is_signed) {
        unsigned shift = 64u - 8u * s.bytes;
        v = (uint64_t)((int64_t)(v << shift) >> shift);
    }
    set_rd(h, i, v);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_store(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    unsigned f3 = f3_of(i);
    if (f3 > F3_STORE_MAX) return RVEMU_STOP_ILLEGAL;
    uint64_t addr = h->x[rs1_of(i)] + (uint64_t)imm_s(i);
    return rvemu_vm_store(h, m, addr, 1u << f3, h->x[rs2_of(i)]);
}

/* OP-IMM: shifts carry a 6-bit funct6 (bits 31:26) that selects srl or sra
 * and must otherwise be zero; the other forms reuse the register ALU. */
static int op_imm_shift(uint32_t i, unsigned f3, unsigned *f7)
{
    unsigned f6 = i >> 26;
    if (f3 == 1u) return f6 == 0 ? 0 : -1;
    if (f6 == 0) { *f7 = 0; return 0; }
    if (f6 == F6_SRAI) { *f7 = F7_SRA; return 0; }
    return -1;
}

static enum rvemu_stop exec_op_imm(struct rvemu_hart *h, uint32_t i)
{
    unsigned f3 = f3_of(i), f7 = 0;
    uint64_t a = h->x[rs1_of(i)], v = 0;
    int rc;
    if (f3 == 1u || f3 == 5u) {
        unsigned f6=i >> 26;
        if ((f6==0x18u || f6==0x1au || f6==0x0au) &&
            rvemu_zbb_imm(i >> 20,f3,0,a,&v)==0) {
            set_rd(h,i,v);
            return RVEMU_STOP_NONE;
        }
        if (op_imm_shift(i, f3, &f7) != 0) return RVEMU_STOP_ILLEGAL;
        rc = rvemu_alu(f3, f7, 0, a, (i >> 20) & 63u, &v);
    } else {
        rc = rvemu_alu(f3, 0, 0, a, (uint64_t)imm_i(i), &v);
    }
    if (rc != 0) return RVEMU_STOP_ILLEGAL;
    set_rd(h, i, v);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_op_imm32(struct rvemu_hart *h, uint32_t i)
{
    unsigned f3 = f3_of(i), f7 = f7_of(i);
    uint64_t a = h->x[rs1_of(i)], v = 0;
    int rc;
    if (f7==0x30u && rvemu_zbb_imm(i >> 20, f3, 1, a, &v) == 0) {
        set_rd(h, i, v);
        return RVEMU_STOP_NONE;
    }
    if (f3 == 0u) {
        rc = rvemu_alu(0, 0, 1, a, (uint64_t)imm_i(i), &v);
    } else if ((f3 == 1u && f7 == 0u) || (f3 == 5u && (f7 == 0u || f7 == F7_SRA))) {
        rc = rvemu_alu(f3, f7, 1, a, (i >> 20) & 31u, &v);
    } else {
        rc = -1;
    }
    if (rc != 0) return RVEMU_STOP_ILLEGAL;
    set_rd(h, i, v);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop exec_op(struct rvemu_hart *h, uint32_t i, int word)
{
    uint64_t v = 0;
    /* RV64 zext.h fixes the encoded rs2 to x0, not merely its value. */
    if (word && f7_of(i) == 0x04u && f3_of(i) == 4u && rs2_of(i) != 0u)
        return RVEMU_STOP_ILLEGAL;
    if (rvemu_alu(f3_of(i), f7_of(i), word, h->x[rs1_of(i)], h->x[rs2_of(i)], &v) != 0)
        return RVEMU_STOP_ILLEGAL;
    set_rd(h, i, v);
    return RVEMU_STOP_NONE;
}

static uint64_t csr_new_value(unsigned op, uint64_t old, uint64_t src)
{
    if (op == 1u) return src;
    return op == 2u ? (old | src) : (old & ~src);
}

/* Zicsr: the old value goes to rd. csrrw and csrrwi always write; csrrs and
 * csrrc write only when the source (rs1 or uimm) is non-zero. */
static enum rvemu_stop exec_csr(struct rvemu_hart *h, uint32_t i)
{
    unsigned f3 = f3_of(i), op = f3 & 3u, addr = i >> 20;
    uint64_t src = (f3 & 4u) ? (uint64_t)rs1_of(i) : h->x[rs1_of(i)];
    uint64_t old = 0;
    if (rvemu_csr_read(h, addr, &old) != 0) return RVEMU_STOP_ILLEGAL;
    if ((op == 1u || rs1_of(i) != 0) &&
        rvemu_csr_write(h, addr, csr_new_value(op, old, src)) != 0)
        return RVEMU_STOP_ILLEGAL;
    set_rd(h, i, old);
    return RVEMU_STOP_NONE;
}

/* MISC-MEM: fence is a no-op. fence.i drops the decoded-instruction cache.
 * A store over a cached parcel drops that line on its own, so a guest that
 * writes instruction bytes and then fence.i cannot execute the old bits. */
static enum rvemu_stop exec_misc_mem(struct rvemu_hart *h, uint32_t i)
{
    unsigned f3 = f3_of(i);
    if (f3 == 1u) rvemu_icache_flush(h);
    if (f3 == 0u || f3 == 1u) return RVEMU_STOP_NONE;
    return RVEMU_STOP_ILLEGAL;
}

static enum rvemu_stop exec_system(struct rvemu_hart *h, uint32_t i, uint64_t *next)
{
    if (i == INSN_ECALL) return RVEMU_STOP_ECALL;
    if (i == INSN_EBREAK) return RVEMU_STOP_EBREAK;
    if (h->profile != RVEMU_PROFILE_STOP) {
        enum rvemu_stop s = RVEMU_STOP_NONE;
        if (rvemu_priv_exec(h, i, next, &s)) return s;
    } else if (i == INSN_MRET) {
        *next = h->csr.mepc;
        return RVEMU_STOP_NONE;
    }
    unsigned f3 = f3_of(i);
    if (f3 == 0u || f3 == 4u) return RVEMU_STOP_ILLEGAL;
    return exec_csr(h, i);
}

static enum rvemu_stop exec_insn(struct rvemu_hart *h, struct rvemu_mem *m,
                                 uint32_t i, unsigned len, uint64_t *next)
{
    switch (i & 0x7fu) {
    case OP_LUI: return exec_lui(h, i);
    case OP_AUIPC: return exec_auipc(h, i);
    case OP_JAL: return exec_jal(h, i, len, next);
    case OP_JALR: return exec_jalr(h, i, len, next);
    case OP_BRANCH: return exec_branch(h, i, next);
    case OP_LOAD: return exec_load(h, m, i);
    case OP_STORE: return exec_store(h, m, i);
    case OP_IMM: return exec_op_imm(h, i);
    case OP_IMM32: return exec_op_imm32(h, i);
    case OP_REG: return exec_op(h, i, 0);
    case OP_REG32: return exec_op(h, i, 1);
    case OP_MISC_MEM: return exec_misc_mem(h, i);
    case OP_SYSTEM: return exec_system(h, i, next);
    case OP_AMO: return rvemu_exec_amo(h, m, i);
    default: return rvemu_fpu_exec(h, m, i); /* F and D opcodes, else ILLEGAL */
    }
}

void rvemu_hart_init(struct rvemu_hart *hart, uint64_t entry_pc)
{
    memset(hart, 0, sizeof(*hart));
    hart->pc = entry_pc;
    hart->mem_epoch = 1;
    hart->priv = RVEMU_PRIV_M;
    hart->profile = RVEMU_PROFILE_STOP;
    hart->csr.mstatus = MSTATUS_XL_FIXED;
    rvemu_fpu_reset(hart);
}

void rvemu_hart_init_machine(struct rvemu_hart *hart, uint64_t entry_pc)
{
    rvemu_hart_init(hart, entry_pc);
    hart->profile = RVEMU_PROFILE_MACHINE;
}

/* SBI profile: S-mode entry, the supervisor interrupts delegated (which is
 * what sie and sip mask by) and every counter readable below M. */
void rvemu_hart_init_sbi(struct rvemu_hart *hart, uint64_t entry_pc)
{
    rvemu_hart_init(hart, entry_pc);
    hart->profile = RVEMU_PROFILE_SBI;
    hart->priv = RVEMU_PRIV_S;
    hart->csr.mideleg = IRQ_S_MASK;
    hart->csr.mcounteren = 0xffffffffull;
}

/* Fetches the instruction at pc. A halfword whose low two bits are not 0b11
 * is compressed: it is expanded to its 32-bit equivalent and len is 2.
 * Otherwise the full word is fetched and len is 4. ctx->raw gets the bits as
 * fetched, also when a compressed halfword turns out to be reserved. */
static enum rvemu_stop fetch_insn(struct rvemu_hart *h, struct rvemu_mem *mem,
                                  struct rvemu_ctx *ctx, unsigned *len)
{
    uint32_t raw = 0;
    enum rvemu_stop s = rvemu_vm_fetch(h, mem, h->pc, &raw);
    if (s != RVEMU_STOP_NONE) return s;
    ctx->raw = raw;
    if ((raw & 3u) != 3u) {
        *len = 2u;
        return rvemu_rvc_expand((uint16_t)raw, &ctx->insn) == 0 ? RVEMU_STOP_NONE
                                                                : RVEMU_STOP_ILLEGAL;
    }
    ctx->insn = raw;
    *len = 4u;
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_step_core(struct rvemu_hart *hart, struct rvemu_mem *mem,
                                struct rvemu_ctx *ctx)
{
    ctx->insn = 0;
    ctx->raw = 0;
    ctx->executed = 0;
    hart->fault_set = 0;
    if ((hart->pc & 1u) != 0) return RVEMU_STOP_MISALIGNED;
    unsigned len = 0;
    enum rvemu_stop s = fetch_insn(hart, mem, ctx, &len);
    if (s != RVEMU_STOP_NONE) return s;
    ctx->executed = 1;
    uint64_t next = hart->pc + len;
    s = exec_insn(hart, mem, ctx->insn, len, &next);
    if (s != RVEMU_STOP_NONE) return s;
    hart->pc = next;
    rvemu_count(hart, 1);
    return RVEMU_STOP_NONE;
}

enum rvemu_stop rvemu_step(struct rvemu_hart *hart, struct rvemu_mem *mem)
{
    if (!hart || !mem || !mem->bytes) return RVEMU_STOP_OUT_OF_RANGE;
    if (hart->profile != RVEMU_PROFILE_STOP) return rvemu_step_machine(hart, mem);
    struct rvemu_ctx ctx;
    return rvemu_step_core(hart, mem, &ctx);
}

int rvemu_run(struct rvemu_hart *hart, struct rvemu_mem *mem, uint64_t max_steps,
              enum rvemu_stop *stop)
{
    if (!stop) return -1;
    *stop = RVEMU_STOP_STEP_LIMIT;
    if (!hart || !mem) return -1;
    for (uint64_t n = 0; n < max_steps; n++) {
        enum rvemu_stop s = rvemu_step(hart, mem);
        if (s != RVEMU_STOP_NONE) {
            *stop = s;
            return 0;
        }
    }
    return 0;
}
