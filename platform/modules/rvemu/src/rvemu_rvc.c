/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RV64C expansion. Each 16-bit compressed encoding is rewritten as
 * its 32-bit base-ISA equivalent, so the executor needs no compressed-only
 * paths. The decode is a table indexed by quadrant (bits 1:0) and funct3
 * (bits 15:13); a reserved encoding returns -1 and the caller reports
 * RVEMU_STOP_ILLEGAL. */
#include "rvemu_internal.h"

#define OPC_LOAD 0x03u
#define OPC_FLOAD 0x07u
#define OPC_OP_IMM 0x13u
#define OPC_OP_IMM32 0x1bu
#define OPC_STORE 0x23u
#define OPC_FSTORE 0x27u
#define OPC_OP 0x33u
#define OPC_OP32 0x3bu
#define OPC_LUI 0x37u
#define OPC_BRANCH 0x63u
#define OPC_JALR 0x67u
#define OPC_JAL 0x6fu
#define INSN_EBREAK 0x00100073u
#define REG_ZERO 0u
#define REG_RA 1u
#define REG_SP 2u

typedef int (*rvc_fn)(uint32_t c, uint32_t *out);

struct alu_op {
    uint32_t opc;
    uint32_t f3;
    uint32_t f7;
};

/* Reg-reg ALU of quadrant 1: row 0 is bit 12 clear (sub xor or and), row 1
 * is bit 12 set (subw addw). An opc of 0 marks a reserved form. */
static const struct alu_op RVC_REG_ALU[2][4] = {
    {{OPC_OP, 0, 0x20}, {OPC_OP, 4, 0}, {OPC_OP, 6, 0}, {OPC_OP, 7, 0}},
    {{OPC_OP32, 0, 0x20}, {OPC_OP32, 0, 0}, {0, 0, 0}, {0, 0, 0}},
};

/* Sign-extends the low bits of v, which holds a field of the given width. */
static uint32_t sext(uint32_t v, unsigned bits)
{
    uint32_t sign = 1u << (bits - 1u);
    return (v ^ sign) - sign;
}

static uint32_t enc_i(uint32_t opc, uint32_t f3, uint32_t rd, uint32_t rs1, uint32_t imm)
{
    return ((imm & 0xfffu) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opc;
}

static uint32_t enc_r(uint32_t opc, uint32_t f3, uint32_t f7, uint32_t rd, uint32_t rs1,
                      uint32_t rs2)
{
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opc;
}

static uint32_t enc_s(uint32_t opc, uint32_t f3, uint32_t rs1, uint32_t rs2, uint32_t imm)
{
    return (((imm >> 5) & 0x7fu) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) |
           ((imm & 0x1fu) << 7) | opc;
}

/* imm is a byte offset with bit 0 clear. */
static uint32_t enc_b(uint32_t f3, uint32_t rs1, uint32_t rs2, uint32_t imm)
{
    return (((imm >> 12) & 1u) << 31) | (((imm >> 5) & 0x3fu) << 25) | (rs2 << 20) |
           (rs1 << 15) | (f3 << 12) | (((imm >> 1) & 0xfu) << 8) |
           (((imm >> 11) & 1u) << 7) | OPC_BRANCH;
}

static uint32_t enc_j(uint32_t rd, uint32_t imm)
{
    return (((imm >> 20) & 1u) << 31) | (((imm >> 1) & 0x3ffu) << 21) |
           (((imm >> 11) & 1u) << 20) | (((imm >> 12) & 0xffu) << 12) | (rd << 7) | OPC_JAL;
}

static uint32_t enc_u(uint32_t opc, uint32_t rd, uint32_t imm)
{
    return (imm & 0xfffff000u) | (rd << 7) | opc;
}

/* Register fields. CL, CS and CA forms name registers x8..x15 in 3 bits. */
static uint32_t c_rd(uint32_t c) { return (c >> 7) & 31u; }
static uint32_t c_rs2(uint32_t c) { return (c >> 2) & 31u; }
static uint32_t c_rs1p(uint32_t c) { return 8u + ((c >> 7) & 7u); }
static uint32_t c_rdp(uint32_t c) { return 8u + ((c >> 2) & 7u); }

/* Six-bit immediate in bits 12 and 6:2: c.addi, c.li, c.andi, c.lui. */
static uint32_t c_imm6(uint32_t c) { return sext(((c >> 7) & 0x20u) | ((c >> 2) & 0x1fu), 6); }
static uint32_t c_shamt(uint32_t c) { return ((c >> 7) & 0x20u) | ((c >> 2) & 0x1fu); }

/* Scaled load and store offsets, one per access width and base register. */
static uint32_t c_off_w(uint32_t c) { return (((c >> 10) & 7u) << 3) | (((c >> 6) & 1u) << 2) | (((c >> 5) & 1u) << 6); }
static uint32_t c_off_d(uint32_t c) { return (((c >> 10) & 7u) << 3) | (((c >> 5) & 3u) << 6); }
static uint32_t c_off_lwsp(uint32_t c) { return (((c >> 12) & 1u) << 5) | (((c >> 4) & 7u) << 2) | (((c >> 2) & 3u) << 6); }
static uint32_t c_off_ldsp(uint32_t c) { return (((c >> 12) & 1u) << 5) | (((c >> 5) & 3u) << 3) | (((c >> 2) & 7u) << 6); }
static uint32_t c_off_swsp(uint32_t c) { return (((c >> 9) & 0xfu) << 2) | (((c >> 7) & 3u) << 6); }
static uint32_t c_off_sdsp(uint32_t c) { return (((c >> 10) & 7u) << 3) | (((c >> 7) & 7u) << 6); }

/* Jump and branch offsets, sign-extended from their own width. */
static uint32_t c_off_j(uint32_t c)
{
    uint32_t off = (((c >> 12) & 1u) << 11) | (((c >> 11) & 1u) << 4) |
                   (((c >> 9) & 3u) << 8) | (((c >> 8) & 1u) << 10) |
                   (((c >> 7) & 1u) << 6) | (((c >> 6) & 1u) << 7) |
                   (((c >> 3) & 7u) << 1) | (((c >> 2) & 1u) << 5);
    return sext(off, 12);
}

static uint32_t c_off_b(uint32_t c)
{
    uint32_t off = (((c >> 12) & 1u) << 8) | (((c >> 10) & 3u) << 3) |
                   (((c >> 5) & 3u) << 6) | (((c >> 3) & 3u) << 1) |
                   (((c >> 2) & 1u) << 5);
    return sext(off, 9);
}

static int rvc_reserved(uint32_t c, uint32_t *out)
{
    (void)c;
    (void)out;
    return -1;
}

/* Quadrant 0 */

static int q0_addi4spn(uint32_t c, uint32_t *out)
{
    uint32_t nz = (((c >> 11) & 3u) << 4) | (((c >> 7) & 0xfu) << 6) |
                  (((c >> 6) & 1u) << 2) | (((c >> 5) & 1u) << 3);
    if (nz == 0) return -1;
    *out = enc_i(OPC_OP_IMM, 0, c_rdp(c), REG_SP, nz);
    return 0;
}

static int q0_fld(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_FLOAD, 3, c_rdp(c), c_rs1p(c), c_off_d(c));
    return 0;
}

static int q0_lw(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_LOAD, 2, c_rdp(c), c_rs1p(c), c_off_w(c));
    return 0;
}

static int q0_ld(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_LOAD, 3, c_rdp(c), c_rs1p(c), c_off_d(c));
    return 0;
}

static int q0_fsd(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_FSTORE, 3, c_rs1p(c), c_rdp(c), c_off_d(c));
    return 0;
}

static int q0_sw(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_STORE, 2, c_rs1p(c), c_rdp(c), c_off_w(c));
    return 0;
}

static int q0_sd(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_STORE, 3, c_rs1p(c), c_rdp(c), c_off_d(c));
    return 0;
}

/* Quadrant 1 */

static int q1_addi(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 0, c_rd(c), c_rd(c), c_imm6(c));
    return 0;
}

static int q1_addiw(uint32_t c, uint32_t *out)
{
    if (c_rd(c) == REG_ZERO) return -1;
    *out = enc_i(OPC_OP_IMM32, 0, c_rd(c), c_rd(c), c_imm6(c));
    return 0;
}

static int q1_li(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 0, c_rd(c), REG_ZERO, c_imm6(c));
    return 0;
}

/* c.addi16sp: the scaled immediate is nzimm = sext(raw6) * 16, where raw6
 * holds nzimm[9:4] in the bit order the spec gives. */
static int q1_addi16sp(uint32_t c, uint32_t *out)
{
    uint32_t raw = (((c >> 12) & 1u) << 5) | (((c >> 3) & 3u) << 3) |
                   (((c >> 5) & 1u) << 2) | (((c >> 2) & 1u) << 1) | ((c >> 6) & 1u);
    uint32_t imm = sext(raw, 6) << 4;
    if (imm == 0) return -1;
    *out = enc_i(OPC_OP_IMM, 0, REG_SP, REG_SP, imm);
    return 0;
}

static int q1_lui(uint32_t c, uint32_t *out)
{
    uint32_t imm = c_imm6(c);
    if (imm == 0) return -1;
    *out = enc_u(OPC_LUI, c_rd(c), imm << 12);
    return 0;
}

static int q1_lui_or_sp(uint32_t c, uint32_t *out)
{
    return c_rd(c) == REG_SP ? q1_addi16sp(c, out) : q1_lui(c, out);
}

static int q1_srli(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 5, c_rs1p(c), c_rs1p(c), c_shamt(c));
    return 0;
}

static int q1_srai(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 5, c_rs1p(c), c_rs1p(c), 0x400u | c_shamt(c));
    return 0;
}

static int q1_andi(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 7, c_rs1p(c), c_rs1p(c), c_imm6(c));
    return 0;
}

static int q1_reg_alu(uint32_t c, uint32_t *out)
{
    const struct alu_op *op = &RVC_REG_ALU[(c >> 12) & 1u][(c >> 5) & 3u];
    if (op->opc == 0) return -1;
    *out = enc_r(op->opc, op->f3, op->f7, c_rs1p(c), c_rs1p(c), c_rdp(c));
    return 0;
}

static int q1_misc_alu(uint32_t c, uint32_t *out)
{
    switch ((c >> 10) & 3u) {
    case 0: return q1_srli(c, out);
    case 1: return q1_srai(c, out);
    case 2: return q1_andi(c, out);
    default: return q1_reg_alu(c, out);
    }
}

static int q1_j(uint32_t c, uint32_t *out)
{
    *out = enc_j(REG_ZERO, c_off_j(c));
    return 0;
}

static int q1_beqz(uint32_t c, uint32_t *out)
{
    *out = enc_b(0, c_rs1p(c), REG_ZERO, c_off_b(c));
    return 0;
}

static int q1_bnez(uint32_t c, uint32_t *out)
{
    *out = enc_b(1, c_rs1p(c), REG_ZERO, c_off_b(c));
    return 0;
}

/* Quadrant 2 */

static int q2_slli(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_OP_IMM, 1, c_rd(c), c_rd(c), c_shamt(c));
    return 0;
}

static int q2_fldsp(uint32_t c, uint32_t *out)
{
    *out = enc_i(OPC_FLOAD, 3, c_rd(c), REG_SP, c_off_ldsp(c));
    return 0;
}

static int q2_lwsp(uint32_t c, uint32_t *out)
{
    if (c_rd(c) == REG_ZERO) return -1;
    *out = enc_i(OPC_LOAD, 2, c_rd(c), REG_SP, c_off_lwsp(c));
    return 0;
}

static int q2_ldsp(uint32_t c, uint32_t *out)
{
    if (c_rd(c) == REG_ZERO) return -1;
    *out = enc_i(OPC_LOAD, 3, c_rd(c), REG_SP, c_off_ldsp(c));
    return 0;
}

/* c.jr and c.mv, bit 12 clear. */
static int q2_jr_mv(uint32_t c, uint32_t *out)
{
    if (c_rs2(c) != REG_ZERO) {
        *out = enc_r(OPC_OP, 0, 0, c_rd(c), REG_ZERO, c_rs2(c));
        return 0;
    }
    if (c_rd(c) == REG_ZERO) return -1;
    *out = enc_i(OPC_JALR, 0, REG_ZERO, c_rd(c), 0);
    return 0;
}

/* c.ebreak, c.jalr and c.add, bit 12 set. */
static int q2_jalr_add(uint32_t c, uint32_t *out)
{
    if (c_rs2(c) != REG_ZERO) {
        *out = enc_r(OPC_OP, 0, 0, c_rd(c), c_rd(c), c_rs2(c));
        return 0;
    }
    if (c_rd(c) == REG_ZERO) {
        *out = INSN_EBREAK;
        return 0;
    }
    *out = enc_i(OPC_JALR, 0, REG_RA, c_rd(c), 0);
    return 0;
}

static int q2_cr(uint32_t c, uint32_t *out)
{
    return ((c >> 12) & 1u) != 0 ? q2_jalr_add(c, out) : q2_jr_mv(c, out);
}

static int q2_fsdsp(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_FSTORE, 3, REG_SP, c_rs2(c), c_off_sdsp(c));
    return 0;
}

static int q2_swsp(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_STORE, 2, REG_SP, c_rs2(c), c_off_swsp(c));
    return 0;
}

static int q2_sdsp(uint32_t c, uint32_t *out)
{
    *out = enc_s(OPC_STORE, 3, REG_SP, c_rs2(c), c_off_sdsp(c));
    return 0;
}

/* Indexed by quadrant, then funct3. Quadrant 3 is 32-bit and never gets here. */
static const rvc_fn RVC_TABLE[3][8] = {
    {q0_addi4spn, q0_fld, q0_lw, q0_ld, rvc_reserved, q0_fsd, q0_sw, q0_sd},
    {q1_addi, q1_addiw, q1_li, q1_lui_or_sp, q1_misc_alu, q1_j, q1_beqz, q1_bnez},
    {q2_slli, q2_fldsp, q2_lwsp, q2_ldsp, q2_cr, q2_fsdsp, q2_swsp, q2_sdsp},
};

int rvemu_rvc_expand(uint16_t c, uint32_t *out)
{
    uint32_t quadrant = c & 3u, f3 = (c >> 13) & 7u;
    if (quadrant == 3u) return -1;
    return RVC_TABLE[quadrant][f3]((uint32_t)c, out);
}
