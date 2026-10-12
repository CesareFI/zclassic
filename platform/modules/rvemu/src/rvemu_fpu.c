/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: F and D instruction execution, the fcsr/frm/fflags CSRs and the
 * mstatus.FS gate. The arithmetic itself is the integer-only soft float in
 * rvemu_softfp.c, so results and exception flags are identical on any host.
 * Singles live NaN-boxed in the 64-bit registers; an improperly boxed single
 * reads as the canonical NaN. */
#include "rvemu_internal.h"
#include "rvemu_softfp.h"

#define OP_LOAD_FP 0x07u
#define OP_STORE_FP 0x27u
#define OP_FMADD 0x43u
#define OP_FMSUB 0x47u
#define OP_FNMSUB 0x4bu
#define OP_FNMADD 0x4fu
#define OP_FP 0x53u

#define CSR_FFLAGS 0x001u
#define CSR_FRM 0x002u
#define CSR_FCSR 0x003u
#define FCSR_FLAGS 0x1fu
#define FCSR_FRM_SHIFT 5u
#define FS_SHIFT 13u
#define FS_MASK (3ull << FS_SHIFT)
#define RM_DYNAMIC 7u
#define BOX_HI 0xffffffff00000000ull
#define ONE_S 0x3f800000ull
#define ONE_D 0x3ff0000000000000ull

static unsigned rd_of(uint32_t i) { return (i >> 7) & 31u; }
static unsigned f3_of(uint32_t i) { return (i >> 12) & 7u; }
static unsigned rs1_of(uint32_t i) { return (i >> 15) & 31u; }
static unsigned rs2_of(uint32_t i) { return (i >> 20) & 31u; }
static unsigned rs3_of(uint32_t i) { return i >> 27; }
static unsigned fmt_of(uint32_t i) { return (i >> 25) & 3u; }
static int64_t imm_i(uint32_t i) { return (int64_t)(int32_t)i >> 20; }
static int64_t imm_s(uint32_t i)
{
    return ((int64_t)(int32_t)i >> 25) * 32 + (int64_t)((i >> 7) & 31u);
}

static int fs_off(const struct rvemu_hart *h) { return (h->csr.mstatus & FS_MASK) == 0; }

static void mark_dirty(struct rvemu_hart *h) { h->csr.mstatus |= FS_MASK | MSTATUS_SD; }

void rvemu_fpu_reset(struct rvemu_hart *h)
{
    for (unsigned r = 0; r < 32u; r++) h->f[r] = 0;
    h->fcsr = 0;
}

/* ---- fcsr, frm and fflags. ---- */

int rvemu_fpu_csr_read(struct rvemu_hart *h, unsigned addr, uint64_t *out)
{
    if (addr != CSR_FFLAGS && addr != CSR_FRM && addr != CSR_FCSR) return 1;
    if (fs_off(h)) return -1;
    if (addr == CSR_FFLAGS) *out = h->fcsr & FCSR_FLAGS;
    else if (addr == CSR_FRM) *out = (h->fcsr >> FCSR_FRM_SHIFT) & 7u;
    else *out = h->fcsr & 0xffu;
    return 0;
}

int rvemu_fpu_csr_write(struct rvemu_hart *h, unsigned addr, uint64_t val)
{
    if (addr != CSR_FFLAGS && addr != CSR_FRM && addr != CSR_FCSR) return 1;
    if (fs_off(h)) return -1;
    uint32_t v = (uint32_t)val;
    if (addr == CSR_FFLAGS) h->fcsr = (h->fcsr & ~FCSR_FLAGS) | (v & FCSR_FLAGS);
    else if (addr == CSR_FRM) h->fcsr = (h->fcsr & FCSR_FLAGS) | ((v & 7u) << FCSR_FRM_SHIFT);
    else h->fcsr = v & 0xffu;
    mark_dirty(h);
    return 0;
}

/* ---- register access. ---- */

static uint64_t fget(const struct rvemu_hart *h, unsigned r, int dbl)
{
    uint64_t v = h->f[r];
    if (dbl) return v;
    return (v >> 32) == 0xffffffffull ? (v & 0xffffffffull) : sfp_canon_nan(sfp_fmt(0));
}

static void fput(struct rvemu_hart *h, unsigned r, int dbl, uint64_t bits)
{
    h->f[r] = dbl ? bits : (BOX_HI | (bits & 0xffffffffull));
}

static void commit(struct rvemu_hart *h, unsigned flags)
{
    h->fcsr |= flags & FCSR_FLAGS;
    mark_dirty(h);
}

/* Resolve the instruction rm field (7 = dynamic frm). -1 when reserved. */
static int resolve_rm(const struct rvemu_hart *h, unsigned f3, unsigned *rm)
{
    *rm = f3 == RM_DYNAMIC ? (h->fcsr >> FCSR_FRM_SHIFT) & 7u : f3;
    return *rm <= SFP_RMM ? 0 : -1;
}

/* ---- loads, stores. ---- */

static enum rvemu_stop fp_load(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    unsigned f3 = f3_of(i);
    uint64_t v = 0;
    if (f3 != 2u && f3 != 3u) return RVEMU_STOP_ILLEGAL;
    enum rvemu_stop s = rvemu_vm_load(h, m, h->x[rs1_of(i)] + (uint64_t)imm_i(i), 1u << f3, &v);
    if (s != RVEMU_STOP_NONE) return s;
    fput(h, rd_of(i), f3 == 3u, v);
    mark_dirty(h);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_store(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    unsigned f3 = f3_of(i);
    if (f3 != 2u && f3 != 3u) return RVEMU_STOP_ILLEGAL;
    uint64_t addr = h->x[rs1_of(i)] + (uint64_t)imm_s(i);
    return rvemu_vm_store(h, m, addr, 1u << f3, h->f[rs2_of(i)]);
}

/* ---- fused multiply-add family (R4 type). ---- */

static enum rvemu_stop fp_fma(struct rvemu_hart *h, uint32_t i)
{
    unsigned rm = 0, fl = 0, op = i & 0x7fu, mode = 0;
    int dbl = (int)fmt_of(i);
    if (fmt_of(i) > 1u || resolve_rm(h, f3_of(i), &rm) != 0) return RVEMU_STOP_ILLEGAL;
    if (op == OP_FMSUB || op == OP_FNMADD) mode |= SFP_NEG_ADD;
    if (op == OP_FNMSUB || op == OP_FNMADD) mode |= SFP_NEG_PROD;
    uint64_t r = sfp_fma(sfp_fmt(dbl), fget(h, rs1_of(i), dbl), fget(h, rs2_of(i), dbl),
                         fget(h, rs3_of(i), dbl), mode, rm, &fl);
    fput(h, rd_of(i), dbl, r);
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

/* ---- OP-FP: add, sub, mul, div, sqrt. ---- */

static enum rvemu_stop fp_arith(struct rvemu_hart *h, uint32_t i, unsigned op, int dbl)
{
    unsigned rm = 0, fl = 0;
    const struct sfp_fmt *f = sfp_fmt(dbl);
    uint64_t a = fget(h, rs1_of(i), dbl), b = fget(h, rs2_of(i), dbl), r;
    if (resolve_rm(h, f3_of(i), &rm) != 0) return RVEMU_STOP_ILLEGAL;
    if (op == 0) r = sfp_fma(f, a, dbl ? ONE_D : ONE_S, b, 0, rm, &fl);
    else if (op == 1) r = sfp_fma(f, a, dbl ? ONE_D : ONE_S, b, SFP_NEG_ADD, rm, &fl);
    else if (op == 2) r = sfp_fma(f, a, b, 0, SFP_NO_ADD, rm, &fl);
    else if (op == 3) r = sfp_div(f, a, b, rm, &fl);
    else if (rs2_of(i) != 0) return RVEMU_STOP_ILLEGAL;
    else r = sfp_sqrt(f, a, rm, &fl);
    fput(h, rd_of(i), dbl, r);
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

/* ---- sign injection, min/max, compare, class. ---- */

static uint64_t sign_bit(int dbl) { return dbl ? 1ull << 63 : 1ull << 31; }

static enum rvemu_stop fp_sgnj(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned f3 = f3_of(i);
    uint64_t a = fget(h, rs1_of(i), dbl), b = fget(h, rs2_of(i), dbl), s = sign_bit(dbl), bit;
    if (f3 > 2u) return RVEMU_STOP_ILLEGAL;
    if (f3 == 0) bit = b & s;
    else if (f3 == 1u) bit = ~b & s;
    else bit = (a ^ b) & s;
    fput(h, rd_of(i), dbl, (a & ~s) | bit);
    mark_dirty(h);
    return RVEMU_STOP_NONE;
}

/* Total order on non-NaN bit patterns with -0 < +0. */
static int lt_total(uint64_t a, uint64_t b, int dbl)
{
    uint64_t s = sign_bit(dbl), ma = a & ~s, mb = b & ~s;
    int na = (a & s) != 0, nb = (b & s) != 0;
    if (na != nb) return na;
    return na ? ma > mb : ma < mb;
}

static int is_nan_bits(const struct sfp_fmt *f, uint64_t bits)
{
    return sfp_unpack(f, bits).cls == SFP_NAN;
}

static int is_snan_bits(const struct sfp_fmt *f, uint64_t bits)
{
    return (int)sfp_unpack(f, bits).snan;
}

/* Numeric less-than: -0 and +0 compare equal. */
static int lt_num(uint64_t a, uint64_t b, int dbl)
{
    uint64_t s = sign_bit(dbl);
    if (((a | b) & ~s) == 0) return 0;
    return lt_total(a, b, dbl);
}

static uint64_t rvemu_fpu_minmax(int dbl, uint64_t a, uint64_t b, int is_max, unsigned *fl)
{
    const struct sfp_fmt *f = sfp_fmt(dbl);
    int an = is_nan_bits(f, a), bn = is_nan_bits(f, b);
    if (is_snan_bits(f, a) || is_snan_bits(f, b)) *fl |= SFP_NV;
    if (an && bn) return sfp_canon_nan(f);
    if (an) return b;
    if (bn) return a;
    int a_less = lt_total(a, b, dbl);
    return (a_less != is_max) ? a : b;
}

static enum rvemu_stop fp_minmax(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned f3 = f3_of(i), fl = 0;
    if (f3 > 1u) return RVEMU_STOP_ILLEGAL;
    uint64_t r = rvemu_fpu_minmax(dbl, fget(h, rs1_of(i), dbl), fget(h, rs2_of(i), dbl),
                                  (int)f3, &fl);
    fput(h, rd_of(i), dbl, r);
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_cmp(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned f3 = f3_of(i), fl = 0;
    const struct sfp_fmt *f = sfp_fmt(dbl);
    uint64_t a = fget(h, rs1_of(i), dbl), b = fget(h, rs2_of(i), dbl), s = sign_bit(dbl);
    int any_nan = is_nan_bits(f, a) || is_nan_bits(f, b), r = 0;
    if (f3 > 2u) return RVEMU_STOP_ILLEGAL;
    if (f3 == 2u) {
        if (is_snan_bits(f, a) || is_snan_bits(f, b)) fl |= SFP_NV;
        r = !any_nan && (a == b || ((a | b) & ~s) == 0);
    } else {
        if (any_nan) fl |= SFP_NV;
        r = !any_nan && (f3 == 1u ? lt_num(a, b, dbl)
                                  : (lt_num(a, b, dbl) || a == b || ((a | b) & ~s) == 0));
    }
    if (rd_of(i) != 0) h->x[rd_of(i)] = (uint64_t)r;
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

static uint64_t rvemu_fpu_class(int dbl, uint64_t bits)
{
    struct sfp_val v = sfp_unpack(sfp_fmt(dbl), bits);
    const struct sfp_fmt *f = sfp_fmt(dbl);
    int sub = ((bits >> f->fb) & ((1ull << f->eb) - 1u)) == 0;
    switch (v.cls) {
    case SFP_INF: return v.sign ? 1u : 1u << 7;
    case SFP_NAN: return v.snan ? 1u << 8 : 1u << 9;
    case SFP_ZERO: return v.sign ? 1u << 3 : 1u << 4;
    default:
        if (sub) return v.sign ? 1u << 2 : 1u << 5;
        return v.sign ? 1u << 1 : 1u << 6;
    }
}

/* ---- conversions and moves. ---- */

static void set_x(struct rvemu_hart *h, uint32_t i, uint64_t v)
{
    if (rd_of(i) != 0) h->x[rd_of(i)] = v;
}

static enum rvemu_stop fp_cvt_ff(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned rm = 0, fl = 0;
    int src_dbl = rs2_of(i) == 1u;
    if (rs2_of(i) > 1u || src_dbl == dbl) return RVEMU_STOP_ILLEGAL;
    if (resolve_rm(h, f3_of(i), &rm) != 0) return RVEMU_STOP_ILLEGAL;
    uint64_t r = sfp_f2f(sfp_fmt(src_dbl), sfp_fmt(dbl), fget(h, rs1_of(i), src_dbl), rm, &fl);
    fput(h, rd_of(i), dbl, r);
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_cvt_fi(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned rm = 0, fl = 0, k = rs2_of(i);
    if (k > 3u || resolve_rm(h, f3_of(i), &rm) != 0) return RVEMU_STOP_ILLEGAL;
    set_x(h, i, sfp_f2i(sfp_fmt(dbl), fget(h, rs1_of(i), dbl), rm, (enum sfp_ikind)k, &fl));
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_cvt_if(struct rvemu_hart *h, uint32_t i, int dbl)
{
    unsigned rm = 0, fl = 0, k = rs2_of(i);
    if (k > 3u) return RVEMU_STOP_ILLEGAL;
    if (resolve_rm(h, f3_of(i), &rm) != 0) return RVEMU_STOP_ILLEGAL;
    uint64_t r = sfp_i2f(sfp_fmt(dbl), h->x[rs1_of(i)], (enum sfp_ikind)k, rm, &fl);
    fput(h, rd_of(i), dbl, r);
    commit(h, fl);
    return RVEMU_STOP_NONE;
}

/* fmv.x.w / fmv.x.d (f3 = 0) move raw bits; fclass (f3 = 1) classifies. */
static enum rvemu_stop fp_move_x(struct rvemu_hart *h, uint32_t i, int dbl)
{
    if (rs2_of(i) != 0 || f3_of(i) > 1u) return RVEMU_STOP_ILLEGAL;
    if (f3_of(i) == 1u) {
        set_x(h, i, rvemu_fpu_class(dbl, fget(h, rs1_of(i), dbl)));
    } else {
        uint64_t raw = h->f[rs1_of(i)];
        set_x(h, i, dbl ? raw : (uint64_t)(int64_t)(int32_t)(uint32_t)raw);
    }
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_move_f(struct rvemu_hart *h, uint32_t i, int dbl)
{
    if (rs2_of(i) != 0 || f3_of(i) != 0) return RVEMU_STOP_ILLEGAL;
    fput(h, rd_of(i), dbl, h->x[rs1_of(i)]);
    mark_dirty(h);
    return RVEMU_STOP_NONE;
}

static enum rvemu_stop fp_op_conv(struct rvemu_hart *h, uint32_t i, int dbl)
{
    switch (i >> 27) {
    case 0x08: return fp_cvt_ff(h, i, dbl);
    case 0x14: return fp_cmp(h, i, dbl);
    case 0x18: return fp_cvt_fi(h, i, dbl);
    case 0x1a: return fp_cvt_if(h, i, dbl);
    case 0x1c: return fp_move_x(h, i, dbl);
    case 0x1e: return fp_move_f(h, i, dbl);
    default: return RVEMU_STOP_ILLEGAL;
    }
}

static enum rvemu_stop fp_op(struct rvemu_hart *h, uint32_t i)
{
    unsigned top = i >> 27;
    int dbl = (int)fmt_of(i);
    if (fmt_of(i) > 1u) return RVEMU_STOP_ILLEGAL;
    switch (top) {
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x0b:
        return fp_arith(h, i, top == 0x0b ? 4u : top, dbl);
    case 0x04: return fp_sgnj(h, i, dbl);
    case 0x05: return fp_minmax(h, i, dbl);
    default: return fp_op_conv(h, i, dbl);
    }
}

enum rvemu_stop rvemu_fpu_exec(struct rvemu_hart *h, struct rvemu_mem *m, uint32_t i)
{
    if (fs_off(h)) return RVEMU_STOP_ILLEGAL;
    switch (i & 0x7fu) {
    case OP_LOAD_FP: return fp_load(h, m, i);
    case OP_STORE_FP: return fp_store(h, m, i);
    case OP_FMADD:
    case OP_FMSUB:
    case OP_FNMSUB:
    case OP_FNMADD: return fp_fma(h, i);
    case OP_FP: return fp_op(h, i);
    default: return RVEMU_STOP_ILLEGAL;
    }
}
