/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: integer-only IEEE-754 core for the F and D extensions: unpack,
 * round-and-pack for all five RISC-V rounding modes (tininess detected after
 * rounding), fused multiply-add, divide and square root. Every operation is
 * built from 64-bit integer arithmetic, so no host FPU state is read. */
#include "rvemu_softfp.h"

static const struct sfp_fmt FMT_S = {23u, 8u};
static const struct sfp_fmt FMT_D = {52u, 11u};

const struct sfp_fmt *sfp_fmt(int is_double) { return is_double ? &FMT_D : &FMT_S; }

static int bias_of(const struct sfp_fmt *f) { return (1 << (f->eb - 1)) - 1; }
static uint64_t frac_mask(const struct sfp_fmt *f) { return (1ull << f->fb) - 1u; }
static uint64_t sign_mask(const struct sfp_fmt *f) { return 1ull << (f->fb + f->eb); }

uint64_t sfp_canon_nan(const struct sfp_fmt *f)
{
    return ((((uint64_t)1 << f->eb) - 1u) << f->fb) | (1ull << (f->fb - 1u));
}

unsigned sfp_clz64(uint64_t x)
{
    unsigned n = 0;
    for (unsigned s = 32u; s != 0; s >>= 1) {
        if ((x >> (64u - s)) == 0) {
            n += s;
            x <<= s;
        }
    }
    return n;
}

struct sfp_val sfp_unpack(const struct sfp_fmt *f, uint64_t bits)
{
    struct sfp_val v = {SFP_ZERO, 0, 0, 0, 0};
    uint64_t frac = bits & frac_mask(f);
    uint64_t field = (bits >> f->fb) & ((1ull << f->eb) - 1u);
    v.sign = (unsigned)((bits >> (f->fb + f->eb)) & 1u);
    if (field == (1ull << f->eb) - 1u) {
        v.cls = frac ? SFP_NAN : SFP_INF;
        v.snan = (frac != 0 && (frac >> (f->fb - 1u)) == 0) ? 1u : 0u;
        return v;
    }
    if (field == 0) {
        if (frac == 0) return v;
        uint64_t lead = frac << (63u - f->fb);
        unsigned c = sfp_clz64(lead);
        v.cls = SFP_NORM;
        v.sig = lead << c;
        v.exp = 1 - bias_of(f) - (int)c;
        return v;
    }
    v.cls = SFP_NORM;
    v.sig = (frac | (1ull << f->fb)) << (63u - f->fb);
    v.exp = (int)field - bias_of(f);
    return v;
}

unsigned sfp_round_state(uint64_t rem, uint64_t half)
{
    if (rem == 0) return 0;
    if (rem < half) return 1;
    return rem == half ? 2u : 3u;
}

int sfp_round_inc(unsigned rm, unsigned sign, uint64_t lsb, unsigned state)
{
    if (state == 0) return 0;
    switch (rm) {
    case SFP_RNE: return state == 3u || (state == 2u && (lsb & 1u) != 0);
    case SFP_RMM: return state >= 2u;
    case SFP_RTZ: return 0;
    case SFP_RDN: return sign != 0;
    default: return sign == 0;
    }
}

static uint64_t jam_shr64(uint64_t x, unsigned n)
{
    if (n == 0) return x;
    if (n >= 64u) return x != 0;
    return (x >> n) | ((x & ((1ull << n) - 1u)) != 0);
}

static uint64_t overflow_bits(const struct sfp_fmt *f, unsigned sign, unsigned rm)
{
    uint64_t inf = (((uint64_t)1 << f->eb) - 1u) << f->fb;
    uint64_t max = inf - 1u;
    int to_inf = rm == SFP_RNE || rm == SFP_RMM || (rm == SFP_RUP && !sign) ||
                 (rm == SFP_RDN && sign);
    return (sign ? sign_mask(f) : 0) | (to_inf ? inf : max);
}

/* After-rounding tininess: below the normal range and not rounding up into it. */
static int is_tiny(const struct sfp_fmt *f, unsigned sign, int exp, uint64_t sig, unsigned rm)
{
    int emin = 1 - bias_of(f);
    unsigned low = 63u - f->fb;
    if (exp >= emin) return 0;
    if (exp < emin - 1) return 1;
    uint64_t q = sig >> low, rem = sig & ((1ull << low) - 1u);
    int carries = q == (1ull << (f->fb + 1u)) - 1u &&
                  sfp_round_inc(rm, sign, q, sfp_round_state(rem, 1ull << (low - 1u)));
    return !carries;
}

uint64_t sfp_round_pack(const struct sfp_fmt *f, unsigned sign, int exp, uint64_t sig,
                        unsigned rm, unsigned *fl)
{
    unsigned p = f->fb + 1u, low = 64u - p;
    int bias = bias_of(f), emin = 1 - bias;
    int tiny = is_tiny(f, sign, exp, sig, rm);
    int sub = exp < emin;
    if (sub) {
        sig = jam_shr64(sig, (unsigned)(emin - exp > 64 ? 64 : emin - exp));
        exp = emin;
    }
    uint64_t q = sig >> low, rem = sig & ((1ull << low) - 1u);
    unsigned state = sfp_round_state(rem, 1ull << (low - 1u));
    if (sfp_round_inc(rm, sign, q, state)) q++;
    if (state) *fl |= SFP_NX;
    if (tiny && state) *fl |= SFP_UF;
    uint64_t sbit = sign ? sign_mask(f) : 0;
    if (sub) return sbit | q;
    if ((q >> p) != 0) {
        q >>= 1;
        exp++;
    }
    if (exp > bias) {
        *fl |= SFP_OF | SFP_NX;
        return overflow_bits(f, sign, rm);
    }
    return sbit | ((uint64_t)(exp + bias) << f->fb) | (q & frac_mask(f));
}

/* ---- 128-bit helpers on (hi, lo) pairs. ---- */

struct u128 {
    uint64_t hi;
    uint64_t lo;
};

static int w_zero(struct u128 x) { return x.hi == 0 && x.lo == 0; }

static int w_cmp(struct u128 a, struct u128 b)
{
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
    return 0;
}

static struct u128 w_add(struct u128 a, struct u128 b)
{
    struct u128 r = {a.hi + b.hi, a.lo + b.lo};
    if (r.lo < a.lo) r.hi++;
    return r;
}

static struct u128 w_sub(struct u128 a, struct u128 b)
{
    struct u128 r = {a.hi - b.hi, a.lo - b.lo};
    if (a.lo < b.lo) r.hi--;
    return r;
}

static struct u128 w_shl(struct u128 x, unsigned n)
{
    if (n == 0) return x;
    if (n >= 64u) {
        struct u128 r = {x.lo << (n - 64u), 0};
        return r;
    }
    struct u128 r = {(x.hi << n) | (x.lo >> (64u - n)), x.lo << n};
    return r;
}

static struct u128 w_shr1(struct u128 x)
{
    struct u128 r = {x.hi >> 1, (x.lo >> 1) | (x.hi << 63)};
    return r;
}

/* Shift right by n, folding every lost bit into bit 0 (jamming). */
static struct u128 w_shr_jam(struct u128 x, unsigned n)
{
    struct u128 r = {0, 0};
    uint64_t lost;
    if (n == 0) return x;
    if (n >= 128u) {
        r.lo = !w_zero(x);
        return r;
    }
    if (n >= 64u) {
        unsigned m = n - 64u;
        lost = x.lo != 0 || (x.hi & ((1ull << m) - 1u)) != 0;
        r.lo = (x.hi >> m) | lost;
        return r;
    }
    lost = (x.lo & ((1ull << n) - 1u)) != 0;
    r.hi = x.hi >> n;
    r.lo = ((x.lo >> n) | (x.hi << (64u - n))) | lost;
    return r;
}

static struct u128 w_mul64(uint64_t a, uint64_t b)
{
    uint64_t a0 = a & 0xffffffffu, a1 = a >> 32, b0 = b & 0xffffffffu, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffu) + (p10 & 0xffffffffu);
    struct u128 r = {p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32),
                     (mid << 32) | (p00 & 0xffffffffu)};
    return r;
}

/* Normalize w to bit 127 and fold the low half into a sticky bit. A window
 * with its top bit at 126 stands for 1.x * 2^(*exp). */
static uint64_t w_to_sig(struct u128 w, int *exp)
{
    unsigned n = w.hi ? sfp_clz64(w.hi) : 64u + sfp_clz64(w.lo);
    w = w_shl(w, n);
    *exp = *exp + 1 - (int)n;
    return w.hi | (w.lo != 0);
}

/* ---- fused multiply-add. ---- */

struct fma_in {
    const struct sfp_fmt *f;
    struct sfp_val a, b, c;
    uint64_t cbits;
    unsigned mode, rm, ps, cs;
};

struct win {
    unsigned sign;
    int exp;
    struct u128 w;
};


static int fma_inf_zero(const struct fma_in *in)
{
    return (in->a.cls == SFP_INF && in->b.cls == SFP_ZERO) ||
           (in->a.cls == SFP_ZERO && in->b.cls == SFP_INF);
}

static int fma_has_addend(const struct fma_in *in) { return (in->mode & SFP_NO_ADD) == 0; }

static int fma_any_nan(const struct fma_in *in)
{
    return in->a.cls == SFP_NAN || in->b.cls == SFP_NAN ||
           (fma_has_addend(in) && in->c.cls == SFP_NAN);
}

static int fma_any_snan(const struct fma_in *in)
{
    return in->a.snan || in->b.snan || (fma_has_addend(in) && in->c.snan);
}

static int fma_inf_clash(const struct fma_in *in)
{
    int pinf = in->a.cls == SFP_INF || in->b.cls == SFP_INF;
    int cinf = fma_has_addend(in) && in->c.cls == SFP_INF;
    return pinf && cinf && in->ps != in->cs;
}

/* 1 when the operands force the canonical NaN; NV is raised when invalid. */
static int fma_nan_result(const struct fma_in *in, unsigned *fl)
{
    int invalid = fma_inf_zero(in) || fma_inf_clash(in);
    if (!invalid && !fma_any_nan(in)) return 0;
    if (invalid || fma_any_snan(in)) *fl |= SFP_NV;
    return 1;
}

static int fma_special(const struct fma_in *in, unsigned *fl, uint64_t *out)
{
    int has_c = (in->mode & SFP_NO_ADD) == 0;
    int pinf = in->a.cls == SFP_INF || in->b.cls == SFP_INF;
    int cinf = has_c && in->c.cls == SFP_INF;
    uint64_t inf = (((uint64_t)1 << in->f->eb) - 1u) << in->f->fb;
    if (fma_nan_result(in, fl)) {
        *out = sfp_canon_nan(in->f);
        return 1;
    }
    if (!pinf && !cinf) return 0;
    *out = inf | ((pinf ? in->ps : in->cs) ? sign_mask(in->f) : 0);
    return 1;
}


static uint64_t fma_zero_product(const struct fma_in *in)
{
    uint64_t sm = sign_mask(in->f);
    if ((in->mode & SFP_NO_ADD) || in->c.cls == SFP_ZERO) {
        unsigned s = ((in->mode & SFP_NO_ADD) || in->ps == in->cs) ? in->ps : (in->rm == SFP_RDN);
        return s ? sm : 0;
    }
    return (in->cbits & ~sm) | (in->cs ? sm : 0);
}

static struct win product_window(const struct fma_in *in)
{
    struct u128 p = w_mul64(in->a.sig, in->b.sig);
    struct win r = {in->ps, in->a.exp + in->b.exp, p};
    if (p.hi >> 63) {
        r.w = w_shr_jam(p, 1);
        r.exp++;
    }
    return r;
}

static struct win addend_window(const struct fma_in *in)
{
    struct u128 w = {in->c.sig >> 1, in->c.sig << 63};
    struct win r = {in->cs, in->c.exp, w};
    return r;
}

static uint64_t add_windows(const struct fma_in *in, struct win x, struct win y, unsigned *fl)
{
    if (y.exp > x.exp || (y.exp == x.exp && w_cmp(y.w, x.w) > 0)) {
        struct win t = x;
        x = y;
        y = t;
    }
    y.w = w_shr_jam(y.w, (unsigned)(x.exp - y.exp));
    struct u128 r;
    if (x.sign == y.sign) {
        r = w_add(x.w, y.w);
    } else {
        r = w_sub(x.w, y.w);
        if (w_zero(r)) return in->rm == SFP_RDN ? sign_mask(in->f) : 0;
    }
    int exp = x.exp;
    uint64_t sig = w_to_sig(r, &exp);
    return sfp_round_pack(in->f, x.sign, exp, sig, in->rm, fl);
}

uint64_t sfp_fma(const struct sfp_fmt *f, uint64_t a, uint64_t b, uint64_t c,
                 unsigned mode, unsigned rm, unsigned *fl)
{
    struct fma_in in = {f, sfp_unpack(f, a), sfp_unpack(f, b), sfp_unpack(f, c), c, mode, rm, 0, 0};
    uint64_t out = 0;
    in.ps = in.a.sign ^ in.b.sign ^ ((mode & SFP_NEG_PROD) ? 1u : 0u);
    in.cs = in.c.sign ^ ((mode & SFP_NEG_ADD) ? 1u : 0u);
    if (fma_special(&in, fl, &out)) return out;
    if (in.a.cls == SFP_ZERO || in.b.cls == SFP_ZERO) return fma_zero_product(&in);
    struct win p = product_window(&in);
    if ((mode & SFP_NO_ADD) || in.c.cls == SFP_ZERO) {
        int exp = p.exp;
        uint64_t sig = w_to_sig(p.w, &exp);
        return sfp_round_pack(f, p.sign, exp, sig, rm, fl);
    }
    return add_windows(&in, p, addend_window(&in), fl);
}

/* ---- divide and square root. ---- */

static int div_special(const struct sfp_fmt *f, const struct sfp_val *a, const struct sfp_val *b,
                       unsigned *fl, uint64_t *out)
{
    unsigned s = a->sign ^ b->sign;
    uint64_t inf = (((uint64_t)1 << f->eb) - 1u) << f->fb, sm = s ? sign_mask(f) : 0;
    if (a->cls == SFP_NAN || b->cls == SFP_NAN || (a->cls == b->cls && a->cls != SFP_NORM)) {
        if (a->snan || b->snan || (a->cls != SFP_NAN && b->cls != SFP_NAN)) *fl |= SFP_NV;
        *out = sfp_canon_nan(f);
        return 1;
    }
    if (a->cls == SFP_INF) { *out = sm | inf; return 1; }
    if (b->cls == SFP_INF || a->cls == SFP_ZERO) { *out = sm; return 1; }
    if (b->cls == SFP_ZERO) {
        *fl |= SFP_DZ;
        *out = sm | inf;
        return 1;
    }
    return 0;
}

uint64_t sfp_div(const struct sfp_fmt *f, uint64_t a, uint64_t b, unsigned rm, unsigned *fl)
{
    struct sfp_val x = sfp_unpack(f, a), y = sfp_unpack(f, b);
    uint64_t out = 0;
    if (div_special(f, &x, &y, fl, &out)) return out;
    int exp = x.exp - y.exp;
    uint64_t rem = x.sig, q = 0;
    unsigned steps = 64u;
    if (rem >= y.sig) {
        rem -= y.sig;
        q = 1ull << 63;
        steps = 63u;
    } else {
        exp--;
    }
    for (unsigned i = 0; i < steps; i++) {
        uint64_t carry = rem >> 63;
        rem <<= 1;
        if (carry || rem >= y.sig) {
            rem -= y.sig;
            q |= 1ull << (steps - 1u - i);
        }
    }
    return sfp_round_pack(f, x.sign ^ y.sign, exp, q | (rem != 0), rm, fl);
}

static struct u128 isqrt128(struct u128 n, int *inexact)
{
    struct u128 res = {0, 0}, bit = {1ull << 62, 0};
    for (unsigned i = 0; i < 64u; i++) {
        struct u128 t = w_add(res, bit);
        if (w_cmp(n, t) >= 0) {
            n = w_sub(n, t);
            res = w_add(w_shr1(res), bit);
        } else {
            res = w_shr1(res);
        }
        bit = w_shr1(w_shr1(bit));
    }
    *inexact = !w_zero(n);
    return res;
}

uint64_t sfp_sqrt(const struct sfp_fmt *f, uint64_t a, unsigned rm, unsigned *fl)
{
    struct sfp_val x = sfp_unpack(f, a);
    if (x.cls == SFP_NAN || (x.sign && x.cls != SFP_ZERO)) {
        if (x.snan || x.cls != SFP_NAN) *fl |= SFP_NV;
        return sfp_canon_nan(f);
    }
    if (x.cls != SFP_NORM) return a;
    unsigned odd = (unsigned)x.exp & 1u;
    struct u128 n = {0, x.sig};
    int inexact = 0;
    struct u128 r = isqrt128(w_shl(n, 63u + odd), &inexact);
    return sfp_round_pack(f, 0, (x.exp - (int)odd) / 2, r.lo | (uint64_t)inexact, rm, fl);
}
