/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: integer-only conversions for the F and D extensions: between the
 * two float formats, float to 32/64-bit integer (saturating, NV on overflow
 * or NaN) and integer to float. */
#include "rvemu_softfp.h"

uint64_t sfp_f2f(const struct sfp_fmt *src, const struct sfp_fmt *dst, uint64_t bits,
                 unsigned rm, unsigned *fl)
{
    struct sfp_val v = sfp_unpack(src, bits);
    uint64_t sm = v.sign ? 1ull << (dst->fb + dst->eb) : 0;
    uint64_t inf = (((uint64_t)1 << dst->eb) - 1u) << dst->fb;
    switch (v.cls) {
    case SFP_NAN:
        if (v.snan) *fl |= SFP_NV;
        return sfp_canon_nan(dst);
    case SFP_INF: return sm | inf;
    case SFP_ZERO: return sm;
    default: return sfp_round_pack(dst, v.sign, v.exp, v.sig, rm, fl);
    }
}

/* Magnitude of |v| rounded to an integer; *over is set past 2^64 - 1. */
static uint64_t round_to_int(const struct sfp_val *v, unsigned rm, unsigned *state, int *over)
{
    uint64_t mag = 0, rem = 0;
    *state = 0;
    *over = 0;
    if (v->exp >= 64) {
        *over = 1;
        return 0;
    }
    if (v->exp == 63) return v->sig;
    unsigned s = (unsigned)(63 - v->exp);
    if (s > 64u) {
        *state = 1;
    } else if (s == 64u) {
        *state = sfp_round_state(v->sig, 1ull << 63);
        mag = 0;
    } else {
        mag = v->sig >> s;
        rem = v->sig & ((1ull << s) - 1u);
        *state = sfp_round_state(rem, 1ull << (s - 1u));
    }
    if (sfp_round_inc(rm, v->sign, mag, *state)) {
        if (mag == UINT64_MAX) *over = 1;
        mag++;
    }
    return mag;
}

static uint64_t sext32(uint64_t v) { return (uint64_t)(int64_t)(int32_t)(uint32_t)v; }

/* Saturated results: positive-side maximum and negative-side minimum. */
static uint64_t sat_value(enum sfp_ikind k, unsigned neg)
{
    switch (k) {
    case SFP_W: return neg ? 0xffffffff80000000ull : 0x7fffffffull;
    case SFP_WU: return neg ? 0 : UINT64_MAX;
    case SFP_L: return neg ? 0x8000000000000000ull : 0x7fffffffffffffffull;
    default: return neg ? 0 : UINT64_MAX;
    }
}

/* 1 when (neg, mag) fits the kind. */
static int fits(enum sfp_ikind k, unsigned neg, uint64_t mag)
{
    switch (k) {
    case SFP_W: return mag <= (neg ? 0x80000000ull : 0x7fffffffull);
    case SFP_WU: return neg ? mag == 0 : mag <= 0xffffffffull;
    case SFP_L: return mag <= (neg ? 0x8000000000000000ull : 0x7fffffffffffffffull);
    default: return neg ? mag == 0 : 1;
    }
}

static uint64_t encode_int(enum sfp_ikind k, unsigned neg, uint64_t mag)
{
    uint64_t v = neg ? (uint64_t)0 - mag : mag;
    return (k == SFP_W || k == SFP_WU) ? sext32(v) : v;
}

uint64_t sfp_f2i(const struct sfp_fmt *f, uint64_t bits, unsigned rm, enum sfp_ikind kind,
                 unsigned *fl)
{
    struct sfp_val v = sfp_unpack(f, bits);
    unsigned state = 0;
    int over = 0;
    uint64_t mag;
    if (v.cls == SFP_NAN || v.cls == SFP_INF) {
        *fl |= SFP_NV;
        return sat_value(kind, v.cls == SFP_INF ? v.sign : 0u);
    }
    if (v.cls == SFP_ZERO) return 0;
    mag = round_to_int(&v, rm, &state, &over);
    if (over || !fits(kind, v.sign, mag)) {
        *fl |= SFP_NV;
        return sat_value(kind, v.sign);
    }
    if (state) *fl |= SFP_NX;
    return encode_int(kind, v.sign, mag);
}

uint64_t sfp_i2f(const struct sfp_fmt *f, uint64_t val, enum sfp_ikind kind, unsigned rm,
                 unsigned *fl)
{
    unsigned neg = 0;
    uint64_t mag = val;
    if (kind == SFP_W) {
        mag = sext32(val);
        neg = (unsigned)(mag >> 63);
        if (neg) mag = (uint64_t)0 - mag;
    } else if (kind == SFP_WU) {
        mag = val & 0xffffffffull;
    } else if (kind == SFP_L) {
        neg = (unsigned)(val >> 63);
        if (neg) mag = (uint64_t)0 - val;
    }
    if (mag == 0) return 0;
    unsigned n = sfp_clz64(mag);
    return sfp_round_pack(f, neg, 63 - (int)n, mag << n, rm, fl);
}
