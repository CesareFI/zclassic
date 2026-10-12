/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: integer-only IEEE-754 binary32 / binary64 arithmetic for the F and
 * D extensions. No host floating point is touched, so results and exception
 * flags are bit-exact on every host. Values travel as raw bit patterns. */
#ifndef ZCL_RVEMU_SOFTFP_H
#define ZCL_RVEMU_SOFTFP_H

#include <stdint.h>

/* RISC-V fflags bits. */
#define SFP_NX 1u
#define SFP_UF 2u
#define SFP_OF 4u
#define SFP_DZ 8u
#define SFP_NV 16u

/* RISC-V rounding modes, numbered as in the rm field. */
enum sfp_rm { SFP_RNE = 0, SFP_RTZ = 1, SFP_RDN = 2, SFP_RUP = 3, SFP_RMM = 4 };

/* fma mode bits: negate the product, negate the addend, or have no addend. */
#define SFP_NEG_PROD 1u
#define SFP_NEG_ADD 2u
#define SFP_NO_ADD 4u

/* fcvt integer kinds: 32/64 bit, signed/unsigned. */
enum sfp_ikind { SFP_W = 0, SFP_WU = 1, SFP_L = 2, SFP_LU = 3 };

enum sfp_cls { SFP_ZERO = 0, SFP_NORM = 1, SFP_INF = 2, SFP_NAN = 3 };

struct sfp_fmt {
    unsigned fb; /* fraction bits */
    unsigned eb; /* exponent bits */
};

/* Unpacked operand: value = sig * 2^(exp - 63), sig normalized to bit 63 for
 * SFP_NORM (subnormals are normalized too). */
struct sfp_val {
    enum sfp_cls cls;
    unsigned sign;
    unsigned snan;
    int exp;
    uint64_t sig;
};

const struct sfp_fmt *sfp_fmt(int is_double);
uint64_t sfp_canon_nan(const struct sfp_fmt *f);
struct sfp_val sfp_unpack(const struct sfp_fmt *f, uint64_t bits);
unsigned sfp_clz64(uint64_t x);
/* Round and encode: value = sig * 2^(exp - 63); bit 0 of sig is a sticky. */
uint64_t sfp_round_pack(const struct sfp_fmt *f, unsigned sign, int exp, uint64_t sig,
                        unsigned rm, unsigned *fl);
/* 0 exact, 1 below half, 2 exactly half, 3 above half. */
unsigned sfp_round_state(uint64_t rem, uint64_t half);
int sfp_round_inc(unsigned rm, unsigned sign, uint64_t lsb, unsigned state);

/* (a * b) +/- c, or a * b alone with SFP_NO_ADD, rounded once. */
uint64_t sfp_fma(const struct sfp_fmt *f, uint64_t a, uint64_t b, uint64_t c,
                 unsigned mode, unsigned rm, unsigned *fl);
uint64_t sfp_div(const struct sfp_fmt *f, uint64_t a, uint64_t b, unsigned rm, unsigned *fl);
uint64_t sfp_sqrt(const struct sfp_fmt *f, uint64_t a, unsigned rm, unsigned *fl);

/* Conversions. f2i saturates and raises NV out of range. */
uint64_t sfp_f2f(const struct sfp_fmt *src, const struct sfp_fmt *dst, uint64_t bits,
                 unsigned rm, unsigned *fl);
uint64_t sfp_f2i(const struct sfp_fmt *f, uint64_t bits, unsigned rm, enum sfp_ikind kind,
                 unsigned *fl);
uint64_t sfp_i2f(const struct sfp_fmt *f, uint64_t val, enum sfp_ikind kind, unsigned rm,
                 unsigned *fl);

#endif
