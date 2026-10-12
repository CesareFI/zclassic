/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RV64IM and Zbb integer ALU semantics. Operations
 * on the W forms compute on the low 32 bits and sign-extend the result. */
#include "rvemu_internal.h"
#include "base/serialize_le.h"

#define F3_ADD 0u
#define F3_SLL 1u
#define F3_SLT 2u
#define F3_SLTU 3u
#define F3_XOR 4u
#define F3_SR 5u
#define F3_OR 6u
#define F3_AND 7u
#define F7_ALT 0x20u
#define F7_MULDIV 0x01u

static uint64_t sext32(uint64_t v)
{
    return (uint64_t)(int64_t)(int32_t)(uint32_t)v;
}

/* RV64 Zbb, ratified bit-manipulation instructions. */
static unsigned zbb_zeros(uint64_t a,unsigned width,int leading)
{
    unsigned n=0;
    for (unsigned i=0;i<width;i++) {
        unsigned bit=leading?width-1u-i:i;
        if (a&(UINT64_C(1)<<bit)) break;
        n++;
    }
    return n;
}
static unsigned zbb_ones(uint64_t a)
{
    unsigned n=0;
    while (a) { a&=a-1u; n++; }
    return n;
}
static uint64_t zbb_rotate(uint64_t a,uint64_t b,int word,int left)
{
    unsigned width=word?32u:64u;
    unsigned sh=(unsigned)(b&(width-1u));
    if (word) a=(uint32_t)a;
    uint64_t result=a;
    if (sh) {
        if (left) result=(a<<sh)|(a>>(width-sh));
        else result=(a>>sh)|(a<<(width-sh));
    }
    return word?sext32(result):result;
}
static uint64_t zbb_bytes(uint64_t a,int reverse)
{
    if (reverse) return zcl_bswap64(a);
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, a);
    for (unsigned i=0;i<sizeof(bytes);i++)
        bytes[i]=bytes[i]?UINT8_MAX:0;
    return zcl_read_u64_le(bytes);
}
static int zbb_count(unsigned imm,int word,uint64_t a,uint64_t *out)
{
    unsigned width=word?32u:64u;
    switch (imm) {
    case 0x600u: *out=zbb_zeros(a,width,1); return 0;
    case 0x601u: *out=zbb_zeros(a,width,0); return 0;
    case 0x602u: *out=zbb_ones(word?(uint32_t)a:a); return 0;
    default: return -1;
    }
}
static int zbb_extend(unsigned imm,int word,uint64_t a,uint64_t *out)
{
    if (word) return -1;
    switch (imm) {
    case 0x604u: *out=((a&UINT64_C(255))^UINT64_C(128))-UINT64_C(128);return 0;
    case 0x605u: *out=((a&UINT64_C(65535))^UINT64_C(32768))-UINT64_C(32768);return 0;
    default: return -1;
    }
}
int rvemu_zbb_imm(unsigned imm,unsigned f3,int word,uint64_t a,uint64_t *out)
{
    if (f3==F3_SLL) {
        if (zbb_count(imm,word,a,out)==0) return 0;
        return zbb_extend(imm,word,a,out);
    }
    if (f3!=F3_SR) return -1;
    if ((!word && (imm>>6)==0x18u) || (word && (imm>>5)==0x30u)) {
        *out=zbb_rotate(a,imm,word,0);return 0;
    }
    if (word) return -1;
    if (imm==0x287u) { *out=zbb_bytes(a,0);return 0; }
    if (imm==0x6b8u) { *out=zbb_bytes(a,1);return 0; }
    return -1;
}
static int zbb_minmax(unsigned f3,uint64_t a,uint64_t b,uint64_t *out)
{
    switch (f3) {
    case 4u: *out=(int64_t)a<(int64_t)b?a:b;return 0;
    case 5u: *out=a<b?a:b;return 0;
    case 6u: *out=(int64_t)a>(int64_t)b?a:b;return 0;
    case 7u: *out=a>b?a:b;return 0;
    default: return -1;
    }
}
static int zbb_inverse(unsigned f3,int word,uint64_t a,uint64_t b,uint64_t *out)
{
    if (word) return -1;
    switch (f3) {
    case F3_XOR: *out=~(a^b);return 0;
    case F3_OR: *out=a|~b;return 0;
    case F3_AND: *out=a&~b;return 0;
    default: return -1;
    }
}
static int zbb_register(unsigned f3,unsigned f7,int word,uint64_t a,uint64_t b,uint64_t *out)
{
    if (f7==0x30u) {
        if (f3!=F3_SLL && f3!=F3_SR) return -1;
        *out=zbb_rotate(a,b,word,f3==F3_SLL);return 0;
    }
    if (f7==0x04u && word && f3==F3_XOR) { *out=a&UINT64_C(65535);return 0; }
    if (f7==0x05u && !word) return zbb_minmax(f3,a,b,out);
    return -1;
}
/* High 64 bits of the unsigned 128-bit product, without __int128. */
static uint64_t mulhu64(uint64_t a, uint64_t b)
{
    uint64_t al = a & 0xffffffffu, ah = a >> 32;
    uint64_t bl = b & 0xffffffffu, bh = b >> 32;
    uint64_t lh = al * bh, hl = ah * bl;
    uint64_t mid = ((al * bl) >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
    return ah * bh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static uint64_t mulhs64(uint64_t a, uint64_t b)
{
    uint64_t r = mulhu64(a, b);
    if ((int64_t)a < 0) r -= b;
    if ((int64_t)b < 0) r -= a;
    return r;
}

static uint64_t mulhsu64(uint64_t a, uint64_t b)
{
    uint64_t r = mulhu64(a, b);
    if ((int64_t)a < 0) r -= b;
    return r;
}

static uint64_t div_s64(uint64_t a, uint64_t b)
{
    int64_t x = (int64_t)a, y = (int64_t)b;
    if (y == 0) return UINT64_MAX;
    if (y == -1 && x == INT64_MIN) return a;
    return (uint64_t)(x / y);
}

static uint64_t rem_s64(uint64_t a, uint64_t b)
{
    int64_t x = (int64_t)a, y = (int64_t)b;
    if (y == 0) return a;
    if (y == -1) return 0;
    return (uint64_t)(x % y);
}

static uint64_t div_u64(uint64_t a, uint64_t b)
{
    return b == 0 ? UINT64_MAX : a / b;
}

static uint64_t rem_u64(uint64_t a, uint64_t b)
{
    return b == 0 ? a : a % b;
}

/* Multiply and divide on already-widened operands (f3 selects the op). */
static uint64_t muldiv64(unsigned f3, uint64_t a, uint64_t b)
{
    switch (f3) {
    case 0: return a * b;
    case 1: return mulhs64(a, b);
    case 2: return mulhsu64(a, b);
    case 3: return mulhu64(a, b);
    case 4: return div_s64(a, b);
    case 5: return div_u64(a, b);
    case 6: return rem_s64(a, b);
    default: return rem_u64(a, b);
    }
}

/* Word M ops: signed forms (mulw, divw, remw) widen with sign extension,
 * unsigned forms (divuw, remuw) with zero extension. Only f3 0, 4..7 exist. */
static int alu_muldiv(unsigned f3, int word, uint64_t a, uint64_t b, uint64_t *out)
{
    if (word) {
        if (f3 == 1 || f3 == 2 || f3 == 3) return -1;
        int is_unsigned = f3 == 5 || f3 == 7;
        uint64_t wa = is_unsigned ? (uint64_t)(uint32_t)a : sext32(a);
        uint64_t wb = is_unsigned ? (uint64_t)(uint32_t)b : sext32(b);
        *out = sext32(muldiv64(f3, wa, wb));
        return 0;
    }
    *out = muldiv64(f3, a, b);
    return 0;
}

static uint64_t shift_op(unsigned f3, int alt, int word, uint64_t a, uint64_t b)
{
    if (word) {
        unsigned sh = (unsigned)(b & 31u);
        uint32_t lo = (uint32_t)a;
        if (f3 == F3_SLL) return sext32((uint64_t)(lo << sh));
        if (alt) return sext32((uint64_t)((int32_t)lo >> sh));
        return sext32((uint64_t)(lo >> sh));
    }
    unsigned sh = (unsigned)(b & 63u);
    if (f3 == F3_SLL) return a << sh;
    if (alt) return (uint64_t)((int64_t)a >> sh);
    return a >> sh;
}

static int is_word_invalid_f3(unsigned f3)
{
    return f3 == F3_SLT || f3 == F3_SLTU || f3 == F3_XOR || f3 == F3_OR || f3 == F3_AND;
}

static uint64_t alu_addsub(int alt, int word, uint64_t a, uint64_t b)
{
    uint64_t r = alt ? a - b : a + b;
    return word ? sext32(r) : r;
}

static int alu_base(unsigned f3, unsigned f7, int word, uint64_t a, uint64_t b, uint64_t *out)
{
    int alt = f7 == F7_ALT;
    if (alt && f3 != F3_ADD && f3 != F3_SR) return zbb_inverse(f3,word,a,b,out);
    if (word && is_word_invalid_f3(f3)) return -1;
    switch (f3) {
    case F3_ADD: *out = alu_addsub(alt, word, a, b); return 0;
    case F3_SLL: *out = shift_op(f3, 0, word, a, b); return 0;
    case F3_SLT: *out = (int64_t)a < (int64_t)b; return 0;
    case F3_SLTU: *out = a < b; return 0;
    case F3_XOR: *out = a ^ b; return 0;
    case F3_SR: *out = shift_op(f3, alt, word, a, b); return 0;
    case F3_OR: *out = a | b; return 0;
    default: *out = a & b; return 0;
    }
}

int rvemu_alu(unsigned f3, unsigned f7, int word, uint64_t a, uint64_t b, uint64_t *out)
{
    if (f7 == F7_MULDIV) return alu_muldiv(f3, word, a, b, out);
    if (f7 != 0u && f7 != F7_ALT) return zbb_register(f3,f7,word,a,b,out);
    return alu_base(f3, f7, word, a, b, out);
}
