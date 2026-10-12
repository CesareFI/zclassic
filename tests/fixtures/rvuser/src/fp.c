/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser lp64d fixture. Real double math on the F/D hardware: sqrt(2),
 * a Newton iteration with fdiv, and sqrt(2)*1e6, printed with integer-only
 * formatting. Expected stdout (bit-exact IEEE-754 binary64):
 *   int=1414213\n frac=562373\n bits=3ff6a09e667f3bcd\n newton=3ff6a09e667f3bcc\n */
#include "sys.h"

static void put_hex(const char *label, u64 v)
{
    char b[40];
    u64 n = 0;
    while (label[n]) { b[n] = label[n]; n++; }
    for (int s = 60; s >= 0; s -= 4) b[n++] = "0123456789abcdef"[(v >> s) & 15u];
    b[n++] = '\n';
    put(1, b, n);
}

static u64 bits_of(double d)
{
    union { double d; u64 u; } x;
    x.d = d;
    return x.u;
}

int main(void)
{
    volatile double two = 2.0, scale = 1000000.0;
    double s = __builtin_sqrt(two);
    double x = 1.0;
    for (int i = 0; i < 8; i++) x = (x + two / x) * 0.5;
    double big = s * scale;
    i64 ip = (i64)big;
    double rest = (big - (double)ip) * scale;
    puts_fd1("int=");
    put_num(1, (u64)ip);
    puts_fd1("frac=");
    put_num(1, (u64)(i64)rest);
    put_hex("bits=", bits_of(s));
    put_hex("newton=", bits_of(x));
    return 0;
}
