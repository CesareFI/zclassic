/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, static PIE whose global pointer tables need R_RISCV_RELATIVE
 * relocations (data pointers and a function pointer). Without the crt0 relocation step the
 * pointers hold link-time addresses and the output is wrong. Prints the table, then the result
 * of calling through the function table; exit status is the number of entries. */
#include "sys.h"
static const char s0[] = "alpha\n";
static const char s1[] = "beta\n";
static const char s2[] = "gamma\n";
static void f_a(void) { put(1, "fa\n", 3); }
static void f_b(void) { put(1, "fb\n", 3); }
const char *const table[] = {s0, s1, s2};
void (*const fns[])(void) = {f_a, f_b};
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    for (int i = 0; i < 3; i++) puts_fd1(table[i]);
    for (int i = 0; i < 2; i++) fns[i]();
    return 5;
}
