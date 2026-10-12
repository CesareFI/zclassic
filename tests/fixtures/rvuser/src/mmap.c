/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, anonymous mmap of two pages, write 1..9, read back,
 * require the second page to be zero-filled, exit with the sum (45). */
#include "sys.h"
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    int err;
    /* PROT_READ|PROT_WRITE = 3, MAP_PRIVATE|MAP_ANON = 0x1002, fd -1 */
    unsigned char *p = (unsigned char *)sys6(SYS_mmap, 0, 8192, 3, 0x1002, -1, 0, &err);
    if (err) return 99;
    if (p[4096] != 0) return 98;
    for (int i = 1; i < 10; i++) p[i] = (unsigned char)i;
    int sum = 0;
    for (int i = 1; i < 10; i++) sum += p[i];
    return sum;
}
