/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, static PIE. Writes "pie hello\n", then the auxv entries the loader
 * supplied as "key=value\n" lines (AT_PAGESZ skipped), so the test can check AT_PHDR, AT_PHENT,
 * AT_PHNUM, AT_BASE and AT_ENTRY against the load bias. Exits 0. */
#include "sys.h"

static void line(u64 key, u64 val)
{
    char b[48];
    u64 n = fmt_u64(b, key);
    b[n++] = '=';
    n += fmt_u64(b + n, val);
    b[n++] = '\n';
    put(1, b, n);
}

int main(int argc, char **argv)
{
    put(1, "pie hello\n", 10);
    u64 *p = (u64 *)(argv + argc + 1);
    while (*p) p++; /* skip envp */
    for (p++; p[0]; p += 2)
        if (p[0] != 6) line(p[0], p[1]);
    return 0;
}
