/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser bounded-path-copy fixture. The last environment string ends at
 * the very top of guest memory; overwrite its NUL so the path runs off the end of
 * memory, then open it. Exit status is the errno of that open (EFAULT = 14 expected). */
#include "sys.h"

int main(int argc, char **argv)
{
    int err;
    char **envp = argv + argc + 1;
    char *last = 0;
    while (envp[0]) { last = envp[0]; envp++; }
    if (!last) return 99;
    while (*last) last++;
    *last = 'A'; /* last byte of guest memory: no NUL left */
    i64 r = sys3(SYS_open, (i64)last, O_RDONLY, 0, &err);
    return err ? (int)r : 0;
}
