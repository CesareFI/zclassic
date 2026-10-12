/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fd-table fixture. Open argv[1] read-only up to 40 times without
 * closing; print the number of successes, exit with the errno of the first failure
 * (0 when none failed). Then close the first descriptor and reopen: a freed slot
 * must be reusable, which prints "reuse=<fd>". */
#include "sys.h"

int main(int argc, char **argv)
{
    int err = 0;
    i64 fds[40], r = 0;
    int n = 0, status = 0;
    if (argc < 2) return 99;
    while (n < 40) {
        r = sys3(SYS_open, (i64)argv[1], O_RDONLY, 0, &err);
        if (err) { status = (int)r; break; }
        fds[n++] = r;
    }
    puts_fd1("opened=");
    put_num(1, (u64)n);
    sys3(SYS_close, fds[0], 0, 0, &err);
    r = sys3(SYS_open, (i64)argv[1], O_RDONLY, 0, &err);
    if (!err) { puts_fd1("reuse="); put_num(1, (u64)r); }
    return status;
}
