/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser granted-file fixture. open(argv[1], O_RDONLY) and copy it to
 * stdout; then open(argv[2], O_WRONLY|O_CREAT|O_TRUNC) and write the copied byte
 * count as decimal text plus newline. Exit status: 0 on success, the errno when
 * the read open fails, 100 + errno when the write open fails. */
#include "sys.h"

int main(int argc, char **argv)
{
    int err;
    char buf[64];
    u64 total = 0;
    if (argc < 3) return 99;
    i64 in = sys3(SYS_open, (i64)argv[1], O_RDONLY, 0, &err);
    if (err) return (int)in;
    for (;;) {
        i64 n = sys3(SYS_read, in, (i64)buf, sizeof(buf), &err);
        if (err || n <= 0) break;
        put(1, buf, (u64)n);
        total += (u64)n;
    }
    sys3(SYS_close, in, 0, 0, &err);
    i64 out = sys3(SYS_open, (i64)argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644, &err);
    if (err) return 100 + (int)out;
    u64 len = fmt_u64(buf, total);
    buf[len++] = '\n';
    sys3(SYS_write, out, (i64)buf, (i64)len, &err);
    sys3(SYS_close, out, 0, 0, &err);
    return 0;
}
