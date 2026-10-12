/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, file offsets at the signed limit. Opens argv[1] (readable), argv[2]
 * (writable) and argv[3] (append-only, reported by the caller as INT64_MAX bytes long), then
 * does a 1-byte read, write, pread, pwrite and an append write at offset INT64_MAX. Each must
 * fail with EINVAL (22) and reach no caller callback; prints "label=errno\n", then closes every
 * fd and prints the close results (0). */
#include "sys.h"

#define OFF_MAX 0x7fffffffffffffffL

static void show(const char *label, i64 v)
{
    puts_fd1(label);
    put_num(1, (u64)v);
}

int main(int argc, char **argv)
{
    int err;
    char b[2] = {'x', 'y'};
    if (argc < 4) return 99;
    i64 fr = sys3(SYS_openat, AT_FDCWD, (i64)argv[1], O_RDONLY, &err);
    i64 fw = sys3(SYS_openat, AT_FDCWD, (i64)argv[2], O_WRONLY | O_CREAT, &err);
    i64 fa = sys3(SYS_openat, AT_FDCWD, (i64)argv[3], O_WRONLY | 0x8, &err);
    show("lseek_r=", sys3(SYS_lseek, fr, OFF_MAX, 0, &err));
    show("lseek_w=", sys3(SYS_lseek, fw, OFF_MAX, 0, &err));
    show("read=", sys3(SYS_read, fr, (i64)b, 1, &err));
    show("write=", sys3(SYS_write, fw, (i64)b, 1, &err));
    show("pread=", sys4(SYS_pread, fr, (i64)b, 1, OFF_MAX, &err));
    show("pwrite=", sys4(SYS_pwrite, fw, (i64)b, 1, OFF_MAX, &err));
    show("append=", sys3(SYS_write, fa, (i64)b, 1, &err));
    show("close_r=", sys3(SYS_close, fr, 0, 0, &err));
    show("close_w=", sys3(SYS_close, fw, 0, 0, &err));
    show("close_a=", sys3(SYS_close, fa, 0, 0, &err));
    return 0;
}
