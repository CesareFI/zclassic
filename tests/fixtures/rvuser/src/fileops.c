/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser granted-file mechanics fixture: openat(AT_FDCWD), fstat,
 * lseek SET/CUR/END, read, pread, pwrite, write, close and the error returns
 * (EBADF 9, EINVAL 22, ESPIPE 29). Each result is printed as "label=value\n";
 * a failing call prints its errno. argv[1] is a granted 14-byte file, argv[2]
 * a granted writable path. */
#include "sys.h"

static void show(const char *label, i64 v)
{
    puts_fd1(label);
    put_num(1, (u64)v);
}

int main(int argc, char **argv)
{
    int err;
    u64 sb[28]; /* 224-byte FreeBSD riscv64 struct stat */
    char buf[8];
    if (argc < 3) return 99;
    i64 fd = sys3(SYS_openat, AT_FDCWD, (i64)argv[1], O_RDONLY, &err);
    show("fd=", fd);
    sys3(SYS_fstat, fd, (i64)sb, 0, &err);
    show("size=", (i64)sb[14]);
    show("mode=", (i64)(sb[3] & 0xffffu));
    show("end=", sys3(SYS_lseek, fd, -3, 2, &err));
    i64 n = sys3(SYS_read, fd, (i64)buf, 8, &err);
    puts_fd1("tail=");
    put(1, buf, (u64)n);
    put(1, "\n", 1);
    show("cur=", sys3(SYS_lseek, fd, 0, 1, &err));
    n = sys4(SYS_pread, fd, (i64)buf, 4, 2, &err);
    puts_fd1("pread=");
    put(1, buf, (u64)n);
    put(1, "\n", 1);
    show("cur2=", sys3(SYS_lseek, fd, 0, 1, &err));
    show("badfd=", sys3(SYS_openat, 5, (i64)argv[1], O_RDONLY, &err));
    show("badflag=", sys3(SYS_open, (i64)argv[1], 0x40000000, 0, &err));
    show("badwhence=", sys3(SYS_lseek, fd, 0, 9, &err));
    show("negseek=", sys3(SYS_lseek, fd, -100, 0, &err));
    show("rowrite=", sys3(SYS_write, fd, (i64)"x", 1, &err));
    show("spipe=", sys4(SYS_pread, 1, (i64)buf, 1, 0, &err));
    sys3(SYS_close, fd, 0, 0, &err);
    show("closed=", sys3(SYS_close, fd, 0, 0, &err));
    i64 w = sys3(SYS_open, (i64)argv[2], O_RDWR | O_CREAT | O_TRUNC, 0644, &err);
    sys3(SYS_write, w, (i64)"AB", 2, &err);
    sys4(SYS_pwrite, w, (i64)"Z", 1, 5, &err);
    show("woff=", sys3(SYS_lseek, w, 0, 1, &err));
    sys3(SYS_fstat, w, (i64)sb, 0, &err);
    show("wsize=", (i64)sb[14]);
    sys3(SYS_close, w, 0, 0, &err);
    return 0;
}
