/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, call unknown system call 9999 and exit with the
 * errno it returned (ENOSYS = 78 on FreeBSD) if the error flag was set. */
#include "sys.h"
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    int err;
    i64 r = sys3(9999, 0, 0, 0, &err);
    return err ? (int)r : 1;
}
