/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, write "hello\n" to fd 1 and exit 0. */
#include "sys.h"
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    put(1, "hello\n", 6);
    return 0;
}
