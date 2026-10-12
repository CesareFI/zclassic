/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, print "argc=N" then each argv entry on its own line. */
#include "sys.h"
int main(int argc, char **argv)
{
    char line[8] = {'a', 'r', 'g', 'c', '=', (char)('0' + argc % 10), '\n', 0};
    put(1, line, 7);
    for (int i = 0; i < argc; i++) {
        puts_fd1(argv[i]);
        put(1, "\n", 1);
    }
    return 0;
}
