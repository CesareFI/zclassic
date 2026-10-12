/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser fixture, spin forever with no system call (host abort and budget tests). */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    for (;;) __asm__ volatile("");
}
