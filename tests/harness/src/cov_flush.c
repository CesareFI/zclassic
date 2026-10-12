/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coverage flush on crash. Compiled into `test_zcl_cov` only (the Makefile
 * passes `-DCOVERAGE_BUILD`); otherwise an empty translation unit.
 *
 * gcov writes .gcda files only on clean exit; a __attribute__((constructor))
 * signal handler calls __gcov_dump() before the crash propagates so partial
 * runs still yield coverage data.
 */

#ifdef COVERAGE_BUILD

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Provided by libgcov when -fprofile-arcs is on. */
extern void __gcov_dump(void);

static volatile sig_atomic_t g_in_handler = 0;

static void cov_flush_handler(int sig)
{
    /* Re-entrant guard: if __gcov_dump itself crashes (shouldn't but
     * we're already in a bad state), don't loop. */
    if (g_in_handler) {
        _exit(128 + sig);
    }
    g_in_handler = 1;

    __gcov_dump();

    /* _exit, not re-raising: libgcov's atexit cleanup would write the .gcda
     * files a second time with a different checksum. */
    _exit(128 + sig);
}

__attribute__((constructor))
static void install_cov_flush(void)
{
    struct sigaction sa;
    sa.sa_handler = cov_flush_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
}

#else /* !COVERAGE_BUILD */

/* ISO C forbids an empty translation unit and the main build runs
 * with -Werror=pedantic, so leave a single no-op declaration here. */
typedef int cov_flush_no_op_placeholder;

#endif /* COVERAGE_BUILD */
