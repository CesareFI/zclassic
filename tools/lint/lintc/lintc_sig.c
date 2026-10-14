/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: implementation of lintc_sig.h. The only file-scope state is the
 * volatile sig_atomic_t the handler stores into.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <signal.h>
#include <stddef.h>
#include "lintc_sig.h"

static volatile sig_atomic_t lsc_seen;

static const int lsc_signals[] = { SIGINT, SIGTERM, SIGHUP };

static void lsc_handler(int sig)
{
    lsc_seen = (sig_atomic_t)sig;
}

static void lsc_mask(int how)
{
    sigset_t set;
    sigemptyset(&set);
    for (size_t i = 0; i < sizeof lsc_signals / sizeof lsc_signals[0]; i++)
        sigaddset(&set, lsc_signals[i]);
    sigprocmask(how, &set, NULL);
}

int lsc_install(void)
{
    struct sigaction sa = { .sa_handler = lsc_handler, .sa_flags = 0 };
    sigemptyset(&sa.sa_mask);
    lsc_mask(SIG_BLOCK);
    lsc_seen = 0;
    for (size_t i = 0; i < sizeof lsc_signals / sizeof lsc_signals[0]; i++) {
        if (sigaction(lsc_signals[i], &sa, NULL) != 0)
            return -1;
    }
    return 0;
}

void lsc_unblock(void)
{
    lsc_mask(SIG_UNBLOCK);
}

void lsc_block(void)
{
    lsc_mask(SIG_BLOCK);
}

int lsc_pending(void)
{
    return (int)lsc_seen;
}

void lsc_reset_in_child(void)
{
    struct sigaction sa = { .sa_handler = SIG_DFL };
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof lsc_signals / sizeof lsc_signals[0]; i++)
        sigaction(lsc_signals[i], &sa, NULL);
    lsc_mask(SIG_UNBLOCK);
}

void lsc_finish(int sig)
{
    lsc_reset_in_child();
    raise(sig);
}
