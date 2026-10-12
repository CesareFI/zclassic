/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: state shared by the dev.app.machine.shell leaf and its console
 *          session loop. */
#ifndef ZCL_NATIVE_MACHINE_SHELL_H
#define ZCL_NATIVE_MACHINE_SHELL_H

#include "rvmachine/rvmachine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MS_IN_CHUNK 64u
#define MS_OUT_BUF 1024u
#define MS_ESCAPE_QUIT 'q'

/* How a session ended. */
enum ms_end {
    MS_END_NONE = 0,
    MS_END_SHUTDOWN, /* the guest powered off */
    MS_END_REBOOT,   /* the guest asked for a reset; the machine takes one kernel */
    MS_END_ESCAPE,   /* the escape prefix followed by q */
    MS_END_EOF,      /* input ended and the console output went quiet */
    MS_END_SIGNAL,   /* SIGINT, SIGTERM, SIGHUP or SIGQUIT */
    MS_END_CAP,      /* the work cap was reached */
    MS_END_FAULT,    /* the engine could not continue */
    MS_END_ERROR     /* console output failed, the machine refused, or setup failed */
};

struct ms_session {
    struct rvmachine *m;
    int in_fd, out_fd;
    bool tty;            /* in_fd and out_fd are terminals: raw mode */
    uint8_t escape;      /* the control byte that prefixes a session command */
    uint64_t max_work;   /* 0: no cap */
    uint32_t eof_quiet_ms;

    uint8_t pend[2u * MS_IN_CHUNK]; /* filtered input not yet queued to the guest */
    size_t pend_pos, pend_len;
    bool prefix_seen, quit, eof;

    uint8_t out[MS_OUT_BUF];
    size_t out_len;
    uint8_t last_byte;
    bool out_failed;
    int64_t last_output_us;

    uint64_t bytes_in, bytes_out;
    int signo;
    enum rvmachine_status status; /* the refusal behind MS_END_ERROR, if any */
    bool setup_failed;            /* terminal or signal setup failed */
    bool restore_failed;          /* the terminal could not be restored */
    enum ms_end end;
    struct rvmachine_result res;
};

const char *ms_end_name(enum ms_end end);
/* The machine's console sink: buffers guest bytes for the output descriptor. */
void ms_console(void *ctx, uint8_t byte);
/* Runs the session to its end. False when the terminal or signal setup
 * failed or the terminal could not be restored; s->end says how it ended. */
bool ms_run(struct ms_session *s);

#endif
