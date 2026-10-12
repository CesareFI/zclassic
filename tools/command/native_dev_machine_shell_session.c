/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the console session of dev.app.machine.shell: host terminal in raw
 *          mode, input and output pumped around the machine's run loop, idle
 *          guest time spent asleep in the host.
 *
 * The machine runs in slices of MS_SLICE_WORK work units. Between slices the
 * loop reads at most MS_IN_CHUNK bytes of input, and only when the previous
 * chunk has been queued to the guest and its serial queue has room, so the
 * guest console's acceptance bounds how much is read. Input passes through a
 * two-state filter for the escape prefix.
 *
 * The machine runs with wait_stops. When the hart waits with nothing to run,
 * the loop sleeps in poll() on the input descriptor for at most
 * MS_IDLE_MAX_MS and then advances guest time by the host time that passed,
 * never past the armed timer. While idle, guest time follows the host
 * monotonic clock; while running, it is retired instructions / 10.
 *
 * Signals only set a flag. The terminal attributes and the signal dispositions
 * are restored in ms_run, the one exit of every session. */

#include "native_dev_machine_shell.h"

#include "platform/time_compat.h"

const char *ms_end_name(enum ms_end end)
{
    static const char *const names[] = {"none", "guest_shutdown", "guest_reboot", "escape",
                                        "stdin_eof", "signal", "work_cap", "guest_fault",
                                        "error"};
    return (unsigned)end < sizeof names / sizeof names[0] ? names[end] : "error";
}

#if !defined(_WIN32)
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define MS_SLICE_WORK 16384u
#define MS_IDLE_MAX_MS 100
#define MS_UNITS_PER_US (RVMACHINE_TIMEBASE_HZ / 1000000u)

static volatile sig_atomic_t g_ms_signal;

static void ms_on_signal(int signo) { g_ms_signal = signo; }


/* ---- signals and terminal ---- */

static const int ms_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
#define MS_SIGNALS (sizeof ms_signals / sizeof ms_signals[0])

struct ms_saved {
    struct sigaction old[MS_SIGNALS];
    struct sigaction old_pipe;
    size_t installed;
    bool pipe_ignored;
    struct termios tio;
    bool tio_saved;
};

static void ms_signals_leave(struct ms_saved *sv)
{
    for (size_t i = 0; i < sv->installed; i++) (void)sigaction(ms_signals[i], &sv->old[i], NULL);
    if (sv->pipe_ignored) (void)sigaction(SIGPIPE, &sv->old_pipe, NULL);
    sv->installed = 0;
    sv->pipe_ignored = false;
}

/* Handlers without SA_RESTART, so a blocked read, write or poll returns. */
static bool ms_signals_enter(struct ms_saved *sv)
{
    struct sigaction act, ign;
    memset(&act, 0, sizeof act);
    memset(&ign, 0, sizeof ign);
    act.sa_handler = ms_on_signal;
    ign.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    sigemptyset(&ign.sa_mask);
    g_ms_signal = 0;
    for (; sv->installed < MS_SIGNALS; sv->installed++)
        if (sigaction(ms_signals[sv->installed], &act, &sv->old[sv->installed]) != 0) {
            ms_signals_leave(sv);
            return false;
        }
    sv->pipe_ignored = sigaction(SIGPIPE, &ign, &sv->old_pipe) == 0;
    if (sv->pipe_ignored) return true;
    ms_signals_leave(sv);
    return false;
}

static bool ms_term_apply(int fd, int when, const struct termios *tio)
{
    int rc;
    do rc = tcsetattr(fd, when, tio);
    while (rc != 0 && errno == EINTR);
    return rc == 0;
}

static bool ms_term_enter(const struct ms_session *s, struct ms_saved *sv)
{
    struct termios raw;
    if (tcgetattr(s->in_fd, &sv->tio) != 0) return false;
    raw = sv->tio;
    raw.c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    raw.c_oflag &= ~(tcflag_t)OPOST;
    raw.c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    raw.c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    sv->tio_saved = true;
    if (ms_term_apply(s->in_fd, TCSANOW, &raw)) return true;
    sv->tio_saved = false;
    return false;
}

/* TCSAFLUSH drops input typed but not read, so it is not replayed to the shell
 * that started the session. */
static bool ms_term_leave(const struct ms_session *s, const struct ms_saved *sv)
{
    return !sv->tio_saved || ms_term_apply(s->in_fd, TCSAFLUSH, &sv->tio);
}

/* ---- output ---- */

static bool ms_write_all(struct ms_session *s, const uint8_t *p, size_t n)
{
    while (n != 0) {
        ssize_t w = write(s->out_fd, p, n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
            continue;
        }
        if (g_ms_signal != 0) return false;
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && errno == EAGAIN) {
            struct pollfd out = {.fd = s->out_fd, .events = POLLOUT};
            (void)poll(&out, 1, MS_IDLE_MAX_MS);
            continue;
        }
        return false;
    }
    return true;
}

static void ms_flush(struct ms_session *s)
{
    if (s->out_len == 0) return;
    s->last_output_us = platform_time_monotonic_us();
    s->last_byte = s->out[s->out_len - 1u];
    if (!s->out_failed && ms_write_all(s, s->out, s->out_len)) s->bytes_out += s->out_len;
    else if (!s->out_failed) {
        s->out_failed = true;
        rvmachine_request_stop(s->m);
    }
    s->out_len = 0;
}

static void ms_console_byte(struct ms_session *s, uint8_t byte)
{
    s->out[s->out_len++] = byte;
    if (s->out_len == sizeof s->out) ms_flush(s);
}

/* The receipt that follows on the output starts on a line of its own. */
static void ms_finish_line(struct ms_session *s)
{
    static const uint8_t crlf[] = {'\r', '\n'};
    if (s->bytes_out == 0 || s->last_byte == '\n' || s->out_failed) return;
    (void)ms_write_all(s, s->tty ? crlf : crlf + 1, s->tty ? 2u : 1u);
}

/* ---- input ---- */

static void ms_push(struct ms_session *s, uint8_t byte) { s->pend[s->pend_len++] = byte; }

/* Escape prefix then q ends the session; the prefix twice sends it once; the
 * prefix then any other byte sends both bytes. */
static void ms_filter(struct ms_session *s, const uint8_t *in, size_t n)
{
    for (size_t i = 0; i < n && !s->quit; i++) {
        uint8_t b = in[i];
        if (!s->prefix_seen && b == s->escape) {
            s->prefix_seen = true;
            continue;
        }
        if (!s->prefix_seen) {
            ms_push(s, b);
            continue;
        }
        s->prefix_seen = false;
        if (b == MS_ESCAPE_QUIT) s->quit = true;
        else {
            ms_push(s, s->escape);
            if (b != s->escape) ms_push(s, b);
        }
    }
}

static size_t ms_room(const struct ms_session *s)
{
    return RVMACHINE_INPUT_MAX - s->m->serial_in.count;
}

static bool ms_can_read(const struct ms_session *s)
{
    return !s->eof && !s->quit && s->pend_len == 0 && ms_room(s) != 0;
}

static void ms_set_eof(struct ms_session *s)
{
    s->eof = true;
    if (s->prefix_seen) ms_push(s, s->escape);
    s->prefix_seen = false;
    s->last_output_us = platform_time_monotonic_us();
}

static void ms_read_input(struct ms_session *s)
{
    uint8_t buf[MS_IN_CHUNK];
    struct pollfd in = {.fd = s->in_fd, .events = POLLIN};
    ssize_t n;
    if (!ms_can_read(s) || poll(&in, 1, 0) <= 0) return;
    n = (in.revents & POLLIN) != 0 ? read(s->in_fd, buf, sizeof buf) : 0;
    if (n > 0) ms_filter(s, buf, (size_t)n);
    else if (n == 0 || (errno != EINTR && errno != EAGAIN)) ms_set_eof(s);
}

static void ms_feed(struct ms_session *s)
{
    size_t n = s->pend_len - s->pend_pos;
    if (n > ms_room(s)) n = ms_room(s);
    if (n == 0) return;
    s->bytes_in += rvmachine_console_input(s->m, s->pend + s->pend_pos, n);
    s->pend_pos += n;
    if (s->pend_pos == s->pend_len) s->pend_pos = s->pend_len = 0;
}

/* ---- idle ---- */

static int ms_idle_timeout_ms(const struct ms_session *s)
{
    uint64_t now = rvmachine_time(s->m), deadline = rvmachine_timer_deadline(s->m);
    uint64_t units_per_ms = (uint64_t)MS_UNITS_PER_US * 1000u;
    if (deadline != RVMACHINE_NO_DEADLINE && deadline > now) {
        uint64_t ms = (deadline - now) / units_per_ms + 1u;
        if (ms < (uint64_t)MS_IDLE_MAX_MS) return (int)ms;
    }
    return MS_IDLE_MAX_MS;
}

static void ms_sleep(const struct ms_session *s, int timeout_ms)
{
    struct pollfd in = {.fd = s->in_fd, .events = POLLIN};
    (void)poll(&in, ms_can_read(s) ? 1u : 0u, timeout_ms);
}

/* Sleeps until input, the armed timer or MS_IDLE_MAX_MS, then moves guest time
 * by the host time that passed, not beyond the timer. */
static void ms_idle(struct ms_session *s)
{
    uint64_t now, target, deadline;
    int64_t start, elapsed;
    if ((rvmachine_pending(s->m) & RVMACHINE_PENDING_RUNNABLE) != 0u) return;
    start = platform_time_monotonic_us();
    ms_sleep(s, ms_idle_timeout_ms(s));
    now = rvmachine_time(s->m);
    deadline = rvmachine_timer_deadline(s->m);
    elapsed = platform_time_monotonic_us() - start;
    target = now + (uint64_t)(elapsed > 0 ? elapsed : 0) * MS_UNITS_PER_US;
    if (deadline != RVMACHINE_NO_DEADLINE && target > deadline) target = deadline;
    (void)rvmachine_advance_time(s->m, target);
}

/* ---- the loop ---- */

static uint64_t ms_used(const struct ms_session *s)
{
    return s->res.retired + s->res.fw_calls + s->res.device_work;
}

static bool ms_quiet(const struct ms_session *s)
{
    return platform_time_monotonic_us() - s->last_output_us >= (int64_t)s->eof_quiet_ms * 1000;
}

static void ms_check(struct ms_session *s)
{
    if (g_ms_signal != 0) {
        s->end = MS_END_SIGNAL;
        s->signo = (int)g_ms_signal;
    } else if (s->out_failed) {
        s->end = MS_END_ERROR;
    } else if (s->quit) {
        ms_feed(s);
        s->end = MS_END_ESCAPE;
    } else if (s->max_work != 0 && ms_used(s) >= s->max_work) {
        s->end = MS_END_CAP;
    } else if (s->eof && s->pend_len == 0 && ms_quiet(s)) {
        s->end = MS_END_EOF;
    }
}

static void ms_stopped(struct ms_session *s)
{
    switch (s->res.stop) {
    case RVMACHINE_STOP_SHUTDOWN: s->end = MS_END_SHUTDOWN; break;
    case RVMACHINE_STOP_REBOOT: s->end = MS_END_REBOOT; break;
    case RVMACHINE_STOP_FAULT: s->end = MS_END_FAULT; break;
    case RVMACHINE_STOP_REQUESTED: s->end = MS_END_ERROR; break;
    case RVMACHINE_STOP_IDLE:
    case RVMACHINE_STOP_WAIT: ms_idle(s); break;
    case RVMACHINE_STOP_BUDGET: break;
    }
}

static void ms_step(struct ms_session *s)
{
    uint64_t slice = MS_SLICE_WORK;
    enum rvmachine_status status;
    if (s->max_work != 0 && s->max_work - ms_used(s) < slice) slice = s->max_work - ms_used(s);
    status = rvmachine_run(s->m, slice, &s->res);
    ms_flush(s);
    if (status == RVMACHINE_ERR_WAITING) ms_idle(s);
    else if (status != RVMACHINE_OK) {
        s->status = status;
        s->end = MS_END_ERROR;
    } else ms_stopped(s);
}

static void ms_loop(struct ms_session *s)
{
    s->last_output_us = platform_time_monotonic_us();
    while (s->end == MS_END_NONE) {
        ms_check(s);
        if (s->end != MS_END_NONE) break;
        ms_read_input(s);
        ms_feed(s);
        ms_step(s);
    }
    ms_flush(s);
    if (s->out_failed && s->end != MS_END_SIGNAL) s->end = MS_END_ERROR; /* output was lost */
}

static bool ms_run_posix(struct ms_session *s)
{
    struct ms_saved sv;
    memset(&sv, 0, sizeof sv);
    if (!ms_signals_enter(&sv) || (s->tty && !ms_term_enter(s, &sv))) {
        ms_signals_leave(&sv);
        s->setup_failed = true;
        s->end = MS_END_ERROR;
        return false;
    }
    ms_loop(s);
    ms_finish_line(s);
    s->restore_failed = !ms_term_leave(s, &sv);
    ms_signals_leave(&sv);
    return !s->restore_failed;
}
#endif

void ms_console(void *ctx, uint8_t byte)
{
#if !defined(_WIN32)
    ms_console_byte(ctx, byte);
#else
    (void)ctx;
    (void)byte;
#endif
}

bool ms_run(struct ms_session *s)
{
#if !defined(_WIN32)
    return ms_run_posix(s);
#else
    s->setup_failed = true;
    s->end = MS_END_ERROR;
    return false;
#endif
}
