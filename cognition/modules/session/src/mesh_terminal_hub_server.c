/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the terminal hub session loop. One connected stream, one confined
 * worker (mesh_terminal_worker, unchanged), one poll over the socket, the
 * pty master and the shell's pidfd. The loop blocks in poll until bytes or a
 * real deadline arrive; there are no sleeps and no tick. Output is read from
 * the pty straight into the frame buffer behind its 3-byte header and sent
 * with one send(); keystrokes are written to the pty from the receive buffer
 * with no intermediate copy. */

#define _GNU_SOURCE /* accept4, pipe2, pidfd — must precede every include */

#include "session/mesh_terminal_hub.h"

#include <stdio.h>
#include <string.h>

size_t mesh_terminal_hub_audit_line(
    char *out, size_t cap, const struct mesh_terminal_hub_report *r)
{
    static const char *const refusals[] = { "none", "auth", "busy", "request",
                                            "confinement", "shutdown", "exec" };
    char status[48] = "exit_code=- signal=-";
    if (r->exit_code >= 0)
        snprintf(status, sizeof status, "exit_code=%d signal=-", r->exit_code);
    else if (r->signal > 0)
        snprintf(status, sizeof status, "exit_code=- signal=%d", r->signal);
    int refusal = r->refusal >= 0 && r->refusal <= MESH_TERMINAL_HUB_REFUSE_EXEC
                      ? r->refusal : 0;
    int n = snprintf(out, cap,
        "event=TERMINAL_HUB_SESSION admitted=%u refusal=%s start=%lld end=%lld "
        "duration_s=%lld reason=%s %s bytes_in=%llu bytes_out=%llu name=%s "
        "name_verified=0 exec=\"%s\"",
        r->admitted ? 1u : 0u, refusals[refusal], (long long)r->start_unix,
        (long long)r->end_unix, (long long)(r->end_unix - r->start_unix),
        r->admitted ? mesh_terminal_close_reason_string(r->reason) : "-", status,
        (unsigned long long)r->bytes_in, (unsigned long long)r->bytes_out,
        r->name[0] ? r->name : "-", r->exec[0] ? r->exec : "-");
    return n < 0 ? 0 : ((size_t)n < cap ? (size_t)n : cap - 1u);
}

#if !defined(__linux__)

static void hub_serve_fd_arm(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    (void)fd; (void)cfg;
    memset(report, 0, sizeof(*report));
    report->refusal = MESH_TERMINAL_HUB_REFUSE_CONFINEMENT;
    report->exit_code = -1;
}

static int hub_listen_arm(uint16_t port, uint16_t *bound_port)
{
    (void)port; (void)bound_port;
    return -1;
}

static int hub_listen_run_arm(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    (void)listener; (void)cfg;
    return -1;
}

#else

#include "mesh_terminal_hub_io.h"

#include "platform/rng.h"
#include "platform/time_compat.h"
#include "session/mesh_terminal_worker.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HUB_SEND_TIMEOUT_S 10
#define HUB_PUMP_CHUNKS 8u
#define HUB_FALLBACK_POLL_MS 1000

struct hub_sess {
    int fd;
    int pidfd;                   /* -1 when the kernel has none */
    bool pty_eof;
    int64_t last_check;
    bool forced;                /* ended by us, not by the shell */
    enum mesh_terminal_close_reason forced_reason;
    struct mesh_terminal_worker w;
    struct hub_rx rx;
    uint8_t out[MESH_TERMINAL_HUB_FRAME_MAX];
};

static int64_t hub_now(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static void hub_force(struct hub_sess *s, enum mesh_terminal_close_reason why)
{
    if (!s->forced) {
        s->forced = true;
        s->forced_reason = why;
    }
}

static void hub_socket_prepare(int fd)
{
    int one = 1;
    struct timeval tv = { .tv_sec = HUB_SEND_TIMEOUT_S };
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static void hub_refuse(int fd, struct mesh_terminal_hub_report *r, int code)
{
    uint8_t c = (uint8_t)code;
    r->refusal = code;
    (void)hub_io_send_frame(fd, MESH_TERMINAL_HUB_REFUSE, &c, 1);
}

/* CHALLENGE, then one HELLO inside the handshake deadline. */
static bool hub_admit(struct hub_sess *s,
                      const struct mesh_terminal_hub_serve_cfg *cfg,
                      struct mesh_terminal_hub_report *r,
                      struct mesh_terminal_hub_hello *hello)
{
    uint8_t body[1 + MESH_TERMINAL_HUB_NONCE_BYTES];
    body[0] = MESH_TERMINAL_HUB_VERSION;
    if (!rng_fill(body + 1, MESH_TERMINAL_HUB_NONCE_BYTES) ||
        !hub_io_send_frame(s->fd, MESH_TERMINAL_HUB_CHALLENGE, body, sizeof body))
        return false;
    uint8_t type;
    const uint8_t *payload;
    size_t len;
    int wait_ms = cfg->handshake_ms ? cfg->handshake_ms : MESH_TERMINAL_HUB_HANDSHAKE_MS;
    if (hub_rx_wait(&s->rx, s->fd, wait_ms, &type, &payload, &len) != HUB_WAIT_FRAME ||
        type != MESH_TERMINAL_HUB_HELLO) {
        hub_refuse(s->fd, r, MESH_TERMINAL_HUB_REFUSE_REQUEST);
        return false;
    }
    enum mesh_terminal_hub_hello_status v = mesh_terminal_hub_hello_verify(
        hello, payload, len, cfg->key, body + 1);
    hub_rx_consume(&s->rx, len);
    if (v != MESH_TERMINAL_HUB_HELLO_OK) {
        hub_refuse(s->fd, r, v == MESH_TERMINAL_HUB_HELLO_MAC
                                 ? MESH_TERMINAL_HUB_REFUSE_AUTH
                                 : MESH_TERMINAL_HUB_REFUSE_REQUEST);
        return false;
    }
    return true;
}

static bool hub_exec_runnable(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}

/* A quiet (non-tty) client has no use for the pty echoing back what it sent. */
static void hub_echo_off(struct hub_sess *s)
{
    struct termios t;
    if (tcgetattr(s->w.master_fd, &t) != 0)
        return;
    t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
    (void)tcsetattr(s->w.master_fd, TCSANOW, &t);
}

/* 0 when the worker runs, otherwise the refusal code to send. */
static int hub_start_worker(struct hub_sess *s,
                            const struct mesh_terminal_hub_serve_cfg *cfg,
                            const struct mesh_terminal_hub_hello *hello)
{
    bool exec = hello->argc != 0;
    struct mesh_terminal_worker_config wc = {
        .shell_path = exec ? hello->argv[0] : cfg->shell_path, .workdir = cfg->workdir,
        .cols = hello->cols, .rows = hello->rows,
        .max_bytes_in = cfg->max_bytes_in, .max_bytes_out = cfg->max_bytes_out,
        .lifetime_seconds = cfg->lifetime_seconds, .idle_seconds = cfg->idle_seconds,
        .argv = exec ? hello->argv : NULL,
    };
    if (exec && (!mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_POSIX, wc.shell_path) ||
                 !hub_exec_runnable(wc.shell_path)))
        return MESH_TERMINAL_HUB_REFUSE_EXEC;
    struct zcl_result r = mesh_terminal_worker_spawn(&wc, hub_now(), &s->w);
    if (!r.ok)
        return exec && (r.code == MESH_TERMINAL_WORKER_ERR_EXEC || r.code == MESH_TERMINAL_WORKER_ERR_CONFIG)
                   ? MESH_TERMINAL_HUB_REFUSE_EXEC : MESH_TERMINAL_HUB_REFUSE_CONFINEMENT;
    s->pidfd = (int)syscall(SYS_pidfd_open, s->w.pid, 0);
    if (hello->flags & MESH_TERMINAL_HUB_HELLO_QUIET)
        hub_echo_off(s);
    return 0;
}

/* poll() timeout: the nearest lifetime/idle deadline, never earlier than a
 * real one (worker clocks are whole seconds, now_unix truncates down). */
static int hub_timeout_ms(const struct hub_sess *s)
{
    const struct mesh_terminal_worker *w = &s->w;
    int64_t now = hub_now(), next = INT64_MAX;
    if (w->lifetime_seconds)
        next = w->started_unix + (int64_t)w->lifetime_seconds;
    if (w->idle_seconds && w->last_activity_unix + (int64_t)w->idle_seconds < next)
        next = w->last_activity_unix + (int64_t)w->idle_seconds;
    int64_t ms = next == INT64_MAX ? -1 : (next - now) * 1000;
    if (ms < 0 && next != INT64_MAX)
        ms = 0;
    if (s->pidfd < 0 && (ms < 0 || ms > HUB_FALLBACK_POLL_MS))
        ms = HUB_FALLBACK_POLL_MS;
    return ms > INT32_MAX ? INT32_MAX : (int)ms;
}

/* Keystrokes and control frames from the client. false = session over. */
static bool hub_frame_in(struct hub_sess *s, uint8_t type, const uint8_t *p, size_t len)
{
    switch (type) {
    case MESH_TERMINAL_HUB_DATA: {
        struct zcl_result r = mesh_terminal_worker_input(&s->w, p, len, hub_now());
        return r.ok || r.code != MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT;
    }
    case MESH_TERMINAL_HUB_RESIZE:
        if (len == 4)
            (void)mesh_terminal_worker_resize(
                &s->w, (uint16_t)((unsigned)p[0] << 8 | p[1]),
                (uint16_t)((unsigned)p[2] << 8 | p[3]));
        return len == 4 || (hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL), false);
    case MESH_TERMINAL_HUB_CLOSE:
        hub_force(s, MESH_TERMINAL_CLOSE_REQUESTED);
        return false;
    default:
        hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
        return false;
    }
}

static bool hub_drain_frames(struct hub_sess *s)
{
    for (;;) {
        uint8_t type;
        const uint8_t *payload;
        size_t len;
        enum hub_rx_status st = hub_rx_next(&s->rx, &type, &payload, &len);
        if (st == HUB_RX_NEED_MORE)
            return true;
        if (st == HUB_RX_BAD) {
            hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
            return false;
        }
        bool more = hub_frame_in(s, type, payload, len);
        hub_rx_consume(&s->rx, len);
        if (!more)
            return false;
    }
}

static bool hub_socket_ready(struct hub_sess *s)
{
    long got = hub_rx_read(&s->rx, s->fd);
    if (got == 0 || got == -1) {
        hub_force(s, MESH_TERMINAL_CLOSE_SESSION_LOST);
        return false;
    }
    return got == -2 || hub_drain_frames(s);
}

/* Shell output to the client: read behind the header, seal, one send. */
static bool hub_pty_ready(struct hub_sess *s, bool hung_up)
{
    for (unsigned i = 0; i < HUB_PUMP_CHUNKS; i++) {
        size_t n = 0;
        struct zcl_result r = mesh_terminal_worker_output(
            &s->w, s->out + MESH_TERMINAL_HUB_HEADER_BYTES,
            MESH_TERMINAL_HUB_PAYLOAD_MAX, &n, hub_now());
        if (n) {
            size_t total = mesh_terminal_hub_frame_seal(s->out, MESH_TERMINAL_HUB_DATA, n);
            if (!hub_io_send(s->fd, s->out, total)) {
                hub_force(s, MESH_TERMINAL_CLOSE_SESSION_LOST);
                return false;
            }
        }
        if (!r.ok)
            return false; /* byte limit: the worker named the reason */
        if (n < MESH_TERMINAL_HUB_PAYLOAD_MAX) {
            s->pty_eof = n == 0 && hung_up;
            return true;
        }
    }
    return true;
}

/* The worker's budget check reads the process census, so a keystroke must
 * not pay for it: run it on a timeout, when the shell's pidfd fires, and at
 * most once per second while the session is busy. */
static bool hub_budget_due(struct hub_sess *s, bool must)
{
    int64_t now = hub_now();
    if (!must && now == s->last_check)
        return false;
    s->last_check = now;
    return mesh_terminal_worker_budget_exceeded(&s->w, now);
}

static void hub_run(struct hub_sess *s, int stop_fd)
{
    while (!s->forced) {
        struct pollfd pfd[4] = {
            { .fd = s->fd, .events = POLLIN },
            { .fd = s->pty_eof ? -1 : s->w.master_fd, .events = POLLIN },
            { .fd = s->pidfd, .events = POLLIN },
            { .fd = stop_fd, .events = POLLIN },
        };
        int ready = poll(pfd, 4, hub_timeout_ms(s));
        if (ready < 0 && errno != EINTR) {
            hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
        } else if (pfd[3].revents) {
            hub_force(s, MESH_TERMINAL_CLOSE_SHUTDOWN);
        } else if ((pfd[0].revents && !hub_socket_ready(s)) ||
                   (pfd[1].revents &&
                    !hub_pty_ready(s, pfd[1].revents & (POLLHUP | POLLERR))) ||
                   hub_budget_due(s, ready == 0 || pfd[2].revents)) {
            return;
        }
    }
}

static void hub_finish(struct hub_sess *s, struct mesh_terminal_hub_report *r)
{
    bool natural = !s->forced;
    if (natural || s->forced_reason == MESH_TERMINAL_CLOSE_REQUESTED) {
        s->pty_eof = false;
        (void)hub_pty_ready(s, false); /* last words of a shell that just exited */
    }
    enum mesh_terminal_close_reason why = s->forced ? s->forced_reason : s->w.close_reason;
    int code = -1, sig = 0;
    if (natural && why == MESH_TERMINAL_CLOSE_WORKER_EXITED) {
        sig = s->w.term_signal;
        code = sig ? -1 : s->w.exit_code;
    }
    mesh_terminal_worker_kill(&s->w);
    r->reason = why;
    r->exit_code = code;
    r->signal = sig;
    r->bytes_in = s->w.bytes_in;
    r->bytes_out = s->w.bytes_out;
    uint8_t body[4] = { (uint8_t)why,
        (uint8_t)((code >= 0 ? MESH_TERMINAL_HUB_EXIT_HAS_CODE : 0) |
                  (sig > 0 ? MESH_TERMINAL_HUB_EXIT_HAS_SIGNAL : 0)),
        (uint8_t)(code >= 0 ? code : 0), (uint8_t)sig };
    (void)hub_io_send_frame(s->fd, MESH_TERMINAL_HUB_EXIT, body, sizeof body);
}

static void hub_serve_fd_arm(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    struct hub_sess s = { .fd = fd, .pidfd = -1 };
    struct mesh_terminal_hub_hello hello;
    memset(report, 0, sizeof(*report));
    report->exit_code = -1;
    report->start_unix = hub_now();
    report->reason = MESH_TERMINAL_CLOSE_INTERNAL;
    snprintf(report->exec, sizeof report->exec, "-");
    hub_socket_prepare(fd);
    if (hub_admit(&s, cfg, report, &hello)) {
        snprintf(report->name, sizeof report->name, "%s", hello.name);
        mesh_terminal_hub_exec_label(report->exec, sizeof report->exec, hello.argv, hello.argc);
        int refusal = hub_start_worker(&s, cfg, &hello);
        if (refusal) {
            hub_refuse(fd, report, refusal);
        } else if (hub_io_send_frame(fd, MESH_TERMINAL_HUB_READY, NULL, 0)) {
            report->admitted = true;
            if (hub_drain_frames(&s))
                hub_run(&s, cfg->stop_fd);
            hub_finish(&s, report);
        } else {
            mesh_terminal_worker_kill(&s.w);
        }
    }
    if (s.pidfd >= 0)
        close(s.pidfd);
    report->end_unix = hub_now();
}

static int hub_listen_arm(uint16_t port, uint16_t *bound_port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t alen = sizeof a;
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return -1;
    }
    if (bound_port)
        *bound_port = ntohs(a.sin_port);
    return fd;
}

/* ── Supervisor ───────────────────────────────────────────────────────── */

static int g_hub_signal_pipe[2] = { -1, -1 };

static void hub_on_signal(int sig)
{
    int saved = errno;
    char c = sig == SIGCHLD ? 'C' : 'T';
    if (g_hub_signal_pipe[1] >= 0)
        (void)!write(g_hub_signal_pipe[1], &c, 1);
    errno = saved;
}

/* The supervisor also wants SIGCHLD; a session child must not (the shell's
 * exit is its own business and a stray byte would read as a stop). */
static bool hub_signals_install(bool watch_children)
{
    struct sigaction act = { .sa_handler = hub_on_signal, .sa_flags = SA_NOCLDSTOP };
    sigemptyset(&act.sa_mask);
    if (pipe2(g_hub_signal_pipe, O_NONBLOCK | O_CLOEXEC) != 0)
        return false;
    if (watch_children)
        sigaction(SIGCHLD, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);
    return true;
}

static void hub_signals_reset(void)
{
    signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    close(g_hub_signal_pipe[0]);
    close(g_hub_signal_pipe[1]);
    g_hub_signal_pipe[0] = g_hub_signal_pipe[1] = -1;
}

/* A session child: its own stop pipe, so SIGTERM from the supervisor ends
 * the session through the normal path and the worker's group is killed. */
static void hub_child(int fd, int listener,
                      const struct mesh_terminal_hub_listen_cfg *cfg)
{
    struct mesh_terminal_hub_serve_cfg serve = cfg->serve;
    struct mesh_terminal_hub_report report;
    char line[768];
    close(listener);
    hub_signals_reset();
    if (hub_signals_install(false))
        serve.stop_fd = g_hub_signal_pipe[0];
    mesh_terminal_hub_serve_fd(fd, &serve, &report);
    size_t n = mesh_terminal_hub_audit_line(line, sizeof line - 1u, &report);
    line[n++] = '\n';
    (void)!write(cfg->audit_fd, line, n);
    _exit(0);
}

static void hub_busy(int fd)
{
    uint8_t c = MESH_TERMINAL_HUB_REFUSE_BUSY;
    (void)hub_io_send_frame(fd, MESH_TERMINAL_HUB_REFUSE, &c, 1);
}

struct hub_sup {
    unsigned active, started, done;
    bool stopping;
    pid_t kids[MESH_TERMINAL_HUB_ACTIVE_MAX];
};

static void hub_sup_reap(struct hub_sup *sup)
{
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
            if (sup->kids[i] == pid) {
                sup->kids[i] = 0;
                sup->active--;
                sup->done++;
            }
    }
}

static void hub_sup_accept(struct hub_sup *sup, int listener,
                           const struct mesh_terminal_hub_listen_cfg *cfg)
{
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    unsigned limit = cfg->max_active < MESH_TERMINAL_HUB_ACTIVE_MAX
                         ? cfg->max_active : MESH_TERMINAL_HUB_ACTIVE_MAX;
    if (fd < 0)
        return;
    if (sup->active >= limit) {
        hub_busy(fd);
        close(fd);
        return;
    }
    pid_t pid = fork();
    if (pid == 0)
        hub_child(fd, listener, cfg);
    close(fd);
    if (pid < 0)
        return;
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
        if (!sup->kids[i]) {
            sup->kids[i] = pid;
            break;
        }
    sup->active++;
    sup->started++;
}

static void hub_sup_stop(struct hub_sup *sup)
{
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
        if (sup->kids[i])
            (void)kill(sup->kids[i], SIGTERM);
    while (sup->active) {
        if (waitpid(-1, NULL, 0) > 0)
            sup->active--;
        else if (errno != EINTR)
            break;
    }
}

/* A stop request and finished children arrive as bytes on the signal pipe. */
static void hub_sup_signals(struct hub_sup *sup)
{
    char sig[16];
    ssize_t n = read(g_hub_signal_pipe[0], sig, sizeof sig);
    for (ssize_t i = 0; i < n; i++)
        sup->stopping = sup->stopping || sig[i] == 'T';
    hub_sup_reap(sup);
}

/* One blocking wait: a signal byte or a connection. false on a poll failure. */
static bool hub_sup_step(struct hub_sup *sup, int listener,
                         const struct mesh_terminal_hub_listen_cfg *cfg, bool full)
{
    struct pollfd pfd[2] = { { .fd = g_hub_signal_pipe[0], .events = POLLIN },
                             { .fd = full ? -1 : listener, .events = POLLIN } };
    if (poll(pfd, 2, -1) < 0 && errno != EINTR)
        return false;
    if (pfd[0].revents)
        hub_sup_signals(sup);
    if (pfd[1].revents && !sup->stopping)
        hub_sup_accept(sup, listener, cfg);
    return true;
}

static int hub_listen_run_arm(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    struct hub_sup sup = { 0 };
    if (listener < 0 || !cfg || !hub_signals_install(true)) {
        if (listener >= 0)
            close(listener);
        return 1;
    }
    while (!sup.stopping) {
        bool full = cfg->max_sessions && sup.started >= cfg->max_sessions;
        if ((full && sup.active == 0) || !hub_sup_step(&sup, listener, cfg, full))
            break;
    }
    hub_sup_stop(&sup);
    hub_signals_reset();
    close(listener);
    return 0;
}

#endif /* __linux__ */

void mesh_terminal_hub_serve_fd(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    hub_serve_fd_arm(fd, cfg, report);
}

int mesh_terminal_hub_listen(uint16_t port, uint16_t *bound_port)
{
    return hub_listen_arm(port, bound_port);
}

int mesh_terminal_hub_listen_run(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    return hub_listen_run_arm(listener, cfg);
}
