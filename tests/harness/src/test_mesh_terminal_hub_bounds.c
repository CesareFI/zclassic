/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Residual bounds for the terminal hub, run from test_mesh_terminal_hub: a
 * stopped supervisor leaves no worker group behind, every hub write is
 * bounded by its deadline even when another writer wins the readiness, and
 * max_sessions counts every accepted connection (a busy refusal included).
 * The write races are made exact with the before-write seam: the hook fills
 * the pipe between "ready" and "write", which is what a second writer does. */

#define _GNU_SOURCE

#include "test/test_core.h"
#include "session/mesh_terminal_hub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_fbsh;
static const char *g_dir;
static int g_note_fd = -1;

static int check(int failures, bool ok, const char *label)
{
    printf("  %s... %s\n", label, ok ? "OK" : "FAIL");
    return failures + (ok ? 0 : 1);
}

static void base_cfg(struct mesh_terminal_hub_serve_cfg *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    for (int i = 0; i < 32; i++)
        cfg->key[i] = (uint8_t)(0x5a + i * 3);
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->max_bytes_in = 1u << 20;
    cfg->max_bytes_out = 1u << 24;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
    cfg->stop_fd = -1;
}

static int tcp_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Waits for a child to exit on its own; kills it when it does not. */
static bool exits_within(pid_t pid, int ms, int *status)
{
    for (int waited = 0; waited <= ms; waited += 20) {
        if (waitpid(pid, status, WNOHANG) == pid)
            return true;
        poll(NULL, 0, 20); /* real-clock: waits on another process; there is no seam to inject */
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return false;
}

static bool readable_within(int fd, int ms)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, ms) > 0;
}

/* Reads until `needle` appears in buf, within ms. */
static bool read_until(int fd, const char *needle, char *buf, size_t cap, int ms)
{
    size_t fill = 0;
    buf[0] = '\0';
    for (int waited = 0; waited < ms && fill + 1 < cap; waited += 20) {
        ssize_t n = readable_within(fd, 20) ? read(fd, buf + fill, cap - fill - 1) : 0;
        if (n > 0) {
            fill += (size_t)n;
            buf[fill] = '\0';
        }
        if (strstr(buf, needle))
            return true;
    }
    return false;
}

/* Members of a process group that are running (a zombie is already dead). */
static unsigned group_running(pid_t pgid)
{
    unsigned live = 0;
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    while (proc && (ent = readdir(proc)) != NULL) {
        char path[64], buf[512];
        long pid = strtol(ent->d_name, NULL, 10);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        int fd = open(path, O_RDONLY);
        ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
        if (fd >= 0)
            close(fd);
        const char *after = n > 0 ? (buf[n] = '\0', strrchr(buf, ')')) : NULL;
        char state = 0;
        long ppid = 0, pgrp = 0;
        if (after && sscanf(after + 1, " %c %ld %ld", &state, &ppid, &pgrp) == 3 && pgrp == pgid && state != 'Z')
            live++;
    }
    if (proc)
        closedir(proc);
    return live;
}

/* The production client in a child, on pipes. */
struct cl {
    pid_t pid;
    int keys_w, screen_r, res_r, ev_w;
};

static bool cl_start(struct cl *c, int net_fd, int drop_fd, const char *const *argv)
{
    int keys[2], screen[2], res[2], ev[2];
    if (pipe2(keys, O_CLOEXEC) || pipe2(screen, O_CLOEXEC) || pipe2(res, O_CLOEXEC) || pipe2(ev, O_CLOEXEC))
        return false;
    c->pid = fork();
    if (c->pid == 0) {
        struct mesh_terminal_hub_client_cfg cfg;
        struct mesh_terminal_hub_client_result r;
        struct mesh_terminal_hub_serve_cfg sc;
        if (drop_fd >= 0)
            close(drop_fd);
        base_cfg(&sc);
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.key, sc.key, sizeof cfg.key);
        cfg.name = "bounds";
        cfg.argv = argv;
        cfg.net_fd = net_fd;
        cfg.in_fd = keys[0];
        cfg.out_fd = screen[1];
        cfg.event_fd = ev[0];
        cfg.handshake_ms = 5000;
        mesh_terminal_hub_client_run(&cfg, &r);
        ssize_t w = write(res[1], &r, sizeof r);
        _exit(w == (ssize_t)sizeof r ? 0 : 1);
    }
    close(keys[0]); close(screen[1]); close(res[1]); close(ev[0]);
    c->keys_w = keys[1];
    c->screen_r = screen[0];
    c->res_r = res[0];
    c->ev_w = ev[1];
    return c->pid > 0;
}

static void cl_end(struct cl *c)
{
    int st;
    kill(c->pid, SIGKILL);
    waitpid(c->pid, &st, 0);
    close(c->keys_w); close(c->screen_r); close(c->res_r); close(c->ev_w);
}

/* ── the hook: a second writer wins the readiness ─────────────────────── */

static void fill_pipe_fd(int fd)
{
    char chunk[4096];
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
        return;
    memset(chunk, 'f', sizeof chunk);
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    while (write(fd, chunk, sizeof chunk) > 0) {}
    fcntl(fd, F_SETFL, fl);
}

static void note(void)
{
    ssize_t w = g_note_fd >= 0 ? write(g_note_fd, "!", 1) : 0;
    (void)w;
}

static void hook_fill(int fd)
{
    fill_pipe_fd(fd);
    note();
}

static void hook_fill_second(int fd)
{
    static int calls;
    if (++calls == 2)
        hook_fill(fd);
}

/* ── a stopped supervisor leaves no worker group ──────────────────────── */

static int stop_orphan_case(void)
{
    int failures = 0, status = 0, leader = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char screen[256];
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c",
        "trap '' HUP; echo PGID=$$; (while :; do :; done)", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.stop_grace_ms = 300;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int listener = cfg.audit_fd < 0 ? -1 : mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        mesh_terminal_hub_testing_children_ignore_term(true); /* a wedged session */
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    }
    close(listener);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run);
    bool said = up && read_until(c.screen_r, "\n", screen, sizeof screen, 8000) && strstr(screen, "PGID=") &&
                sscanf(strstr(screen, "PGID="), "PGID=%d", &leader) == 1;
    failures = check(failures, said && group_running(leader) >= 2,
                     "worker stop: the worker group (a HUP-ignoring leader and its child) is running");
    if (sup > 0)
        kill(sup, SIGTERM);
    bool stopped = sup > 0 && exits_within(sup, 5000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "worker stop: SIGTERM ends the supervisor although the session ignores it");
    for (int i = 0; said && i < 150 && group_running(leader); i++)
        poll(NULL, 0, 20); /* real-clock: the kernel finishes the kill asynchronously; no seam */
    bool gone = said && group_running(leader) == 0;
    failures = check(failures, gone, "worker stop: the WORKER group is gone, not only the supervisor");
    if (said && !gone)
        kill(-leader, SIGKILL);
    if (up)
        cl_end(&c);
    if (net >= 0)
        close(net);
    close(cfg.audit_fd);
    return failures;
}

/* ── the audit write is bounded when another writer takes the room ────── */

static int audit_race_case(void)
{
    int failures = 0, status = 0, sink[2];
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char errpath[300], errtext[512] = "";
    uint16_t port = 0;
    const char *const run[] = { "/bin/true", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.max_sessions = 1;
    cfg.audit_wait_ms = 300;
    snprintf(errpath, sizeof errpath, "%s/race-stderr.log", g_dir);
    if (pipe2(sink, O_CLOEXEC) != 0)
        return check(failures, false, "audit race setup");
    cfg.audit_fd = sink[1];
    int listener = mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        int e = open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (e >= 0)
            dup2(e, STDERR_FILENO);
        mesh_terminal_hub_testing_before_write(hook_fill); /* children inherit it */
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    }
    close(listener);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run);
    bool stopped = up && exits_within(sup, 6000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "audit race: a line whose room another writer took is dropped at its deadline");
    close(sink[0]);
    close(sink[1]);
    int fd = open(errpath, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, errtext, sizeof errtext - 1);
    errtext[n > 0 ? n : 0] = '\0';
    if (fd >= 0)
        close(fd);
    failures = check(failures, strstr(errtext, "event=TERMINAL_HUB_AUDIT_DROPPED count=1") != NULL,
                     "audit race: the dropped line is counted");
    if (up)
        cl_end(&c);
    if (net >= 0)
        close(net);
    return failures;
}

/* ── the client's output is bounded and a stop is still served ────────── */

static void frame_out(int fd, uint8_t type, const void *payload, size_t len)
{
    uint8_t f[MESH_TERMINAL_HUB_FRAME_MAX];
    if (len)
        memcpy(f + MESH_TERMINAL_HUB_HEADER_BYTES, payload, len);
    size_t n = mesh_terminal_hub_frame_seal(f, type, len);
    ssize_t w = write(fd, f, n);
    (void)w;
}

/* A scripted server: challenge, ready, one DATA, and optionally an EXIT. */
static bool script_client(struct cl *c, int *server, void (*hook)(int), const void *exit_body)
{
    int sv[2], note_p[2];
    uint8_t ch[33] = { MESH_TERMINAL_HUB_VERSION };
    memset(ch + 1, 0x42, 32);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || pipe2(note_p, O_CLOEXEC) != 0)
        return false;
    g_note_fd = note_p[1];
    mesh_terminal_hub_testing_before_write(hook);
    bool ok = cl_start(c, sv[1], sv[0], NULL);
    mesh_terminal_hub_testing_before_write(NULL);
    close(sv[1]);
    close(note_p[1]);
    g_note_fd = note_p[0]; /* the parent waits on the read end */
    *server = sv[0];
    frame_out(sv[0], MESH_TERMINAL_HUB_CHALLENGE, ch, sizeof ch);
    frame_out(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    frame_out(sv[0], MESH_TERMINAL_HUB_DATA, "x", 1);
    if (exit_body)
        frame_out(sv[0], MESH_TERMINAL_HUB_EXIT, exit_body, 4);
    return ok;
}

static int client_stop_case(void)
{
    int failures = 0, server;
    struct cl c;
    struct mesh_terminal_hub_client_result r;
    memset(&r, 0, sizeof r);
    bool up = script_client(&c, &server, hook_fill, NULL);
    bool wedged = up && readable_within(g_note_fd, 3000);
    ssize_t w = wedged ? write(c.ev_w, "S", 1) : 0;
    (void)w;
    bool prompt = wedged && readable_within(c.res_r, 3000) && read(c.res_r, &r, sizeof r) == (ssize_t)sizeof r;
    failures = check(failures, prompt && r.exit_code == 130 && !strcmp(r.code, "INTERRUPTED"),
                     "client output: a stop is served although another writer filled the screen pipe");
    if (up)
        cl_end(&c);
    close(server);
    close(g_note_fd);
    return failures;
}

static int client_tail_case(void)
{
    static const uint8_t done[4] = { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 0, 0 };
    int failures = 0, server;
    struct cl c;
    struct mesh_terminal_hub_client_result r;
    memset(&r, 0, sizeof r);
    bool up = script_client(&c, &server, hook_fill_second, done);
    bool filled = up && readable_within(g_note_fd, 3000);
    bool fin = filled && readable_within(c.res_r, 3000) && read(c.res_r, &r, sizeof r) == (ssize_t)sizeof r;
    failures = check(failures, fin && r.exit_code == 0 && r.output_dropped == 1,
                     "client output: the closing newline is dropped at its deadline and counted");
    if (up)
        cl_end(&c);
    close(server);
    close(g_note_fd);
    return failures;
}

/* ── max_sessions counts every accepted connection ────────────────────── */

static int busy_count_case(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char screen[64];
    uint8_t refuse[16] = { 0 };
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c", "echo UP; read x", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.max_sessions = 2;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int listener = cfg.audit_fd < 0 ? -1 : mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0)
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    close(listener);
    int a = sup > 0 ? tcp_connect(port) : -1;
    bool up = a >= 0 && cl_start(&c, a, -1, run) && read_until(c.screen_r, "UP", screen, sizeof screen, 8000);
    int b = up ? tcp_connect(port) : -1;
    ssize_t got = b >= 0 && readable_within(b, 3000) ? read(b, refuse, sizeof refuse) : -1;
    failures = check(failures, got >= 4 && refuse[0] == MESH_TERMINAL_HUB_REFUSE &&
                     refuse[3] == MESH_TERMINAL_HUB_REFUSE_BUSY,
                     "max_sessions: the second connection is refused busy");
    ssize_t w = up ? write(c.keys_w, "\n", 1) : 0;
    (void)w;
    bool stopped = sup > 0 && exits_within(sup, 8000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "max_sessions: a busy refusal counts, so the supervisor stops by itself after two connections");
    if (up)
        cl_end(&c);
    if (b >= 0)
        close(b);
    if (a >= 0)
        close(a);
    close(cfg.audit_fd);
    return failures;
}

int test_mesh_terminal_hub_bounds(const char *fbsh, const char *dir)
{
    g_fbsh = fbsh;
    g_dir = dir;
    signal(SIGPIPE, SIG_IGN);
    return stop_orphan_case() + audit_race_case() + client_stop_case() +
           client_tail_case() + busy_count_case();
}

#else /* __linux__ */

int test_mesh_terminal_hub_bounds(const char *fbsh, const char *dir)
{
    (void)fbsh; (void)dir;
    return 0;
}

#endif
