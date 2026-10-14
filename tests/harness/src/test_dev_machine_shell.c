/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proofs for dev.app.machine.shell, through the command dispatcher.
 * The guests are the committed images of tests/fixtures/rvmachine, read only.
 * The console is a pair of pipes ("stdio":"pipe") or a pseudo-terminal pair.
 *
 * Covered: input bytes reach the guest and its output returns in order; the
 * end by guest shutdown, end of input, the work cap, the escape sequence and
 * a signal; the escape prefix rules; guest timers across idle sleeps; the
 * receipt file; the named refusals; and the terminal attributes, which are
 * raw during the session and equal to the original afterwards, on the escape
 * exit and on the signal exit; and, through the built z23-dev binary, that
 * stdout holds only the console bytes while the envelope goes to stderr. */
#define _XOPEN_SOURCE 700
#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "rvmachine/rvmachine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define TMS_FIXTURES "tests/fixtures/rvmachine/"
#define TMS_WIRE 16384u
#define TMS_OUT 4096u
#define ESC "\x1d"
/* A run that retires instructions is bounded by a work cap. A guest that waits
 * in wfi retires none, so the cap cannot bound it: every pipe-mode run is also
 * bounded by a watchdog that sends the session SIGTERM after TMS_WATCHDOG_S
 * seconds, which turns a hang into failed assertions. */
#define TMS_GUARD ",\"max_instr\":50000000"
#define TMS_WATCHDOG_S 20

static void tms_watchdog(int sig)
{
    (void)sig;
    (void)kill(getpid(), SIGTERM);
}

/* SIGTERM is ignored while no session owns it, so a late watchdog cannot end
 * the test process. */
struct tms_guard {
    struct sigaction alarm, term;
};

static void tms_guard_enter(struct tms_guard *g)
{
    struct sigaction wd, ign;
    struct itimerval t = {.it_value = {.tv_sec = TMS_WATCHDOG_S}};
    memset(&wd, 0, sizeof wd);
    memset(&ign, 0, sizeof ign);
    wd.sa_handler = tms_watchdog;
    ign.sa_handler = SIG_IGN;
    sigemptyset(&wd.sa_mask);
    sigemptyset(&ign.sa_mask);
    (void)sigaction(SIGTERM, &ign, &g->term);
    (void)sigaction(SIGALRM, &wd, &g->alarm);
    (void)setitimer(ITIMER_REAL, &t, NULL);
}

static void tms_guard_leave(const struct tms_guard *g)
{
    struct itimerval off = {{0, 0}, {0, 0}};
    (void)setitimer(ITIMER_REAL, &off, NULL);
    (void)sigaction(SIGALRM, &g->alarm, NULL);
    (void)sigaction(SIGTERM, &g->term, NULL);
}

struct tms_run {
    char wire[TMS_WIRE];
    struct json_value doc;
    bool parsed;
    char out[TMS_OUT];
    size_t out_len;
};

static void tms_end(struct tms_run *r)
{
    if (r->parsed) json_free(&r->doc);
    r->parsed = false;
}

/* The dispositions of every signal the session installs or ignores. */
static const int tms_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE};
#define TMS_NSIGNALS (sizeof tms_signals / sizeof tms_signals[0])

static void tms_sig_snapshot(struct sigaction out[TMS_NSIGNALS])
{
    for (size_t i = 0; i < TMS_NSIGNALS; i++) (void)sigaction(tms_signals[i], NULL, &out[i]);
}

static bool tms_sig_same(const struct sigaction a[TMS_NSIGNALS],
                         const struct sigaction b[TMS_NSIGNALS])
{
    for (size_t i = 0; i < TMS_NSIGNALS; i++)
        if (a[i].sa_handler != b[i].sa_handler || a[i].sa_flags != b[i].sa_flags) return false;
    return true;
}

static bool g_watchdog = true; /* the pseudo-terminal cases run their own alarm */

/* Runs the registered leaf with the given descriptors as the console. */
static bool tms_exec(struct tms_run *r, const char *json, int in_fd, int out_fd)
{
    const struct zcl_command_spec *found =
        zcl_command_registry_find(zcl_command_catalog(), "dev.app.machine.shell", NULL);
    struct zcl_command_spec spec;
    struct json_value input;
    struct tms_guard guard;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t len = 0;
    json_init(&r->doc);
    json_init(&input);
    r->parsed = false;
    if (found == NULL) return false;
    spec = *found;
    spec.handler = zcl_native_handle_dev_machine_shell;
    if (json_read(&input, json, strlen(json)) && input.type == JSON_OBJ) {
        if (g_watchdog) tms_guard_enter(&guard);
        zcl_ms_test_fds(in_fd, out_fd);
        len = zcl_command_registry_execute_json(zcl_command_catalog(), &spec, NULL, &input,
                                                false, "dev.app.machine.shell", NULL, 0, 0,
                                                NULL, r->wire, sizeof r->wire, &exit_code);
        zcl_ms_test_fds(-1, -1);
        if (g_watchdog) tms_guard_leave(&guard);
    }
    json_free(&input);
    r->parsed = len > 0 && json_read(&r->doc, r->wire, len);
    return r->parsed;
}

/* Runs the leaf in pipe mode: the bytes are written to the input pipe, which is
 * closed after them when eof is set; everything the guest printed is read back. */
static bool tms_go(struct tms_run *r, const char *json, const char *in, size_t in_len, bool eof)
{
    int ip[2], op[2];
    ssize_t n;
    bool ok;
    r->out_len = 0;
    if (pipe(ip) != 0) return false;
    if (pipe(op) != 0) {
        close(ip[0]);
        close(ip[1]);
        return false;
    }
    ok = in_len == 0 || write(ip[1], in, in_len) == (ssize_t)in_len;
    if (eof) close(ip[1]);
    ok = ok && tms_exec(r, json, ip[0], op[1]);
    close(op[1]);
    while ((n = read(op[0], r->out + r->out_len, TMS_OUT - 1u - r->out_len)) > 0)
        r->out_len += (size_t)n;
    r->out[r->out_len] = '\0';
    if (!eof) close(ip[1]);
    close(ip[0]);
    close(op[0]);
    return ok;
}

static const struct json_value *tms_data(const struct tms_run *r, const char *key)
{
    return json_get(json_get(&r->doc, "data"), key);
}

static int64_t tms_int(const struct tms_run *r, const char *key)
{
    const struct json_value *v = tms_data(r, key);
    return v != NULL && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *tms_str(const struct tms_run *r, const char *key)
{
    const char *s = json_get_str(tms_data(r, key));
    return s != NULL ? s : "";
}

static bool tms_ok(const struct tms_run *r)
{
    const struct json_value *ok = json_get(&r->doc, "ok");
    return ok != NULL && ok->type == JSON_BOOL && json_get_bool(ok);
}

static const char *tms_error_code(const struct tms_run *r)
{
    const char *s = json_get_str(json_get(json_get(&r->doc, "error"), "code"));
    return s != NULL ? s : "";
}

static void tms_json(char *out, size_t cap, const char *kernel, const char *extra)
{
    snprintf(out, cap, "{\"kernel\":\"" TMS_FIXTURES "%s.bin\",\"ram_mib\":64,"
             "\"stdio\":\"pipe\"%s}", kernel, extra);
}

/* ---- pipe mode ---- */

static int t_echo(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: input reaches the guest and its output returns in order") {
        struct tms_run r;
        char json[512];
        tms_json(json, sizeof json, "echo", TMS_GUARD);
        ASSERT(tms_go(&r, json, "abc", 3, false));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(r.out, "abcabc");
        ASSERT_STR_EQ(tms_str(&r, "end"), "guest_shutdown");
        ASSERT_STR_EQ(tms_str(&r, "stop"), "shutdown");
        ASSERT_EQ(tms_int(&r, "bytes_in"), 3);
        ASSERT_EQ(tms_int(&r, "bytes_out"), 6);
        ASSERT(json_get_bool(tms_data(&r, "interactive")));
        ASSERT(!json_get_bool(tms_data(&r, "deterministic")));
        ASSERT_STR_EQ(json_get_str(json_get(tms_data(&r, "entropy"), "source")), "host_os_csprng");
        ASSERT_STR_EQ(json_get_str(json_get(tms_data(&r, "entropy"), "boot_seed")),
                      "not_offered_flat_image");
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_ends(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: end of input and the work cap end the session with their reasons") {
        struct tms_run r;
        char json[512];
        tms_json(json, sizeof json, "rearm", ",\"eof_quiet_ms\":20");
        ASSERT(tms_go(&r, json, "", 0, true));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(tms_str(&r, "end"), "stdin_eof");
        ASSERT(tms_int(&r, "retired") > 0);
        tms_end(&r);
        tms_json(json, sizeof json, "rearm", ",\"max_instr\":100000");
        ASSERT(tms_go(&r, json, "", 0, false));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(tms_str(&r, "end"), "work_cap");
        ASSERT(tms_int(&r, "retired") + tms_int(&r, "fw_calls") + tms_int(&r, "device_work") >= 100000);
        ASSERT(tms_int(&r, "retired") + tms_int(&r, "fw_calls") + tms_int(&r, "device_work") < 100000 + 20000);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_escape(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: the escape prefix then q ends the session; other bytes pass through") {
        struct tms_run r;
        char json[512];
        tms_json(json, sizeof json, "rearm", "");
        ASSERT(tms_go(&r, json, "x" ESC "q", 3, false));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(tms_str(&r, "end"), "escape");
        ASSERT_EQ(tms_int(&r, "bytes_in"), 1);
        tms_end(&r);
        tms_json(json, sizeof json, "rearm", ",\"escape\":\"a\"");
        ASSERT(tms_go(&r, json, "\x01q", 2, false));
        ASSERT_STR_EQ(tms_str(&r, "end"), "escape");
        ASSERT_EQ(tms_int(&r, "bytes_in"), 0);
        tms_end(&r);
        /* the prefix twice is one prefix byte */
        tms_json(json, sizeof json, "echo", TMS_GUARD);
        ASSERT(tms_go(&r, json, "a" ESC ESC "b", 4, false));
        ASSERT_STR_EQ(r.out, "a" ESC "ba" ESC "b");
        ASSERT_EQ(tms_int(&r, "bytes_in"), 3);
        tms_end(&r);
        /* the prefix then another byte is both bytes */
        ASSERT(tms_go(&r, json, "a" ESC "z", 3, false));
        ASSERT_STR_EQ(r.out, "a" ESC "za" ESC "z");
        ASSERT_EQ(tms_int(&r, "bytes_in"), 3);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_timers(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: guest timers fire across idle sleeps") {
        struct tms_run r;
        char json[512];
        tms_json(json, sizeof json, "ticker", TMS_GUARD);
        ASSERT(tms_go(&r, json, "", 0, false));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(tms_str(&r, "end"), "guest_shutdown");
        ASSERT(strstr(r.out, "tick 4\n") != NULL);
        ASSERT(tms_int(&r, "skip") > 0);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_receipt(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: the receipt file is created once and carries the result") {
        struct tms_run r;
        char dir[256], path[320], json[768], extra[400], text[TMS_OUT];
        FILE *f;
        size_t n;
        ASSERT(test_mkdtemp(dir, sizeof dir, "machine_shell") != NULL);
        snprintf(path, sizeof path, "%s/receipt.json", dir);
        snprintf(extra, sizeof extra, TMS_GUARD ",\"receipt\":\"%s\"", path);
        tms_json(json, sizeof json, "echo", extra);
        ASSERT(tms_go(&r, json, "abc", 3, false));
        ASSERT(tms_ok(&r));
        f = fopen(path, "rb");
        ASSERT(f != NULL);
        n = fread(text, 1, sizeof text - 1u, f);
        fclose(f);
        text[n] = '\0';
        ASSERT(strstr(text, "\"interactive\":true") != NULL);
        ASSERT(strstr(text, "\"end\":\"guest_shutdown\"") != NULL);
        ASSERT(strstr(text, "\"verdict\":{\"status\":\"passed\",\"code\":\"\"}") != NULL);
        tms_end(&r);
        /* the existing path is refused and the guest never starts */
        ASSERT(tms_go(&r, json, "abc", 3, false));
        ASSERT(!tms_ok(&r));
        ASSERT_STR_EQ(tms_error_code(&r), "RECEIPT_UNWRITABLE");
        ASSERT_EQ((int)r.out_len, 0);
        tms_end(&r);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_refusals(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: refusals are named and nothing runs") {
        struct tms_run r;
        char json[512];
        ASSERT(tms_go(&r, "{\"stdio\":\"pipe\"}", "", 0, true));
        ASSERT(!tms_ok(&r));
        ASSERT_STR_EQ(tms_error_code(&r), "KERNEL_REQUIRED");
        tms_end(&r);
        ASSERT(tms_go(&r, "{\"kernel\":\"/nonexistent/kernel\",\"stdio\":\"pipe\"}", "", 0, true));
        ASSERT_STR_EQ(tms_error_code(&r), "INPUT_UNREADABLE");
        tms_end(&r);
        ASSERT(tms_go(&r, "{\"kernel\":\"" TMS_FIXTURES "echo.bin\",\"disk\":\"/nonexistent/disk\","
                          "\"stdio\":\"pipe\"}", "", 0, true));
        ASSERT_STR_EQ(tms_error_code(&r), "INPUT_UNREADABLE");
        tms_end(&r);
        /* pipes are not terminals */
        ASSERT(tms_go(&r, "{\"kernel\":\"" TMS_FIXTURES "echo.bin\"}", "", 0, true));
        ASSERT_STR_EQ(tms_error_code(&r), "NOT_A_TERMINAL");
        tms_end(&r);
        ASSERT(tms_go(&r, "{\"kernel\":\"" TMS_FIXTURES "echo.bin\",\"stdio\":\"tty\"}", "", 0, true));
        ASSERT(!tms_ok(&r));
        tms_end(&r);
        tms_json(json, sizeof json, "echo", ",\"escape\":\"i\"");
        ASSERT(tms_go(&r, json, "", 0, true));
        ASSERT(!tms_ok(&r));
        tms_end(&r);
        tms_json(json, sizeof json, "echo", ",\"bogus\":1");
        ASSERT(tms_go(&r, json, "", 0, true));
        ASSERT(!tms_ok(&r));
        ASSERT(strstr(r.wire, "unknown input key") != NULL);
        tms_end(&r);
        tms_json(json, sizeof json, "echo", ",\"max_instr\":0");
        ASSERT(tms_go(&r, json, "", 0, true));
        ASSERT(!tms_ok(&r));
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- terminal mode ---- */

static int g_pty_master = -1, g_pty_slave = -1;
static const char *g_alarm_bytes;
static size_t g_alarm_len;
static int g_alarm_signo;
static volatile sig_atomic_t g_alarm_raw, g_alarm_acted, g_alarm_tries;
#define TMS_ALARM_TRIES 100

static void tms_arm(long usec)
{
    struct itimerval t = {.it_value = {.tv_sec = 0, .tv_usec = usec}};
    (void)setitimer(ITIMER_REAL, &t, NULL);
}

/* Fires once the session has the terminal raw (its signal handlers are then
 * installed), records that, and ends the session by bytes or by a signal. */
static void tms_alarm(int sig)
{
    struct termios t;
    bool raw;
    (void)sig;
    raw = tcgetattr(g_pty_slave, &t) == 0 && (t.c_lflag & (ICANON | ECHO | ISIG)) == 0;
    if (!raw && ++g_alarm_tries < TMS_ALARM_TRIES) {
        tms_arm(20000);
        return;
    }
    /* After the retries the action is taken anyway, so a session that never
     * became raw ends and the assertions on g_alarm_raw fail. */
    g_alarm_raw = raw;
    g_alarm_acted = 1;
    if (g_alarm_signo != 0) {
        (void)kill(getpid(), g_alarm_signo);
    } else if (write(g_pty_master, g_alarm_bytes, g_alarm_len) != (ssize_t)g_alarm_len) {
        g_alarm_acted = 0;
    }
}

static bool tms_open_pty(void)
{
    char *name;
    g_pty_master = posix_openpt(O_RDWR | O_NOCTTY);
    if (g_pty_master < 0 || grantpt(g_pty_master) != 0 || unlockpt(g_pty_master) != 0) return false;
    name = ptsname(g_pty_master);
    g_pty_slave = name != NULL ? open(name, O_RDWR | O_NOCTTY) : -1;
    return g_pty_slave >= 0;
}

static void tms_close_pty(void)
{
    if (g_pty_slave >= 0) close(g_pty_slave);
    if (g_pty_master >= 0) close(g_pty_master);
    g_pty_slave = g_pty_master = -1;
}

static bool tms_termios_equal(const struct termios *a, const struct termios *b)
{
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag && a->c_cflag == b->c_cflag &&
           a->c_lflag == b->c_lflag && memcmp(a->c_cc, b->c_cc, sizeof a->c_cc) == 0 &&
           cfgetispeed(a) == cfgetispeed(b) && cfgetospeed(a) == cfgetospeed(b);
}

/* One terminal-mode session ended by the alarm; true when the terminal was raw
 * during it and the attributes afterwards equal the originals. */
static bool tms_pty_session(struct tms_run *r, const char *bytes, int signo, const char *end)
{
    struct termios before, after;
    struct sigaction act, old, ign, term, sigs_before[TMS_NSIGNALS], sigs_after[TMS_NSIGNALS];
    char json[512];
    bool ok;
    g_alarm_bytes = bytes;
    g_alarm_len = bytes != NULL ? strlen(bytes) : 0;
    g_alarm_signo = signo;
    g_alarm_raw = g_alarm_acted = g_alarm_tries = 0;
    if (!tms_open_pty() || tcgetattr(g_pty_slave, &before) != 0) return false;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    tms_sig_snapshot(sigs_before);
    memset(&act, 0, sizeof act);
    act.sa_handler = tms_alarm;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, &old) != 0) return false;
    snprintf(json, sizeof json, "{\"kernel\":\"" TMS_FIXTURES "rearm.bin\",\"ram_mib\":64}");
    (void)sigaction(SIGTERM, &ign, &term); /* ignored until the session owns it */
    g_watchdog = false;
    tms_arm(150000);
    ok = tms_exec(r, json, g_pty_slave, g_pty_slave);
    tms_arm(0);
    g_watchdog = true;
    (void)sigaction(SIGTERM, &term, NULL);
    (void)sigaction(SIGALRM, &old, NULL);
    ok = ok && tcgetattr(g_pty_slave, &after) == 0 && tms_termios_equal(&before, &after);
    tms_sig_snapshot(sigs_after);
    ok = ok && tms_sig_same(sigs_before, sigs_after);
    ok = ok && g_alarm_raw && g_alarm_acted && tms_ok(r) && strcmp(tms_str(r, "end"), end) == 0;
    tms_close_pty();
    return ok;
}

static int t_pty_escape(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: a terminal is raw during the session and restored after the escape") {
        struct tms_run r;
        ASSERT(tms_pty_session(&r, ESC "q", 0, "escape"));
        ASSERT_STR_EQ(tms_str(&r, "stdio"), "terminal");
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_pty_signal(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: a terminal is restored when a signal ends the session") {
        struct tms_run r;
        ASSERT(tms_pty_session(&r, NULL, SIGTERM, "signal"));
        ASSERT_EQ(tms_int(&r, "signal"), SIGTERM);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_dispositions(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: all signal dispositions are restored after a pipe session") {
        struct tms_run r;
        struct sigaction before[TMS_NSIGNALS], after[TMS_NSIGNALS];
        char json[512];
        tms_json(json, sizeof json, "echo", TMS_GUARD);
        tms_sig_snapshot(before);
        ASSERT(tms_go(&r, json, "abc", 3, false));
        tms_sig_snapshot(after);
        ASSERT(tms_sig_same(before, after));
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_backpressure(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: input beyond the guest queue stays unread") {
        struct tms_run r;
        char json[512], big[10000];
        memset(big, 'x', sizeof big);
        tms_json(json, sizeof json, "rearm", ",\"max_instr\":5000000");
        ASSERT(tms_go(&r, json, big, sizeof big, false));
        ASSERT(tms_ok(&r));
        ASSERT_STR_EQ(tms_str(&r, "end"), "work_cap");
        ASSERT_EQ(tms_int(&r, "bytes_in"), RVMACHINE_INPUT_MAX);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int t_output_closed(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: a closed output ends the session as failed and the receipt says so") {
        struct tms_run r;
        char dir[256], path[320], json[768], extra[400], text[TMS_OUT];
        int ip[2], op[2];
        FILE *f;
        size_t n;
        ASSERT(test_mkdtemp(dir, sizeof dir, "machine_shell") != NULL);
        snprintf(path, sizeof path, "%s/receipt.json", dir);
        snprintf(extra, sizeof extra, TMS_GUARD ",\"receipt\":\"%s\"", path);
        tms_json(json, sizeof json, "echo", extra);
        ASSERT(pipe(ip) == 0 && pipe(op) == 0);
        ASSERT(write(ip[1], "abc", 3) == 3);
        close(op[0]);
        ASSERT(tms_exec(&r, json, ip[0], op[1]));
        close(ip[0]);
        close(ip[1]);
        close(op[1]);
        ASSERT(!tms_ok(&r));
        ASSERT_STR_EQ(tms_error_code(&r), "SESSION_FAILED");
        f = fopen(path, "rb");
        ASSERT(f != NULL);
        n = fread(text, 1, sizeof text - 1u, f);
        fclose(f);
        text[n] = '\0';
        ASSERT(strstr(text, "\"end\":\"error\"") != NULL);
        ASSERT(strstr(text, "\"verdict\":{\"status\":\"failed\",\"code\":\"SESSION_FAILED\"}") != NULL);
        tms_end(&r);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_receipt_symlink(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: a symlink as the receipt is refused and its target is not created") {
        struct tms_run r;
        char dir[256], target[320], link[320], json[768], extra[800];
        ASSERT(test_mkdtemp(dir, sizeof dir, "machine_shell") != NULL);
        snprintf(target, sizeof target, "%s/target", dir);
        snprintf(link, sizeof link, "%s/link", dir);
        ASSERT(symlink(target, link) == 0);
        snprintf(extra, sizeof extra, TMS_GUARD ",\"receipt\":\"%s\"", link);
        tms_json(json, sizeof json, "echo", extra);
        ASSERT(tms_go(&r, json, "abc", 3, false));
        ASSERT(!tms_ok(&r));
        ASSERT_STR_EQ(tms_error_code(&r), "RECEIPT_UNWRITABLE");
        ASSERT(access(target, F_OK) != 0);
        tms_end(&r);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int t_escape_keys(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: escape accepts a letter or \\ ] ^ _ and refuses the rest") {
        static const char *const refused[] = {"@", "[", "h", "H", "i", "j", "m", "M", "|", "}", "~",
                                              "1", " ", "ab", ""};
        static const char *const accepted[] = {"a", "A", "z", "]", "\\\\", "^", "_"};
        struct tms_run r;
        char json[512], extra[64];
        for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
            snprintf(extra, sizeof extra, ",\"escape\":\"%s\"", refused[i]);
            tms_json(json, sizeof json, "echo", extra);
            ASSERT(tms_go(&r, json, "", 0, true));
            ASSERT(!tms_ok(&r));
            ASSERT_STR_EQ(tms_error_code(&r), "INVALID_INPUT");
            tms_end(&r);
        }
        for (size_t i = 0; i < sizeof accepted / sizeof accepted[0]; i++) {
            snprintf(extra, sizeof extra, ",\"escape\":\"%s\"", accepted[i]);
            tms_json(json, sizeof json, "rearm", extra);
            ASSERT(tms_go(&r, json, "", 0, true));
            ASSERT(tms_ok(&r));
            tms_end(&r);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int t_string_members(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: a non-string or empty member is refused for its own reason") {
        struct tms_run r;
        ASSERT(tms_go(&r, "{\"kernel\":7,\"stdio\":\"pipe\"}", "", 0, true));
        ASSERT_STR_EQ(tms_error_code(&r), "INVALID_INPUT");
        ASSERT(strstr(r.wire, "kernel") != NULL);
        tms_end(&r);
        ASSERT(tms_go(&r, "{\"kernel\":\"" TMS_FIXTURES "echo.bin\",\"bootargs\":\"\",\"stdio\":\"pipe\"}",
                      "", 0, true));
        ASSERT_STR_EQ(tms_error_code(&r), "INVALID_INPUT");
        ASSERT(strstr(r.wire, "bootargs") != NULL);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

/* The framework flag cannot be set outside a one-shot CLI call (the catalog of
 * a test build is not executable), so the leaf's test hook stands for it. */
static int t_input_on_stdin(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: input read from stdin is refused because stdin is the console") {
        struct tms_run r;
        char json[512];
        tms_json(json, sizeof json, "echo", TMS_GUARD);
        zcl_ms_test_input_on_stdin(true);
        ASSERT(tms_go(&r, json, "abc", 3, false));
        zcl_ms_test_input_on_stdin(false);
        ASSERT(!tms_ok(&r));
        ASSERT_STR_EQ(tms_error_code(&r), "INPUT_ON_STDIN");
        ASSERT_EQ((int)r.out_len, 0);
        tms_end(&r);
        PASS();
    } _test_next:;
    return failures;
}

#define TMS_BIN "build/bin/z23-dev"

static long tms_mtime(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (long)st.st_mtime : -1;
}

static bool tms_bin_fresh(void)
{
    static const char *const witness[] = {"tools/command/native_command.c",
                                          "tools/command/native_dev_machine_shell.c",
                                          "tools/command/native_dev_machine_shell_session.c"};
    long bin = tms_mtime(TMS_BIN);
    if (bin < 0) return false;
    for (size_t i = 0; i < sizeof witness / sizeof witness[0]; i++)
        if (tms_mtime(witness[i]) > bin) return false;
    return true;
}

static size_t tms_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n = f ? fread(out, 1, cap - 1u, f) : 0;
    if (f) fclose(f);
    out[n] = '\0';
    return n;
}

/* Runs the binary with stdin from a file and stdout and stderr to files, all
 * in a fresh test-tmp directory that is removed afterwards. */
static bool tms_spawn(const char *input, const char *in, char *out, size_t out_cap, char *err,
                      size_t err_cap)
{
    char dir[512], fin[600], fout[600], ferr[600];
    test_make_tmpdir(dir, sizeof dir, "tms", "streams");
    snprintf(fin, sizeof fin, "%s/in", dir);
    snprintf(fout, sizeof fout, "%s/out", dir);
    snprintf(ferr, sizeof ferr, "%s/err", dir);
    int a = open(fin, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600),
        b = open(fout, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600),
        c = open(ferr, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600), status = -1;
    bool ok = a >= 0 && b >= 0 && c >= 0 && write(a, in, strlen(in)) == (ssize_t)strlen(in);
    pid_t pid = ok ? fork() : -1;
    if (pid == 0) {
        if (lseek(a, 0, SEEK_SET) != 0) _exit(126);
        dup2(a, STDIN_FILENO);
        dup2(b, STDOUT_FILENO);
        dup2(c, STDERR_FILENO);
        execl(TMS_BIN, TMS_BIN, "dev", "app", "machine", "shell", input, (char *)NULL);
        _exit(127);
    }
    ok = pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    tms_slurp(fout, out, out_cap);
    tms_slurp(ferr, err, err_cap);
    for (int i = 0; i < 3; i++) {
        int fd = i == 0 ? a : i == 1 ? b : c;
        if (fd >= 0) close(fd);
    }
    test_rm_rf_recursive(dir);
    return ok;
}

/* A missing or stale binary fails the case: the stream split is observed only
 * through the CLI, so passing without running it would claim an unobserved
 * result. */
static int t_binary_streams(void)
{
    int failures = 0;
    TEST("dev.app.machine.shell: stdout holds only the console bytes; the envelope is on stderr") {
        char out[TMS_OUT], err[TMS_WIRE];
        struct json_value doc;
        const struct json_value *data;
        if (!tms_bin_fresh())
            printf("dev_machine_shell: " TMS_BIN " missing or older than its sources; run make\n");
        ASSERT(tms_bin_fresh());
        ASSERT(tms_spawn("--input={\"kernel\":\"" TMS_FIXTURES "echo.bin\",\"stdio\":\"pipe\","
                         "\"max_instr\":50000000}", "abc", out, sizeof out, err, sizeof err));
        ASSERT_STR_EQ(out, "abcabc");
        ASSERT(strchr(out, '{') == NULL);
        ASSERT(json_read(&doc, err, strlen(err)));
        data = json_get(&doc, "data");
        ASSERT(data != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(data, "guest_exit")), "unobserved");
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_dev_machine_shell(void);
int test_dev_machine_shell(void)
{
#if defined(_WIN32)
    return 0;
#else
    return t_echo() + t_ends() + t_escape() + t_timers() + t_receipt() + t_refusals() +
           t_dispositions() + t_backpressure() + t_output_closed() + t_receipt_symlink() +
           t_escape_keys() + t_string_members() + t_input_on_stdin() + t_pty_escape() +
           t_pty_signal() + t_binary_streams();
#endif
}
