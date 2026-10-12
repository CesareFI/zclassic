/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Request-size guards for the loopback JSON-RPC client. The client composes
 * its POST body in a fixed stack buffer with snprintf; a request whose
 * composed length exceeds that buffer must be refused before connecting —
 * never sent with the would-have-written length, which would read past the
 * buffer and publish a Content-Length the truncated body cannot satisfy.
 * These scenarios prove the guard at the wire with a real loopback listener
 * in a forked child, so no live node is involved.
 *
 * Sibling to test_rpc.c (the group entry point). Fixtures here are private
 * to these scenarios. */

#include "test/test_core.h"
#include "controllers/rpc_client.h"
#include "rpc/client.h"
#include "test/test_rpc_priv.h"
#include "base/safe_alloc.h"
#include "platform/socket_compat.h"
#include "platform/clock.h"
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define RR_REQUEST_CAP (256u * 1024u)
#define RR_BODY_CAP 8192u
#define RR_ACCEPT_MS 2000
#define RR_RECV_IDLE_S 2

static const char rr_reply_body[] = "{\"result\":\"pong\",\"error\":null,\"id\":1}";

/* Build the listener socket on an ephemeral loopback port. */
static int rr_listen(uint16_t *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    return fd;
}

/* Locate seq within buf[0,len). Returns true and sets *at on success. */
static bool rr_find_seq(const char *buf, size_t len, const char *seq,
                        size_t seq_len, size_t *at)
{
    if (seq_len == 0 || len < seq_len)
        return false;
    for (size_t i = 0; i + seq_len <= len; i++) {
        if (memcmp(buf + i, seq, seq_len) == 0) {
            *at = i;
            return true;
        }
    }
    return false;
}

/* True once the buffered bytes hold a complete HTTP request: header
 * terminator found and the body bytes satisfy the declared
 * Content-Length. */
static bool rr_request_complete(const char *buf, size_t len)
{
    size_t hdr_at = 0;
    if (!rr_find_seq(buf, len, "\r\n\r\n", 4, &hdr_at))
        return false;
    size_t cl_at = 0;
    if (!rr_find_seq(buf, hdr_at, "Content-Length:", 15, &cl_at))
        return false;
    const char *value = buf + cl_at + 15;
    const char *line_end = memchr(value, '\r', hdr_at - (cl_at + 15));
    if (!line_end)
        return false;
    char tmp[32];
    size_t vlen = (size_t)(line_end - value);
    if (vlen == 0 || vlen >= sizeof(tmp))
        return false;
    memcpy(tmp, value, vlen);
    tmp[vlen] = 0;
    errno = 0;
    char *end = NULL;
    unsigned long long content_length = strtoull(tmp, &end, 10);
    if (errno != 0 || !end || end == tmp || *end != 0)
        return false;
    size_t body_len = len - (hdr_at + 4);
    return body_len == content_length;
}

static bool rr_request_matches(const char *buf, size_t len,
                               const char *method, const char *params)
{
    size_t hdr_at = 0;
    if (!rr_find_seq(buf, len, "\r\n\r\n", 4, &hdr_at)) return false;
    static const char *const formats[] = {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        "{\"jsonrpc\":\"1.0\",\"id\":\"cli\",\"method\":\"%s\",\"params\":%s}",
        "{\"jsonrpc\":\"1.0\",\"id\":\"z\",\"method\":\"%s\",\"params\":%s}",
    };
    char expected[65536];
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
        int n = snprintf(expected, sizeof(expected), formats[i], method, params);
        if (n >= 0 && (size_t)n < sizeof(expected) &&
            len - hdr_at - 4 == (size_t)n &&
            memcmp(buf + hdr_at + 4, expected, (size_t)n) == 0)
            return true;
    }
    return false;
}

/* Child-side: serve exactly one connection. Exits 0 when a complete,
 * well-formed request arrived (replying with the canned JSON-RPC body when
 * one is provided), 1 when the connection arrived but the request was
 * truncated or malformed, 2 when no connection arrived before the accept
 * deadline, 3 on internal error. */

/* Accept one connection within RR_ACCEPT_MS; _exit(2)/(3) on refusal. */
static int rr_accept_one(int listen_fd)
{
    struct pollfd pfd = { .fd = listen_fd, .events = POLLIN, .revents = 0 };
    int pr;
    do {
        pr = poll(&pfd, 1, RR_ACCEPT_MS);
    } while (pr < 0 && errno == EINTR);
    if (pr < 0) _exit(3);
    if (pr == 0) _exit(2);
    int c = accept(listen_fd, NULL, NULL);
    if (c < 0)
        _exit(3);
    return c;
}

/* Read until the request completes or the peer goes away; true when a
 * complete request sits in buf. */
static bool rr_recv_request(int c, char *buf, size_t cap, size_t *len_out)
{
    size_t len = 0;
    bool complete = false;
    for (;;) {
        ssize_t n = recv(c, buf + len, cap - len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
        if (len >= cap) break;
        if (rr_request_complete(buf, len)) {
            complete = true;
            break;
        }
    }
    *len_out = len;
    return complete;
}

/* Best-effort canned reply; the client's verdict never depends on it. */
static void rr_send_reply(int c, const char *reply_body)
{
    char reply[512];
    int rlen = snprintf(reply, sizeof(reply),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        strlen(reply_body), reply_body);
    if (rlen <= 0 || (size_t)rlen >= sizeof(reply)) _exit(3);
    size_t reply_len = (size_t)rlen;
    size_t sent = 0;
    while (sent < reply_len) {
        ssize_t n = send(c, reply + sent, reply_len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0) break;
        sent += (size_t)n;
    }
}

static void rr_serve_child(int listen_fd, const char *reply_body,
                           const char *method, const char *params)
{
    int c = rr_accept_one(listen_fd);
    struct timeval idle = { .tv_sec = RR_RECV_IDLE_S, .tv_usec = 0 };
    if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &idle, sizeof(idle)) != 0)
        _exit(3);
    static char buf[RR_REQUEST_CAP];
    size_t len = 0;
    bool complete = rr_recv_request(c, buf, sizeof(buf), &len) &&
                    rr_request_matches(buf, len, method, params);
    if (complete && reply_body)
        rr_send_reply(c, reply_body);
    close(c);
    close(listen_fd);
    _exit(complete ? 0 : 1);
}

/* Compose ["aaaa...a"] with exactly inner 'a' characters. */
static char *rr_params_of_size(size_t inner)
{
    char *p = zcl_malloc(inner + 5, "rr params");
    if (!p)
        return NULL;
    p[0] = '[';
    p[1] = '"';
    memset(p + 2, 'a', inner);
    p[2 + inner] = '"';
    p[3 + inner] = ']';
    p[4 + inner] = 0;
    return p;
}

/* Fork the listener child, run one client call, and reap the verdict. */
/* A child cannot extend its lifetime by repeated EINTR or partial input.
 * Reap normally within ten seconds, then kill only this checked child and
 * allow two seconds for the kernel to report its exit. */
static bool rr_wait_child(pid_t pid, int *status, int timeout_ms)
{
    int64_t deadline = clock_now_monotonic_ns() + (int64_t)timeout_ms * 1000000;
    bool killed = false;
    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) return !killed;
        if (r < 0 && errno != EINTR) {
            fprintf(stderr, "rr_wait_child: wait failed: %s\n", strerror(errno));
            return false;
        }
        if (clock_now_monotonic_ns() >= deadline) {
            if (killed) {
                fprintf(stderr, "rr_wait_child: killed child exit unobserved\n");
                return false;
            }
            fprintf(stderr, "rr_wait_child: child lifetime exceeded deadline\n");
            if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
                fprintf(stderr, "rr_wait_child: kill failed: %s\n", strerror(errno));
                return false;
            }
            killed = true;
            deadline = clock_now_monotonic_ns() + INT64_C(30000000000);
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
            fprintf(stderr, "rr_wait_child: sleep failed: %s\n", strerror(errno));
            /* Continue supervising the checked pid; never abandon it on a
             * sleep error or mistake an unobserved exit for success. */
        }
    }
}

static char *rr_call_with_listener(const char *datadir, const char *method,
                                   const char *params, const char *reply_body,
                                   int *child_verdict, bool absolute)
{
    uint16_t port = 0;
    int listen_fd = rr_listen(&port);
    if (listen_fd < 0) {
        fprintf(stderr, "rr_call_with_listener: listener failed: %s\n",
                strerror(errno));
        return NULL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "rr_call_with_listener: fork failed: %s\n", strerror(errno));
        close(listen_fd);
        return NULL;
    }
    if (pid == 0)
        rr_serve_child(listen_fd, reply_body, method, params);
    close(listen_fd);
    char *resp = absolute
        ? node_rpc_call_at_until(datadir, (int)port, method, params, 250,
                                 clock_now_monotonic_ns() / 1000000 + 5000)
        : node_rpc_call_at_deadline(datadir, (int)port, method, params, 250, 5000);
    int status = 0;
    if (!rr_wait_child(pid, &status, 10000) || !WIFEXITED(status)) {
        fprintf(stderr, "rr_call_with_listener: child was not observed exiting\n");
        *child_verdict = 3;
        return resp;
    }
    *child_verdict = WEXITSTATUS(status);
    return resp;
}

static int rr_write_cookie(const char *dir)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/.cookie", dir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs("rruser:rrpass\n", f);
    return fclose(f) == 0 ? 0 : -1;
}

static bool rr_cli_launch(const char *binary, const char *dir, uint16_t port,
                          const char *method, const char *arg,
                          const char *log, int *status)
{
    char datadir[1100], rpcport[64];
    int n = snprintf(datadir, sizeof(datadir), "-datadir=%s", dir);
    if (n < 0 || (size_t)n >= sizeof(datadir)) return false;
    n = snprintf(rpcport, sizeof(rpcport), "-rpcport=%u", (unsigned)port);
    if (n < 0 || (size_t)n >= sizeof(rpcport)) return false;
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "rr_cli_launch: fork failed: %s\n", strerror(errno));
        return false;
    }
    if (pid == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
            dup2(fd, STDERR_FILENO) < 0) _exit(125);
        close(fd);
        if (setenv("HOME", dir, 1) != 0 ||
            setenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP", "1", 1) != 0) _exit(125);
        execl(binary, binary, datadir, rpcport, method, arg, (char *)NULL);
        _exit(127);
    }
    return rr_wait_child(pid, status, 10000) && WIFEXITED(*status);
}

static bool rr_cli_read_output(const char *log, char *output, size_t cap)
{
    FILE *f = fopen(log, "r");
    if (!f) {
        fprintf(stderr, "rr_cli_read_output: open failed: %s\n", strerror(errno));
        return false;
    }
    size_t count = fread(output, 1, cap - 1, f);
    output[count] = 0;
    bool ok = !ferror(f);
    return fclose(f) == 0 && ok;
}

static bool rr_cli_verdict(int status, int server_status, const char *output,
                           bool refusal)
{
    if (refusal)
        return WEXITSTATUS(status) != 0 && WEXITSTATUS(server_status) == 2 &&
               (strstr(output, "request too large") ||
                strstr(output, "REQUEST_TOO_LARGE"));
    return WEXITSTATUS(status) == 0 && WEXITSTATUS(server_status) == 0 &&
           strstr(output, "pong") != NULL;
}

static bool rr_cli_case(const char *binary, const char *dir,
                        const char *method, const char *arg,
                        const char *params, bool refusal)
{
    uint16_t port = 0;
    int fd = rr_listen(&port);
    if (fd < 0) {
        fprintf(stderr, "rr_cli_case: listener failed: %s\n", strerror(errno));
        return false;
    }
    pid_t server = fork();
    if (server < 0) {
        fprintf(stderr, "rr_cli_case: fork failed: %s\n", strerror(errno));
        close(fd);
        return false;
    }
    if (server == 0) rr_serve_child(fd, rr_reply_body, method, params);
    close(fd);
    char log[1100];
    int n = snprintf(log, sizeof(log), "%s/cli-output", dir);
    int status = 0, server_status = 0;
    bool ran = n > 0 && (size_t)n < sizeof(log) &&
               rr_cli_launch(binary, dir, port, method, arg, log, &status);
    bool observed = rr_wait_child(server, &server_status, 10000) &&
                    WIFEXITED(server_status);
    char output[4096] = {0};
    bool read_ok = ran && rr_cli_read_output(log, output, sizeof(output));
    if (!ran || !observed || !read_ok) return false;
    return rr_cli_verdict(status, server_status, output, refusal);
}

static int rr_cli_param_boundaries(const char *binary, const char *dir)
{
    int failures = 0;
    for (size_t inner = 32763; inner <= 32764; inner++) {
        char *arg = zcl_malloc(inner + 1, "rr CLI parameter");
        char *params = rr_params_of_size(inner);
        bool ok = false;
        if (arg && params) {
            memset(arg, 'a', inner);
            arg[inner] = 0;
            ok = rr_cli_case(binary, dir, "rrmethod", arg, params, inner == 32764);
        }
        printf("rpc CLI serialized parameter boundary %s %zu... %s\n",
               binary, inner + 4, ok ? "OK" : "FAIL");
        failures += !ok;
        free(arg);
        free(params);
    }
    return failures;
}

static int rr_cli_boundaries(const char *dir)
{
    static const char *const binaries[] = {
        "build/bin/zclassic-cli", "build/bin/zclassic23",
    };
    char *method = zcl_malloc(65537, "rr CLI oversized method");
    if (!method) return 1;
    memset(method, 'm', 65536);
    method[65536] = 0;
    int failures = 0;
    for (size_t i = 0; i < sizeof(binaries) / sizeof(binaries[0]); i++) {
        int overhead = snprintf(NULL, 0,
            "{\"jsonrpc\":\"1.0\",\"id\":\"%s\",\"method\":\"\",\"params\":[]}",
            i == 0 ? "cli" : "z");
        bool ok = overhead > 0 && overhead < 65535 &&
                  rr_cli_case(binaries[i], dir, "rrmethod", NULL, "[]", false);
        if (ok) {
            size_t fitting = 65535 - (size_t)overhead;
            method[fitting] = 0;
            ok = rr_cli_case(binaries[i], dir, method, NULL, "[]", false);
            method[fitting] = 'm';
        }
        ok = ok && rr_cli_case(binaries[i], dir, method, NULL, "[]", true);
        printf("rpc CLI real-binary small/max success and oversized refusal %s... %s\n",
               binaries[i], ok ? "OK" : "FAIL");
        failures += !ok;
        failures += rr_cli_param_boundaries(binaries[i], dir);
    }
    free(method);
    return failures;
}

static bool rr_observe_refusal(const char *dir, const char *method,
                               const char *params)
{
    int verdict = 3;
    char *resp = rr_call_with_listener(dir, method, params, NULL, &verdict, false);
    bool named = resp && strstr(resp, "too large") != NULL;
    bool ok = named && verdict == 2;
    if (!ok) printf("FAIL (verdict=%d refusal=%s)\n", verdict,
                    named ? "named" : "missing");
    free(resp);
    return ok;
}

static char *rr_params_for_body_size(size_t size)
{
    int overhead = snprintf(NULL, 0,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rrmethod\",\"params\":[\"\"]}");
    if (overhead <= 0 || size < (size_t)overhead) return NULL;
    return rr_params_of_size(size - (size_t)overhead);
}

static int rr_absolute_boundaries(const char *dir)
{
    int failures = 0;
    for (size_t size = RR_BODY_CAP - 1; size <= RR_BODY_CAP; size++) {
        char *params = rr_params_for_body_size(size);
        int verdict = 3;
        char *resp = params ? rr_call_with_listener(dir, "rrmethod", params,
            rr_reply_body, &verdict, true) : NULL;
        bool fitting = size < RR_BODY_CAP;
        bool ok = resp && (fitting
            ? verdict == 0 && strstr(resp, "pong") != NULL
            : verdict == 2 && strstr(resp, "too large") != NULL);
        printf("rpc absolute-deadline exact request boundary %zu... %s\n",
               size, ok ? "OK" : "FAIL");
        failures += !ok;
        free(resp);
        free(params);
    }
    return failures;
}

int check_rpc_node_client_rejects_oversized_request(void)
{
    int failures = 0;
    printf("rpc_request_fixture_reaps_stalled_child... ");
    pid_t stalled = fork();
    if (stalled == 0) {
        for (;;) pause();
    }
    if (stalled < 0) {
        fprintf(stderr, "rpc watchdog fixture: fork failed: %s\n", strerror(errno));
        failures++;
    } else {
        int status = 0;
        bool observed = rr_wait_child(stalled, &status, 100);
        bool ok = !observed && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
        printf("%s\n", ok ? "OK" : "FAIL");
        failures += !ok;
    }
    char dir[1024];
    test_make_tmpdir(dir, sizeof(dir), "rpc", "reqsize-big");
    node_rpc_client_set_test_hook(NULL);
    if (rr_write_cookie(dir) != 0) {
        printf("rpc request-size fixture: cookie creation failed\n");
        test_rm_rf(dir);
        return 1;
    }
    const size_t sizes[] = {RR_BODY_CAP, 9000};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        printf("rpc_node_client_rejects_body_%zu... ", sizes[i]);
        char *params = rr_params_for_body_size(sizes[i]);
        bool ok = params && rr_observe_refusal(dir, "rrmethod", params);
        printf("%s\n", ok ? "OK" : "FAIL");
        failures += !ok;
        free(params);
    }
    printf("rpc_node_client_rejects_oversized_method... ");
    char *method = zcl_malloc(RR_BODY_CAP + 1, "rr oversized method");
    bool ok = false;
    if (method) {
        memset(method, 'm', RR_BODY_CAP);
        method[RR_BODY_CAP] = 0;
        ok = rr_observe_refusal(dir, method, "[]");
    }
    printf("%s\n", ok ? "OK" : "FAIL");
    failures += !ok;
    free(method);
    failures += rr_cli_boundaries(dir);
    test_rm_rf(dir);
    return failures;
}

int check_rpc_node_client_sends_max_sized_request(void)
{
    int failures = 0;

    printf("rpc_node_client_sends_max_sized_request... ");
    {
        char dir[1024];
        test_make_tmpdir(dir, sizeof(dir), "rpc", "reqsize-max");
        node_rpc_client_set_test_hook(NULL);
        bool ok = rr_write_cookie(dir) == 0;
        int verdict = 3;
        char *resp = NULL;
        char *params = rr_params_for_body_size(RR_BODY_CAP - 1);
        if (!params)
            ok = false;
        if (ok)
            resp = rr_call_with_listener(dir, "rrmethod", params, rr_reply_body,
                                         &verdict, false);
        /* The largest fitting body (8191 bytes) must round-trip intact:
         * the listener checked every byte against the expected body, and the
         * client parsed the result out of the reply. */
        ok = ok && resp && strstr(resp, "pong") != NULL && verdict == 0;
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL (verdict=%d)\n", verdict);
            failures++;
        }
        free(resp);
        free(params);
        failures += rr_absolute_boundaries(dir);
        test_rm_rf(dir);
    }

    return failures;
}

/* Include the exact production composers without their socket/entry code. */
#define ZCL_RPC_COMPOSER_TEST
#include "../../../engine/entry/cli.c"
#include "../../../engine/entry/main_cli_modes.c"
#undef ZCL_RPC_COMPOSER_TEST

static bool rpc_test_composer_refusal(
    bool (*compose)(const char *, const char **, size_t, char *, size_t))
{
    const char *params[] = { "retained", "refused" };
    char buf[64] = "unchanged";
    size_t before = json_test_live_blocks();
    zcl_alloc_fault_fail_nth("json_set_str", 2);
    bool converted = compose("help", params, 2, buf, sizeof(buf));
    bool consumed = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    return !converted && consumed && strcmp(buf, "unchanged") == 0 &&
           json_test_live_blocks() == before;
}

static bool rpc_test_retained_prefix(void)
{
    const char *params[] = { "retained", "refused" };
    struct json_value result;
    size_t before = json_test_live_blocks();
    zcl_alloc_fault_fail_nth("json_set_str", 2);
    bool converted = rpc_convert_values("help", params, 2, &result);
    bool consumed = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    const struct json_value *first = json_at(&result, 0);
    bool ok = !converted && consumed && result.type == JSON_ARR &&
              json_size(&result) == 1 && first && first->type == JSON_STR;
    if (ok) ok = strcmp(json_get_str(first), "retained") == 0;
    json_free(&result);
    return ok && json_test_live_blocks() == before;
}

static bool rpc_test_string_conversion(const char *arg, bool fault)
{
    const char *params[] = { arg };
    struct json_value result;
    if (fault) zcl_alloc_fault_fail_next("json_set_str");
    bool converted = rpc_convert_values("help", params, 1, &result);
    bool consumed = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    bool ok = converted == !fault && consumed && result.type == JSON_ARR &&
              json_size(&result) == (fault ? 0 : 1);
    if (!fault) {
        const struct json_value *value = json_at(&result, 0);
        ok = ok && value && value->type == (arg ? JSON_STR : JSON_NULL);
        if (ok && arg) ok = strcmp(json_get_str(value), arg) == 0;
    }
    json_free(&result); /* The partial array remains caller-owned. */
    return ok;
}

int check_rpc_string_conversion_cases(void)
{
    printf("rpc_convert_values string allocation refusal and null policy... ");
    bool ok = rpc_test_string_conversion("getinfo", true);
    ok = rpc_test_string_conversion("getinfo", false) && ok;
    ok = rpc_test_string_conversion("", false) && ok;
    ok = rpc_test_string_conversion(NULL, false) && ok;
    ok = rpc_test_retained_prefix() && ok;
    ok = rpc_test_composer_refusal(rpc_compose_params) && ok;
    ok = rpc_test_composer_refusal(cli_compose_rpc_params) && ok;
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
