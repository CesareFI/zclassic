/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: real Darwin outbound raw entry against an isolated PSK fixture hub. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#if defined(__APPLE__)
#include "test/test_core.h"
#include "services/device_identity.h"
#include "services/device_host_runtime.h"
#include "services/device_host_runtime_entry.h"
#include "command/native_command.h"
#include "platform/socket_compat.h"
#include "platform/pipe_compat.h"
#include "platform/clock.h"
#include "base/hex.h"
#include <signal.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>

int host_runtime_darwin_cases(void);
enum { MAC_HOST_TARGET_UNOPENED = -1 };
struct mac_host_fixture {
    char home[1024], directory[2][1200];
    struct device_pairing_store store[2];
    struct db_device_pairing row[2]; uint8_t root[2][32];
    int listener, target_listener, target, app[2], diagnostics[2], output[2];
    uint16_t port, target_port;
    pid_t child; int status; bool custody_lost;
    struct device_host_psk_bridge hub;
    char diagnostic_text[4096]; size_t diagnostic_used;
};
static bool mac_host_cleanup_incomplete;
static void mac_host_close(int *fd)
{
    if (*fd >= 0) close(*fd);
    *fd = -1;
}
static int mac_host_listener(uint16_t *port)
{
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    if (bind(fd, (struct sockaddr *)&address, length) == 0 && listen(fd, 1) == 0 &&
        getsockname(fd, (struct sockaddr *)&address, &length) == 0) {
        *port = ntohs(address.sin_port); return fd;
    }
    close(fd); return -1;
}
static bool mac_host_insert_pair(struct mac_host_fixture *f,
    struct device_identity identity[2], size_t i, bool wrong)
{
    uint64_t now = (uint64_t)(clock_now_wall_ms() / 1000);
    struct db_device_pairing *row = &f->row[i];
    *row = (struct db_device_pairing){.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD,
        .paired_at = now - 1, .expires_at = now + 600};
    memcpy(row->local_key, identity[i].public_key, 32);
    memcpy(row->peer_key, identity[1-i].public_key, 32);
    memcpy(row->profile, f->store[i].profile, 32);
    row->host_scope.inbound_port = row->host_scope.outbound_port = f->target_port;
    row->host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
    struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
    binding->credential_id[0] = 91; binding->key_epoch = 1;
    bool first = memcmp(row->local_key, row->peer_key, 32) < 0;
    memcpy(binding->endpoint_a, first ? row->local_key : row->peer_key, 32);
    memcpy(binding->endpoint_b, first ? row->peer_key : row->local_key, 32);
    uint8_t secret[32] = {17}, proposal[32];
    if (wrong && i == 1) secret[0] = 18;
    struct device_pairing_psk_publication report; struct db_device_pairing found;
    return device_pairing_host_proposal_root(row, proposal) &&
        db_device_pairing_insert_host_psk(&f->store[i], row, secret, proposal, &report) &&
        db_device_pairing_inspect(&f->store[i], row->peer_key, &found, f->root[i]);
}
static bool mac_host_pairs(struct mac_host_fixture *f, bool wrong)
{
    struct device_identity identity[2] = {0};
    struct device_identity_publication_report publication;
    bool ok = true;
    for (size_t i = 0; i < 2; i++) {
        int n = snprintf(f->directory[i], sizeof(f->directory[i]), "%s/profile-%zu", f->home, i);
        if (n <= 0 || (size_t)n >= sizeof(f->directory[i]) ||
            !device_identity_open(&identity[i], f->directory[i], true, &publication).ok) ok = false;
    }
    for (size_t i = 0; i < 2 && ok; i++) {
        ok = device_identity_pair_store(&identity[i], identity[1-i].public_key, &f->store[i]).ok;
        if (!ok) break;
        ok = mac_host_insert_pair(f, identity, i, wrong);
    }
    device_identity_close(&identity[0]); device_identity_close(&identity[1]); return ok;
}
static bool mac_host_open(struct mac_host_fixture *f, bool wrong)
{
    memset(f, 0, sizeof(*f));
    f->listener = f->target_listener = f->child = -1;
    f->target = MAC_HOST_TARGET_UNOPENED;
    f->app[0] = f->app[1] = f->diagnostics[0] = f->diagnostics[1] = f->output[0] = f->output[1] = -1;
    device_host_psk_bridge_init(&f->hub);
    if (mac_host_cleanup_incomplete) return false;
    if (!test_mkdtemp(f->home, sizeof(f->home), "mac-host-client")) return false;
    f->listener = mac_host_listener(&f->port);
    f->target_listener = mac_host_listener(&f->target_port);
    return f->listener >= 0 && f->target_listener >= 0 && platform_socket_pair(f->app) &&
        platform_socket_set_nonblocking(f->app[0], true) &&
        platform_pipe_cloexec_nonblock(f->diagnostics) == 0 &&
        platform_pipe_cloexec_nonblock(f->output) == 0 && mac_host_pairs(f, wrong);
}
static bool mac_host_input(struct mac_host_fixture *f, struct json_value *input, unsigned mode)
{
    char peer[65], root[65];
    zcl_hex_encode(f->row[0].peer_key, 32, peer); zcl_hex_encode(f->root[0], 32, root);
    json_set_object(input);
    return json_push_kv_str(input, "directory", f->directory[0]) && json_push_kv_str(input, "peer_key", peer) &&
        json_push_kv_str(input, "expected_root", root) && json_push_kv_int(input, "target_port", f->target_port) &&
        json_push_kv_str(input, "route_id", "Darwin-isolated-client") && json_push_kv_bool(input, "confirm", true) &&
        json_push_kv_int(input, "handshake_ms", mode == 2 ? 100 : 1500) &&
        json_push_kv_int(input, "session_ms", 3000) && json_push_kv_int(input, "idle_ms", 1500) &&
        json_push_kv_str(input, "route_address", "127.0.0.1") && json_push_kv_int(input, "route_port", f->port) &&
        json_push_kv_int(input, "connect_ms", 1000);
}
static void mac_host_native_entry(struct mac_host_fixture *f, struct json_value *input, bool named, bool standalone)
{
    char wire[4097], argument[4120], path[1200];
    size_t length = json_write(input, wire, sizeof(wire));
    if (length == 0 || length >= sizeof(wire)) _exit(122);
    if (named) {
        if (snprintf(path, sizeof(path), "%s/client-input", f->home) >= (int)sizeof(path)) _exit(122);
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0 || write(fd, wire, length) != (ssize_t)length) _exit(122);
        if (close(fd) != 0 || snprintf(argument, sizeof(argument), "--input-file=%s", path) >= (int)sizeof(argument)) _exit(122);
    } else if (snprintf(argument, sizeof(argument), "--input=%s", wire) >= (int)sizeof(argument)) _exit(122);
    char home[1200];
    if (snprintf(home, sizeof(home), "HOME=%s", f->home) >= (int)sizeof(home)) _exit(122);
    char *env[] = {home, "PATH=/usr/bin:/bin", "ZCL_OPERATOR_LANE=INVALID-PUBLIC-RAW-SENTINEL", NULL};
    char *node_argv[] = {"build/bin/z23", "ops.mesh.device.host.client", argument, NULL};
    char *tunnel_argv[] = {"build/bin/tunnel", "client", argument, NULL};
    char **argv = standalone ? tunnel_argv : node_argv;
    execve(argv[0], argv, env); _exit(127);
}
static bool mac_host_masks_equal(const sigset_t *a, const sigset_t *b)
{
    for (int number = 1; number < NSIG; number++)
        if (sigismember(a, number) != sigismember(b, number)) {
            fprintf(stderr, "mac HOST signal mask mismatch signal=%d before=%d after=%d\n",
                    number, sigismember(a, number), sigismember(b, number));
            return false;
        }
    return true;
}
static bool mac_host_signals_restored(const struct sigaction prior[3], const sigset_t *mask)
{
    const int numbers[] = {SIGINT, SIGTERM, SIGHUP};
    sigset_t restored;
    if (sigprocmask(SIG_SETMASK, NULL, &restored) != 0) {
        fprintf(stderr, "mac HOST restored process mask query errno=%d\n", errno); return false;
    }
    if (!mac_host_masks_equal(mask, &restored)) return false;
    for (size_t i = 0; i < 3; i++) {
        struct sigaction after;
        if (sigaction(numbers[i], NULL, &after) != 0) {
            fprintf(stderr, "mac HOST restored sigaction query signal=%d errno=%d\n", numbers[i], errno); return false;
        }
        if (after.sa_handler != prior[i].sa_handler || after.sa_flags != prior[i].sa_flags ||
            !mac_host_masks_equal(&after.sa_mask, &prior[i].sa_mask)) {
            fprintf(stderr, "mac HOST sigaction mismatch signal=%d handler_equal=%d flags_before=%x flags_after=%x\n",
                    numbers[i], after.sa_handler == prior[i].sa_handler, prior[i].sa_flags, after.sa_flags);
            return false;
        }
    }
    return true;
}
static void mac_host_prior_signal(int number) { (void)number; }
static bool mac_host_distinct_signals(void)
{
    const int numbers[] = {SIGINT, SIGTERM, SIGHUP};
    struct sigaction action = {.sa_handler = mac_host_prior_signal, .sa_flags = SA_RESTART | SA_NODEFER};
    sigemptyset(&action.sa_mask); sigaddset(&action.sa_mask, SIGUSR1);
    for (size_t i = 0; i < 3; i++)
        if (sigaction(numbers[i], &action, NULL) != 0) return false;
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked, SIGUSR2);
    return sigprocmask(SIG_BLOCK, &blocked, NULL) == 0;
}
/* A full bounded kernel inventory: truncation or an out-of-range FD refuses. */
static bool mac_host_fd_snapshot(int flags[256])
{
    struct proc_fdinfo descriptors[256];
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (bytes <= 0 || bytes >= (int)sizeof(descriptors) || bytes % (int)sizeof(descriptors[0]) != 0) {
        fprintf(stderr, "mac HOST fd inventory bytes=%d capacity=%zu errno=%d\n", bytes, sizeof(descriptors), errno);
        return false;
    }
    for (size_t i = 0; i < 256; i++) flags[i] = -1;
    size_t count = (size_t)bytes / sizeof(descriptors[0]);
    for (size_t i = 0; i < count; i++) {
        int fd = descriptors[i].proc_fd;
        if (fd < 0 || fd >= 256) {
            fprintf(stderr, "mac HOST fd inventory out of range fd=%d\n", fd); return false;
        }
        flags[fd] = fcntl(fd, F_GETFD);
        if (flags[fd] < 0) {
            fprintf(stderr, "mac HOST fd inventory F_GETFD fd=%d errno=%d\n", fd, errno); return false;
        }
    }
    return true;
}
static void mac_host_shared_entry(struct json_value *input)
{
    const int numbers[] = {SIGINT, SIGTERM, SIGHUP};
    struct sigaction prior[3]; sigset_t mask;
    int before[256], after[256];
    int flags[2] = {fcntl(0, F_GETFL), fcntl(1, F_GETFL)};
    if (!mac_host_distinct_signals()) {
        fprintf(stderr, "mac HOST setup distinct signals errno=%d\n", errno); _exit(125);
    }
    if (!mac_host_fd_snapshot(before)) {
        fprintf(stderr, "mac HOST setup fd inventory failed\n"); _exit(125);
    }
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0) {
        fprintf(stderr, "mac HOST setup process mask errno=%d\n", errno); _exit(125);
    }
    for (size_t i = 0; i < 3; i++)
        if (sigaction(numbers[i], NULL, &prior[i]) != 0) {
            fprintf(stderr, "mac HOST setup sigaction signal=%d errno=%d\n", numbers[i], errno); _exit(125);
        }
    enum device_host_runtime_entry_exit status;
    (void)device_host_runtime_entry_run(input, false, &status);
    for (int fd = 0; fd < 2; fd++) {
        int restored = fcntl(fd, F_GETFL);
        if (restored != flags[fd]) {
            fprintf(stderr, "mac HOST stdio flags fd=%d before=%x after=%x errno=%d\n", fd, flags[fd], restored, errno);
            _exit(125);
        }
    }
    if (!mac_host_signals_restored(prior, &mask)) {
        fprintf(stderr, "mac HOST signal restoration failed\n"); _exit(125);
    }
    if (!mac_host_fd_snapshot(after)) {
        fprintf(stderr, "mac HOST restored fd inventory failed\n"); _exit(125);
    }
    for (size_t i = 0; i < 256; i++) if (before[i] != after[i]) {
        fprintf(stderr, "mac HOST fd mismatch fd=%zu before=%d after=%d\n", i, before[i], after[i]); _exit(125);
    }
    _exit((int)status);
}
static int mac_host_child_output(struct mac_host_fixture *f, unsigned mode)
{
    if (mode != 5) return f->output[1];
    char path[1200];
    if (snprintf(path, sizeof(path), "%s/regular-output", f->home) >= (int)sizeof(path)) return -1;
    return open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
}
static void mac_host_child(struct mac_host_fixture *f, struct json_value *input, bool native, unsigned mode)
{
    struct sigaction action = {.sa_handler = SIG_DFL}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) != 0) _exit(120);
    sigset_t unblocked; sigemptyset(&unblocked); sigaddset(&unblocked, SIGPIPE);
    if (sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0) _exit(124);
    int output = mac_host_child_output(f, mode);
    if (output < 0) _exit(121);
    if (dup2(f->app[1], 0) < 0 || dup2(output, 1) < 0 || dup2(f->diagnostics[1], 2) < 0) _exit(121);
    mac_host_close(&f->app[0]); mac_host_close(&f->app[1]);
    mac_host_close(&f->diagnostics[0]); mac_host_close(&f->diagnostics[1]);
    mac_host_close(&f->listener); mac_host_close(&f->target_listener);
    if (output != f->output[1]) close(output);
    mac_host_close(&f->output[0]); mac_host_close(&f->output[1]);
    if (native || mode == 6) mac_host_native_entry(f, input, mode == 0, mode == 6);
    mac_host_shared_entry(input);
}
static bool mac_host_poll_child(struct mac_host_fixture *f)
{
    if (f->child <= 0) return !f->custody_lost;
    pid_t seen = waitpid(f->child, &f->status, WNOHANG);
    if (seen == f->child) { f->child = -1; return true; }
    if (seen < 0 && errno == ECHILD) {
        fprintf(stderr, "mac HOST fixture lost child custody pid=%ld\n", (long)f->child);
        f->custody_lost = true; f->child = -1;
    }
    return false;
}
static bool mac_host_reap(struct mac_host_fixture *f)
{
    if (mac_host_poll_child(f)) return true;
    if (f->custody_lost) return false;
    if (kill(f->child, SIGKILL) < 0 && errno != ESRCH) return false;
    int64_t end = clock_now_monotonic_ns() + INT64_C(2000000000);
    for (unsigned attempt = 0; attempt < 400 && clock_now_monotonic_ns() < end; attempt++) {
        if (mac_host_poll_child(f)) return true;
        (void)poll(NULL, 0, 5);
    }
    fprintf(stderr, "mac HOST fixture cleanup retained child=%ld\n", (long)f->child); return false;
}
static bool mac_host_cleanup(struct mac_host_fixture *f)
{
    bool reaped = mac_host_reap(f);
    if (!reaped) {
        mac_host_cleanup_incomplete = true;
        fprintf(stderr, "mac HOST fixture retains home=%s child=%ld cleanup_incomplete\n", f->home, (long)f->child);
    }
    device_host_psk_bridge_close(&f->hub, DEVICE_HOST_BRIDGE_CANCELLED);
    int *fds[] = {&f->listener,&f->target_listener,&f->target,&f->app[0],&f->app[1],
        &f->diagnostics[0],&f->diagnostics[1],&f->output[0],&f->output[1]};
    for (size_t i = 0; i < sizeof(fds)/sizeof(fds[0]); i++) mac_host_close(fds[i]);
    if (reaped && f->home[0]) test_rm_rf(f->home);
    return reaped;
}
static bool mac_host_hub_open(struct mac_host_fixture *f, int carrier)
{
    if (!platform_socket_set_nonblocking(carrier, true)) { close(carrier); return false; }
    struct device_host_psk_spec session = {.store = &f->store[1], .direction = DEVICE_PAIRING_HOST_INBOUND,
        .port = f->target_port, .deadline_ns = clock_now_monotonic_ns() + INT64_C(3000000000)};
    memcpy(session.peer, f->row[1].peer_key, 32); memcpy(session.approved_root, f->root[1], 32);
    struct device_host_psk_bridge_spec spec = {.session = session,
        .carrier_input_fd = carrier, .carrier_output_fd = carrier, .input_fd = -1, .output_fd = -1};
    enum device_host_bridge_result result;
    (void)device_host_psk_bridge_open(&f->hub, &spec, &result);
    if (!f->hub.observation.io_taken) close(carrier);
    return result == DEVICE_HOST_BRIDGE_READY;
}
static void mac_host_diagnostics(struct mac_host_fixture *f)
{
    size_t left = sizeof(f->diagnostic_text) - f->diagnostic_used - 1;
    ssize_t seen = read(f->diagnostics[0], f->diagnostic_text + f->diagnostic_used, left);
    if (seen > 0) f->diagnostic_used += (size_t)seen;
    f->diagnostic_text[f->diagnostic_used] = 0;
}
static bool mac_host_target_tick(struct mac_host_fixture *f, bool *echoed)
{
    if (f->target < 0) {
        f->target = accept(f->target_listener, NULL, NULL);
        if (f->target >= 0 && !platform_socket_set_nonblocking(f->target, true)) return false;
    }
    if (f->target < 0 || *echoed) return true;
    char bytes[3]; ssize_t seen = recv(f->target, bytes, sizeof(bytes), MSG_PEEK | MSG_DONTWAIT);
    if (seen != 3) return seen >= 0 || errno == EAGAIN;
    if (recv(f->target, bytes, 3, MSG_DONTWAIT) != 3 || memcmp(bytes, "abc", 3) != 0) return false;
    if (send(f->target, "xyz", 3, MSG_NOSIGNAL) != 3 || shutdown(f->target, SHUT_WR) != 0) return false;
    *echoed = true; return true;
}
static bool mac_host_hub_tick(struct mac_host_fixture *f, unsigned mode, bool *opened, bool *echoed)
{
    int carrier = *opened ? -1 : accept(f->listener, NULL, NULL);
    if (carrier >= 0) {
        *opened = true;
        if (!mac_host_hub_open(f, carrier)) return false;
    }
    if (*opened && mode != 2 && mode != 3) {
        enum device_host_bridge_result result;
        (void)device_host_psk_bridge_step(&f->hub, &result);
        if (!mac_host_target_tick(f, echoed)) return false;
    }
    return true;
}
static bool mac_host_reply_complete(unsigned mode, bool echoed, size_t got, const char reply[4])
{
    return (mode != 0 && mode != 6) || (echoed && got == 3 && memcmp(reply, "xyz", 3) == 0);
}
static bool mac_host_pump(struct mac_host_fixture *f, unsigned mode, char reply[4])
{
    bool echoed = false, opened = false, cancelled = false; size_t got = 0;
    int64_t start = clock_now_monotonic_ns(), end = start + INT64_C(5000000000);
    for (unsigned attempt = 0; attempt < 5000 && clock_now_monotonic_ns() < end; attempt++) {
        if (!mac_host_hub_tick(f, mode, &opened, &echoed)) return false;
        if (mode == 3 && opened && !cancelled && clock_now_monotonic_ns() - start > INT64_C(100000000)) {
            if (kill(f->child, SIGTERM) != 0) return false;
            cancelled = true;
        }
        if (got < 3) {
            ssize_t seen = read(f->output[0], reply + got, 3 - got);
            if (seen > 0) got += (size_t)seen;
        }
        mac_host_diagnostics(f);
        if (mac_host_poll_child(f)) {
            mac_host_diagnostics(f);
            return mac_host_reply_complete(mode, echoed, got, reply);
        }
        (void)poll(NULL, 0, 1);
    }
    return false;
}
static int mac_host_case(unsigned mode, bool native)
{
    int failures = 0; struct mac_host_fixture f; struct json_value input = {0}; char reply[4] = {0};
    bool opened = mac_host_open(&f, mode == 1);
    TEST_CASE("Darwin raw HOST client: real isolated PSK hub, exact bytes and finite terminal cleanup") {
        ASSERT(opened); ASSERT(mac_host_input(&f, &input, mode));
        /* Darwin exposes the historical FWASWRITTEN bit through F_GETFL.
         * Prime it before fork so exact restoration checks retain every bit. */
        char primed = 0;
        ASSERT_EQ(write(f.output[1], "p", 1), 1);
        ASSERT_EQ(read(f.output[0], &primed, 1), 1);
        ASSERT_EQ(primed, 'p');
        if (mode == 4) {
            mac_host_close(&f.output[0]);
        }
        ASSERT_EQ(fflush(NULL), 0);
        f.child = fork(); ASSERT(f.child >= 0);
        if (f.child == 0) mac_host_child(&f, &input, native, mode);
        mac_host_close(&f.app[1]); mac_host_close(&f.diagnostics[1]); mac_host_close(&f.output[1]);
        if (mode != 5) {
            ASSERT_EQ(send(f.app[0], "abc", 3, MSG_NOSIGNAL), 3);
            ASSERT_EQ(shutdown(f.app[0], SHUT_WR), 0);
        }
        ASSERT(mac_host_pump(&f, mode, reply)); ASSERT(WIFEXITED(f.status));
        if (WEXITSTATUS(f.status) == 125) fprintf(stderr, "mac HOST child diagnostic: %s\n", f.diagnostic_text);
        ASSERT_EQ(WEXITSTATUS(f.status), (mode == 0 || mode == 6) ? DEVICE_HOST_ENTRY_OK : DEVICE_HOST_ENTRY_FAILED);
        ASSERT(strstr(f.diagnostic_text, "cleanup_complete=1") != NULL);
        if (mode == 2) ASSERT(strstr(f.diagnostic_text, "result=deadline") != NULL);
        if (mode == 3) ASSERT(strstr(f.diagnostic_text, "result=cancelled") != NULL);
        if (mode == 4) ASSERT(strstr(f.diagnostic_text, "result=io_error") != NULL);
        if (mode == 1 || mode == 2 || mode == 3) { ASSERT_EQ(f.target, MAC_HOST_TARGET_UNOPENED); ASSERT_EQ(reply[0], 0); }
    } TEST_END
    json_free(&input); if (!mac_host_cleanup(&f)) failures++; return failures;
}
static int mac_host_refusals(void)
{
    int failures = 0;
    TEST_CASE("Darwin receiver remains unsupported without changing stdio flags") {
        struct device_host_runtime_observation out;
        struct zcl_result result = device_host_runtime_receiver_run(NULL, &out);
        ASSERT(!result.ok); ASSERT_EQ(out.result, DEVICE_HOST_BRIDGE_UNSUPPORTED); ASSERT(out.cleanup_complete);
        struct json_value input = {0}; enum device_host_runtime_entry_exit status;
        int input_flags = fcntl(0, F_GETFL), output_flags = fcntl(1, F_GETFL);
        result = device_host_runtime_entry_run(&input, true, &status);
        ASSERT(!result.ok); ASSERT_EQ(status, DEVICE_HOST_ENTRY_UNSUPPORTED);
        ASSERT_EQ(fcntl(0, F_GETFL), input_flags); ASSERT_EQ(fcntl(1, F_GETFL), output_flags);
        json_free(&input);
    } TEST_END
    return failures;
}
static int mac_host_unsupported_roles(void)
{
    int failures = 0;
    const char *roles[] = {"ops.mesh.device.host.receiver", "ops.mesh.device.host.package.run"};
    TEST_CASE("Darwin native receiver/package retain unsupported dispatch") {
        for (size_t i = 0; i < sizeof(roles)/sizeof(roles[0]); i++) {
            struct mac_host_fixture f = {.child = -1};
            ASSERT_EQ(fflush(NULL), 0);
            f.child = fork(); ASSERT(f.child >= 0);
            if (f.child == 0) {
                char *argv[] = {"z23", (char *)roles[i], "--input={}", NULL};
                zcl_native_device_host_runtime_exit_if_requested(3, argv); _exit(123);
            }
            int64_t end = clock_now_monotonic_ns() + INT64_C(2000000000);
            for (unsigned attempt = 0; attempt < 400 && !mac_host_poll_child(&f) && clock_now_monotonic_ns() < end; attempt++)
                (void)poll(NULL, 0, 5);
            bool exited = f.child <= 0;
            bool cleaned = mac_host_reap(&f);
            ASSERT(exited && cleaned); ASSERT(WIFEXITED(f.status)); ASSERT_EQ(WEXITSTATUS(f.status), ZCL_COMMAND_EXIT_BLOCKED);
        }
    } TEST_END
    return failures;
}
static void mac_host_mutate_input(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd >= 0) { (void)write(fd, "x", 1); close(fd); }
}
static int mac_host_named_input(void)
{
    int failures = 0; char root[1024] = {0}, path[1200], alias[1200];
    int fd = -1; char text[128]; size_t length = 0;
    TEST_CASE("Darwin named input retains bounded owner-mode nofollow preparation") {
        ASSERT(test_mkdtemp(root, sizeof(root), "mac-host-input"));
        ASSERT(snprintf(path, sizeof(path), "%s/input", root) < (int)sizeof(path));
        ASSERT(snprintf(alias, sizeof(alias), "%s/alias", root) < (int)sizeof(alias));
        ASSERT(!zcl_native_device_host_input_file_read(path, text, sizeof(text), &length));
        ASSERT_EQ(length, 0);
        fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600); ASSERT(fd >= 0);
        ASSERT_EQ(write(fd, "{}\n", 3), 3); ASSERT_EQ(close(fd), 0); fd = -1;
        ASSERT(zcl_native_device_host_input_file_read(path, text, sizeof(text), &length));
        ASSERT_EQ(length, 2); ASSERT(strcmp(text, "{}") == 0);
        ASSERT(!zcl_native_device_host_input_file_read(path, text, 3, &length)); ASSERT_EQ(length, 0);
        ASSERT_EQ(chmod(path, 0666), 0);
        ASSERT(!zcl_native_device_host_input_file_read(path, text, sizeof(text), &length));
        ASSERT_EQ(chmod(path, 0600), 0); ASSERT_EQ(symlink(path, alias), 0);
        ASSERT(!zcl_native_device_host_input_file_read(alias, text, sizeof(text), &length));
        zcl_native_device_host_input_file_hook_for_test(mac_host_mutate_input);
        bool stable = zcl_native_device_host_input_file_read(path, text, sizeof(text), &length);
        zcl_native_device_host_input_file_hook_for_test(NULL);
        ASSERT(!stable); ASSERT_EQ(length, 0);
    } TEST_END
    zcl_native_device_host_input_file_hook_for_test(NULL);
    if (fd >= 0) close(fd);
    if (root[0]) test_rm_rf(root);
    return failures;
}
struct mac_shell_fixture {
    char home[1024], ssh[1200], route[1200], calls[1200], probe_pid[1200], output[1200];
    struct mac_host_fixture process;
};
static bool mac_shell_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode);
    if (fd < 0) return false;
    bool ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    return close(fd) == 0 && ok;
}
static bool mac_shell_read(const char *path, char *text, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t count = read(fd, text, capacity - 1);
    bool closed = close(fd) == 0;
    if (count < 0) return false;
    text[count] = 0; return closed;
}
static bool mac_shell_prepare(struct mac_shell_fixture *f, unsigned mode)
{
    memset(f, 0, sizeof(*f)); f->process.child = -1;
    if (!test_mkdtemp(f->home, sizeof(f->home), "mac-host-shell")) return false;
    const char *names[] = {"ssh", "route", "calls", "probe-pid", "output"};
    char *paths[] = {f->ssh, f->route, f->calls, f->probe_pid, f->output};
    for (size_t i = 0; i < 5; i++)
        if (snprintf(paths[i], 1200, "%s/%s", f->home, names[i]) >= 1200) return false;
    char script[8192];
    const char *probe = mode == 2 ? "printf 'mlkem768x25519-sha256\n'" :
        mode == 3 ? "exec /bin/sleep 30" : "printf 'mlkem768x25519-sha256\nsntrup761x25519-sha512@openssh.com\n'";
    int length = snprintf(script, sizeof(script),
        "#!/bin/sh\nif [ \"$1\" = -Q ]; then\n printf '%%s\n' \"$$\" >%s\n %s\n exit 0\nfi\nprintf '%%s\n' \"$@\" >%s\nexit 73\n",
        f->probe_pid, probe, f->calls);
    const char *route = "{\"directory\":\"/var/lib/z23x\",\"peer_key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"expected_root\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"target_port\":22,\"route_id\":\"PUBLIC-local-loopback\",\"handshake_ms\":5000,\"session_ms\":15000,\"idle_ms\":5000,\"confirm\":true,\"route_address\":\"127.0.0.1\",\"route_port\":4000,\"connect_ms\":3000}";
    return length > 0 && (size_t)length < sizeof(script) &&
        mac_shell_write(f->ssh, script, 0700) && mac_shell_write(f->route, route, 0600);
}
static void mac_shell_exec(struct mac_shell_fixture *f, unsigned mode)
{
    char input[1600], path[1400];
    int length = snprintf(input, sizeof(input), "--input={\"user\":\"%s\",\"host\":\"private-peer\",\"route_input\":\"%s\",\"dry_run\":%s}",
        mode == 4 ? "bad;user" : "alice", f->route, mode == 0 ? "true" : "false");
    if (length < 0 || (size_t)length >= sizeof(input)) _exit(122);
    int fd = open(f->output, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(122);
    close(fd);
    if (snprintf(path, sizeof(path), "PATH=%s", f->home) >= (int)sizeof(path)) _exit(122);
    char *env[] = {path, NULL};
    char *argv[] = {"build/bin/z23", "ops.mesh.device.host.shell", input, NULL};
    execve(argv[0], argv, env); _exit(127);
}
static bool mac_shell_exact_argv(struct mac_shell_fixture *f)
{
    char self[4096], actual[8192], expected[8192];
    if (!realpath("build/bin/z23", self) || !mac_shell_read(f->calls, actual, sizeof(actual))) return false;
    int length = snprintf(expected, sizeof(expected),
        "-o\nKexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com\n-o\nStrictHostKeyChecking=yes\n-o\nControlPath=none\n-o\nProxyCommand=%s ops mesh device host client --input-file=%s\n--\nalice@private-peer\n", self, f->route);
    return length > 0 && (size_t)length < sizeof(expected) && !strcmp(expected, actual);
}
static bool mac_shell_probe_gone(const struct mac_shell_fixture *f)
{
    char text[64];
    if (!mac_shell_read(f->probe_pid, text, sizeof(text))) return false;
    char *end = NULL; long pid = strtol(text, &end, 10);
    if (pid <= 1 || !end || strcmp(end, "\n")) return false;
    return kill((pid_t)pid, 0) < 0 && errno == ESRCH;
}
static bool mac_shell_verify(struct mac_shell_fixture *f, unsigned mode)
{
    const int expected[] = {ZCL_COMMAND_EXIT_OK, 73, ZCL_COMMAND_EXIT_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED, ZCL_COMMAND_EXIT_INVALID};
    char output[8192]; struct stat st;
    if (!WIFEXITED(f->process.status) || WEXITSTATUS(f->process.status) != expected[mode]) return false;
    if (!mac_shell_read(f->output, output, sizeof(output))) return false;
    bool calls = mode == 1 ? mac_shell_exact_argv(f) : lstat(f->calls, &st) < 0 && errno == ENOENT;
    if (!calls) return false;
    bool probe = mode == 0 || mode == 4 ? lstat(f->probe_pid, &st) < 0 && errno == ENOENT : mac_shell_probe_gone(f);
    if (!probe) return false;
    if (mode == 0) return strstr(output, "\"kex_probe\":\"skipped\"") != NULL;
    if (mode == 2 || mode == 3) return strstr(output, "HOST_SHELL_SSH_KEX_UNAVAILABLE") != NULL;
    return true;
}
static bool mac_shell_cleanup(struct mac_shell_fixture *f)
{
    if (!mac_host_reap(&f->process)) return false;
    struct stat st;
    if (lstat(f->probe_pid, &st) == 0 && !mac_shell_probe_gone(f)) {
        /* A recorded probe may outlive failed z23 cleanup. Never signal an
         * unowned numeric PID; retain its identity/evidence for reconciliation. */
        char identity[64] = {0};
        (void)mac_shell_read(f->probe_pid, identity, sizeof(identity));
        fprintf(stderr, "mac shell fixture retained home=%s probe_pid=%s", f->home, identity);
        mac_host_cleanup_incomplete = true;
        return false;
    }
    if (f->home[0]) test_rm_rf(f->home);
    return true;
}
static int mac_shell_case(unsigned mode)
{
    int failures = 0; struct mac_shell_fixture f;
    bool prepared = mac_shell_prepare(&f, mode);
    TEST_CASE("Darwin actual host.shell: private fake SSH, no network, exact execution/refusal") {
        ASSERT(prepared); ASSERT_EQ(fflush(NULL), 0);
        f.process.child = fork(); ASSERT(f.process.child >= 0);
        if (f.process.child == 0) mac_shell_exec(&f, mode);
        int64_t end = clock_now_monotonic_ns() + INT64_C(8000000000);
        for (unsigned i = 0; i < 1600 && !mac_host_poll_child(&f.process) && clock_now_monotonic_ns() < end; i++)
            (void)poll(NULL, 0, 5);
        ASSERT(f.process.child <= 0);
        bool verified = mac_shell_verify(&f, mode);
        if (!verified) fprintf(stderr, "mac shell mode=%u waitstatus=%d\n", mode, f.process.status);
        ASSERT(verified);
    } TEST_END
    if (!mac_shell_cleanup(&f)) failures++;
    return failures;
}

int host_runtime_darwin_cases(void)
{
    int failures = mac_host_refusals() + mac_host_unsupported_roles() + mac_host_named_input();
    for (unsigned mode = 0; mode < 5; mode++) failures += mac_host_case(mode, mode % 2 == 0);
    failures += mac_host_case(0, false) + mac_host_case(5, false) + mac_host_case(6, false);
    for (unsigned mode = 0; mode < 5; mode++) failures += mac_shell_case(mode);
    return failures;
}
#else
typedef int host_runtime_darwin_tests_not_built;
#endif
