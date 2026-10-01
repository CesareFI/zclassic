/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A deliberately tiny OS-socket fixture for bench_fresh_sync's isolated-peer
 * preflight.  It is not a chain source and cannot make an IBD benchmark pass:
 * it proves only the benchmark's no-node/no-datadir localhost contract. */

#include "test/test_core.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct bench_peer_fixture {
    char dir[PATH_MAX];
    platform_socket_t listener;
    pthread_t thread;
    _Atomic bool accepted;
};

static void *bench_peer_accept_once(void *opaque) /* raw-pthread-ok: joined */
{
    struct bench_peer_fixture *fixture = opaque;
    struct sockaddr_in client = {0};
    size_t client_size = sizeof(client);
    platform_socket_t peer = platform_socket_accept(
        fixture->listener, (struct sockaddr *)&client, &client_size);
    if (peer != PLATFORM_SOCKET_INVALID) {
        atomic_store(&fixture->accepted, true);
        platform_socket_close(peer);
    }
    return NULL;
}

static bool bench_peer_fixture_write_marker(const char *dir)
{
    char marker[PATH_MAX];
    int marker_len;
    FILE *file;
    bool written;
    bool closed;

    if (!dir)
        return false;
    marker_len = snprintf(marker, sizeof(marker), "%s/fixture.ready", dir);
    if (marker_len < 0 || (size_t)marker_len >= sizeof(marker))
        return false;
    file = fopen(marker, "w");
    if (!file)
        return false;
    written = fputs("localhost-only\n", file) >= 0;
    closed = fclose(file) == 0;
    return written && closed;
}

static bool bench_peer_fixture_listen(struct bench_peer_fixture *fixture,
                                      unsigned short *port_out)
{
    struct sockaddr_in address = {0};
    size_t address_size = sizeof(address);

    fixture->listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true,
                                             false);
    if (fixture->listener == PLATFORM_SOCKET_INVALID)
        return false;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (platform_socket_bind(fixture->listener,
                             (const struct sockaddr *)&address,
                             sizeof(address)) != 0)
        return false;
    if (platform_socket_listen(fixture->listener, 1) != 0)
        return false;
    if (platform_socket_local_address(fixture->listener,
                                      (struct sockaddr *)&address,
                                      &address_size) != 0 ||
        address.sin_family != AF_INET ||
        address.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        address.sin_port == 0)
        return false;
    *port_out = ntohs(address.sin_port);
    return pthread_create(&fixture->thread, NULL, bench_peer_accept_once,
                          fixture) == 0;
}

static bool bench_peer_fixture_start(struct bench_peer_fixture *fixture,
                                     unsigned short *port_out)
{
    if (!fixture || !port_out) return false;
    memset(fixture, 0, sizeof(*fixture));
    fixture->listener = PLATFORM_SOCKET_INVALID;
    if (!test_mkdtemp(fixture->dir, sizeof(fixture->dir), "bench_peer"))
        return false;
    if (!bench_peer_fixture_write_marker(fixture->dir))
        goto fail;
    if (!bench_peer_fixture_listen(fixture, port_out))
        goto fail;
    return true;

fail:
    if (fixture->listener != PLATFORM_SOCKET_INVALID)
        platform_socket_close(fixture->listener);
    fixture->listener = PLATFORM_SOCKET_INVALID;
    (void)test_rm_rf_recursive(fixture->dir);
    return false;
}

static void bench_peer_fixture_stop(struct bench_peer_fixture *fixture)
{
    if (fixture->listener != PLATFORM_SOCKET_INVALID) {
        (void)platform_socket_shutdown_both(fixture->listener);
        platform_socket_close(fixture->listener);
        fixture->listener = PLATFORM_SOCKET_INVALID;
    }
    pthread_join(fixture->thread, NULL);
    (void)test_rm_rf_recursive(fixture->dir);
}

static bool bench_preflight_run(const char *endpoint, bool expect_success)
{
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        if (endpoint)
            (void)setenv("ZCL_BENCH_CONNECT", endpoint, 1);
        else
            (void)unsetenv("ZCL_BENCH_CONNECT");
        (void)setenv("ZCL_BENCH_PREFLIGHT_ONLY", "1", 1);
        execl("./build/bin/bench_fresh_sync", "bench_fresh_sync",
              (char *)NULL);
        _exit(127);
    }
    int status = 0;
    for (unsigned wait_ms = 0; wait_ms < 2000; wait_ms += 20) {
        if (waitpid(child, &status, WNOHANG) == child)
            return WIFEXITED(status) &&
                   (WEXITSTATUS(status) == (expect_success ? 0 : 2));
        platform_sleep_ms(20);
    }
    (void)kill(child, SIGTERM);
    (void)waitpid(child, &status, 0);
    return false;
}

int test_bench_fresh_sync_fixture(void)
{
    int failures = 0;
    TEST("bench fresh sync: bounded localhost peer preflight") {
        struct bench_peer_fixture fixture;
        unsigned short port = 0;
        ASSERT(bench_peer_fixture_start(&fixture, &port));
        char endpoint[64];
        int endpoint_len = snprintf(endpoint, sizeof(endpoint),
                                    "127.0.0.1:%u", (unsigned)port);
        ASSERT(endpoint_len > 0 && (size_t)endpoint_len < sizeof(endpoint));
        ASSERT(bench_preflight_run(endpoint, true));
        bench_peer_fixture_stop(&fixture);
        ASSERT(atomic_load(&fixture.accepted));
        ASSERT(access(fixture.dir, F_OK) != 0);
        ASSERT(bench_preflight_run(NULL, false));
    } _test_next:;
    return failures;
}
