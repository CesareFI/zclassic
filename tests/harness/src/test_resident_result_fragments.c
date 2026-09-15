/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Deterministic regression compiling the actual shared codec under a narrow
 * recv observation wrapper. No sleeps, child processes or production hook.
 * Define RLF_SOURCE as the absolute production .c path; RLF_STANDALONE adds main.
 */
/* Wired into the registered resident_launch group by A: self-identify the
 * production source when the build does not pass -DRLF_SOURCE. Quote-include
 * resolves relative to this file (tests/harness/src -> repo root is ../../..). */
#ifndef RLF_SOURCE
#define RLF_SOURCE "../../../platform/modules/platform/src/resident_launch.c"
#endif
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int rlf_target = -1, rlf_writer = -1;
static const unsigned char *rlf_wire;
static size_t rlf_offset, rlf_sizes[3], rlf_piece;
static unsigned rlf_eagain;
static bool rlf_send_failed;

static ssize_t rlf_recv(int fd, void *data, size_t size, int flags)
{
    ssize_t got = recv(fd, data, size, flags);
    int saved = errno;
    if (fd == rlf_target && got < 0 && (saved == EAGAIN || saved == EWOULDBLOCK)) {
        ++rlf_eagain;
        if (rlf_piece < 3 && rlf_sizes[rlf_piece]) {
            size_t count = rlf_sizes[rlf_piece++];
            ssize_t sent = send(rlf_writer, rlf_wire + rlf_offset, count, MSG_NOSIGNAL);
            if (sent != (ssize_t)count) rlf_send_failed = true;
            else rlf_offset += count;
        }
    }
    errno = saved; /* Return the actual empty-socket EAGAIN, never fabricated data. */
    return got;
}

/* A second test-only instantiation of actual source, with private symbol names.
 * Normal production TU and its API remain entirely unchanged. */
#define resident_launch_revalidate rlf_launch_revalidate
#define resident_launch_init rlf_launch_init
#define resident_launch_prepare rlf_launch_prepare
#define resident_launch_spawn rlf_launch_spawn
#define resident_launch_cancel rlf_launch_cancel
#define resident_result_read rlf_result_read
#define resident_launch_close rlf_launch_close
#include "platform/resident_launch.h"
#define recv rlf_recv
#ifndef RLF_SOURCE
#error "RLF_SOURCE must identify the actual shared resident_launch.c"
#endif
#include RLF_SOURCE
#undef recv
#undef resident_launch_revalidate
#undef resident_launch_init
#undef resident_launch_prepare
#undef resident_launch_spawn
#undef resident_launch_cancel
#undef resident_result_read
#undef resident_launch_close

static int rlf_case(bool split_header)
{
    int peer[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, peer) != 0) { perror("fragment socketpair"); return 1; }
    int flags = fcntl(peer[0], F_GETFL);
    if (flags < 0 || fcntl(peer[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        perror("fragment nonblocking"); (void)close(peer[0]); (void)close(peer[1]); return 1;
    }
    struct resident_result_header wire = {0};
    memcpy(wire.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memset(wire.nonce, 'a', 64); wire.nonce[64] = 0; wire.payload_len = 5;
    unsigned char frame[sizeof(wire) + 5];
    memcpy(frame, &wire, sizeof(wire)); memcpy(frame + sizeof(wire), "READY", 5);
    size_t first = split_header ? 7 : sizeof(wire);
    bool queued = send(peer[1], frame, first, MSG_NOSIGNAL) == (ssize_t)first;
    rlf_target = peer[0]; rlf_writer = peer[1]; rlf_wire = frame;
    rlf_offset = first; rlf_piece = 0; rlf_eagain = 0; rlf_send_failed = false;
    rlf_sizes[0] = split_header ? sizeof(wire) - first : 2;
    rlf_sizes[1] = split_header ? 2 : 3;
    rlf_sizes[2] = split_header ? 3 : 0;
    struct resident_launch launch = {.ipc_native = (uintptr_t)peer[0]};
    memcpy(launch.nonce, wire.nonce, sizeof(launch.nonce));
    struct resident_result_header out = {0};
    char payload[5] = {0}, error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    bool ok = queued && rlf_result_read(&launch, &out, payload, sizeof(payload), 1000,
                                       error, sizeof(error));
    unsigned expected = split_header ? 3 : 2;
    bool passed = ok && !rlf_send_failed && rlf_eagain == expected &&
        out.payload_len == 5 && memcmp(payload, "READY", 5) == 0;
    printf("resident_fragment %s: %s actual_empty_reads=%u expected=%u error=%s\n",
        split_header ? "header_and_payload" : "payload_only", passed ? "GREEN" : "RED",
        rlf_eagain, expected, error);
    rlf_target = rlf_writer = -1; rlf_wire = NULL;
    bool closed_read = close(peer[0]) == 0;
    bool closed_write = close(peer[1]) == 0;
    if (!closed_read || !closed_write) passed = false;
    return passed ? 0 : 1;
}

struct rlf_boundary {
    const char *name;
    size_t queued;
    bool eof, stale, accepted;
    uint32_t timeout;
    int error_number;
    const char *error_text;
};

static int rlf_boundary_case(const struct rlf_boundary *test)
{
    int peer[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, peer) != 0) { perror("boundary socketpair"); return 1; }
    int flags = fcntl(peer[0], F_GETFL);
    if (flags < 0 || fcntl(peer[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        perror("boundary nonblocking"); (void)close(peer[0]); (void)close(peer[1]); return 1;
    }
    struct resident_result_header wire = {0};
    memcpy(wire.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memset(wire.nonce, test->stale ? 'b' : 'a', 64);
    wire.payload_len = 5;
    unsigned char frame[sizeof(wire) + 5];
    memcpy(frame, &wire, sizeof(wire)); memcpy(frame + sizeof(wire), "READY", 5);
    bool setup = send(peer[1], frame, test->queued, MSG_NOSIGNAL) == (ssize_t)test->queued;
    if (test->eof && shutdown(peer[1], SHUT_WR) != 0) setup = false;
    struct resident_launch launch = {.ipc_native = (uintptr_t)peer[0]};
    memset(launch.nonce, 'a', 64);
    struct resident_result_header out = {0};
    char payload[5] = {0}, error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    errno = 0;
    bool accepted = setup && rlf_result_read(&launch, &out, payload, sizeof(payload),
                                            test->timeout, error, sizeof(error));
    int observed_errno = errno;
    bool passed = setup && accepted == test->accepted;
    if (accepted) passed = passed && out.payload_len == 5 && memcmp(payload, "READY", 5) == 0;
    else passed = passed && observed_errno == test->error_number && strstr(error, test->error_text) != NULL;
    printf("resident_fragment %s: %s errno=%d error=%s\n", test->name, passed ? "GREEN" : "RED",
           observed_errno, error);
    bool closed_read = close(peer[0]) == 0;
    bool closed_write = close(peer[1]) == 0;
    return passed && closed_read && closed_write ? 0 : 1;
}

static int rlf_boundaries(void)
{
    const size_t h = sizeof(struct resident_result_header);
    const struct rlf_boundary tests[] = {
        {"timeout0_complete", h + 5, false, false, true, 0, 0, ""},
        {"timeout0_header_withheld", 7, false, false, false, 0, ETIMEDOUT, "timed out after 0 ms"},
        {"timeout0_payload_withheld", h, false, false, false, 0, ETIMEDOUT, "timed out after 0 ms"},
        {"header_EOF", 7, true, false, false, 1000, ECONNRESET, "resident closed the channel"},
        {"payload_EOF", h + 2, true, false, false, 1000, ECONNRESET, "truncated result payload"},
        {"stale_nonce", h + 5, false, true, false, 1000, ESTALE, "result_stale_launch"}
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        failures += rlf_boundary_case(&tests[i]);
    return failures;
}

int resident_result_fragments_run(void)
{
    int failures = rlf_case(false) + rlf_case(true);
    return failures + rlf_boundaries();
}
#ifdef RLF_STANDALONE
int main(void) { return resident_result_fragments_run(); }
#endif
