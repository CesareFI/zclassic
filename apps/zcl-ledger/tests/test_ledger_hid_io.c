/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "ledger_hid.h"

#undef NDEBUG
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { REPLY_CAPACITY = 80 };

static void ignore_broken_pipe(void) {
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
    if (sigemptyset(&ignore_pipe.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignore_pipe, NULL) != 0) _exit(7);
}

static void fake_device(int fd, int mode) {
    ignore_broken_pipe();
    uint8_t request[LEDGER_HID_REPORT_SIZE + 1];
    if (read(fd, request, sizeof request) != (ssize_t)sizeof request) _exit(2);
    uint8_t payload[80] = {'Z', 'C', 'L', 8, 1, 0x90, 0};
    size_t payload_length = mode >= 2 ? sizeof payload : 7;
    if (mode >= 3) { payload[5] = 0; payload[78] = 0x90; }
    uint8_t report[LEDGER_HID_REPORT_SIZE];
    size_t consumed = 0;
    if (ledger_hid_encode(payload, payload_length, 0, report,
                          &consumed) < 0) _exit(3);
    if (mode == 1) report[4] = 1;
    const struct timespec delay = {.tv_nsec = 70000000L};
    if (mode == 4) (void)nanosleep(&delay, NULL);
    if (write(fd, report, sizeof report) !=
        (ssize_t)sizeof report && mode != 4) _exit(4);
    if (mode >= 3) {
        if (mode == 4) (void)nanosleep(&delay, NULL);
        if (ledger_hid_encode(payload + consumed, payload_length - consumed,
                1, report, &consumed) < 0) _exit(5);
        if (write(fd, report, sizeof report) !=
            (ssize_t)sizeof report && mode != 4) _exit(6);
    }
    _exit(0);
}

static void test_reply(int mode, bool expected_success) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(sockets[0]);
        fake_device(sockets[1], mode);
    }
    close(sockets[1]);
    const uint8_t command[] = {0xa5, 1, 0, 0, 0};
    uint8_t response[REPLY_CAPACITY];
    memset(response, 0xa5, sizeof response);
    size_t length = 99;
    int result = ledger_hid_exchange_timeout(sockets[0], command,
                    sizeof command, response, sizeof response, &length, 1000);
    close(sockets[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (expected_success) {
        const uint8_t expected[] = {'Z', 'C', 'L', 8, 1, 0x90, 0};
        assert(result == 0 && length == sizeof expected);
        assert(memcmp(response, expected, sizeof expected) == 0);
    } else {
        assert(result < 0 && length == 0);
        for (size_t i = 0; i < sizeof response; ++i) assert(response[i] == 0);
    }
}

static void test_timeout(void) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    const uint8_t command[] = {0xa5, 1, 0, 0, 0};
    uint8_t response[REPLY_CAPACITY];
    memset(response, 0xa5, sizeof response);
    size_t length = 99;
    assert(ledger_hid_exchange_timeout(sockets[0], command,
        sizeof command, response, sizeof response, &length, 10) < 0);
    assert(length == 0);
    for (size_t i = 0; i < sizeof response; ++i) assert(response[i] == 0);
    close(sockets[0]);
    close(sockets[1]);
}

static void test_multipart_deadline(int mode, int timeout_ms,
                                    bool expected_success) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(sockets[0]);
        fake_device(sockets[1], mode);
    }
    close(sockets[1]);
    const uint8_t command[] = {0xa5, 1, 0, 0, 0};
    uint8_t response[REPLY_CAPACITY];
    memset(response, 0xa5, sizeof response);
    size_t length = 99;
    int result = ledger_hid_exchange_timeout(sockets[0], command,
        sizeof command, response, sizeof response, &length, timeout_ms);
    close(sockets[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (expected_success) {
        assert(result == 0 && length == REPLY_CAPACITY);
        assert(response[0] == 'Z' && response[78] == 0x90 &&
            response[79] == 0);
    } else {
        assert(result < 0 && length == 0);
        for (size_t i = 0; i < sizeof response; ++i)
            assert(response[i] == 0);
    }
}

int main(void) {
    test_reply(0, true);
    test_reply(1, false);
    test_reply(2, false);
    test_timeout();
    test_multipart_deadline(3, 1000, true);
    test_multipart_deadline(4, 100, false);
    return 0;
}
