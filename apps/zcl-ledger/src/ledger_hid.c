/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "ledger_hid.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint16_t read_be16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

int ledger_hid_encode(const uint8_t *payload, size_t payload_len,
                      uint16_t sequence, uint8_t report[LEDGER_HID_REPORT_SIZE],
                      size_t *consumed) {
    if (!payload || !report || !consumed || payload_len > UINT16_MAX ||
        (!sequence && !payload_len)) return -1;
    memset(report, 0, LEDGER_HID_REPORT_SIZE);
    report[0] = 1;
    report[1] = 1;
    report[2] = 5;
    report[3] = (uint8_t)(sequence >> 8);
    report[4] = (uint8_t)sequence;
    size_t header = sequence ? 5u : 7u;
    if (!sequence) {
        report[5] = (uint8_t)(payload_len >> 8);
        report[6] = (uint8_t)payload_len;
    }
    size_t n = payload_len < LEDGER_HID_REPORT_SIZE - header
                   ? payload_len : LEDGER_HID_REPORT_SIZE - header;
    memcpy(report + header, payload, n);
    *consumed = n;
    return 0;
}

int ledger_hid_decode(const uint8_t report[LEDGER_HID_REPORT_SIZE],
                      uint16_t sequence, size_t *declared_len,
                      const uint8_t **chunk, size_t *chunk_len) {
    if (!report || !declared_len || !chunk || !chunk_len ||
        report[0] != 1 || report[1] != 1 || report[2] != 5 ||
        read_be16(report + 3) != sequence) return -1;
    size_t header = sequence ? 5u : 7u;
    if (!sequence) *declared_len = read_be16(report + 5);
    *chunk = report + header;
    *chunk_len = LEDGER_HID_REPORT_SIZE - header;
    return 0;
}

static bool deadline_start(struct timespec *deadline, int timeout_ms) {
    if (clock_gettime(CLOCK_MONOTONIC, deadline) < 0) return false;
    deadline->tv_sec += timeout_ms / 1000;
    deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        ++deadline->tv_sec;
        deadline->tv_nsec -= 1000000000L;
    }
    return true;
}

static int deadline_remaining(const struct timespec *deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    if (now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec &&
         now.tv_nsec >= deadline->tv_nsec)) return 0;
    time_t seconds = deadline->tv_sec - now.tv_sec;
    long nanos = deadline->tv_nsec - now.tv_nsec;
    if (nanos < 0) { --seconds; nanos += 1000000000L; }
    if (seconds >= INT_MAX / 1000) return INT_MAX;
    return (int)(seconds * 1000 + (nanos + 999999L) / 1000000L);
}

static int transfer(int fd, short events, uint8_t *buffer, size_t len,
                    const struct timespec *deadline) {
    struct pollfd pfd = {.fd = fd, .events = events};
    int ready = -1;
    do {
        int remaining = deadline_remaining(deadline);
        if (remaining <= 0) return -1;
        ready = poll(&pfd, 1, remaining);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0 || !(pfd.revents & events)) return -1;
    ssize_t count;
    do {
        if (deadline_remaining(deadline) <= 0) return -1;
        count = events == POLLOUT ? write(fd, buffer, len) : read(fd, buffer, len);
    } while (count < 0 && errno == EINTR);
    return count == (ssize_t)len ? 0 : -1;
}

static int send_apdu(int fd, const uint8_t *apdu, size_t apdu_len,
                     const struct timespec *deadline) {
    uint8_t report[LEDGER_HID_REPORT_SIZE + 1] = {0};
    uint16_t sequence = 0;
    size_t offset = 0;
    while (offset < apdu_len) {
        size_t consumed;
        if (ledger_hid_encode(apdu + offset, apdu_len - offset, sequence,
                              report + 1, &consumed) < 0 ||
            transfer(fd, POLLOUT, report, sizeof report, deadline) < 0) return -1;
        offset += consumed;
        if (sequence == UINT16_MAX) return -1;
        ++sequence;
    }
    return 0;
}

static int recv_response(int fd, uint8_t *response, size_t response_cap,
                         size_t *response_len,
                         const struct timespec *deadline) {
    uint8_t report[LEDGER_HID_REPORT_SIZE + 1] = {0};
    uint16_t sequence = 0;
    size_t offset = 0;
    size_t declared = 0;
    do {
        if (transfer(fd, POLLIN, report, LEDGER_HID_REPORT_SIZE,
                     deadline) < 0) return -1;
        const uint8_t *chunk;
        size_t available;
        if (ledger_hid_decode(report, sequence, &declared, &chunk,
                              &available) < 0 || declared < 2 ||
            declared > response_cap || declared > LEDGER_HID_MAX_RESPONSE ||
            offset > declared) return -1;
        size_t remaining = declared - offset;
        size_t n = remaining < available ? remaining : available;
        memcpy(response + offset, chunk, n);
        offset += n;
        if (sequence == UINT16_MAX) return -1;
        ++sequence;
    } while (offset < declared);
    *response_len = declared;
    return 0;
}

int ledger_hid_exchange_timeout(int fd, const uint8_t *apdu, size_t apdu_len,
                                uint8_t *response, size_t response_cap,
                                size_t *response_len, int timeout_ms) {
    if (response_len) *response_len = 0;
    if (fd < 0 || !apdu || !apdu_len || apdu_len > UINT16_MAX ||
        !response || !response_len || response_cap < 2 || timeout_ms < 1) return -1;
    struct timespec deadline;
    if (!deadline_start(&deadline, timeout_ms)) {
        memset(response, 0, response_cap);
        return -1;
    }
    size_t received = 0;
    if (send_apdu(fd, apdu, apdu_len, &deadline) < 0 ||
        recv_response(fd, response, response_cap, &received, &deadline) < 0) {
        memset(response, 0, response_cap);
        return -1;
    }
    *response_len = received;
    return 0;
}

int ledger_hid_exchange(int fd, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len) {
    return ledger_hid_exchange_timeout(fd, apdu, apdu_len, response,
                                       response_cap, response_len, 3000);
}
