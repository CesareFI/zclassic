/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: see mesh_terminal_hub_io.h. */

#if defined(__linux__)

#define _GNU_SOURCE
#include "mesh_terminal_hub_io.h"

#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

bool hub_io_send(int fd, const uint8_t *frame, size_t total)
{
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = send(fd, frame + sent, total - sent, MSG_NOSIGNAL);
        if (n > 0)
            sent += (size_t)n;
        else if (n < 0 && errno != EINTR)
            return false;
    }
    return true;
}

bool hub_io_send_frame(int fd, uint8_t type, const uint8_t *payload, size_t len)
{
    uint8_t frame[MESH_TERMINAL_HUB_FRAME_MAX];
    if (len && payload)
        memcpy(frame + MESH_TERMINAL_HUB_HEADER_BYTES, payload, len);
    size_t total = mesh_terminal_hub_frame_seal(frame, type, len);
    return total != 0 && hub_io_send(fd, frame, total);
}

#if defined(ZCL_TESTING)
static void (*g_before_write)(int fd);

void mesh_terminal_hub_testing_before_write(void (*hook)(int fd))
{
    g_before_write = hook;
}
#endif

void hub_io_before_write(int fd)
{
#if defined(ZCL_TESTING)
    if (g_before_write)
        g_before_write(fd);
#else
    (void)fd;
#endif
}

void hub_wfd_open(struct hub_wfd *w, int fd)
{
    struct stat st;
    int fl = fcntl(fd, F_GETFL);
    *w = (struct hub_wfd){ .fd = fd, .restore = -1 };
    if (fl < 0 || (fl & O_NONBLOCK) || fstat(fd, &st) != 0 || S_ISREG(st.st_mode))
        return;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0)
        w->restore = fl;
}

void hub_wfd_close(struct hub_wfd *w)
{
    if (w->restore >= 0)
        (void)fcntl(w->fd, F_SETFL, w->restore);
}

bool hub_wfd_write(const struct hub_wfd *w, const void *buf, size_t n, int64_t deadline_ms)
{
    const uint8_t *p = buf;
    while (n) {
        hub_io_before_write(w->fd);
        ssize_t k = write(w->fd, p, n);
        if (k > 0) {
            p += k;
            n -= (size_t)k;
            continue;
        }
        if (k < 0 && errno == EINTR)
            continue;
        if (k < 0 && errno != EAGAIN)
            return false;
        int64_t left = deadline_ms - platform_time_monotonic_ms();
        struct pollfd pfd = { .fd = w->fd, .events = POLLOUT };
        if (left <= 0 || (poll(&pfd, 1, (int)left) < 0 && errno != EINTR))
            return false;
    }
    return true;
}

enum hub_rx_status hub_rx_next(const struct hub_rx *rx, uint8_t *type,
                               const uint8_t **payload, size_t *len)
{
    if (rx->fill < MESH_TERMINAL_HUB_HEADER_BYTES)
        return HUB_RX_NEED_MORE;
    if (!mesh_terminal_hub_frame_header(rx->buf, rx->fill, type, len))
        return HUB_RX_BAD;
    if (rx->fill < MESH_TERMINAL_HUB_HEADER_BYTES + *len)
        return HUB_RX_NEED_MORE;
    *payload = rx->buf + MESH_TERMINAL_HUB_HEADER_BYTES;
    return HUB_RX_FRAME;
}

void hub_rx_consume(struct hub_rx *rx, size_t payload_len)
{
    size_t total = MESH_TERMINAL_HUB_HEADER_BYTES + payload_len;
    if (total >= rx->fill) {
        rx->fill = 0;
        return;
    }
    rx->fill -= total;
    memmove(rx->buf, rx->buf + total, rx->fill);
}

long hub_rx_read(struct hub_rx *rx, int fd)
{
    ssize_t n = read(fd, rx->buf + rx->fill, sizeof(rx->buf) - rx->fill);
    if (n > 0) {
        rx->fill += (size_t)n;
        return (long)n;
    }
    if (n == 0)
        return 0;
    return (errno == EINTR || errno == EAGAIN) ? -2 : -1;
}

enum hub_wait hub_rx_wait(struct hub_rx *rx, int fd, int timeout_ms,
                          uint8_t *type, const uint8_t **payload, size_t *len)
{
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    for (;;) {
        enum hub_rx_status s = hub_rx_next(rx, type, payload, len);
        if (s == HUB_RX_FRAME)
            return HUB_WAIT_FRAME;
        if (s == HUB_RX_BAD)
            return HUB_WAIT_BAD;
        int64_t left = deadline - platform_time_monotonic_ms();
        if (left <= 0)
            return HUB_WAIT_TIMEOUT;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ready = poll(&pfd, 1, (int)left);
        if (ready < 0 && errno != EINTR)
            return HUB_WAIT_CLOSED;
        if (ready <= 0)
            continue;
        long got = hub_rx_read(rx, fd);
        if (got == 0 || got == -1)
            return HUB_WAIT_CLOSED;
    }
}

#endif /* __linux__ */
