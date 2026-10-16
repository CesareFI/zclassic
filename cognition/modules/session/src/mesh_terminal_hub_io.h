/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: stream plumbing shared by the terminal hub server and client —
 * whole-frame sends and a receive buffer that hands out frames in place, so
 * a DATA payload is written to its destination from the buffer it was read
 * into. Internal to cognition/modules/session. */

#ifndef ZCL_SESSION_MESH_TERMINAL_HUB_IO_H
#define ZCL_SESSION_MESH_TERMINAL_HUB_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "session/mesh_terminal_hub.h"

struct hub_rx {
    uint8_t buf[2u * MESH_TERMINAL_HUB_FRAME_MAX];
    size_t fill;
};

enum hub_rx_status { HUB_RX_NEED_MORE, HUB_RX_FRAME, HUB_RX_BAD };
enum hub_wait { HUB_WAIT_FRAME, HUB_WAIT_TIMEOUT, HUB_WAIT_CLOSED, HUB_WAIT_BAD };

/* Sends frame[0..total) whole (retrying partial sends); false on a lost peer
 * or a send timeout. Never raises SIGPIPE. */
bool hub_io_send(int fd, const uint8_t *frame, size_t total);

/* A write end that cannot block, without touching the descriptor's flags:
 * O_NONBLOCK lives on the open file description, which a tty, stdout or
 * stderr shares with other holders, and it would outlive us if we were
 * SIGKILLed. So every attempt is non-blocking by itself: send(MSG_DONTWAIT)
 * on a socket; pwritev2(RWF_NOWAIT) on a pipe (the kernel refuses to wait
 * for room, however many writers share it); and where the file does not take
 * RWF_NOWAIT (a tty), poll(POLLOUT, 0) followed by a chunk of at most
 * PIPE_BUF, the amount a ready descriptor is guaranteed to take. Regular
 * files are plain writes. */
enum hub_wfd_mode { HUB_WFD_NOWAIT, HUB_WFD_SOCKET, HUB_WFD_POLLED, HUB_WFD_PLAIN };
struct hub_wfd {
    int fd;
    enum hub_wfd_mode mode;
};
void hub_wfd_open(struct hub_wfd *w, int fd);

/* One non-blocking attempt: bytes written, or -1 with errno (EAGAIN: no room
 * right now). */
ssize_t hub_wfd_try(struct hub_wfd *w, const void *buf, size_t n);

/* Called right before each write attempt (inside hub_wfd_try); it compiles
 * to nothing outside ZCL_TESTING, where a test can put another writer
 * exactly between "ready" and "write". */
#if defined(ZCL_TESTING)
void hub_io_before_write(int fd);
#else
static inline void hub_io_before_write(int fd) { (void)fd; }
#endif

/* All n bytes written, or false at the absolute monotonic deadline (or a
 * hard error). Loops write / EAGAIN / poll, so another writer consuming the
 * readiness can never leave it blocked past the deadline. */
bool hub_wfd_write(struct hub_wfd *w, const void *buf, size_t n, int64_t deadline_ms);

/* Copies payload behind a header into a small stack frame and sends it. For
 * control frames only: the hot paths seal a frame in place instead. */
bool hub_io_send_frame(int fd, uint8_t type, const uint8_t *payload, size_t len);

/* The frame at the head of the buffer, if complete. payload points into rx. */
enum hub_rx_status hub_rx_next(const struct hub_rx *rx, uint8_t *type,
                               const uint8_t **payload, size_t *len);
void hub_rx_consume(struct hub_rx *rx, size_t payload_len);

/* One read() into the free tail: >0 bytes, 0 at end of stream, -1 on a hard
 * error, -2 when the call should simply be retried (EINTR, EAGAIN). */
long hub_rx_read(struct hub_rx *rx, int fd);

/* Waits on poll (no sleeps) until a whole frame is buffered, the stream
 * ends, or timeout_ms passes. */
enum hub_wait hub_rx_wait(struct hub_rx *rx, int fd, int timeout_ms,
                          uint8_t *type, const uint8_t **payload, size_t *len);

#endif
