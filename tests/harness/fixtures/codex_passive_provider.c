/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Intercepted passive transport fixtures without live controller access. */
#if !defined(CGO_PROVIDER_FIXTURE_INTERCEPTED)
#error "Controller provider fixture requires intercepted syscalls"
#endif
/* Portable local Unix/WebSocket JSON-RPC bridge. Trial tool, no worker
 * scheduler. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <setjmp.h>
#include "command/native_devagent_codex_observation_decode.h"
#include "json/json.h"
#include "base/safe_alloc.h"
#include <time.h>
/* Derived existing reference4e7 framing; caller-local failure/buffer state. */
struct cgo_m1_transport {
  jmp_buf escape;
  int fd, random_fd;
  char *out, *payload, *masked;
  size_t out_length;
  char *why;
  size_t why_cap;
};
#define CAP CGO_RESPONSE_CAP
static _Noreturn void die(struct cgo_m1_transport *t, const char *s) {
  fprintf(stderr, "codex-link: %s: %s\n", s, strerror(errno));
  if (t->why && t->why_cap) (void)snprintf(t->why, t->why_cap, "%s: %s", s, strerror(errno));
  longjmp(t->escape, 1);
}
static void all(struct cgo_m1_transport *t, int fd, const void *v, size_t n) {
  const char *p = v;
  while (n) {
    ssize_t k = write(fd, p, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      die(t, "write");
    p += k;
    n -= (size_t)k;
  }
}
static void exact(struct cgo_m1_transport *t, int fd, void *v, size_t n) {
  char *p = v;
  while (n) {
    ssize_t k = read(fd, p, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      die(t, "read/timeout; passive capture unavailable");
    p += k;
    n -= (size_t)k;
  }
}
static void release_payload(struct cgo_m1_transport *t, char *p) {
  if (t->masked == p) t->masked = NULL;
  if (t->payload == p) t->payload = NULL;
  free(p);
}
static void frame(struct cgo_m1_transport *t, int fd, unsigned op, const char *s, size_t n) {
  unsigned char h[14] = {0x80u | (unsigned char)op, 0};
  size_t z = 2;
  if (n < 126)
    h[1] = 0x80u | (unsigned char)n;
  else if (n <= 65535) {
    h[1] = 0xfe;
    h[2] = (unsigned char)(n >> 8);
    h[3] = (unsigned char)n;
    z = 4;
  } else {
    h[1] = 0xff;
    for (int j = 0; j < 8; j++)
      h[2 + j] = (unsigned char)((uint64_t)n >> (56 - 8 * j));
    z = 10;
  }
  int r = t->random_fd = open("/dev/urandom", O_RDONLY);
  if (r < 0)
    die(t, "random mask");
  exact(t, r, h + z, 4);
  close(r);
  t->random_fd = -1;
  char *p = t->masked = zcl_malloc(n ? n : 1, "codex.passive.frame");
  if (!p)
    die(t, "allocation");
  for (size_t j = 0; j < n; j++)
    p[j] = s[j] ^ (char)h[z + j % 4];
  all(t, fd, h, z + 4);
  all(t, fd, p, n);
  release_payload(t, p);
}
static uint64_t receive_size(struct cgo_m1_transport *t, int fd, unsigned encoded) {
  if (encoded == 126) {
    unsigned char b[2];
    exact(t, fd, b, 2);
    return ((uint64_t)b[0] << 8) | b[1];
  }
  if (encoded == 127) {
    unsigned char b[8];
    exact(t, fd, b, 8);
    uint64_t n = 0;
    for (int j = 0; j < 8; j++) n = (n << 8) | b[j];
    return n;
  }
  return encoded;
}
static bool receive_control(struct cgo_m1_transport *t, int fd, unsigned op,
                            char *p, size_t n) {
  if (op == 8) {
    errno = ECONNRESET;
    die(t, "server close");
  }
  if (op == 9) frame(t, fd, 10, p, n);
  if (op == 9 || op == 10) {
    release_payload(t, p);
    return true;
  }
  return false;
}
static char *receive(struct cgo_m1_transport *t, int fd) {
  char *out = t->out = zcl_malloc(CAP + 1, "codex.passive.receive");
  if (!out)
    die(t, "allocation");
  size_t total = 0;
  for (;;) {
    unsigned char h[2];
    exact(t, fd, h, 2);
    unsigned op = h[0] & 15;
    uint64_t n = receive_size(t, fd, h[1] & 127);
    if (n > CAP || total + n > CAP || (h[1] & 128)) {
      errno = EINVAL;
      die(t, "unsupported/oversize server frame");
    }
    char *p = t->payload = zcl_malloc((size_t)n + 1, "codex.passive.payload");
    if (!p)
      die(t, "allocation");
    exact(t, fd, p, (size_t)n);
    p[n] = 0;
    if (receive_control(t, fd, op, p, (size_t)n)) continue;
    if (op != 1 && op != 0) {
      errno = EINVAL;
      die(t, "non-text frame");
    }
    memcpy(out + total, p, (size_t)n);
    total += (size_t)n;
    release_payload(t, p);
    if (h[0] & 128) {
      out[total] = 0;
      t->out_length = total;
      return out;
    }
  }
}
static int connectws(struct cgo_m1_transport *t, const char *path) {
  int fd = t->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    die(t, "socket");
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  if (strlen(path) >= sizeof(a.sun_path)) {
    errno = ENAMETOOLONG;
    die(t, "socket path");
  }
  strcpy(a.sun_path, path);
  if (connect(fd, (struct sockaddr *)&a, sizeof(a)))
    die(t, "connect");
  struct timeval tv = {.tv_sec = 5};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  const char *h =
      "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: "
      "Upgrade\r\nSec-WebSocket-Key: "
      "dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
  all(t, fd, h, strlen(h));
  char b[8192];
  size_t n = 0;
  while (n < sizeof(b) - 1) {
    exact(t, fd, b + n, 1);
    b[++n] = 0;
    if (n >= 4 && !memcmp(b + n - 4, "\r\n\r\n", 4))
      break;
  }
  if (!strstr(b, " 101 ") || !strstr(b, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) {
    errno = EPROTO;
    die(t, "websocket handshake");
  }
  return fd;
}

static char *cgo_m1_reply(struct cgo_m1_transport *t, const char *id, size_t id_length,
    size_t *length)
{
    (void)id; (void)id_length;
    for (unsigned i = 0; i < 256; i++) {
        char *reply = receive(t, t->fd);
        size_t reply_length = t->out_length;
        struct json_value root = {0};
        bool parsed = json_read(&root, reply, reply_length);
        const struct json_value *v = json_get(&root, "id");
        const struct json_value *method = json_get(&root, "method");
        bool notification = parsed && root.type == JSON_OBJ && !v &&
            method && method->type == JSON_STR && !json_get(&root, "result") &&
            !json_get(&root, "error");
        json_free(&root);
        /* Any response, wrong ID or malformed bytes go to the strict producer;
         * never silently skip a contradictory acknowledgement. */
        if (!notification) {
            /* Publish a span only with its returned response, never with a
             * discarded notification before a later longjmp/failure. */
            *length = reply_length;
            return reply;
        }
        free(t->out); t->out = NULL;
    }
    errno = EOVERFLOW; die(t, "passive notification bound");
}

/* Shares producer validation, rather than a second JSON/envelope codec. */
extern enum cga_result cgo_caller_initialize_reply(const char *, size_t, char *, size_t);

static enum cga_result cgo_m1_begin(void *context, const char *initialize,
    size_t initialize_length, const char *initialized, size_t initialized_length,
    char **reply, size_t *reply_length, char *why, size_t why_cap)
{
    struct cgo_m1_transport *t = context;
    t->why = why; t->why_cap = why_cap;
    if (setjmp(t->escape)) return CGA_UNCERTAIN;
    t->fd = connectws(t, "/fixture/no-socket");
    frame(t, t->fd, 1, initialize, initialize_length);
    *reply = cgo_m1_reply(t, "initialize", 10, reply_length);
    enum cga_result result = cgo_caller_initialize_reply(*reply, *reply_length, why, why_cap);
    if (result != CGA_OK) return result;
    frame(t, t->fd, 1, initialized, initialized_length);
    return CGA_OK;
}

static enum cga_result cgo_m1_exchange(void *context, enum cgo_passive_method method,
    const char *request, size_t length, char **reply, size_t *reply_length,
    char *why, size_t why_cap)
{
    struct cgo_m1_transport *t = context;
    t->why = why; t->why_cap = why_cap;
    if (setjmp(t->escape)) return CGA_UNCERTAIN;
    if (method < CGO_PASSIVE_READ || method > CGO_PASSIVE_TURNS) {
        errno = EINVAL; die(t, "passive method closed allowlist");
    }
    struct json_value root = {0};
    bool valid = json_read(&root, request, length);
    const struct json_value *id = json_get(&root, "id");
    char selected[CGA_ID_CAP];
    if (!valid || !id || id->type != JSON_STR || strlen(id->val.s) >= sizeof(selected)) {
        json_free(&root); errno = EPROTO; die(t, "encoded passive request invalid");
    }
    strcpy(selected, id->val.s);
    json_free(&root);
    frame(t, t->fd, 1, request, length);
    *reply = cgo_m1_reply(t, selected, strlen(selected), reply_length);
    return CGA_OK;
}

static void cgo_m1_release(void *context, char *reply, size_t length)
{
    struct cgo_m1_transport *t = context;
    (void)length;
    if (t->out == reply) t->out = NULL;
    free(reply);
}

static void cgo_m1_end(void *context)
{
    struct cgo_m1_transport *t = context;
    if (t->fd >= 0) close(t->fd);
    if (t->random_fd >= 0) close(t->random_fd);
    t->fd = -1;
    free(t->out); free(t->payload); free(t->masked);
    t->out = NULL; t->payload = NULL; t->masked = NULL;
}

static bool cgo_m1_clock(void *context, int64_t *wall, int64_t *mono)
{
    (void)context;
    struct timespec realtime, monotonic;
    if (clock_gettime(CLOCK_REALTIME, &realtime) || clock_gettime(CLOCK_MONOTONIC, &monotonic)) {
        fprintf(stderr, "passive controller: native clock unavailable: %s\n", strerror(errno));
        return false;
    }
    *wall = (int64_t)realtime.tv_sec * 1000 + realtime.tv_nsec / 1000000;
    *mono = (int64_t)monotonic.tv_sec * 1000 + monotonic.tv_nsec / 1000000;
    return true;
}

enum cga_result cgo_passive_local_m1_v1(const struct cgo_passive_caller_request *request,
    struct cgo_passive_owned **out, char *why, size_t why_cap)
{
    struct cgo_m1_transport transport = { .fd = -1, .random_fd = -1 };
    const struct cgo_passive_caller_io io = { &transport, cgo_m1_begin,
        cgo_m1_exchange, cgo_m1_release, cgo_m1_end, cgo_m1_clock };
    return cgo_passive_caller_v1(request, &io, out, why, why_cap);
}
/* Agreed additive fixed local rhett2 binding; legacy provider entry unchanged. */
enum cga_result cgo_passive_local_rhett2_v1(
    const struct cgo_passive_rhett2_request_v1 *request,
    struct cgo_passive_owned **out, char *why, size_t why_cap)
{
    struct cgo_m1_transport transport = { .fd = -1, .random_fd = -1 };
    const struct cgo_passive_caller_io io = { &transport, cgo_m1_begin,
        cgo_m1_exchange, cgo_m1_release, cgo_m1_end, cgo_m1_clock };
    return cgo_passive_rhett2_caller_v1(request, &io, out, why, why_cap);
}
