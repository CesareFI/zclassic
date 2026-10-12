/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* zbuf — bounded growable byte buffer
 *
 * Apache-2.0 licensed. C23, hosted (uses realloc), sticky errors.
 *
 * A heap byte buffer that grows geometrically up to a hard caller-set
 * maximum. Once any operation fails (allocation or bound), the buffer
 * enters a sticky error state: later writes are no-ops and report the
 * same error; zbuf_free() and zbuf_clear() always work.
 *
 * This removes the per-callsite dance of measuring emitters and
 * manual growth checks that bounded string building otherwise needs.
 */
#ifndef ZBUF_H
#define ZBUF_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ZBUF_OK = 0,
  ZBUF_ERR_ARG = 1,  /* NULL argument or unrepresentable maximum */
  ZBUF_ERR_FULL = 2, /* would exceed the configured maximum */
  ZBUF_ERR_OOM = 3   /* allocation failed */
} zbuf_err;

typedef struct {
  unsigned char *data; /* owned; NULL until first write */
  size_t len;
  size_t cap;
  size_t max;      /* hard bound on len */
  zbuf_err err;    /* sticky */
} zbuf;

/* Initialize an empty buffer with hard maximum `max` bytes.
 * `max` must be at most SIZE_MAX - 1, leaving room for the NUL slot.
 * Invalid arguments return ZBUF_ERR_ARG without changing the buffer. */
zbuf_err zbuf_init(zbuf *b, size_t max);

/* Free storage and reset to a fresh empty state (max kept). */
void zbuf_free(zbuf *b);

/* Drop content, keep storage and max; clears the sticky error. */
void zbuf_clear(zbuf *b);

/* Append operations. Allocation/bound errors stick; invalid arguments
 * return ZBUF_ERR_ARG without changing a healthy buffer. An existing
 * sticky error takes precedence and is returned by every later write.
 * write/str may append borrowed buffer bytes, including on growth. */
zbuf_err zbuf_put(zbuf *b, unsigned char byte);
zbuf_err zbuf_write(zbuf *b, const void *data, size_t n);
zbuf_err zbuf_str(zbuf *b, const char *cstr);

/* printf-style append. A format failure or truncation past `max`
 * sticks ZBUF_ERR_FULL. Format and string arguments may borrow buffer
 * storage; rendering completes before growth invalidates them. */
zbuf_err zbuf_printf(zbuf *b, const char *fmt, ...);
zbuf_err zbuf_vprintf(zbuf *b, const char *fmt, va_list ap);

/* NUL-terminated view of retained content, including after a sticky
 * error. Returns "" for a NULL buffer or one without storage. The
 * pointer is valid until the next mutation. */
const char *zbuf_cstr(zbuf *b);

size_t zbuf_len(const zbuf *b);
zbuf_err zbuf_status(const zbuf *b);
const char *zbuf_err_str(zbuf_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZBUF_H */
