/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/*
 * zwrap — greedy UTF-8-aware word wrapping, built on zutf8.
 *
 * Wraps text to a column width measured in codepoints (not bytes).
 * Words are runs of non-blank characters; spaces and tabs are word
 * separators and are collapsed at wrap points.  Existing newlines are
 * preserved and reset the column count.
 *
 * Long-word policy is explicit: when a single word exceeds the width,
 * it is hard-broken at the width boundary (codepoint granularity,
 * never mid-sequence) if break_long is set; otherwise it overflows
 * the width on its own line.
 *
 * Malformed UTF-8 is not an error: an undecodable byte passes through
 * unchanged and counts as one column.  Output is valid UTF-8 whenever
 * the input is.
 *
 * snprintf-style contract: the return value is the length that would
 * have been written (excluding NUL); the output is always
 * NUL-terminated when out_cap > 0. Truncation retains a prefix of whole
 * codepoints (or individual malformed bytes). NULL out with out_cap 0 measures.
 * Input extents above SIZE_MAX/2 are refused before reading input, returning
 * SIZE_MAX and an empty output when writable. This bound keeps the worst-case
 * width-one expansion representable. NULL input with nonzero length retains
 * its empty-output, zero-return behavior. Input and output must be disjoint.
 */
#ifndef ZWRAP_H
#define ZWRAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  size_t width;    /* columns; 0 selects the default of 72 */
  int break_long;  /* nonzero: hard-break over-width words */
} zwrap_opts;

zwrap_opts zwrap_default_opts(void);

size_t zwrap(const char *in, size_t in_len, char *out, size_t out_cap,
             const zwrap_opts *opts);

#ifdef __cplusplus
}
#endif

#endif /* ZWRAP_H */
