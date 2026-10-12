/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: utf8check - validate stdin as well-formed UTF-8.
 *
 * Usage: zutf8 < data
 *
 * Exit 0 when the whole input is well-formed UTF-8, 1 when it is not
 * (byte offset and reason on stderr), 2 on I/O error or input over
 * the 64 MiB bound. With --count, print the code-point count instead
 * of validating silently.
 */
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <string.h>

/* Private bindings let C tests inject streams without redefining stdio names. */
#ifndef ZUTF8_CLI_STDIO
#define ZUTF8_CLI_STDIN stdin
#define ZUTF8_CLI_STDOUT stdout
#define ZUTF8_CLI_STDERR stderr
#define ZUTF8_CLI_PRINTF printf
#define ZUTF8_CLI_FERROR ferror
#define ZUTF8_CLI_FFLUSH fflush
#define ZUTF8_CLI_FCLOSE fclose
#endif

#define MAX_INPUT (64u * 1024u * 1024u)

static char input[MAX_INPUT];

static int validate_input(int argc, char **argv) {
  int count_mode = 0;
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "--count"))) {
    fprintf(ZUTF8_CLI_STDERR, "usage: zutf8 [--count] < data\n");
    return 2;
  }
  count_mode = argc == 2;

  size_t len = fread(input, 1, sizeof(input), ZUTF8_CLI_STDIN);
  /* Filling the buffer does not set EOF, even at the exact input limit. */
  int extra = len == sizeof(input) ? fgetc(ZUTF8_CLI_STDIN) : EOF;
  if (ZUTF8_CLI_FERROR(ZUTF8_CLI_STDIN) || extra != EOF) {
    fprintf(ZUTF8_CLI_STDERR, "zutf8: read error or input over 64 MiB bound\n");
    return 2;
  }

  size_t pos = 0, count = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    zutf8_status st = zutf8_decode_n(input + pos, len - pos, &cp, &used);
    if (st != ZUTF8_OK) {
      fprintf(ZUTF8_CLI_STDERR, "zutf8: %s at byte %zu\n",
              st == ZUTF8_TRUNCATED ? "truncated sequence"
                                    : "invalid byte sequence",
              pos);
      return 1;
    }
    pos += used;
    count++;
  }
  if (count_mode)
    ZUTF8_CLI_PRINTF("%zu\n", count);
  return 0;
}

static int finish_output(FILE *stream, int status) {
  if (ZUTF8_CLI_FERROR(stream))
    status = 2;
  if (ZUTF8_CLI_FFLUSH(stream) == EOF)
    status = 2;
  if (ZUTF8_CLI_FCLOSE(stream) == EOF)
    status = 2;
  return status;
}

int main(int argc, char **argv) {
  int status = validate_input(argc, argv);
  int result = finish_output(ZUTF8_CLI_STDOUT, status);
  if (result != status)
    fputs("zutf8: output error\n", ZUTF8_CLI_STDERR);
  return finish_output(ZUTF8_CLI_STDERR, result);
}
