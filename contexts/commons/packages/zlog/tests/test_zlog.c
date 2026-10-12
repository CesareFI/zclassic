#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "zlog/zlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

struct capture {
    char lines[16][300];
    size_t count;
};

static void capture_emit(void *ctx, const char *line)
{
    struct capture *c = ctx;
    if (c->count >= 16) return;
    size_t n = strlen(line);
    if (n >= sizeof c->lines[0]) n = sizeof c->lines[0] - 1;
    memcpy(c->lines[c->count], line, n);
    c->lines[c->count][n] = '\0';
    c->count++;
}

static void test_levels_and_threshold(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_INFO, true, "net" };

    CHECK(!zlog_trace(&s, "too low"));
    CHECK(!zlog_debug(&s, "too low"));
    CHECK(zlog_info(&s, "hello"));
    CHECK(zlog_warn(&s, "careful"));
    CHECK(zlog_error(&s, "bad"));
    CHECK(cap.count == 3);
    CHECK(strcmp(cap.lines[0], "INFO net hello\n") == 0);
    CHECK(strcmp(cap.lines[1], "WARN net careful\n") == 0);
    CHECK(strcmp(cap.lines[2], "ERROR net bad\n") == 0);

    /* OFF silences everything. */
    s.threshold = ZLOG_OFF;
    CHECK(!zlog_error(&s, "silence"));
    CHECK(cap.count == 3);

    /* TRACE threshold lets all through. */
    s.threshold = ZLOG_TRACE;
    CHECK(zlog_trace(&s, "fine"));
    CHECK(strcmp(cap.lines[3], "TRACE net fine\n") == 0);

    /* Invalid level values rejected. */
    CHECK(!zlog_write(&s, (zlog_level)-1, "x"));
    CHECK(!zlog_write(&s, (zlog_level)5, "x"));

    /* NULL sink / NULL message. */
    CHECK(!zlog_write(NULL, ZLOG_INFO, "x"));
    CHECK(zlog_write(&s, ZLOG_INFO, NULL)); /* emits header-only line */

    /* NULL emit callback: counted, nothing written. */
    zlog_sink silent = { NULL, NULL, ZLOG_TRACE, true, "t" };
    CHECK(zlog_write(&silent, ZLOG_INFO, "gone"));
}

static void test_no_tag(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_TRACE, false, "ignored" };
    CHECK(zlog_info(&s, "plain"));
    CHECK(strcmp(cap.lines[0], "INFO plain\n") == 0);

    /* include_tag with NULL tag behaves like no tag. */
    s.include_tag = true;
    s.tag = NULL;
    CHECK(zlog_info(&s, "plain2"));
    CHECK(strcmp(cap.lines[1], "INFO plain2\n") == 0);

    s.tag = "";
    CHECK(zlog_info(&s, "plain3"));
    CHECK(strcmp(cap.lines[2], "INFO plain3\n") == 0);
}

static void test_truncation(void)
{
    struct capture cap = {0};
    zlog_sink s = { capture_emit, &cap, ZLOG_TRACE, true, "sys" };

    char huge[1000];
    memset(huge, 'x', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';

    CHECK(zlog_info(&s, huge));
    CHECK(cap.count == 1);
    size_t n = strlen(cap.lines[0]);
    CHECK(n < 256);            /* line cap respected */
    CHECK(cap.lines[0][n - 1] == '\n');
    CHECK(strncmp(cap.lines[0], "INFO sys ", 9) == 0);

    /* Very long tag also bounded. */
    char bigtag[600];
    memset(bigtag, 't', sizeof bigtag - 1);
    bigtag[sizeof bigtag - 1] = '\0';
    s.tag = bigtag;
    CHECK(zlog_warn(&s, "msg"));
    CHECK(strlen(cap.lines[1]) < 256);
}

static void test_names_and_parse(void)
{
    CHECK(strcmp(zlog_level_name(ZLOG_TRACE), "TRACE") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_DEBUG), "DEBUG") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_INFO), "INFO") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_WARN), "WARN") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_ERROR), "ERROR") == 0);
    CHECK(strcmp(zlog_level_name(ZLOG_OFF), "OFF") == 0);
    CHECK(strcmp(zlog_level_name((zlog_level)99), "OFF") == 0);

    CHECK(zlog_level_parse("trace") == ZLOG_TRACE);
    CHECK(zlog_level_parse("DEBUG") == ZLOG_DEBUG);
    CHECK(zlog_level_parse("Info") == ZLOG_INFO);
    CHECK(zlog_level_parse("warn") == ZLOG_WARN);
    CHECK(zlog_level_parse("ERROR") == ZLOG_ERROR);
    CHECK(zlog_level_parse("off") == ZLOG_OFF);
    CHECK(zlog_level_parse("nonsense") == ZLOG_OFF);
    CHECK(zlog_level_parse(NULL) == ZLOG_OFF);
    /* Prefixes must not match. */
    CHECK(zlog_level_parse("information") == ZLOG_OFF);
    CHECK(zlog_level_parse("warnx") == ZLOG_OFF);
}

static int cli_failures;
#define CLI_CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL CLI %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        cli_failures++; \
    } \
} while (0)

static FILE *cli_err;
static FILE *real_stderr(void) { return stderr; }
#undef stderr
#define stderr cli_err
#define main cli_main
#include "../app/main.c"
#undef main
#undef stderr
#define stderr (real_stderr())

#if !defined(_WIN32)
static int cli_expected_status(int status, const char *expected, int mode)
{
    if (status) return status;
    return mode && expected[0] ? 1 : 0;
}

static void exercise_cli(char **argv, int argc, const char *expected,
                         int mode, int status)
{
    char output[128] = {0}, buffer[BUFSIZ];
    FILE *err = mode ? fopen("/dev/null", "w") :
                      fmemopen(output, sizeof(output), "w");
    CLI_CHECK(err != NULL);
    if (!err) return;
    CLI_CHECK(setvbuf(err, buffer, mode == 2 ? _IONBF : _IOFBF,
                     sizeof(buffer)) == 0);
    if (mode) CLI_CHECK(close(fileno(err)) == 0);
    cli_err = err;
    int result = cli_main(argc, argv);
    cli_err = stderr;
    CLI_CHECK(result == cli_expected_status(status, expected, mode));
    int flushed = fflush(err);
    if (mode && expected[0]) CLI_CHECK(flushed == EOF || ferror(err));
    if (!mode) {
        CLI_CHECK(flushed == 0);
        CLI_CHECK(strcmp(output, expected) == 0);
    }
    int closed = fclose(err);
    CLI_CHECK(mode ? closed == EOF : closed == 0);
}
#endif

static void test_cli_output_refusal(void)
{
#if !defined(_WIN32)
    char *plain[] = {"zlog", "info", "hello", NULL};
    char *tag[] = {"zlog", "-t", "net", "warn", "retry", NULL};
    char *level[] = {"zlog", "-l", "trace", "error", "stop", NULL};
    char *filtered[] = {"zlog", "debug", "hidden", NULL};
    for (int mode = 0; mode < 3; mode++) {
        fprintf(stderr, "CLI row plain mode=%d\n", mode);
        exercise_cli(plain, 3, "INFO hello\n", mode, 0);
        fprintf(stderr, "CLI row tag mode=%d\n", mode);
        exercise_cli(tag, 5, "WARN net retry\n", mode, 0);
        fprintf(stderr, "CLI row level mode=%d\n", mode);
        exercise_cli(level, 5, "ERROR stop\n", mode, 0);
        fprintf(stderr, "CLI row filtered mode=%d\n", mode);
        exercise_cli(filtered, 3, "", mode, 0);
    }
    char *usage[] = {"zlog", NULL};
    char *unknown[] = {"zlog", "invalid", "hello", NULL};
    for (int mode = 0; mode < 3; mode++) {
        fprintf(stderr, "CLI control usage mode=%d\n", mode);
        exercise_cli(usage, 1,
            "usage: zlog [-t tag] [-l level] <level> <message>\n", mode, 2);
        fprintf(stderr, "CLI control unknown mode=%d\n", mode);
        exercise_cli(unknown, 3, "zlog: unknown level invalid\n", mode, 2);
    }
#else
    (void)cli_main;
    fprintf(stderr, "zlog: required CLI refusal coverage unavailable on _WIN32\n");
    cli_failures++;
#endif
}

int main(void)
{
    cli_err = stderr;
    test_levels_and_threshold();
    test_no_tag();
    test_truncation();
    test_names_and_parse();
    test_cli_output_refusal();
    if (cli_failures) return 1;
    puts("test_zlog: all groups passed (levels notag trunc names)");
    return 0;
}
