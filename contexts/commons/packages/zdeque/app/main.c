/* zdeque CLI: exercise the deque over lines from stdin.
 *
 *   zdeque reverse    print stdin lines in reverse order (LIFO)
 *   zdeque rotate N   rotate the line queue left by N positions
 *
 * Demonstrates a real consumer of the two-ended container.
 */
#include "zdeque/zdeque.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINES 4096
#define MAX_LINE 512

static int parse_rotation(int argc, char **argv, long *rotation)
{
    if (argc < 3) return 0;
    char *end;
    errno = 0;
    const long value = strtol(argv[2], &end, 10);
    if (errno == ERANGE || end == argv[2] || *end != '\0') return 0;
    *rotation = value;
    return 1;
}

static int append_line(zdeque *dq, char *line, size_t length)
{
    line[length] = '\0';
    if (zdeque_push_back(dq, line) != ZDEQUE_OK) {
        fprintf(stderr, "zdeque: cannot append input line\n");
        return 1;
    }
    return 0;
}

static int read_lines(zdeque *dq, char lines[MAX_LINES][MAX_LINE])
{
    size_t n = 0, length = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (n >= MAX_LINES) {
            fprintf(stderr, "zdeque: input exceeds %d lines\n", MAX_LINES);
            return 1;
        }
        if (c == '\n') {
            if (append_line(dq, lines[n], length)) return 1;
            n++;
            length = 0;
        } else {
            if (c == '\0' || length >= MAX_LINE - 1) {
                fprintf(stderr, "zdeque: invalid or oversized input line\n");
                return 1;
            }
            lines[n][length++] = (char)c;
        }
    }
    if (ferror(stdin)) {
        fprintf(stderr, "zdeque: error reading stdin\n");
        return 1;
    }
    return length ? append_line(dq, lines[n], length) : 0;
}

static int finish_output(void)
{
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fprintf(stderr, "zdeque: error writing stdout\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "reverse") != 0 &&
                     strcmp(argv[1], "rotate") != 0)) {
        fprintf(stderr, "usage: zdeque <reverse|rotate N>\n");
        return 2;
    }

    static char lines[MAX_LINES][MAX_LINE];
    static void *slots[MAX_LINES];
    zdeque dq;
    if (zdeque_init(&dq, slots, MAX_LINES) != ZDEQUE_OK) return 1;

    if (read_lines(&dq, lines)) return 1;

    if (strcmp(argv[1], "reverse") == 0) {
        void *p;
        while (zdeque_pop_back(&dq, &p) == ZDEQUE_OK)
            printf("%s\n", (char *)p);
        return finish_output();
    }

    /* rotate N */
    long rot;
    if (!parse_rotation(argc, argv, &rot)) {
        fprintf(stderr, "usage: zdeque rotate N\n");
        return 2;
    }
    size_t sz = zdeque_size(&dq);
    if (sz == 0) return finish_output();
    long r = ((rot % (long)sz) + (long)sz) % (long)sz;
    for (long i = 0; i < r; i++) {
        void *p = NULL;
        zdeque_pop_front(&dq, &p);
        zdeque_push_back(&dq, p);
    }
    void *p;
    while (zdeque_pop_front(&dq, &p) == ZDEQUE_OK)
        printf("%s\n", (char *)p);
    return finish_output();
}
