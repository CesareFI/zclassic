/* zescape CLI: escape or unescape stdin.
 *
 *   zescape escape     raw stdin -> escaped stdout
 *   zescape unescape   escaped stdin -> raw stdout
 */
#include "zescape/zescape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *read_all(FILE *f, size_t *out_len)
{
    size_t cap = 4096, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
    }
    if (ferror(f)) { free(buf); return NULL; }
    *out_len = len;
    return buf;
}

static int write_output(const void *data, size_t n)
{
    if (fwrite(data, 1, n, stdout) != n || fputc('\n', stdout) == EOF ||
        fflush(stdout) == EOF) {
        fprintf(stderr, "zescape: output write failed\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "escape") != 0 && strcmp(argv[1], "unescape") != 0)) {
        fprintf(stderr, "usage: zescape <escape|unescape>\n");
        return 2;
    }

    size_t len = 0;
    uint8_t *data = read_all(stdin, &len);
    if (!data) { fprintf(stderr, "zescape: cannot read input\n"); return 1; }

    int status = 0;
    if (strcmp(argv[1], "escape") == 0) {
        size_t cap = zescape_escaped_max(len);
        if (cap == SIZE_MAX) {
            fprintf(stderr, "zescape: escaped size exceeds addressable memory\n");
            free(data);
            return 1;
        }
        cap++;
        char *out = malloc(cap);
        if (!out) { free(data); return 1; }
        size_t n = 0;
        zescape_err e = zescape_escape(data, len, out, cap, &n);
        if (e != ZESCAPE_OK) {
            fprintf(stderr, "zescape: %s\n", zescape_err_str(e));
            free(out);
            free(data);
            return 1;
        }
        if (!write_output(out, n)) status = 1;
        free(out);
    } else {
        uint8_t *out = malloc(len + 1);
        if (!out) { free(data); return 1; }
        /* Tolerate one trailing newline from shells. */
        if (len > 0 && data[len - 1] == '\n') len--;
        size_t n = 0, pos = 0;
        zescape_err e = zescape_unescape((const char *)data, len, out, len + 1, &n, &pos);
        if (e != ZESCAPE_OK) {
            fprintf(stderr, "zescape: %s at position %zu\n",
                    zescape_err_str(e), pos);
            free(out);
            free(data);
            return 1;
        }
        if (!write_output(out, n)) status = 1;
        free(out);
    }
    free(data);
    return status;
}
