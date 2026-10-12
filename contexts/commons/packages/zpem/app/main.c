/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* zpem CLI: armor DER stdin as PEM, or unarmor one PEM block.
 *
 *   zpem encode LABEL   DER stdin  -> PEM stdout
 *   zpem decode         PEM stdin  -> DER stdout, label on stderr
 */
#include "zpem/zpem.h"

#include <errno.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool grow_input(uint8_t **buf, size_t *cap)
{
    size_t next;
    if (*cap == 0 || ckd_mul(&next, *cap, 2)) {
        errno = EOVERFLOW;
        return false;
    }
    uint8_t *replacement = realloc(*buf, next);
    if (!replacement) return false;
    *buf = replacement;
    *cap = next;
    return true;
}

static uint8_t *finish_input(FILE *f, uint8_t *buf, size_t len, size_t *out_len)
{
    if (ferror(f)) {
        free(buf);
        errno = EIO;
        return NULL;
    }
    *out_len = len;
    return buf;
}

static uint8_t *read_all(FILE *f, size_t *out_len)
{
    size_t cap = 4096, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            if (!grow_input(&buf, &cap)) { free(buf); return NULL; }
        }
    }
    return finish_input(f, buf, len, out_len);
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "encode") != 0 &&
                     strcmp(argv[1], "decode") != 0)) {
        fprintf(stderr, "usage: zpem <encode LABEL|decode>\n");
        return 2;
    }

    size_t len = 0;
    uint8_t *data = read_all(stdin, &len);
    if (!data) { perror("zpem: read input"); return 1; }

    if (strcmp(argv[1], "encode") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: zpem encode LABEL\n");
            free(data);
            return 2;
        }
        size_t cap = zpem_encoded_len(len, strlen(argv[2]));
        if (cap == 0) {
            fprintf(stderr, "zpem: %s\n", zpem_err_str(ZPEM_ERR_RANGE));
            free(data);
            return 1;
        }
        char *out = malloc(cap);
        if (!out) { free(data); return 1; }
        size_t out_len = 0;
        zpem_err e = zpem_encode(argv[2], strlen(argv[2]), data, len,
                                 out, cap, &out_len);
        if (e != ZPEM_OK) {
            fprintf(stderr, "zpem: %s\n", zpem_err_str(e));
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, out_len, stdout);
        free(out);
    } else {
        char *scratch = malloc(len ? len : 1);
        uint8_t *der = malloc(len ? len : 1);
        if (!scratch || !der) { free(scratch); free(der); free(data); return 1; }
        size_t der_len = 0;
        zpem_block blk;
        zpem_err e = zpem_read((const char *)data, len, scratch, len,
                               der, len, &der_len, &blk);
        if (e != ZPEM_OK) {
            fprintf(stderr, "zpem: %s\n", zpem_err_str(e));
            free(scratch);
            free(der);
            free(data);
            return 1;
        }
        fprintf(stderr, "zpem: label %.*s, %zu bytes decoded\n",
                (int)blk.label_len, blk.label, der_len);
        fwrite(der, 1, der_len, stdout);
        free(scratch);
        free(der);
    }
    free(data);
    return 0;
}
