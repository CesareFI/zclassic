/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_render.h"
#include "blue_review_simulate.h"
#include "zcl_tx_review.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *prefix;
    unsigned page;
    bool dark, large;
} output;

static bool save_page(const blue_review_app *app, void *context) {
    output *out = context;
    char path[4096];
    if (out->large) {
        for (int line = 0; line < ZCL_BLUE_REVIEW_LINES; ++line) {
            if (!app->lines[line][0]) continue;
            int count = snprintf(path, sizeof path, "%s-%02u-%02d.png",
                                 out->prefix, out->page, line + 1);
            if (count < 0 || (size_t)count >= sizeof path ||
                !blue_review_render_preview_png(path, app, out->dark, line))
                return false;
            puts(path);
        }
    } else {
        int count = snprintf(path, sizeof path, "%s-%02u.png", out->prefix,
                             out->page);
        if (count < 0 || (size_t)count >= sizeof path ||
            !blue_review_render_preview_png(path, app, out->dark, -1))
            return false;
        puts(path);
    }
    ++out->page;
    return true;
}

static bool read_transaction(const char *path, uint8_t **wire, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    bool ok = fseek(file, 0, SEEK_END) == 0;
    long size = ok ? ftell(file) : -1;
    ok = ok && size >= 29 && size <= ZCL_BLUE_REVIEW_MAX_BYTES &&
         fseek(file, 0, SEEK_SET) == 0;
    uint8_t *bytes = ok ? malloc((size_t)size) : NULL;
    ok = bytes && fread(bytes, 1, (size_t)size, file) == (size_t)size &&
         fgetc(file) == EOF && !ferror(file);
    fclose(file);
    if (!ok) { free(bytes); return false; }
    *wire = bytes;
    *length = (size_t)size;
    return true;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fputs("Usage: zcl-blue-screen-sim TRANSACTION.bin OUTPUT_PREFIX [--large-text] [--dark]\n", stderr);
        return 2;
    }
    output out = {.prefix = argv[2]};
    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--large-text") == 0) out.large = true;
        else if (strcmp(argv[i], "--dark") == 0) out.dark = true;
        else { fputs("Unknown screen option.\n", stderr); return 2; }
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (!read_transaction(argv[1], &wire, &length)) {
        fputs("Cannot read a Blue-sized transaction.\n", stderr);
        return 1;
    }
    zcl_tx_review review;
    bool ok = zcl_tx_review_parse(wire, length, &review) == 0 &&
              blue_review_simulate_pages(wire, length, &review,
                                         save_page, &out);
    free(wire);
    if (!ok) {
        fputs("Transaction or screen simulation failed; inspect any partial PNGs.\n",
              stderr);
        return 1;
    }
    return 0;
}
