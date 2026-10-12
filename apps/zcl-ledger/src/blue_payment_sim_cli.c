/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_render.h"
#include "blue_payment_simulate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static uint8_t *read_wire(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    uint8_t *wire = NULL;
    if (fseek(file, 0, SEEK_END) != 0) goto done;
    long size = ftell(file);
    if (size <= 0 || size > ZCL_TX_STREAM_MAX_BYTES ||
        fseek(file, 0, SEEK_SET) != 0) goto done;
    wire = malloc((size_t)size);
    if (!wire) goto done;
    if (fread(wire, 1, (size_t)size, file) != (size_t)size) {
        free(wire);
        wire = NULL;
    } else {
        *length = (size_t)size;
    }
done:
    if (fclose(file) != 0) {
        free(wire);
        return NULL;
    }
    return wire;
}

static bool save_screens(const char *prefix,
    const blue_payment_screen *screens, uint32_t count, bool dark) {
    char path[4096];
    for (uint32_t i = 0; i < count; ++i) {
        int used = snprintf(path, sizeof path, "%s-output-%02u.png",
            prefix, i + 1);
        if (used < 0 || (size_t)used >= sizeof path ||
            !blue_payment_render_png(path, &screens[i], dark)) return false;
        puts(path);
    }
    return true;
}

static bool parse_branch(const char *text, uint32_t *branch) {
    if (!text || !branch || strlen(text) != 8) return false;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 16);
    if (errno || !end || *end || parsed > UINT32_MAX) return false;
    *branch = (uint32_t)parsed;
    return true;
}

int main(int argc, char **argv) {
    bool dark = argc == 5 && strcmp(argv[1], "--dark") == 0;
    if (argc != 4 && !dark) {
        fprintf(stderr, "Usage: %s [--dark] BRANCH_ID_HEX UNSIGNED_TX.bin OUTPUT_PREFIX\n",
            argv[0]);
        return 2;
    }
    uint32_t branch_id = 0;
    if (!parse_branch(argv[dark ? 2 : 1], &branch_id)) {
        fputs("Expected an eight-digit consensus branch ID\n", stderr);
        return 2;
    }
    const char *input = argv[dark ? 3 : 2];
    const char *prefix = argv[dark ? 4 : 3];
    size_t length = 0;
    uint8_t *wire = read_wire(input, &length);
    if (!wire) {
        fputs("Cannot read unsigned transaction\n", stderr);
        return 1;
    }
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS];
    uint32_t count = 0;
    bool valid = blue_payment_simulate(wire, length, branch_id,
        screens, &count);
    free(wire);
    if (!valid || !save_screens(prefix, screens, count, dark)) {
        fputs("Transaction replay or screen preview failed\n", stderr);
        return 1;
    }
    return 0;
}
