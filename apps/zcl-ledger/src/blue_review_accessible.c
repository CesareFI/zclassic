/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_accessible.h"
#include "blue_review_screen.h"

#include <stddef.h>

/* Widths from Ledger's Apache-2.0 Open Sans Light 16/22 BAGL table. */
static const unsigned char glyph_width[96] = {
    5,5,7,14,12,17,15,4,6,6,12,12,5,7,5,7,
    12,12,12,12,12,12,12,12,12,12,5,5,12,12,12,9,
    19,13,13,13,15,12,11,15,15,5,6,12,11,18,15,16,
    12,16,12,11,11,15,12,19,11,11,12,7,7,7,12,9,
    12,11,12,10,12,12,8,11,12,5,5,10,5,19,12,12,
    12,12,8,10,7,12,10,15,10,10,10,7,11,7,12,13
};

static unsigned line_width(const char *text, size_t from, size_t to) {
    unsigned width = 0;
    for (size_t i = from; i < to; ++i)
        width += glyph_width[(unsigned char)text[i] - 0x20];
    return width;
}

bool blue_review_accessible_wrap(const char *source, char destination[40]) {
    if (!source || !destination) return false;
    size_t used = 0, start = 0;
    for (const unsigned char *p = (const unsigned char *)source; *p; ++p) {
        if (*p < 0x20 || *p > 0x7e || used + 2 >= 40 ||
            used >= ZCL_BLUE_REVIEW_LINE_SIZE + 2) return false;
        destination[used++] = (char)*p;
        if (line_width(destination, start, used) <= 280) continue;
        size_t split = used;
        while (split > start && destination[split - 1] != ' ') --split;
        if (split > start) {
            destination[split - 1] = '\n';
            start = split;
        } else {
            destination[used - 1] = '\n';
            destination[used++] = (char)*p;
            start = used - 1;
        }
    }
    destination[used] = 0;
    return true;
}
