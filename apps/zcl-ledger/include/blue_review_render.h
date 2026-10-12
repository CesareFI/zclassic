/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REVIEW_RENDER_H
#define ZCL_BLUE_REVIEW_RENDER_H

#include "blue_review_app.h"

/* Returns false when text cannot fit or the PNG cannot be written. */
bool blue_review_render_preview_png(const char *path,
    const blue_review_app *app, bool dark, int large_line);
bool blue_review_render_lines_png(const char *path,
    const char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE],
    const char *title, const char *next_label, bool dark, int large_line);

#endif
