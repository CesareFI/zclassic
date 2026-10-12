/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_render.h"
#include "blue_bagl_canvas.h"
#include "blue_review_accessible.h"
#include "blue_review_layout.h"

#include <stdint.h>
#include <stdio.h>

static bool draw_large_line(blue_bagl_canvas *image, const char *label,
                            uint32_t foreground, uint32_t background) {
    char wrapped[40];
    if (!blue_review_accessible_wrap(label, wrapped)) return false;
    int y = ZCL_BLUE_LARGE_DETAIL_Y;
    for (char *row = wrapped; *row;) {
        char *end = row;
        while (*end && *end != '\n') ++end;
        bool more = *end == '\n';
        *end = 0;
        if (y > 330 || !blue_bagl_text(image, row, 20, y, 280, false,
                                        foreground, background,
                                        BLUE_BAGL_TEXT_22)) return false;
        if (!more) break;
        row = end + 1;
        y += blue_bagl_font_height(BLUE_BAGL_TEXT_22);
    }
    return true;
}

static bool render_header(blue_bagl_canvas *image, const char *title,
                          bool dark, uint32_t button) {
    blue_bagl_rectangle(image, 0, 0, ZCL_BLUE_SCREEN_WIDTH,
                        ZCL_BLUE_HEADER_HEIGHT, ZCL_BLUE_COLOR_HEADER);
    bool fit = blue_bagl_text(image, title, ZCL_BLUE_HEADER_TEXT_X,
        (ZCL_BLUE_HEADER_HEIGHT / 2 - 12 / 2 - 1),
        ZCL_BLUE_HEADER_TEXT_WIDTH, false, ZCL_BLUE_COLOR_WHITE,
        ZCL_BLUE_COLOR_HEADER, BLUE_BAGL_TEXT_14);
    blue_bagl_round_rectangle(image, ZCL_BLUE_THEME_X, ZCL_BLUE_THEME_Y,
        ZCL_BLUE_THEME_WIDTH, ZCL_BLUE_THEME_HEIGHT, button);
    if (fit) fit = blue_bagl_text(image, dark ? "LIGHT" : "DARK",
        ZCL_BLUE_THEME_X,
        ZCL_BLUE_THEME_Y + ZCL_BLUE_THEME_HEIGHT / 2 - 12 / 2 - 1,
        ZCL_BLUE_THEME_WIDTH, true, ZCL_BLUE_COLOR_HEADER, button,
        BLUE_BAGL_TEXT_14);
    return fit;
}

static bool render_body(blue_bagl_canvas *image,
    const char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE],
    int large_line, uint32_t foreground, uint32_t background) {
    if (large_line >= 0 && large_line < ZCL_BLUE_REVIEW_LINES) {
        char title[24];
        return snprintf(title, sizeof title, "DETAIL %d/6", large_line + 1) > 0 &&
            blue_bagl_text(image, title, 20, ZCL_BLUE_LARGE_TITLE_Y, 280,
                           true, foreground, background, BLUE_BAGL_TEXT_22) &&
            draw_large_line(image, lines[large_line],
                            foreground, background);
    }
    if (large_line != -1) return false;
    for (int i = 0; i < ZCL_BLUE_REVIEW_LINES; ++i)
        if (!blue_bagl_text(image, lines[i], ZCL_BLUE_LINE_X,
                            ZCL_BLUE_LINE_FIRST_Y + i * ZCL_BLUE_LINE_STEP_Y,
                            ZCL_BLUE_LINE_WIDTH, true, foreground, background,
                            BLUE_BAGL_TEXT_14)) return false;
    return true;
}

static bool render_controls(blue_bagl_canvas *image, int large_line,
    const char *next_label, uint32_t background, uint32_t button) {
    blue_bagl_round_rectangle(image, ZCL_BLUE_NEXT_X, ZCL_BLUE_BUTTON_Y,
        ZCL_BLUE_BUTTON_WIDTH, ZCL_BLUE_BUTTON_HEIGHT, button);
    blue_bagl_round_rectangle(image, ZCL_BLUE_EXIT_X, ZCL_BLUE_BUTTON_Y,
        ZCL_BLUE_BUTTON_WIDTH, ZCL_BLUE_BUTTON_HEIGHT, button);
    blue_bagl_round_rectangle(image, 20, ZCL_BLUE_TEXT_TOGGLE_Y, 280,
        ZCL_BLUE_TEXT_TOGGLE_HEIGHT, button);
    bool fit = blue_bagl_text(image,
        large_line < 0 ? "LARGER TEXT" : "STANDARD TEXT", 20,
        ZCL_BLUE_TEXT_TOGGLE_Y + ZCL_BLUE_TEXT_TOGGLE_HEIGHT / 2 - 12 / 2 - 1,
        280, true, background, button, BLUE_BAGL_TEXT_14);
    int button_text_y = ZCL_BLUE_BUTTON_Y +
                        ZCL_BLUE_BUTTON_HEIGHT / 2 - 12 / 2 - 1;
    if (fit) fit = blue_bagl_text(image,
        large_line < 0 ? next_label : "NEXT DETAIL",
        ZCL_BLUE_NEXT_X, button_text_y, ZCL_BLUE_BUTTON_WIDTH, true,
        background, button, BLUE_BAGL_TEXT_14);
    if (fit) fit = blue_bagl_text(image, "EXIT", ZCL_BLUE_EXIT_X,
        button_text_y, ZCL_BLUE_BUTTON_WIDTH, true, background, button,
        BLUE_BAGL_TEXT_14);
    return fit;
}

bool blue_review_render_preview_png(const char *path,
    const blue_review_app *app, bool dark, int large_line) {
    return app && blue_review_render_lines_png(path, app->lines,
        "ZCL Review", "NEXT PAGE", dark, large_line);
}

bool blue_review_render_lines_png(const char *path,
    const char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE],
    const char *title, const char *next_label, bool dark, int large_line) {
    if (!path || !lines || !title || !next_label) return false;
    uint32_t background = dark ? ZCL_BLUE_COLOR_DARK_BODY : ZCL_BLUE_COLOR_BODY;
    uint32_t foreground = dark ? ZCL_BLUE_COLOR_DARK_TEXT : ZCL_BLUE_COLOR_TEXT;
    uint32_t button = dark ? ZCL_BLUE_COLOR_DARK_BUTTON : ZCL_BLUE_COLOR_BUTTON;
    blue_bagl_canvas *image = blue_bagl_canvas_create(background);
    if (!image) return false;
    bool fit = render_header(image, title, dark, button) &&
               render_body(image, lines, large_line, foreground, background) &&
               render_controls(image, large_line, next_label,
                   background, button);
    if (fit) fit = blue_bagl_write_png(image, path);
    blue_bagl_canvas_destroy(image);
    return fit;
}
