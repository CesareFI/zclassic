/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_BAGL_CANVAS_H
#define ZCL_BLUE_BAGL_CANVAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { BLUE_BAGL_WIDTH = 320, BLUE_BAGL_HEIGHT = 480 };
typedef struct blue_bagl_canvas blue_bagl_canvas;
typedef enum { BLUE_BAGL_TEXT_14, BLUE_BAGL_TEXT_22 } blue_bagl_font;

blue_bagl_canvas *blue_bagl_canvas_create(uint32_t background);
void blue_bagl_canvas_destroy(blue_bagl_canvas *canvas);
void blue_bagl_rectangle(blue_bagl_canvas *canvas, int x, int y,
                         int width, int height, uint32_t color);
void blue_bagl_round_rectangle(blue_bagl_canvas *canvas, int x, int y,
                               int width, int height, uint32_t color);
bool blue_bagl_text(blue_bagl_canvas *canvas, const char *label,
                    int x, int y, int width, bool centered,
                    uint32_t foreground, uint32_t background,
                    blue_bagl_font font);
int blue_bagl_font_height(blue_bagl_font font);
bool blue_bagl_wrap_ascii(const char *source, size_t source_length,
                          char *output, size_t output_capacity,
                          unsigned max_width, unsigned max_lines,
                          blue_bagl_font font);
bool blue_bagl_write_png(const blue_bagl_canvas *canvas, const char *path);
const uint8_t *blue_bagl_canvas_rgb(const blue_bagl_canvas *canvas,
                                    size_t *length);

#endif
