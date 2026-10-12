/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_bagl_canvas.h"

#include <png.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
    abort(); \
} } while (0)

static void expect_rgb(const uint8_t *pixels, int x, int y, uint32_t color) {
    size_t offset = ((size_t)y * BLUE_BAGL_WIDTH + (size_t)x) * 3;
    CHECK(pixels[offset] == (uint8_t)(color >> 16));
    CHECK(pixels[offset + 1] == (uint8_t)(color >> 8));
    CHECK(pixels[offset + 2] == (uint8_t)color);
}

int main(void) {
    CHECK(blue_bagl_font_height(BLUE_BAGL_TEXT_14) == 16);
    CHECK(blue_bagl_font_height(BLUE_BAGL_TEXT_22) == 22);
    CHECK(blue_bagl_font_height((blue_bagl_font)99) == 0);
    blue_bagl_canvas *image = blue_bagl_canvas_create(0x112233);
    CHECK(image);
    blue_bagl_rectangle(image, -10, -10, 12, 12, 0xaabbcc);
    blue_bagl_rectangle(image, 319, 479, 100, 100, 0xabcdef);
    blue_bagl_round_rectangle(image, 4, 4, 20, 20, 0x556677);
    CHECK(blue_bagl_text(image, "ZCL", 20, 40, 100, false,
                          0xffffff, 0x112233, BLUE_BAGL_TEXT_14));
    CHECK(!blue_bagl_text(image, "\xc3\xa9", 20, 40, 100, false,
                           0xffffff, 0x112233, BLUE_BAGL_TEXT_14));
    CHECK(!blue_bagl_text(image, "TOO WIDE", 20, 40, 1, false,
                           0xffffff, 0x112233, BLUE_BAGL_TEXT_14));
    CHECK(!blue_bagl_text(image, "A", 319, 40, 10, false,
                           0xffffff, 0x112233, BLUE_BAGL_TEXT_14));
    char wrapped[24];
    CHECK(blue_bagl_wrap_ascii("AAAA BBBB", 9, wrapped, sizeof wrapped,
                               52, 2, BLUE_BAGL_TEXT_22));
    CHECK(strcmp(wrapped, "AAAA\nBBBB") == 0);
    CHECK(blue_bagl_wrap_ascii("AAAAA", 5, wrapped, sizeof wrapped,
                               52, 2, BLUE_BAGL_TEXT_22));
    CHECK(strcmp(wrapped, "AAAA\nA") == 0);
    CHECK(blue_bagl_wrap_ascii("AAAA ", 5, wrapped, sizeof wrapped,
                               52, 1, BLUE_BAGL_TEXT_22));
    CHECK(strcmp(wrapped, "AAAA") == 0);
    CHECK(!blue_bagl_wrap_ascii("AAAA BBBB", 9, wrapped, sizeof wrapped,
                                52, 1, BLUE_BAGL_TEXT_22));
    CHECK(!blue_bagl_wrap_ascii("AAAA BBBB", 9, wrapped, 5,
                                52, 2, BLUE_BAGL_TEXT_22));
    CHECK(!blue_bagl_wrap_ascii("\xc3\xa9", 2, wrapped, sizeof wrapped,
                                52, 2, BLUE_BAGL_TEXT_22));
    char memo[512], memo_lines[640];
    memset(memo, 'A', sizeof memo);
    CHECK(blue_bagl_wrap_ascii(memo, sizeof memo, memo_lines,
                               sizeof memo_lines, 52, 128,
                               BLUE_BAGL_TEXT_22));
    CHECK(strlen(memo_lines) == 639);
    CHECK(!blue_bagl_wrap_ascii(memo, sizeof memo, memo_lines,
                                sizeof memo_lines, 52, 127,
                                BLUE_BAGL_TEXT_22));
    char path[] = "/tmp/zcl-blue-canvas-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(blue_bagl_write_png(image, path));
    size_t raw_length = 0;
    const uint8_t *raw = blue_bagl_canvas_rgb(image, &raw_length);
    CHECK(raw && raw_length == BLUE_BAGL_WIDTH * BLUE_BAGL_HEIGHT * 3u);
    CHECK(!blue_bagl_canvas_rgb(NULL, &raw_length));
    CHECK(!blue_bagl_canvas_rgb(image, NULL));

    png_image png = {0};
    png.version = PNG_IMAGE_VERSION;
    CHECK(png_image_begin_read_from_file(&png, path));
    CHECK(png.width == BLUE_BAGL_WIDTH && png.height == BLUE_BAGL_HEIGHT);
    png.format = PNG_FORMAT_RGB;
    uint8_t *pixels = malloc(PNG_IMAGE_SIZE(png));
    CHECK(pixels);
    CHECK(png_image_finish_read(&png, NULL, pixels, 0, NULL));
    CHECK(memcmp(raw, pixels, raw_length) == 0);
    expect_rgb(pixels, 0, 0, 0xaabbcc);
    expect_rgb(pixels, 2, 2, 0x112233);
    expect_rgb(pixels, 4, 4, 0x112233);
    expect_rgb(pixels, 14, 14, 0x556677);
    expect_rgb(pixels, 319, 479, 0xabcdef);
    expect_rgb(pixels, 100, 100, 0x112233);
    free(pixels);
    blue_bagl_canvas_destroy(image);
    png_image_free(&png);
    CHECK(unlink(path) == 0);
    return 0;
}
