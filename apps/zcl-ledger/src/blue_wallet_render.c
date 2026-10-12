/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_render.h"
#include "blue_bagl_canvas.h"
#include "blue_wallet_layout.h"
#include "blue_wallet_receive.h"

#include <stdint.h>

static bool draw_label(blue_bagl_canvas *image, const char *label,
                       int y, blue_bagl_font font) {
    return blue_bagl_text(image, label, 20, y, 280, true,
        ZCL_WALLET_COLOR_TEXT, ZCL_WALLET_COLOR_BODY, font);
}

static bool draw_receive(blue_bagl_canvas *image, const char *address) {
    char lines[ZCL_WALLET_ADDRESS_LINES][ZCL_WALLET_ADDRESS_LINE_SIZE];
    if (!blue_wallet_receive_split(address, lines)) return false;
    return draw_label(image, "RECEIVE ZCL", ZCL_WALLET_TITLE_Y,
                      BLUE_BAGL_TEXT_22) &&
           draw_label(image, "m/44'/147'/0'/0/0", ZCL_WALLET_PATH_Y,
                      BLUE_BAGL_TEXT_14) &&
           draw_label(image, lines[0], ZCL_WALLET_ADDRESS_1_Y,
                      BLUE_BAGL_TEXT_22) &&
           draw_label(image, lines[1], ZCL_WALLET_ADDRESS_2_Y,
                      BLUE_BAGL_TEXT_22) &&
           draw_label(image, lines[2], ZCL_WALLET_ADDRESS_3_Y,
                      BLUE_BAGL_TEXT_22) &&
           draw_label(image, "MATCH ALL 35 CHARACTERS",
                      ZCL_WALLET_INSTRUCTION_Y, BLUE_BAGL_TEXT_14);
}

static bool draw_error(blue_bagl_canvas *image) {
    return draw_label(image, "ADDRESS UNAVAILABLE", 135,
                      BLUE_BAGL_TEXT_22) &&
           draw_label(image, "EXIT; CHECK DEVICE", 195,
                      BLUE_BAGL_TEXT_14);
}

bool blue_wallet_render_png(const char *path, const char *address) {
    if (!path) return false;
    blue_bagl_canvas *image =
        blue_bagl_canvas_create(ZCL_WALLET_COLOR_BODY);
    if (!image) return false;
    bool fit = address ? draw_receive(image, address) : draw_error(image);
    blue_bagl_round_rectangle(image, 40, ZCL_WALLET_EXIT_Y, 240, 48,
                              ZCL_WALLET_COLOR_ACCENT);
    if (fit) fit = blue_bagl_text(image, "EXIT", 40, ZCL_WALLET_EXIT_Y + 14,
        240, true, ZCL_WALLET_COLOR_BODY, ZCL_WALLET_COLOR_ACCENT,
        BLUE_BAGL_TEXT_14);
    if (fit) fit = blue_bagl_write_png(image, path);
    blue_bagl_canvas_destroy(image);
    return fit;
}
