/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_render.h"
#include "blue_bagl_canvas.h"
#include "blue_wallet_layout.h"

#include <stdint.h>

static bool draw(blue_bagl_canvas *canvas, const char *label, int y,
    blue_bagl_font font, uint32_t foreground, uint32_t background) {
    return blue_bagl_text(canvas, label, 20, y, 280, true,
        foreground, background, font);
}

static bool draw_details(blue_bagl_canvas *canvas,
    const blue_payment_screen *screen, uint32_t foreground,
    uint32_t background) {
    if (!draw(canvas, screen->title, 25, BLUE_BAGL_TEXT_22,
              foreground, background) ||
        !draw(canvas, screen->kind, 68, BLUE_BAGL_TEXT_22,
              foreground, background) ||
        !draw(canvas, screen->amount, 115, BLUE_BAGL_TEXT_22,
              foreground, background) ||
        !draw(canvas, "ZCL MAINNET ADDRESS", 172, BLUE_BAGL_TEXT_14,
              foreground, background)) return false;
    for (unsigned i = 0; i < 3; ++i)
        if (!draw(canvas, screen->address_lines[i], 208 + (int)i * 36,
                  BLUE_BAGL_TEXT_22, foreground, background)) return false;
    return draw(canvas, "DRAFT; NO SIGNING", 331, BLUE_BAGL_TEXT_14,
                foreground, background);
}

bool blue_payment_render_canvas(blue_bagl_canvas *canvas,
    const blue_payment_screen *screen, bool dark) {
    if (!canvas || !screen) return false;
    uint32_t background = dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8;
    uint32_t foreground = dark ? ZCL_WALLET_COLOR_TEXT : 0x10212a;
    uint32_t accent = dark ? ZCL_WALLET_COLOR_ACCENT : 0x116f61;
    bool fit = draw_details(canvas, screen, foreground, background);
    blue_bagl_round_rectangle(canvas, 20, 386, 135, 58, accent);
    blue_bagl_round_rectangle(canvas, 165, 386, 135, 58, accent);
    if (fit) fit = blue_bagl_text(canvas, "CONTINUE", 20, 404,
        135, true, dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    if (fit) fit = blue_bagl_text(canvas, "EXIT", 165, 404,
        135, true, dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    return fit;
}

bool blue_payment_render_png(const char *path,
    const blue_payment_screen *screen, bool dark) {
    if (!path) return false;
    blue_bagl_canvas *canvas = blue_bagl_canvas_create(
        dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8);
    if (!canvas) return false;
    bool fit = blue_payment_render_canvas(canvas, screen, dark);
    if (fit) fit = blue_bagl_write_png(canvas, path);
    blue_bagl_canvas_destroy(canvas);
    return fit;
}

static bool draw_fee_details(blue_bagl_canvas *canvas,
    const char *fee_text, const char *paths, uint32_t foreground,
    uint32_t background) {
    return draw(canvas, "CALCULATED FEE", 70, BLUE_BAGL_TEXT_22,
                foreground, background) &&
        draw(canvas, fee_text, 145, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "m/44'/147'/0'", 195, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, paths, 232, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "CHAIN UNCHECKED", 283, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "BRANCH UNCHECKED", 315, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "NO SIGNING", 347, BLUE_BAGL_TEXT_22,
             foreground, background);
}

bool blue_payment_render_fee_canvas(blue_bagl_canvas *canvas,
    uint64_t fee_zat, uint8_t input_paths, bool dark) {
    char fee_text[32];
    const char *paths = blue_payment_input_paths_label(input_paths);
    if (!canvas || !paths || !blue_payment_amount_text(fee_zat, fee_text))
        return false;
    uint32_t background = dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8;
    uint32_t foreground = dark ? ZCL_WALLET_COLOR_TEXT : 0x10212a;
    uint32_t accent = dark ? ZCL_WALLET_COLOR_ACCENT : 0x116f61;
    bool fit = draw_fee_details(canvas, fee_text, paths,
                                foreground, background);
    blue_bagl_round_rectangle(canvas, 20, 386, 135, 58, accent);
    blue_bagl_round_rectangle(canvas, 165, 386, 135, 58, accent);
    if (fit) fit = blue_bagl_text(canvas, "TOTALS", 20, 404, 135, true,
        dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    if (fit) fit = blue_bagl_text(canvas, "EXIT", 165, 404, 135, true,
        dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    return fit;
}

bool blue_payment_render_fee_png(const char *path, uint64_t fee_zat,
    uint8_t input_paths, bool dark) {
    if (!path) return false;
    blue_bagl_canvas *canvas = blue_bagl_canvas_create(
        dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8);
    if (!canvas) return false;
    bool fit = blue_payment_render_fee_canvas(canvas, fee_zat,
        input_paths, dark) && blue_bagl_write_png(canvas, path);
    blue_bagl_canvas_destroy(canvas);
    return fit;
}

static bool draw_totals_details(blue_bagl_canvas *canvas,
    const char *others, const char *own, const char *fee,
    uint32_t foreground, uint32_t background) {
    return draw(canvas, "OUTPUT TOTALS", 25, BLUE_BAGL_TEXT_22,
                foreground, background) &&
        draw(canvas, "OWNER NOT VERIFIED", 75, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, others, 110, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "MATCHES YOUR KEY", 165, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, own, 200, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "FEE", 250, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, fee, 280, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "CHAIN UNCHECKED", 314, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "BRANCH UNCHECKED", 339, BLUE_BAGL_TEXT_22,
             foreground, background) &&
        draw(canvas, "NO SIGNING", 364, BLUE_BAGL_TEXT_22,
             foreground, background);
}

bool blue_payment_render_totals_canvas(blue_bagl_canvas *canvas,
    uint64_t output_zat, uint64_t own_output_zat, uint64_t fee_zat,
    bool dark) {
    char others[32], own[32], fee[32];
    if (!canvas || own_output_zat > output_zat ||
        !blue_payment_amount_text(output_zat - own_output_zat, others) ||
        !blue_payment_amount_text(own_output_zat, own) ||
        !blue_payment_amount_text(fee_zat, fee)) return false;
    uint32_t background = dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8;
    uint32_t foreground = dark ? ZCL_WALLET_COLOR_TEXT : 0x10212a;
    uint32_t accent = dark ? ZCL_WALLET_COLOR_ACCENT : 0x116f61;
    bool fit = draw_totals_details(canvas, others, own, fee,
                                   foreground, background);
    blue_bagl_round_rectangle(canvas, 20, 386, 135, 58, accent);
    blue_bagl_round_rectangle(canvas, 165, 386, 135, 58, accent);
    if (fit) fit = blue_bagl_text(canvas, "BACK", 20, 404, 135, true,
        dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    if (fit) fit = blue_bagl_text(canvas, "NEXT", 165, 404, 135, true,
        dark ? background : 0xffffff, accent, BLUE_BAGL_TEXT_22);
    return fit;
}

bool blue_payment_render_totals_png(const char *path, uint64_t output_zat,
    uint64_t own_output_zat, uint64_t fee_zat, bool dark) {
    if (!path) return false;
    blue_bagl_canvas *canvas = blue_bagl_canvas_create(
        dark ? ZCL_WALLET_COLOR_BODY : 0xf5f7f8);
    if (!canvas) return false;
    bool fit = blue_payment_render_totals_canvas(canvas, output_zat,
        own_output_zat, fee_zat, dark) &&
        blue_bagl_write_png(canvas, path);
    blue_bagl_canvas_destroy(canvas);
    return fit;
}
