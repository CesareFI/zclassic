/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_RENDER_H
#define ZCL_BLUE_PAYMENT_RENDER_H

#include "blue_payment_screen.h"
#include "blue_bagl_canvas.h"

/* Host-only 320x480 PNG preview using the Blue SDK font bitmap. */
bool blue_payment_render_png(const char *path,
    const blue_payment_screen *screen, bool dark);
bool blue_payment_render_canvas(blue_bagl_canvas *canvas,
    const blue_payment_screen *screen, bool dark);

/* Mirrors the fixed-path and fee summary screen without device keys. */
bool blue_payment_render_fee_png(const char *path, uint64_t fee_zat,
    uint8_t input_paths, bool dark);
/* Draws on a canvas initialized with the selected theme background. */
bool blue_payment_render_fee_canvas(blue_bagl_canvas *canvas,
    uint64_t fee_zat, uint8_t input_paths, bool dark);

/* Mirrors the device-derived output totals and fee page. */
bool blue_payment_render_totals_png(const char *path, uint64_t output_zat,
    uint64_t own_output_zat, uint64_t fee_zat, bool dark);
bool blue_payment_render_totals_canvas(blue_bagl_canvas *canvas,
    uint64_t output_zat, uint64_t own_output_zat, uint64_t fee_zat,
    bool dark);

#endif
