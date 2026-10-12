/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded QR matrix encoding and dependency-free RGB rendering. */

#include "encoding/qr.h"
#include "base/safe_alloc.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../vendor/qrcodegen/qrcodegen.h"

static void qr_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        snprintf(error, cap, "%s", message ? message : "QR operation failed");
}

bool qr_matrix_backend_available(void)
{
    return true;
}

static bool qr_encoded_width_valid(uint32_t width)
{
    return width != 0 && width <= 177u &&
           (size_t)width <= SIZE_MAX / (size_t)width;
}

bool qr_matrix_encode(const char *payload, struct qr_matrix *out,
                      char *error, size_t error_cap)
{
    if (!out) {
        qr_error(error, error_cap, "missing QR output matrix");
        return false;
    }
    out->modules = NULL;
    out->width = 0;
    if (!payload || !payload[0]) {
        qr_error(error, error_cap, "QR payload must not be empty");
        return false;
    }
    size_t payload_len = strnlen(payload, ZCL_QR_MAX_PAYLOAD + 1u);
    if (payload_len > ZCL_QR_MAX_PAYLOAD) {
        qr_error(error, error_cap, "QR payload exceeds 2048 bytes");
        return false;
    }

    uint8_t work[qrcodegen_BUFFER_LEN_MAX];
    uint8_t encoded[qrcodegen_BUFFER_LEN_MAX];
    memcpy(work, payload, payload_len);
    if (!qrcodegen_encodeBinary(work, payload_len, encoded,
                                qrcodegen_Ecc_MEDIUM,
                                qrcodegen_VERSION_MIN,
                                qrcodegen_VERSION_MAX,
                                qrcodegen_Mask_AUTO, false)) {
        qr_error(error, error_cap, "QR encoder rejected the payload");
        return false;
    }
    int encoded_width = qrcodegen_getSize(encoded);
    uint32_t width = encoded_width > 0 ? (uint32_t)encoded_width : 0;
    if (!qr_encoded_width_valid(width)) {
        qr_error(error, error_cap, "QR encoder returned an invalid matrix");
        return false;
    }
    size_t count = (size_t)width * (size_t)width;
    uint8_t *modules = zcl_malloc(count, "qr.matrix.modules");
    if (!modules) {
        char message[128];
        snprintf(message, sizeof message,
                 "QR matrix allocation failed during encode (%zu bytes); "
                 "retry after freeing memory", count);
        qr_error(error, error_cap, message);
        return false;
    }
    for (uint32_t y = 0; y < width; y++) {
        for (uint32_t x = 0; x < width; x++) {
            modules[(size_t)y * width + x] =
                qrcodegen_getModule(encoded, (int)x, (int)y) ? 1u : 0u;
        }
    }
    out->modules = modules;
    out->width = width;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

void qr_matrix_free(struct qr_matrix *matrix)
{
    if (!matrix) return;
    free(matrix->modules);
    matrix->modules = NULL;
    matrix->width = 0;
}

/* Argument gate + out-param hygiene for qr_matrix_render_rgb. */
static const char *qr_render_args_error(const struct qr_matrix *matrix,
                                 uint32_t scale, uint32_t quiet_modules,
                                 uint8_t **pixels, uint32_t *side)
{
    if (pixels) *pixels = NULL;
    if (side) *side = 0;
    if (!matrix) return "QR matrix: supply a matrix";
    if (!matrix->modules) return "QR matrix.modules: supply module data";
    if (!matrix->width) return "QR matrix.width: use a nonzero width";
    if (!pixels) return "QR pixels: supply an output pointer";
    if (!side) return "QR side: supply an output pointer";
    if (!scale || scale > 64u) return "QR scale: use 1..64";
    if (quiet_modules > 32u) return "QR quiet_modules: use 0..32";
    return NULL;
}

/* Arguments have passed qr_render_args_error. The widened sum and scale
 * product fit uint64_t; bound the side before squaring and RGB expansion. */
static bool qr_render_size(uint32_t width, uint32_t scale,
                           uint32_t quiet_modules, uint32_t *out_side,
                           size_t *out_bytes)
{
    *out_side = 0;
    *out_bytes = 0;
    uint64_t module_side = (uint64_t)width + 2u * quiet_modules;
    uint64_t image_side = module_side * scale;
    if (image_side == 0 || image_side > UINT32_MAX) return false;
    uint64_t area = image_side * image_side;
    if (area > SIZE_MAX / 3u) return false;
    *out_side = (uint32_t)image_side;
    *out_bytes = (size_t)area * 3u;
    return true;
}

bool qr_matrix_render_rgb(const struct qr_matrix *matrix, uint32_t scale,
                          uint32_t quiet_modules, uint8_t **pixels,
                          uint32_t *side, char *error, size_t error_cap)
{
    const char *args_error = qr_render_args_error(matrix, scale, quiet_modules,
                                                 pixels, side);
    if (args_error) {
        qr_error(error, error_cap, args_error);
        return false;
    }
    uint32_t out_side;
    size_t bytes;
    if (!qr_render_size(matrix->width, scale, quiet_modules,
                        &out_side, &bytes)) {
        if (error && error_cap > 0)
            snprintf(error, error_cap,
                     "QR render dimensions overflow: width=%" PRIu32
                     " scale=%" PRIu32 " quiet=%" PRIu32
                     "; reduce width or scale",
                     matrix->width, scale, quiet_modules);
        return false;
    }
    uint8_t *rgb = zcl_malloc((size_t)bytes, "qr.render.rgb");
    if (!rgb) {
        char message[128];
        snprintf(message, sizeof message,
                 "QR render allocation failed: %zu bytes, side=%u; "
                 "retry after freeing memory", bytes, (unsigned)out_side);
        qr_error(error, error_cap, message);
        return false;
    }
    memset(rgb, 0xff, (size_t)bytes);
    for (uint32_t my = 0; my < matrix->width; my++) {
        for (uint32_t mx = 0; mx < matrix->width; mx++) {
            if (!(matrix->modules[(size_t)my * matrix->width + mx] & 1u))
                continue;
            uint32_t y0 = (my + quiet_modules) * scale;
            uint32_t x0 = (mx + quiet_modules) * scale;
            for (uint32_t py = 0; py < scale; py++) {
                size_t offset = ((size_t)(y0 + py) * out_side + x0) * 3u;
                memset(rgb + offset, 0, (size_t)scale * 3u);
            }
        }
    }
    *pixels = rgb;
    *side = out_side;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}
