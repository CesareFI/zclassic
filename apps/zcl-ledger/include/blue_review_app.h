/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REVIEW_APP_H
#define ZCL_BLUE_REVIEW_APP_H

#include "blue_review_protocol.h"
#include "blue_review_screen.h"

typedef struct {
    blue_review_state transaction;
    uint8_t reply[76];
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    uint32_t page;
    uint8_t detail;
    bool large_text;
    bool dark;
} blue_review_app;

void blue_review_app_reset(blue_review_app *app);
uint16_t blue_review_app_command(blue_review_app *app,
    const uint8_t *apdu, size_t apdu_length, uint8_t *reply,
    size_t reply_capacity, size_t *reply_length,
    blue_review_digest_fn digest, const zcl_zip243_hasher *zip243_hasher);
bool blue_review_app_next(blue_review_app *app, blue_review_hash_fn hash);
bool blue_review_app_advance(blue_review_app *app, blue_review_hash_fn hash);
void blue_review_app_toggle_text(blue_review_app *app);
void blue_review_app_toggle_dark(blue_review_app *app);

#endif
