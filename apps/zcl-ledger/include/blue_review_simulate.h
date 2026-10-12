/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_REVIEW_SIMULATE_H
#define ZCL_BLUE_REVIEW_SIMULATE_H

#include "zcl_tx_review.h"
#include "blue_review_app.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue app simulation requires ISO C23"
#endif

bool blue_review_simulate(const uint8_t *wire, size_t length,
    const zcl_tx_review *review, bool has_branch, uint32_t branch_id,
    const uint8_t zip_digest[32]);

typedef bool (*blue_review_page_fn)(const blue_review_app *app, void *context);
bool blue_review_simulate_pages(const uint8_t *wire, size_t length,
    const zcl_tx_review *review, blue_review_page_fn page, void *context);

#endif
