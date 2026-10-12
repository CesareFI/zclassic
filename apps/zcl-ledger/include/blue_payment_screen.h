/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_SCREEN_H
#define ZCL_BLUE_PAYMENT_SCREEN_H

#include "blue_payment_review.h"

typedef bool (*blue_payment_hash_fn)(const uint8_t *bytes, size_t length,
    uint8_t digest[32]);

typedef struct {
    char title[24];
    char amount[32];
    char address[40];
    char address_lines[3][13];
    char kind[20];
} blue_payment_screen;

enum { BLUE_PAYMENT_AMOUNT_TEXT_SIZE = sizeof "21000000.00000000 ZCL" };

typedef enum {
    BLUE_PAYMENT_ACCOUNT_UNKNOWN,
    BLUE_PAYMENT_THIS_ACCOUNT,
    BLUE_PAYMENT_OWN_INTERNAL,
    BLUE_PAYMENT_OTHER_P2PKH,
    BLUE_PAYMENT_P2SH_ADDRESS
} blue_payment_account_relation;

enum {
    BLUE_PAYMENT_INPUT_EXTERNAL = 1,
    BLUE_PAYMENT_INPUT_INTERNAL = 2
};

/* Labels the fixed derivation path or both paths used by verified inputs. */
const char *blue_payment_input_paths_label(uint8_t paths);

/* Exact P2PKH matches to device-derived external 0/0 and internal 1/0
 * addresses are distinguished. Neither match proves that an output is
 * change. P2SH cannot be classified as owned from its script hash. */
blue_payment_account_relation blue_payment_account_classify(
    const blue_payment_output *output,
    const uint8_t account_hash160[20],
    const uint8_t internal_hash160[20], bool account_ready);

/* Replaces the output-type label with a device-derived account relation.
 * Failure clears the label so an unverified account claim cannot be shown. */
bool blue_payment_screen_mark_account(blue_payment_screen *screen,
    const blue_payment_output *output,
    const uint8_t account_hash160[20],
    const uint8_t internal_hash160[20], bool account_ready);

/* Formats one provisional transparent output from the replay parser.
 * The full address is retained; this screen cannot approve signing. */
bool blue_payment_screen_format(const blue_payment_output *output,
    uint32_t total_outputs, blue_payment_hash_fn hash,
    blue_payment_screen *screen);

/* Formats a bounded transparent ZCL amount without host-provided text. */
bool blue_payment_amount_text(uint64_t zat,
                              char text[BLUE_PAYMENT_AMOUNT_TEXT_SIZE]);

#endif
