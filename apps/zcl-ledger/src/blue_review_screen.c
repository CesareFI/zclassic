/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_screen.h"
#include "zcl_base58.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"

#include <stddef.h>
#include <string.h>

static uint32_t read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static bool append_text(char line[ZCL_BLUE_REVIEW_LINE_SIZE],
                        size_t *used, const char *text) {
    size_t length = strlen(text);
    if (length >= ZCL_BLUE_REVIEW_LINE_SIZE - *used) return false;
    memcpy(line + *used, text, length);
    *used += length;
    line[*used] = 0;
    return true;
}

static bool append_number(char line[ZCL_BLUE_REVIEW_LINE_SIZE],
                          size_t *used, uint64_t value) {
    char digits[20];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    if (count >= ZCL_BLUE_REVIEW_LINE_SIZE - *used) return false;
    while (count) line[(*used)++] = digits[--count];
    line[*used] = 0;
    return true;
}

static bool append_zcl(char line[ZCL_BLUE_REVIEW_LINE_SIZE],
                       size_t *used, uint64_t zat) {
    if (!append_number(line, used, zat / 100000000) ||
        !append_text(line, used, ".")) return false;
    uint64_t fraction = zat % 100000000;
    uint64_t place = 10000000;
    for (unsigned i = 0; i < 8; ++i, place /= 10) {
        if (*used + 1 >= ZCL_BLUE_REVIEW_LINE_SIZE) return false;
        line[(*used)++] = (char)('0' + fraction / place);
        fraction %= place;
    }
    line[*used] = 0;
    return append_text(line, used, " ZCL");
}

static bool format_pair(char line[ZCL_BLUE_REVIEW_LINE_SIZE],
                        const char *label, uint32_t first, uint32_t second) {
    size_t used = 0;
    return append_text(line, &used, label) &&
        append_number(line, &used, first) &&
        append_text(line, &used, "/") &&
        append_number(line, &used, second);
}

bool blue_review_screen_format(
    const uint8_t reply[76],
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!reply || !lines) return false;
    memset(lines, 0, ZCL_BLUE_REVIEW_LINES * ZCL_BLUE_REVIEW_LINE_SIZE);
    size_t used = 0;
    if (!format_pair(lines[0], "PUBLIC IN/OUT: ",
                     read_u32(reply), read_u32(reply + 4)) ||
        !append_text(lines[1], &used, "PUB OUT: ") ||
        !append_zcl(lines[1], &used, read_u64(reply + 20)) ||
        !format_pair(lines[2], "SHIELDED SPEND/OUT: ",
                     read_u32(reply + 8), read_u32(reply + 12)))
        return false;
    used = 0;
    if (!append_text(lines[3], &used, "FEE UNKNOWN; SPROUT: ") ||
        !append_number(lines[3], &used, read_u32(reply + 16)))
        return false;
    used = 0;
    if (!append_text(lines[4], &used, "SHIELDED HIDDEN; NO SIGNING"))
        return false;
    static const char hex[] = "0123456789abcdef";
    used = 0;
    if (!append_text(lines[5], &used, "TX SHA256: ")) return false;
    for (unsigned i = 0; i < 8; ++i) {
        lines[5][used++] = hex[reply[44 + i] >> 4];
        lines[5][used++] = hex[reply[44 + i] & 15];
    }
    lines[5][used] = 0;
    return true;
}

bool blue_review_screen_zip243(
    const uint8_t reply[76],
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!blue_review_screen_format(reply, lines)) return false;
    static const char hex[] = "0123456789abcdef";
    memset(lines[5], 0, ZCL_BLUE_REVIEW_LINE_SIZE);
    memcpy(lines[5], "ZIP243 PREFIX: ", sizeof "ZIP243 PREFIX: " - 1);
    for (unsigned i = 0; i < 8; ++i) {
        lines[5][15 + 2 * i] = hex[reply[44 + i] >> 4];
        lines[5][16 + 2 * i] = hex[reply[44 + i] & 15];
    }
    lines[5][31] = 0;
    return true;
}

bool blue_review_screen_zip243_digest(const uint8_t digest[32],
    uint32_t branch_id,
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!digest || !lines) return false;
    static const char hex[] = "0123456789abcdef";
    static const char branch_hex[] = "0123456789ABCDEF";
    memset(lines, 0, ZCL_BLUE_REVIEW_LINES * ZCL_BLUE_REVIEW_LINE_SIZE);
    memcpy(lines[0], "ZIP243 BRANCH 0x", sizeof "ZIP243 BRANCH 0x" - 1);
    for (unsigned i = 0; i < 8; ++i)
        lines[0][16 + i] = branch_hex[(branch_id >> (28u - 4u * i)) & 15u];
    lines[0][24] = 0;
    for (unsigned row = 0; row < 4; ++row) {
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t byte = digest[row * 8 + i];
            lines[row + 1][2 * i] = hex[byte >> 4];
            lines[row + 1][2 * i + 1] = hex[byte & 15];
        }
    }
    memcpy(lines[5], "CHAIN UNCHECKED; NO SIGNING",
        sizeof "CHAIN UNCHECKED; NO SIGNING");
    return true;
}

bool blue_review_screen_wire_commitment(const uint8_t commitment[32],
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!commitment || !lines) return false;
    static const char hex[] = "0123456789abcdef";
    memset(lines, 0, ZCL_BLUE_REVIEW_LINES * ZCL_BLUE_REVIEW_LINE_SIZE);
    memcpy(lines[0], "FULL WIRE SHA-256", sizeof "FULL WIRE SHA-256");
    for (unsigned row = 0; row < 4; ++row)
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t byte = commitment[row * 8 + i];
            lines[row + 1][2 * i] = hex[byte >> 4];
            lines[row + 1][2 * i + 1] = hex[byte & 15];
        }
    memcpy(lines[5], "READ ONLY; NO SIGNING",
        sizeof "READ ONLY; NO SIGNING");
    return true;
}

bool blue_review_screen_progress(uint8_t pass, uint32_t received,
    uint32_t total,
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!lines || pass < 1 || pass > 6 || !total || received > total)
        return false;
    memset(lines, 0, ZCL_BLUE_REVIEW_LINES * ZCL_BLUE_REVIEW_LINE_SIZE);
    size_t used = 0;
    if (!append_text(lines[0], &used, "REVIEW PASS: ") ||
        !append_number(lines[0], &used, pass) ||
        !append_text(lines[0], &used, "/6")) return false;
    used = 0;
    if (!append_text(lines[1], &used, "UPLOAD BYTES: ") ||
        !append_number(lines[1], &used, received) ||
        !append_text(lines[1], &used, "/") ||
        !append_number(lines[1], &used, total)) return false;
    memcpy(lines[2], "CHECKING FULL TRANSACTION",
        sizeof "CHECKING FULL TRANSACTION");
    memcpy(lines[3], "SHIELDED DETAILS HIDDEN",
        sizeof "SHIELDED DETAILS HIDDEN");
    memcpy(lines[4], "READ ONLY; NO SIGNING",
        sizeof "READ ONLY; NO SIGNING");
    return true;
}

typedef struct {
    uint32_t index;
    uint32_t count;
    zcl_tx_output output;
    bool found;
} output_selection;

static bool select_output(void *context, const zcl_tx_output *output) {
    output_selection *selection = context;
    ++selection->count;
    if (output->index == selection->index) {
        selection->output = *output;
        selection->found = true;
    }
    return true;
}

static bool output_address(const zcl_tx_output *output,
                           blue_review_hash_fn hash, char address[40]) {
    uint8_t payload[26] = {0x1c};
    uint8_t first[32], second[32];
    payload[1] = output->type == ZCL_TX_OUTPUT_P2PKH ? 0xb8 : 0xbd;
    memcpy(payload + 2, output->script +
        (output->type == ZCL_TX_OUTPUT_P2PKH ? 3 : 2), 20);
    if (!hash(payload, 22, first) || !hash(first, 32, second)) return false;
    memcpy(payload + 22, second, 4);
    return zcl_base58_encode(payload, sizeof payload, address, 40) == 0;
}

static bool format_output_header(const output_selection *selection,
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    size_t used = 0;
    return append_text(lines[0], &used, "OUTPUT ") &&
        append_number(lines[0], &used, selection->index + 1u) &&
        append_text(lines[0], &used, "/") &&
        append_number(lines[0], &used, selection->count) &&
        append_text(lines[0], &used, ": ") &&
        append_text(lines[0], &used,
            selection->output.type == ZCL_TX_OUTPUT_P2PKH ? "P2PKH" :
            selection->output.type == ZCL_TX_OUTPUT_P2SH ? "P2SH" :
            selection->output.type == ZCL_TX_OUTPUT_OP_RETURN ? "OP_RETURN" :
            "OTHER");
}

static bool format_output_details(const zcl_tx_output *output,
    blue_review_hash_fn hash,
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    size_t used = 0;
    if (!append_text(lines[1], &used, "AMOUNT: ") ||
        !append_zcl(lines[1], &used, output->value_zat)) return false;
    if (output->type != ZCL_TX_OUTPUT_P2PKH &&
        output->type != ZCL_TX_OUTPUT_P2SH) {
        uint8_t digest[32];
        static const char hex[] = "0123456789abcdef";
        if (!hash(output->script, output->script_length, digest)) return false;
        used = 0;
        if (!append_text(lines[2], &used, "SCRIPT BYTES: ") ||
            !append_number(lines[2], &used, output->script_length))
            return false;
        memcpy(lines[3], "SHA256: ", 8);
        for (unsigned i = 0; i < 10; ++i) {
            lines[3][8 + 2 * i] = hex[digest[i] >> 4];
            lines[3][9 + 2 * i] = hex[digest[i] & 15];
        }
        lines[3][28] = 0;
        return append_text(lines[4], &(size_t){0},
            output->type == ZCL_TX_OUTPUT_OP_RETURN ?
            "TOKEN STATUS UNVERIFIED" : "NO STANDARD ADDRESS");
    }
    char address[40];
    if (!output_address(output, hash, address)) return false;
    if (!append_text(lines[2], &(size_t){0}, "ZCL MAINNET ADDRESS"))
        return false;
    size_t address_length = strlen(address);
    size_t first = address_length < 18 ? address_length : 18;
    memcpy(lines[3], address, first);
    lines[3][first] = 0;
    memcpy(lines[4], address + first, address_length - first + 1);
    return true;
}

bool blue_review_screen_output(
    const uint8_t *wire, size_t length, uint32_t index,
    blue_review_hash_fn hash,
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE]) {
    if (!wire || !hash || !lines) return false;
    output_selection selection = {.index = index};
    if (zcl_tx_outputs_visit(wire, length, select_output, &selection) < 0 ||
        !selection.found) return false;
    memset(lines, 0, ZCL_BLUE_REVIEW_LINES * ZCL_BLUE_REVIEW_LINE_SIZE);
    return format_output_header(&selection, lines) &&
        format_output_details(&selection.output, hash, lines) &&
        append_text(lines[5], &(size_t){0}, "READ ONLY; NO SIGNING");
}
