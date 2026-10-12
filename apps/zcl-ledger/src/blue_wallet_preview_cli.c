/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_render.h"
#include "zcl_address.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool parse_pubkey(const char *hex, uint8_t pubkey[33]) {
    if (strlen(hex) != 66) return false;
    for (size_t i = 0; i < 33; ++i) {
        int high = nibble(hex[2 * i]), low = nibble(hex[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        pubkey[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s PUBKEY_HEX|--error OUTPUT.png\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--error") == 0) {
        if (!blue_wallet_render_png(argv[2], NULL)) return 1;
    } else {
        uint8_t pubkey[33];
        char address[ZCL_ADDRESS_SIZE];
        if (!parse_pubkey(argv[1], pubkey) ||
            zcl_address_from_pubkey(pubkey, address) < 0 ||
            !blue_wallet_render_png(argv[2], address)) return 1;
    }
    puts(argv[2]);
    return 0;
}
