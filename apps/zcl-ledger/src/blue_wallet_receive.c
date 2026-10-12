/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_receive.h"

#include <string.h>

bool blue_wallet_receive_split(
    const char address[ZCL_WALLET_ADDRESS_CHARS + 1],
    char lines[ZCL_WALLET_ADDRESS_LINES][ZCL_WALLET_ADDRESS_LINE_SIZE]) {
    static const char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (!address || !lines || address[0] != 't' || address[1] != '1')
        return false;
    for (size_t i = 0; i < ZCL_WALLET_ADDRESS_CHARS; ++i)
        if (!address[i] || !strchr(alphabet, address[i])) return false;
    if (address[ZCL_WALLET_ADDRESS_CHARS] != 0) return false;
    memcpy(lines[0], address, 12);
    memcpy(lines[1], address + 12, 12);
    memcpy(lines[2], address + 24, 11);
    lines[0][12] = lines[1][12] = lines[2][11] = 0;
    return true;
}
