/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_receive.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    static const char address[] = "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs";
    char lines[ZCL_WALLET_ADDRESS_LINES][ZCL_WALLET_ADDRESS_LINE_SIZE];
    assert(strlen(address) == ZCL_WALLET_ADDRESS_CHARS);
    assert(blue_wallet_receive_split(address, lines));
    assert(strcmp(lines[0], "t1UYsZVJkLPe") == 0);
    assert(strcmp(lines[1], "MjxEtACvSxfW") == 0);
    assert(strcmp(lines[2], "uNmddpWfxzs") == 0);
    char changed[sizeof address];
    memcpy(changed, address, sizeof changed);
    changed[12] = '0';
    assert(!blue_wallet_receive_split(changed, lines));
    changed[12] = address[12];
    changed[34] = 0;
    assert(!blue_wallet_receive_split(changed, lines));
    assert(!blue_wallet_receive_split(NULL, lines));
    assert(!blue_wallet_receive_split(address, NULL));
    return 0;
}
