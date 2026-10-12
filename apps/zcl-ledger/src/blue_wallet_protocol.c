/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_protocol.h"

#include <string.h>

bool blue_wallet_identity_matches(const uint8_t *reply, size_t length) {
    static const uint8_t prefix[3] = {'Z', 'C', 'L'};
    return reply && length == 7 &&
        memcmp(reply, prefix, sizeof prefix) == 0 &&
        ((reply[3] == 8 && reply[4] == 1) ||
         (reply[3] == 11 && reply[4] == 15) ||
         (reply[3] == BLUE_WALLET_PROTOCOL_VERSION &&
          reply[4] == BLUE_WALLET_CAPABILITIES)) &&
        reply[5] == 0x90 && reply[6] == 0;
}

uint16_t blue_wallet_handle(const blue_wallet_state *state,
                            const uint8_t *apdu, size_t apdu_length,
                            uint8_t *reply, size_t reply_capacity,
                            size_t *reply_length) {
    if (!reply_length) return 0x6f00;
    *reply_length = 0;
    if (!state || !apdu || !reply) return 0x6f00;
    if (apdu_length != 5 || apdu[4] != 0) return 0x6700;
    if (apdu[0] != 0xa5) return 0x6e00;
    if (apdu[2] || apdu[3]) return 0x6b00;
    if (apdu[1] == 0x01) {
        static const uint8_t identity[] = {
            'Z', 'C', 'L', BLUE_WALLET_PROTOCOL_VERSION,
            BLUE_WALLET_CAPABILITIES
        };
        if (reply_capacity < sizeof identity) return 0x6700;
        memcpy(reply, identity, sizeof identity);
        *reply_length = sizeof identity;
        return 0x9000;
    }
    if (apdu[1] != 0x02) return 0x6d00;
    if (!state->address_ready) return 0x6985;
    if (reply_capacity < sizeof state->public_key) return 0x6700;
    memcpy(reply, state->public_key, sizeof state->public_key);
    *reply_length = sizeof state->public_key;
    return 0x9000;
}
