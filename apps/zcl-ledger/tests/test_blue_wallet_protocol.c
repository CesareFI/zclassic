/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_wallet_protocol.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static void check(blue_wallet_state *state, const uint8_t *apdu,
                  size_t apdu_length, uint16_t expected_status,
                  size_t expected_length) {
    uint8_t reply[35];
    memset(reply, 0xa5, sizeof reply);
    size_t length = 99;
    uint16_t status = blue_wallet_handle(state, apdu, apdu_length,
                                         reply, sizeof reply, &length);
    assert(status == expected_status);
    assert(length == expected_length);
    for (size_t i = length; i < sizeof reply; ++i) assert(reply[i] == 0xa5);
    if (length == BLUE_WALLET_PUBLIC_KEY_SIZE)
        assert(memcmp(reply, state->public_key, length) == 0);
    if (length == 5) {
        const uint8_t identity[] = {'Z', 'C', 'L',
            BLUE_WALLET_PROTOCOL_VERSION, BLUE_WALLET_CAPABILITIES};
        assert(memcmp(reply, identity, sizeof identity) == 0);
    }
}

static void check_mutations(blue_wallet_state *state) {
    uint8_t malformed[5];
    uint32_t random = 0x23c1a55u;
    for (size_t i = 0; i < 10000; ++i) {
        for (size_t j = 0; j < sizeof malformed; ++j) {
            random = random * 1664525u + 1013904223u;
            malformed[j] = (uint8_t)(random >> 24);
        }
        size_t n = i % 6;
        if (n == 5 && malformed[0] == 0xa5 &&
            malformed[1] <= 2 && malformed[2] == 0 &&
            malformed[3] == 0 && malformed[4] == 0) continue;
        check(state, malformed, n, n == 5 && malformed[4] == 0
              ? (malformed[0] != 0xa5 ? 0x6e00
                 : malformed[2] || malformed[3] ? 0x6b00 : 0x6d00)
              : 0x6700, 0);
    }
}

int main(void) {
    uint8_t identity_v8[7] = {'Z', 'C', 'L', 8, 1, 0x90, 0};
    uint8_t identity_v11[7] = {'Z', 'C', 'L', 11, 15, 0x90, 0};
    uint8_t identity_current[7] = {'Z', 'C', 'L',
        BLUE_WALLET_PROTOCOL_VERSION, BLUE_WALLET_CAPABILITIES, 0x90, 0};
    assert(blue_wallet_identity_matches(identity_v8, sizeof identity_v8));
    assert(blue_wallet_identity_matches(identity_v11, sizeof identity_v11));
    assert(blue_wallet_identity_matches(identity_current,
        sizeof identity_current));
    identity_current[4] ^= 2;
    assert(!blue_wallet_identity_matches(identity_current,
        sizeof identity_current));
    identity_current[4] ^= 2;
    identity_current[6] = 1;
    assert(!blue_wallet_identity_matches(identity_current,
        sizeof identity_current));
    const uint8_t retired_v9[7] = {'Z', 'C', 'L', 9, 3, 0x90, 0};
    assert(!blue_wallet_identity_matches(retired_v9,
        sizeof retired_v9));
    const uint8_t retired_v10[7] = {'Z', 'C', 'L', 10, 7, 0x90, 0};
    assert(!blue_wallet_identity_matches(retired_v10,
        sizeof retired_v10));
    assert(!blue_wallet_identity_matches(identity_v8, 6));
    blue_wallet_state state = {0};
    const uint8_t identify[] = {0xa5, 1, 0, 0, 0};
    const uint8_t read_key[] = {0xa5, 2, 0, 0, 0};
    check(&state, identify, sizeof identify, 0x9000, 5);
    check(&state, read_key, sizeof read_key, 0x6985, 0);
    state.address_ready = true;
    state.public_key[0] = 2;
    for (size_t i = 1; i < sizeof state.public_key; ++i)
        state.public_key[i] = (uint8_t)i;
    check(&state, read_key, sizeof read_key, 0x9000, 33);

    uint8_t malformed[5];
    memcpy(malformed, read_key, sizeof malformed);
    for (size_t n = 0; n < 5; ++n) check(&state, malformed, n, 0x6700, 0);
    malformed[0] = 0xe0;
    check(&state, malformed, 5, 0x6e00, 0);
    malformed[0] = 0xa5;
    malformed[1] = 0x03;
    check(&state, malformed, 5, 0x6d00, 0);
    malformed[1] = 0x02;
    malformed[2] = 1;
    check(&state, malformed, 5, 0x6b00, 0);
    malformed[2] = 0;
    malformed[3] = 1;
    check(&state, malformed, 5, 0x6b00, 0);
    malformed[3] = 0;
    malformed[4] = 1;
    check(&state, malformed, 5, 0x6700, 0);

    uint8_t reply[33];
    size_t length = 99;
    assert(blue_wallet_handle(&state, read_key, 5, reply, 32, &length) == 0x6700);
    assert(length == 0);
    assert(blue_wallet_handle(&state, identify, 5, reply, 4, &length) == 0x6700);
    assert(length == 0);
    assert(blue_wallet_handle(&state, NULL, 5, reply, 33, &length) == 0x6f00);
    assert(length == 0);
    assert(blue_wallet_handle(NULL, read_key, 5, reply, 33, &length) == 0x6f00);
    assert(length == 0);
    assert(blue_wallet_handle(&state, read_key, 5, NULL, 33, &length) == 0x6f00);
    assert(length == 0);
    assert(blue_wallet_handle(&state, read_key, 5, reply, 33, NULL) == 0x6f00);

    check_mutations(&state);
    return 0;
}
