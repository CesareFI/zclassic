/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define main blue_fixture_cli_entry
#include "../src/blue_wallet_fixture_cli.c"
#undef main

#undef NDEBUG
#include <assert.h>

static unsigned abort_calls;
static uint16_t abort_status;
static bool transport_failed;

int ledger_hid_exchange_timeout(int fd, const uint8_t *apdu, size_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length, int timeout_ms) {
    assert(fd == 37 && length == 5 && capacity >= 2 && timeout_ms == 5000);
    assert(memcmp(apdu, (const uint8_t[]){0xa5, 0x24, 0, 0, 0}, 5) == 0);
    ++abort_calls;
    if (transport_failed) return -1;
    reply[0] = (uint8_t)(abort_status >> 8);
    reply[1] = (uint8_t)abort_status;
    *reply_length = 2;
    return 0;
}

int main(void) {
    fixture_device device = {.fd = 37};
    abort_status = 0x9000;
    assert(!finish_live_fixture(&device, false));
    assert(abort_calls == 1);
    assert(finish_live_fixture(&device, true));
    assert(abort_calls == 2);
    abort_status = 0x6985;
    assert(!finish_live_fixture(&device, true));
    assert(abort_calls == 3);
    transport_failed = true;
    assert(!finish_live_fixture(&device, true));
    assert(abort_calls == 4);
    return 0;
}
