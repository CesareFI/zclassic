/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef ZCL_BLUE_SHIELDED_REVIEW
#include "blue_sapling_fixture.h"
#include "zcl_zip243.h"
#include "zcl_zip243_host.h"
#endif

#define main blue_shielded_review_device_main
#ifdef ZCL_BLUE_SHIELDED_REVIEW
#include "../device-blue-shielded-review/src/main.c"
#else
#include "../device-blue-review/src/main.c"
#endif
#undef main
#undef cx_hash

unsigned char G_io_apdu_buffer[260];
static const bagl_element_t *shown;
static size_t shown_count;
static unsigned displays;
static blue_try_context *active_try;
static unsigned exchange_calls;
static unsigned fail_exchange_call;
static bool oversized_receive;
static bool reset_during_send;
static void expect_erased(const void *memory, size_t length);
#ifdef ZCL_BLUE_SHIELDED_REVIEW
static bool scripted_review;
static bool scripted_fault;
static bool reset_on_final_display, expect_revoked_reply;
static uint8_t injected_usb_reason;
static uint8_t review_wire[BLUE_SYNTHETIC_SAPLING_BYTES];
static uint8_t review_reply[110];
static unsigned review_pass, review_stage, review_replies, review_runs;
static unsigned fault_stage, fault_replies;
static unsigned request_displays;
static bool redraw_expected;
static size_t review_offset;
#endif

void blue_wallet_test_display(const bagl_element_t *elements, size_t count,
    unsigned int (*button)(unsigned int, unsigned int)) {
    assert(button && button(0, 0) == 0);
    shown = elements;
    shown_count = count;
    ++displays;
#ifdef ZCL_BLUE_SHIELDED_REVIEW
    if (reset_on_final_display && review_app.transaction.complete) {
        reset_on_final_display = false;
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = injected_usb_reason;
        (void)io_event(CHANNEL_SPI);
    }
#endif
}

void blue_wallet_test_finger(const unsigned char *buffer) { (void)buffer; }
void blue_try_enter(blue_try_context *context) {
    context->code = 0;
    context->previous = active_try;
    active_try = context;
}
void blue_try_leave(void) { active_try = active_try->previous; }
blue_try_context *blue_try_current(void) { return active_try; }
void blue_throw(unsigned error) {
    assert(active_try);
    active_try->code = error;
    longjmp(active_try->jump, 1);
}
void os_boot(void) {}
static unsigned exits;
void os_sched_exit(unsigned code) { assert(code == 0); ++exits; }
void io_seproxyhal_init(void) {}
void USB_power(int enabled) { (void)enabled; }
static unsigned short identity_request(unsigned char channel,
                                       unsigned short length) {
    static const uint8_t request[] = {0xa5, 0x01, 0, 0, 0};
    assert(channel == CHANNEL_APDU && length == 0);
    memcpy(G_io_apdu_buffer, request, sizeof request);
    return sizeof request;
}

static unsigned short exchange_reset(unsigned char channel,
                                     unsigned short length) {
    if (exchange_calls == 1) return identity_request(channel, length);
    if (exchange_calls == 2) {
        assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
        assert(length >= 2);
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
        (void)io_event(CHANNEL_SPI);
        for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
            assert(G_io_apdu_buffer[i] == 0);
        return 0;
    }
    assert(channel == CHANNEL_APDU && length == 0);
    blue_throw(0x6f44);
}

static unsigned short exchange_oversized(unsigned char channel,
                                         unsigned short length) {
    if (exchange_calls == 1) {
        assert(channel == CHANNEL_APDU && length == 0);
        memset(G_io_apdu_buffer, 0x5a, sizeof G_io_apdu_buffer);
        return sizeof G_io_apdu_buffer + 1;
    }
    assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
    assert(length == 2 && G_io_apdu_buffer[0] == 0x68 &&
           G_io_apdu_buffer[1] == INVALID_PARAMETER);
    for (size_t i = 2; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    blue_throw(0x6f43);
}

static unsigned short exchange_failed(unsigned char channel,
                                      unsigned short length) {
    if (exchange_calls == 1) return identity_request(channel, length);
    if (exchange_calls == 2) {
        assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
        assert(length >= 2);
        if (fail_exchange_call == 3) return 0;
    }
    if (exchange_calls == 3)
        assert(channel == CHANNEL_APDU && length == 0);
    memset(&review_app.transaction, 0x5a,
           sizeof review_app.transaction);
    memset(&zip_context, 0x5a, sizeof zip_context);
    memset(G_io_apdu_buffer, 0x5a, sizeof G_io_apdu_buffer);
    blue_throw(0x6f42);
}

#ifdef ZCL_BLUE_SHIELDED_REVIEW
static unsigned short review_request(unsigned char channel,
                                      unsigned short length) {
    assert(channel == CHANNEL_APDU && length == 0);
    request_displays = displays;
    uint8_t *apdu = G_io_apdu_buffer;
    apdu[sizeof G_io_apdu_buffer - 2] = 0x5a;
    apdu[sizeof G_io_apdu_buffer - 1] = 0xa5;
    memcpy(apdu, (uint8_t[]){0xa5, 0x20, 0, 0, 8}, 5);
    if (review_stage == 0) {
        for (unsigned i = 0; i < 4; ++i) {
            apdu[5 + i] = (uint8_t)(BLUE_SYNTHETIC_SAPLING_BYTES >> (8 * i));
            apdu[9 + i] = (uint8_t)(0x76b809bbu >> (8 * i));
        }
        review_stage = 1;
        redraw_expected = true;
        return 13;
    }
    if (review_stage == 1) {
        size_t take = sizeof review_wire - review_offset;
        if (take > 220) take = 220;
        apdu[1] = 0x21;
        apdu[4] = (uint8_t)take;
        memcpy(apdu + 5, review_wire + review_offset, take);
        review_offset += take;
        if (review_offset == sizeof review_wire) review_stage = 2;
        redraw_expected = review_stage == 2;
        return (unsigned short)(take + 5);
    }
    if (review_stage == 2) {
        apdu[1] = review_pass == 6 ? 0x23 : 0x22;
        apdu[4] = 0;
        review_stage = review_pass == 6 ? 3 : 1;
        if (review_pass != 6) {
            ++review_pass;
            review_offset = 0;
        }
        redraw_expected = true;
        return 5;
    }
    assert(review_stage == 3);
    if (expect_revoked_reply) blue_throw(0x6f47);
    if (review_runs == 1) {
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
        (void)io_event(CHANNEL_SPI);
        assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
        expect_erased(&review_app.transaction,
                      sizeof review_app.transaction);
        review_pass = 1;
        review_stage = 0;
        review_offset = 0;
        return 0;
    }
    blue_throw(0x6f45);
}

static void review_touch(const char *label) {
    for (size_t i = 0; i < shown_count; ++i)
        if (shown[i].text && strcmp(shown[i].text, label) == 0 &&
            shown[i].tap) {
            (void)shown[i].tap(&shown[i]);
            return;
        }
    fprintf(stderr, "missing touch label: %s\n", label);
    abort();
}

static void assert_screen_hex(const uint8_t bytes[32]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned row = 0; row < 4; ++row)
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t byte = bytes[row * 8 + i];
            assert(review_app.lines[row + 1][2 * i] == hex[byte >> 4]);
            assert(review_app.lines[row + 1][2 * i + 1] ==
                hex[byte & 15]);
        }
}

static void verify_review_result(void) {
    struct blake2b_ctx host_context;
    zcl_zip243_hasher host = zcl_zip243_host_hasher(&host_context);
    uint8_t expected[32];
    assert(zcl_zip243_shielded_digest(review_wire,
        sizeof review_wire, 0x76b809bb, &host, expected) == 0);
    assert(review_reply[108] == 0x90 && review_reply[109] == 0);
    assert(review_reply[8] == 1 && review_reply[12] == 1);
    assert(memcmp(review_reply + 44, expected, 32) == 0);
    zsha256_ctx sha;
    zsha256_init(&sha);
    zsha256_update(&sha, review_wire, sizeof review_wire);
    uint8_t commitment[32];
    zsha256_final(&sha, commitment);
    assert(memcmp(review_reply + 76, commitment, 32) == 0);
    assert(memcmp(review_app.transaction.digest, expected, 32) == 0);
    assert(strcmp(review_app.lines[0], "PUBLIC IN/OUT: 0/0") == 0);
    assert(strcmp(review_app.lines[4],
        "SHIELDED HIDDEN; NO SIGNING") == 0);
    if (review_runs == 1) {
        assert(!review_app.large_text && !review_app.dark);
        review_touch("NEXT / REFRESH");
        assert(strcmp(review_app.lines[0],
            "ZIP243 BRANCH 0x76B809BB") == 0);
        assert_screen_hex(expected);
        review_touch("NEXT / REFRESH");
        assert(strcmp(review_app.lines[0],
            "FULL WIRE SHA-256") == 0);
        assert_screen_hex(commitment);
        assert(strcmp(review_app.lines[5],
            "READ ONLY; NO SIGNING") == 0);
        review_touch("LARGER TEXT");
        assert(review_app.large_text && shown == review_ui_large);
        review_touch("DARK");
        assert(review_app.dark);
    } else {
        assert(review_app.large_text && review_app.dark);
        review_touch("NEXT DETAIL");
        assert(review_app.detail == 1);
        review_touch("STANDARD TEXT");
        review_touch("LIGHT");
        assert(!review_app.large_text && !review_app.dark);
    }
    review_touch("EXIT");
    assert(exits == review_runs);
}

static unsigned short exchange_review(unsigned char channel,
                                       unsigned short length) {
    if (channel == CHANNEL_APDU) return review_request(channel, length);
    assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX) && length >= 2);
    assert(!expect_revoked_reply || review_stage != 3);
    assert((displays > request_displays) == redraw_expected);
    assert(G_io_apdu_buffer[length - 2] == 0x90 &&
           G_io_apdu_buffer[length - 1] == 0);
    for (size_t i = length; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    if (length == sizeof review_reply) {
        memcpy(review_reply, G_io_apdu_buffer, length);
        assert(review_pass == 6 && review_stage == 3);
        ++review_runs;
        verify_review_result();
    }
    ++review_replies;
    return 0;
}

static unsigned short fault_request(unsigned short length) {
    assert(length == 0);
    if (fault_stage == 6) blue_throw(0x6f46);
    request_displays = displays;
    uint8_t *apdu = G_io_apdu_buffer;
    apdu[sizeof G_io_apdu_buffer - 2] = 0x5a;
    apdu[sizeof G_io_apdu_buffer - 1] = 0xa5;
    memcpy(apdu, (uint8_t[]){0xa5, 0x20, 0, 0, 8}, 5);
    if (fault_stage == 0 || fault_stage == 3 || fault_stage == 5) {
        for (unsigned i = 0; i < 4; ++i) {
            apdu[5 + i] =
                (uint8_t)(BLUE_SYNTHETIC_SAPLING_BYTES >> (8 * i));
            apdu[9 + i] = (uint8_t)(0x76b809bbu >> (8 * i));
        }
        ++fault_stage;
        redraw_expected = true;
        return 13;
    }
    apdu[1] = fault_stage == 2 ? 0x24 : 0x21;
    apdu[4] = fault_stage == 2 ? 0 : fault_stage == 4 ? 2 : 1;
    if (apdu[1] == 0x21) apdu[5] = review_wire[0];
    redraw_expected = apdu[1] == 0x24 || fault_stage == 4;
    ++fault_stage;
    return apdu[1] == 0x21 ? 6 : 5;
}

static unsigned short exchange_fault(unsigned char channel,
                                       unsigned short length) {
    if (channel == CHANNEL_APDU) return fault_request(length);
    assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
    assert((displays > request_displays) == redraw_expected);
    assert(fault_stage == fault_replies + 1);
    uint16_t status = fault_stage == 5 ? 0x6700 : 0x9000;
    assert(G_io_apdu_buffer[length - 2] == (uint8_t)(status >> 8) &&
           G_io_apdu_buffer[length - 1] == (uint8_t)status);
    for (size_t i = length; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    if (fault_stage == 3 || fault_stage == 5) {
        assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
        expect_erased(&review_app.transaction,
                      sizeof review_app.transaction);
    }
    ++fault_replies;
    return 0;
}
#endif

unsigned short io_exchange(unsigned char channel, unsigned short length) {
    ++exchange_calls;
#ifdef ZCL_BLUE_SHIELDED_REVIEW
    if (scripted_review) return exchange_review(channel, length);
    if (scripted_fault) return exchange_fault(channel, length);
#endif
    if (reset_during_send) return exchange_reset(channel, length);
    if (oversized_receive) return exchange_oversized(channel, length);
    if (fail_exchange_call) return exchange_failed(channel, length);
    abort();
}
void io_seproxyhal_spi_send(const unsigned char *bytes,
    unsigned short length) { (void)bytes; (void)length; }
unsigned short io_seproxyhal_spi_recv(unsigned char *bytes,
    unsigned short capacity, int flags) {
    (void)bytes;
    (void)capacity;
    (void)flags;
    abort();
}
void io_seproxyhal_display_default(bagl_element_t *element) {
    (void)element;
}
int io_seproxyhal_spi_is_status_sent(void) { return 1; }
void io_seproxyhal_general_status(void) { abort(); }
int cx_blake2b_init2(void *context, unsigned bits, const void *key,
    size_t key_length, const uint8_t *personal, size_t personal_length) {
#ifdef ZCL_BLUE_SHIELDED_REVIEW
    assert(bits == 256 && key_length == 0 && personal_length == 16);
    return blake2b_init_salt_personal(context, 32, key, key_length,
        NULL, personal) == 0 ? CX_BLAKE2B : 0;
#else
    (void)context; (void)bits; (void)key; (void)key_length;
    (void)personal; (void)personal_length;
    abort();
#endif
}
int cx_hash_sha256(const uint8_t *bytes, unsigned length,
    uint8_t digest[32]) {
    (void)bytes; (void)length; (void)digest;
    abort();
}
int cx_hash(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest, unsigned digest_length) {
#ifdef ZCL_BLUE_SHIELDED_REVIEW
    assert(context == &zip_context);
    if (mode == CX_LAST) {
        assert(digest && digest_length == 32);
        return blake2b_final(context, digest, 32) == 0 ? 32 : -1;
    }
    assert(!digest && digest_length == 0);
    return blake2b_update(context, bytes, length);
#else
    (void)context; (void)mode; (void)bytes; (void)length;
    (void)digest; (void)digest_length;
    abort();
#endif
}

static void expect_erased(const void *memory, size_t length) {
    const uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) assert(bytes[i] == 0);
}

#ifdef ZCL_BLUE_SHIELDED_REVIEW
static void test_complete_review_and_reconnect(void) {
    blue_sapling_fixture(review_wire);
    blue_review_app_reset(&review_app);
    review_app.large_text = review_app.dark = false;
    review_pass = 1;
    review_stage = review_replies = review_runs = 0;
    review_offset = 0;
    scripted_review = true;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f45 && review_runs == 2 &&
           review_replies == 98);
    blue_try_leave();
    scripted_review = false;
    expect_erased(&review_app.transaction,
                  sizeof review_app.transaction);
    expect_erased(&zip_context, sizeof zip_context);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

static void test_cancel_error_and_recovery(void) {
    blue_sapling_fixture(review_wire);
    blue_review_app_reset(&review_app);
    fault_stage = fault_replies = 0;
    scripted_fault = true;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f46 && fault_replies == 6);
    blue_try_leave();
    scripted_fault = false;
    assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
    expect_erased(&review_app.transaction,
                  sizeof review_app.transaction);
    expect_erased(&zip_context, sizeof zip_context);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

static void test_reset_during_final_redraw(uint8_t reason) {
    blue_sapling_fixture(review_wire);
    blue_review_app_reset(&review_app);
    review_pass = 1;
    review_stage = review_replies = review_runs = 0;
    review_offset = 0;
    injected_usb_reason = reason;
    scripted_review = reset_on_final_display = expect_revoked_reply = true;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f47 && review_runs == 0);
    blue_try_leave();
    scripted_review = expect_revoked_reply = false;
    assert(!reset_on_final_display);
    assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
    expect_erased(&review_app.transaction,
                  sizeof review_app.transaction);
    expect_erased(&zip_context, sizeof zip_context);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}
#endif

static void test_usb_cleanup(uint8_t reason, bool large) {
    blue_review_app_reset(&review_app);
    review_app.dark = large;
    review_app.large_text = large;
    memset(&review_app.transaction, 0x5a, sizeof review_app.transaction);
    memset(&zip_context, 0x5a, sizeof zip_context);
    memset(G_io_apdu_buffer, 0x5a, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = reason;
    unsigned before = displays;
    (void)io_event(CHANNEL_SPI);
    assert(displays == before + 1);
    assert(shown == (large ? review_ui_large : review_ui));
    assert(shown_count == (large ? sizeof review_ui_large /
        sizeof review_ui_large[0] : sizeof review_ui / sizeof review_ui[0]));
    assert(review_app.dark == large && review_app.large_text == large);
    assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
    expect_erased(&review_app.transaction, sizeof review_app.transaction);
    expect_erased(&zip_context, sizeof zip_context);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

static void test_failed_exchange(unsigned fail_at) {
    blue_review_app_reset(&review_app);
    fail_exchange_call = fail_at;
    exchange_calls = 0;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f42 && exchange_calls == fail_at);
    blue_try_leave();
    fail_exchange_call = 0;
    expect_erased(&review_app.transaction, sizeof review_app.transaction);
    expect_erased(&zip_context, sizeof zip_context);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

static void test_oversized_receive(void) {
    blue_review_app_reset(&review_app);
    oversized_receive = true;
    exchange_calls = 0;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f43 && exchange_calls == 2);
    blue_try_leave();
    oversized_receive = false;
    expect_erased(&review_app.transaction, sizeof review_app.transaction);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

static void test_reset_during_send(void) {
    blue_review_app_reset(&review_app);
    reset_during_send = true;
    exchange_calls = 0;
    blue_try_context outer = {0};
    blue_try_enter(&outer);
    if (setjmp(outer.jump) == 0) {
        answer_command();
        abort();
    }
    assert(outer.code == 0x6f44 && exchange_calls == 3);
    blue_try_leave();
    reset_during_send = false;
    assert(strcmp(review_app.lines[0], "CONNECT Z23") == 0);
    expect_erased(&review_app.transaction, sizeof review_app.transaction);
    expect_erased(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
}

int main(void) {
    test_usb_cleanup(SEPROXYHAL_TAG_USB_EVENT_RESET, false);
    test_usb_cleanup(SEPROXYHAL_TAG_USB_EVENT_SUSPENDED, true);
    test_failed_exchange(2);
    test_failed_exchange(3);
    test_oversized_receive();
    test_reset_during_send();
#ifdef ZCL_BLUE_SHIELDED_REVIEW
    test_complete_review_and_reconnect();
    test_cancel_error_and_recovery();
    test_reset_during_final_redraw(SEPROXYHAL_TAG_USB_EVENT_RESET);
    test_reset_during_final_redraw(SEPROXYHAL_TAG_USB_EVENT_SUSPENDED);
#endif
    return 0;
}
