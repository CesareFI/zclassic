/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zsha256/zsha256.h"
#include "zripemd/zripemd.h"
#include "os.h"
#include "os_io_seproxyhal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define main blue_wallet_device_main
#include "../device-blue-wallet/src/main.c"
#undef main

extern uint8_t _sdata, _edata, _sidata, _sbss, _ebss;
extern uint8_t _stack_bottom, _stack_top;
extern void _exit(int status);
extern void initialise_monitor_handles(void);
void blue_wallet_reset(void);

__attribute__((used, section(".vectors")))
const uintptr_t blue_wallet_m0_vectors[2] = {
    (uintptr_t)&_stack_top, (uintptr_t)blue_wallet_reset
};

unsigned char G_io_apdu_buffer[260];
unsigned blue_wallet_test_tick_ms;
static blue_try_context *active_try;
static wallet_boot_material boot_material;
static const bagl_element_t *shown;
static size_t shown_count;
static bool account_ready, account_initialized, ready_before_exit;
static bool exited, failed, outside_rejected;
static bool reset_restored, suspend_restored, payment_visible;
static unsigned request_step, replies_valid, derivations, wipes;
static unsigned payment_displays, payment_aborts;
static const bagl_element_t payment_ui[1];

static void test_text(const char *message) {
    (void)write(1, message, strlen(message));
}

static void test_hex16(unsigned value) {
    static const char digits[] = "0123456789abcdef";
    char output[4];
    for (int shift = 12; shift >= 0; shift -= 4) {
        output[(12 - shift) / 4] = digits[(value >> shift) & 15u];
    }
    (void)write(1, output, sizeof output);
}

void blue_try_enter(blue_try_context *context) {
    context->code = 0;
    context->previous = active_try;
    active_try = context;
}

void blue_try_leave(void) {
    if (!active_try) { failed = true; return; }
    active_try = active_try->previous;
}

blue_try_context *blue_try_current(void) { return active_try; }

void blue_throw(unsigned error) {
    if (!active_try || !error) _exit(1);
    active_try->code = error;
    longjmp(active_try->jump, 1);
}

void blue_wallet_test_display(const bagl_element_t *elements, size_t count,
    unsigned int (*button)(unsigned int, unsigned int)) {
    if (!button || button(0, 0) != 0) failed = true;
    shown = elements;
    shown_count = count;
}

void blue_wallet_test_finger(const unsigned char *buffer) {
    if (!buffer || buffer[0] != SEPROXYHAL_TAG_FINGER_EVENT) {
        failed = true;
        return;
    }
    if (buffer[3] != SEPROXYHAL_TAG_FINGER_EVENT_RELEASE) return;
    unsigned x = ((unsigned)buffer[4] << 8) | buffer[5];
    unsigned y = ((unsigned)buffer[6] << 8) | buffer[7];
    for (size_t i = 0; i < shown_count; ++i) {
        const bagl_element_t *element = &shown[i];
        if ((element->component.type & BAGL_FLAG_TOUCHABLE) &&
            element->tap &&
            x >= (unsigned)element->component.x &&
            x < (unsigned)(element->component.x + element->component.width) &&
            y >= (unsigned)element->component.y &&
            y < (unsigned)(element->component.y + element->component.height)) {
            if (!element->text || strcmp(element->text, "EXIT") != 0)
                failed = true;
            (void)shown[i].tap(&shown[i]);
            return;
        }
    }
}

static void finger_release(unsigned x, unsigned y) {
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_FINGER_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_FINGER_EVENT_RELEASE;
    G_io_seproxyhal_spi_buffer[4] = (uint8_t)(x >> 8);
    G_io_seproxyhal_spi_buffer[5] = (uint8_t)x;
    G_io_seproxyhal_spi_buffer[6] = (uint8_t)(y >> 8);
    G_io_seproxyhal_spi_buffer[7] = (uint8_t)y;
    (void)io_event(CHANNEL_SPI);
}

wallet_boot_material *wallet_payment_boot_material(void) {
    return &boot_material;
}

void wallet_payment_boot_clear(void) {
    volatile uint8_t *bytes = (volatile uint8_t *)&boot_material;
    for (size_t i = 0; i < sizeof boot_material; ++i) bytes[i] = 0;
}

void wallet_payment_set_account_hashes(const uint8_t external[20],
    const uint8_t internal[20]) {
    if (!external || !internal) failed = true;
    account_ready = true;
    account_initialized = true;
}

bool wallet_payment_account_ready(void) { return account_ready; }

void wallet_payment_revoke_account(void) {
    wallet_payment_abort();
    account_ready = false;
}

void wallet_payment_boot_reset(void) {
    wallet_payment_revoke_account();
}

void wallet_payment_abort(void) {
    if (payment_visible) ++payment_aborts;
    payment_visible = false;
}
bool wallet_payment_interrupt(void) {
    wallet_payment_abort();
    return true;
}
void wallet_payment_display(void) {
    if (!payment_visible) failed = true;
    shown = payment_ui;
    shown_count = 1;
    ++payment_displays;
}
bool wallet_payment_visible(void) { return payment_visible; }
bool wallet_payment_finger_allowed(const unsigned char *event) {
    return event != NULL;
}
bool wallet_payment_timeout(void) { return false; }
uint16_t wallet_payment_command(const uint8_t *apdu, size_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    (void)reply; (void)capacity;
    *reply_length = 0;
    if (!apdu || length != 5 || apdu[1] != 0x20 || payment_visible) {
        failed = true;
        return 0x6985;
    }
    payment_visible = true;
    return 0x9000;
}
void blue_wallet_signer_wipe(void) { ++wipes; }

int os_global_pin_is_validated(void) { return 1; }

void os_perso_derive_node_bip32(unsigned curve, const unsigned *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    if (curve != CX_CURVE_256K1 || length != 5 ||
        path[0] != 0x8000002c || path[1] != 0x80000093 ||
        path[2] != 0x80000000 || path[3] > 1 || path[4] != 0)
        failed = true;
    ++derivations;
    memset(raw, path[3] ? 0x22 : 0x11, 32);
    memset(chain, path[3] ? 0x44 : 0x33, 32);
}

int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key) {
    key->curve = curve;
    key->d_len = length;
    memcpy(key->d, raw, 32);
    return 0;
}

int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate) {
    if (curve != CX_CURVE_256K1 || keepprivate != 1) failed = true;
    public_key->curve = curve;
    public_key->W_len = 65;
    public_key->W[0] = 4;
    memcpy(public_key->W + 1, private_key->d, 32);
    memset(public_key->W + 33, private_key->d[0] + 1, 32);
    return 0;
}

int cx_hash_sha256(const uint8_t *bytes, unsigned length, uint8_t digest[32]) {
    zsha256(bytes, length, digest);
    return 32;
}

int cx_ripemd160_init(cx_ripemd160_t *context) {
    context->header = CX_RIPEMD160;
    return CX_RIPEMD160;
}

int cx_hash5(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest) {
    if (((cx_ripemd160_t *)context)->header != CX_RIPEMD160 ||
        mode != CX_LAST) failed = true;
    zripemd160(bytes, length, digest);
    return 20;
}

void os_boot(void) {}
void io_seproxyhal_init(void) {}
void USB_power(int enabled) { if (enabled != 0 && enabled != 1) failed = true; }
void os_sched_exit(unsigned code) { if (code != 0) failed = true; exited = true; }

static bool reply_matches(unsigned short length) {
    if (request_step == 1)
        return length == 7 &&
            blue_wallet_identity_matches(G_io_apdu_buffer, length);
    if (request_step == 2)
        return length == 35 &&
            memcmp(G_io_apdu_buffer, wallet_state.public_key, 33) == 0 &&
            G_io_apdu_buffer[33] == 0x90 && G_io_apdu_buffer[34] == 0;
    return (request_step == 3 || request_step == 4) && length == 2 &&
        G_io_apdu_buffer[0] == 0x90 && G_io_apdu_buffer[1] == 0;
}

static bool address_lines_match(void);

static unsigned short receive_request(void) {
    if (request_step++ == 0) {
        const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
        memcpy(G_io_apdu_buffer, identity, sizeof identity);
        return sizeof identity;
    }
    if (request_step == 2) {
        const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
        memcpy(G_io_apdu_buffer, address, sizeof address);
        return sizeof address;
    }
    if (request_step == 3 || request_step == 4) {
        if (request_step == 4) {
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
            G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
            (void)io_event(CHANNEL_SPI);
            reset_restored = !payment_visible && shown == receive_ui;
        }
        const uint8_t payment[] = {0xa5, 0x20, 0, 0, 0};
        memcpy(G_io_apdu_buffer, payment, sizeof payment);
        return sizeof payment;
    }
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_SUSPENDED;
    (void)io_event(CHANNEL_SPI);
    suspend_restored = !payment_visible && shown == receive_ui;
    ready_before_exit = account_ready && wallet_state.address_ready &&
        strlen(receive_address) == ZCL_WALLET_ADDRESS_CHARS &&
        address_lines_match();
    finger_release(0, 0);
    outside_rejected = !exited;
    finger_release(160, ZCL_WALLET_EXIT_Y + 24);
    blue_throw(0x6812);
}

unsigned short io_exchange(unsigned char channel, unsigned short tx_length) {
    if (tx_length) {
        if (channel != (CHANNEL_APDU | IO_RETURN_AFTER_TX) ||
            !reply_matches(tx_length)) failed = true;
        else ++replies_valid;
        return 0;
    }
    if (channel != CHANNEL_APDU) failed = true;
    return receive_request();
}

void io_seproxyhal_spi_send(const unsigned char *bytes,
    unsigned short length) { (void)bytes; (void)length; failed = true; }
unsigned short io_seproxyhal_spi_recv(unsigned char *bytes,
    unsigned short capacity, int flags) {
    (void)bytes; (void)capacity; (void)flags; failed = true; return 0;
}
void io_seproxyhal_display_default(bagl_element_t *element) {
    (void)element; failed = true;
}
int io_seproxyhal_spi_is_status_sent(void) { return 1; }
void io_seproxyhal_general_status(void) { failed = true; }

static bool address_lines_match(void) {
    size_t cursor = 0;
    for (size_t line = 0; line < ZCL_WALLET_ADDRESS_LINES; ++line) {
        size_t i = 0;
        for (; i < ZCL_WALLET_ADDRESS_LINE_SIZE &&
               address_lines[line][i]; ++i) {
            if (cursor >= ZCL_WALLET_ADDRESS_CHARS ||
                address_lines[line][i] != receive_address[cursor++])
                return false;
        }
        if (i == ZCL_WALLET_ADDRESS_LINE_SIZE) return false;
    }
    return cursor == ZCL_WALLET_ADDRESS_CHARS;
}

static void reset_ram(void) {
    uint8_t *source = &_sidata;
    for (volatile uint8_t *target = &_sdata; target < &_edata; ++target)
        *target = *source++;
    for (volatile uint8_t *target = &_sbss; target < &_ebss; ++target)
        *target = 0;
}

static unsigned stack_used(const volatile uint8_t *guard) {
    unsigned lowest = 1536;
    for (unsigned i = 0; i < 1536; ++i)
        if (guard[i] != 0xa5u) { lowest = i; break; }
    return lowest == 1536 ? 512 : 2048u - lowest;
}

static bool boot_material_clear(void) {
    const uint8_t *bytes = (const uint8_t *)&boot_material;
    for (size_t i = 0; i < sizeof boot_material; ++i)
        if (bytes[i]) return false;
    return true;
}

static bool wallet_flow_valid(void) {
    return replies_valid == 4 && account_initialized &&
        ready_before_exit && !account_ready && outside_rejected &&
        reset_restored && suspend_restored && payment_aborts == 2 &&
        payment_displays == 2 && derivations == 2 && wipes >= 2;
}

static bool wallet_run_valid(int result, unsigned used) {
    bool account_cleared = !wallet_state.address_ready &&
        !receive_address[0];
    for (size_t i = 0; i < sizeof wallet_state.public_key; ++i)
        if (wallet_state.public_key[i]) account_cleared = false;
    for (size_t i = 0; i < sizeof address_lines; ++i)
        if (((const uint8_t *)address_lines)[i]) account_cleared = false;
    return result == 0 && !failed && !active_try && exited &&
        wallet_flow_valid() && shown == receive_ui && account_cleared &&
        boot_material_clear() && used <= 1536;
}

void blue_wallet_reset(void) {
    reset_ram();
    initialise_monitor_handles();
    volatile uint8_t *guard = &_stack_bottom;
    volatile uint8_t marker = 0;
    if ((uintptr_t)&marker <= (uintptr_t)guard + 1568u) {
        test_text("M0 WALLET STACK SETUP FAIL\n");
        _exit(1);
    }
    for (unsigned i = 0; i < 1536; ++i) guard[i] = 0xa5u;
    int result = blue_wallet_device_main();
    unsigned used = stack_used(guard);
    bool valid = wallet_run_valid(result, used);
    test_text("M0 WALLET STACK 0x");
    test_hex16(used);
    test_text(valid ? "\nM0 WALLET PASS\n" : "\nM0 WALLET FAIL\n");
    _exit(valid ? 0 : 1);
}
