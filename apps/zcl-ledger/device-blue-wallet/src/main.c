/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "os_io_seproxyhal.h"
#include "blue_wallet_layout.h"
#include "blue_wallet_protocol.h"
#include "blue_wallet_receive.h"
#include "wallet_payment_device.h"
#include "blue_wallet_signer_device.h"
#include "zcl_base58.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define __ASM __asm
#define __STATIC_INLINE static inline
#include "core_cmFunc.h"
#undef __STATIC_INLINE
#undef __ASM

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Ledger Blue wallet requires ISO C23"
#endif

#ifndef HAVE_BOLOS_APP_STACK_CANARY
#error "The Ledger Blue wallet requires the SDK stack canary"
#endif

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t ux;

static blue_wallet_state wallet_state;
static char receive_address[ZCL_WALLET_ADDRESS_CHARS + 1];
static char address_lines[ZCL_WALLET_ADDRESS_LINES][ZCL_WALLET_ADDRESS_LINE_SIZE];

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static void clear_app_account(void) {
    wallet_payment_revoke_account();
    wallet_payment_boot_clear();
    blue_wallet_signer_wipe();
    wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
    wipe(&wallet_state, sizeof wallet_state);
    wipe(receive_address, sizeof receive_address);
    wipe(address_lines, sizeof address_lines);
}

void blue_wallet_close(void) {
    clear_app_account();
    os_sched_exit(0);
}

static const bagl_element_t *exit_app(const bagl_element_t *element) {
    (void)element;
    blue_wallet_close();
    return NULL;
}

static unsigned int receive_ui_button(unsigned int mask, unsigned int count) {
    (void)mask;
    (void)count;
    return 0;
}

static unsigned int error_ui_button(unsigned int mask, unsigned int count) {
    return receive_ui_button(mask, count);
}

static unsigned int locked_ui_button(unsigned int mask, unsigned int count) {
    return receive_ui_button(mask, count);
}

#define BODY ZCL_WALLET_COLOR_BODY
#define TEXT ZCL_WALLET_COLOR_TEXT
#define ACCENT ZCL_WALLET_COLOR_ACCENT
#define ADDRESS_LINE(top, value) { \
    .component = { \
        .type = BAGL_LABEL, .x = 20, .y = (top), .width = 280, \
        .height = 32, .fgcolor = TEXT, .bgcolor = BODY, \
        .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | \
                   BAGL_FONT_ALIGNMENT_CENTER \
    }, .text = (value) \
}
#define EXIT_BUTTON { \
    .component = { \
        .type = BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, \
        .x = 40, .y = ZCL_WALLET_EXIT_Y, .width = 240, .height = 48, \
        .radius = 6, .fill = BAGL_FILL, \
        .fgcolor = ACCENT, .bgcolor = BODY, \
        .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px | \
                   BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE \
    }, .text = "EXIT", .tap = exit_app \
}

static const bagl_element_t receive_ui[] = {
    {
        .component = {
            .type = BAGL_RECTANGLE, .x = 0, .y = 0,
            .width = ZCL_WALLET_SCREEN_WIDTH,
            .height = ZCL_WALLET_SCREEN_HEIGHT, .fill = BAGL_FILL,
            .fgcolor = BODY, .bgcolor = BODY
        }
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = ZCL_WALLET_TITLE_Y,
            .width = 280, .height = 30,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16_22PX |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "RECEIVE ZCL"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = ZCL_WALLET_PATH_Y,
            .width = 280, .height = 25,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "m/44'/147'/0'/0/0"
    },
    ADDRESS_LINE(ZCL_WALLET_ADDRESS_1_Y, address_lines[0]),
    ADDRESS_LINE(ZCL_WALLET_ADDRESS_2_Y, address_lines[1]),
    ADDRESS_LINE(ZCL_WALLET_ADDRESS_3_Y, address_lines[2]),
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = ZCL_WALLET_INSTRUCTION_Y,
            .width = 280, .height = 25,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "MATCH ALL 35 CHARACTERS"
    },
    EXIT_BUTTON
};

static const bagl_element_t error_ui[] = {
    {
        .component = {
            .type = BAGL_RECTANGLE, .x = 0, .y = 0,
            .width = ZCL_WALLET_SCREEN_WIDTH,
            .height = ZCL_WALLET_SCREEN_HEIGHT, .fill = BAGL_FILL,
            .fgcolor = BODY, .bgcolor = BODY
        }
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 135,
            .width = 280, .height = 40,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16_22PX |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "ADDRESS UNAVAILABLE"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 195,
            .width = 280, .height = 25,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "EXIT; CHECK DEVICE"
    },
    EXIT_BUTTON
};

static const bagl_element_t locked_ui[] = {
    {
        .component = {
            .type = BAGL_RECTANGLE, .x = 0, .y = 0,
            .width = ZCL_WALLET_SCREEN_WIDTH,
            .height = ZCL_WALLET_SCREEN_HEIGHT, .fill = BAGL_FILL,
            .fgcolor = BODY, .bgcolor = BODY
        }
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 135,
            .width = 280, .height = 40,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16_22PX |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "DEVICE LOCKED"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 195,
            .width = 280, .height = 25,
            .fgcolor = TEXT, .bgcolor = BODY,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "UNLOCK THEN REOPEN"
    },
    EXIT_BUTTON
};

#undef ADDRESS_LINE
#undef EXIT_BUTTON
#undef BODY
#undef TEXT
#undef ACCENT

static void display_idle(void) {
    bool pin_valid = os_global_pin_is_validated();
    if (!pin_valid && wallet_payment_account_ready())
        wallet_payment_revoke_account();
    if (wallet_state.address_ready && !wallet_payment_account_ready()) {
        wipe(wallet_state.public_key, sizeof wallet_state.public_key);
        wipe(receive_address, sizeof receive_address);
        wipe(address_lines, sizeof address_lines);
    }
    if (!pin_valid ||
        (wallet_state.address_ready && !wallet_payment_account_ready())) {
        UX_DISPLAY(locked_ui, NULL);
    } else if (wallet_state.address_ready) {
        UX_DISPLAY(receive_ui, NULL);
    } else {
        UX_DISPLAY(error_ui, NULL);
    }
}

static void handle_finger_event(void) {
    if (wallet_payment_finger_allowed(G_io_seproxyhal_spi_buffer))
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
    if (wallet_state.address_ready && !wallet_payment_account_ready())
        display_idle();
}

static bool session_locked(void) {
    return !os_global_pin_is_validated() ||
           (wallet_state.address_ready && !wallet_payment_account_ready());
}

static bool idle_lock_detected(void) {
    return wallet_state.address_ready && wallet_payment_account_ready() &&
           !os_global_pin_is_validated();
}

static bool command_locked(unsigned int received) {
    return session_locked() &&
           (received < 2 || G_io_apdu_buffer[1] != 0x01);
}

static void scrub_command_reply(volatile uint16_t *status, size_t *length,
                                volatile bool *redraw_receive) {
    const size_t capacity = sizeof G_io_apdu_buffer - 2;
    if (*length > capacity) {
        wallet_payment_abort();
        *redraw_receive = true;
    }
    if (*status != 0x9000 || *length > capacity) {
        if (*status == 0x9000) *status = 0x6f00;
        *length = 0;
        wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
    } else {
        wipe(G_io_apdu_buffer + *length,
             sizeof G_io_apdu_buffer - *length);
    }
}

static void handle_command(unsigned int received, volatile uint16_t *status,
                           size_t *length, volatile bool *redraw_receive) {
    bool identity_request = received >= 2 &&
        received <= sizeof G_io_apdu_buffer &&
        G_io_apdu_buffer[1] == 0x01;
    if (received > sizeof G_io_apdu_buffer) {
        wallet_payment_abort();
        *redraw_receive = true;
        *status = 0x6700;
    } else if (command_locked(received)) {
        wallet_payment_abort();
        wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
        *status = 0x6985;
    } else if (received >= 2 && G_io_apdu_buffer[1] >= 0x20) {
        *status = wallet_payment_command(G_io_apdu_buffer, received,
            G_io_apdu_buffer, sizeof G_io_apdu_buffer - 2, length);
        if (*status != 0x9000 && wallet_state.address_ready)
            *redraw_receive = true;
    } else {
        bool was_visible = wallet_payment_visible();
        if (was_visible) wallet_payment_abort();
        *status = blue_wallet_handle(&wallet_state, G_io_apdu_buffer,
            received, G_io_apdu_buffer, sizeof G_io_apdu_buffer - 2,
            length);
        if (was_visible) *redraw_receive = true;
    }
    if (session_locked()) {
        if (wallet_payment_account_ready()) wallet_payment_revoke_account();
        *redraw_receive = true;
        if (!identity_request) {
            wallet_payment_abort();
            wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
            *length = 0;
            *status = 0x6985;
        }
    }
    scrub_command_reply(status, length, redraw_receive);
}

static bool derive_public_key(unsigned int chain, uint8_t compressed[33]) {
    const unsigned int path[] = {
        0x8000002c, 0x80000093, 0x80000000, chain, 0
    };
    if (!compressed || chain > 1 || !os_global_pin_is_validated()) return false;
    wallet_boot_material *material = wallet_payment_boot_material();
    os_perso_derive_node_bip32(CX_CURVE_256K1, path, 5,
                                material->raw, material->chain);
    int initialized = cx_ecfp_init_private_key(CX_CURVE_256K1, material->raw, 32,
                                   &material->key);
    wipe(material->raw, sizeof material->raw);
    wipe(material->chain, sizeof material->chain);
    if (initialized < 0 || material->key.curve != CX_CURVE_256K1 ||
        material->key.d_len != 32) {
        wallet_payment_boot_clear();
        return false;
    }
    int generated = cx_ecfp_generate_pair(CX_CURVE_256K1,
                                           &material->public_key,
                                           &material->key, 1);
    wipe(&material->key, sizeof material->key);
    if (generated != 0 || !os_global_pin_is_validated() ||
        material->public_key.W_len != 65 ||
        material->public_key.W[0] != 4) {
        wallet_payment_boot_clear();
        return false;
    }
    compressed[0] = (uint8_t)(2u | (material->public_key.W[64] & 1u));
    memcpy(compressed + 1, material->public_key.W + 1, 32);
    wallet_payment_boot_clear();
    return true;
}

bool blue_wallet_public_hash160(const uint8_t compressed[33],
    uint8_t hash160[20]) {
    uint8_t digest[32];
    cx_ripemd160_t ripemd;
    return cx_hash_sha256(compressed, 33, digest) == 32 &&
        cx_ripemd160_init(&ripemd) == CX_RIPEMD160 &&
        cx_hash(&ripemd.header, CX_LAST, digest, sizeof digest,
                hash160) == 20;
}

static bool format_receive_address(void) {
    uint8_t digest[32], checksum[32], payload[26];
    if (!blue_wallet_public_hash160(wallet_state.public_key,
            payload + 2)) return false;
    payload[0] = 0x1c;
    payload[1] = 0xb8;
    if (cx_hash_sha256(payload, 22, digest) != 32 ||
        cx_hash_sha256(digest, sizeof digest, checksum) != 32) return false;
    memcpy(payload + 22, checksum, 4);
    if (zcl_base58_encode(payload, sizeof payload, receive_address,
                           sizeof receive_address) < 0 ||
        !blue_wallet_receive_split(receive_address, address_lines)) return false;
    uint8_t internal_public[33], internal_hash160[20];
    bool valid = derive_public_key(1, internal_public) &&
        blue_wallet_public_hash160(internal_public, internal_hash160);
    wipe(internal_public, sizeof internal_public);
    if (!valid || !os_global_pin_is_validated()) return false;
    wallet_payment_set_account_hashes(payload + 2, internal_hash160);
    wipe(internal_hash160, sizeof internal_hash160);
    return true;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    if ((channel & ~IO_FLAGS) != CHANNEL_SPI) THROW(INVALID_PARAMETER);
    if (tx_len) {
        io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
        return 0;
    }
    return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                 sizeof G_io_apdu_buffer, 0);
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

static void handle_usb_interrupt(void) {
    if (G_io_seproxyhal_spi_buffer[3] != SEPROXYHAL_TAG_USB_EVENT_RESET &&
        G_io_seproxyhal_spi_buffer[3] !=
            SEPROXYHAL_TAG_USB_EVENT_SUSPENDED) return;
    bool was_visible = wallet_payment_visible();
    wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
    if (!was_visible && !wallet_payment_account_ready()) return;
    bool cleared = wallet_payment_interrupt();
    if (cleared) blue_wallet_signer_wipe();
    if (was_visible && cleared) display_idle();
}

static void handle_ticker(void) {
    bool timed_out = wallet_payment_timeout();
    bool locked = idle_lock_detected();
    if (!timed_out && !locked) return;
    wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
    bool cleared = !locked || wallet_payment_interrupt();
    if (cleared) {
        blue_wallet_signer_wipe();
        display_idle();
    }
}

unsigned char io_event(unsigned char channel) {
    (void)channel;
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_USB_EVENT:
        handle_usb_interrupt();
        break;
    case SEPROXYHAL_TAG_FINGER_EVENT:
        handle_finger_event();
        break;
    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;
    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (!UX_DISPLAYED()) UX_DISPLAYED_EVENT();
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, handle_ticker(););
        break;
    default:
        break;
    }
    if (!io_seproxyhal_spi_is_status_sent()) io_seproxyhal_general_status();
    return 1;
}

static void answer_command(void) {
    volatile unsigned int received = 0, sent = 0;
    volatile bool redraw_receive = false;
    for (;;) {
        if (sent) {
            (void)io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, sent);
            sent = 0;
            if (redraw_receive) {
                display_idle();
                redraw_receive = false;
            } else if (wallet_payment_visible()) {
                wallet_payment_display();
            }
        }
        volatile uint16_t status = 0x6f00;
        BEGIN_TRY {
            TRY {
                received = 0;
                received = io_exchange(CHANNEL_APDU, 0);
                size_t length = 0;
                handle_command(received, &status, &length, &redraw_receive);
                sent = length;
            }
            CATCH_OTHER(error) {
                if (!received) {
                    wallet_payment_abort();
                    blue_wallet_signer_wipe();
                    wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
                    CLOSE_TRY;
                    THROW(error);
                }
                wipe(G_io_apdu_buffer, sizeof G_io_apdu_buffer);
                status = (error & 0xf000) == 0x6000 ||
                         (error & 0xf000) == 0x9000
                             ? error : (0x6800 | (error & 0x07ff));
                sent = 0;
                wallet_payment_abort();
                redraw_receive = true;
            }
            FINALLY {
                blue_wallet_signer_wipe();
            }
        }
        END_TRY;
        G_io_apdu_buffer[sent++] = (uint8_t)(status >> 8);
        G_io_apdu_buffer[sent++] = (uint8_t)status;
    }
}

__attribute__((section(".boot"))) int main(void) {
    __enable_irq();
    os_boot();
    UX_INIT();
    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();
            USB_power(0);
            USB_power(1);
            /* Restart reuses this SRAM. Drop any earlier approval first. */
            wallet_payment_boot_reset();
            wallet_state.address_ready =
                derive_public_key(0, wallet_state.public_key) &&
                                         format_receive_address();
            if (!wallet_state.address_ready) {
                wipe(wallet_state.public_key, sizeof wallet_state.public_key);
                wipe(receive_address, sizeof receive_address);
                wipe(address_lines, sizeof address_lines);
            }
            display_idle();
            answer_command();
        }
        CATCH_OTHER(error) { (void)error; }
        FINALLY {
            clear_app_account();
        }
    }
    END_TRY;
    return 0;
}
