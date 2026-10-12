/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_STARTUP_UX_H
#define ZCL_BLUE_WALLET_STARTUP_UX_H

#include "../blue_wallet_sdk_stub/os_io_seproxyhal.h"

enum {
    SEPROXYHAL_TAG_USB_EVENT = 1,
    SEPROXYHAL_TAG_USB_EVENT_RESET = 2,
    SEPROXYHAL_TAG_USB_EVENT_SUSPENDED = 3,
    SEPROXYHAL_TAG_FINGER_EVENT = 4,
    SEPROXYHAL_TAG_BUTTON_PUSH_EVENT = 5,
    SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT = 6,
    SEPROXYHAL_TAG_TICKER_EVENT = 7
};

void io_seproxyhal_init(void);
void USB_power(int enabled);
void io_seproxyhal_spi_send(const unsigned char *bytes, unsigned short length);
unsigned short io_seproxyhal_spi_recv(unsigned char *bytes,
    unsigned short capacity, int flags);
void io_seproxyhal_display_default(bagl_element_t *element);
int io_seproxyhal_spi_is_status_sent(void);
void io_seproxyhal_general_status(void);
void blue_wallet_test_finger(const unsigned char *buffer);

#define UX_INIT() ((void)0)
#define UX_FINGER_EVENT(buffer) blue_wallet_test_finger(buffer)
#define UX_BUTTON_PUSH_EVENT(buffer) ((void)(buffer))
#define UX_DISPLAYED() 1
#define UX_DISPLAYED_EVENT() ((void)0)
#define UX_TICKER_EVENT(buffer, code) do { (void)(buffer); code } while (0)

#endif
