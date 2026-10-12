/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_TEST_UX_H
#define ZCL_BLUE_WALLET_TEST_UX_H

#include "os.h"

#define SEPROXYHAL_TAG_FINGER_EVENT_TOUCH 1
#define SEPROXYHAL_TAG_FINGER_EVENT_RELEASE 2

void blue_wallet_test_display(const bagl_element_t *elements, size_t count,
    unsigned int (*button)(unsigned int, unsigned int));
extern unsigned blue_wallet_test_tick_ms;
void blue_wallet_test_set_interval(unsigned ms);

#define UX_CALLBACK_SET_INTERVAL(ms) \
    blue_wallet_test_set_interval(ms)

/* Match the SDK macro's multiple statements so conditional callers need braces. */
#define UX_DISPLAY(elements_array, preprocessor) \
    blue_wallet_test_display((elements_array), \
        sizeof(elements_array) / sizeof((elements_array)[0]), \
        elements_array##_button); \
    (void)(preprocessor)

#endif
