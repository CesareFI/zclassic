/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_cm.h"
#include "base/log_level.h"

#include <stdint.h>
#include <string.h>
#ifdef BLUE_QEMU_M0
#include <unistd.h>
#define CM_MODEL "CM-M0"
#else
#define CM_MODEL "CM-M3"
#endif

extern uint8_t _sdata, _edata, _sidata, _sbss, _ebss;
extern uint8_t _stack_bottom, _stack_top;
extern void _exit(int status);
#ifdef BLUE_QEMU_M0
extern void initialise_monitor_handles(void);
#endif
void blue_m3_reset(void);

[[gnu::used, gnu::section(".vectors")]]
const uintptr_t blue_cm_vectors[2] = {
    (uintptr_t)&_stack_top, (uintptr_t)blue_m3_reset
};

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_OFF; }

void memory_cleanse(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static void report(const char *message) {
#ifdef BLUE_QEMU_M0
    (void)write(1, message, strlen(message));
#else
    volatile uint32_t *const uart = (volatile uint32_t *)0x40004000u;
    uart[4] = 16u;
    uart[2] = 1u;
    while (*message) {
        while (uart[1] & 1u) {}
        uart[0] = (uint8_t)*message++;
    }
#endif
}

static void report_stack(unsigned used) {
    static const char digits[] = "0123456789abcdef";
    char value[5];
    for (unsigned i = 0; i < 4; ++i)
        value[i] = digits[(used >> (12 - 4 * i)) & 15u];
    value[4] = 0;
    report(CM_MODEL " STACK 0x");
    report(value);
    report("\n");
}

static unsigned hex_digit(char character) {
    if (character >= '0' && character <= '9')
        return (unsigned)(character - '0');
    if (character >= 'a' && character <= 'f')
        return (unsigned)(character - 'a') + 10u;
    return 16;
}

static bool parse_hex(uint8_t *bytes, size_t length, const char *hex) {
    for (size_t i = 0; i < length; ++i) {
        unsigned high = hex_digit(hex[2 * i]);
        unsigned low = hex_digit(hex[2 * i + 1]);
        if (high >= 16 || low >= 16) return false;
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    return hex[2 * length] == 0;
}

static blue_sapling_cm_workspace workspace;
static uint8_t note[564];

static bool check_fixture(void) {
    static const char note_hex[] =
        "019cf4941906e9f1951a9199f0b9f50500000000641056f7c54fdd6d"
        "5ad028ad54d98cb18aa0f737b22f44d0663c16a276043501";
    static const char pkd_hex[] =
        "25d4fed2b7ef105caae1f69f11626d7ac79a51a69fc20163"
        "b48668d70fd10f3a";
    static const char cm_hex[] =
        "b87c248004b3dfa9da8ec12fad3cad21f93ed039a2421de3"
        "d5f5b09e6654e765";
    uint8_t pk_d[32], cm[32];
    if (!parse_hex(note, 52, note_hex) ||
        !parse_hex(pk_d, sizeof pk_d, pkd_hex) ||
        !parse_hex(cm, sizeof cm, cm_hex)) return false;
    note[52] = 0xf6;
    if (!blue_sapling_cm_matches(note, pk_d, cm, &workspace))
        return false;
    cm[0] ^= 1u;
    if (blue_sapling_cm_matches(note, pk_d, cm, &workspace)) return false;
    cm[0] ^= 1u;
    note[12] ^= 1u;
    if (blue_sapling_cm_matches(note, pk_d, cm, &workspace)) return false;
    note[12] ^= 1u;
    note[52] ^= 1u;
    if (!blue_sapling_cm_matches(note, pk_d, cm, &workspace))
        return false;
    const uint8_t *scratch = (const uint8_t *)&workspace;
    for (size_t i = 0; i < sizeof workspace; ++i)
        if (scratch[i]) return false;
    return true;
}

void blue_m3_reset(void) {
    uint8_t *source = &_sidata;
    for (volatile uint8_t *target = &_sdata; target < &_edata; ++target)
        *target = *source++;
    for (volatile uint8_t *target = &_sbss; target < &_ebss; ++target)
        *target = 0;
#ifdef BLUE_QEMU_M0
    initialise_monitor_handles();
#endif
    volatile uint8_t *guard = &_stack_bottom;
    volatile uint8_t marker = 0;
    bool passed = (uintptr_t)&marker > (uintptr_t)guard + 1568u;
    if (passed) {
        for (unsigned i = 0; i < 1536; ++i) guard[i] = 0xa5u;
        passed = check_fixture();
        unsigned lowest = 1536;
        for (unsigned i = 0; i < 1536; ++i)
            if (guard[i] != 0xa5u) { lowest = i; break; }
        report_stack(lowest == 1536 ? 512 : 2048 - lowest);
        if (lowest < 512) passed = false;
    }
    report(passed ? CM_MODEL " PASS\n" : CM_MODEL " FAIL\n");
    _exit(passed ? 0 : 1);
}
