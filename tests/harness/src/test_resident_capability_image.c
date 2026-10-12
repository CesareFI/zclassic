/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: test bounded ELF byte parsing, refusal reasons and cleared outputs. */
#include "test/test_core.h"
#include "platform/resident_capability_image.h"
#include "base/serialize_le.h"

static void rci_put(uint8_t *p, unsigned width, uint64_t value)
{
    switch (width) {
    case 1: *p = (uint8_t)value; break;
    case 2: zcl_write_u16_le(p, (uint16_t)value); break;
    case 4: zcl_write_u32_le(p, (uint32_t)value); break;
    case 8: zcl_write_u64_le(p, value); break;
    default: fprintf(stderr, "resident_capability_image: invalid fixture width\n"); abort();
    }
}

static void rci_fixture(uint8_t *b, size_t length)
{
    memset(b, 0, length);
    memcpy(b, "\177ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;
    rci_put(b + 16, 2, 2); rci_put(b + 18, 2, 62); rci_put(b + 20, 4, 1);
    rci_put(b + 24, 8, 0x400000); rci_put(b + 32, 8, 64);
    rci_put(b + 52, 2, 64); rci_put(b + 54, 2, 56); rci_put(b + 56, 2, 1);
    rci_put(b + 64, 4, 1); rci_put(b + 68, 4, 5);
    rci_put(b + 80, 8, 0x400000);
    rci_put(b + 96, 8, length); rci_put(b + 104, 8, length);
    rci_put(b + 112, 8, 4096);
}

static int rci_expect(const uint8_t *b, size_t n,
                      enum resident_capability_image_v1_status expected)
{
    struct resident_capability_image_v1_info out;
    memset(&out, 0xa5, sizeof(out));
    enum resident_capability_image_v1_status got = resident_capability_image_validate_v1(b, n, &out);
    struct resident_capability_image_v1_info zero;
    memset(&zero, 0, sizeof(zero));
    bool clear = expected == RESIDENT_CAPABILITY_IMAGE_V1_OK || !memcmp(&out, &zero, sizeof(out));
    if (got == expected && clear) return 0;
    fprintf(stderr, "resident_capability_image: length=%zu expected=%s got=%s cleared=%d\n",
            n, resident_capability_image_status_name_v1(expected),
            resident_capability_image_status_name_v1(got), clear);
    return 1;
}

struct rci_mutation { unsigned offset, width; uint64_t value; enum resident_capability_image_v1_status status; };

static int rci_mutations(void)
{
#define S(x) RESIDENT_CAPABILITY_IMAGE_V1_##x
    static const struct rci_mutation cases[] = {
        {0,1,0,S(IDENTIFICATION)}, {4,1,1,S(IDENTIFICATION)}, {5,1,2,S(IDENTIFICATION)},
        {6,1,0,S(IDENTIFICATION)}, {16,2,1,S(HEADER)}, {18,2,3,S(HEADER)},
        {20,4,0,S(HEADER)}, {52,2,63,S(HEADER)}, {54,2,55,S(PROGRAM_TABLE)},
        {56,2,0,S(PROGRAM_TABLE)}, {56,2,129,S(PROGRAM_TABLE)},
        {32,8,UINT64_MAX,S(PROGRAM_TABLE)}, {32,8,240,S(PROGRAM_TABLE)},
        {64,4,3,S(INTERPRETER)}, {72,8,UINT64_MAX,S(SEGMENT)},
        {96,8,257,S(SEGMENT)}, {104,8,255,S(SEGMENT)},
        {80,8,UINT64_MAX,S(SEGMENT)}, {112,8,3,S(SEGMENT)},
        {112,8,8192,S(OK)}, {72,8,1,S(SEGMENT)}, {68,4,4,S(ENTRY)},
        {24,8,0x400100,S(ENTRY)}, {64,4,0,S(ENTRY)}, {104,8,0,S(SEGMENT)}
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t b[256]; rci_fixture(b, sizeof(b));
        rci_put(b + cases[i].offset, cases[i].width, cases[i].value);
        failures += rci_expect(b, sizeof(b), cases[i].status);
    }
    return failures;
}

static int rci_dynamic_tests(void)
{
    uint8_t b[256]; rci_fixture(b, sizeof(b));
    rci_put(b + 56, 2, 2); rci_put(b + 120, 4, 2);
    rci_put(b + 128, 8, 240); rci_put(b + 152, 8, 16);
    int failures = rci_expect(b, sizeof(b), S(OK));
    rci_put(b + 240, 8, 1); failures += rci_expect(b, sizeof(b), S(DEPENDENCY));
    rci_put(b + 240, 8, 2); failures += rci_expect(b, sizeof(b), S(DYNAMIC));
    rci_put(b + 152, 8, 15); failures += rci_expect(b, sizeof(b), S(DYNAMIC));
    rci_put(b + 152, 8, 0); failures += rci_expect(b, sizeof(b), S(DYNAMIC));
    rci_put(b + 152, 8, 17); failures += rci_expect(b, sizeof(b), S(SEGMENT));
    return failures;
}

static int rci_boundaries(void)
{
    size_t maximum = RESIDENT_CAPABILITY_IMAGE_V1_MAX_BYTES;
    uint8_t *allocation = malloc(maximum + 2);
    if (!allocation) { fprintf(stderr, "resident_capability_image: fixture allocation failed\n"); return 1; }
    uint8_t *b = allocation + 1;
    rci_fixture(b, maximum);
    int failures = rci_expect(b, maximum, S(OK));
    failures += rci_expect(b, maximum + 1, S(LENGTH));
    rci_fixture(b, 256);
    for (size_t n = 0; n < 120; ++n)
        failures += rci_expect(b, n, n < 64 ? S(LENGTH) : S(PROGRAM_TABLE));
    for (size_t n = 120; n < 256; ++n) failures += rci_expect(b, n, S(SEGMENT));
    rci_fixture(b, 64 + 128 * 56); rci_put(b + 56, 2, 128);
    failures += rci_expect(b, 64 + 128 * 56, S(OK));
    rci_fixture(b, 32768); rci_put(b + 56, 2, 2); rci_put(b + 120, 4, 2);
    rci_put(b + 128, 8, 4096); rci_put(b + 152, 8, 1024 * 16);
    for (unsigned i = 0; i < 1024; ++i) rci_put(b + 4096 + i * 16, 8, 2);
    failures += rci_expect(b, 32768, S(DYNAMIC));
    rci_put(b + 4096 + 1023 * 16, 8, 0); failures += rci_expect(b, 32768, S(OK));
    rci_put(b + 152, 8, 1025 * 16); failures += rci_expect(b, 32768, S(DYNAMIC));
    free(allocation);
    return failures;
}

static int rci_stale_output(void)
{
    uint8_t b[256]; rci_fixture(b, sizeof(b));
    struct resident_capability_image_v1_info out, zero;
    memset(&zero, 0, sizeof(zero));
    if (resident_capability_image_validate_v1(b, sizeof(b), &out) != S(OK)) return 1;
    b[0] = 0;
    if (resident_capability_image_validate_v1(b, sizeof(b), &out) != S(IDENTIFICATION)) return 1;
    return memcmp(&out, &zero, sizeof(out)) != 0;
}

static int rci_literal_profile(void)
{
    static const uint8_t bytes[128] = {
        [0] = 0x7f, [1] = 'E', [2] = 'L', [3] = 'F',
        [4] = 2, [5] = 1, [6] = 1, [16] = 2, [18] = 62, [20] = 1,
        [26] = 0x40, [32] = 64, [52] = 64, [54] = 56, [56] = 1,
        [64] = 1, [68] = 5, [82] = 0x40, [96] = 128, [104] = 128,
        [113] = 0x10
    };
    return rci_expect(bytes, sizeof(bytes), S(OK));
}

int test_resident_capability_image(void)
{
    uint8_t b[256]; rci_fixture(b, sizeof(b));
    int failures = rci_expect(b, sizeof(b), S(OK));
    struct resident_capability_image_v1_info out;
    if (resident_capability_image_validate_v1(b, sizeof(b), &out) != S(OK) ||
        out.image_bytes != sizeof(b) || out.entry != 0x400000 || out.elf_type != 2 ||
        out.machine != 62 || out.program_headers != 1) ++failures;
    rci_put(b + 16, 2, 3); failures += rci_expect(b, sizeof(b), S(OK));
    failures += rci_expect(NULL, sizeof(b), S(ARGUMENT));
    if (resident_capability_image_validate_v1(b, sizeof(b), NULL) != S(ARGUMENT)) ++failures;
    if (strcmp(resident_capability_image_status_name_v1((enum resident_capability_image_v1_status)-1), "unknown")) ++failures;
    failures += rci_mutations() + rci_dynamic_tests() + rci_boundaries() + rci_stale_output() + rci_literal_profile();
    return failures;
}
