/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "blue_jubjub_lowmem.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_jubjub_encode.h"
#include "blue_jubjub_decode.h"
#include "blue_redjubjub_challenge.h"
#include "blue_redjubjub_nonce.h"
#include "blue_redjubjub_response.h"
#include "blue_redjubjub_sign_isolated.h"
#include "blue_zip32_master.h"
#include "blue_zip32_fvk.h"
#include "blue_zip32_child.h"
#include "blue_zip32_seed_bridge.h"
#include "blue_sapling_entropy_device.h"
#include "blue_sapling_spend_device.h"
#include "blue_sapling_spend_auth.h"
#include "blue_sapling_aead.h"
#include "blue_sapling_memo.h"
#include "blue_sapling_epk.h"
#include "blue_consensus_spend_fixture.h"
#include "blue_sapling_generators.h"
#include "blue_mod256.h"
#include "blue_fr_ct.h"
#include "blue_fr_sqrt.h"
#include "blue_fs_ct.h"
#include "sapling/jubjub.h"
#include "base/log_level.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifdef BLUE_QEMU_M0
#include <unistd.h>
#define BLUE_QEMU_MODEL "M0"
#else
#define BLUE_QEMU_MODEL "M3"
#endif

extern uint8_t _sdata, _edata, _sidata, _sbss, _ebss;
extern uint8_t _stack_bottom, _stack_top;
extern void _exit(int status);
#ifdef BLUE_QEMU_M0
extern void initialise_monitor_handles(void);
#endif
void blue_m3_reset(void);

static int entropy_pin_valid;
static bool entropy_revoke_inside_rng;

int os_global_pin_is_validated(void) {
    return entropy_pin_valid;
}

unsigned char *cx_rng(unsigned char *buffer, unsigned int length) {
    if (length != BLUE_SAPLING_ENTROPY_BYTES) return NULL;
    for (unsigned i = 0; i < length; ++i)
        buffer[i] = (uint8_t)i;
    if (entropy_revoke_inside_rng) entropy_pin_valid = 0;
    return buffer;
}

void os_perso_derive_node_bip32(unsigned curve, const unsigned int *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    if (curve != CX_CURVE_256K1 || length != 3 ||
        path[0] != 0x80000020u || path[1] != 0x80000093u ||
        path[2] != 0x80000000u || !entropy_pin_valid) {
        entropy_pin_valid = 0;
        return;
    }
    for (unsigned i = 0; i < 32; ++i) {
        raw[i] = (uint8_t)i;
        chain[i] = (uint8_t)(i + 32);
    }
}

enum zcl_log_level zcl_log_level_get(void) {
    return ZCL_LOG_OFF;
}

void memory_cleanse(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

__attribute__((used, section(".vectors")))
const uintptr_t blue_m3_vectors[2] = {
    (uintptr_t)&_stack_top, (uintptr_t)blue_m3_reset
};

static const struct jub_point generator = {
    .x = {.d = {0x9fea675eb63e8cf6ULL, 0x15ba8508eb7f13c5ULL,
                0x87a02da79c8b7ef8ULL, 0x0af4897169c1851eULL}},
    .y = {.d = {0xfb63146264e65a56ULL, 0x77f3f8c6fd45d5e5ULL,
                0x8770a243986a6eb9ULL, 0x6dde055ca112d037ULL}},
    .z = {.d = {0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
                0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL}},
    .t = {.d = {0x1c78341b5c609fc6ULL, 0xbb8cd2689521ecaeULL,
                0xb1768e136106271aULL, 0x16f2498b4757e919ULL}}
};

static const struct jub_point expected_ak = {
    .x = {.d = {0x47264d8ded287d0cULL, 0xf9e3de776cacc5e1ULL,
                0x06c3920105de6efaULL, 0x69de38448e77f369ULL}},
    .y = {.d = {0xbb5f2c42f7f1e69aULL, 0x40ab629c77009200ULL,
                0xc4ff253197088dd8ULL, 0x3eb6abd2f8657248ULL}},
    .z = {.d = {0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
                0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL}},
    .t = {.d = {0xd742d6186120baeaULL, 0xecc41f669b8a3ec8ULL,
                0x182d90daafa0fb89ULL, 0x4ca04356cb166d7eULL}}
};

static unsigned hex_digit(char value) {
    if (value >= '0' && value <= '9') return (unsigned)(value - '0');
    if (value >= 'a' && value <= 'f') return (unsigned)(value - 'a' + 10);
    return 0xffu;
}

static bool decode_reversed(uint8_t out[32], const char hex[65]) {
    for (unsigned i = 0; i < 32; ++i) {
        unsigned high = hex_digit(hex[2 * i]);
        unsigned low = hex_digit(hex[2 * i + 1]);
        if (high > 15 || low > 15) return false;
        out[31 - i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool matches_hex(const uint8_t actual[32], const char hex[65]) {
    for (unsigned i = 0; i < 32; ++i) {
        unsigned high = hex_digit(hex[2 * i]);
        unsigned low = hex_digit(hex[2 * i + 1]);
        if (high > 15 || low > 15 ||
            actual[i] != (uint8_t)((high << 4) | low)) return false;
    }
    return true;
}

static bool same_field(const struct fr *a, const struct fr *b) {
    uint64_t difference = 0;
    for (unsigned i = 0; i < 4; ++i) difference |= a->d[i] ^ b->d[i];
    return difference == 0;
}

static bool same_point(const struct jub_point *a,
    const struct jub_point *b) {
    struct fr left, right;
    blue_fr_mul_ct(&left, &a->x, &b->z);
    blue_fr_mul_ct(&right, &b->x, &a->z);
    bool x_equal = same_field(&left, &right);
    blue_fr_mul_ct(&left, &a->y, &b->z);
    blue_fr_mul_ct(&right, &b->y, &a->z);
    bool y_equal = same_field(&left, &right);
    return x_equal && y_equal;
}

static void uart_text(const char *text) {
#ifdef BLUE_QEMU_M0
    (void)write(1, text, strlen(text));
#else
    volatile uint32_t *const uart = (volatile uint32_t *)0x40004000u;
    uart[4] = 16u;
    uart[2] = 1u;
    while (*text) {
        while (uart[1] & 1u) {}
        uart[0] = (uint8_t)*text++;
    }
#endif
}

static void uart_hex16(unsigned value) {
    static const char digits[] = "0123456789abcdef";
#ifdef BLUE_QEMU_M0
    char output[4];
    for (int shift = 12; shift >= 0; shift -= 4)
        output[(12 - shift) / 4] = digits[(value >> shift) & 15u];
    (void)write(1, output, sizeof output);
#else
    volatile uint32_t *const uart = (volatile uint32_t *)0x40004000u;
    for (int shift = 12; shift >= 0; shift -= 4) {
        while (uart[1] & 1u) {}
        uart[0] = (uint8_t)digits[(value >> shift) & 15u];
    }
#endif
}

static bool check_reduction(void) {
    uint8_t digest[64] = {0}, reduced[32];
    jubjub_to_scalar(digest, reduced);
    for (unsigned i = 0; i < 32; ++i)
        if (reduced[i] != 0) return false;
    digest[0] = 1;
    jubjub_to_scalar(digest, reduced);
    if (reduced[0] != 1) return false;
    for (unsigned i = 1; i < 32; ++i)
        if (reduced[i] != 0) return false;
    for (unsigned i = 0; i < 64; ++i) digest[i] = 0xffu;
    jubjub_to_scalar(digest, reduced);
    if (!matches_hex(reduced,
        "3077e595a49a716726fce39cf0ceb051a5e926c0fab7da698876128d7b54f604"))
        return false;
    for (unsigned i = 0; i < 64; ++i)
        digest[i] = (uint8_t)(i * 29u + 7u);
    jubjub_to_scalar(digest, reduced);
    return matches_hex(reduced,
        "94c661df522f94a9436c0c1a47a5bbbfd1acdfa93aaa165d9089754fc2a1e001");
}

static bool check_outgoing_open(void) {
    static const uint8_t key[32] = {
        0xd9,0x53,0x84,0xf8,0x1b,0x92,0xc9,0x07,
        0xc1,0x32,0x79,0x86,0xcb,0x66,0xb7,0x65,
        0x42,0x83,0x73,0x72,0x59,0x5e,0xa0,0x5f,
        0xff,0xec,0x20,0x6d,0x4d,0x44,0x40,0xbb
    };
    static const uint8_t cipher[80] = {
        0x54,0x7b,0xd9,0xe1,0x72,0xfb,0xb9,0x45,
        0xa8,0x39,0x81,0x21,0xa5,0x1c,0x9b,0xdd,
        0x8d,0xad,0x14,0x98,0x0f,0x0e,0x3a,0x77,
        0x92,0x34,0xab,0x04,0x0c,0x55,0x16,0xe1,
        0xd2,0xa8,0xc2,0xd5,0x0a,0x21,0xf9,0xfb,
        0x25,0x85,0x54,0xc3,0x90,0x9a,0x7c,0x53,
        0x2f,0x8d,0xe1,0x61,0x99,0xe0,0x07,0x67,
        0x89,0xca,0xd1,0x5d,0xf0,0x61,0xfe,0x48,
        0x63,0x03,0xaa,0xb9,0x4e,0x92,0x45,0x98,
        0xdc,0xae,0x7e,0xe1,0x05,0x04,0x57,0x5d
    };
    static const uint8_t expected[64] = {
        0x25,0xd4,0xfe,0xd2,0xb7,0xef,0x10,0x5c,
        0xaa,0xe1,0xf6,0x9f,0x11,0x62,0x6d,0x7a,
        0xc7,0x9a,0x51,0xa6,0x9f,0xc2,0x01,0x63,
        0xb4,0x86,0x68,0xd7,0x0f,0xd1,0x0f,0x3a,
        0xca,0xd2,0xf8,0xc7,0x01,0x5b,0xcd,0x97,
        0x59,0x0b,0xf2,0xba,0x2f,0x68,0x30,0x8e,
        0x18,0x6b,0x3d,0x62,0x41,0xa1,0xe8,0x72,
        0x5c,0x21,0x08,0xf3,0x12,0x4b,0xba,0x06
    };
    uint8_t recovered[64], changed[80];
    if (!blue_sapling_out_open(recovered, key, cipher) ||
        memcmp(recovered, expected, sizeof expected) != 0) return false;
    memcpy(changed, cipher, sizeof changed);
    if (!blue_sapling_out_open_inplace(changed, key) ||
        memcmp(changed, expected, sizeof expected) != 0) return false;
    for (size_t i = sizeof expected; i < sizeof changed; ++i)
        if (changed[i]) return false;
    memcpy(changed, cipher, sizeof changed);
    changed[79] ^= 1u;
    if (blue_sapling_out_open(recovered, key, changed)) return false;
    for (unsigned i = 0; i < sizeof recovered; ++i)
        if (recovered[i]) return false;
    if (blue_sapling_out_open_inplace(changed, key)) return false;
    for (size_t i = 0; i < sizeof changed; ++i)
        if (changed[i]) return false;
    return true;
}

static bool check_note_open(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t cipher[BLUE_SAPLING_NOTE_CIPHER_BYTES] = {
        [BLUE_SAPLING_NOTE_PLAIN_BYTES] =
            0x95,0x22,0xd6,0x67,0x36,0x7b,0x4c,0x44,
            0x02,0xb1,0x2d,0x0b,0x07,0x3e,0x21,0x53
    };
    static const uint8_t first[8] = {
        0x18,0xb8,0x42,0x31,0xad,0xe6,0xa6,0xd1
    };
    static const uint8_t last[8] = {
        0x71,0xc7,0x04,0x32,0xec,0x34,0xbf,0xc6
    };
    uint8_t recovered[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    if (!blue_sapling_note_open(recovered, key, cipher) ||
        memcmp(recovered, first, sizeof first) != 0 ||
        memcmp(recovered + sizeof recovered - sizeof last,
            last, sizeof last) != 0) return false;
    uint8_t wrong_key[32];
    memcpy(wrong_key, key, sizeof key);
    wrong_key[0] ^= 1u;
    if (blue_sapling_note_open(recovered, wrong_key, cipher)) return false;
    for (size_t i = 0; i < sizeof recovered; ++i)
        if (recovered[i]) return false;
    return true;
}

static bool check_note_open_inplace(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t cipher[BLUE_SAPLING_NOTE_CIPHER_BYTES] = {
        [BLUE_SAPLING_NOTE_PLAIN_BYTES] =
            0x95,0x22,0xd6,0x67,0x36,0x7b,0x4c,0x44,
            0x02,0xb1,0x2d,0x0b,0x07,0x3e,0x21,0x53
    };
    static const uint8_t first[8] = {
        0x18,0xb8,0x42,0x31,0xad,0xe6,0xa6,0xd1
    };
    static const uint8_t last[8] = {
        0x71,0xc7,0x04,0x32,0xec,0x34,0xbf,0xc6
    };
    uint8_t inplace[BLUE_SAPLING_NOTE_CIPHER_BYTES];
    memcpy(inplace, cipher, sizeof inplace);
    if (!blue_sapling_note_open_inplace(inplace, key) ||
        memcmp(inplace, first, sizeof first) != 0 ||
        memcmp(inplace + BLUE_SAPLING_NOTE_PLAIN_BYTES - sizeof last,
            last, sizeof last) != 0) return false;
    for (size_t i = BLUE_SAPLING_NOTE_PLAIN_BYTES; i < sizeof inplace; ++i)
        if (inplace[i]) return false;
    memcpy(inplace, cipher, sizeof inplace);
    inplace[sizeof inplace - 1] ^= 1u;
    if (blue_sapling_note_open_inplace(inplace, key)) return false;
    for (size_t i = 0; i < sizeof inplace; ++i)
        if (inplace[i]) return false;
    return true;
}

static void scalar_bytes(uint8_t out[32], const struct fs *value) {
    for (unsigned i = 0; i < 32; ++i)
        out[i] = (uint8_t)(value->d[i / 8] >> (8 * (i % 8)));
}

static void scalar_from_bytes(struct fs *out, const uint8_t bytes[32]) {
    for (unsigned limb = 0; limb < 4; ++limb) {
        out->d[limb] = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            out->d[limb] |= (uint64_t)bytes[limb * 8 + byte] << (byte * 8);
    }
}

static bool check_changed_message(const struct jub_point *key,
    const struct jub_point *nonce_point,
    const struct jub_point *response_point, const uint8_t rbar[32],
    const uint8_t vkbar[32], uint8_t message[32]) {
    static struct jub_point challenge_key, expected;
    uint8_t challenge_bytes[32];
    message[0] ^= 1u;
    if (!blue_redjubjub_challenge(challenge_bytes, rbar, vkbar, message))
        return false;
    if (matches_hex(challenge_bytes,
        "cc190cb691dc8867cf624b96fbfe0f0845bef7acc28e3a76a07ee58ce0aa800d"))
        return false;
    if (!blue_jubjub_scalar_mul_lowmem(&challenge_key, key,
        challenge_bytes)) return false;
    blue_jub_add(&expected, nonce_point, &challenge_key);
    return !same_point(response_point, &expected);
}

static bool encode_fixture_points(uint8_t rbar[32], uint8_t vkbar[32],
    const struct jub_point *key, const struct jub_point *nonce_point) {
    return blue_jubjub_encode(vkbar, key) &&
        matches_hex(vkbar,
        "8652af3ed8bf43bb9bbf4c269050b76332e2c4a38846fe7803a51782dfa9bccd") &&
        blue_jubjub_encode(rbar, nonce_point) &&
        matches_hex(rbar,
        "41c838bc82512ca1c7fd74a6dd210bba07693ed7858a1d03f2d7f3fb5b34362e");
}

static bool check_signing_equation(void) {
    static struct jub_point key, nonce_point, response_point;
    static struct jub_point challenge_key, expected;
    struct fs secret = {.d = {23}}, nonce = {.d = {97}};
    struct fs challenge, product, response;
    uint8_t scalar[32], challenge_bytes[32], message[32];
    uint8_t rbar[32], vkbar[32];
    for (unsigned i = 0; i < 32; ++i) message[i] = (uint8_t)i;
    scalar_bytes(scalar, &secret);
    if (!blue_jubjub_scalar_mul_lowmem(&key, &generator, scalar)) return false;
    scalar_bytes(scalar, &nonce);
    if (!blue_jubjub_scalar_mul_lowmem(&nonce_point, &generator, scalar))
        return false;
    if (!encode_fixture_points(rbar, vkbar, &key, &nonce_point))
        return false;
    if (!blue_redjubjub_challenge(challenge_bytes, rbar, vkbar, message) ||
        !matches_hex(challenge_bytes,
        "cc190cb691dc8867cf624b96fbfe0f0845bef7acc28e3a76a07ee58ce0aa800d"))
        return false;
    scalar_from_bytes(&challenge, challenge_bytes);
    blue_fs_mul_ct(&product, &challenge, &secret);
    blue_fs_add_ct(&response, &nonce, &product);
    scalar_bytes(scalar, &response);
    if (!matches_hex(scalar,
        "b2a6cfb84fa3e730e7855cb47a3ce5122641f97068fcca188df7605bf2823f06"))
        return false;
    if (!blue_jubjub_scalar_mul_lowmem(&response_point, &generator, scalar))
        return false;
    scalar_bytes(scalar, &challenge);
    if (!blue_jubjub_scalar_mul_lowmem(&challenge_key, &key, scalar))
        return false;
    blue_jub_add(&expected, &nonce_point, &challenge_key);
    bool valid = same_point(&response_point, &expected);
    response.d[0] ^= 1u;
    scalar_bytes(scalar, &response);
    if (!blue_jubjub_scalar_mul_lowmem(&response_point, &generator, scalar))
        return false;
    if (!valid || same_point(&response_point, &expected)) return false;
    response.d[0] ^= 1u;
    scalar_bytes(scalar, &response);
    if (!blue_jubjub_scalar_mul_lowmem(&response_point, &generator, scalar))
        return false;
    return check_changed_message(&key, &nonce_point, &response_point,
        rbar, vkbar, message);
}

static bool check_challenge(void) {
    uint8_t rbar[32], vkbar[32], message[32], actual[32];
    for (unsigned i = 0; i < 32; ++i) {
        rbar[i] = (uint8_t)i;
        vkbar[i] = (uint8_t)(i + 32);
        message[i] = (uint8_t)(i + 64);
    }
    if (!blue_redjubjub_challenge(actual, rbar, vkbar, message)) return false;
    return matches_hex(actual,
        "17b7ba4df18cc10026143ed72d67bf355a7dac21164951edb121643d551d4d0b");
}

static bool check_scalar_output_overlap(void) {
    struct jub_point output = generator;
    const uint8_t *scalar =
        (const uint8_t *)&output + sizeof output - 32;
    return !blue_jubjub_scalar_mul_lowmem(&output, &generator, scalar) &&
        memcmp(&output, &generator, sizeof output) == 0;
}

static bool check_entropy_signature(void) {
    static struct jub_point key, nonce_point, response_point;
    static struct jub_point challenge_key, expected;
    struct fs secret = {.d = {23}};
    uint8_t seed[80], message[32], scalar[32], rbar[32], vkbar[32];
    uint8_t nonce[32], challenge[32], secret_bytes[32];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof message; ++i)
        message[i] = (uint8_t)i;
    scalar_bytes(scalar, &secret);
    if (!blue_jubjub_scalar_mul_lowmem(&key, &generator, scalar) ||
        !blue_jubjub_encode(vkbar, &key)) return false;
    if (!blue_redjubjub_nonce_from_entropy(scalar, seed,
            vkbar, message) ||
        !matches_hex(scalar,
        "923570e916048b7c59ac0e27affb7a1db7acf6e2fbb4d1be2b9077466e48f806"))
        return false;
    memcpy(nonce, scalar, sizeof nonce);
    if (!blue_jubjub_scalar_mul_lowmem(&nonce_point, &generator,
            scalar) || !blue_jubjub_encode(rbar, &nonce_point) ||
        !blue_redjubjub_challenge(scalar, rbar, vkbar, message))
        return false;
    memcpy(challenge, scalar, sizeof challenge);
    scalar_bytes(secret_bytes, &secret);
    if (!blue_redjubjub_response(scalar, nonce, challenge,
            secret_bytes)) return false;
    if (!blue_jubjub_scalar_mul_lowmem(&response_point, &generator,
        scalar)) return false;
    memcpy(scalar, challenge, sizeof scalar);
    if (!blue_jubjub_scalar_mul_lowmem(&challenge_key, &key, scalar))
        return false;
    blue_jub_add(&expected, &nonce_point, &challenge_key);
    return same_point(&response_point, &expected);
}

static bool check_device_entropy(void) {
    uint8_t entropy[BLUE_SAPLING_ENTROPY_BYTES];
    memset(entropy, 0xa5, sizeof entropy);
    entropy_pin_valid = 0;
    if (blue_sapling_device_entropy(entropy)) return false;
    for (unsigned i = 0; i < sizeof entropy; ++i)
        if (entropy[i]) return false;
    entropy_pin_valid = 1;
    if (!blue_sapling_device_entropy(entropy)) return false;
    for (unsigned i = 0; i < sizeof entropy; ++i)
        if (entropy[i] != (uint8_t)i) return false;
    entropy_revoke_inside_rng = true;
    if (blue_sapling_device_entropy(entropy)) return false;
    entropy_revoke_inside_rng = false;
    for (unsigned i = 0; i < sizeof entropy; ++i)
        if (entropy[i]) return false;
    return true;
}

static union {
    struct {
        uint8_t entropy[80];
        union {
            blue_zip32_workspace fvk;
            blue_zip32_seed_workspace node;
        } scratch;
        union {
            struct zip32_xsk master;
            blue_sapling_spend_workspace auth;
        } parent;
        struct zip32_xsk child;
        uint8_t seed[32];
    } review;
    blue_sapling_device_spend_workspace device;
    blue_jubjub_decode_workspace point;
} fixture_memory;
static uint8_t device_signature[64];

/* QEMU cases run sequentially and reuse the same bounded test RAM. */
#define signing_seed fixture_memory.review.entropy
#define signing_signature device_signature
#define checked_workspace fixture_memory.review.scratch
#define checked_parent fixture_memory.review.parent
#define checked_child fixture_memory.review.child
#define checked_seed fixture_memory.review.seed
#define point_workspace fixture_memory.point

static bool check_isolated_signature(void) {
    uint8_t secret[32] = {23}, message[32];
    for (unsigned i = 0; i < sizeof signing_seed; ++i)
        signing_seed[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof message; ++i)
        message[i] = (uint8_t)i;
    if (!blue_redjubjub_sign_isolated(signing_signature, secret,
            signing_seed, message)) return false;
    bool matches = matches_hex(signing_signature,
        "8f40696890377cb1a4146a7117d9ceecd6014d9136de23f2f7781ad10f8850d2") &&
        matches_hex(signing_signature + 32,
        "ffe3a89b2c2105c9b216070288b519e68c829a95aa9fca3307611d6dd277d306");
    memset(signing_seed, 0, sizeof signing_seed);
    if (blue_redjubjub_sign_isolated(signing_signature, secret,
            signing_seed, message)) return false;
    for (unsigned i = 0; i < sizeof signing_signature; ++i)
        matches &= signing_signature[i] == 0;
    return matches;
}

static bool check_shielded_digest_signature(void) {
    static const uint8_t digest[32] = {
        0xdf,0x7c,0x3c,0x4c,0x47,0xac,0x47,0xfb,
        0x23,0x84,0x4b,0x19,0x6c,0x89,0x5a,0xbc,
        0x56,0x40,0xef,0x2f,0xb0,0x4a,0x0c,0xe5,
        0xb7,0x92,0xcc,0x2c,0x98,0x71,0x42,0x4e
    };
    uint8_t secret[32] = {23};
    for (unsigned i = 0; i < sizeof signing_seed; ++i)
        signing_seed[i] = (uint8_t)i;
    if (!blue_redjubjub_sign_isolated(signing_signature, secret,
            signing_seed, digest)) return false;
    return matches_hex(signing_signature,
        "473240ce569bb29ec88ebb7a7b01c824e11e450ecf60fcba44dff83f21a0422d") &&
        matches_hex(signing_signature + 32,
        "dd6824f3bcc664aa4577b40551625f6e3c6f81d55c2ccd5664754ab4b2980705");
}

static bool check_key_vector(void) {
    static const char ask_hex[] =
        "06880e0df04583674f05d25dcf1119cf18f84420407823aa47a53e474aa14885";
    uint8_t ask[32];
    struct jub_point derived;
    return decode_reversed(ask, ask_hex) &&
        blue_jubjub_scalar_mul_lowmem(&derived, &generator, ask) &&
        same_point(&derived, &expected_ak);
}

static bool check_fs_boundary(void) {
    struct fs max = {.d = {0xd0970e5ed6f72cb6ULL,
        0xa6682093ccc81082ULL, 0x06673b0101343b00ULL,
        0x0e7db4ea6533afa9ULL}};
    struct fs product, one = {.d = {1}};
    blue_fs_mul_ct(&product, &max, &max);
    for (unsigned i = 0; i < 4; ++i)
        if (product.d[i] != one.d[i]) return false;
    return true;
}

static bool check_fr_codec(void) {
    static const uint8_t p_minus_one[32] = {
        0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
        0xfe,0x5b,0xfe,0xff,0x02,0xa4,0xbd,0x53,
        0x05,0xd8,0xa1,0x09,0x08,0xd8,0x39,0x33,
        0x48,0x7d,0x9d,0x29,0x53,0xa7,0xed,0x73
    };
    struct fr field;
    uint8_t restored[32], invalid[32];
    if (!blue_fr_from_bytes_canonical(&field, p_minus_one)) return false;
    blue_fr_to_bytes(restored, &field);
    if (memcmp(restored, p_minus_one, sizeof restored) != 0) return false;
    memcpy(invalid, p_minus_one, sizeof invalid);
    ++invalid[0];
    if (blue_fr_from_bytes_canonical(&field, invalid)) return false;
    for (size_t i = 0; i < 4; ++i)
        if (field.d[i]) return false;
    ++invalid[0];
    return !blue_fr_from_bytes_canonical(&field, invalid);
}

static bool check_fr_sqrt(void) {
    const uint8_t four_bytes[32] = {4}, five_bytes[32] = {5};
    struct fr four, five, root, squared;
    if (!blue_fr_from_bytes_canonical(&four, four_bytes) ||
        !blue_fr_from_bytes_canonical(&five, five_bytes) ||
        !blue_fr_sqrt_public(&root, &four)) return false;
    blue_fr_mul_ct(&squared, &root, &root);
    if (!same_field(&squared, &four)) return false;
    if (blue_fr_sqrt_public(&root, &five)) return false;
    for (unsigned i = 0; i < 4; ++i)
        if (root.d[i]) return false;
    return true;
}

static bool check_point_decode(void) {
    uint8_t encoded[32], identity[32] = {1};
    struct jub_point decoded;
    if (!blue_jubjub_encode(encoded, &generator) ||
        !blue_jubjub_decode_public(&decoded, &point_workspace, encoded) ||
        !same_point(&decoded, &generator)) return false;
    if (blue_jubjub_decode_public(&decoded, &point_workspace, identity))
        return false;
    const struct jub_point zero = {0};
    return memcmp(&decoded, &zero, sizeof zero) == 0;
}

static bool bridge_ready;

static bool fixture_bip32_node(void *context, const uint32_t path[3],
    uint8_t private_key[32], uint8_t chain_code[32]) {
    (void)context;
    if (path[0] != 0x80000020u || path[1] != 0x80000093u ||
        path[2] != 0x80000000u) return false;
    for (unsigned i = 0; i < 32; ++i) {
        private_key[i] = (uint8_t)i;
        chain_code[i] = (uint8_t)(i + 32);
    }
    return true;
}

static const uint8_t mapped_ar[32] = {7};
static const uint8_t mapped_rk[32] = {
        0x14,0xcc,0x33,0xd5,0x40,0x19,0x4d,0x86,
        0xc5,0x36,0x07,0x2e,0xba,0x2f,0xb2,0xd5,
        0xcd,0x89,0xe5,0x52,0x24,0x3d,0x58,0x04,
        0xf1,0x2e,0xd2,0x1a,0x53,0xcf,0x83,0x0f
};
static const uint8_t mapped_wrong_rk[32] = {
        0x15,0xcc,0x33,0xd5,0x40,0x19,0x4d,0x86,
        0xc5,0x36,0x07,0x2e,0xba,0x2f,0xb2,0xd5,
        0xcd,0x89,0xe5,0x52,0x24,0x3d,0x58,0x04,
        0xf1,0x2e,0xd2,0x1a,0x53,0xcf,0x83,0x0f
};
static const uint8_t mapped_digest[32] = {
        0x44,0xc7,0xdb,0x79,0xd6,0x04,0x5d,0x0e,
        0xbd,0xdb,0x2f,0x3b,0x2f,0x3b,0x1f,0xef,
        0xcc,0xdb,0x19,0x82,0x4d,0x72,0xd3,0x57,
        0x7f,0x4b,0xee,0xc1,0x93,0x03,0xe9,0x7d
};

static bool check_mapped_spend_signature(void) {
    bool valid = bridge_ready;
    entropy_pin_valid = 1;
    if (valid) valid = blue_sapling_device_spend_sign(device_signature,
        &fixture_memory.device, 0, mapped_ar, mapped_rk, mapped_digest) &&
        matches_hex(device_signature,
            "d0f960eaff1d0883efdaf4972e8393fa4b08426e3b6721758c0f2e3292c71bad") &&
        matches_hex(device_signature + 32,
            "306569f4adfe9d09e708a61efc3ac2d86e10f8e4d783a404c1453ee21dacd20b");
    blue_mod256_wipe(device_signature, sizeof device_signature);
    bridge_ready = false;
    return valid;
}

static bool check_mapped_spend_reject(void) {
    bool valid = true;
    entropy_pin_valid = 1;
    memset(device_signature, 0xa5, sizeof device_signature);
    valid &= !blue_sapling_device_spend_sign(device_signature,
        &fixture_memory.device, 0, mapped_ar, mapped_wrong_rk,
        mapped_digest);
    for (unsigned i = 0; i < sizeof device_signature; ++i)
        valid &= device_signature[i] == 0;
    blue_mod256_wipe(device_signature, sizeof device_signature);
    return valid;
}

static bool check_mapped_spend_locked(void) {
    bool valid = true;
    entropy_pin_valid = 0;
    valid &= !blue_sapling_device_spend_sign(device_signature,
        &fixture_memory.device, 0, mapped_ar, mapped_rk, mapped_digest);
    for (unsigned i = 0; i < sizeof fixture_memory.device; ++i)
        valid &= ((const uint8_t *)&fixture_memory.device)[i] == 0;
    blue_mod256_wipe(device_signature, sizeof device_signature);
    return valid;
}

static bool check_zip32_seed_bridge(void) {
    static const uint8_t root[32] = {
        0x2d,0x26,0x76,0x85,0xb1,0x14,0x36,0x26,
        0x95,0x83,0xfd,0x90,0xcf,0x71,0xa4,0x13,
        0xfe,0x25,0xc4,0x6a,0x9d,0x67,0x0a,0x06,
        0x9f,0x4c,0xe7,0x52,0xbb,0xa3,0x4e,0x1e
    };
    bool valid = blue_zip32_master_from_bip32(&checked_parent.master,
        &checked_workspace.node, fixture_bip32_node, NULL) &&
        blue_zip32_master_xsk(&checked_child, root) &&
        checked_parent.master.depth == checked_child.depth &&
        checked_parent.master.parent_fvk_tag == checked_child.parent_fvk_tag &&
        checked_parent.master.child_index == checked_child.child_index &&
        memcmp(checked_parent.master.chain_code,
            checked_child.chain_code, 32) == 0 &&
        memcmp(checked_parent.master.dk, checked_child.dk, 32) == 0 &&
        memcmp(&checked_parent.master.expsk, &checked_child.expsk,
            sizeof checked_parent.master.expsk) == 0;
    for (unsigned i = 0; i < sizeof checked_workspace.node; ++i)
        valid &= ((const uint8_t *)&checked_workspace.node)[i] == 0;
    bridge_ready = valid;
    if (!valid) {
        blue_mod256_wipe(&checked_parent, sizeof checked_parent);
        blue_mod256_wipe(&checked_child, sizeof checked_child);
    }
    return valid;
}

static bool check_consensus_spend_signature(void) {
    for (unsigned i = 0; i < sizeof signing_seed; ++i)
        signing_seed[i] = (uint8_t)i;
    bool valid = blue_sapling_spend_auth_sign(signing_signature,
        &checked_parent.auth, blue_consensus_ask, blue_consensus_ar,
        blue_consensus_rk, signing_seed, blue_consensus_digest) &&
        memcmp(signing_signature, blue_consensus_signature,
               sizeof signing_signature) == 0;
    if (valid) {
        memset(signing_signature, 0xa5, sizeof signing_signature);
        memcpy(signing_signature, blue_consensus_rk, 32);
        signing_signature[0] ^= 1u;
        valid = !blue_sapling_spend_auth_sign(signing_signature,
            &checked_parent.auth, blue_consensus_ask, blue_consensus_ar,
            signing_signature, signing_seed, blue_consensus_digest) &&
            signing_signature[0] == (uint8_t)(blue_consensus_rk[0] ^ 1u) &&
            memcmp(signing_signature + 1, blue_consensus_rk + 1, 31) == 0;
        for (unsigned i = 32; i < sizeof signing_signature; ++i)
            valid &= signing_signature[i] == 0xa5;
    }
    blue_mod256_wipe(&checked_parent, sizeof checked_parent);
    blue_mod256_wipe(signing_seed, sizeof signing_seed);
    blue_mod256_wipe(signing_signature, sizeof signing_signature);
    return valid;
}

static bool check_zip32_master(void) {
    uint8_t seed[32];
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    struct zip32_xsk result;
    if (!blue_zip32_master_xsk(&result, seed)) return false;
    bool matches = result.depth == 0 && result.parent_fvk_tag == 0 &&
        result.child_index == 0 &&
        matches_hex(result.expsk.ask,
        "b6c00c93d36032b9a268e99e86a860776560bf0e83c1a10b51f607c954742506") &&
        matches_hex(result.expsk.nsk,
        "8204ede83b2f1fbd84f9b45d7f996e2ebd0a030ad243b48ed39f748a8821ea06") &&
        matches_hex(result.expsk.ovk,
        "395884890323b9d4933c021db89bcf767df21977b2ff0683848321a4df4afb21") &&
        matches_hex(result.chain_code,
        "d0947c4b03bf72a37ab44f72276d1cf3fdcd7ebf3e73348b7e550d752018668e") &&
        matches_hex(result.dk,
        "77c17cb75b7796afb39f0f3e91c924607da56fa9a20e283509bc8a3ef996a172");
    if (blue_zip32_master_xsk(&result, NULL)) return false;
    const uint8_t *bytes = (const uint8_t *)&result;
    for (unsigned i = 0; i < sizeof result; ++i)
        matches &= bytes[i] == 0;
    return matches;
}

static bool check_zip32_fvk(void) {
    uint8_t encoded[32], seed[32];
    bool valid = blue_jubjub_encode(encoded,
        &blue_proof_generation_generator) &&
        matches_hex(encoded,
            "e7e85de0f7f97a46d249a1f5ea51df50cc48490f8401c9de7a2adf1807d1b6d4");
    for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
    struct zip32_xsk master = {0};
    if (valid) valid = blue_zip32_master_xsk(&master, seed);
    if (valid) valid = blue_zip32_fvk_from_expsk(&checked_workspace.fvk.fvk,
        &master.expsk);
    uint32_t tag = 0;
    if (valid) valid = blue_zip32_fvk_tag(&tag, &checked_workspace.fvk.fvk) &&
        tag == 0x3a71c214u;
    blue_mod256_wipe(&checked_workspace, sizeof checked_workspace);
    blue_mod256_wipe(&master, sizeof master);
    return valid;
}

static bool check_zip32_storage_alias(void) {
    memset(&checked_parent, 0xa5, sizeof checked_parent);
    uint8_t *bytes = (uint8_t *)&checked_parent.master;
    bool valid = !blue_zip32_master_xsk(&checked_parent.master,
        bytes + offsetof(struct zip32_xsk, expsk) + 4) &&
        !blue_zip32_fvk_from_expsk(
            (struct zip32_fvk *)(void *)(bytes +
                offsetof(struct zip32_xsk, expsk) + 4),
            &checked_parent.master.expsk) &&
        !blue_zip32_derive_child(
            (struct zip32_xsk *)(void *)(bytes + 4),
            &checked_parent.master, 1, &checked_workspace.fvk);
    for (unsigned i = 0; i < sizeof checked_parent; ++i)
        valid &= ((const uint8_t *)&checked_parent)[i] == 0xa5;
    blue_mod256_wipe(&checked_parent, sizeof checked_parent);
    return valid;
}

static bool check_zip32_child_signature(const struct zip32_xsk *child) {
    static const uint8_t digest[32] = {
        0xdf,0x7c,0x3c,0x4c,0x47,0xac,0x47,0xfb,
        0x23,0x84,0x4b,0x19,0x6c,0x89,0x5a,0xbc,
        0x56,0x40,0xef,0x2f,0xb0,0x4a,0x0c,0xe5,
        0xb7,0x92,0xcc,0x2c,0x98,0x71,0x42,0x4e
    };
    for (unsigned i = 0; i < sizeof signing_seed; ++i)
        signing_seed[i] = (uint8_t)i;
    bool valid = blue_redjubjub_sign_isolated(signing_signature,
        child->expsk.ask, signing_seed, digest) &&
        matches_hex(signing_signature,
            "40396e53f8d178f819ef67c1c2f5fb80c9abd4754a01efde1583a22a697d420c") &&
        matches_hex(signing_signature + 32,
            "8978be725870ca472723d2b2917558a5a2d2fb9745590c710573286d126ad707");
    blue_mod256_wipe(signing_seed, sizeof signing_seed);
    blue_mod256_wipe(signing_signature, sizeof signing_signature);
    return valid;
}

static bool check_zip32_children(void) {
    for (unsigned i = 0; i < sizeof checked_seed; ++i)
        checked_seed[i] = (uint8_t)i;
    bool valid = blue_zip32_master_xsk(&checked_parent.master, checked_seed) &&
        blue_zip32_derive_child(&checked_child, &checked_parent.master, 1,
            &checked_workspace.fvk);
    if (valid) valid = checked_child.depth == 1 &&
        checked_child.parent_fvk_tag == 0x3a71c214u &&
        checked_child.child_index == 1 &&
        matches_hex(checked_child.chain_code,
            "0147110c691a03b9d9f0ba9005c5e790a595b7f04e3329d2fa438a6705dabce6") &&
        matches_hex(checked_child.expsk.ask,
            "282bc197a516287c8ea8f68c424abad302b45cdf95407961d7b8b455267a350c");
    if (valid) valid = check_zip32_child_signature(&checked_child);
    if (valid) {
        memcpy(&checked_parent.master, &checked_child, sizeof checked_child);
        valid = blue_zip32_derive_child(&checked_child,
            &checked_parent.master,
            0x80000002u, &checked_workspace.fvk);
    }
    if (valid) valid = checked_child.depth == 2 &&
        checked_child.parent_fvk_tag == 0x079e99dbu &&
        checked_child.child_index == 0x80000002u &&
        matches_hex(checked_child.expsk.ask,
            "8be8113cee3413a71f82c41fc8da517be134049832e6825c92da6b84fee4c60d");
    blue_mod256_wipe(&checked_parent, sizeof checked_parent);
    blue_mod256_wipe(&checked_workspace, sizeof checked_workspace);
    blue_mod256_wipe(&checked_child, sizeof checked_child);
    blue_mod256_wipe(checked_seed, sizeof checked_seed);
    return valid;
}

static bool check_memo(void) {
    blue_sapling_memo_info info;
    uint8_t checked_memo[BLUE_SAPLING_MEMO_BYTES];
    memset(checked_memo, 0, sizeof checked_memo);
    checked_memo[0] = 0xf6;
    if (!blue_sapling_memo_inspect(checked_memo, &info) ||
        info.kind != BLUE_SAPLING_MEMO_NONE) return false;
    uint8_t no_memo_hash[32];
    memcpy(no_memo_hash, info.sha256, sizeof no_memo_hash);
    checked_memo[511] = 1;
    if (!blue_sapling_memo_inspect(checked_memo, &info) ||
        info.kind != BLUE_SAPLING_MEMO_FUTURE ||
        memcmp(info.sha256, no_memo_hash, 32) == 0) return false;
    memset(checked_memo, 0, sizeof checked_memo);
    checked_memo[0] = 'Z';
    checked_memo[1] = 'C';
    checked_memo[2] = 'L';
    return blue_sapling_memo_inspect(checked_memo, &info) &&
        info.kind == BLUE_SAPLING_MEMO_TEXT &&
        info.text_length == 3 && !info.contains_nul;
}

static bool check_epk(void) {
    static const uint8_t diversifier[11] = {
        0x9c,0xf4,0x94,0x19,0x06,0xe9,0xf1,0x95,0x1a,0x91,0x99
    };
    static const uint8_t esk[32] = {
        0xca,0xd2,0xf8,0xc7,0x01,0x5b,0xcd,0x97,
        0x59,0x0b,0xf2,0xba,0x2f,0x68,0x30,0x8e,
        0x18,0x6b,0x3d,0x62,0x41,0xa1,0xe8,0x72,
        0x5c,0x21,0x08,0xf3,0x12,0x4b,0xba,0x06
    };
    static const uint8_t epk[32] = {
        0xe0,0x9d,0x67,0xf1,0x56,0x80,0x07,0x5d,
        0x53,0x1d,0x9c,0x8c,0x76,0x26,0xdb,0x12,
        0x98,0x7e,0x5a,0xf5,0x98,0x9c,0xe9,0x88,
        0x41,0xde,0x0c,0xf4,0x15,0xf5,0x58,0xb1
    };
    uint8_t altered[32];
    if (!blue_sapling_epk_matches(diversifier, esk, epk,
            &fixture_memory.point)) return false;
    memcpy(altered, epk, sizeof altered);
    altered[0] ^= 1u;
    return !blue_sapling_epk_matches(diversifier, esk, altered,
        &fixture_memory.point);
}

typedef bool (*m3_case_fn)(void);
static const struct {
    const char *name;
    m3_case_fn run;
} cases[] = {
    {"KEY", check_key_vector},
    {"FIELD", check_fs_boundary},
    {"FRCODEC", check_fr_codec},
    {"FRSQRT", check_fr_sqrt},
    {"POINT", check_point_decode},
    {"REDUCE", check_reduction},
    {"OUTOPEN", check_outgoing_open},
    {"NOTEOPEN", check_note_open},
    {"NOTEINPLACE", check_note_open_inplace},
    {"MEMO", check_memo},
    {"EPK", check_epk},
    {"EQUATION", check_signing_equation},
    {"SCALAR ALIAS", check_scalar_output_overlap},
    {"CHALLENGE", check_challenge},
    {"NONCE", check_entropy_signature},
    {"ENTROPY", check_device_entropy},
    {"SIGN", check_isolated_signature},
    {"TXSIGN", check_shielded_digest_signature},
    {"ZIP32", check_zip32_master},
    {"FVK", check_zip32_fvk},
    {"ZIP32 ALIAS", check_zip32_storage_alias},
    {"CHILD", check_zip32_children},
    {"BRIDGE", check_zip32_seed_bridge},
    {"MAPPED", check_mapped_spend_signature},
    {"MAPPED REJECT", check_mapped_spend_reject},
    {"MAPPED LOCK", check_mapped_spend_locked},
    {"SAPLING", check_consensus_spend_signature}
};

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
    if ((uintptr_t)&marker <= (uintptr_t)guard + 1568u) {
        uart_text(BLUE_QEMU_MODEL " STACK SETUP FAIL\n");
        _exit(1);
    }
    bool passed = true;
    unsigned peak = 0;
    for (unsigned test = 0; test < sizeof cases / sizeof cases[0]; ++test) {
        for (unsigned i = 0; i < 1536; ++i) guard[i] = 0xa5u;
        bool case_passed = cases[test].run();
        unsigned lowest = 1536;
        for (unsigned i = 0; i < 1536; ++i) {
            if (guard[i] != 0xa5u) {
                lowest = i;
                break;
            }
        }
        unsigned used = lowest == 1536 ? 512 : 2048u - lowest;
        if (used > peak) peak = used;
        if (!case_passed || lowest < 512) passed = false;
        uart_text(BLUE_QEMU_MODEL " ");
        uart_text(cases[test].name);
        uart_text(lowest == 1536 ? " <=0x" : " 0x");
        uart_hex16(used);
        uart_text("\n");
    }
    uart_text(BLUE_QEMU_MODEL " STACK 0x");
    uart_hex16(peak);
    uart_text("\n");
    uart_text(passed ? BLUE_QEMU_MODEL " PASS\n" :
        BLUE_QEMU_MODEL " FAIL\n");
    _exit(passed ? 0 : 1);
}
