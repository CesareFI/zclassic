/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: observe owned xprv scratch retirement before its lifetime ends.
 * Include the shipping boundary with deterministic codec/key callbacks; real
 * BIP32 encoding and derivation remain covered by test_hd_keychain. No actual
 * wallet or key material is used. Fixture state is private to this test group. */
#include "test/test_core.h"
#include "wallet/hd_keychain.h"
#include "domain/encoding/base58.h"
#include "support/cleanse.h"

enum retirement_case { RET_OK, RET_ENCODE_FAIL, RET_DECODE_FAIL, RET_SHORT,
                       RET_VERSION, RET_KEY };
static struct {
    enum retirement_case mode;
    uintptr_t payload, scratch;
    size_t scratch_size;
    unsigned codec_calls, key_calls, cleanses;
    bool payload_retired, scratch_retired;
} retirement;
static const unsigned char retirement_version[4] = {4, 0x88, 0xad, 0xe4};

static bool retirement_covers(uintptr_t start, size_t size,
                               uintptr_t address, size_t length)
{
    return address >= start && address - start <= size &&
           length <= size - (address - start);
}

static void retirement_cleanse(void *data, size_t size)
{
    uintptr_t start = (uintptr_t)data;
    retirement.payload_retired |= retirement_covers(start, size, retirement.payload,
                                                   BIP32_EXTKEY_SIZE);
    retirement.scratch_retired |= retirement_covers(start, size, retirement.scratch,
                                                   retirement.scratch_size);
    retirement.cleanses++;
    memory_cleanse(data, size);
}

static void retirement_encode(const struct ext_key *key, unsigned char *data)
{
    (void)key;
    retirement.payload = (uintptr_t)data;
    retirement.key_calls++;
    memset(data, 0x5a, BIP32_EXTKEY_SIZE);
}

static void retirement_decode(struct ext_key *key, const unsigned char *data)
{
    (void)data;
    retirement.key_calls++;
    memset(key, 0, sizeof(*key));
    key->key.fValid = retirement.mode != RET_KEY;
}

static bool retirement_base58_encode(const unsigned char *data, size_t size,
                                      char *out, size_t capacity, size_t *written)
{
    (void)out; (void)capacity; (void)written;
    retirement.scratch = (uintptr_t)data;
    retirement.scratch_size = size;
    retirement.codec_calls++;
    return retirement.mode != RET_ENCODE_FAIL;
}

static bool retirement_base58_decode(const char *text, unsigned char *data,
                                      size_t capacity, size_t *written)
{
    (void)text;
    retirement.scratch = (uintptr_t)data;
    retirement.scratch_size = capacity;
    retirement.codec_calls++;
    /* Populate before returning a forced failure, so refusal cleanup is live. */
    memset(data, 0x5a, capacity);
    memcpy(data, retirement_version, sizeof(retirement_version));
    if (retirement.mode == RET_VERSION) data[0] ^= 1;
    *written = retirement.mode == RET_SHORT ? 77 : 78;
    return retirement.mode != RET_DECODE_FAIL;
}

#define hd_serialize_xprv retirement_serialize
#define hd_deserialize_xprv retirement_deserialize
#define ext_key_encode retirement_encode
#define ext_key_decode retirement_decode
#define domain_encoding_base58check_encode retirement_base58_encode
#define domain_encoding_base58check_decode retirement_base58_decode
#define memory_cleanse retirement_cleanse
#include "../../../contexts/wallet/modules/wallet/src/hd_xprv.c"
#undef hd_serialize_xprv
#undef hd_deserialize_xprv
#undef ext_key_encode
#undef ext_key_decode
#undef domain_encoding_base58check_encode
#undef domain_encoding_base58check_decode
#undef memory_cleanse

static int retirement_test_encode(enum retirement_case mode)
{
    memset(&retirement, 0, sizeof(retirement));
    retirement.mode = mode;
    struct ext_key key = {0};
    char out[HD_XKEY_STRING_SIZE];
    bool ok = retirement_serialize(&key, retirement_version, out, sizeof(out));
    bool pass = ok == (mode == RET_OK) && retirement.codec_calls == 1 &&
                retirement.key_calls == 1 && retirement.cleanses == 1 &&
                retirement.payload_retired && retirement.scratch_retired;
    printf("hd_xprv_retirement: encode mode=%d all scratch retired: %s\n",
           (int)mode, pass ? "OK" : "FAIL");
    return !pass;
}

static int retirement_test_decode(enum retirement_case mode)
{
    memset(&retirement, 0, sizeof(retirement));
    retirement.mode = mode;
    struct ext_key key = {0};
    bool ok = retirement_deserialize("synthetic", retirement_version, &key);
    unsigned key_calls = mode == RET_OK || mode == RET_KEY ? 1 : 0;
    bool pass = ok == (mode == RET_OK) && retirement.codec_calls == 1 &&
                retirement.key_calls == key_calls && retirement.cleanses == 1 &&
                retirement.scratch_retired;
    printf("hd_xprv_retirement: decode mode=%d scratch retired: %s\n",
           (int)mode, pass ? "OK" : "FAIL");
    return !pass;
}

int hd_xprv_retirement_tests(void)
{
    return retirement_test_encode(RET_OK) + retirement_test_encode(RET_ENCODE_FAIL) +
           retirement_test_decode(RET_OK) + retirement_test_decode(RET_DECODE_FAIL) +
           retirement_test_decode(RET_SHORT) + retirement_test_decode(RET_VERSION) +
           retirement_test_decode(RET_KEY);
}
