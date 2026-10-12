/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: BIP32 private-key serialization with one owned scratch buffer,
 * retired on every return after acquisition. No derivation or format changes. */
#include "wallet/hd_keychain.h"
#include "domain/encoding/base58.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>

#define DOMAIN "hd"
#define BIP32_SERIALIZED_SIZE 78
static_assert(BIP32_SERIALIZED_SIZE == 4 + BIP32_EXTKEY_SIZE,
              "version and key payload must fit the serialized scratch");

bool hd_serialize_xprv(const struct ext_key *ek,
                       const unsigned char version[4],
                       char *out, size_t out_size)
{
    GUARD_NOT_NULL(ek, DOMAIN, "ek");
    GUARD_NOT_NULL(version, DOMAIN, "version");
    GUARD_NOT_NULL(out, DOMAIN, "out");
    GUARD(out_size >= HD_XKEY_STRING_SIZE,
          DOMAIN, "out_size too small: %zu", out_size);

    unsigned char data[BIP32_SERIALIZED_SIZE];
    memcpy(data, version, 4);
    /* Encode directly into the owned buffer: no second private-key copy. */
    ext_key_encode(ek, data + 4);
    size_t written = 0;
    bool ok = domain_encoding_base58check_encode(data, sizeof(data), out, out_size, &written);
    memory_cleanse(data, sizeof(data));
    if (!ok)
        LOG_FAIL(DOMAIN, "base58check_encode failed for xprv");
    return true;
}

bool hd_deserialize_xprv(const char *str,
                         const unsigned char expected_version[4],
                         struct ext_key *ek_out)
{
    GUARD_NOT_NULL(str, DOMAIN, "str");
    GUARD_NOT_NULL(expected_version, DOMAIN, "expected_version");
    GUARD_NOT_NULL(ek_out, DOMAIN, "ek_out");

    unsigned char data[BIP32_SERIALIZED_SIZE + 4];
    size_t decoded_len = 0;
    if (!domain_encoding_base58check_decode(str, data, sizeof(data), &decoded_len)) {
        memory_cleanse(data, sizeof(data));
        LOG_FAIL(DOMAIN, "base58check_decode failed for xprv");
    }
    if (decoded_len != BIP32_SERIALIZED_SIZE) {
        memory_cleanse(data, sizeof(data));
        LOG_FAIL(DOMAIN, "unexpected decoded length: %zu (expected %d)",
                 decoded_len, BIP32_SERIALIZED_SIZE);
    }
    if (memcmp(data, expected_version, 4) != 0) {
        memory_cleanse(data, sizeof(data));
        LOG_FAIL(DOMAIN, "version mismatch in xprv");
    }
    ext_key_decode(ek_out, data + 4);
    memory_cleanse(data, sizeof(data));
    if (!privkey_is_valid(&ek_out->key))
        LOG_FAIL(DOMAIN, "decoded xprv has invalid private key");
    return true;
}
