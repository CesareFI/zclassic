/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "wallet/wallet_db.h"
#include "support/cleanse.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t fixture_seed_len;
static bool fixture_freed;
static bool fixture_retired;

static bool fixture_db_read(struct db_wrapper *db, const char *key,
                            size_t key_len, char **value, size_t *value_len)
{
    (void)db;
    (void)key;
    (void)key_len;
    *value = malloc(fixture_seed_len);
    if (!*value)
        return false;
    memset(*value, 0xa5, fixture_seed_len);
    *value_len = fixture_seed_len;
    return true;
}

static void observe_seed_cleanse(void *bytes, size_t length)
{
    memory_cleanse(bytes, length);
}

static void observe_seed_free(void *bytes)
{
    const unsigned char *span = bytes;
    fixture_retired = true;
    for (size_t i = 0; i < fixture_seed_len; ++i)
        if (span[i] != 0)
            fixture_retired = false;
    fixture_freed = true;
    free(bytes);
}

static bool span_is_byte(const uint8_t *span, size_t length, uint8_t value)
{
    for (size_t i = 0; i < length; ++i)
        if (span[i] != value)
            return false;
    return true;
}

#define db_read fixture_db_read
#define memory_cleanse observe_seed_cleanse
#define free observe_seed_free
#define wallet_db_open retirement_wallet_db_open
#define wallet_db_close retirement_wallet_db_close
#define wallet_db_read_keys retirement_wallet_db_read_keys
#define wallet_db_read_txs retirement_wallet_db_read_txs
#define wallet_db_read_scan_height retirement_wallet_db_read_scan_height
#define wallet_db_read_sapling_seed retirement_wallet_db_read_sapling_seed
#define wallet_db_read_sapling_keys retirement_wallet_db_read_sapling_keys
#define wallet_db_read_scripts retirement_wallet_db_read_scripts
#include "../../../contexts/wallet/modules/wallet/src/wallet_db.c"
#undef wallet_db_read_scripts
#undef wallet_db_read_sapling_keys
#undef wallet_db_read_sapling_seed
#undef wallet_db_read_scan_height
#undef wallet_db_read_txs
#undef wallet_db_read_keys
#undef wallet_db_close
#undef wallet_db_open
#undef free
#undef memory_cleanse
#undef db_read

static bool retirement_case(size_t stored_len, bool expected_result)
{
    struct wallet_db db = {0};
    uint8_t seed[32];
    memset(seed, 0x3c, sizeof(seed));
    db.open = true;
    fixture_seed_len = stored_len;
    fixture_freed = false;
    fixture_retired = false;
    bool result = retirement_wallet_db_read_sapling_seed(&db, seed);
    uint8_t expected_byte = expected_result ? 0xa5 : 0x3c;
    bool output_ok = span_is_byte(seed, sizeof(seed), expected_byte);
    return result == expected_result && output_ok && fixture_freed &&
           fixture_retired;
}

int wallet_db_seed_retirement_cases(void);
int wallet_db_seed_retirement_cases(void)
{
    bool okay = retirement_case(32, true) && retirement_case(31, false);
    printf("wallet_persistence: LevelDB seed allocation retirement... %s\n",
           okay ? "OK" : "FAIL");
    return okay ? 0 : 1;
}
