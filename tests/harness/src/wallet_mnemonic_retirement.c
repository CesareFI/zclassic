/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "support/cleanse.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Compile the actual decoder with a live-span observer, without changing its
 * production ABI or inspecting expired stack storage. Other test groups retain
 * the ordinary implementation and its public BIP39 vectors. */
static unsigned index_wipes;
static bool erased, contained_indices;
static void observe_cleanse(void *bytes, size_t length)
{
    const unsigned char *span = bytes;
    if (length == 24 * sizeof(int)) {
        for (size_t i = 0; i < length; ++i)
            if (span[i] != 0) contained_indices = true;
    }
    memory_cleanse(bytes, length);
    if (length != 24 * sizeof(int)) return;
    ++index_wipes;
    for (size_t i = 0; i < length; ++i)
        if (span[i] != 0) erased = false;
}

#define memory_cleanse observe_cleanse
#define domain_wallet_mnemonic_wordlist_get retirement_wordlist_get
#define domain_wallet_mnemonic_wordlist_find retirement_wordlist_find
#define domain_wallet_mnemonic_entropy_bytes_for_words retirement_entropy_bytes
#define domain_wallet_mnemonic_normalize retirement_normalize
#define domain_wallet_mnemonic_from_entropy retirement_from_entropy
#define domain_wallet_mnemonic_to_entropy retirement_to_entropy
#define domain_wallet_mnemonic_validate retirement_validate
#define domain_wallet_mnemonic_to_seed retirement_to_seed
#include "../../../contexts/wallet/domain/src/mnemonic.c"
#undef memory_cleanse

static_assert(DOMAIN_WALLET_BIP39_MAX_WORDS == 24, "observer matches decoded index span");

static bool decode_and_retire(const char *phrase, bool expected_ok, bool expect_indices)
{
    uint8_t entropy[32];
    memset(entropy, 0xa5, sizeof(entropy));
    size_t length = 777;
    index_wipes = 0;
    erased = true;
    contained_indices = false;
    const struct zcl_result result = retirement_to_entropy(phrase, entropy, sizeof(entropy), &length);
    bool okay = result.ok == expected_ok && index_wipes == 1 && erased && contained_indices == expect_indices;
    if (!expected_ok) {
        for (size_t i = 0; i < sizeof(entropy); ++i)
            if (entropy[i] != 0xa5) okay = false;
    }
    memory_cleanse(entropy, sizeof(entropy));
    return okay;
}

static bool checksum_refusal(char *phrase, size_t capacity)
{
    char *last = strrchr(phrase, ' ');
    if (last == NULL) return false;
    const int index = retirement_wordlist_find(last + 1);
    if (index < 0) return false;
    const char *changed = retirement_wordlist_get(index ^ 1);
    const size_t length = strlen(changed) + 1;
    if ((size_t)(last + 1 - phrase) > capacity - length) return false;
    memcpy(last + 1, changed, length); /* Flip one checksum bit, same entropy. */
    return decode_and_retire(phrase, false, true);
}

static int decoded_indices(size_t entropy_length)
{
    /* Public synthetic bytes, never installed as a wallet or printed. */
    uint8_t entropy[32];
    memset(entropy, 0x7f, sizeof(entropy));
    char phrase[DOMAIN_WALLET_BIP39_PHRASE_MAX];
    size_t written = 0;
    const struct zcl_result encoded = retirement_from_entropy(entropy, entropy_length,
        phrase, sizeof(phrase), &written);
    if (!encoded.ok || written == 0) return 1;
    bool okay = decode_and_retire(phrase, true, true);
    okay = checksum_refusal(phrase, sizeof(phrase)) && okay;
    char *last = strrchr(phrase, ' ');
    if (last == NULL) return 1;
    /* An unknown final word follows admitted indices. */
    last[1] = '?'; last[2] = '\0';
    okay = decode_and_retire(phrase, false, true) && okay;
    *last = '\0'; /* Incorrect word count after admitted indices. */
    okay = decode_and_retire(phrase, false, true) && okay;
    phrase[0] = (char)0x80; phrase[1] = '\0'; /* Normalize failure before any index. */
    okay = decode_and_retire(phrase, false, false) && okay;
    memory_cleanse(entropy, sizeof(entropy));
    memory_cleanse(phrase, sizeof(phrase));
    return okay ? 0 : 1;
}

int wallet_mnemonic_retirement_cases(void);
int wallet_mnemonic_retirement_cases(void)
{
    const int failed = decoded_indices(16) + decoded_indices(32);
    printf("domain_wallet_mnemonic: decoded indices retire on success/refusal... %s\n",
        failed == 0 ? "OK" : "FAIL");
    return failed;
}
