/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Encoding and core utility tests: uint256, base58, bech32, arith_uint256,
 * random, time, consensus upgrades, money, string encoding, version,
 * chainparams, noui, deprecation, timedata, ConvertBits. */

#include "test/test_core.h"
#include "domain/encoding/base58.h"
#include "domain/encoding/bech32.h"
#include "core/arith_uint256.h"
#include "core/random.h"
#include "core/utiltime.h"
#include "consensus/upgrades.h"
#include "encoding/utilmoneystr.h"
#include "encoding/utilstrencodings.h"
#include "util/clientversion.h"
#include "chain/chainparamsbase.h"
#include "util/util.h"
#include "util/ui_interface.h"
#include "util/noui.h"
#include "util/timedata.h"

#include <errno.h>
#include "platform/clock.h"

static int sanitize_capacity_cases(void)
{
    int failures = 0;
    const char *inputs[] = { "", "hello" };
    const int rules[] = { SAFE_CHARS_DEFAULT, SAFE_CHARS_UA_COMMENT };
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        for (size_t r = 0; r < sizeof(rules) / sizeof(rules[0]); r++) {
            char guard = 'X';
            SanitizeString(inputs[i], rules[r], &guard, 0);
            if (guard != 'X') {
                printf("FAIL: SanitizeString capacity 0 input %zu rule %d\n", i, rules[r]);
                failures++;
            }
            char bounded[] = { 'X', 'X' };
            SanitizeString(inputs[i], rules[r], bounded, 1);
            if (bounded[0] != '\0' || bounded[1] != 'X') {
                printf("FAIL: SanitizeString capacity 1 input %zu rule %d\n", i, rules[r]);
                failures++;
            }
        }
    }
    return failures;
}

static int64_t encoding_fixed_wall_ms(void *self)
{
    (void)self;
    return 1700000123000LL;
}

static int64_t encoding_fixed_monotonic_ns(void *self)
{
    (void)self;
    return 123000000000LL;
}

static const clock_iface_t encoding_clock = {
    .now_monotonic_ns = encoding_fixed_monotonic_ns,
    .now_wall_ms = encoding_fixed_wall_ms,
};

/* Each zero-capacity row detects the unconditional terminator store. */
static int encoding_base64_zero_capacity(void)
{
    const char *inputs[] = { "", "Hello" };
    int failures = 0;
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        char guarded[] = { 'X', 'X', 'X' };
        size_t written = EncodeBase64((const unsigned char *)inputs[i],
                                      strlen(inputs[i]), guarded + 1, 0);
        printf("EncodeBase64 length=%zu capacity=0... ", strlen(inputs[i]));
        if (written == 0 && memcmp(guarded, "XXX", sizeof(guarded)) == 0)
            printf("OK\n");
        else {
            printf("FAIL: written=%zu guard=%d\n", written, guarded[1]);
            failures++;
        }
    }
    return failures;
}

/* Compatibility controls: these retain the positive-capacity behavior. */
static int encoding_base64_positive_capacities(void)
{
    static const struct {
        const char *input;
        size_t len, capacity, written;
        char expected[12];
    } cases[] = {
        { "", 0, 1, 0, "X\0XXXXXXXXX" },
        { "Hello", 5, 1, 0, "X\0XXXXXXXXX" },
        { "Hello", 5, 9, 8, "XSGVsbG8=\0X" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char guarded[11];
        memset(guarded, 'X', sizeof(guarded));
        size_t written = EncodeBase64((const unsigned char *)cases[i].input,
                                      cases[i].len, guarded + 1, cases[i].capacity);
        printf("EncodeBase64 length=%zu capacity=%zu... ",
               cases[i].len, cases[i].capacity);
        if (written == cases[i].written &&
            memcmp(guarded, cases[i].expected, sizeof(guarded)) == 0)
            printf("OK\n");
        else {
            printf("FAIL: written=%zu expected=%zu\n", written, cases[i].written);
            failures++;
        }
    }
    return failures;
}

static int encoding_uint256_base58(void)
{
    int failures = 0;

    printf("uint256 hex... ");
    struct uint256 u;
    uint256_set_hex(&u, "00000000000000000000000000000000000000000000000000000000deadbeef");
    char hexbuf[65];
    uint256_get_hex(&u, hexbuf);
    if (strcmp(hexbuf, "00000000000000000000000000000000000000000000000000000000deadbeef") == 0) {
        printf("OK\n");
    } else {
        printf("FAIL: %s\n", hexbuf);
        failures++;
    }

    printf("base58 encode... ");
    {
        const unsigned char data[] = { 0x00, 0x01, 0x02, 0x03 };
        char b58[64];
        size_t b58_len;
        domain_encoding_base58_encode(data, 4, b58, sizeof(b58), &b58_len);
        if (strcmp(b58, "1Ldp") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", b58);
            failures++;
        }
    }

    printf("base58 decode... ");
    {
        unsigned char out[64];
        size_t out_len;
        if (domain_encoding_base58_decode("1Ldp", out, sizeof(out), &out_len) &&
            out_len == 4 && out[0] == 0x00 && out[1] == 0x01 && out[2] == 0x02 && out[3] == 0x03)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("base58check roundtrip... ");
    {
        const unsigned char payload[] = { 0x00, 0x14, 0x01, 0x02, 0x03 };
        char encoded[128];
        size_t enc_len;
        domain_encoding_base58check_encode(payload, 5, encoded, sizeof(encoded), &enc_len);
        unsigned char decoded[128];
        size_t dec_len;
        if (domain_encoding_base58check_decode(encoded, decoded, sizeof(decoded), &dec_len) &&
            dec_len == 5 && memcmp(decoded, payload, 5) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("bech32 encode... ");
    {
        uint8_t values[] = { 0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22 };
        char out[128];
        if (domain_encoding_bech32_encode(out, sizeof(out), "bc", values, 33) && strlen(out) > 0)
            printf("OK (%s)\n", out);
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int encoding_bech32_arithmetic(void)
{
    int failures = 0;

    printf("bech32 decode... ");
    {
        char hrp[16];
        uint8_t data[128];
        size_t data_len;
        if (domain_encoding_bech32_decode(hrp, sizeof(hrp), data, sizeof(data), &data_len, "a12uel5l") &&
            strcmp(hrp, "a") == 0 && data_len == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("bech32 roundtrip... ");
    {
        uint8_t values[] = { 1, 2, 3, 4, 5 };
        char encoded[128];
        domain_encoding_bech32_encode(encoded, sizeof(encoded), "test", values, 5);
        char hrp[16];
        uint8_t decoded[128];
        size_t dec_len;
        if (domain_encoding_bech32_decode(hrp, sizeof(hrp), decoded, sizeof(decoded), &dec_len, encoded) &&
            strcmp(hrp, "test") == 0 && dec_len == 5 &&
            memcmp(decoded, values, 5) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("arith_uint256 compact roundtrip... ");
    {
        struct arith_uint256 target;
        bool neg, ovf;
        arith_uint256_set_compact(&target, 0x1d00ffff, &neg, &ovf);
        uint32_t compact = arith_uint256_get_compact(&target, false);
        if (compact == 0x1d00ffff && !neg && !ovf)
            printf("OK\n");
        else {
            printf("FAIL: compact=0x%08x neg=%d ovf=%d\n", compact, neg, ovf);
            failures++;
        }
    }

    printf("arith_uint256 arithmetic... ");
    {
        struct arith_uint256 a, b, r;
        arith_uint256_set_u64(&a, 0xFFFFFFFF);
        arith_uint256_set_u64(&b, 2);
        arith_uint256_mul_u32(&r, &a, 2);
        if (arith_uint256_get_low64(&r) == 0x1FFFFFFFE)
            printf("OK\n");
        else {
            printf("FAIL: got 0x%llx\n", (unsigned long long)arith_uint256_get_low64(&r));
            failures++;
        }
    }

    printf("arith_uint256 shift... ");
    {
        struct arith_uint256 a, r;
        arith_uint256_set_u64(&a, 1);
        arith_uint256_shl(&r, &a, 64);
        if (r.pn[2] == 1 && r.pn[0] == 0 && r.pn[1] == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int encoding_arithmetic_random_time(void)
{
    int failures = 0;

    printf("arith_uint256 division... ");
    {
        struct arith_uint256 a, b, r;
        arith_uint256_set_u64(&a, 100);
        arith_uint256_set_u64(&b, 7);
        arith_uint256_div(&r, &a, &b);
        if (arith_uint256_get_low64(&r) == 14)
            printf("OK\n");
        else {
            printf("FAIL: got %llu\n", (unsigned long long)arith_uint256_get_low64(&r));
            failures++;
        }
    }

    printf("arith_uint256 <-> uint256 conversion... ");
    {
        struct uint256 u2;
        uint256_set_hex(&u2, "00000000000000000000000000000000000000000000000000000000deadbeef");
        struct arith_uint256 a;
        uint256_to_arith(&a, &u2);
        struct uint256 u3;
        arith_to_uint256(&u3, &a);
        char hex[65];
        uint256_get_hex(&u3, hex);
        if (strcmp(hex, "00000000000000000000000000000000000000000000000000000000deadbeef") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", hex);
            failures++;
        }
    }

    printf("random bytes... ");
    {
        unsigned char buf[32];
        memset(buf, 0, 32);
        GetRandBytes(buf, 32);
        int nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (buf[i] != 0) nonzero++;
        if (nonzero > 0)
            printf("OK (%d non-zero bytes)\n", nonzero);
        else {
            printf("FAIL: all zeros\n");
            failures++;
        }
    }

    printf("GetRand... ");
    {
        uint64_t r = GetRand(100);
        if (r < 100)
            printf("OK (%llu)\n", (unsigned long long)r);
        else {
            printf("FAIL: %llu >= 100\n", (unsigned long long)r);
            failures++;
        }
    }

    printf("GetTime... ");
    {
        const clock_iface_t *saved_clock = clock_default();
        clock_set_default(&encoding_clock);
        int64_t t = GetTime();
        clock_set_default(saved_clock);
        if (t == 1700000123)
            printf("OK (%lld)\n", (long long)t);
        else {
            printf("FAIL: %lld\n", (long long)t);
            failures++;
        }
    }

    printf("DateTimeStrFormat... ");
    {
        char buf[64];
        DateTimeStrFormat(buf, sizeof(buf), "%Y-%m-%d", 0);
        if (strcmp(buf, "1970-01-01") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", buf);
            failures++;
        }
    }

    printf("consensus upgrade state... ");
    {
        struct consensus_params params;
        memset(&params, 0, sizeof(params));
        params.vUpgrades[BASE_SPROUT].nActivationHeight = NETWORK_UPGRADE_ALWAYS_ACTIVE;
        params.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 100;
        params.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 200;
        params.vUpgrades[UPGRADE_TESTDUMMY].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
        params.vUpgrades[UPGRADE_BUBBLES].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
        params.vUpgrades[UPGRADE_DIFFADJ].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
        params.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;

        if (consensus_upgrade_state(50, &params, UPGRADE_OVERWINTER) == UPGRADE_PENDING &&
            consensus_upgrade_state(100, &params, UPGRADE_OVERWINTER) == UPGRADE_ACTIVE &&
            consensus_upgrade_state(50, &params, UPGRADE_TESTDUMMY) == UPGRADE_DISABLED &&
            consensus_current_epoch(150, &params) == UPGRADE_OVERWINTER &&
            consensus_current_epoch(250, &params) == UPGRADE_SAPLING)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("FormatMoney... ");
    {
        char buf[64];
        FormatMoney(100000000, buf, sizeof(buf));
        if (strcmp(buf, "1.0") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", buf);
            failures++;
        }
    }

    return failures;
}

static int encoding_money_hex_base64(void)
{
    int failures = 0;

    printf("ParseMoney... ");
    {
        CAmount val = 0;
        if (ParseMoney("1.5", &val) && val == 150000000)
            printf("OK\n");
        else {
            printf("FAIL: %lld\n", (long long)val);
            failures++;
        }
    }

    printf("IsHex... ");
    {
        if (IsHex("deadbeef") && !IsHex("deadbee") && !IsHex("xyz"))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("ParseHex... ");
    {
        unsigned char out[32];
        size_t n = ParseHex("deadbeef", out, sizeof(out));
        if (n == 4 && out[0] == 0xde && out[1] == 0xad && out[2] == 0xbe && out[3] == 0xef)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("HexStr... ");
    {
        unsigned char data[] = { 0xde, 0xad, 0xbe, 0xef };
        char hexout[64];
        HexStr(data, 4, false, hexout, sizeof(hexout));
        if (strcmp(hexout, "deadbeef") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", hexout);
            failures++;
        }
    }

    printf("EncodeBase64... ");
    {
        char b64[64];
        EncodeBase64((const unsigned char *)"Hello", 5, b64, sizeof(b64));
        if (strcmp(b64, "SGVsbG8=") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", b64);
            failures++;
        }
    }

    return failures;
}

static int encoding_decoding_parsing(void)
{
    int failures = 0;

    printf("DecodeBase64... ");
    {
        unsigned char out[64];
        bool invalid = false;
        size_t n = DecodeBase64("SGVsbG8=", out, sizeof(out), &invalid);
        if (!invalid && n == 5 && memcmp(out, "Hello", 5) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("EncodeBase32... ");
    {
        char b32[64];
        EncodeBase32((const unsigned char *)"Hello", 5, b32, sizeof(b32));
        if (strcmp(b32, "jbswy3dp") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", b32);
            failures++;
        }
    }

    printf("ParseInt32... ");
    {
        int32_t val = 0;
        if (ParseInt32("12345", &val) && val == 12345 &&
            !ParseInt32("", &val) && !ParseInt32(" 1", &val))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("ParseFixedPoint... ");
    {
        int64_t amount = 0;
        if (ParseFixedPoint("1.5", 8, &amount) && amount == 150000000LL &&
            ParseFixedPoint("-0.5", 8, &amount) && amount == -50000000LL)
            printf("OK\n");
        else {
            printf("FAIL: %lld\n", (long long)amount);
            failures++;
        }
    }

    printf("SanitizeString... ");
    {
        char out[64];
        SanitizeString("hello<world>&test", SAFE_CHARS_DEFAULT, out, sizeof(out));
        if (strcmp(out, "helloworldtest") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", out);
            failures++;
        }
    }

    printf("FormatVersion... ");
    {
        char ver[64];
        FormatVersion(CLIENT_VERSION, ver, sizeof(ver));
        if (strstr(ver, "0.1.0") != NULL)
            printf("OK (%s)\n", ver);
        else {
            printf("FAIL: %s\n", ver);
            failures++;
        }
    }

    return failures;
}

static int encoding_parameters_datadirs(void)
{
    int failures = 0;

    printf("CLIENT_NAME... ");
    {
        if (strcmp(CLIENT_NAME, "ZClassic23") == 0)
            printf("OK\n");
        else {
            printf("FAIL: %s\n", CLIENT_NAME);
            failures++;
        }
    }

    printf("ParseParameters... ");
    {
        const char *argv[] = { "test", "-foo=bar", "-debug", "-baz=42" };
        ParseParameters(4, argv);
        if (strcmp(GetArg("-foo", ""), "bar") == 0 &&
            GetBoolArg("-debug", false) == true &&
            GetArgInt("-baz", 0) == 42 &&
            strcmp(GetArg("-noexist", "default"), "default") == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    /* GetDataDir() and SetDataDir() mkdir their argument unconditionally
     * (platform/modules/util/src/util.c). The assertion is about the returned
     * STRING, so use a per-process path under ./test-tmp/ that cleans up. */
    printf("GetDataDir cache invalidates on ParseParameters... ");
    {
        char before[1024];
        char after[1024];
        char datadir[512];
        char datadir_arg[600];
        test_make_tmpdir(datadir, sizeof(datadir), "encoding_datadir", "cache");
        snprintf(datadir_arg, sizeof(datadir_arg), "-datadir=%s", datadir);
        const char *empty_argv[] = { "test" };
        const char *datadir_argv[] = { "test", datadir_arg };

        ParseParameters(1, empty_argv);
        GetDataDir(false, before, sizeof(before));
        ParseParameters(2, datadir_argv);
        GetDataDir(false, after, sizeof(after));

        if (strcmp(after, datadir) == 0 &&
            strcmp(before, after) != 0)
            printf("OK\n");
        else {
            printf("FAIL: before=%s after=%s\n", before, after);
            failures++;
        }
        (void)test_rm_rf_recursive(datadir);
    }

    printf("SetDataDir overrides cached default... ");
    {
        char before[1024];
        char after[1024];
        char datadir[512];
        test_make_tmpdir(datadir, sizeof(datadir), "encoding_datadir",
                         "selected");
        const char *empty_argv[] = { "test" };

        ParseParameters(1, empty_argv);
        GetDataDir(false, before, sizeof(before));
        SetDataDir(datadir);
        GetDataDir(false, after, sizeof(after));

        if (strcmp(after, datadir) == 0 &&
            strcmp(before, after) != 0)
            printf("OK\n");
        else {
            printf("FAIL: before=%s after=%s\n", before, after);
            failures++;
        }

        ParseParameters(1, empty_argv);
        ClearDataDirCache();
        (void)test_rm_rf_recursive(datadir);
    }

    return failures;
}

static int encoding_datadir_runtime(void)
{
    int failures = 0;

    printf("SetDataDir refuses a symlinked directory... ");
    {
        char root[512], target[600], datadir[600];
        test_make_tmpdir(root, sizeof(root), "encoding_datadir", "symlink");
        snprintf(target, sizeof(target), "%s/target", root);
        snprintf(datadir, sizeof(datadir), "%s/selected", root);
        bool fixture_ready = mkdir(target, 0700) == 0 &&
                             symlink(target, datadir) == 0;
        errno = 0;
        bool refused = fixture_ready && !SetDataDir(datadir) &&
                       errno == EACCES;
        bool recovered = unlink(datadir) == 0 && mkdir(datadir, 0700) == 0 &&
                         SetDataDir(datadir);

        if (refused && recovered)
            printf("OK\n");
        else {
            printf("FAIL: fixture=%d refused=%d recovered=%d errno=%d\n",
                   fixture_ready, refused, recovered, errno);
            failures++;
        }

        SetDataDir("");
        ClearDataDirCache();
        (void)test_rm_rf_recursive(root);
    }

    printf("GetNumCores... ");
    {
        int n = GetNumCores();
        if (n >= 1)
            printf("OK (%d)\n", n);
        else {
            printf("FAIL: %d\n", n);
            failures++;
        }
    }

    printf("chainparamsbase... ");
    {
        SelectBaseParams(CHAIN_MAIN);
        const struct base_chain_params *p = BaseParams();
        if (p->nRPCPort == 8023 && AreBaseParamsConfigured()) {
            SelectBaseParams(CHAIN_TESTNET);
            p = BaseParams();
            if (p->nRPCPort == 18023 && strcmp(p->strDataDir, "testnet3") == 0)
                printf("OK\n");
            else {
                printf("FAIL: testnet\n");
                failures++;
            }
        } else {
            printf("FAIL: main\n");
            failures++;
        }
    }

    printf("noui_connect... ");
    {
        noui_connect();
        if (uiInterface.ThreadSafeMessageBox != NULL &&
            uiInterface.InitMessage != NULL)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int encoding_adjusted_time_bits(void)
{
    int failures = 0;

    printf("GetAdjustedTime... ");
    {
        const clock_iface_t *saved_clock = clock_default();
        clock_set_default(&encoding_clock);
        int64_t t = GetAdjustedTime();
        clock_set_default(saved_clock);
        if (t == 1700000123 + GetTimeOffset())
            printf("OK (%lld)\n", (long long)t);
        else {
            printf("FAIL: %lld\n", (long long)t);
            failures++;
        }
    }

    printf("ConvertBits 8->5... ");
    {
        unsigned char in[] = { 0xff, 0x00 };
        unsigned char out[8];
        size_t out_len = 0;
        if (ConvertBits(8, 5, true, in, 2, out, sizeof(out), &out_len) &&
            out_len == 4 && out[0] == 0x1f && out[1] == 0x1c && out[2] == 0x00 && out[3] == 0x00)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static bool encoding_hex_buffer_matches(const char *actual, size_t size,
                                       const char *expect, size_t pairs)
{
    size_t nul = pairs * 2u;
    if (memcmp(actual, expect, nul) != 0 || actual[nul] != '\0')
        return false;
    for (size_t k = nul + 1u; k < size; k++)
        if (actual[k] != 'Z')
            return false;
    return true;
}

/* Expected strings come from plain bit arithmetic, not HexStr. Covers
 * lengths 0 to 96 (spanning the NEON fast path's 16-byte threshold, all
 * vector lanes and the scalar tail) against exact-fit, one-short and
 * one-long buffers; sentinel padding proves nothing beyond the
 * terminating NUL was written. */
static int encoding_hex_oracle(void)
{
    int failures = 0;

    printf("HexStr oracle sweep... ");
    {
        static const char digits[] = "0123456789abcdef";
        unsigned char src[97];
        char expect[197], actual[256];
        bool ok = true;

        for (size_t i = 0; i < sizeof(src); i++)
            src[i] = (unsigned char)(i * 37u + 11u);

        for (size_t n = 0; n < sizeof(src); n++) {
            for (size_t t = 0; t < 2u * n; t++)
                expect[t] = digits[(src[t / 2] >> ((t % 2) ? 0 : 4)) & 0xF];
            expect[2 * n] = '\0';

            size_t sizes[] = { 1, 2, 3, 2u * n, 2u * n + 1u,
                               2u * n + 2u };
            for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]) && ok;
                 s++) {
                size_t os = sizes[s];
                if (os == 0 || os > sizeof(actual))
                    continue;
                memset(actual, 'Z', sizeof(actual));
                HexStr(src, n, false, actual, os);
                size_t pairs = (os - 1u) / 2u;
                if (pairs > n)
                    pairs = n;
                ok = encoding_hex_buffer_matches(actual, sizeof(actual), expect, pairs);
            }
        }
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok)
            failures++;
    }

    return failures;
}

/* Overlap must retain the scalar loop's established byte order even when
 * the process-wide implementation tier is NEON. */
static int encoding_hex_variants(void)
{
    int failures = 0;

    printf("HexStr overlap fallback... ");
    {
        unsigned char actual[64], expect[64];
        for (size_t i = 0; i < sizeof(actual); i++)
            actual[i] = expect[i] = (unsigned char)(i * 19u + 3u);
        static const char digits[] = "0123456789abcdef";
        size_t j = 0;
        for (size_t i = 0; i < 20; i++) {
            expect[j++] = (unsigned char)digits[expect[i] >> 4];
            expect[j++] = (unsigned char)digits[expect[i] & 0x0f];
        }
        expect[j] = '\0';
        HexStr(actual, 20, false, (char *)actual, sizeof(actual));
        bool ok = memcmp(actual, expect, sizeof(actual)) == 0;
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok)
            failures++;
    }

    /* --- IsHex: accept/reject table ------------------------------------------ */
    printf("IsHex table... ");
    {
        static const struct { const char *s; bool want; } cases[] = {
            { "", false },
            { "a", false },
            { "ab", true },
            { "deadbeef", true },
            { "DEADBEEF", true },
            { "DeadBeef", true },
            { "deadbee", false },      /* odd length      */
            { "xyz", false },
            { "0123456789abcdef", true },
            { "gh", false },           /* just past range */
            { "`a", false },           /* '`' = 0x60, below 'a' */
            { "g\0b", false },         /* odd after embedded NUL */
            { "ab\0cd", true },        /* strlen stops at the NUL: len 2, even */
            { "00112233445566778899aabbccddeeff", true },
            { "  ab", false },
            { "ab ", false },
        };
        bool ok = true;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            if (IsHex(cases[i].s) != cases[i].want) ok = false;
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok)
            failures++;
    }

    /* --- HexStr: the spaced form keeps its own shape ------------------------- */
    printf("HexStr spaces path... ");
    {
        unsigned char data[] = { 0xde, 0xad, 0xbe, 0xef };
        char out[64];
        memset(out, 'Z', sizeof(out));
        HexStr(data, sizeof(data), true, out, sizeof(out));
        int bad = strcmp(out, "de ad be ef");
        printf("%s\n", bad == 0 ? "OK" : "FAIL");
        if (bad != 0) {
            printf("  got \"%s\"\n", out);
            failures++;
        }
    }

    /* --- HexStr: name the live encoder tier ---------------------------------
     * Observability only: the reported HexStr_impl_name() tier has already
     * passed the known-answer gate and the sweep above; recording it makes a
     * failure legible as "this build shipped the NEON tier". */
    printf("HexStr_impl_name... ");
    {
        const char *impl = HexStr_impl_name();
        if (impl != NULL && *impl != '\0')
            printf("OK (%s)\n", impl);
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

int test_encoding(void)
{
    int failures = 0;
    failures += sanitize_capacity_cases();
    failures += encoding_uint256_base58();
    failures += encoding_bech32_arithmetic();
    failures += encoding_arithmetic_random_time();
    failures += encoding_money_hex_base64();
    failures += encoding_base64_zero_capacity();
    failures += encoding_base64_positive_capacities();
    failures += encoding_decoding_parsing();
    failures += encoding_parameters_datadirs();
    failures += encoding_datadir_runtime();
    failures += encoding_adjusted_time_bits();
    failures += encoding_hex_oracle();
    failures += encoding_hex_variants();
    return failures;
}
