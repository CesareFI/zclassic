#include "zrand/zrand.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int inject_output_failure;
static size_t injected_fwrite_result;

static int test_cli_printf(const char *format, ...)
{
    if (inject_output_failure == 1) return -1;
    if (inject_output_failure == 2) return 0;
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    return result;
}

static int test_cli_puts(const char *s)
{
    if (inject_output_failure == 1) return EOF;
    if (inject_output_failure == 2) return 0;
    return puts(s);
}

static size_t test_cli_fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
    if (inject_output_failure == 1) return injected_fwrite_result;
    if (inject_output_failure == 2) return count;
    return fwrite(ptr, size, count, stream);
}

static inline int test_cli_fflush(FILE *stream)
{
    return inject_output_failure == 2 ? EOF : fflush(stream);
}

#define fflush test_cli_fflush
#define printf test_cli_printf
#define puts test_cli_puts
#define fwrite test_cli_fwrite
#define main zrand_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef puts
#undef fwrite
#undef fflush

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_reference_vectors(void)
{
    /* Cross-checked against an independent Python implementation of
     * xoshiro256** with splitmix64 seeding (from the public spec). */
    static const uint64_t seed42_first10[10] = {
        1546998764402558742ull, 6990951692964543102ull,
        12544586762248559009ull, 17057574109182124193ull,
        18295552978065317476ull, 14199186830065750584ull,
        13267978908934200754ull, 15679888225317814407ull,
        14044878350692344958ull, 10760895422300929085ull
    };
    zrand r;
    zrand_seed(&r, 42);
    for (int i = 0; i < 10; i++)
        CHECK(zrand_u64(&r) == seed42_first10[i]);

    static const uint64_t seed0_first3[3] = {
        11091344671253066420ull, 13793997310169335082ull,
        1900383378846508768ull
    };
    zrand_seed(&r, 0);
    for (int i = 0; i < 3; i++)
        CHECK(zrand_u64(&r) == seed0_first3[i]);

    /* Determinism: reseed replays the stream. */
    zrand a, b;
    zrand_seed(&a, 12345);
    zrand_seed(&b, 12345);
    for (int i = 0; i < 100; i++)
        CHECK(zrand_u64(&a) == zrand_u64(&b));
}

static void test_bounded(void)
{
    zrand r;
    zrand_seed(&r, 7);

    /* Degenerate bounds. */
    CHECK(zrand_bounded(&r, 0) == 0);
    CHECK(zrand_bounded(&r, 1) == 0);

    /* Every draw in range, over many bounds including odd ones. */
    static const uint64_t bounds[] = {2, 3, 7, 10, 100, 255, 256, 1000,
                                      65535, 65536, UINT64_MAX};
    for (size_t bi = 0; bi < sizeof bounds / sizeof bounds[0]; bi++) {
        uint64_t bound = bounds[bi];
        for (int i = 0; i < 2000; i++) {
            uint64_t v = zrand_bounded(&r, bound);
            CHECK(v < bound);
        }
    }

    /* Coverage: small bound sees every value over enough draws. */
    zrand_seed(&r, 99);
    uint64_t seen = 0;
    for (int i = 0; i < 10000; i++)
        seen |= 1ull << zrand_bounded(&r, 16);
    CHECK(seen == 0xffff);

    /* Rough uniformity sanity on a tiny bound: each of 4 buckets
     * within 35%..65% of fair share over 100k draws. */
    zrand_seed(&r, 5);
    size_t counts[4] = {0, 0, 0, 0};
    for (int i = 0; i < 100000; i++)
        counts[zrand_bounded(&r, 4)]++;
    for (int i = 0; i < 4; i++) {
        CHECK(counts[i] > 22000);
        CHECK(counts[i] < 28000);
    }

    /* Range helper. */
    zrand_seed(&r, 11);
    CHECK(zrand_range(&r, 5, 5) == 0);
    CHECK(zrand_range(&r, 5, 3) == 0);
    for (int i = 0; i < 5000; i++) {
        uint64_t v = zrand_range(&r, 10, 20);
        CHECK(v >= 10 && v < 20);
    }
}

static void test_double_bool_bytes(void)
{
    zrand r;
    zrand_seed(&r, 77);
    for (int i = 0; i < 100000; i++) {
        double d = zrand_double(&r);
        CHECK(d >= 0.0 && d < 1.0);
    }

    zrand_seed(&r, 13);
    size_t ones = 0;
    for (int i = 0; i < 100000; i++)
        if (zrand_bool(&r)) ones++;
    CHECK(ones > 45000 && ones < 55000);

    /* Bytes: deterministic per seed. */
    uint8_t b1[37], b2[37];
    zrand_seed(&r, 21);
    zrand_bytes(&r, b1, sizeof b1);
    zrand ar;
    zrand_seed(&ar, 21);
    zrand_bytes(&ar, b2, sizeof b2);
    CHECK(memcmp(b1, b2, sizeof b1) == 0);
    /* Not constant. */
    int all_same = 1;
    for (size_t i = 1; i < sizeof b1; i++)
        if (b1[i] != b1[0]) all_same = 0;
    CHECK(!all_same);
}

static void test_shuffle(void)
{
    int arr[64];
    for (int i = 0; i < 64; i++) arr[i] = i;

    zrand r;
    zrand_seed(&r, 3);
    zrand_shuffle(&r, arr, 64, sizeof arr[0]);

    /* Permutation: every value still present exactly once. */
    int seen[64] = {0};
    for (int i = 0; i < 64; i++) {
        CHECK(arr[i] >= 0 && arr[i] < 64);
        seen[arr[i]]++;
    }
    for (int i = 0; i < 64; i++) CHECK(seen[i] == 1);

    /* Deterministic for the same seed, different across seeds. */
    int a2[64], b2[64];
    for (int i = 0; i < 64; i++) { a2[i] = i; b2[i] = i; }
    zrand_seed(&r, 3);
    zrand_shuffle(&r, a2, 64, sizeof a2[0]);
    CHECK(memcmp(arr, a2, sizeof arr) == 0);
    zrand_seed(&r, 4);
    zrand_shuffle(&r, b2, 64, sizeof b2[0]);
    CHECK(memcmp(arr, b2, sizeof arr) != 0);

    /* Degenerate sizes are safe. */
    zrand_shuffle(&r, arr, 0, sizeof arr[0]);
    zrand_shuffle(&r, arr, 1, sizeof arr[0]);
    zrand_shuffle(&r, NULL, 5, sizeof arr[0]);
}

static void test_jump(void)
{
    /* A jumped generator must not collide with the original stream
     * over a long window. */
    zrand a, b;
    zrand_seed(&a, 8);
    b = a;
    zrand_jump(&b);

    size_t collisions = 0;
    for (int i = 0; i < 100000; i++)
        if (zrand_u64(&a) == zrand_u64(&b)) collisions++;
    CHECK(collisions == 0);

    /* Jump is deterministic. */
    zrand c, d;
    zrand_seed(&c, 8);
    zrand_seed(&d, 8);
    zrand_jump(&c);
    zrand_jump(&d);
    CHECK(zrand_u64(&c) == zrand_u64(&d));

    /* long_jump differs from jump. */
    zrand e, f;
    zrand_seed(&e, 8);
    zrand_seed(&f, 8);
    zrand_jump(&e);
    zrand_long_jump(&f);
    CHECK(zrand_u64(&e) != zrand_u64(&f));
}

static void test_null_safety(void)
{
    zrand_seed(NULL, 1);
    CHECK(zrand_u64(NULL) == 0);
    CHECK(zrand_bounded(NULL, 10) == 0);
    CHECK(zrand_range(NULL, 1, 5) == 0);
    CHECK(zrand_double(NULL) == 0.0);
    zrand_bytes(NULL, NULL, 0);
    zrand_shuffle(NULL, NULL, 0, 0);
    zrand_jump(NULL);
    zrand_long_jump(NULL);
}

static void test_shuffle_large_items(void)
{
    unsigned failures = 0;
    const size_t sizes[] = {257, 512, 513};
    for (size_t row = 0; row < sizeof sizes / sizeof sizes[0]; row++) {
        size_t size = sizes[row];
        unsigned char actual[3 * 513 + 2], expected[sizeof actual];
        memset(actual, 0xa5, sizeof actual);
        for (size_t i = 0; i < 3; i++)
            for (size_t j = 0; j < size; j++)
                actual[1 + i * size + j] = (unsigned char)(i * 67 + j);
        memcpy(expected, actual, sizeof actual);
        zrand rng, reference;
        zrand_seed(&rng, 1234);
        reference = rng;
        for (size_t i = 2; i > 0; i--) {
            size_t k = (size_t)zrand_bounded(&reference, i + 1);
            for (size_t j = 0; j < size; j++) {
                unsigned char byte = expected[1 + i * size + j];
                expected[1 + i * size + j] = expected[1 + k * size + j];
                expected[1 + k * size + j] = byte;
            }
        }
        zrand_shuffle(&rng, actual + 1, 3, size);
        unsigned char held[4] = {1, 2, 3, 4};
        const unsigned char unchanged[4] = {1, 2, 3, 4};
        zrand invalid, saved;
        zrand_seed(&invalid, 1234);
        saved = invalid;
        zrand_shuffle(&invalid, held, 3, SIZE_MAX / 2 + 1);
        zrand_shuffle(&invalid, held, 2, SIZE_MAX - 10);
        int ok = memcmp(held, unchanged, sizeof held) == 0 &&
                 memcmp(&invalid, &saved, sizeof invalid) == 0 &&
                 memcmp(actual, expected, sizeof actual) == 0 &&
                 memcmp(&rng, &reference, sizeof rng) == 0;
        fprintf(stderr, "large_shuffle_row=%zu size=%zu result=%s\n", row,
                size, ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }
    CHECK(failures == 0);
}

static void test_shuffle_span_overflow(void)
{
    unsigned char bytes[4] = {1, 2, 3, 4};
    const unsigned char expected[4] = {1, 2, 3, 4};
    zrand rng, original;
    zrand_seed(&rng, 1234);
    original = rng;
    zrand_shuffle(&rng, bytes, SIZE_MAX / 2 + 1, 2);
    CHECK(memcmp(bytes, expected, sizeof bytes) == 0 &&
          memcmp(&rng, &original, sizeof rng) == 0);
}

static void test_cli_rejects_invalid_unsigned(void)
{
    const char *rows[] = {"", "-1", "18446744073709551616",
                          "18446744073709551616000000000"};
    unsigned failures = 0;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        int ok = 73;
        uint64_t value = parse_u64(rows[i], &ok);
        int rejected = !ok && value == 0;
        fprintf(stderr, "rand_unsigned_row=%zu result=%s\n", i,
                rejected ? "PASS" : "FAIL");
        if (!rejected) failures++;
    }
    CHECK(failures == 0);
}

static void test_cli_reports_output_failures(void)
{
    const char *ops[] = {"u64", "double", "bounded", "shuffle", "bytes", "bytes",
                         "u64", "double", "bounded", "shuffle", "bytes"};
    unsigned failures = 0;
    for (size_t row = 0; row < sizeof ops / sizeof ops[0]; row++) {
        char *args[] = {"zrand", (char *)ops[row], "42", "1", "1", NULL};
        size_t mode = row < 6 ? row : row - 6;
        int argc = 4;
        if (mode == 2) argc = 5;
        if (mode == 3) { args[3] = "a"; args[4] = "b"; argc = 5; }
        if (mode >= 4) args[3] = "4";
        inject_output_failure = row < 6 ? 1 : 2;
        injected_fwrite_result = row == 5 ? 2 : 0;
        int ok = zrand_cli_main(argc, args) == 1;
        inject_output_failure = 0;
        fprintf(stderr, "output_failure_row=%zu op=%s result=%s\n", row,
                ops[row], ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }
    CHECK(failures == 0);
}

int main(void)
{
    test_cli_reports_output_failures();
    test_cli_rejects_invalid_unsigned();
    test_shuffle_large_items();
    test_shuffle_span_overflow();
    test_reference_vectors();
    test_bounded();
    test_double_bool_bytes();
    test_shuffle();
    test_jump();
    test_null_safety();
    puts("test_zrand: all groups passed (vectors bounded double shuffle jump null)");
    return 0;
}
