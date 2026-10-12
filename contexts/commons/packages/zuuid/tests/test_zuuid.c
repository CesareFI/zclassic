#include "zuuid/zuuid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_nil(void)
{
    zuuid n = zuuid_nil();
    CHECK(zuuid_is_nil(&n));
    CHECK(zuuid_version(&n) == 0);
    CHECK(zuuid_variant(&n) == 0);

    char s[ZUUID_STR_LEN];
    CHECK(zuuid_format(&n, s) == ZUUID_OK);
    CHECK(strcmp(s, "00000000-0000-0000-0000-000000000000") == 0);
    CHECK(strlen(s) == 36);

    zuuid back;
    CHECK(zuuid_parse(s, &back) == ZUUID_OK);
    CHECK(zuuid_equal(&n, &back));
}

static void test_parse_strict(void)
{
    zuuid u;
    char s[ZUUID_STR_LEN];

    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_OK);
    CHECK(u.b[0] == 0xf8 && u.b[1] == 0x1d && u.b[15] == 0xf6);
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6") == 0);

    /* Uppercase accepted by parser; format is canonical lowercase. */
    CHECK(zuuid_parse("F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6", &u) == ZUUID_OK);
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6") == 0);
    CHECK(zuuid_format_upper(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6") == 0);

    /* Wrong length / hyphen placement / bad digit. */
    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6ff", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("f81d4fae_7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("g81d4fae-7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_ERR_BAD_CHAR);
    CHECK(zuuid_parse(NULL, &u) == ZUUID_ERR_NULL);
    CHECK(zuuid_parse(s, NULL) == ZUUID_ERR_NULL);
}

static void test_parse_lenient(void)
{
    zuuid a, b;
    const char *canon = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    CHECK(zuuid_parse(canon, &a) == ZUUID_OK);

    CHECK(zuuid_parse_lenient("f81d4fae7dec11d0a76500a0c91e6bf6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("F81D4FAE7DEC11D0A76500A0C91E6BF6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("{urn:uuid:f81d4fae7dec11d0a76500a0c91e6bf6}", &b) == ZUUID_OK);

    CHECK(zuuid_parse_lenient("xyz", &b) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse_lenient("f81d4fae7dec11d0a76500a0c91e6bg6", &b) == ZUUID_ERR_BAD_CHAR);
    CHECK(zuuid_parse_lenient(NULL, &b) == ZUUID_ERR_NULL);
}

static void test_parse_failure_preserves_uuid(void)
{
    const char *canon = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    zuuid before;
    memset(&before, 0xa5, sizeof before);
    for (size_t i = 0; i < 36; i++) {
        if (canon[i] == '-') continue;
        char malformed[ZUUID_STR_LEN];
        memcpy(malformed, canon, sizeof malformed);
        malformed[i] = 'g';
        for (int lenient = 0; lenient <= 1; lenient++) {
            zuuid out = before;
            zuuid_err err = lenient ? zuuid_parse_lenient(malformed, &out)
                                    : zuuid_parse(malformed, &out);
            CHECK(err == ZUUID_ERR_BAD_CHAR);
            CHECK(zuuid_equal(&out, &before));
            CHECK(zuuid_parse(canon, &out) == ZUUID_OK);
            CHECK(out.b[0] == 0xf8 && out.b[15] == 0xf6);
        }
    }
    zuuid out = before;
    CHECK(zuuid_parse(NULL, &out) == ZUUID_ERR_NULL);
    CHECK(zuuid_equal(&out, &before));
    CHECK(zuuid_parse("", &out) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_equal(&out, &before));
}

static void test_compare(void)
{
    zuuid a, b, c;
    CHECK(zuuid_parse("00000000-0000-0000-0000-000000000001", &a) == ZUUID_OK);
    CHECK(zuuid_parse("00000000-0000-0000-0000-000000000002", &b) == ZUUID_OK);
    CHECK(zuuid_parse("10000000-0000-0000-0000-000000000000", &c) == ZUUID_OK);

    CHECK(zuuid_compare(&a, &a) == 0);
    CHECK(zuuid_compare(&a, &b) < 0);
    CHECK(zuuid_compare(&b, &a) > 0);
    CHECK(zuuid_compare(&a, &c) < 0); /* last byte 1 < first byte 0x10 */
    CHECK(zuuid_compare(NULL, NULL) == 0);
    CHECK(zuuid_compare(NULL, &a) < 0);
    CHECK(zuuid_compare(&a, NULL) > 0);
    CHECK(!zuuid_equal(&a, &b));
}

/* Deterministic counter RNG for tests. */
struct counter_rng { uint64_t v; };
static int counter_fill(void *ctx, uint8_t *buf, size_t n)
{
    struct counter_rng *r = ctx;
    for (size_t i = 0; i < n; i++) {
        r->v = r->v * 6364136223846793005ull + 1442695040888963407ull;
        buf[i] = (uint8_t)(r->v >> 56);
    }
    return 0;
}
static int fail_rng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx; (void)buf; (void)n;
    return -1;
}

struct partial_rng { size_t written; int calls; };
static int partial_fail_rng(void *ctx, uint8_t *buf, size_t n)
{
    struct partial_rng *r = ctx;
    CHECK(n == ZUUID_BYTES && r->written <= n);
    r->calls++;
    memset(buf, 0x5a, r->written);
    return -1;
}

static void test_rng_failure_preserves_uuid(void)
{
    for (size_t n = 0; n <= ZUUID_BYTES; n++) {
        struct partial_rng rng = {n, 0};
        struct { unsigned char before; zuuid value; unsigned char after; } out;
        memset(&out, 0xa5, sizeof out);
        zuuid before = out.value;
        CHECK(zuuid_generate_v4(&out.value, partial_fail_rng, &rng) == ZUUID_ERR_RNG);
        CHECK(rng.calls == 1);
        CHECK(zuuid_equal(&out.value, &before));
        CHECK(out.before == 0xa5 && out.after == 0xa5);
        struct counter_rng good = {42};
        CHECK(zuuid_generate_v4(&out.value, counter_fill, &good) == ZUUID_OK);
        CHECK(zuuid_version(&out.value) == 4 && zuuid_variant(&out.value) == 1);
        CHECK(out.before == 0xa5 && out.after == 0xa5);
    }
}

static void test_generate_v4(void)
{
    struct counter_rng rng = {42};
    zuuid u;
    CHECK(zuuid_generate_v4(&u, counter_fill, &rng) == ZUUID_OK);
    CHECK(zuuid_version(&u) == 4);
    CHECK(zuuid_variant(&u) == 1);
    CHECK(!zuuid_is_nil(&u));

    /* Round trip through text. */
    char s[ZUUID_STR_LEN];
    zuuid back;
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(zuuid_parse(s, &back) == ZUUID_OK);
    CHECK(zuuid_equal(&u, &back));

    /* Distinct draws. */
    zuuid v;
    CHECK(zuuid_generate_v4(&v, counter_fill, &rng) == ZUUID_OK);
    CHECK(!zuuid_equal(&u, &v));

    /* Many draws all carry v4 + RFC variant. */
    for (int i = 0; i < 1000; i++) {
        CHECK(zuuid_generate_v4(&v, counter_fill, &rng) == ZUUID_OK);
        CHECK(zuuid_version(&v) == 4);
        CHECK(zuuid_variant(&v) == 1);
    }

    /* Failure and NULL paths. */
    CHECK(zuuid_generate_v4(&v, fail_rng, NULL) == ZUUID_ERR_RNG);
    CHECK(zuuid_generate_v4(NULL, counter_fill, &rng) == ZUUID_ERR_NULL);
    CHECK(zuuid_generate_v4(&v, NULL, NULL) == ZUUID_ERR_NULL);
}

static void test_err_str(void)
{
    CHECK(strcmp(zuuid_err_str(ZUUID_OK), "ok") == 0);
    CHECK(strstr(zuuid_err_str(ZUUID_ERR_FORMAT), "shape") != NULL);
    CHECK(zuuid_err_str((zuuid_err)999) != NULL);
}

int main(void)
{
    test_nil();
    test_parse_strict();
    test_parse_lenient();
    test_parse_failure_preserves_uuid();
    test_compare();
    test_generate_v4();
    test_rng_failure_preserves_uuid();
    test_err_str();
    puts("test_zuuid: all groups passed (nil strict lenient compare v4 errstr)");
    return 0;
}
