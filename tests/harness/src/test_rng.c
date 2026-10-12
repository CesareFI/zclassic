/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the platform RNG abstraction (platform/modules/platform/src/rng.c).
 *
 * Coverage:
 *   - rng_fill(32 bytes) succeeds and produces non-zero output
 *     (statistical — failure odds ≈ 1/2^256, treat as deterministic)
 *   - rng_u32_range(10, 20) produces values strictly in [10, 20)
 *     across 1000 calls, and produces > 1 distinct value
 *   - inject a seeded xorshift RNG; assert rng_u64 returns the expected
 *     sequence
 *   - rng_set_default(NULL) is a no-op
 *   - rng_reset_default restores real behavior
 */

#include "test/test_core.h"
#include "platform/rng.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <sys/random.h>
static unsigned host_test_calls;
static unsigned host_test_mode;
static unsigned host_test_tape_calls;
static uint64_t host_test_tape(void *ctx)
{
    (void)ctx;
    host_test_tape_calls++;
    return 42;
}
static ssize_t host_test_getrandom(void *out, size_t n, unsigned flags)
{
    host_test_calls++;
    if (flags != GRND_NONBLOCK) { errno = EINVAL; return -1; }
    if (host_test_mode == 1u) { errno = EINTR; return -1; }
    if (host_test_mode == 3u) { errno = EIO; return -1; }
    if (host_test_mode == 4u) { errno = ENOSYS; return -1; }
    if (host_test_mode == 2u && host_test_calls > 1u) {
        errno = EAGAIN;
        return -1;
    }
    size_t got = host_test_mode == 2u ? 1u : n;
    memset(out, 0x5a, got);
    return (ssize_t)got;
}
#define getrandom host_test_getrandom
#define rng_host_fill host_test_fill
#define rng_default host_test_default
#define rng_fill host_test_rng_fill
#define rng_u64 host_test_u64
#define rng_u32_range host_test_range
#define rng_set_default host_test_set_default
#define rng_reset_default host_test_reset_default
#define platform_rng_set_source host_test_set_source
#define platform_rng_clear_source host_test_clear_source
bool host_test_fill(uint8_t *out, size_t len);
const rng_iface_t *host_test_default(void);
bool host_test_rng_fill(uint8_t *out, size_t len);
uint64_t host_test_u64(void);
uint32_t host_test_range(uint32_t lo, uint32_t hi);
void host_test_set_default(const rng_iface_t *iface);
void host_test_reset_default(void);
void host_test_set_source(struct platform_rng_source *src);
void host_test_clear_source(void);
#include "../../../platform/modules/platform/src/rng.c"
#undef getrandom
#undef rng_host_fill
#undef rng_default
#undef rng_fill
#undef rng_u64
#undef rng_u32_range
#undef rng_set_default
#undef rng_reset_default
#undef platform_rng_set_source
#undef platform_rng_clear_source
#endif

#define RNG_CHECK(name, expr) do { \
    printf("rng: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Seeded xorshift64 RNG for the injection test ───────────────── */

struct xs64 {
    _Atomic uint64_t state;
};

static uint64_t xs64_next(struct xs64 *r)
{
    /* Marsaglia xorshift64: not cryptographic; a reproducible stream. */
    uint64_t x = atomic_load(&r->state);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    atomic_store(&r->state, x);
    return x;
}

static bool xs64_fill(void *self, uint8_t *out, size_t len)
{
    struct xs64 *r = (struct xs64 *)self;
    size_t i = 0;
    while (i < len) {
        uint64_t v = xs64_next(r);
        size_t chunk = len - i;
        if (chunk > sizeof(v)) chunk = sizeof(v);
        memcpy(out + i, &v, chunk);
        i += chunk;
    }
    return true;
}

#if defined(__linux__)
static int test_host_interruption(void)
{
    int failures = 0;
    uint8_t span[18];
    memset(span, 0xa5, sizeof span);
    host_test_calls = 0;
    RNG_CHECK("host invalid span makes no syscall", !host_test_fill(span, 4097) &&
              host_test_calls == 0u && span[0] == 0xa5);
    host_test_mode = 1;
    host_test_calls = 0;
    RNG_CHECK("host provider EINTR bound", !host_test_fill(span + 1, 16) &&
              host_test_calls == 8u);
    bool cleared = true;
    for (size_t i = 1; i < 17; i++) cleared &= span[i] == 0;
    RNG_CHECK("host failure clears only output", cleared && span[0] == 0xa5 &&
              span[17] == 0xa5);
    return failures;
}

static int test_host_errors(void)
{
    int failures = 0;
    uint8_t span[18];
    memset(span, 0xa5, sizeof span);
    host_test_mode = 2;
    host_test_calls = 0;
    RNG_CHECK("host partial EAGAIN refuses", !host_test_fill(span + 1, 16) &&
              host_test_calls == 2u);
    bool cleared = true;
    for (size_t i = 1; i < 17; i++) cleared &= span[i] == 0;
    RNG_CHECK("partial host bytes cleared", cleared);
    host_test_mode = 3;
    host_test_calls = 0;
    RNG_CHECK("host hard error refuses immediately", !host_test_fill(span + 1, 16) &&
              host_test_calls == 1u);
    memset(span, 0xa5, sizeof span);
    host_test_mode = 4;
    host_test_calls = 0;
    RNG_CHECK("host ENOSYS refuses without fallback", !host_test_fill(span + 1, 16) &&
              host_test_calls == 1u);
    cleared = true;
    for (size_t i = 1; i < 17; i++) cleared &= span[i] == 0;
    RNG_CHECK("ENOSYS clears only output", cleared && span[0] == 0xa5 &&
              span[17] == 0xa5);
    return failures;
}

static int test_host_bypass(void)
{
    int failures = 0;
    uint8_t span[18];
    memset(span, 0xa5, sizeof span);
    host_test_mode = 0;
    host_test_calls = 0;
    struct xs64 injected = {.state = 123};
    const rng_iface_t iface = {.fill = xs64_fill, .self = &injected};
    struct platform_rng_source tape = {.u64 = host_test_tape, .user = NULL};
    host_test_set_default(&iface);
    host_test_tape_calls = 0;
    host_test_set_source(&tape);
    RNG_CHECK("host provider bypasses injected default", host_test_fill(span + 1, 16) &&
              host_test_calls == 1u && atomic_load(&injected.state) == 123 &&
              host_test_tape_calls == 0u);
    RNG_CHECK("host provider preserves injected default",
              host_test_rng_fill(span + 1, 16) && atomic_load(&injected.state) != 123);
    host_test_clear_source();
    host_test_reset_default();
    return failures;
}
#endif

int test_rng(void)
{
    printf("\n=== platform rng tests ===\n");
    int failures = 0;

#if defined(__linux__)
    failures += test_host_interruption();
    failures += test_host_errors();
    failures += test_host_bypass();
#endif

    /* ── real default: 32-byte fill non-zero ────────────────────── */
    {
        rng_reset_default();
        uint8_t buf[32];
        memset(buf, 0, sizeof(buf));
        bool ok = rng_fill(buf, sizeof(buf));
        RNG_CHECK("rng_fill(32) returns true", ok);

        bool any_nonzero = false;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] != 0) { any_nonzero = true; break; }
        }
        RNG_CHECK("rng_fill(32) produces non-zero bytes", any_nonzero);

        /* Zero-length fill is a no-op success. */
        ok = rng_fill(NULL, 0);
        RNG_CHECK("rng_fill(NULL,0) returns true (no-op)", ok);
    }

    /* ── range bounds + distribution ────────────────────────────── */
    {
        rng_reset_default();
        bool in_range = true;
        uint32_t distinct_mask = 0;
        for (int i = 0; i < 1000; i++) {
            uint32_t v = rng_u32_range(10, 20);
            if (v < 10 || v >= 20) { in_range = false; break; }
            distinct_mask |= (1u << (v - 10));
        }
        RNG_CHECK("rng_u32_range(10,20): all in [10,20)", in_range);
        /* With 1000 draws over 10 buckets, every bucket should be hit
         * with overwhelming probability. Conservatively require at
         * least 2 distinct values so we'd catch a stuck constant. */
        int distinct = __builtin_popcount(distinct_mask);
        RNG_CHECK("rng_u32_range produced >=2 distinct values",
                  distinct >= 2);

        /* Degenerate range returns lo. */
        uint32_t deg = rng_u32_range(42, 42);
        RNG_CHECK("rng_u32_range(42,42) == 42", deg == 42);
        deg = rng_u32_range(100, 50);
        RNG_CHECK("rng_u32_range(100,50) == 100 (lo>hi clamps)",
                  deg == 100);

        /* Single-element range. */
        for (int i = 0; i < 8; i++) {
            uint32_t v = rng_u32_range(7, 8);
            if (v != 7) { in_range = false; break; }
        }
        RNG_CHECK("rng_u32_range(7,8) always returns 7", in_range);
    }

    /* ── u64 returns non-zero on real default ───────────────────── */
    {
        rng_reset_default();
        uint64_t a = rng_u64();
        uint64_t b = rng_u64();
        /* Two consecutive draws being equal is ~1/2^64. */
        RNG_CHECK("two real rng_u64 draws differ", a != b);
        RNG_CHECK("real rng_u64 not stuck at zero", a != 0 || b != 0);
    }

    /* ── inject seeded RNG: deterministic sequence ──────────────── */
    {
        struct xs64 r;
        atomic_store(&r.state, (uint64_t)0xDEADBEEFCAFEBABEULL);

        const rng_iface_t iface = {
            .fill = xs64_fill,
            .self = &r,
        };
        rng_set_default(&iface);

        /* Compute the expected sequence from an identical instance. */
        struct xs64 expected;
        atomic_store(&expected.state, (uint64_t)0xDEADBEEFCAFEBABEULL);

        bool ok = true;
        for (int i = 0; i < 8; i++) {
            uint64_t got = rng_u64();
            uint64_t exp = xs64_next(&expected);
            if (got != exp) {
                printf("\n  draw %d: got=0x%016llx exp=0x%016llx\n",
                       i, (unsigned long long)got,
                       (unsigned long long)exp);
                ok = false;
                break;
            }
        }
        RNG_CHECK("seeded RNG: rng_u64 matches expected sequence", ok);

        RNG_CHECK("rng_default returns the injected pointer",
                  rng_default() == &iface);

        /* Restore so later tests see real RNG again. */
        rng_reset_default();

        /* After reset, rng_u64 should now produce a fresh value
         * (not part of the seeded sequence). With overwhelming
         * probability it differs from xs64_next(&expected). */
        uint64_t real = rng_u64();
        uint64_t next_seeded = xs64_next(&expected);
        RNG_CHECK("after reset_default: rng_u64 ≠ next seeded value",
                  real != next_seeded);
    }

    /* ── set NULL is rejected ───────────────────────────────────── */
    {
        rng_reset_default();
        const rng_iface_t *before = rng_default();
        rng_set_default(NULL);
        const rng_iface_t *after = rng_default();
        RNG_CHECK("set_default(NULL) is no-op", before == after);
    }

    rng_reset_default();

    if (failures == 0) {
        printf("=== platform rng tests: ALL PASS ===\n\n");
    } else {
        printf("=== platform rng tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
