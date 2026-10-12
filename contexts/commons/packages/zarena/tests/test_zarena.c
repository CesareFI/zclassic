/* zarena tests. */
#include "zarena/zarena.h"

#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void test_basic_and_alignment(void)
{
    static _Alignas(16) unsigned char buf[256];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    char *p1 = zarena_alloc(&a, 10, 1);
    check(p1 != NULL, "basic alloc");
    double *p2 = zarena_alloc(&a, sizeof(double), alignof(double));
    check(p2 != NULL && ((uintptr_t)p2 % alignof(double)) == 0,
          "aligned to 8");
    void *p3 = zarena_alloc(&a, 16, 16);
    check(p3 != NULL && ((uintptr_t)p3 % 16) == 0, "aligned to 16");
    check(p1 != (void *)p2 && (void *)p2 != p3, "no overlap");
    check(zarena_used(&a) > 0, "used grows");
}

static void test_exhaustion(void)
{
    static unsigned char buf[64];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    check(zarena_alloc(&a, 64, 1) != NULL, "exact fit");
    check(zarena_alloc(&a, 1, 1) == NULL, "overflow fails");
    check(zarena_remaining(&a) == 0, "remaining zero");
    zarena_clear(&a);
    check(zarena_used(&a) == 0, "clear resets");
    check(zarena_alloc(&a, 64, 1) != NULL, "alloc after clear");
}

static void test_mark_rewind(void)
{
    static unsigned char buf[128];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    void *keep = zarena_alloc(&a, 16, 1);
    zarena_mark m = zarena_save(&a);
    void *tmp1 = zarena_alloc(&a, 32, 1);
    void *tmp2 = zarena_alloc(&a, 32, 1);
    check(keep && tmp1 && tmp2, "mark phase allocs");
    size_t used_before = zarena_used(&a);
    zarena_rewind(&a, m);
    check(zarena_used(&a) < used_before, "rewind shrinks");
    void *tmp3 = zarena_alloc(&a, 64, 1);
    check(tmp3 == tmp1, "rewound memory reused");
}

static void test_bad_args(void)
{
    static unsigned char buf[32];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    check(zarena_alloc(&a, 4, 3) == NULL, "non-pow2 align fails");
    check(zarena_alloc(&a, 4, 0) == NULL, "zero align fails");

    zarena dead;
    zarena_init(&dead, NULL, 100);
    check(zarena_alloc(&dead, 1, 1) == NULL, "null buffer arena");
}

static void test_zero_size(void)
{
    static unsigned char buf[32];
    zarena a;
    zarena_init(&a, buf, sizeof buf);

    void *p = zarena_alloc(&a, 0, 1);
    check(p != NULL, "zero-size alloc ok");
    check(zarena_used(&a) >= 1, "zero-size advances frontier");
}

static void test_zero_size_bounds(void)
{
    unsigned char byte[1];
    zarena a;
    zarena_init(&a, byte, sizeof byte);
    check(zarena_alloc(&a, 1, 1) == byte, "fill one-byte arena");
    check(zarena_alloc(&a, 0, 1) == NULL, "zero-size exhausted arena fails");
    check(zarena_used(&a) == 1, "failed zero-size preserves frontier");
    check(zarena_remaining(&a) == 0, "failed zero-size preserves remaining");

    zarena_clear(&a);
    check(zarena_alloc(&a, 0, 1) == byte, "zero-size uses available byte");
    check(zarena_used(&a) == 1 && zarena_remaining(&a) == 0,
          "zero-size consumes exactly one byte");
    check(zarena_alloc(&a, 0, 1) == NULL, "second zero-size allocation fails");
    check(zarena_used(&a) == 1, "repeated exhaustion preserves frontier");

    _Alignas(16) unsigned char aligned[17];
    zarena_init(&a, aligned, 16);
    check(zarena_alloc(&a, 1, 1) == aligned, "alignment prefix allocation");
    check(zarena_alloc(&a, 0, 16) == NULL,
          "alignment padding leaves no minimal allocation space");
    check(zarena_used(&a) == 1 && zarena_remaining(&a) == 15,
          "alignment exhaustion preserves frontier and remaining");
    zarena_init(&a, aligned, sizeof aligned);
    check(zarena_alloc(&a, 1, 1) == aligned, "exact alignment prefix");
    check(zarena_alloc(&a, 0, 16) == aligned + 16,
          "aligned zero-size exact fit");
    check(zarena_used(&a) == 17 && zarena_remaining(&a) == 0,
          "exact fit includes alignment padding and minimal byte");
    check(zarena_alloc(&a, 0, 1) == NULL, "aligned arena exhausted");
    check(zarena_used(&a) == 17 && zarena_remaining(&a) == 0,
          "aligned exhaustion leaves state unchanged");
}

int main(void)
{
    test_basic_and_alignment();
    test_exhaustion();
    test_mark_rewind();
    test_bad_args();
    test_zero_size();
    test_zero_size_bounds();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zarena: all tests passed");
    return 0;
}
