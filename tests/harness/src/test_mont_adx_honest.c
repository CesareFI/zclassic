/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Honesty guard for the Montgomery-multiply accelerator's operator-visible
 * name: if bn254_accel_implementation() claims ADCX/ADOX carry chains, the
 * machine code the linker actually produced must contain ADCX and ADOX.
 *
 * If bn254_accel_implementation() claims ADCX/ADOX carry chains, the linked
 * machine code must contain ADCX and ADOX. C cannot pin two carry chains to
 * two flag bits, so a compiler may lower them to plain ADC.
 *
 * A code-reading test, not a timing test: the instruction encoding is a fact
 * about the artifact. ADCX = 66 [REX.W] 0F 38 F6 /r, ADOX = F3 [REX.W] 0F 38
 * F6 /r; we scan a bounded window from the function entry and classify each
 * 0F 38 F6 hit by its prefix (one optional REX byte between). Presence
 * counting only, so the bar is a minimum count: the real routine emits 40 of
 * each (4 CIOS rounds x [4 rows + 1 carry fold] x 2 phases). */

#include "test/test_core.h"
#include "sapling/bn254_accel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* mont_mul_adx4 fully unrolled is ~900 bytes at -O2/-O3. 2 KiB is generous
 * enough to cover it under any reasonable scheduling and still far too tight to
 * accumulate 32 false hits of each form. */
#define SCAN_WINDOW 2048u
/* 4 rounds x 2 phases x (4 rows + 1 fold) = 40 of each; require most of them so
 * the bar survives a compiler that folds a fold, but not a path with none. */
#define MIN_EXPECTED 32u

static bool claims_adx(const char *impl)
{
    return strstr(impl, "ADCX") != NULL || strstr(impl, "ADOX") != NULL;
}

static void count_adx_ops(const unsigned char *p, size_t n,
                          unsigned *adcx, unsigned *adox)
{
    *adcx = *adox = 0;
    for (size_t i = 0; i + 2 < n; i++) {
        if (p[i] != 0x0f || p[i + 1] != 0x38 || p[i + 2] != 0xf6)
            continue;
        /* Walk back over an optional REX byte to find the mandatory prefix. */
        size_t j = i;
        if (j > 0 && p[j - 1] >= 0x40 && p[j - 1] <= 0x4f)
            j--;
        if (j == 0)
            continue;
        if (p[j - 1] == 0x66) (*adcx)++;
        else if (p[j - 1] == 0xf3) (*adox)++;
    }
}

int test_mont_adx_honest(void);

int test_mont_adx_honest(void)
{
    int failures = 0;

    printf("\n=== Montgomery accel: reported name vs compiled bytes ===\n");

    const char *impl = bn254_accel_implementation();
    if (!impl) {
        printf("  FAIL: implementation string is NULL\n");
        return 1;
    }
    printf("reported impl: %s\n", impl);

    const void *code = bn254_accel_adx_code();

    /* Host without BMI2+ADX: the string must not claim what cannot run. */
    if (code == NULL) {
        printf("no ADX path installed on this host... ");
        if (claims_adx(impl)) {
            printf("FAILED\n  string claims ADCX/ADOX but no ADX path is installed\n");
            failures++;
        } else {
            printf("ok (string does not claim it)\n");
        }
        printf("\n%d mont adx honesty test(s) %s\n", failures,
               failures ? "FAILED" : "all passed");
        return failures;
    }

    unsigned adcx = 0, adox = 0;
    count_adx_ops((const unsigned char *)code, SCAN_WINDOW, &adcx, &adox);
    printf("compiled multiply: adcx=%u adox=%u (window %u bytes, floor %u)\n",
           adcx, adox, (unsigned)SCAN_WINDOW, (unsigned)MIN_EXPECTED);

    if (claims_adx(impl)) {
        printf("string claims ADCX/ADOX, bytes must deliver... ");
        if (adcx < MIN_EXPECTED || adox < MIN_EXPECTED) {
            printf("FAILED\n"
                   "  reported \"%s\" but the compiled multiply contains\n"
                   "  adcx=%u adox=%u (need >= %u of each). This is the exact\n"
                   "  overclaim the tier shipped with before: intrinsics with a\n"
                   "  literal 0 carry-in lower to plain ADC.\n",
                   impl, adcx, adox, (unsigned)MIN_EXPECTED);
            failures++;
        } else {
            printf("ok\n");
        }
    } else {
        printf("string does not claim ADCX/ADOX, bytes must agree... ");
        if (adcx >= MIN_EXPECTED && adox >= MIN_EXPECTED) {
            printf("FAILED\n"
                   "  compiled multiply builds real carry chains (adcx=%u "
                   "adox=%u)\n  but the reported string \"%s\" hides it\n",
                   adcx, adox, impl);
            failures++;
        } else {
            printf("ok\n");
        }
    }

    printf("\n%d mont adx honesty test(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
