/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Falsification fixture compiled by fixed_result_launcher_probe.c:
 *          parses an encoded pins v2 file with the launcher's own parser and
 *          proves a forged byte, a trailing byte, a truncation, a v1 text
 *          file and a reordered label each parse or refuse by name. */
#define main launcher_entry
#include "tools/verify/fixed_result_launcher.c"
#undef main

static const char *pins_why(const uint8_t *b, size_t n)
{
    struct zcl_fixed_result_v2_roots roots;
    const char *why = NULL;
    return zcl_fr_pins_parse(b, n, &roots, &why) ? "accepted" : why;
}

static int policy_matches(void)
{
    FILE *policy = fopen("tools/verify/fixed_result_launch_policy.v1", "rb");
    char policy_copy[2048];
    if (!policy) return 8;
    size_t policy_len = fread(policy_copy, 1, sizeof(policy_copy), policy);
    if (ferror(policy) || fclose(policy) != 0 ||
        policy_len != strlen(policy_text) ||
        memcmp(policy_copy, policy_text, policy_len) != 0) return 9;
    return 0;
}

static int mutations(uint8_t *bytes, size_t len)
{
    static const char v1[] = "z23verify.fixed_result.pins.v1\n"
                             "strict_args_sha3=aa\n";
    struct zcl_fixed_result_v2_roots roots;
    const char *why = NULL;
    bytes[len - 1u] ^= 0xffu;          /* still a root, different bytes */
    if (!zcl_fr_pins_parse(bytes, len, &roots, &why) ||
        roots.tree_checker[31] == 0xccu) return 4;
    bytes[len] = 0;
    if (strcmp(pins_why(bytes, len + 1u), ZCL_FR_WHY_TRAILING)) return 5;
    if (strcmp(pins_why(bytes, len - 1u), ZCL_FR_WHY_TRUNCATED)) return 10;
    if (strcmp(pins_why((const uint8_t *)v1, sizeof(v1) - 1u),
               ZCL_FR_WHY_V1_RETIRED)) return 6;
    bytes[8 + 30 + 8] ^= 0x01u;         /* the "profile" label */
    if (strcmp(pins_why(bytes, len), ZCL_FR_WHY_FIELD_ORDER)) return 7;
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t bytes[2048];
    struct zcl_fixed_result_v2_roots roots;
    const char *why = NULL;
    if (argc != 2) return 1;
    int rc = policy_matches();
    if (rc) return rc;
    FILE *pins = fopen(argv[1], "rb");
    if (!pins) return 2;
    size_t len = fread(bytes, 1, sizeof(bytes) - 1u, pins);
    if (ferror(pins) || fclose(pins) != 0) return 2;
    if (!zcl_fr_pins_parse(bytes, len, &roots, &why)) return 3;
    if (roots.tree_checker[0] != 0xccu) return 3;
    return mutations(bytes, len);
}
