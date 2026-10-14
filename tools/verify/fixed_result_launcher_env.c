/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Fixture compiled by fixed_result_launcher_probe.c: prints the
 *          environment root the launcher requires in a pins v2 file. */
#include "verify/fixed_result_contract.h"
#include "base/hex.h"
#include <stdio.h>
int main(void)
{
    uint8_t root[32];
    char hex[65];
    zcl_fr_env_fixed_root(root);
    zcl_hex_encode(root, 32u, hex);
    puts(hex);
    return 0;
}
