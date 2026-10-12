#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# Ineligible launcher preflight and pins v2 falsification on an unprivileged
# host. It builds the launcher, encodes a pins v2 file with it, and proves
# that file, a forged byte, a trailing byte, a v1 text pins file and the
# strict profile digest each parse or refuse by name.
set -euo pipefail

fail() { printf 'fixed_result_launcher_probe_refuse=%s\n' "$1" >&2; exit 2; }
repo=$(git rev-parse --show-toplevel)
[[ $PWD == "$repo" ]] || fail checkout_cwd
work=$(mktemp -d "$HOME/.z23-launcher-probe.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

cc_flags=(-std=c23 -Wall -Wextra -Werror -pedantic -Itools
          -Iplatform/modules/sha3/include -Iplatform/modules/base/include
          -Iplatform/modules/platform/include)
common=(tools/verify/fixed_result_contract.c tools/verify/fixed_result_source.c
        platform/modules/base/src/safe_alloc.c platform/modules/sha3/src/sha3.c
        platform/modules/platform/src/os_proc.c)
/usr/bin/cc "${cc_flags[@]}" tools/verify/fixed_result_launcher.c \
    "${common[@]}" -o "$work/launcher"

cat > "$work/check.c" <<'EOF'
#define main launcher_entry
#include "tools/verify/fixed_result_launcher.c"
#undef main

static const char *pins_why(const uint8_t *b, size_t n)
{
    struct zcl_fixed_result_v2_roots roots;
    const char *why = NULL;
    return zcl_fr_pins_parse(b, n, &roots, &why) ? "accepted" : why;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    FILE *policy = fopen("tools/verify/fixed_result_launch_policy.v1", "rb");
    char policy_copy[2048];
    if (!policy) return 8;
    size_t policy_len = fread(policy_copy, 1, sizeof(policy_copy), policy);
    if (ferror(policy) || fclose(policy) != 0 ||
        policy_len != strlen(policy_text) ||
        memcmp(policy_copy, policy_text, policy_len) != 0) return 9;
    FILE *pins = fopen(argv[1], "rb");
    uint8_t bytes[2048];
    if (!pins) return 2;
    size_t len = fread(bytes, 1, sizeof(bytes) - 1u, pins);
    if (ferror(pins) || fclose(pins) != 0) return 2;
    struct zcl_fixed_result_v2_roots roots;
    const char *why = NULL;
    if (!zcl_fr_pins_parse(bytes, len, &roots, &why)) return 3;
    if (roots.tree_checker[0] != 0xccu) return 3;
    bytes[len - 1u] ^= 0xffu;          /* still a root, different bytes */
    if (!zcl_fr_pins_parse(bytes, len, &roots, &why) ||
        roots.tree_checker[31] == 0xccu) return 4;
    bytes[len] = 0;
    if (strcmp(pins_why(bytes, len + 1u), ZCL_FR_WHY_TRAILING)) return 5;
    if (strcmp(pins_why(bytes, len - 1u), ZCL_FR_WHY_TRUNCATED)) return 10;
    static const char v1[] = "z23verify.fixed_result.pins.v1\n"
                             "strict_args_sha3=aa\n";
    if (strcmp(pins_why((const uint8_t *)v1, sizeof(v1) - 1u),
               ZCL_FR_WHY_V1_RETIRED)) return 6;
    bytes[8 + 30 + 8] ^= 0x01u;         /* the "profile" label */
    if (strcmp(pins_why(bytes, len), ZCL_FR_WHY_FIELD_ORDER)) return 7;
    return 0;
}
EOF
/usr/bin/cc "${cc_flags[@]}" -I. "$work/check.c" "${common[@]}" \
    -o "$work/check"

fast=$(openssl dgst -sha3-256 tools/verify/fixed_result_fast.args | awk '{print $NF}')
strict=5fb3b13597488c20a9f5aeca2b654fad92b39714d93069c12c082206977aadaf
roots=()
for i in 0 1 2 3 4 5 6 7 8 9 10 11; do
    roots+=("$(printf '%02x' $((i + 1)))$(printf 'ab%.0s' {1..31})")
done
roots[1]=$fast
# The environment root is computed, not typed: the launcher refuses any
# other, so ask it for the refusal token and then encode with the real one.
roots[11]=$(printf 'cc%.0s' {1..32})
if "$work/launcher" pins-encode "${roots[@]}" > "$work/pins" 2> "$work/err"; then
    fail env_root_unchecked
fi
grep -Fx 'fixed_result_launcher_refuse=contract_env_mismatch' "$work/err" \
    >/dev/null || fail env_wrong_refusal
cat > "$work/env.c" <<'EOF'
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
EOF
/usr/bin/cc "${cc_flags[@]}" "$work/env.c" "${common[@]}" -o "$work/env"
roots[7]=$("$work/env")
"$work/launcher" pins-encode "${roots[@]}" > "$work/pins" ||
    fail pins_encode_refused
"$work/check" "$work/pins" || fail parser_false_green
roots[1]=$strict
if "$work/launcher" pins-encode "${roots[@]}" > "$work/strict" 2> "$work/err"
then fail strict_profile_accepted; fi
grep -Fx 'fixed_result_launcher_refuse=contract_profile_mismatch' \
    "$work/err" >/dev/null || fail strict_wrong_refusal

if "$work/launcher" preflight > "$work/out" 2> "$work/err"; then
    fail same_uid_accepted
fi
grep -Fx 'fixed_result_launcher_refuse=root_required' "$work/err" >/dev/null ||
    fail same_uid_wrong_refusal
if "$work/launcher" other > "$work/out" 2> "$work/err"; then
    fail unknown_command_accepted
fi
grep -Fx 'fixed_result_launcher_refuse=request_shape_unsupported' \
    "$work/err" >/dev/null || fail unknown_wrong_refusal
if platform/deploy/fixed-result-launcher-install.sh install \
        > "$work/out" 2> "$work/err"; then
    fail same_uid_install_accepted
fi
grep -Fx 'fixed_result_install_refuse=root_required' "$work/err" >/dev/null ||
    fail same_uid_install_wrong_refusal
# The source_content pin: the v2 root of the fixed chain, independent of
# owner and mode, and refused through a link.
content=$("$work/launcher" source-content "$repo") ||
    fail source_content_refused
[[ $content =~ ^[0-9a-f]{64}$ ]] || fail source_content_shape
for rel in platform/modules/base/include/base/format_attribute.h \
           platform/modules/base/include/base/result.h \
           platform/modules/base/src/result.c; do
    mkdir -p "$work/src/${rel%/*}"
    cp -- "$rel" "$work/src/$rel"
    chmod 0600 "$work/src/$rel"
done
[[ $("$work/launcher" source-content "$work/src") == "$content" ]] ||
    fail source_content_mode_dependent
mv -- "$work/src/platform/modules/base/include/base/result.h" "$work/result.h"
ln -s -- "$work/result.h" "$work/src/platform/modules/base/include/base/result.h"
if "$work/launcher" source-content "$work/src" > "$work/out" 2> "$work/err"
then fail source_content_followed_link; fi
grep -Fx 'fixed_result_launcher_refuse=source_content_unreadable' \
    "$work/err" >/dev/null || fail source_content_link_wrong_refusal
printf 'pins_v2_parser=GREEN forged_label=RED trailing_bytes=RED '
printf 'truncated=RED v1_pins=RED strict_profile=RED env_root=RED '
printf 'same_uid=REFUSE compiler_invocations=3 executed_launcher=8 '
printf 'installer_refusals=1 source_content=GREEN source_content_link=RED '
printf 'proof_launches_avoided=0 attest_eligible=0\n'
