#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# Local prerequisites only. No same-account result authorizes attestation.
set -euo pipefail

if (( $# != 2 )) || [[ $1 != /usr/bin/gcc ]] ||
    [[ $2 != -std=c2x && $2 != -std=c23 ]]; then
    printf 'usage: %s /usr/bin/gcc -std=c2x|-std=c23\n' "$0" >&2
    exit 2
fi
compiler=$1
standard=$2
# The shared checkout's development ancestors are group-writable. Exercise
# the ownership gate under the user's private home instead of weakening it.
work=$(mktemp -d "$HOME/.z23-verify-tree-probe.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -m 700 "$work/root" "$work/tool" "$work/red-tool"

"$compiler" "$standard" -Wall -Wextra -Werror -pedantic \
    -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
    tools/verify/tree_closure.c platform/modules/sha3/src/sha3.c \
    platform/modules/base/src/safe_alloc.c \
    -o "$work/tree-closure"
"$compiler" "$standard" -Wall -Wextra -Werror -pedantic \
    -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
    tools/verify/fixed_result_closure.c platform/modules/sha3/src/sha3.c \
    -o "$work/fixed-result-closure"

uid=$(id -u)
hash_tree() {
    "$work/tree-closure" hash "$work/root" "$uid"
}
digest() {
    sed -n 's/^tree_sha3=\([0-9a-f]\{64\}\) .*/\1/p'
}
content_digest() {
    sed -n 's/.* content_sha3=\([0-9a-f]\{64\}\) .*/\1/p'
}
refuse() {
    local expected=$1
    if hash_tree > "$work/refused.out" 2> "$work/refused.err"; then
        printf 'expected tree refusal: %s\n' "$expected" >&2
        exit 1
    fi
    grep -Fx "tree_closure_refuse=$expected" "$work/refused.err" >/dev/null
}

printf 'backend-one\n' > "$work/root/cc1"
printf 'backend-one\n' > "$work/tool/cc1"
printf '#include "base.h"\n' > "$work/root/result.c"
printf 'int result(void);\n' > "$work/root/base.h"
first=$(hash_tree)
grep -F 'attest_eligible=0' <<< "$first" >/dev/null
[[ $(digest <<< "$first") == $(hash_tree | digest) ]]
[[ $(content_digest <<< "$first") == $(hash_tree | content_digest) ]]
cp -a "$work/root" "$work/clone"
[[ $("$work/tree-closure" hash "$work/clone" "$uid" | content_digest) == \
   "$(content_digest <<< "$first")" ]]
if "$work/tree-closure" hash "$work/root" 60092 > "$work/uid.out" 2> "$work/uid.err"; then
    printf 'expected signer-vs-receiver UID refusal\n' >&2
    exit 1
fi
grep -Fx 'tree_closure_refuse=unsafe_root' "$work/uid.err" >/dev/null

zeros=$(printf '%064d' 0)
ones=$(printf '%064d' 1)
combine() {
    "$work/fixed-result-closure" combine \
        "$("$work/tree-closure" hash "$work/tool" "$uid" | content_digest)" \
        "$(hash_tree | content_digest)" \
        "$("$work/tree-closure" hash "$work/tool" "$uid" | digest)" \
        "$(hash_tree | digest)" "$1" "$zeros" "$PWD"
}
closure_digest() {
    sed -n 's/^closure_sha3=\([0-9a-f]\{64\}\)$/\1/p'
}
baseline_closure=$(combine "$zeros" | closure_digest)
[[ -n $baseline_closure ]]
[[ $(COMPILER_PATH="$work/red-tool" combine "$zeros" | closure_digest) == \
   "$baseline_closure" ]]
[[ $(combine "$ones" | closure_digest) != "$baseline_closure" ]]

# A formerly absent optional header changes a directory's complete identity.
printf 'int optional(void);\n' > "$work/root/optional.h"
optional=$(hash_tree | digest)
[[ $optional != "$(digest <<< "$first")" ]]
[[ $(combine "$zeros" | closure_digest) != "$baseline_closure" ]]
rm "$work/root/optional.h"
[[ $(hash_tree | digest) == "$(digest <<< "$first")" ]]
[[ $(combine "$zeros" | closure_digest) == "$baseline_closure" ]]

# Same-length backend replacement is detected even when a driver is unchanged.
printf 'backend-two\n' > "$work/root/cc1"
[[ $(hash_tree | digest) != "$(digest <<< "$first")" ]]
printf 'backend-one\n' > "$work/root/cc1"
printf 'backend-two\n' > "$work/tool/cc1"
[[ $(combine "$zeros" | closure_digest) != "$baseline_closure" ]]
printf 'backend-one\n' > "$work/tool/cc1"
chmod 666 "$work/root/cc1"
refuse writable_entry
chmod 600 "$work/root/cc1"

ln -s cc1 "$work/root/backend-link"
hash_tree >/dev/null
rm "$work/root/backend-link"
ln -s /etc/passwd "$work/root/backend-link"
refuse symlink_absolute
rm "$work/root/backend-link"
printf 'outside\n' > "$work/outside"
ln -s ../outside "$work/root/backend-link"
refuse symlink_escapes_root
rm "$work/root/backend-link"
mkfifo "$work/root/pipe"
refuse special_entry
rm "$work/root/pipe"

# GCC's unpinned COMPILER_PATH can replace cc1 while the driver bytes stay
# fixed. The wrapper delegates to real cc1, so a successful compile is RED.
real_cc1=$("$compiler" -print-prog-name=cc1)
cat > "$work/red-tool/cc1" <<'SH'
#!/bin/sh
printf 'invoked\n' > "$RED_MARKER"
exec "$REAL_CC1" "$@"
SH
chmod 700 "$work/red-tool/cc1"
printf 'int z23_red(void) { return 7; }\n' > "$work/unit.c"
driver_before=$(sha256sum "$compiler" | cut -d ' ' -f1)
RED_MARKER="$work/cc1.marker" REAL_CC1="$real_cc1" \
    COMPILER_PATH="$work/red-tool" \
    "$compiler" "$standard" -c "$work/unit.c" -o "$work/unit.o"
driver_after=$(sha256sum "$compiler" | cut -d ' ' -f1)
[[ -s $work/cc1.marker && $driver_before == "$driver_after" ]]
printf 'tree_green=1 portable_content_equal=1 uid_mismatch_red=1 negative_header_red=1 backend_replacement_red=1 policy_claim_red=1 unsafe_entry_refusals=4\n'
printf 'compiler_path_red=1 unchanged_driver=1 fixed_env_claim_stable=1 gcc_driver_invocations=4 actual_compiles=3 proof_launches_avoided=0 attestation_eligible=0\n'
