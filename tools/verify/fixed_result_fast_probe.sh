#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# Local test-fast result.c worker acceptance. No same-UID result is eligible.
set -euo pipefail

fail() { printf 'fixed_result_fast_refuse=%s\n' "$1" >&2; exit 2; }
repo=$(git rev-parse --show-toplevel)
[[ $PWD == "$repo" && $PWD == "$(pwd -P)" ]] || fail physical_cwd_mismatch
[[ $(realpath /usr/bin/cc) == /usr/bin/x86_64-linux-gnu-gcc-14 ]] ||
    fail gcc14_driver_mismatch
command -v openssl >/dev/null || fail sha3_tool_missing
[[ -x /usr/bin/time ]] || fail time_tool_missing
manifest=tools/verify/fixed_result_fast.args
manifest_hash=$(openssl dgst -sha3-256 "$manifest" | awk '{print $NF}')
[[ $manifest_hash == 5e8a1cafce7350ff3c335c6a714f59c75c1e646de82eb03d076f68bdad244e1c ]] ||
    fail manifest_bytes_mismatch
work=$(mktemp -d "$HOME/.z23-fast-result.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

make -s --eval='__z23_fast_profile: ; @printf "__PROFILE_BEGIN__\n"; printf "%s\n" $(CC) $(TEST_FAST_OBJECT_CFLAGS) $(ZCL_TU_RANDOM_SEED); printf "__TARGET__\n%s\n" "$(TEST_FAST_OBJ_DIR)/platform/modules/base/src/result.o"' \
    __z23_fast_profile > "$work/make.out"
mapfile -t actual < <(awk '/^__PROFILE_BEGIN__$/ {inside=1; next} /^__TARGET__$/ {exit} inside {print}' "$work/make.out")
mapfile -t pinned < "$manifest"
[[ ${#actual[@]} == 184 && ${#pinned[@]} == 183 &&
   ${actual[0]} == "$repo/build/bin/zcc" && ${actual[1]} == cc ]] ||
    fail make_profile_shape
for ((i = 0; i < 182; i++)); do
    [[ ${actual[i + 1]} == "${pinned[i]//@CWD@/$repo}" ]] ||
        fail make_profile_mismatch
done
[[ ${actual[183]} == '-frandom-seed=' &&
   ${pinned[182]} == '-frandom-seed=platform/modules/base/src/result.c' ]] ||
    fail seed_mismatch
target=$(sed -n '/^__TARGET__$/ {n;p;q}' "$work/make.out")
[[ $target == build/test-obj/epochs/*/platform/modules/base/src/result.o ]] ||
    fail target_malformed

/usr/bin/cc -std=c23 -Wall -Wextra -Werror -pedantic \
    -Itools -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
    -Iplatform/modules/platform/include \
    tools/verify/fixed_result_worker.c tools/verify/fixed_result_contract.c \
    platform/modules/sha3/src/sha3.c \
    platform/modules/platform/src/os_proc.c \
    -o "$work/worker"
/usr/bin/cc -std=c23 -Wall -Wextra -Werror -pedantic \
    tools/verify/fixed_result_peer_probe.c -o "$work/peer"
mkdir "$work/full" "$work/sparse" "$work/sparse/src"
for arg in "${pinned[@]}"; do
    [[ $arg == -I* ]] || continue
    mkdir -p "$work/sparse/src/${arg#-I}"
done
mkdir -p "$work/sparse/src/platform/modules/base/src" \
    "$work/sparse/src/platform/modules/base/include/base"
cp platform/modules/base/src/result.c \
    "$work/sparse/src/platform/modules/base/src/result.c"
cp platform/modules/base/include/base/result.h \
   platform/modules/base/include/base/format_attribute.h \
   "$work/sparse/src/platform/modules/base/include/base/"

/usr/bin/time -f 'full_wall=%e full_user=%U full_system=%S' -o "$work/full.time" \
    "$work/worker" qualify "$repo" "$target" "$work/full" > "$work/full.out"
/usr/bin/time -f 'sparse_wall=%e sparse_user=%U sparse_system=%S' -o "$work/sparse.time" \
    "$work/worker" qualify "$work/sparse/src" "$target" "$work/sparse" > "$work/sparse.out"
for name in result.o deps.d stderr.bin result.i; do
    cmp "$work/full/$name" "$work/sparse/$name" || fail "$name-byte-mismatch"
done
[[ $(sha256sum "$work/full/result.o" | awk '{print $1}') == \
   32a13af795e799469c81dcf5e961a41fd3a6cb59745942efc17d2ae140454660 ]] ||
    fail object_baseline_mismatch

# The key normalizes -MT across immutable test-fast epochs. Prove that only
# depfile target bytes change when the direct-source output target changes.
target_b=build/test-obj/epochs/$(printf 'b%.0s' {1..64})/platform/modules/base/src/result.o
args=()
for arg in "${pinned[@]}"; do args+=("${arg//@CWD@/$repo}"); done
(
    cd "$repo"
    env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin "${args[@]}" \
        -MMD -MP -MF "$work/epoch-b.d" -MT "$target_b" -c \
        -o "$work/epoch-b.o" platform/modules/base/src/result.c \
        2> "$work/epoch-b.err"
)
cmp "$work/full/result.o" "$work/epoch-b.o" || fail epoch_object_mismatch
cmp "$work/full/stderr.bin" "$work/epoch-b.err" || fail epoch_stderr_mismatch
if cmp -s "$work/full/deps.d" "$work/epoch-b.d"; then
    fail epoch_dep_target_not_changed
fi

# Linux ZCC's private stage reaches GCC as /proc/self/fd/N/leaf. A direct
# compile through that spelling must be byte-equivalent to the worker's
# ordinary private-directory output spelling before their values normalize.
mkdir "$work/fd-stage"
args=()
for arg in "${pinned[@]}"; do args+=("${arg//@CWD@/$repo}"); done
(
    cd "$repo"
    exec {stage_fd}< "$work/fd-stage"
    env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin "${args[@]}" \
        -MMD -MP -MF "/proc/self/fd/$stage_fd/result.d" \
        -MT "$target" -c -o "/proc/self/fd/$stage_fd/result.o" \
        platform/modules/base/src/result.c 2> "$work/fd-stage.err"
    exec {stage_fd}<&-
)
cmp "$work/full/result.o" "$work/fd-stage/result.o" || fail fd_object_mismatch
cmp "$work/full/deps.d" "$work/fd-stage/result.d" || fail fd_dep_mismatch
cmp "$work/full/stderr.bin" "$work/fd-stage.err" || fail fd_stderr_mismatch

# A formerly absent earlier search-path header redirects this exact include.
# Fresh preprocessing and the current-target depfile must expose the change;
# the three positive input file hashes alone would not.
mkdir -p "$work/sparse/src/engine/models/include/base"
cp platform/modules/base/include/base/result.h \
   "$work/sparse/src/engine/models/include/base/result.h"
args=()
for arg in "${pinned[@]}"; do args+=("${arg//@CWD@/$work/sparse/src}"); done
(
    cd "$work/sparse/src"
    env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin "${args[@]}" \
        -fno-working-directory -MMD -MP -MF "$work/shadow.d" \
        -MT "$target" -E -o "$work/shadow.i" \
        platform/modules/base/src/result.c 2> "$work/shadow.err"
)
if cmp -s "$work/sparse/result.i" "$work/shadow.i" ||
   cmp -s "$work/sparse/deps.d" "$work/shadow.d"; then
    fail header_shadow_not_detected
fi
rm "$work/sparse/src/engine/models/include/base/result.h"
printf '#include_next <stdio.h>\n' > \
    "$work/sparse/src/engine/models/include/stdio.h"
(
    cd "$work/sparse/src"
    env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin "${args[@]}" \
        -fno-working-directory -MMD -MP -MF "$work/system-shadow.d" \
        -MT "$target" -E -o "$work/system-shadow.i" \
        platform/modules/base/src/result.c 2> "$work/system-shadow.err"
)
if cmp -s "$work/sparse/result.i" "$work/system-shadow.i" ||
   cmp -s "$work/sparse/deps.d" "$work/system-shadow.d"; then
    fail system_header_shadow_not_detected
fi
rm "$work/sparse/src/engine/models/include/stdio.h"

sed 's/<zcl_result: missing format>/<zcl_result: altered format>/' \
    "$work/sparse/src/platform/modules/base/src/result.c" > "$work/changed-source.c"
mv "$work/changed-source.c" "$work/sparse/src/platform/modules/base/src/result.c"
if "$work/worker" qualify "$work/sparse/src" "$target" "$work/red-body" \
        > "$work/red.out" 2> "$work/red.err"; then
    fail changed_source_accepted
fi
grep -Fx 'fixed_result_worker_refuse=pinned_input_digest_mismatch' \
    "$work/red.err" >/dev/null || fail changed_source_wrong_refusal
"$work/peer" "$work/worker" 2> "$work/serve.err" ||
    fail same_uid_accepted
grep -Fx 'fixed_result_worker_refuse=launcher_peer_mismatch' "$work/serve.err" \
    >/dev/null || fail same_uid_wrong_refusal

# The stale pre-edit object and a fresh direct compile must be observably
# different when this pinned source changes. Neither object is proof reuse.
(
    cd "$work/sparse/src"
    env -i LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin "${args[@]}" \
        -MMD -MP -MF "$work/changed.d" -MT "$target" -c \
        -o "$work/changed.o" platform/modules/base/src/result.c
)
cat > "$work/driver.c" <<'EOF'
#include "base/result.h"
#include <stdio.h>
int main(void)
{
    struct zcl_result r = zcl_result_make(-1, __FILE__, __LINE__, NULL);
    puts(r.message);
    return 0;
}
EOF
/usr/bin/cc -std=c23 -Iplatform/modules/base/include \
    "$work/driver.c" "$work/full/result.o" -o "$work/stale-driver"
/usr/bin/cc -std=c23 -Iplatform/modules/base/include \
    "$work/driver.c" "$work/changed.o" -o "$work/fresh-driver"
"$work/stale-driver" > "$work/stale.out"
"$work/fresh-driver" > "$work/fresh.out"
grep -Fx '<zcl_result: missing format>' "$work/stale.out" >/dev/null ||
    fail stale_behavior_mismatch
grep -Fx '<zcl_result: altered format>' "$work/fresh.out" >/dev/null ||
    fail fresh_behavior_mismatch

printf 'profile_green=1 source=platform/modules/base/src/result.c manifest_sha3=%s\n' \
    "$manifest_hash"
sha256sum "$work/full/result.o" "$work/full/deps.d" \
    "$work/full/stderr.bin" "$work/full/result.i"
wc -c "$work/full/result.o" "$work/full/deps.d" \
    "$work/full/stderr.bin" "$work/full/result.i"
cat "$work/full.time" "$work/sparse.time"
printf '%s\n' \
    'object_equal=1 dep_equal=1 stderr_equal=1 pp_equal=1 epoch_object_equal=1 epoch_dep_target_differs=1 fd_output_parity=1 header_shadow_red=1 system_header_shadow_red=1 profile_compiler_launches=5 preprocess_launches=4 worker_build_invocations=1 peer_fixture_build_invocations=1 driver_compile_link_invocations=2 executed_drivers=2 red_pin_compiler_launches=0 proof_launches_avoided=0 attest_eligible=0'
