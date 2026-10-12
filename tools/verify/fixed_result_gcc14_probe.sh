#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# Exact current build-only result.c profile witness; never authorizes reuse.
set -euo pipefail

fail() { printf 'fixed_result_refuse=%s\n' "$1" >&2; exit 2; }
repo=$(git rev-parse --show-toplevel)
[[ $PWD == "$repo" && $PWD == "$(pwd -P)" ]] || fail physical_cwd_mismatch
[[ $(realpath /usr/bin/cc) == /usr/bin/x86_64-linux-gnu-gcc-14 ]] ||
    fail gcc14_driver_mismatch
source_tu=platform/modules/base/src/result.c
[[ -f $source_tu && ! -L $source_tu ]] || fail source_missing
command -v openssl >/dev/null 2>&1 || fail sha3_tool_missing
[[ -x /usr/bin/time ]] || fail time_tool_missing
manifest=tools/verify/fixed_result_gcc14.args
manifest_sha3=$(openssl dgst -sha3-256 "$manifest" | awk '{print $NF}')
[[ $manifest_sha3 == befa08b481efd3d6387c61d39095f77ec65e9bf229f55a3da4a9cf4efdd20cfa ]] ||
    fail pinned_manifest_bytes_mismatch
work=$(mktemp -d /tmp/z23-fixed-result-gcc14.XXXXXX)
trap 'rm -rf -- "$work"' EXIT

# Expand the same Make variables as its build-only epoch recipe. The only
# automatic variable not available here is the source seed, appended below.
make -s --eval='__z23_result_profile: ; @printf "__PROFILE_BEGIN__\n"; printf "%s\n" $(CC) $(BUILD_ONLY_OBJECT_CFLAGS); printf "__TARGET__\n%s\n" "$(OBJ_DIR)/platform/modules/base/src/result.o"' \
    __z23_result_profile > "$work/make.args"
mapfile -t actual < "$work/make.args"
mapfile -t pinned < "$manifest"
[[ ${#actual[@]} == 184 && ${#pinned[@]} == 181 ]] || fail argv_count_mismatch
[[ ${actual[0]} == __PROFILE_BEGIN__ &&
   ${actual[1]} == "$repo/build/bin/zcc" &&
   ${actual[2]} == cc && ${actual[182]} == __TARGET__ ]] ||
    fail make_recipe_mismatch
target=${actual[183]}
[[ $target == build/obj/epochs/*/platform/modules/base/src/result.o ]] ||
    fail epoch_target_malformed

args=()
for ((i = 0; i < 180; i++)); do
    pinned_arg=${pinned[i]//@CWD@/$repo}
    [[ ${actual[i + 2]} == "$pinned_arg" ]] || fail pinned_profile_mismatch
    args+=("$pinned_arg")
done
[[ ${pinned[180]} == "-frandom-seed=$source_tu" ]] ||
    fail source_seed_mismatch
args+=("${pinned[180]}")

fixed_env=(LC_ALL=C TZ=UTC TMPDIR=/tmp PATH=/usr/bin:/bin)
compile() {
    local object=$1 dep=$2 stderr=$3 timing=$4
    /usr/bin/time -f 'wall_seconds=%e user_seconds=%U system_seconds=%S' \
        -o "$timing" env -i "${fixed_env[@]}" "${args[@]}" -MMD -MP -MF "$dep" \
        -MT "$target" -c -o "$object" "$source_tu" 2> "$stderr"
}
compile "$work/cold.o" "$work/cold.d" "$work/cold.stderr" "$work/cold.time"
compile "$work/repeat.o" "$work/repeat.d" "$work/repeat.stderr" "$work/repeat.time"
cmp "$work/cold.o" "$work/repeat.o" || fail object_bytes_differ
cmp "$work/cold.d" "$work/repeat.d" || fail dep_bytes_differ
cmp "$work/cold.stderr" "$work/repeat.stderr" || fail stderr_bytes_differ
/usr/bin/time -f 'wall_seconds=%e user_seconds=%U system_seconds=%S' \
    -o "$work/preprocess.time" env -i "${fixed_env[@]}" "${args[@]}" -MMD -MP \
    -MF "$work/preprocess.d" -MT "$target" -E -o "$work/result.i" \
    "$source_tu" 2> "$work/preprocess.stderr"
cmp "$work/cold.d" "$work/preprocess.d" || fail fresh_dep_bytes_differ

printf 'profile_green=1 source=%s cwd=%s gcc=%s flags=180 epoch_target=%s\n' \
    "$source_tu" "$repo" "$(realpath /usr/bin/cc)" "$target"
printf 'manifest_sha3=%s\n' "$manifest_sha3"
sha256sum "$work/cold.o" "$work/repeat.o" "$work/cold.d" "$work/result.i"
for run in cold repeat preprocess; do
    printf '%s ' "$run"
    cat "$work/$run.time"
done
printf 'cold_bytes object=%s dep=%s stderr=%s preprocess=%s\n' \
    "$(wc -c < "$work/cold.o")" "$(wc -c < "$work/cold.d")" \
    "$(wc -c < "$work/cold.stderr")" "$(wc -c < "$work/result.i")"
printf 'repeat_bytes object=%s dep=%s stderr=%s\n' \
    "$(wc -c < "$work/repeat.o")" "$(wc -c < "$work/repeat.d")" \
    "$(wc -c < "$work/repeat.stderr")"
printf 'object_equal=1 dep_equal=1 fresh_dep_equal=1 compiler_launches=2 preprocess_launches=1 proof_launches_avoided=0 attest_eligible=0\n'
