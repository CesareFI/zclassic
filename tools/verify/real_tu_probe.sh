#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# Linux x86-64 GCC 13/14 witness and unprivileged compile-core qualification.
# The result never authorizes reuse: the complete input/tool closure is absent.
set -euo pipefail

if (( $# != 2 )); then
    printf 'usage: %s /absolute/gcc -std=c23|-std=c2x\n' "$0" >&2
    exit 2
fi
compiler=$1
standard=$2
case "$standard" in
    -std=c23|-std=c2x) ;;
    *) printf 'unsupported standard: %s\n' "$standard" >&2; exit 2 ;;
esac
case "$compiler" in
    /*) ;;
    *) printf 'compiler path must be absolute\n' >&2; exit 2 ;;
esac
if [[ $compiler != /usr/bin/gcc ]]; then
    printf 'qualification supports only root-owned /usr/bin/gcc\n' >&2
    exit 2
fi

repo=$(git rev-parse --show-toplevel)
source_tu=platform/modules/base/src/result.c
work=$(mktemp -d /tmp/z23-verify-real-tu.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
flags=(
    "$standard" -g -O3 -march=x86-64-v3 -flto=auto
    -Wall -Wextra -Werror -pedantic
    "-ffile-prefix-map=$repo=/zclassic23"
    -gno-record-gcc-switches -fstack-protector-strong
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fcf-protection=full -fPIE
    -Iplatform/modules/sha3/include -Iplatform/modules/base/include
    -D_POSIX_C_SOURCE=200809L
    "-frandom-seed=$source_tu"
)

cd "$repo"
baseline_start_ns=$(date +%s%N)
"$compiler" "${flags[@]}" -E "$source_tu" -o "$work/input.i"
"$compiler" "${flags[@]}" -c -MD -MF "$work/cold.d" -MT result.o \
    "$source_tu" -o "$work/result.o" 2> "$work/cold.stderr"
cp "$work/result.o" "$work/source.o"
"$compiler" "${flags[@]}" -x cpp-output -c "$work/input.i" -o "$work/result.o"
baseline_end_ns=$(date +%s%N)

if cmp -s "$work/source.o" "$work/result.o"; then
    equal=1
else
    equal=0
fi
printf 'real_tu=%s compiler=%s standard=%s source_vs_cpp_equal=%d\n' \
    "$source_tu" "$compiler" "$standard" "$equal"
sha256sum "$work/source.o" "$work/result.o"
printf 'baseline_compiler_launches=3 reusable_object=%d baseline_ms=%d\n' \
    "$equal" "$(((baseline_end_ns - baseline_start_ns) / 1000000))"
if (( equal != 0 )); then
    printf 'expected GCC debug/LTO direct-source mismatch disappeared\n' >&2
    exit 1
fi

# Build the fixed-profile C23 core, then make its byte claims independently.
"$compiler" "$standard" -D_XOPEN_SOURCE=700 -Wall -Wextra -Werror -pedantic \
    -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
    tools/verify/compile_core.c platform/modules/sha3/src/sha3.c \
    -o "$work/compile-core"
driver=$(realpath -- "$compiler")
driver_hash=$("$work/compile-core" hash "$driver")
source_hash=$("$work/compile-core" hash "$source_tu")
pp_hash=$("$work/compile-core" hash "$work/input.i")
mkdir -m 700 "$work/qualified"
core_start_ns=$(date +%s%N)
"$work/compile-core" compile "$compiler" "$standard" \
    "$driver_hash" "$source_hash" "$pp_hash" "$work/qualified" \
    > "$work/qualified.out"
core_end_ns=$(date +%s%N)
cmp "$work/source.o" "$work/qualified/result.o"
cmp "$work/cold.d" "$work/qualified/result.d"
cmp "$work/cold.stderr" "$work/qualified/compile.stderr"
grep -Fx "object_sha3=$("$work/compile-core" hash "$work/qualified/result.o")" \
    "$work/qualified.out" >/dev/null
grep -Fx "dep_sha3=$("$work/compile-core" hash "$work/qualified/result.d")" \
    "$work/qualified.out" >/dev/null
grep -Fx "stderr_sha3=$("$work/compile-core" hash "$work/qualified/compile.stderr")" \
    "$work/qualified.out" >/dev/null
grep -Fx 'attest_eligible=0' "$work/qualified.out"
grep -Fx 'reason=tool_and_input_closure_unproven' "$work/qualified.out"
printf 'direct_source_artifacts_equal=1 core_compiler_launches=2 core_ms=%d qualification_only=1 proof_launches_avoided=0\n' \
    "$(((core_end_ns - core_start_ns) / 1000000))"

refuse() {
    local want=$1
    shift
    local got
    if "$work/compile-core" "$@" > "$work/refused.out" 2> "$work/refused.err"; then
        printf 'expected refusal: %s\n' "$want" >&2
        exit 1
    else
        got=$?
    fi
    if (( got != 2 )); then
        printf 'wrong refusal exit for %s: %d\n' "$want" "$got" >&2
        exit 1
    fi
    grep -Fx "compile_core_refuse=$want" "$work/refused.err" >/dev/null
}

zeros=$(printf '%064d' 0)
mkdir -m 700 "$work/bad-std" "$work/bad-hash" "$work/bad-source" \
    "$work/bad-pp" "$work/bad-driver"
mkdir -m 755 "$work/bad-output"
refuse request_shape_unsupported compile
refuse standard_unsupported compile "$compiler" -std=gnu23 \
    "$driver_hash" "$source_hash" "$pp_hash" "$work/bad-std"
refuse hash_malformed compile "$compiler" "$standard" \
    X "$source_hash" "$pp_hash" "$work/bad-hash"
refuse source_bytes_mismatch compile "$compiler" "$standard" \
    "$driver_hash" "$zeros" "$pp_hash" "$work/bad-source"
refuse preprocessed_bytes_mismatch compile "$compiler" "$standard" \
    "$driver_hash" "$source_hash" "$zeros" "$work/bad-pp"
refuse output_dir_unsafe compile "$compiler" "$standard" \
    "$driver_hash" "$source_hash" "$pp_hash" "$work/bad-output"

# A replaced executable must be rejected even if it would still compile.
cp -- "$driver" "$work/replaced-gcc"
printf '\001' >> "$work/replaced-gcc"
chmod 700 "$work/replaced-gcc"
replacement_hash=$("$work/compile-core" hash "$work/replaced-gcc")
refuse driver_bytes_mismatch compile "$compiler" "$standard" \
    "$replacement_hash" "$source_hash" "$pp_hash" "$work/bad-driver"
refuse compiler_path_unsupported compile "$work/replaced-gcc" "$standard" \
    "$driver_hash" "$source_hash" "$pp_hash" "$work/bad-driver"
printf 'red_refusals=8 replacement_byte_claim_refused=1 arbitrary_compiler_refused=1\n'
