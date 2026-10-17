#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-vendor-lock.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
fail() { printf 'vendor_lock_selftest: %s\n' "$*" >&2; exit 1; }
host_cc="${HOSTCC:-cc}"
case "$(uname -s 2>/dev/null)" in
    MSYS*|MINGW*|CYGWIN*) host_cc="${HOSTCC:-${ZCL_BOOTSTRAP_CC:-/usr/bin/cc}}" ;;
esac
[[ "$host_cc" =~ ^[A-Za-z0-9_./:+,=%-]+([[:space:]]+[A-Za-z0-9_./:+,=%-]+)*$ ]] ||
    fail 'HOSTCC contains unsupported shell syntax'
read -r -a host_argv <<<"$host_cc"
case "${host_argv[0]}" in
    /*) ;;
    */*) [[ ! -f "$ROOT/${host_argv[0]}" ]] || host_argv[0]="$ROOT/${host_argv[0]}" ;;
esac
native_acl=false
acl_sources=() acl_flags=()
case "$("${host_argv[@]}" -dM -E -x c - </dev/null)" in
    *'#define __MSYS__ 1'*)
        native_acl=true
        acl_sources=("$ROOT/platform/modules/platform/src/private_acl_internal.c"
            "$ROOT/platform/modules/base/src/safe_alloc.c")
        acl_flags=(-ladvapi32)
        ;;
esac
"${host_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE=1 \
    -I"$ROOT/platform/modules/platform/include" -I"$ROOT/platform/modules/util/include" \
    -I"$ROOT/platform/modules/base/include" "$ROOT/platform/modules/platform/src/clock.c" \
    -I"$ROOT/platform/modules/platform/src" "$ROOT/tools/vendor_lock.c" \
    ${acl_sources[@]+"${acl_sources[@]}"} ${acl_flags[@]+"${acl_flags[@]}"} -o "$fixture/lock"
"${host_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror "$ROOT/tools/tests/vendor_lock_test.c" -o "$fixture/test"
"$fixture/test" "$fixture/lock" "$fixture/runtime.lock"
[[ -f "$fixture/runtime.lock" ]] || fail 'persistent regular lock disappeared'
mkdir "$fixture/legacy.lock"
if "$fixture/lock" "$fixture/legacy.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'unknown legacy directory admitted'
fi
[[ -d "$fixture/legacy.lock" ]] || fail 'legacy directory removed'
[[ "$(cat "$fixture/out")" == *vendor_lock_legacy_directory_refused* ]] || fail 'unnamed legacy refusal'
if $native_acl; then
    MSYS="${MSYS:+$MSYS }winsymlinks:sys" ln -s "$fixture/runtime.lock" "$fixture/symlink.lock"
else
    ln -s "$fixture/runtime.lock" "$fixture/symlink.lock"
fi
[[ -L "$fixture/symlink.lock" ]] || fail 'symlink fixture was not created'
if "$fixture/lock" "$fixture/symlink.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'symlink lock admitted'
fi
if $native_acl; then
    "${host_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror \
        "$ROOT/tools/tests/vendor_lock_acl_test.c" -ladvapi32 -o "$fixture/acl-test"
    "$fixture/acl-test" "$fixture/lock" "$fixture/acl.lock"
else
chmod 0666 "$fixture/runtime.lock"
if "$fixture/lock" "$fixture/runtime.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'writable lock admitted'
fi
chmod 0600 "$fixture/runtime.lock"
fi
VENDOR_LOCK_HELD=1 "$fixture/lock" "$fixture/runtime.lock" 0 true
printf '%s\n' 'vendor_lock_selftest: legacy, symlink, permissions, environment PASS'
