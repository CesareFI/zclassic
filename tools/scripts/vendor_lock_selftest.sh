#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-vendor-lock.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
fail() { printf 'vendor_lock_selftest: %s\n' "$*" >&2; exit 1; }
cc -std=c23 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE=1 \
    -I"$ROOT/platform/modules/platform/include" -I"$ROOT/platform/modules/util/include" \
    -I"$ROOT/platform/modules/base/include" "$ROOT/platform/modules/platform/src/clock.c" \
    "$ROOT/tools/vendor_lock.c" -o "$fixture/lock"
cc -std=c23 -O2 -Wall -Wextra -Werror "$ROOT/tools/tests/vendor_lock_test.c" -o "$fixture/test"
"$fixture/test" "$fixture/lock" "$fixture/runtime.lock"
[[ -f "$fixture/runtime.lock" ]] || fail 'persistent regular lock disappeared'
mkdir "$fixture/legacy.lock"
if "$fixture/lock" "$fixture/legacy.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'unknown legacy directory admitted'
fi
[[ -d "$fixture/legacy.lock" ]] || fail 'legacy directory removed'
[[ "$(cat "$fixture/out")" == *vendor_lock_legacy_directory_refused* ]] || fail 'unnamed legacy refusal'
ln -s "$fixture/runtime.lock" "$fixture/symlink.lock"
if "$fixture/lock" "$fixture/symlink.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'symlink lock admitted'
fi
chmod 0666 "$fixture/runtime.lock"
if "$fixture/lock" "$fixture/runtime.lock" 0 true >"$fixture/out" 2>&1; then
    fail 'writable lock admitted'
fi
chmod 0600 "$fixture/runtime.lock"
VENDOR_LOCK_HELD=1 "$fixture/lock" "$fixture/runtime.lock" 0 true
printf '%s\n' 'vendor_lock_selftest: legacy, symlink, permissions, environment PASS'
