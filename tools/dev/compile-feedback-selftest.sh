#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Exercise the actual diagnostic gate against isolated compiler outputs.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="$(awk '/^compile_affected_gate\(\) \{/{f=1} f{print} f&&/^\}/{exit}' \
    "$repo/tools/agent_fast_ci.sh")"
[ -n "$gate" ] || { printf 'missing diagnostic gate\n' >&2; exit 1; }
eval "$gate"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/zcl-compile-feedback.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT
cd "$fixture"
printf 'original-object\n' > epoch.o
printf 'original-depfile\n' > epoch.d
changed_file_hints() { printf '%s\n' changed.c Makefile; }
log() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; exit 1; }
make_fast() {
    printf '%s\n' "$1" >> order
    case "$1" in
        templates) printf '#define GENERATED_VALUE 0\n' > generated.h ;;
        fast-compile) : > full ;;
        *) fail "unexpected target $1" ;;
    esac
}
capture_source_identity_record() { printf 'recapture\n' >> order; printf 'fixture 0 0\n'; }
ensure_fresh_compdb() {
    [ -s generated.h ] || fail 'generated prerequisite not prepared'
    [ "$FROZEN_SOURCE_RECORD" = 'fixture 0 0' ] || fail 'source was not recaptured'
    printf 'compdb\n' >> order
}
compdb_command_for_source() {
    printf 'diagnostic\n' >> order
    printf 'cc -std=c2x -Werror -MMD -MP -MF epoch.d -MT epoch.o -c -o epoch.o changed.c'
}
jq() { printf 'epoch.o\n'; }
printf '#include "generated.h"\nint main(void) { return GENERATED_VALUE; }\n' > changed.c
compile_affected_gate
[ -e full ]
[ "$(cat order)" = "$(printf 'templates\nrecapture\ncompdb\ndiagnostic\nfast-compile')" ]
[ "$(cat epoch.o)" = original-object ]
[ "$(cat epoch.d)" = original-depfile ]
rm full order generated.h
printf 'int main( {\n' > changed.c
if compile_affected_gate; then fail 'invalid C accepted'; fi
[ ! -e full ]
[ "$(cat epoch.o)" = original-object ]
[ "$(cat epoch.d)" = original-depfile ]
# Unknown recipes remain on the native path without executing their command.
rm order
compdb_command_for_source() { printf 'touch unexpected-diagnostic'; }
compile_affected_gate
[ ! -e unexpected-diagnostic ]
[ "$(cat order)" = "$(printf 'templates\nrecapture\ncompdb\nfast-compile')" ]
[ "$(cat epoch.o)" = original-object ]
[ "$(cat epoch.d)" = original-depfile ]
rm full
# A failed prerequisite must refuse even when the caller tests the exit code.
rm order
make_fast() { printf '%s\n' "$1" >> order; return 1; }
if compile_affected_gate; then fail 'failed prerequisite accepted'; fi
[ "$(cat order)" = templates ]
# Header-only changes keep the original full fallback without diagnostic work.
rm order
make_fast() { printf '%s\n' "$1" >> order; }
changed_file_hints() { printf 'generated.h\n'; }
compile_affected_gate
[ "$(cat order)" = fast-compile ]
printf 'PASS compile-feedback-selftest prerequisites scratch failure fallback\n'
