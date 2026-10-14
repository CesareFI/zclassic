#!/bin/sh
# check_result_discard — RATCHET gate (shrink-only).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-result-discard "$@"
