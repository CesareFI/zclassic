#!/bin/sh
# check_lib_layering — HARD lib/ → app/ include fence (native).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-lib-layering "$@"
