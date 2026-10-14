#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
bin="$(dirname "$0")/../../build/bin/z23-lint"
[ "${1:-}" = "--self-test" ] && { shift; exec "$bin" check-windows-acceptance-guard --selftest "$@"; }
exec "$bin" check-windows-acceptance-guard "$@"
