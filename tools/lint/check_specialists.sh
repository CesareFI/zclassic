#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Gate: tools/lint/lintc/gate_specialists.c. Exit 0 clean, 1 false row, 2 hollow or missing catalog.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-specialists "$@"
