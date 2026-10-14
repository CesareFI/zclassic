#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Gate: tools/lint/lintc/gate_no_new_coordination_shell.c; baseline: tools/lint/coordination_shell_baseline.txt.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-new-coordination-shell "$@"
