#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Shim: the gate is tools/lint/lintc/gate_accel_oracle_pinned.c.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-accel-oracle-pinned "$@"
