#!/bin/sh
# check_command_input_keys.sh — exec shim: the gate is C23 in z23-lint.
cd "$(dirname "$0")/../.." || exit 2
exec build/bin/z23-lint check-command-input-keys "$@"
