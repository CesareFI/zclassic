#!/bin/sh
# check_hosted_suite_verdict.sh — exec shim: the gate is C23 in z23-lint.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hosted-suite-verdict "$@"
