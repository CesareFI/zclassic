#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
d=$(cd "$(dirname "$0")" && pwd) && r=$d/../../.. && mkdir -p "$r/build/bin" || exit 2
${CC:-cc} -std=c23 -Wall -Wextra -Werror -pedantic -DPARITY_DIR="\"$d\"" -o "$r/build/bin/run-parity-oracle" "$d/run_parity_oracle.c" || exit $?
exec "$r/build/bin/run-parity-oracle" "$@"
