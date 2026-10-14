#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
p=$(mktemp "$HOME/.z23-tree-probe.XXXXXX") && trap 'rm -f "$p"' EXIT || exit 1
${CC:-cc} -std=c23 -Wall -Wextra -Werror -pedantic -Iplatform/modules/sha3/include -Iplatform/modules/base/include tools/verify/tree_closure_probe.c platform/modules/sha3/src/sha3.c -o "$p" && "$p" "$0" "$@"
