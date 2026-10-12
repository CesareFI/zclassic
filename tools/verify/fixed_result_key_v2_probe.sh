#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
set -euo pipefail
work=$(mktemp -d "${HOME}/.z23-fixed-key-v2.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
/usr/bin/cc -std=c23 -Wall -Wextra -Werror -pedantic \
    -Itools -Iplatform/modules/base/include -Iplatform/modules/sha3/include \
    -Iplatform/modules/platform/include \
    tools/verify/fixed_result_key_v2.c tools/verify/fixed_result_contract.c \
    tools/verify/fixed_result_key_v2_probe.c \
    platform/modules/sha3/src/sha3.c -o "$work/probe"
"$work/probe"
