#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
R=$(cd "$(dirname "$0")/../.." && pwd); B=$R/build/bin/gate_receipt; A=$R/tools/agent
{ [ -x "$B" ] && [ -z "$(find "$A" "$R/platform/modules/sha3" "$R/platform/modules/base" "$R/core/modules/crypto" \( -name 'gate_receipt*' -o -name '*.h' -o -name sha3.c -o -name safe_alloc.c \) -newer "$B" 2>/dev/null)" ]; } || { mkdir -p "$R/build/bin" && "${CC:-cc}" -std=c23 -O2 -Wall -Wextra -Werror -pedantic -I"$R/platform/modules/sha3/include" -I"$R/core/modules/crypto/include" -I"$R/platform/modules/base/include" -o "$B.$$" "$A/gate_receipt.c" "$A/gate_receipt_proc.c" "$A/gate_receipt_text.c" "$R/platform/modules/sha3/src/sha3.c" "$R/platform/modules/base/src/safe_alloc.c" && mv -f "$B.$$" "$B"; } >&2 || { rm -f "$B.$$"; echo "gate-receipt: cannot build $B (see above)" >&2; exit 2; }
exec "$B" "$R" "$@"
