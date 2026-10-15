#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: the promotion receipt ledger stays an append-only, hash-linked, signed chain.
l=$(dirname "$0")/../../build/bin/z23-lint; [ -x "$l" ] || make -s -C "$(dirname "$0")/../.." build/bin/z23-lint >&2 || exit 2
exec "$l" check-promotion-receipt-chain "$@"
