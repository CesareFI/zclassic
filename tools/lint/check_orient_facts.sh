#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
r=$(dirname "$0")/../..; l=$r/build/bin/z23-lint
[ -x "$l" ] || make -s -C "$r" build/bin/z23-lint >&2 || exit 2
exec "$l" check-orient-facts "$@"
