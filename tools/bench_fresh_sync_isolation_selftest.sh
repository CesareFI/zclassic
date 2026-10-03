#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify the fresh-sync benchmark never imports serving TLS material.
set -eu

bench=$1
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z23-bench-fixture.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/home/.zclassic-c23/ssl" "$fixture/run/build/bin"
printf 'certificate-sentinel\n' > "$fixture/home/.zclassic-c23/ssl/fullchain.pem"
printf 'private-key-sentinel\n' > "$fixture/home/.zclassic-c23/ssl/privkey.pem"
ln -s /bin/true "$fixture/run/build/bin/zclassic23"

set +e
(cd "$fixture/run" && HOME="$fixture/home" "$bench") > "$fixture/output" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]

benchdir=$(find "$fixture/home" -maxdepth 1 -type d \
    -name '.zclassic-c23-bench-*' -print -quit)
[ -n "$benchdir" ]
test ! -e "$benchdir/ssl/fullchain.pem"
test ! -e "$benchdir/ssl/privkey.pem"
printf '%s\n' 'bench_fresh_sync isolation: PASS'
