#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Select a verified host-local dev linker, with portable fallback.
#
# No persistent selection cache: this runs from $(shell) at Makefile parse
# time and re-probes every invocation (a few tiny `int main` links, well
# under a second). A cached `-fuse-ld=mold` value outlived the mold binary
# on this host and broke every dev/test link with
# `collect2: fatal error: cannot find 'ld'`; re-probing cannot go stale.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

probe_fuse_ld()
{
    local ld="$1"
    local out="$ROOT/build/.ld-probe-$ld"
    mkdir -p "$ROOT/build" || return 1
    if printf 'int main(void){return 0;}\n' |
        cc -fuse-ld="$ld" -x c - -o "$out" >/dev/null 2>&1; then
        rm -f "$out"
        return 0
    fi
    rm -f "$out"
    return 1
}

if probe_fuse_ld mold; then
    printf '%s' '-fuse-ld=mold'
elif probe_fuse_ld lld; then
    printf '%s' '-fuse-ld=lld'
elif probe_fuse_ld gold; then
    # gold defaults to --no-threads; mold and lld parallelize internally
    # with no flag needed, but gold's monolithic test_parallel_fast /
    # z23-dev links (hundreds of objects, one shot, every edit) pay for
    # single-threaded symbol resolution on every dev-loop link unless
    # asked. --thread-count matches the devbuild scheduler's per-lane CPU
    # share (28 logical CPUs / 3 z23 lanes), not the host's full core
    # count, so a link never bids for CPU another lane already holds.
    printf '%s' '-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9'
fi
