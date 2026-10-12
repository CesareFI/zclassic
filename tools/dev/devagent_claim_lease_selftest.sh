#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Exercise lease takeover through the public dev command in disposable Git worktrees.
set -eu

bin=${1:-build/bin/z23-dev}
case $bin in /*) ;; *) bin="$(pwd)/$bin" ;; esac
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z23-claim-lease.XXXXXX")
fixture=$(cd "$fixture" && pwd -P)
trap 'test ! -d "$fixture/repo/.git" || chmod 700 "$fixture/repo/.git"; rm -rf "$fixture"' EXIT HUP INT TERM
repo=$fixture/repo
other=$fixture/other
mkdir "$repo"
git -C "$repo" init -q
printf 'base\n' > "$repo/base.txt"
git -C "$repo" add base.txt
git -C "$repo" -c user.name='Z23 Test' -c user.email='z23-test@example.invalid' \
    -c commit.gpgsign=false commit -q -m base
git -C "$repo" worktree add -q -b other "$other"
ledger=$repo/.git/z23-agent-claims.jsonl

claim() {
    "$bin" dev agent claim --input="{\"cwd\":\"$1\",\"story\":\"lease-test\",\"files\":[\"engine/a.c\"]}"
}

# A well-formed expired lease becomes available and is removed atomically.
printf '{"ts":"old","expires_unix":1,"worktree":"%s","branch":"other","story":"stalled","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo")
printf '%s\n' "$result" | grep -q '"status":"passed"'
printf '%s\n' "$result" | grep -q '"expired_reclaimed":1'
printf '%s\n' "$result" | grep -q '"expires_unix":'
if grep -q '"story":"stalled"' "$ledger"; then
    printf 'expired foreign lease survived claim\n' >&2
    exit 1
fi
result=$(claim "$other" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'
result=$(claim "$repo")
printf '%s\n' "$result" | grep -q '"live":1'
test "$(wc -l < "$ledger")" -eq 1

# A live lease and an old row without expiry still protect their owner.
future=$(($(date +%s) + 300))
printf '{"ts":"live","expires_unix":%s,"worktree":"%s","branch":"other","story":"live","files":["engine/a.c"]}\n' "$future" "$other" > "$ledger"
before=$(git hash-object "$ledger")
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'
test "$before" = "$(git hash-object "$ledger")"

printf '{"ts":"legacy","worktree":"%s","branch":"other","story":"legacy","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'

printf '{"ts":"bad","expires_unix":"bad","worktree":"%s","branch":"other","story":"bad","files":["engine/a.c"]}\n' "$other" > "$ledger"
result=$(claim "$repo" || true)
printf '%s\n' "$result" | grep -q '"code":"CLAIM_OVERLAP"'

# Explicit retirement preserves exact orphan evidence and every other byte.
orphan=$fixture/retired
registered=$fixture/registered
legacy=$fixture/legacy.row
keep=$fixture/kept.rows
printf '{"ts":"legacy", "worktree":"%s", "branch":"old", "story":"orphan", "files":["engine/a.c"]}\r\n' "$orphan" > "$legacy"
printf '\r\n{"ts":"keep","expires_unix":%s,"worktree":"%s","story":"live","files":["engine/b.c"]}\r\n' "$future" "$other" > "$keep"

retire() {
    "$bin" dev agent claim --input="{\"cwd\":\"$repo\",\"story\":\"retire verified orphan\",\"files\":[],\"retire_worktree\":\"$1\"}"
}

cat "$legacy" "$keep" > "$ledger"
if result=$(retire "$orphan"); then
    :
else
    printf 'verified orphan retirement failed: %s\n' "$result" >&2
    exit 1
fi
printf '%s\n' "$result" | grep -q '"retired":1'
printf '%s\n' "$result" | grep -q '"evidence_sha256":"[0-9a-f]\{64\}"'
evidence=$(printf '%s\n' "$result" | sed -n 's/.*"evidence_path":"\([^"]*\)".*/\1/p')
test -n "$evidence"
cmp "$legacy" "$evidence"
cmp "$keep" "$ledger"

assert_retirement_refused() {
    before=$(git hash-object "$ledger")
    result=$(retire "$1" || true)
    if ! printf '%s\n' "$result" | grep -q "\"code\":\"$2\""; then
        printf 'expected %s without mutation, got: %s\n' "$2" "$result" >&2
        exit 1
    fi
    test "$before" = "$(git hash-object "$ledger")"
}

# Registration protects a missing checkout; case aliases are conservative.
git -C "$repo" worktree add -q -b registered "$registered"
rm -rf "$registered"
printf '{"worktree":"%s","files":["engine/a.c"]}\n' "$registered" > "$ledger"
assert_retirement_refused "$registered" CLAIM_OWNER_REGISTERED
alias=$fixture/REGISTERED
printf '{"worktree":"%s","files":["engine/a.c"]}\n' "$alias" > "$ledger"
assert_retirement_refused "$alias" CLAIM_OWNER_REGISTERED
git -C "$repo" worktree prune --expire=now

# A live path, dangling symlink, leases and ambiguous rows remain untouched.
mkdir "$orphan"
cat "$legacy" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_OWNER_NOT_ABSENT
rmdir "$orphan"
ln -s "$fixture/not-present" "$orphan"
assert_retirement_refused "$orphan" CLAIM_OWNER_NOT_ABSENT
rm "$orphan"
for expiry in "$future" 1 '"bad"' null; do
    printf '{"expires_unix":%s,"worktree":"%s","files":["engine/a.c"]}\n' "$expiry" "$orphan" > "$ledger"
    assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
done
cat "$legacy" "$legacy" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
cat "$legacy" > "$ledger"
printf '{"expires_unix":%s,"worktree":"%s","files":["engine/a.c"]}\n' "$future" "$orphan" >> "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
printf '{"worktree":"%s","worktree":"%s","files":[]}\n' "$orphan" "$orphan" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
printf '{"worktree":"%s","story":"ambiguous\\u0020encoding","files":[]}\n' "$orphan" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED

# Malformed raw strings and numbers cannot authorize an exact-owner match.
printf '{"worktree":"%s\000suffix","files":[]}\n' "$orphan" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
printf '{"worktree\000suffix":"%s","files":[]}\n' "$orphan" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
printf '{"worktree":"%s","story":"bad\001control","files":[]}\n' "$orphan" > "$ledger"
assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
for number in 01 - 1e 1. 1e+ -01; do
    printf '{"worktree":"%s","extra":%s,"files":[]}\n' "$orphan" "$number" > "$ledger"
    assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
done

# A failed evidence create leaves all claims intact. No root-only assertion.
if test "$(id -u)" -ne 0; then
    cat "$legacy" "$keep" > "$ledger"
    chmod 500 "$repo/.git"
    assert_retirement_refused "$orphan" CLAIM_ORPHAN_REFUSED
    chmod 700 "$repo/.git"
fi

printf 'devagent_claim_lease: PASS\n'
