#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Deterministic fixture/refusal tests; NO sockets, nodes, SSH or live acceptance.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
runner=$root/tools/scripts/qualify_wiki_runtime.sh
jq=$root/build/bin/jsonq
bounded=$root/build/bin/z23_bounded_run
scratch=${WIKI_RUNTIME_TEST_SCRATCH:-$HOME/.cache/development-scratch/z23}
mkdir -p "$scratch"
dd=$(mktemp -d "$scratch/wiki-runtime-test.XXXXXX")
echo "retained fixture evidence: $dd"
fail() { echo "selftest: $*" >&2; exit 1; }
[ -x "$jq" ] && [ -x "$bounded" ] || fail missing-native-tools
sh -n "$runner"
id_a=$(printf '%064d' 1); id_b=$(printf '%064d' 2)
sig=$(printf '%0128d' 0); zero=$(printf '%064d' 0)
source=$(printf '%040d' 0); binary=$(printf '%064d' 0)
for name in a-v1 a-v2 b-v1 b-v2; do
    parent=$zero
    case "$name" in a-v1) id=$id_a;; a-v2) id=$id_b; parent=$id_a;; b-v1) id=$(printf '%064d' 3);; b-v2) id=$(printf '%064d' 4); parent=$(printf '%064d' 3);; esac
    author=${name%-v?}
    body=$(printf 'G4 fixture %s' "$name" | od -An -v -tx1 | tr -d ' \n')
    bytes=$(printf 'G4 fixture %s' "$name" | wc -c | tr -d ' ')
    printf '{"schema":"zcl.result.v1","ok":true,"data":{"id":"%s","kind":"wiki","created_at":0,"ttl":1,"expires_at":1,"ref":"%s","host":"%s","signature":"%s","agent":"fixture","scope":"fleet","slug":"g4-fixture-%s","title":"G4 %s","supersedes":"%s","signed_scope":0,"signed_room":"","text_len":%s,"data_hex":"%s","offset":0,"next_offset":%s,"complete":true}}\n' "$id" "$zero" "$zero" "$sig" "$author" "$author" "$parent" "$bytes" "$body" "$bytes" > "$dd/$name.post"
done
cp "$dd/a-v1.post" "$dd/a.post"
# Explicit stub; runtime output must stay labelled fixture-only.
cat > "$dd/adapter" <<'ADAPTER'
#!/bin/sh
set -eu
name=$(basename "$0")
op=$1 run=$2
case "$op" in
identity|restart-offline)
    suffix=''
    [ "$op" != restart-offline ] || suffix=',"offline":true'
    [ "${CASE:-}" != restart ] || suffix=',"offline":false'
    printf '{"name":"%s","platform":"fixture","source":"%040d","binary_sha256":"%064d","run_id":"%s","isolation":"isolated"%s}\n' "$name" 0 0 "$run" "$suffix";;
write)
    [ "${CASE:-}" != write ] || exit 1
    case "$name" in a) n=1;; b) n=3;; esac
    case "$3" in *supersedes*) n=$((n+1));; esac
    id=$(printf '%064d' "$n")
    printf '{"ok":true,"data":{"id":"%s"}}\n' "$id";;
read)
    case "$3" in *0000000000000000000000000000000000000000000000000000000000000001*) writer=a-v1;; *0000000000000000000000000000000000000000000000000000000000000002*) writer=a-v2;; *0000000000000000000000000000000000000000000000000000000000000003*) writer=b-v1;; *) writer=b-v2;; esac
    if [ "${CASE:-}" = missing ] && [ "$name" = b ]; then
        case "$writer" in a-v*) exit 1;; esac
    fi
    cat "$FIXTURE_DIR/$writer.post";;
history)
    case "$3" in *g4-fixture-a*) n=1;; *) n=3;; esac
    printf '{"ok":true,"data":{"posts":[{"id":"%064d"},{"id":"%064d"}]}}\n' "$n" "$((n+1))";;
clock) echo '{"unix":2}';;
cleanup) [ "${CASE:-}" != cleanup ];;
*) exit 1;;
esac
ADAPTER
chmod +x "$dd/adapter"
cp "$dd/adapter" "$dd/a"
cp "$dd/adapter" "$dd/b"
manifest() {
    printf 'a\t%s\tfixture\t%s\t%s\t%s/a\nb\t%s\tfixture\t%s\t%s\t%s/b\n' "$1" "$source" "$binary" "$dd" "$2" "$source" "$binary" "$dd"
}
manifest both both > "$dd/valid.tsv"
printf 'a\tboth\nb\tboth\n' > "$dd/required.tsv"
# Observe the REAL timeout helper's result without changing its arguments.
REAL_BOUNDED=$bounded
export REAL_BOUNDED
cat > "$dd/observed-bounded" <<'BOUNDED'
#!/bin/sh
"$REAL_BOUNDED" "$@"
rc=$?
if [ "${3:-}" = matrix ]; then printf '%s\n' "$rc" > "$FIXTURE_DIR/matrix.exit"; fi
exit "$rc"
BOUNDED
chmod +x "$dd/observed-bounded"
export FIXTURE_DIR="$dd" WIKI_RUNTIME_FIXTURE=1
bounded=$dd/observed-bounded
run() { "$runner" "${CASE_REQUIRED:-$dd/required.tsv}" "$1" fixture "$2" "$jq" "$bounded" > "$2.stdout" 2> "$2.stderr"; }
run "$dd/valid.tsv" "$dd/positive" || fail positive
grep -F 'PASS fixture only; no live acceptance' "$dd/positive/verdict.txt" >/dev/null || fail fixture-label
grep -F 'pairs=4' "$dd/positive/scope.txt" >/dev/null || fail matrix
expect_fail() {
    if run "$1" "$dd/$2"; then fail "accepted-$2"; fi
}
printf 'a\tboth\tfixture\t%s\t%s\t%s/a\n' "$source" "$binary" "$dd" > "$dd/missing.tsv"
expect_fail "$dd/missing.tsv" missing
cat "$dd/missing.tsv" "$dd/missing.tsv" > "$dd/duplicate.tsv"
expect_fail "$dd/duplicate.tsv" duplicate
manifest reader reader > "$dd/readers.tsv"
cut -f1,2 "$dd/readers.tsv" > "$dd/readers-required.tsv"
CASE_REQUIRED=$dd/readers-required.tsv
expect_fail "$dd/readers.tsv" no-writer
grep -F 'missing-role' "$dd/no-writer.stderr" >/dev/null || fail no-writer-branch
manifest writer writer > "$dd/writers.tsv"
cut -f1,2 "$dd/writers.tsv" > "$dd/writers-required.tsv"
CASE_REQUIRED=$dd/writers-required.tsv
expect_fail "$dd/writers.tsv" no-reader
grep -F 'missing-role' "$dd/no-reader.stderr" >/dev/null || fail no-reader-branch
unset CASE_REQUIRED
cat "$dd/required.tsv" > "$dd/three-required.tsv"
printf 'c\tboth\n' >> "$dd/three-required.tsv"
CASE_REQUIRED=$dd/three-required.tsv
expect_fail "$dd/valid.tsv" omitted-third
grep -F 'required-set-mismatch' "$dd/omitted-third.stderr" >/dev/null || fail required-branch
unset CASE_REQUIRED
sed 's/fixture/other/g' "$dd/valid.tsv" > "$dd/wrong.tsv"
expect_fail "$dd/wrong.tsv" identity
CASE=write; export CASE
expect_fail "$dd/valid.tsv" uncertain
CASE=restart
expect_fail "$dd/valid.tsv" online-restart
CASE=cleanup
expect_fail "$dd/valid.tsv" cleanup
unset CASE
# Required signed fields, body, exact ID, signature and complete-body bounds.
for mutation in signature id data_hex complete next_offset signed_scope host; do
    case "$mutation" in
        signature|id|host) sed "s/\"$mutation\":\"[0-9]*\"/\"$mutation\":\"bad\"/" "$dd/a.post" > "$dd/bad.json";;
        data_hex) sed 's/"data_hex":"[^"]*"/"data_hex":"00"/' "$dd/a.post" > "$dd/bad.json";;
        complete) sed 's/"complete":true/"complete":false/' "$dd/a.post" > "$dd/bad.json";;
        next_offset) sed 's/"next_offset":[0-9]*/"next_offset":0/' "$dd/a.post" > "$dd/bad.json";;
        signed_scope) sed 's/"signed_scope":0,//' "$dd/a.post" > "$dd/bad.json";;
    esac
    if "$runner" compare "$dd/a.post" "$dd/bad.json" "$jq" > "$dd/$mutation.stdout" 2> "$dd/$mutation.stderr"; then fail "accepted-$mutation"; fi
done
echo '{"ok":false,"data":{}}' > "$dd/bad.json"
if "$runner" compare "$dd/a.post" "$dd/bad.json" "$jq"; then fail native-refusal; fi
printf '{' > "$dd/bad.json"
if "$runner" compare "$dd/a.post" "$dd/bad.json" "$jq"; then fail malformed; fi
# Structural native isolation refusals happen BEFORE binary invocation.
if "$runner" native "$root/build/bin/z23-dev" "$HOME/.zclassic-c23" 39001 "$source" fixture a read fixture '{"id":"bad"}'; then fail canonical-path; fi
echo 'fixture structural/refusal checks completed; no live qualification'
# A missing reader cannot become a partial successful matrix.
CASE=missing; export CASE
expect_fail "$dd/valid.tsv" missing-reader
grep -F 'propagation-deadline' "$dd/missing-reader.stderr" >/dev/null || fail deadline-branch
[ "$(cat "$dd/matrix.exit")" = 124 ] || fail real-deadline-not-exercised
[ -s "$dd/missing-reader/a-v2.original.json" ] && [ -s "$dd/missing-reader/b-v2.original.json" ] || fail deadline-before-originals
unset CASE
# History membership must retain BOTH immutable revisions, not only the head.
printf '{"ok":true,"data":{"posts":[{"id":"%s"}]}}\n' "$id_b" > "$dd/history-missing.json"
if "$runner" history-check "$dd/a-v1.post" "$dd/a-v2.post" "$dd/history-missing.json" "$jq" > "$dd/history.stdout" 2> "$dd/history.stderr"; then fail missing-history; fi
grep -F 'missing-history-revision' "$dd/history.stderr" >/dev/null || fail history-branch
# Even if both inputs omit a required signed field, equality cannot prove it.
sed 's/"signed_scope":0,//' "$dd/a.post" > "$dd/bad.json"
if "$runner" compare "$dd/bad.json" "$dd/bad.json" "$jq"; then fail missing-both; fi
# Prove native endpoint selection with a real binary and NO running fixture.
# Repository-sanctioned isolated root; marker remains as bounded test evidence.
probe=$(mktemp -d /tmp/zcl23-wiki-runtime-probe-XXXXXX)
printf '%s\n' fixture > "$probe/wiki-runtime-owner"
if "$bounded" 3000 "$runner" native "$root/build/bin/z23-dev" "$probe" 39997 "$source" fixture a read fixture "{\"id\":\"$id_a\"}" > "$dd/native-offline.json" 2> "$dd/native-offline.err"; then
    fail offline-endpoint-answered
fi
[ "$("$jq" get error.code < "$dd/native-offline.json")" = NODE_UNAVAILABLE ] || fail native-target-refusal
printf '%s\n' "$probe" > "$dd/native-probe-path.txt"
echo 'PASS complete deterministic checks, including fixed deadline and native offline target refusal'
