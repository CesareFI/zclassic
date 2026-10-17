#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Finite owner-ready isolated-node qualification, never a service.
# Manifest TSV: name role platform source40 binary_sha256 adapter_absolute_path.
# REQUIRED TSV: name role. It must list the owner's COMPLETE target set;
# role omissions are explicit partial coverage, never full G4 qualification.
# Adapter argv: identity|write|read|history|restart-offline|clock|cleanup RUN [INPUT].
# identity: {name,platform,source,binary_sha256,run_id,isolation:"isolated"}.
# write/read: unchanged native zcl.result.v1 envelopes. No uncertain-write retry.
# restart-offline: SAME isolated_node_env datadir/key, no networking; identity
# plus offline:true. Owner wrapper retains isolated_node_env traps/cleanup.
set -eu
fail() { echo "wiki-runtime: $*" >&2; exit 1; }
label() { case "$1" in ''|*[!a-z0-9-]*) return 1;; esac; [ "${#1}" -le 24 ]; }
hex() { [ "${#1}" -eq "$2" ] && case "$1" in *[!0-9a-f]*) return 1;; *) return 0;; esac; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
get() { "$jq" get "$2" < "$1"; }
# This real native endpoint mode is reusable from owner-controlled local/SSH
# wrappers. It neither creates markers nor launches nodes nor invents RPC APIs.
if [ "${1:-}" = native ]; then
    [ "$#" -ge 9 ] || fail 'native BINARY DATADIR RPCPORT SOURCE PLATFORM NAME OP RUN [INPUT]'
    shift; bin=$1 dd=$2 port=$3 source=$4 platform=$5 name=$6 op=$7 run=$8; shift 8
    case "$bin" in /*) [ -x "$bin" ] || fail binary;; *) fail binary;; esac
    case "$dd" in /tmp/zcl23-*) :;; *) fail isolation;; esac
    case "${dd#/tmp/}" in */*) fail isolation-traversal;; esac
    [ "$(CDPATH= cd -P -- "$dd" && pwd)" = "$dd" ] || fail isolation-symlink
    case "$port" in 39[0-9][0-9][0-9]) :;; *) fail port;; esac
    hex "$source" 40 && label "$platform" && label "$name" && label "$run" || fail identity
    [ -f "$dd/wiki-runtime-owner" ] && [ "$(cat "$dd/wiki-runtime-owner")" = "$run" ] || fail owner-marker
    case "$op" in
        identity)
            # source is owner-qualified git provenance, NOT the version's
            # complete-source digest. Artifact SHA below is measured here.
            printf '{"name":"%s","platform":"%s","source":"%s","binary_sha256":"%s","run_id":"%s","isolation":"isolated"}\n' "$name" "$platform" "$source" "$(sha "$bin")" "$run";;
        write|read|history)
            [ "$#" -eq 1 ] || fail input
            ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$bin" "fleet.wiki.$op" --input="$1";;
        clock) printf '{"unix":%s}\n' "$(date +%s)";;
        *) fail 'lifecycle requires owner isolated_node_env wrapper';;
    esac
    exit
fi
if [ "${1:-}" = compare ]; then
    [ "$#" -eq 4 ] || fail compare-args
    original=$2 actual=$3 jq=$4
    [ "$(get "$original" ok)" = true ] && [ "$(get "$actual" ok)" = true ] || fail native-refusal
    # Exclude receiver-local seq/received_at. Include every signed field and
    # All bytes of the short test body must fit this single exact-ID chunk.
    # This compares stored signed content; it is not an independent crypto check.
    for field in id kind created_at ttl expires_at ref host signature agent scope room data_hex text_len slug title supersedes receipt signed_scope signed_room; do
        a=$("$jq" raw "data.$field" < "$original" || true)
        b=$("$jq" raw "data.$field" < "$actual" || true)
        [ "$a" = "$b" ] || fail "signed-field-$field"
    done
    [ "$(get "$actual" data.kind)" = wiki ] || fail kind
    for field in created_at ttl expires_at text_len signed_scope; do
        [ "$("$jq" type "data.$field" < "$actual")" = number ] || fail "missing-$field"
    done
    for field in agent scope slug title supersedes signed_room; do
        [ "$("$jq" type "data.$field" < "$actual")" = string ] || fail "missing-$field"
    done
    hex "$(get "$actual" data.id)" 64 && hex "$(get "$actual" data.signature)" 128 &&
        hex "$(get "$actual" data.host)" 64 && hex "$(get "$actual" data.ref)" 64 || fail signed-id
    [ "$(get "$actual" data.offset)" = 0 ] && [ "$(get "$actual" data.complete)" = true ] &&
        [ "$(get "$actual" data.next_offset)" = "$(get "$actual" data.text_len)" ] || fail full-body-required
    body=$(get "$actual" data.data_hex)
    bytes=$(get "$actual" data.text_len)
    case "$bytes" in ''|*[!0-9]*) fail body-length;; esac
    [ "${#bytes}" -le 3 ] && [ "$bytes" -gt 0 ] && [ "$bytes" -le 200 ] || fail body-length
    hex "$body" "$((bytes*2))" || fail body-length
    exit
fi
if [ "${1:-}" = history-check ]; then
    [ "$#" -eq 5 ] || fail history-args
    first=$2 second=$3 actual=$4 jq=$5
    [ "$(get "$actual" ok)" = true ] || fail history-refused
    count=$("$jq" count data.posts < "$actual")
    case "$count" in ''|*[!0-9]*) fail history-count;; esac
    [ "${#count}" -le 2 ] && [ "$count" -le 64 ] || fail history-count
    one=false two=false i=0
    while [ "$i" -lt "$count" ]; do
        id=$(get "$actual" "data.posts[$i].id")
        [ "$id" != "$(get "$first" data.id)" ] || one=true
        [ "$id" != "$(get "$second" data.id)" ] || two=true
        i=$((i+1))
    done
    [ "$one" = true ] && [ "$two" = true ] || fail missing-history-revision
    exit
fi
if [ "${1:-}" = matrix ]; then
    [ "$#" -eq 5 ] || fail matrix-args
    manifest=$2 out=$3 jq=$4 run=$5
    [ "${WIKI_RUNTIME_CHILD:-}" = "$out" ] || fail internal-only
    self=$0
    : > "$out/writes.tsv"
    for revision in 1 2; do
    pids=''
    while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
        case "$role" in writer|both) :;; *) continue;; esac
        # Safe labels only: no shell or JSON interpolation of arbitrary input.
        parent=''
        if [ "$revision" = 2 ]; then parent=",\"supersedes\":\"$(get "$out/$name-v1.original.json" data.id)\""; fi
        input="{\"slug\":\"g4-$run-$name\",\"title\":\"G4 $name\",\"text\":\"G4 $run $name-v$revision\",\"ttl\":1$parent}"
        "$adapter" write "$run" "$input" > "$out/$name-v$revision.write.json" 2> "$out/$name-v$revision.write.err" &
        pids="$pids $!"
    done < "$manifest"
    for pid in $pids; do wait "$pid" || fail uncertain-write-no-retry; done
    while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
        case "$role" in writer|both) :;; *) continue;; esac
        key=$name-v$revision
        [ "$(get "$out/$key.write.json" ok)" = true ] || fail write-refusal
        id=$(get "$out/$key.write.json" data.id); hex "$id" 64 || fail write-id
        "$adapter" read "$run" "{\"id\":\"$id\"}" > "$out/$key.original.json" || fail original-read
        expected=$(printf 'G4 %s %s' "$run" "$key" | od -An -v -tx1 | tr -d ' \n')
        [ "$(get "$out/$key.original.json" data.data_hex)" = "$expected" ] &&
            [ "$(get "$out/$key.original.json" data.id)" = "$id" ] || fail original-body
        "$self" compare "$out/$key.original.json" "$out/$key.original.json" "$jq"
        if [ "$revision" = 2 ]; then
            [ "$id" != "$(get "$out/$name-v1.original.json" data.id)" ] &&
            [ "$(get "$out/$key.original.json" data.supersedes)" = "$(get "$out/$name-v1.original.json" data.id)" ] || fail revision-lineage
            for field in host slug signed_scope signed_room; do
                [ "$(get "$out/$key.original.json" "data.$field")" = "$(get "$out/$name-v1.original.json" "data.$field")" ] || fail revision-binding
            done
        fi
        printf '%s\t%s\n' "$key" "$id" >> "$out/writes.tsv"
    done < "$manifest"
    done
    pids=''
    while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
        case "$role" in reader|both) :;; *) continue;; esac
        while IFS="$(printf '\t')" read -r writer id; do
            (
                while :; do
                    if "$adapter" read "$run" "{\"id\":\"$id\"}" > "$out/$name.$writer.read.json" 2> "$out/$name.$writer.read.err" &&
                        "$self" compare "$out/$writer.original.json" "$out/$name.$writer.read.json" "$jq" 2> "$out/$name.$writer.compare.err"; then break; fi
                    sleep 0.1
                done
            ) &
            pids="$pids $!"
        done < "$out/writes.tsv"
    done < "$manifest"
    for pid in $pids; do wait "$pid" || fail matrix; done
    exit
fi
[ "$#" -eq 6 ] || fail 'REQUIRED_PARTICIPANTS MANIFEST RUN_ID NEW_OUTPUT_DIR JSONQ BOUNDED_RUN'
required=$1 manifest=$2 run=$3 out=$4 jq=$5 bounded=$6
label "$run" || fail run-id
case "$out" in /*) :;; *) fail absolute-output-required;; esac
[ ! -e "$out" ] || fail output-exists
[ -x "$jq" ] && [ -x "$bounded" ] && [ -r "$manifest" ] || fail tools
awk -F '\t' 'NF != 2 || seen[$1]++ {bad=1} END {exit bad || NR < 2 || NR > 8}' "$required" || fail required-participants
awk -F '\t' 'NR==FNR {role[$1]=$2; n++; next} {if(!($1 in role) || role[$1]!=$2) bad=1; seen[$1]=1; m++} END {exit bad || m!=n}' "$required" "$manifest" || fail required-set-mismatch
awk -F '\t' 'NF != 6 || seen[$1]++ {bad=1} END {exit bad || NR < 2 || NR > 8}' "$manifest" || fail manifest
writers=0 readers=0
while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
    label "$name" && label "$platform" && hex "$source" 40 && hex "$binary" 64 || fail metadata
    case "$role" in writer) writers=$((writers+1));; reader) readers=$((readers+1));; both) writers=$((writers+1)); readers=$((readers+1));; *) fail role;; esac
    case "$adapter" in /*) [ -x "$adapter" ] || fail adapter;; *) fail adapter;; esac
done < "$manifest"
[ "$writers" -gt 0 ] && [ "$readers" -gt 0 ] || fail missing-role
mkdir -m 700 "$out"
cp "$manifest" "$out/participants.tsv"
cp "$required" "$out/required.tsv"
: > "$out/owned.tsv"
cleanup() {
    rc=$?; trap - EXIT HUP INT TERM
    while IFS="$(printf '\t')" read -r name adapter; do
        "$bounded" 10000 "$adapter" cleanup "$run" > "$out/$name.cleanup.json" 2> "$out/$name.cleanup.err" || rc=1
    done < "$out/owned.tsv"
    if [ "$rc" -eq 0 ]; then
        if [ "${WIKI_RUNTIME_FIXTURE:-0}" = 1 ]; then echo 'PASS fixture only; no live acceptance';
        elif [ "$writers" -eq "$participants" ] && [ "$readers" -eq "$participants" ]; then echo 'PASS full declared participant coverage';
        else echo 'PASS partial operational coverage; full G4 NOT qualified'; fi
    else echo 'FAIL or incomplete'; fi > "$out/verdict.txt"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
participants=$(wc -l < "$manifest" | tr -d ' ')
check_identity() {
    f=$1
    [ "$(get "$f" name)" = "$name" ] && [ "$(get "$f" platform)" = "$platform" ] &&
    [ "$(get "$f" source)" = "$source" ] && [ "$(get "$f" binary_sha256)" = "$binary" ] &&
    [ "$(get "$f" run_id)" = "$run" ] && [ "$(get "$f" isolation)" = isolated ]
}
while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
    "$bounded" 10000 "$adapter" identity "$run" > "$out/$name.identity.json" || fail identity
    check_identity "$out/$name.identity.json" || fail identity-mismatch
    printf '%s\t%s\n' "$name" "$adapter" >> "$out/owned.tsv"
done < "$manifest"
self=$(CDPATH= cd -- "$(dirname "$0")" && pwd)/$(basename "$0")
export WIKI_RUNTIME_CHILD="$out"
"$bounded" 10000 "$self" matrix "$manifest" "$out" "$jq" "$run" || fail propagation-deadline
while IFS="$(printf '\t')" read -r name role platform source binary adapter; do
    case "$role" in reader|both) :;; *) continue;; esac
    "$bounded" 30000 "$adapter" restart-offline "$run" > "$out/$name.restart.json" || fail offline-restart
    check_identity "$out/$name.restart.json" && [ "$(get "$out/$name.restart.json" offline)" = true ] || fail restart-identity
    while IFS="$(printf '\t')" read -r writer id; do
        "$bounded" 10000 "$adapter" read "$run" "{\"id\":\"$id\"}" > "$out/$name.$writer.retained.json" || fail retained-read
        "$self" compare "$out/$writer.original.json" "$out/$name.$writer.retained.json" "$jq" || fail retention
        expiry=$(get "$out/$writer.original.json" data.expires_at)
        case "$expiry" in ''|*[!0-9]*) fail expiry;; esac
        [ "${#expiry}" -le 10 ] || fail expiry
        observed=false
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            "$bounded" 2000 "$adapter" clock "$run" > "$out/$name.clock.json" || fail clock
            now=$(get "$out/$name.clock.json" unix)
            case "$now" in ''|*[!0-9]*) fail clock;; esac
            [ "${#now}" -le 10 ] || fail clock
            if [ "$now" -gt "$expiry" ]; then observed=true; break; fi
            sleep 1
        done
        [ "$observed" = true ] || fail expiry-not-observed
        "$bounded" 10000 "$adapter" read "$run" "{\"id\":\"$id\"}" > "$out/$name.$writer.expired.json" || fail expiry-read
        "$self" compare "$out/$writer.original.json" "$out/$name.$writer.expired.json" "$jq" || fail expiry-retention
        case "$writer" in *-v2)
            author=${writer%-v2}
            "$bounded" 10000 "$adapter" history "$run" "{\"slug\":\"g4-$run-$author\"}" > "$out/$name.$author.history.json" || fail history
            "$self" history-check "$out/$author-v1.original.json" "$out/$author-v2.original.json" "$out/$name.$author.history.json" "$jq" || fail retained-history;;
        esac
    done < "$out/writes.tsv"
done < "$manifest"
printf 'writers=%s readers=%s participant-pairs=%s revision-reads=%s deadline=10000ms-before-dispatch verification=stored-signed-field-and-byte-equality independent-crypto=not-performed history=two-exact-revisions-plus-list-membership-offline-expired lifecycle=owner-wrapper-required forks=not-exercised\n' "$writers" "$readers" "$((writers*readers))" "$((writers*readers*2))" > "$out/scope.txt"
