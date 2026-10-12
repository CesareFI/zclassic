#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Compare available linkers on one exact dev candidate and KAT probe.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN="${ZCL_DEV_LINKER_PLAN:-$ROOT/build/dev-loop/restart.env}"
OUTPUT="${ZCL_DEV_LINKER_RECEIPT:-$ROOT/.cache/zcl-dev-loop/linker-shootout.json}"
RUNS="${ZCL_DEV_LINKER_RUNS:-3}"
MODE="${1:-run}"

fail()
{
    printf 'dev-linker-shootout: %s\n' "$*" >&2
    exit 2
}

# The default linker is the one that keeps the tail short: a linker that wins
# the median but blows the p95 is the one that occasionally eats a whole
# minute on a big link, which is exactly the wait a dev loop cannot absorb.
# Selection is therefore p95 first, with p50 then name as tie-breaks. Rows
# with p95=null cannot win here — a candidate that never linked has no
# identical probe and is filtered by the select above.
select_fastest()
{
    jq -s '[.[]|select(.status=="passed" and .probe_identical==true)] |
      if length==0 then error("no verified linker")
      else sort_by([.p95_us,.p50_us,.name]) | .[0] end' "$@"
}

self_test()
{
    local scratch a b bad selected w
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-linker-selftest.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    a="$scratch/a.json"; b="$scratch/b.json"; c="$scratch/c.json"
    t1="$scratch/t1.json"; t2="$scratch/t2.json"; bad="$scratch/bad.json"
    # The decision metric is the tail: gold owns the best median but blows the
    # p95, and bfd — the slower median — owns the tail. The old p50 key picked
    # gold here; the p95 key must pick bfd.
    printf '%s\n' '{"name":"bfd","status":"passed","probe_identical":true,"p50_us":900,"p95_us":950}' >"$a"
    printf '%s\n' '{"name":"gold","status":"passed","probe_identical":true,"p50_us":500,"p95_us":2000}' >"$b"
    printf '%s\n' '{"name":"lld","status":"passed","probe_identical":true,"p50_us":700,"p95_us":1500}' >"$c"
    printf '%s\n' '{"name":"mold","status":"passed","probe_identical":false,"p50_us":100,"p95_us":110}' >"$bad"
    selected="$(select_fastest "$a" "$b" "$c" "$bad")"
    [ "$(jq -r '.name' <<<"$selected")" = bfd ] ||
        fail 'p95-driven linker selection regressed'
    # Equal tails fall back to the median; equal medians fall back to the
    # name — the composite key, pinned in that order.
    printf '%s\n' '{"name":"slow_tie","status":"passed","probe_identical":true,"p50_us":60,"p95_us":100}' >"$t1"
    printf '%s\n' '{"name":"fast_tie","status":"passed","probe_identical":true,"p50_us":40,"p95_us":100}' >"$t2"
    selected="$(select_fastest "$t1" "$t2")"
    [ "$(jq -r '.name' <<<"$selected")" = fast_tie ] ||
        fail 'p50 tie-break inside equal p95 regressed'
    if select_fastest "$bad" >/dev/null 2>&1; then
        fail 'non-identical candidate was selectable'
    fi
    # A gold-tuned DEV_LDFLAGS (dev-linker-select.sh's fallback: mold and
    # lld absent) must not hand its gold-only --threads/--thread-count to a
    # candidate that does not understand them — lld rejects --thread-count
    # outright, which would fail that candidate's link and corrupt the
    # receipt.
    local -a stripped candidate_words
    stripped=()
    while IFS= read -r w; do stripped+=("$w"); done < <(
        strip_linker_specific_ld_words -pthread -rdynamic -pie \
            -fuse-ld=gold -Wl,--threads -Wl,--thread-count=9)
    [ "${#stripped[@]}" -eq 3 ] &&
        [ "${stripped[0]}" = -pthread ] &&
        [ "${stripped[1]}" = -rdynamic ] &&
        [ "${stripped[2]}" = -pie ] ||
        fail 'strip_linker_specific_ld_words left a gold-only or -fuse-ld token behind'
    candidate_words=()
    while IFS= read -r w; do candidate_words+=("$w"); done < <(
        candidate_ld_words lld "${stripped[@]}")
    for w in "${candidate_words[@]}"; do
        case "$w" in
            -Wl,--thread-count=*|-Wl,--threads)
                fail 'lld candidate received a gold-only thread flag';;
        esac
    done
    candidate_words=()
    while IFS= read -r w; do candidate_words+=("$w"); done < <(
        candidate_ld_words gold "${stripped[@]}")
    case " ${candidate_words[*]} " in
        *' -Wl,--threads '*) ;;
        *) fail 'gold candidate is missing --threads';;
    esac
    case " ${candidate_words[*]} " in
        *' -Wl,--thread-count=9 '*) ;;
        *) fail 'gold candidate is missing --thread-count';;
    esac
    printf 'dev-linker-shootout: self-test PASS\n'
}

plan_value()
{
    local key="$1"
    sed -n "s/^${key}=//p" "$PLAN" | sed -n '1p'
}

# The plan's DEV_LDFLAGS carries whatever tools/dev/dev-linker-select.sh
# picked for THIS host's default linker, including linker-specific tuning
# that only that one linker understands (gold's --threads/--thread-count:
# dev-linker-select.sh's fallback branch, since gold defaults to
# --no-threads and every dev/test link paid for idle cores otherwise; see
# check-dev-linker-threads). The shootout tries every OTHER installed
# linker too, so any such tuning must come out of the shared base flags
# before -fuse-ld=<candidate> is appended, or a linker that does not
# understand it (lld has no --thread-count) fails its link and the
# shootout receipt is wrong. Strip here; a linker-specific candidate adds
# its own tuning back in candidate_ld_words below. Keep this list and
# dev-linker-select.sh's gold branch in sync.
strip_linker_specific_ld_words()
{
    local word
    for word in "$@"; do
        case "$word" in
            -fuse-ld=*|-Wl,--threads|-Wl,--no-threads|-Wl,--thread-count=*)
                continue;;
        esac
        printf '%s\n' "$word"
    done
}

# base_ld (already stripped) plus the candidate's own linker-specific
# tuning. Only gold gets --threads/--thread-count today; bfd, lld and mold
# get none (lld/mold already parallelize internally with no flag needed;
# bfd has no equivalent knob this shootout uses).
candidate_ld_words()
{
    local candidate_name="$1"
    shift
    printf '%s\n' "$@"
    case "$candidate_name" in
        gold) printf '%s\n' '-Wl,--threads' '-Wl,--thread-count=9';;
    esac
}

linker_available()
{
    case "$1" in
        bfd) command -v ld.bfd >/dev/null 2>&1 || command -v ld >/dev/null 2>&1;;
        gold) command -v ld.gold >/dev/null 2>&1;;
        lld) command -v ld.lld >/dev/null 2>&1;;
        mold) command -v mold >/dev/null 2>&1;;
        *) return 1;;
    esac
}

run_shootout()
{
    [[ "$RUNS" =~ ^[1-9][0-9]*$ && "$RUNS" -le 9 ]] ||
        fail 'ZCL_DEV_LINKER_RUNS must be 1..9'
    command -v jq >/dev/null || fail 'jq is required'
    command -v timeout >/dev/null || fail 'timeout is required'
    [ -r "$PLAN" ] || fail 'missing restart plan; run make dev-bin'

    local cc_text ldflags_text libs_text link_rsp compiler_id scratch rows
    cc_text="$(plan_value CC)"
    ldflags_text="$(plan_value DEV_LDFLAGS)"
    libs_text="$(plan_value DEV_LIBS)"
    link_rsp="$(plan_value DEV_LINK_RSP)"
    compiler_id="$(plan_value COMPILER_ID)"
    [ -n "$cc_text" ] && [ -n "$ldflags_text" ] && [ -n "$libs_text" ] &&
        [ -r "$ROOT/$link_rsp" ] || fail 'restart plan is incomplete'

    local -a cc_words ld_words libs_words base_ld linkers
    read -r -a cc_words <<<"$cc_text"
    read -r -a ld_words <<<"$ldflags_text"
    read -r -a libs_words <<<"$libs_text"
    base_ld=()
    while IFS= read -r word; do
        base_ld+=("$word")
    done < <(strip_linker_specific_ld_words "${ld_words[@]}")
    linkers=()
    for name in bfd gold lld mold; do
        linker_available "$name" && linkers+=("$name")
    done
    [ "${#linkers[@]}" -gt 0 ] || fail 'no host linker is available'

    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-linker-shootout.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    rows="$scratch/rows"
    : >"$rows"
    local reference_probe='' name run candidate probe start end elapsed rc
    local -a this_ld
    for name in "${linkers[@]}"; do
        this_ld=()
        while IFS= read -r word; do
            this_ld+=("$word")
        done < <(candidate_ld_words "$name" "${base_ld[@]}")
        : >"$scratch/$name.samples"
        rc=0
        for ((run=1; run<=RUNS; run++)); do
            candidate="$scratch/zclassic23-dev-$name"
            start="$(date +%s%N)"
            if ! (cd "$ROOT" && "${cc_words[@]}" "${this_ld[@]}" \
                    "-fuse-ld=$name" -o "$candidate" "@$link_rsp" \
                    "${libs_words[@]}") >"$scratch/$name.link.log" 2>&1; then
                rc=1
                break
            fi
            end="$(date +%s%N)"
            elapsed=$(((end-start)/1000))
            printf '%s\n' "$elapsed" >>"$scratch/$name.samples"
        done
        if [ "$rc" -eq 0 ]; then
            if ! timeout 10s "$candidate" discover help \
                    >"$scratch/$name.probe" 2>"$scratch/$name.probe.err"; then
                rc=1
            fi
        fi
        probe=''
        [ "$rc" -ne 0 ] || probe="$(sha256sum "$scratch/$name.probe" | awk '{print $1}')"
        if [ -z "$reference_probe" ] && [ -n "$probe" ]; then
            reference_probe="$probe"
        fi
        p50=null
        p95=null
        if [ -s "$scratch/$name.samples" ]; then
            count="$(wc -l <"$scratch/$name.samples")"
            rank50=$(((count*50+99)/100))
            rank95=$(((count*95+99)/100))
            p50="$(sort -n "$scratch/$name.samples" | sed -n "${rank50}p")"
            p95="$(sort -n "$scratch/$name.samples" | sed -n "${rank95}p")"
        fi
        jq -cn --arg name "$name" --arg probe "$probe" \
          --arg reference "$reference_probe" --argjson p50 "$p50" \
          --argjson p95 "$p95" --argjson runs "$RUNS" --argjson rc "$rc" \
          '{name:$name,status:(if $rc==0 then "passed" else "rejected" end),
            probe_sha256:$probe,probe_identical:($rc==0 and $probe==$reference),
            runs:$runs,p50_us:$p50,p95_us:$p95}' >"$scratch/$name.json"
        printf '%s\n' "$scratch/$name.json" >>"$rows"
    done
    [ -n "$reference_probe" ] || fail 'every linker candidate failed its probe'
    selected="$(select_fastest $(tr '\n' ' ' <"$rows"))"
    mkdir -p "$(dirname "$OUTPUT")"
    jq -n --arg compiler "$compiler_id" --arg rsp "$link_rsp" \
      --arg rsp_sha "$(sha256sum "$ROOT/$link_rsp" | awk '{print $1}')" \
      --arg probe "$reference_probe" --argjson selected "$selected" \
      --slurpfile results <(xargs jq -c . <"$rows") \
      '{schema:"zcl.dev_linker_shootout.v1",status:"complete",
        compiler_id:$compiler,link_response:$rsp,link_response_sha256:$rsp_sha,
        probe_sha256:$probe,selected:($selected+{verified:true}),
        results:$results}' >"$OUTPUT"
    jq -r --arg output "$OUTPUT" '
      "dev-linker-shootout: selected=\(.selected.name) p95_us=\(.selected.p95_us) p50_us=\(.selected.p50_us) receipt=\($output)"' \
      "$OUTPUT"
}

case "$MODE" in
    --self-test) self_test;;
    run) run_shootout;;
    *) fail 'usage: dev-linker-shootout.sh [run|--self-test]';;
esac
