#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# mvp_c8_judge_cases.sh — executed refusal-path tests for the C8
# genesis-canary judge in tools/mvp_gate.sh.
#
# The judge is inline in a live-node probe, so this harness lifts the real
# judge text out of tools/mvp_gate.sh (verdict reader, identity bind, coarse
# probe and the verdict precedence chain) and runs it against fixture
# verdict files, a faked running-binary identity and a stubbed zclassicd
# height oracle. Nothing here edits or re-implements a judge branch: a
# changed branch in mvp_gate.sh changes what these cases observe.
#
# usage: mvp_c8_judge_cases.sh <repo-root>
# Prints one `CASE <name> VERDICT=<token> FULL=<0|1>` line per case and
# exits 0 only when every token and detail marker matches exactly.
set -uo pipefail

ROOT="${1:?usage: mvp_c8_judge_cases.sh <repo-root>}"
GATE="$ROOT/tools/mvp_gate.sh"
JSONQ="$ROOT/build/bin/jsonq"
[[ -f "$GATE" ]] || { echo "mvp_c8_judge: missing $GATE" >&2; exit 2; }
[[ -x "$JSONQ" ]] || { echo "mvp_c8_judge: missing $JSONQ (make jsonq)" >&2; exit 2; }

mkdir -p "$ROOT/build/scratch"
WORK="$(mktemp -d "$ROOT/build/scratch/mvp-c8-judge.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

# ── lift the real judge segments ──────────────────────────────────
awk '/^CANARY_DIR=/{p=1} /^# Bind release evidence/{p=0} p' "$GATE" > "$WORK/seg_read.sh"
awk '/^json_num\(\) \{/{p=1} p{print} p&&/^\}$/{exit}' "$GATE" > "$WORK/seg_json.sh"
awk '/^G_ID_MATCH=0$/{p=1} p{print} p&&/^fi$/{exit}' "$GATE" > "$WORK/seg_bind.sh"
awk '/^CANARY_LEDGER=/{p=1} /SOAK ACCRUAL CHECK/{exit} p' "$GATE" > "$WORK/seg_verdict.sh"
grep -q "^json_num()" "$WORK/seg_json.sh" &&
grep -q '^canary_read genesis$' "$WORK/seg_read.sh" &&
grep -q 'G_ARTIFACT" == "\$LIVE_ARTIFACT"' "$WORK/seg_bind.sh" &&
grep -q '^set_v 8 "BLOCKED"\|^    set_v 8 "BLOCKED"' "$WORK/seg_verdict.sh" &&
grep -q 'set_v 8 "PASS"' "$WORK/seg_verdict.sh" || {
    echo "mvp_c8_judge: could not lift the C8 judge segments from mvp_gate.sh" >&2
    exit 2
}

SRC_OK="$(printf '1%.0s' {1..64})"
ART_OK="$(printf '2%.0s' {1..64})"
SRC_BAD="$(printf '3%.0s' {1..64})"
ART_BAD="$(printf '4%.0s' {1..64})"
MAX_AGE=604800
FAILURES=0

# run_case <name> <genesis-json|ABSENT> <c23-height> <zd-height> <verdict> <full> <detail-glob>
run_case() {
    local name="$1" json="$2" height="$3" zdh="$4" want_v="$5" want_f="$6" want_d="$7"
    local dir="$WORK/$name"
    mkdir -p "$dir"
    [[ "$json" == ABSENT ]] || printf '%s' "$json" > "$dir/replay_canary_genesis.json"
    local out
    out="$(
        export ZCL_CANARY_VERDICT_DIR="$dir" CANARY_MAX_AGE_S="$MAX_AGE"
        export ZCL_JSONQ="$JSONQ" MVP_REPO_ROOT="$ROOT"
        TIP_GAP_OK=10
        declare -A VERDICT DETAIL FULL
        set_v() { VERDICT[$1]="$2"; DETAIL[$1]="$3"; FULL[$1]="${4:-0}"; }
        zd_rpc() { printf '{"result":%s,"error":null}' "$ZD_H_STUB"; }
        ZD_H_STUB="$zdh"; ZD_RPCPORT=0
        NODE_UP=1; HEIGHT="$height"
        LIVE_SOURCE_ID="$SRC_OK"; LIVE_ARTIFACT="$ART_OK"
        LIVE_ID_DETAIL="running source=$SRC_OK artifact=$ART_OK"
        # shellcheck disable=SC1090
        . "$WORK/seg_json.sh"
        . "$WORK/seg_read.sh"
        . "$WORK/seg_bind.sh"
        . "$WORK/seg_verdict.sh"
        printf 'CASE %s VERDICT=%s FULL=%s\n' "$name" "${VERDICT[8]:-unset}" "${FULL[8]:-unset}"
        printf 'DETAIL %s\n' "${DETAIL[8]:-}"
    )"
    local line detail
    line="$(printf '%s\n' "$out" | grep '^CASE ')"
    detail="$(printf '%s\n' "$out" | sed -n 's/^DETAIL //p')"
    # Keep the canonical C driver's eight markers within its 2048-byte capture.
    # Every additional case still runs and reports full mismatch diagnostics.
    case "$name" in
        absent|stale|wrong_source|wrong_artifact|verdict_fail|height_skew|height_edge|valid)
            printf '%s\n' "$line" ;;
    esac
    if [[ "$line" != "CASE $name VERDICT=$want_v FULL=$want_f" || "$detail" != $want_d ]]; then
        printf 'MISMATCH %s: want VERDICT=%s FULL=%s detail~%s, got detail=%s\n' \
            "$name" "$want_v" "$want_f" "$want_d" "$detail" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

verdict_json() {  # <verdict> <ts> <src> <artifact>
    printf '{"verdict":"%s","ts":%s,"source_id_sha256":"%s","artifact_sha256":"%s","from":"genesis","exact_tier":"match","params_dir_empty":true}' "$1" "$2" "$3" "$4"
}

NOW="$(date +%s)"
FRESH=$((NOW - 60))
STALE=$((NOW - MAX_AGE - 3600))

run_case absent ABSENT 1000 1000 BLOCKED 0 \
    '*no fresh canary PASS*genesis=absent age=-1s*'
run_case stale "$(verdict_json PASS "$STALE" "$SRC_OK" "$ART_OK")" 1000 1000 BLOCKED 0 \
    '*no fresh canary PASS*genesis=PASS age=6*'
run_case wrong_source "$(verdict_json PASS "$FRESH" "$SRC_BAD" "$ART_OK")" 1000 1000 BLOCKED 0 \
    '*PASS belongs to different or unreadable bytes*'
run_case wrong_artifact "$(verdict_json PASS "$FRESH" "$SRC_OK" "$ART_BAD")" 1000 1000 BLOCKED 0 \
    '*PASS belongs to different or unreadable bytes*'
run_case verdict_fail "$(verdict_json FAIL "$FRESH" "$SRC_OK" "$ART_OK")" 1000 1000 FAIL 0 \
    'replay canary (genesis) FAIL*'
run_case height_skew "$(verdict_json PASS "$FRESH" "$SRC_OK" "$ART_OK")" 1000 1011 FAIL 0 \
    'height divergence vs zclassicd*'
run_case height_edge "$(verdict_json PASS "$FRESH" "$SRC_OK" "$ART_OK")" 1000 1010 PASS 1 \
    'EXACT parity: replay-canary (genesis) PASS*'
run_case valid "$(verdict_json PASS "$FRESH" "$SRC_OK" "$ART_OK")" 1000 1000 PASS 1 \
    'EXACT parity: replay-canary (genesis) PASS*coarse height MATCH*'

COMPLETE="$(verdict_json PASS "$FRESH" "$SRC_OK" "$ART_OK")"
run_case exact_skipped "${COMPLETE/\"exact_tier\":\"match\"/\"exact_tier\":\"skew\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case exact_not_run "${COMPLETE/\"exact_tier\":\"match\"/\"exact_tier\":\"not_run\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case missing_exact "${COMPLETE/,\"exact_tier\":\"match\"/}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case wrong_track "${COMPLETE/\"from\":\"genesis\"/\"from\":\"anchor\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case duplicate_exact "${COMPLETE/\"exact_tier\":\"match\"/\"exact_tier\":\"match\",\"exact_tier\":\"match\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case duplicate_track "${COMPLETE/\"from\":\"genesis\"/\"from\":\"genesis\",\"from\":\"genesis\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case params_present "${COMPLETE/\"params_dir_empty\":true/\"params_dir_empty\":false}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case params_wrong_type "${COMPLETE/\"params_dir_empty\":true/\"params_dir_empty\":\"true\"}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case params_missing "${COMPLETE/,\"params_dir_empty\":true/}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case missing_track "${COMPLETE/,\"from\":\"genesis\"/}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case exact_wrong_type "${COMPLETE/\"exact_tier\":\"match\"/\"exact_tier\":true}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case duplicate_params "${COMPLETE/\"params_dir_empty\":true/\"params_dir_empty\":true,\"params_dir_empty\":true}" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'
run_case trailing_garbage "$COMPLETE garbage" 1000 1000 BLOCKED 0 '*no fresh canary PASS*'
MINIMAL_FAIL="$(printf '{"verdict":"FAIL","ts":%s,"source_id_sha256":"%s","artifact_sha256":"%s"}' "$FRESH" "$SRC_OK" "$ART_OK")"
run_case incomplete_fail "$MINIMAL_FAIL" 1000 1000 FAIL 0 'replay canary (genesis) FAIL*'
ESCAPED_DUP="$(printf '{"verdict":"PASS","ts":%s,"source_id_sha256":"%s","artifact_sha256":"%s","from":"genesis","\\u0066rom":"genesis","exact_tier":"match","params_dir_empty":true}' "$FRESH" "$SRC_OK" "$ART_OK")"
run_case duplicate_escaped_track "$ESCAPED_DUP" 1000 1000 BLOCKED 0 '*incomplete full genesis evidence*'

# Healthy live surfaces cannot replace current full-acceptance receipts.
# Execute the production C1/C2/C4 branches with inert observation fixtures.
awk '/^# C1 /{p=1} /^# C3 /{exit} p' "$GATE" > "$WORK/seg_c12.sh"
awk '/^# C4 /{p=1} /^# C5 /{exit} p' "$GATE" > "$WORK/seg_c4.sh"
for helper in json_str json_bool; do
    awk -v helper="$helper" '$0 ~ "^" helper "\\(\\)" {p=1} p{print} p&&/^\}$/{exit}' \
        "$GATE" >> "$WORK/seg_surface_json.sh"
done
run_surface_case() {
    local name="$1" up="$2" onion="$3" addresses="$4" balance="$5" want="$6" out
    out="$(
        NODE_UP="$up"; HEIGHT=1000; ZCL_NODE_BIN="$JSONQ"
        declare -A VERDICT DETAIL FULL
        set_v() { VERDICT[$1]="$2"; DETAIL[$1]="$3"; FULL[$1]="$4"; }
        native() { printf '%s' "$onion"; }
        rpc() {
            case "$1" in
                z_listaddresses) printf '%s' "$addresses" ;;
                z_gettotalbalance) printf '%s' "$balance" ;;
                *) return 1 ;;
            esac
        }
        . "$WORK/seg_surface_json.sh"
        . "$WORK/seg_c12.sh"
        . "$WORK/seg_c4.sh"
        printf '1=%s:%s 2=%s:%s 4=%s:%s' "${VERDICT[1]}" "${FULL[1]}" \
            "${VERDICT[2]}" "${FULL[2]}" "${VERDICT[4]}" "${FULL[4]}"
    )"
    if [[ "$out" != "$want" ]]; then
        printf 'MISMATCH surface_%s: want %s, got %s\n' "$name" "$want" "$out" >&2
        FAILURES=$((FAILURES + 1))
    fi
}
SURFACE_ONION='{"tor_ready":true,"onion_service_ready":true,"onion_address":"fixture.onion"}'
SURFACE_ADDRESSES='{"result":["zs1fixture"],"error":null}'
SURFACE_BALANCE='{"result":{"private":"1.0"},"error":null}'
run_surface_case healthy 1 "$SURFACE_ONION" "$SURFACE_ADDRESSES" "$SURFACE_BALANCE" \
    '1=BLOCKED:0 2=BLOCKED:0 4=BLOCKED:0'
run_surface_case down 0 '' '' '' '1=FAIL:0 2=FAIL:0 4=FAIL:0'
run_surface_case onion_unready 1 '{}' "$SURFACE_ADDRESSES" "$SURFACE_BALANCE" \
    '1=BLOCKED:0 2=FAIL:0 4=BLOCKED:0'
run_surface_case no_address 1 "$SURFACE_ONION" '{"result":[]}' "$SURFACE_BALANCE" \
    '1=BLOCKED:0 2=BLOCKED:0 4=BLOCKED:0'
run_surface_case balance_unavailable 1 "$SURFACE_ONION" "$SURFACE_ADDRESSES" '' \
    '1=BLOCKED:0 2=BLOCKED:0 4=FAIL:0'

# Lift the C5 surface reporter too: no live RPC, wallet or node is accessed.
awk '/^# C5 /{p=1} /^# C6 /{exit} p' "$GATE" > "$WORK/seg_c5.sh"
grep -q 'set_v 5 "BLOCKED"' "$WORK/seg_c5.sh" || exit 2
run_c5_case() {
    local name="$1" document="$2" leaf="$3" want="$4" want_detail="$5"
    local node_up="${6:-1}" parser="${7:-$JSONQ}"
    local out line detail
    out="$(
        NODE_UP="$node_up"; ML_STUB="$document"; RB_STUB="$leaf"
        ZCL_NODE_BIN=c5_node_stub; ZCL_JSONQ="$parser"; MVP_REPO_ROOT="$ROOT"
        rpc() { printf '%s' "$ML_STUB"; }
        c5_node_stub() { printf '%s' "$RB_STUB"; }
        set_v() { printf 'VERDICT=%s FULL=%s\nDETAIL %s\n' "$2" "$4" "$3"; }
        . "$WORK/seg_c5.sh"
    )"
    line="$(printf '%s\n' "$out" | head -1)"
    detail="$(printf '%s\n' "$out" | sed -n 's/^DETAIL //p')"
    if [[ "$line" != "VERDICT=$want FULL=0" || "$detail" != $want_detail ]]; then
        printf 'MISMATCH c5_%s: want %s FULL=0 detail~%s, got %s detail=%s\n' \
            "$name" "$want" "$want_detail" "$line" "$detail" >&2
        FAILURES=$((FAILURES + 1))
    fi
}
C5_HEALTHY='catalog probe passed; remotebuy search matched; exact full remote-buyer qualification required*'
C5_UNAVAILABLE='zmarket_list or the remotebuy leaf is not live*'
run_c5_case object '{"result":{"offers":[]},"error":null}' app.store.remotebuy BLOCKED "$C5_HEALTHY"
run_c5_case populated '{"result":{"offers":[{"name":"fixture"}]},"error":null}' app.store.remotebuy BLOCKED "$C5_HEALTHY"
run_c5_case array '{"result":[],"error":null}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case missing_offers '{"result":{},"error":null}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case wrong_offers '{"result":{"offers":{}},"error":null}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case rpc_error '{"result":{"offers":[]},"error":{"code":-1}}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case missing_error '{"result":{"offers":[]}}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case string_error '{"result":{"offers":[]},"error":"null"}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case malformed '{"result":{"offers":[]},"error":null} trailing' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE"
run_c5_case absent_leaf '{"result":{"offers":[]},"error":null}' '' BLOCKED "$C5_UNAVAILABLE"
run_c5_case parser_absent '{"result":{"offers":[]},"error":null}' app.store.remotebuy BLOCKED "$C5_UNAVAILABLE" 1 "$WORK/no-jsonq"
run_c5_case unreachable '' '' FAIL 'node unreachable' 0

# Exercise the actual local diagnostic and JSON presentation, never a copied
# verdict policy. A missing production block leaves the baseline output intact.
awk '/^# LOCAL VALIDATED SYNC PRESENTATION/{p=1} /^# END LOCAL VALIDATED SYNC PRESENTATION/{print;exit} p' "$GATE" > "$WORK/seg_local_sync.sh"
awk '/^# ── output /{p=1} /^# ── exit /{exit} p' "$GATE" > "$WORK/seg_output.sh"
grep -q '"at_tip"' "$WORK/seg_output.sh" || exit 2

local_snapshot() {
    local gap="${1:-0}" target="${2:-1000}" captured="${3:-100}"
    printf '{"result":{"schema":"zcl.operator_snapshot.v3","execution_locus":"target_node","process_id":123,"source_id_sha256":"%s","summary":{"schema":"zcl.operator_summary.v3","execution_locus":"target_node","source_rpc":"operatorsnapshot","process_id":123,"source_id_sha256":"%s","height":1000,"target_height":%s,"gap":%s,"captured_at":%s,"target_height_source":"target_node.validated_header_tip","critical_frontier_stable":true,"chain_evidence_consistent":true,"verdict_complete":false,"security_review_required":true}},"error":null}' "$SRC_OK" "$SRC_OK" "$target" "$gap" "$captured"
}

run_local_case() {
    local name="$1" document="$2" want_known="$3" want_gap="$4"
    local parser="${5:-$JSONQ}" out known gap tip score posture fresh parity
    out="$(
        SECURITY_SNAPSHOT="$document"; LIVE_PID=123; LIVE_SOURCE_ID="$SRC_OK"
        ZCL_JSONQ="$parser"; MVP_REPO_ROOT="$ROOT"
        JSON_OUT=1; NODE_UP=1; LIVE_DATADIR=/fixture; LIVE_RPCPORT=0
        SECURITY_REVIEW_REQUIRED=true; SECURITY_POSTURE_OK=0
        HEIGHT=1000; REFTIP=3513335; GAP=3512335; AT_TIP=0; MRS=0
        SOAK_VERDICT=NOT_MET; UPTIME_S=1; SOAK_PCT=0; NRESTARTS=0
        declare -A VERDICT DETAIL FULL
        for i in 1 2 3 4 5 6 7 8; do
            VERDICT[$i]=BLOCKED; DETAIL[$i]=fixture; FULL[$i]=0
        done
        . "$WORK/seg_local_sync.sh"
        . "$WORK/seg_output.sh"
    )"
    known="$(printf '%s' "$out" | "$JSONQ" raw local_sync.known 2>/dev/null)"
    gap="$(printf '%s' "$out" | "$JSONQ" raw local_sync.gap 2>/dev/null)"
    tip="$(printf '%s' "$out" | "$JSONQ" raw at_tip 2>/dev/null)"
    score="$(printf '%s' "$out" | "$JSONQ" raw mrs 2>/dev/null)"
    posture="$(printf '%s' "$out" | "$JSONQ" raw security_posture_ok 2>/dev/null)"
    fresh="$(printf '%s' "$out" | "$JSONQ" raw local_sync.freshness_qualified 2>/dev/null)"
    parity="$(printf '%s' "$out" | "$JSONQ" raw local_sync.external_parity_qualified 2>/dev/null)"
    if [[ "$known" != "$want_known" || "$gap" != "$want_gap" ||
          "$tip" != 0 || "$score" != '"0/8"' || "$posture" != false ||
          "$fresh" != false || "$parity" != false ||
          "$(printf '%s' "$out" | "$JSONQ" raw criteria.C6.full_pass 2>/dev/null)" != 0 ||
          "$(printf '%s' "$out" | "$JSONQ" raw soak.verdict 2>/dev/null)" != '"NOT_MET"' ]]; then
        printf 'MISMATCH local_%s: diagnostic or unchanged security/score contract failed\n' "$name" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

LOCAL_VALID="$(local_snapshot)"
[[ "$(printf '%s' "$LOCAL_VALID" | "$JSONQ" type result.summary 2>/dev/null)" == object ]] || exit 2
run_local_case outlier "$LOCAL_VALID" true 0
run_local_case validated_lag "$(local_snapshot 11 1011)" true 11
# An old timestamp is displayed as observation, never promoted to freshness.
run_local_case old_timestamp "$(local_snapshot 0 1000 1)" true 0
run_local_case absent '' false null
run_local_case malformed '{' false null
run_local_case parser_absent "$LOCAL_VALID" false null "$WORK/no-jsonq"
run_local_case unstable "${LOCAL_VALID/\"critical_frontier_stable\":true/\"critical_frontier_stable\":false}" false null
run_local_case null_gap "${LOCAL_VALID/\"gap\":0/\"gap\":null}" false null
run_local_case wrong_pid "${LOCAL_VALID/\"process_id\":123/\"process_id\":124}" false null
run_local_case wrong_source "${LOCAL_VALID/$SRC_OK/$SRC_BAD}" false null
run_local_case wrong_target "${LOCAL_VALID/target_node.validated_header_tip/untrusted_peer_advertisement}" false null
run_local_case inconsistent "${LOCAL_VALID/\"chain_evidence_consistent\":true/\"chain_evidence_consistent\":false}" false null
run_local_case duplicate_gap "${LOCAL_VALID/\"gap\":0/\"gap\":0,\"gap\":0}" false null
run_local_case duplicate_result "${LOCAL_VALID/\"result\":/\"result\":null,\"result\":}" false null
run_local_case rpc_error "${LOCAL_VALID/\"error\":null/\"error\":{\"code\":-1}}" false null

if [[ "$FAILURES" -ne 0 ]]; then
    echo "mvp_c8_judge: $FAILURES case(s) failed" >&2
    exit 1
fi
echo "mvp_c8_judge: ALL CASES OK"
