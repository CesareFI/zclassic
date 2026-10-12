#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Measure useful reflex coverage over a recent production-C window.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/zclassic23-dev}"
HISTORY="${ZCL_REFLEX_HISTORY:-$ROOT/build/dev-loop/substrate-history-benchmark.json}"
OUTPUT="${ZCL_REFLEX_COVERAGE_OUTPUT:-$ROOT/build/dev-loop/reflex-coverage-audit.json}"
ONLY_PATH="${ZCL_REFLEX_COVERAGE_ONLY:-}"
MODE="${1:-run}"

fail() { printf 'reflex-coverage-audit: %s\n' "$*" >&2; exit 2; }

# Independently derive the CodeIndex leaf hash for the actual timed file.
# The wire preimage is tag 0x10, NUL-terminated domain and path, little-endian
# u64 size, then the file bytes (codeindex_merkle.c:merkle_leaf_digest).
source_leaf_sha3()
{
    local path="$1" file="$2" size i octet
    size="$(wc -c <"$file")" || return 1
    {
        printf '\020%s\0%s\0' 'zcl.codeindex.merkle.leaf.v1' "$path"
        for ((i=0; i<8; i++)); do
            octet="$(printf '%03o' "$(( (size >> (8*i)) & 255 ))")"
            printf '%b' "\\$octet"
        done
        cat -- "$file"
    } | openssl dgst -sha3-256 | awk '{print $NF}'
}

candidate_epoch_for_module()
{
    printf 'zcl.dev.candidate.v1\n%s\n' "$1" |
        openssl dgst -sha3-256 | awk '{print $NF}'
}

proof_inputs_for_story()
{
    printf 'zcl.dev.proof-inputs.v1\n%s\n%s\n%s\naffected_proof\n1\n' \
        "$1" "$2" "$3" | openssl dgst -sha3-256 | awk '{print $NF}'
}

# Resolve the producer owner from the same frozen manifests it compiles. The
# changed helper path and the compiled service owner are distinct identities.
story_owner_for_path()
{
    local path="$1" feedback="$2" owner
    case "$feedback" in
      HOT_FORK)
        awk -v wanted="$path" '
          /^HOTFORK_CAPSULE\(/ { active=1; count=0; source=""; members="" }
          active {
            rest=$0
            while (match(rest,/"[^"]*"/)) {
              value=substr(rest,RSTART+1,RLENGTH-2)
              count++; if (count==3) source=value
              if (count==4) {
                members=value; n=split(members,paths,"|")
                if (source==wanted) print source
                for (i=1;i<=n;i++) if (paths[i]==wanted) print source
                active=0; break
              }
              rest=substr(rest,RSTART+RLENGTH)
            }
          }' "$ROOT/engine/composition/hotfork_capsules.def" ;;
      HOT_SHADOW_CORE|HOT_EXECUTE)
        owner="$(awk -v wanted="$path" '
          /^HOTSHADOW_SERVICE_MEMBERS\(/ { active=1; count=0 }
          active {
            rest=$0
            while (match(rest,/"[^"]*"/)) {
              value=substr(rest,RSTART+1,RLENGTH-2)
              count++; if (count==1) source=value
              if (count==2) {
                n=split(value,paths," ")
                for (i=1;i<=n;i++) if (paths[i]==wanted) print source
                active=0; break
              }
              rest=substr(rest,RSTART+RLENGTH)
            }
          }' "$ROOT/engine/composition/hotswap_shadow_owners.def")"
        if [[ -n "$owner" ]]; then printf '%s\n' "$owner"; return; fi
        awk -v wanted="$path" '
          /^HOTSWAP_SERVICE\(/ { active=1; count=0 }
          active {
            rest=$0
            while (match(rest,/"[^"]*"/)) {
              value=substr(rest,RSTART+1,RLENGTH-2)
              count++; if (count==2) {
                if (value==wanted) print value
                active=0; break
              }
              rest=substr(rest,RSTART+RLENGTH)
            }
          }' "$ROOT/engine/composition/hotswap_services.def" ;;
    esac
}

find_impact()
{
    local cursor="$1" terminal="$2" edit="$3" raw next phase observed i
    for ((i=0; i<16 && cursor<terminal; i++)); do
        raw="$($BIN dev loop wait --input="{\"after_epoch\":$cursor,\"timeout_ms\":100}" 2>/dev/null)" || return 1
        next="$(jq -r '.data.epoch//0' <<<"$raw")"
        [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$cursor" &&
           "$next" -le "$terminal" ]] || return 1
        phase="$(jq -r '.data.phase//""' <<<"$raw")"
        observed="$(jq -r '.data.edit_epoch//""' <<<"$raw")"
        if [[ "$phase" == IMPACT_READY && "$observed" == "$edit" ]]; then
            printf '%s\n' "$raw"
            return 0
        fi
        cursor="$next"
    done
    return 1
}

# A root-shaped field is not evidence that this save produced the reported
# behavior. The immutable edit, compiler output, loaded image and handoff must
# all name the same owner and generation before a story can count as coverage.
bound_story()
{
    local impact="$1" sealed="$2" compact="$3"
    local expected_path="$4" expected_owner="$5" expected_class="$6"
    local expected_leaf="$7" expected_size="$8" before="$9" after="${10}"
    local expected_candidate="${11}" expected_inputs="${12}"
    [[ -n "$expected_owner" ]] || return 1
    jq -e --arg path "$expected_path" --arg owner "$expected_owner" \
       --arg class "$expected_class" --arg candidate "$expected_candidate" \
       --arg inputs "$expected_inputs" \
       --arg leaf "$expected_leaf" --argjson impact "$impact" \
       --argjson size "$expected_size" \
       --argjson before "$before" --argjson after "$after" \
       --argjson compact "$compact" '
      def hex64: type=="string" and test("^[0-9a-f]{64}$");
      .ok==true and $compact.ok==true and $after>$before and
      .data.epoch==$after and $compact.data.epoch==$after and
      .data.phase=="STORY_GREEN" and $compact.data.event==.data.phase and
      .data.edit_epoch==$compact.data.edit_epoch and
      $impact.ok==true and $impact.data.phase=="IMPACT_READY" and
      $impact.data.epoch>$before and $impact.data.epoch<$after and
      $impact.data.edit_epoch==.data.edit_epoch and
      $impact.data.file_count==1 and
      ($impact.data.blobs|length)==1 and
      $impact.data.blobs[0].path==$path and
      $impact.data.blobs[0].new_present==true and
      $impact.data.blobs[0].new_size==$size and
      $impact.data.blobs[0].new_blob_sha3==$leaf and ($leaf|hex64) and
      .data.candidate_object_root==$compact.data.candidate_object_root and
      .data.candidate_module_root==$compact.data.candidate_module_root and
      .data.observation_root==$compact.data.observation_root and
      .data.feedback_class==$compact.data.feedback_class and
      .data.feedback_class==$class and
      .data.source_tu==$owner and .data.runtime_published==false and
      (.data.edit_epoch|hex64) and
      .data.proof_handoff.schema=="zcl.dev_proof_handoff.v2" and
      .data.proof_handoff.source_epoch==.data.edit_epoch and
      (.data.proof_handoff.candidate_epoch|hex64) and
      .data.proof_handoff.candidate_epoch==$candidate and
      .data.proof_handoff.affected_component==$owner and
      .data.proof_handoff.affected_file_count==1 and
      .data.proof_handoff.action=="affected_proof" and
      .data.proof_handoff.proof_inputs_sha3==$inputs and ($inputs|hex64) and
      .data.proof_handoff.feedback_class==$class and
      .data.proof_handoff.compile_green==true and
      .data.proof_handoff.story_obtained==true and
      .data.candidate_bytes_executed==true and
      .data.resident.candidate_bytes_executed==true and
      .data.resident.status=="green" and
      (if $class=="HOT_FORK" then
        .data.resident.story_checks_run>0 and
        .data.resident.story_checks_passed==.data.resident.story_checks_run
       else
        .data.resident.probe_stage=="verified" and
        (.data.resident.service_id|type=="string" and length>0)
       end) and
      (.data.candidate_object_root|hex64) and
      (.data.candidate_module_root|hex64) and
      (.data.story_root|hex64) and
      (.data.story_fixture_root|hex64) and
      (.data.observation_root|hex64) and
      .data.build_receipt.source_tu==$owner and
      .data.build_receipt.artifact_sha256==.data.candidate_module_root and
      .data.build_receipt.candidate_object_root==.data.candidate_object_root and
      .data.build_receipt.candidate_module_root==.data.candidate_module_root and
      .data.loaded_mapping_root==.data.candidate_module_root and
      .data.resident.loaded_mapping_root==.data.candidate_module_root and
      .data.resident.candidate_object_root==.data.candidate_object_root and
      .data.resident.candidate_module_root==.data.candidate_module_root and
      .data.resident.story_root==.data.story_root and
      .data.resident.story_fixture_root==.data.story_fixture_root and
      .data.resident.observation_root==.data.observation_root and
      .data.proof_handoff.candidate_object_root==.data.candidate_object_root and
      .data.proof_handoff.candidate_module_root==.data.candidate_module_root and
      .data.proof_handoff.story_root==.data.story_root and
      .data.proof_handoff.story_fixture_root==.data.story_fixture_root and
      .data.proof_handoff.observation_root==.data.observation_root
    ' <<<"$sealed" >/dev/null
}

aggregate()
{
    local history="$1" samples="$2" output="$3"
    jq -n --slurpfile history "$history" --slurpfile samples "$samples" '
      ($history[0]) as $h | ($samples) as $s |
      def observed($path): first($s[] | select(.path==$path)) // null;
      [$h.entries[] | select(.class!="forbidden_authority_surface") |
       . as $entry | (observed(.path)) as $sample |
       $entry + {sample:$sample,
         useful:($sample != null and $sample.result_bound and
                 ($sample.feedback_us//0)>0 and
                 ($sample.feedback_us//0)<1000000),
         claims:{compiled_new_bytes:false,
           executed_exact_new_bytes:false,
           compiled_candidate_artifact:($sample.result_bound//false),
           executed_bound_candidate_artifact:($sample.result_bound//false),
           externally_checked_behavior:false,
           independent_proof:false},
         feedback_us:($sample.feedback_us//null),
         fallback_reason:(if $sample == null then
             (.class + ": " + .reason)
           elif $sample.result_bound and ($sample.feedback_us//0)>=1000000
             then "bound candidate story exceeded 1s feedback target"
           elif $sample.result_bound then ""
           else ($sample.failure//"registered fast owner returned no bound story")
           end)}] as $rows |
      ($rows|length) as $total |
      def covered($limit): [$rows[]|select(.useful and .feedback_us<$limit)]|length;
      {schema:"zcl.reflex_coverage_audit.v2",coverage_basis:"comment_only_edits",
       status:
         (if all($rows[] | select(.class=="COMPILE_ONLY" or
                                  .class=="HOT_EXECUTE" or
                                  .class=="HOT_SHADOW_CORE" or
                                  .class=="HOT_FORK"); .sample!=null)
          then "complete" else "partial" end),
       source_head:$h.source_head,
       history_rows_sha256:$h.history.frozen_rows_sha256,
       production_c_commits:$h.history.production_c_commits,
       nonforbidden_edit_occurrences:$total,
       behavior_coverage:{status:"unmeasured",
         reason:"timed edits are comments; behavior mutation receipts are separate"},
       measured_fast_paths:($s|length),
       coverage:{under_100ms_occurrences:covered(100000),
         under_100ms_percent:(10000*covered(100000)/$total|round/100),
         under_250ms_occurrences:covered(250000),
         under_250ms_percent:(10000*covered(250000)/$total|round/100),
         under_1s_occurrences:covered(1000000),
         under_1s_percent:(10000*covered(1000000)/$total|round/100),
         slower_fallback_occurrences:([$rows[]|select(.useful|not)]|length),
         slower_fallback_percent:
           (10000*([$rows[]|select(.useful|not)]|length)/$total|round/100)},
       fallbacks:([$rows[]|select(.useful|not)]|group_by(.fallback_reason)|
         map({reason:.[0].fallback_reason,edit_occurrences:length,
              unique_paths:(map(.path)|unique|length)})|
         sort_by([-.edit_occurrences,.reason])),
       fast_paths:($s|sort_by([-.frequency,.path])),rows:$rows}' >"$output"
}

self_test()
{
    local scratch history samples output
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-reflex-coverage-selftest.XXXXXX")"
    trap "rm -rf -- '$scratch'" EXIT INT TERM
    history="$scratch/history.json"; samples="$scratch/samples.jsonl"
    output="$scratch/output.json"
    printf '%s\n' '{"source_head":"abc","history":{"frozen_rows_sha256":"def","production_c_commits":2},"entries":[{"path":"a.c","class":"HOT_SHADOW_CORE","reason":"registered"},{"path":"a.c","class":"HOT_SHADOW_CORE","reason":"registered"},{"path":"b.c","class":"requires_fast_restart","reason":"restart"},{"path":"d.c","class":"HOT_FORK","reason":"registered"},{"path":"c.c","class":"forbidden_authority_surface","reason":"forbidden"}]}' >"$history"
    printf '%s\n' '{"path":"a.c","frequency":2,"result_bound":true,"feedback_class":"HOT_SHADOW_CORE","feedback_us":90000,"event":"STORY_GREEN","failure":""}' >"$samples"
    printf '%s\n' '{"path":"d.c","frequency":1,"result_bound":true,"feedback_class":"HOT_FORK","feedback_us":1200000,"event":"STORY_GREEN","failure":""}' >>"$samples"
    aggregate "$history" "$samples" "$output"
    jq -e '.status=="complete" and .coverage_basis=="comment_only_edits" and
      .behavior_coverage.status=="unmeasured" and
      .rows[0].claims.compiled_new_bytes==false and
      .rows[0].claims.executed_exact_new_bytes==false and
      .rows[0].claims.compiled_candidate_artifact==true and
      .rows[0].claims.executed_bound_candidate_artifact==true and
      .rows[0].claims.externally_checked_behavior==false and
      .nonforbidden_edit_occurrences==4 and
      .coverage.under_100ms_occurrences==2 and
      .coverage.under_100ms_percent==50 and
      .coverage.slower_fallback_occurrences==2 and
      any(.fallbacks[]; .reason=="bound candidate story exceeded 1s feedback target" and
          .edit_occurrences==1)' "$output" >/dev/null ||
        fail 'aggregation contract regressed'
    local good impact compact bad root_a root_b candidate_epoch inputs_root
    root_a="$(printf '%064d' 1)"; root_b="$(printf '%064d' 2)"
    candidate_epoch="$(candidate_epoch_for_module "$root_b")"
    inputs_root="$(proof_inputs_for_story "$candidate_epoch" "$root_a" a.c)"
    good="$(jq -cn --arg path a.c --arg class HOT_FORK \
      --arg a "$root_a" --arg b "$root_b" \
      --arg candidate "$candidate_epoch" --arg inputs "$inputs_root" '
      {ok:true,data:{epoch:12,phase:"STORY_GREEN",feedback_class:$class,
       source_tu:$path,runtime_published:false,edit_epoch:$a,
       candidate_bytes_executed:true,candidate_object_root:$a,
       candidate_module_root:$b,loaded_mapping_root:$b,
       story_root:$a,story_fixture_root:$b,observation_root:$a,
       build_receipt:{source_tu:$path,artifact_sha256:$b,
         candidate_object_root:$a,candidate_module_root:$b},
       resident:{status:"green",candidate_bytes_executed:true,
         candidate_object_root:$a,candidate_module_root:$b,
         loaded_mapping_root:$b,story_root:$a,story_fixture_root:$b,
         observation_root:$a,story_checks_run:2,story_checks_passed:2},
       proof_handoff:{schema:"zcl.dev_proof_handoff.v2",source_epoch:$a,
         candidate_epoch:$candidate,affected_component:$path,feedback_class:$class,
         affected_file_count:1,action:"affected_proof",proof_inputs_sha3:$inputs,
         compile_green:true,story_obtained:true,candidate_object_root:$a,
         candidate_module_root:$b,story_root:$a,story_fixture_root:$b,
         observation_root:$a}}}')"
    compact="$(jq -c '{ok,data:{epoch:.data.epoch,event:.data.phase,
      edit_epoch:.data.edit_epoch,feedback_class:.data.feedback_class,
      candidate_object_root:.data.candidate_object_root,
      candidate_module_root:.data.candidate_module_root,
      observation_root:.data.observation_root}}' <<<"$good")"
    impact="$(jq -cn --arg path a.c --arg leaf "$root_b" \
      --arg edit "$root_a" '{ok:true,data:{epoch:11,phase:"IMPACT_READY",
      edit_epoch:$edit,file_count:1,blobs:[{path:$path,new_present:true,
      new_size:42,new_blob_sha3:$leaf}]}}')"
    bound_story "$impact" "$good" "$compact" a.c a.c HOT_FORK \
        "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root" ||
        fail 'valid bound story refused'
    bound_story "$(jq -c '.data.blobs[0].path="helper.c"' <<<"$impact")" \
        "$good" "$compact" helper.c a.c HOT_FORK \
        "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root" ||
        fail 'declared helper to owner binding refused'
    local shadow shadow_compact
    shadow="$(jq -c '.data.feedback_class="HOT_SHADOW_CORE" |
      .data.proof_handoff.feedback_class="HOT_SHADOW_CORE" |
      .data.resident.probe_stage="verified" |
      .data.resident.service_id="fixture.service.v1" |
      del(.data.resident.story_checks_run,.data.resident.story_checks_passed)' <<<"$good")"
    shadow_compact="$(jq -c '.data.feedback_class="HOT_SHADOW_CORE"' <<<"$compact")"
    bound_story "$(jq -c '.data.blobs[0].path="helper.c"' <<<"$impact")" \
        "$shadow" "$shadow_compact" helper.c a.c HOT_SHADOW_CORE \
        "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root" ||
        fail 'pure helper service story refused'
    [[ "$(story_owner_for_path engine/modules/kernel/src/command_registry_input_types.c HOT_FORK)" == \
       engine/modules/kernel/src/command_registry_input_validate.c ]] ||
        fail 'HOT_FORK sibling mapping regressed'
    [[ "$(story_owner_for_path contexts/commons/modules/vcs/src/zcode_workspace_manifest.c HOT_SHADOW_CORE)" == \
       contexts/commons/services/src/zcode_workspace_view_service.c ]] ||
        fail 'shadow service member mapping regressed'
    for bad in \
      "$(jq -c '.data.proof_handoff.source_epoch=.data.proof_handoff.candidate_epoch' <<<"$good")" \
      "$(jq -c '.data.proof_handoff.affected_component="b.c"' <<<"$good")" \
      "$(jq -c '.data.resident.story_checks_passed=1' <<<"$good")" \
      "$(jq -c '.data.build_receipt.source_tu="b.c"' <<<"$good")" \
      "$(jq -c '.data.build_receipt.artifact_sha256=.data.candidate_object_root' <<<"$good")" \
      "$(jq -c '.data.resident.observation_root=.data.candidate_module_root' <<<"$good")" \
      "$(jq -c '.data.proof_handoff.candidate_epoch=.data.candidate_module_root' <<<"$good")" \
      "$(jq -c '.data.proof_handoff.proof_inputs_sha3=.data.candidate_module_root' <<<"$good")" \
      "$(jq -c '.data.loaded_mapping_root=.data.candidate_object_root' <<<"$good")" \
      "$(jq -c '.data.candidate_bytes_executed=false' <<<"$good")"; do
        if bound_story "$impact" "$bad" "$compact" a.c a.c HOT_FORK \
            "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root"; then
            fail 'seeded false admission passed the story guard'
        fi
    done
    if bound_story "$impact" "$good" "$compact" a.c a.c HOT_FORK "$root_b" 42 12 12 "$candidate_epoch" "$inputs_root" ||
       bound_story "$impact" "$good" "$compact" b.c a.c HOT_FORK "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root" ||
       bound_story "$impact" "$good" "$compact" a.c a.c HOT_FORK "$root_a" 42 10 12 "$candidate_epoch" "$inputs_root" ||
       bound_story "$impact" "$good" "$(jq -c '.data.observation_root=.data.candidate_module_root' <<<"$compact")" a.c a.c HOT_FORK "$root_b" 42 10 12 "$candidate_epoch" "$inputs_root"; then
        fail 'stale cursor or wrong owner passed the story guard'
    fi
    printf 'reflex-coverage-audit: self-test PASS\n'
}

if [[ "$MODE" == --self-test ]]; then self_test; exit 0; fi
[[ "$MODE" == run ]] || fail 'usage: reflex-coverage-audit.sh [run|--self-test]'
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
jq -e '.schema=="zcl.dev_loop_history_benchmark.v2" and
       (.entries|type)=="array"' "$HISTORY" >/dev/null ||
    fail 'current production history receipt is missing or invalid'

scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-reflex-coverage.XXXXXX")"
rows="$scratch/rows.jsonl"; samples="$scratch/samples.jsonl"
current_source=""; current_backup=""; watcher_id=0; watcher_session=""
stop_watcher()
{
    if [[ "$watcher_id" -gt 1 ]]; then
        "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" \
            >/dev/null 2>&1 || true
        watcher_id=0
    fi
}
restore_current()
{
    if [[ -n "$current_source" && -f "$current_backup" ]]; then
        cp -p -- "$current_backup" "$current_source"
    fi
}
cleanup()
{
    stop_watcher
    restore_current
    rm -rf -- "$scratch"
}
trap cleanup EXIT INT TERM

drive_to_terminal()
{
    local wait_for_edit="$1" input loops drive_rc
    result=''; event=''; drive_rc=0
    for ((loops = 0; loops < 16; loops++)); do
        input="$(jq -cn --argjson after "$after" \
          --argjson wait "$wait_for_edit" \
          '{after_epoch:$after,wait_for_edit:$wait,timeout_ms:5000}')"
        drive_rc=0
        result="$($BIN dev drive --input="$input")" || drive_rc=$?
        event="$(jq -r '.data.event//""' <<<"$result" 2>/dev/null || true)"
        next="$(jq -r '.data.epoch//0' <<<"$result" 2>/dev/null || printf 0)"
        if [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$after" ]]; then
            after="$next"
        else
            break
        fi
        case "$event" in
            STORY_GREEN|STORY_RED|FOCUSED_GREEN|FOCUSED_PARTIAL|FOCUSED_RED|COMPILE_GREEN|COMPILE_RED)
                break;;
            PROOF_PENDING|"") break;;
        esac
        wait_for_edit=false
    done
    rc="$drive_rc"
}

    jq -c --arg only "$ONLY_PATH" '.entries|map(select(
                               ($only=="" or .path==$only) and
                               (.class=="COMPILE_ONLY" or
                               .class=="HOT_EXECUTE" or
                               .class=="HOT_SHADOW_CORE" or
                               .class=="HOT_FORK")))|
  group_by(.path)|map({path:.[0].path,frequency:length})|
  sort_by([-.frequency,.path])[]' "$HISTORY" >"$rows"
[[ -s "$rows" ]] || fail 'history window has no registered fast owners'

sample_no=0
while IFS= read -r row; do
    sample_no=$((sample_no + 1))
    path="$(jq -r '.path' <<<"$row")"
    frequency="$(jq -r '.frequency' <<<"$row")"
    case "$path" in /*|*..*|*[!A-Za-z0-9_./-]*) fail "unsafe path: $path";; esac
    current_source="$ROOT/$path"
    [[ -f "$current_source" && ! -L "$current_source" ]] ||
        fail "fast owner is not a regular file: $path"
    # The audit is often run against the candidate being measured. Preserve
    # its exact current bytes rather than requiring a clean Git baseline.
    current_backup="$scratch/backup-$sample_no.c"
    cp -p -- "$current_source" "$current_backup"

    begin="$($BIN dev begin)"
    watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")"
    watcher_session="$(jq -er '.data.watcher_session' <<<"$begin")"
    after="$(jq -er '.data.epoch' <<<"$begin")"
    begin_cursor="$after"
    # Prime the owner once. This admits dependency baselines and contracts in
    # the resident service; it is intentionally outside the timed sample.
    staged="$(mktemp "$(dirname "$current_source")/.reflex-coverage.XXXXXX")"
    cp -p -- "$current_backup" "$staged"
    printf '\n/* ZCL_REFLEX_COVERAGE_WARM:%02d:%s */\n' "$sample_no" "$$" >>"$staged"
    chmod --reference="$current_source" "$staged"
    mv -f -- "$staged" "$current_source"
    drive_to_terminal true
    warm_event="$event"
    warm_cursor="$after"

    # A second distinct candidate is the measured warm edit.
    staged="$(mktemp "$(dirname "$current_source")/.reflex-coverage.XXXXXX")"
    cp -p -- "$current_backup" "$staged"
    printf '\n/* ZCL_REFLEX_COVERAGE_TIMED:%02d:%s */\n' "$sample_no" "$$" >>"$staged"
    chmod --reference="$current_source" "$staged"
    measured_start_cursor="$after"
    start_ns="$(date +%s%N)"
    mv -f -- "$staged" "$current_source"
    drive_to_terminal true
    end_ns="$(date +%s%N)"
    result_bound=false
    sealed='{}'; impact='{}'; leaf=''; source_size=0
    feedback_class="$(jq -r '.data.feedback_class//""' <<<"$result" 2>/dev/null || true)"
    case "$feedback_class" in
      HOT_EXECUTE|HOT_SHADOW_CORE|HOT_FORK)
        sealed="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}" 2>/dev/null || printf '{}')"
        edit_epoch="$(jq -r '.data.edit_epoch//""' <<<"$result" 2>/dev/null || true)"
        impact="$(find_impact "$measured_start_cursor" "$after" "$edit_epoch" || printf '{}')"
        leaf="$(source_leaf_sha3 "$path" "$current_source" || true)"
        source_size="$(wc -c <"$current_source")"
        owner="$(story_owner_for_path "$path" "$feedback_class")"
        module="$(jq -r '.data.candidate_module_root//""' <<<"$result")"
        candidate_epoch="$(candidate_epoch_for_module "$module")"
        inputs_root="$(proof_inputs_for_story "$candidate_epoch" "$edit_epoch" "$owner")"
        if [[ -n "$leaf" && -n "$owner" ]] &&
           bound_story "$impact" "$sealed" "$result" "$path" "$owner" \
                       "$feedback_class" "$leaf" "$source_size" \
                       "$measured_start_cursor" "$after" "$candidate_epoch" \
                       "$inputs_root"; then
          result_bound=true
        fi;;
    esac
    feedback_us="$(jq -r '.data.feedback_us//0' <<<"$result" 2>/dev/null || printf 0)"
    reported_reason="$(jq -r 'if (.error.code//"")!="" then
      (.error.code+": "+(.error.message//""))
      else (.data.why_not_live//.data.blocker//"") end' <<<"$result" 2>/dev/null || true)"
    failure="$reported_reason"
    binding_evidence='null'
    if [[ "$result_bound" == true ]]; then
        failure=''
        binding_evidence="$(jq -cn --argjson sealed "$sealed" \
          --argjson impact "$impact" --argjson compact "$result" \
          --arg local_leaf "$leaf" --argjson local_size "$source_size" \
          '{sealed:$sealed,impact:$impact,compact:$compact,
            local_leaf:$local_leaf,local_size:$local_size}')"
    elif [[ "$event" == STORY_GREEN ]]; then
        if [[ "$sealed" == '{}' ]]; then
            failure='sealed_event_unavailable'
        elif [[ "$impact" == '{}' ]]; then
            failure='impact_event_unavailable'
        elif [[ -z "$leaf" ]]; then
            failure='source_leaf_unavailable'
        else
            failure='story_binding_mismatch'
        fi
        binding_evidence="$(jq -cn --argjson sealed "$sealed" \
          --argjson impact "$impact" --argjson compact "$result" \
          --arg local_leaf "$leaf" --argjson local_size "$source_size" \
          '{sealed:$sealed,impact:$impact,compact:$compact,
            local_leaf:$local_leaf,local_size:$local_size}')"
    elif [[ -z "$failure" ]]; then
        failure='story did not bind requested owner, immutable epoch, artifact and behavior'
    fi
    jq -cn --arg path "$path" --argjson frequency "$frequency" \
      --arg event "$event" --argjson result_bound "$result_bound" \
      --arg feedback_class "$feedback_class" \
      --argjson feedback_us "$feedback_us" \
      --argjson wall_us "$(((end_ns-start_ns)/1000))" \
      --argjson exit_code "$rc" --arg failure "$failure" \
      --arg reported_reason "$reported_reason" \
      --argjson binding_evidence "$binding_evidence" \
      --argjson begin_cursor "$begin_cursor" \
      --arg warm_event "$warm_event" --argjson warm_cursor "$warm_cursor" \
      --argjson measured_start_cursor "$measured_start_cursor" \
      --argjson end_cursor "$after" \
      '{path:$path,frequency:$frequency,edit_kind:"comment_only",event:$event,
        feedback_class:$feedback_class,
        result_bound:$result_bound,feedback_us:$feedback_us,wall_us:$wall_us,
        exit_code:$exit_code,failure:$failure,
        reported_reason:$reported_reason,binding_evidence:$binding_evidence,
        begin_cursor:$begin_cursor,
        warm_event:$warm_event,warm_cursor:$warm_cursor,
        measured_start_cursor:$measured_start_cursor,end_cursor:$end_cursor}' \
        >>"$samples"
    printf 'coverage %02d %-62s %8sus %s\n' "$sample_no" "$path" \
      "$feedback_us" "${event:-UNBOUND}" >&2

    stop_watcher
    restore_current
    cmp -s -- "$current_backup" "$current_source" ||
        fail "source restoration mismatch: $path"
    current_source=""; current_backup=""
done <"$rows"

mkdir -p "$(dirname "$OUTPUT")"
aggregate "$HISTORY" "$samples" "$OUTPUT.tmp"
mv "$OUTPUT.tmp" "$OUTPUT"
trap - EXIT INT TERM
rm -rf -- "$scratch"
jq -r --arg output "$OUTPUT" '
  "reflex-coverage-audit: under100=\(.coverage.under_100ms_percent)% under250=\(.coverage.under_250ms_percent)% under1s=\(.coverage.under_1s_percent)% fallback=\(.coverage.slower_fallback_percent)% receipt=\($output)"' "$OUTPUT"
