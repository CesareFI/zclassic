#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Permanent sensitivity proof for the watcher classification core.

set -euo pipefail

ROOT="${ZCL_SOURCE_ROOT:-$(pwd -P)}"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/z23-dev}"
OWNER_KIND="${ZCL_REFLEX_OWNER_KIND:-watch}"
SOURCE="$ROOT/tools/dev/devloop_watch_classify.c"
UNRELATED="$ROOT/contexts/market/services/src/market_moderation_service.c"
OUTPUT="${ZCL_REFLEX_WATCH_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-watch-core-acceptance.json}"
STORY='devloop-watch-classification-core.v1'
STORY_INPUT=''
if [[ "$OWNER_KIND" == watch ]]; then
    STORY_INPUT="$ROOT/tools/dev/hotfork_stories/devloop_watch_classification_core_v1.inc"
fi
FORBIDDEN='git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite'
MUTANT_OLD='return changed || commit_preempts || request_hint_changed;'
MUTANT_NEW='return changed || commit_preempts || !request_hint_changed;'
if [[ "$OWNER_KIND" == cycle ]]; then
    SOURCE="$ROOT/tools/dev/devloop_cycle.c"
    OUTPUT="${ZCL_REFLEX_CYCLE_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-cycle-core-acceptance.json}"
    STORY='devloop-cycle-diagnostic-policy.v1'
    MUTANT_OLD='strcmp(status, "passed") == 0'
    MUTANT_NEW='strcmp(status, "passed") != 0'
elif [[ "$OWNER_KIND" == corpus ]]; then
    SOURCE="$ROOT/tools/command/native_zcode_corpus_command.c"
    OUTPUT="${ZCL_REFLEX_CORPUS_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-corpus-core-acceptance.json}"
    STORY='zcode-corpus-command-core.v1'
    MUTANT_OLD="root[i] >= 'a'"
    MUTANT_NEW="root[i] > 'a'"
elif [[ "$OWNER_KIND" == plan ]]; then
    SOURCE="$ROOT/tools/dev/devloop_plan.c"
    OUTPUT="${ZCL_REFLEX_PLAN_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-plan-core-acceptance.json}"
    STORY='devloop-plan-classification.v1'
    MUTANT_OLD='strcmp(name, "build") == 0'
    MUTANT_NEW='strcmp(name, "build") != 0'
elif [[ "$OWNER_KIND" == shop-want ]]; then
    SOURCE="$ROOT/contexts/market/controllers/src/shop_native_want.c"
    OUTPUT="${ZCL_REFLEX_SHOP_WANT_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-shop-want-core-acceptance.json}"
    STORY='shop-want-command-input-core.v1'
    MUTANT_OLD='w->expires_unix <= now_unix'
    MUTANT_NEW='w->expires_unix < now_unix'
elif [[ "$OWNER_KIND" == command-input ]]; then
    # The per-key integer bounds moved out of command_registry.c into the
    # sibling TU command_registry_input_types.c, where the max_cpu_seconds
    # rule is now the table row below. The capsule names that sibling in its
    # TU set (engine/composition/hotfork_capsules.def), so editing it selects
    # the same story and the mutation is observed inside the capsule rather
    # than resolved from the resident binary.
    SOURCE="$ROOT/engine/modules/kernel/src/command_registry_input_types.c"
    OUTPUT="${ZCL_REFLEX_COMMAND_INPUT_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-command-input-core-acceptance.json}"
    STORY='command-registry-input-validation-core.v1'
    MUTANT_OLD='{ "max_cpu_seconds", 1, 600 },'
    MUTANT_NEW='{ "max_cpu_seconds", 1, 599 },'
elif [[ "$OWNER_KIND" == native-dev ]]; then
    SOURCE="$ROOT/tools/command/native_dev_input_policy.c"
    OUTPUT="${ZCL_REFLEX_NATIVE_DEV_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-native-dev-core-acceptance.json}"
    STORY='native-dev-input-and-interrupt-policy.v1'
    MUTANT_OLD='strstr(path, "..")'
    MUTANT_NEW='strstr(path, "__never__")'
elif [[ "$OWNER_KIND" == curve25519 ]]; then
    SOURCE="$ROOT/core/modules/crypto/src/curve25519.c"
    OUTPUT="${ZCL_REFLEX_CURVE25519_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-curve25519-acceptance.json}"
    STORY='curve25519-rfc7748-calculation.v1'
    MUTANT_OLD='c * (1LL << 16)'
    MUTANT_NEW='c * (1LL << 15)'
elif [[ "$OWNER_KIND" == package-policy ]]; then
    SOURCE="$ROOT/contexts/commons/modules/vcs/src/package_policy.c"
    OUTPUT="${ZCL_REFLEX_PACKAGE_POLICY_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-package-policy-acceptance.json}"
    STORY='package-policy-boundary-calculation.v1'
    MUTANT_OLD='VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW,'
    MUTANT_NEW='VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW - 1u,'
elif [[ "$OWNER_KIND" == shadow-select ]]; then
    # The mutant is a real historical body edit run backwards: 2648a4c186
    # made a moved contract an unknown scope. Undoing it must turn the
    # shadow selector core story RED from the candidate bytes alone.
    SOURCE="$ROOT/tools/dev/dev_shadow_rule.c"
    OUTPUT="${ZCL_REFLEX_SHADOW_SELECT_CORE_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-shadow-select-core-acceptance.json}"
    STORY='dev-shadow-selector-core.v1'
    MUTANT_OLD='facts->plan_refused || facts->contract_moved)'
    MUTANT_NEW='facts->plan_refused)'
elif [[ "$OWNER_KIND" == shadow-select-sibling ]]; then
    # A sibling TU of the same capsule: the lint pricing cap from e3717b5f7c
    # run backwards. Its rule must be observed inside the capsule, never
    # resolved from the resident binary.
    SOURCE="$ROOT/tools/dev/dev_shadow_lint.c"
    OUTPUT="${ZCL_REFLEX_SHADOW_SELECT_SIBLING_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-shadow-select-sibling-acceptance.json}"
    STORY='dev-shadow-selector-core.v1'
    MUTANT_OLD='if (units_ms > rest) units_ms = rest;'
    MUTANT_NEW='if (units_ms > gate_ms) units_ms = gate_ms;'
fi
EDITED_PATH="${SOURCE#$ROOT/}"
CAPSULE_OWNER="$EDITED_PATH"
if [[ "$OWNER_KIND" == command-input ]]; then
    CAPSULE_OWNER='engine/modules/kernel/src/command_registry_input_validate.c'
fi

fail() { printf 'reflex-hotfork-watch-core-acceptance: %s\n' "$*" >&2; exit 2; }

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

find_impact()
{
    local cursor="$1" terminal="$2" edit="$3" raw next phase observed i
    for ((i=0; i<16 && cursor<terminal; i++)); do
        raw="$($BIN dev loop wait --input="{\"after_epoch\":$cursor,\"timeout_ms\":100}")" || return 1
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

find_compile()
{
    local cursor="$1" terminal="$2" edit="$3" raw next phase observed i
    for ((i=0; i<16 && cursor<terminal; i++)); do
        raw="$($BIN dev loop wait --input="{\"after_epoch\":$cursor,\"timeout_ms\":100}")" || return 1
        next="$(jq -r '.data.epoch//0' <<<"$raw")"
        [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$cursor" &&
           "$next" -le "$terminal" ]] || return 1
        phase="$(jq -r '.data.phase//""' <<<"$raw")"
        observed="$(jq -r '.data.edit_epoch//""' <<<"$raw")"
        if [[ "$phase" == COMPILE_GREEN || "$phase" == COMPILE_RED ]] &&
           [[ "$observed" == "$edit" ]]; then
            printf '%s\n' "$raw"
            return 0
        fi
        cursor="$next"
    done
    return 1
}
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
[[ -f "$SOURCE" && ! -L "$SOURCE" ]] || fail "owner source is not a regular file: $SOURCE"
command -v jq >/dev/null || fail 'jq is required'

backup="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-watch-core.XXXXXX")"
unrelated_backup="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-watch-core-unrelated.XXXXXX")"
story_backup=''
if [[ -n "$STORY_INPUT" ]]; then
    story_backup="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-watch-core-story.XXXXXX")"
    cp -p -- "$STORY_INPUT" "$story_backup"
fi
watcher_id=0
watcher_session=""
cleanup()
{
    if [[ "$watcher_id" -gt 0 ]]; then
        "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" >/dev/null 2>&1 || true
    fi
    cp -p -- "$backup" "$SOURCE"
    cp -p -- "$unrelated_backup" "$UNRELATED"
    if [[ -n "$story_backup" ]]; then
        cp -p -- "$story_backup" "$STORY_INPUT"
    fi
    rm -f -- "$backup" "$unrelated_backup"
    if [[ -n "$story_backup" ]]; then rm -f -- "$story_backup"; fi
}
trap cleanup EXIT INT TERM
cp -p -- "$SOURCE" "$backup"
cp -p -- "$UNRELATED" "$unrelated_backup"

begin="$($BIN dev begin)"
watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")" || fail 'watcher id missing'
watcher_session="$(jq -er '.data.watcher_session' <<<"$begin")" || fail 'watcher session missing'
after="$(jq -er '.data.epoch' <<<"$begin")" || fail 'event cursor missing'
nonce="$(date +%s%N)"

record_attempt_failure()
{
    local reason="$1"
    mkdir -p "$(dirname "$OUTPUT")"
    (set -C; jq -n --arg expected "$expected" --arg reason "$reason" \
      --argjson latency_bound "$latency_bound" \
      --arg result_text "$result" --arg compile_text "$compile_raw" '
      ($result_text|try fromjson catch null) as $result |
      ($compile_text|try fromjson catch null) as $compile |
      {schema:"zcl.reflex_watch_attempt_failure.v1",expected:$expected,
       failure_reason:$reason,latency_bound_us:$latency_bound,
       latency_miss:($latency_bound>0 and
         (($result.data.feedback_us//0)>=$latency_bound)),
       result:$result,result_raw:$result_text,
       compile_event:$compile,compile_raw:$compile_text,
       independent_proof:false}' \
      >"$OUTPUT.miss.$nonce.json") || fail 'could not preserve failed attempt'
    fail "$reason"
}

drive_candidate()
{
    local candidate="$1" expected="$2" latency_bound="${3:-1000000}"
    local wait_for_edit=true event='' next loops edit
    chmod --reference="$SOURCE" "$candidate"
    start_cursor="$after"
    mv -f -- "$candidate" "$SOURCE"
    result=''
    compile_raw='null'
    for ((loops = 0; loops < 16; loops++)); do
        if ! result="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":$wait_for_edit,\"timeout_ms\":5000}")"; then
            record_attempt_failure 'dev drive refused or failed'
        fi
        event="$(jq -r '.data.event//""' <<<"$result")" ||
            record_attempt_failure 'dev drive returned malformed event'
        next="$(jq -r '.data.epoch//0' <<<"$result")" ||
            record_attempt_failure 'dev drive returned malformed cursor'
        [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$after" ]] ||
            record_attempt_failure 'event cursor did not advance'
        after="$next"
        [[ "$event" == "$expected" || "$event" == STORY_RED ||
           "$event" == COMPILE_RED ]] && break
        wait_for_edit=false
    done
    edit="$(jq -r '.data.edit_epoch//""' <<<"$result")" ||
        record_attempt_failure 'dev drive returned malformed edit epoch'
    compile_raw="$(find_compile "$start_cursor" "$after" \
      "$edit")" || record_attempt_failure 'matching compile event missing'
    if ! jq -e --arg expected "$expected" --arg story "$STORY" \
      --argjson latency_bound "$latency_bound" \
      --arg forbidden "$FORBIDDEN" '
      .ok==true and .data.event==$expected and
      .data.feedback_class=="HOT_FORK" and
      .data.story_fixture_id==$story and .data.story_adapter==$story and
      .data.story_timeout_ms==1000 and
      .data.forbidden_effect_mask==$forbidden and
      .data.candidate_bytes_executed==true and .data.runtime_published==false and
      ($latency_bound==0 or .data.feedback_us<$latency_bound) and
      (.data.candidate_object_root|test("^[0-9a-f]{64}$")) and
      (.data.candidate_module_root|test("^[0-9a-f]{64}$")) and
      .data.loaded_mapping_root==.data.candidate_module_root and
      (.data.story_root|test("^[0-9a-f]{64}$")) and
      (.data.story_fixture_root|test("^[0-9a-f]{64}$")) and
      (.data.observation_root|test("^[0-9a-f]{64}$"))' <<<"$result" >/dev/null; then
        record_attempt_failure "candidate did not return bound $expected"
    fi
}

green="$(mktemp "$ROOT/tools/dev/.reflex-watch-core-green.XXXXXX")"
cp -p -- "$backup" "$green"
printf '\n/* ZCL_REFLEX_WATCH_CORE_ACCEPTANCE:%s */\n' "$nonce" >>"$green"
drive_candidate "$green" STORY_GREEN
green_result="$result"
green_compile="$compile_raw"
green_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}")"
green_leaf="$(source_leaf_sha3 "${SOURCE#$ROOT/}" "$SOURCE")"
green_size="$(wc -c <"$SOURCE")"
green_impact="$(find_impact "$start_cursor" "$after" "$(jq -r '.data.edit_epoch' <<<"$green_result")")" ||
    fail 'green immutable source impact missing'

printf '\n/* ZCL_REFLEX_WATCH_CORE_UNRELATED:%s */\n' "$nonce" >>"$UNRELATED"
unrelated_wait=true
for ((loops = 0; loops < 16; loops++)); do
    unrelated_event="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":$unrelated_wait,\"timeout_ms\":5000}")"
    next="$(jq -r '.data.epoch//0' <<<"$unrelated_event")"
    [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$after" ]] ||
        fail "unrelated edit cursor did not advance: $(jq -c . <<<"$unrelated_event")"
    after="$next"
    event="$(jq -r '.data.event//""' <<<"$unrelated_event")"
    unrelated_wait=false
    [[ "$event" == IMPACT_READY ]] && continue
    break
done
jq -e --arg story "$STORY" '.ok==true and (.data.story_id//"")!=$story' \
    <<<"$unrelated_event" >/dev/null || fail 'unrelated owner was falsely attributed'

unrelated_proof="$(mktemp "$ROOT/tools/dev/.reflex-watch-core-unrelated-proof.XXXXXX")"
cp -p -- "$backup" "$unrelated_proof"
printf '\n/* ZCL_REFLEX_WATCH_CORE_ACCEPTANCE:%s */\n' "$nonce" >>"$unrelated_proof"
drive_candidate "$unrelated_proof" STORY_GREEN
unrelated_result="$result"
unrelated_compile="$compile_raw"
unrelated_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}")"

mutant="$(mktemp "$ROOT/tools/dev/.reflex-watch-core-red.XXXXXX")"
cp -p -- "$SOURCE" "$mutant"
MUTANT_OLD="$MUTANT_OLD" MUTANT_NEW="$MUTANT_NEW" perl -0pi -e '
  my $old = $ENV{MUTANT_OLD}; my $new = $ENV{MUTANT_NEW};
  my $count = s/\Q$old\E/$new/; die "mutation count=$count\n" unless $count == 1;
' "$mutant"
drive_candidate "$mutant" STORY_RED
red_result="$result"
red_compile="$compile_raw"
jq -e '.data.next_command=="fix the failed check in story_detail, then save the C23 edit"' \
    <<<"$red_result" >/dev/null || fail 'RED did not name the source edit as next action'
red_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}")"
red_leaf="$(source_leaf_sha3 "${SOURCE#$ROOT/}" "$SOURCE")"
red_size="$(wc -c <"$SOURCE")"
red_impact="$(find_impact "$start_cursor" "$after" "$(jq -r '.data.edit_epoch' <<<"$red_result")")" ||
    fail 'red immutable source impact missing'

revert="$(mktemp "$ROOT/tools/dev/.reflex-watch-core-revert.XXXXXX")"
cp -p -- "$backup" "$revert"
printf '\n/* ZCL_REFLEX_WATCH_CORE_ACCEPTANCE:%s */\n' "$nonce" >>"$revert"
drive_candidate "$revert" STORY_GREEN
revert_result="$result"
revert_compile="$compile_raw"
revert_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}")"
revert_leaf="$(source_leaf_sha3 "${SOURCE#$ROOT/}" "$SOURCE")"
revert_size="$(wc -c <"$SOURCE")"
revert_impact="$(find_impact "$start_cursor" "$after" "$(jq -r '.data.edit_epoch' <<<"$revert_result")")" ||
    fail 'revert immutable source impact missing'

object="$(jq -r '.data.candidate_object_root' <<<"$green_result")"
module="$(jq -r '.data.candidate_module_root' <<<"$green_result")"
for raw in "$unrelated_raw" "$revert_raw"; do
    jq -e --arg object "$object" --arg module "$module" '
      .data.build_receipt.artifact_cache_hit==true and
      .data.build_receipt.compiler_processes==0 and
      .data.build_receipt.linker_processes==0 and
      .data.candidate_object_root==$object and .data.candidate_module_root==$module' \
      <<<"$raw" >/dev/null || fail 'exact candidate cache identity was not reused'
done

# These are three separate observations. The source mutation is chosen by
# this resident acceptance script, while the fast story itself remains
# candidate-influenced feedback. Keep the exact build and mapped-image roots
# beside the independently expected green/red/revert sequence.
jq -e --arg owner "$CAPSULE_OWNER" --arg edited "$EDITED_PATH" \
  --argjson green "$green_raw" --argjson red "$red_raw" \
  --argjson revert "$revert_raw" \
  --argjson green_reply "$green_result" \
  --argjson red_reply "$red_result" \
  --argjson revert_reply "$revert_result" \
  --argjson green_impact "$green_impact" \
  --argjson red_impact "$red_impact" \
  --argjson revert_impact "$revert_impact" \
  --arg green_leaf "$green_leaf" --arg red_leaf "$red_leaf" \
  --arg revert_leaf "$revert_leaf" \
  --argjson green_size "$green_size" \
  --argjson red_size "$red_size" \
  --argjson revert_size "$revert_size" '
  def hex64: type=="string" and test("^[0-9a-f]{64}$");
  all([$green,$red,$revert][];
    .ok==true and .data.source_tu==$owner and
    .data.build_receipt.source_tu==$owner and
    (.data.build_receipt.candidate_object_root|hex64) and
    (.data.build_receipt.candidate_module_root|hex64) and
    .data.build_receipt.artifact_sha256==.data.candidate_module_root and
    .data.build_receipt.candidate_object_root==.data.candidate_object_root and
    .data.build_receipt.candidate_module_root==.data.candidate_module_root and
    .data.loaded_mapping_root==.data.candidate_module_root and
    .data.resident.loaded_mapping_root==.data.candidate_module_root and
    .data.resident.candidate_object_root==.data.candidate_object_root and
    .data.resident.candidate_module_root==.data.candidate_module_root and
    .data.resident.observation_root==.data.observation_root and
    (.data.observation_root|hex64) and
    .data.resident.forked==true and
    .data.candidate_bytes_executed==true and
    .data.resident.candidate_bytes_executed==true) and
  $green.data.phase=="STORY_GREEN" and
  $red.data.phase=="STORY_RED" and
  $revert.data.phase=="STORY_GREEN" and
  $green.data.resident.story_checks_run>0 and
  $green.data.resident.story_checks_passed==
    $green.data.resident.story_checks_run and
  $red.data.resident.story_checks_passed<
    $red.data.resident.story_checks_run and
  $revert.data.resident.story_checks_passed==
    $revert.data.resident.story_checks_run and
  $green.data.epoch<$red.data.epoch and
  $red.data.epoch<$revert.data.epoch and
  ($green.data.edit_epoch|hex64) and
  ($red.data.edit_epoch|hex64) and
  ($revert.data.edit_epoch|hex64) and
  $green.data.edit_epoch!=$red.data.edit_epoch and
  $red.data.edit_epoch!=$revert.data.edit_epoch and
  all([[$green,$green_reply],[$red,$red_reply],[$revert,$revert_reply]][];
    .[0].data.epoch==.[1].data.epoch and
    .[0].data.phase==.[1].data.event and
    .[0].data.edit_epoch==.[1].data.edit_epoch and
    .[0].data.candidate_object_root==.[1].data.candidate_object_root and
    .[0].data.candidate_module_root==.[1].data.candidate_module_root and
    .[0].data.observation_root==.[1].data.observation_root) and
  all([[$green,$green_impact,$green_leaf,$green_size],
       [$red,$red_impact,$red_leaf,$red_size],
       [$revert,$revert_impact,$revert_leaf,$revert_size]][];
    .[1].ok==true and .[1].data.phase=="IMPACT_READY" and
    .[1].data.epoch<.[0].data.epoch and
    .[1].data.edit_epoch==.[0].data.edit_epoch and
    .[1].data.file_count==1 and
    (.[1].data.blobs|length)==1 and
    .[1].data.blobs[0].path==$edited and
    .[1].data.blobs[0].new_present==true and
    .[1].data.blobs[0].new_blob_sha3==.[2] and
    .[1].data.blobs[0].new_size==.[3]) and
  $green_leaf!=$red_leaf and $green_leaf==$revert_leaf and
  $red.data.candidate_object_root!=$green.data.candidate_object_root and
  $red.data.candidate_module_root!=$green.data.candidate_module_root and
  $revert.data.candidate_object_root==$green.data.candidate_object_root and
  $revert.data.candidate_module_root==$green.data.candidate_module_root
' <<<"$green_raw" >/dev/null ||
    fail 'green/red/revert did not bind compiled bytes, mapped bytes, and expected behavior'

malformed_result='null'
malformed_raw='null'
malformed_compile='null'
malformed_story_sha256=''
if [[ -n "$STORY_INPUT" ]]; then
    "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" >/dev/null ||
        fail 'could not stop watcher before malformed story fixture'
    watcher_id=0
    watcher_session=''
    perl -0pi -e 's/(out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;)/$1\n    if (out->magic == ZCL_HOTFORK_OBSERVATION_MAGIC) return false;/ or die "story mutation missing\n"' "$STORY_INPUT"
    malformed_story_sha256="$(sha256sum "$STORY_INPUT" | awk '{print $1}')"
    begin="$($BIN dev begin)"
    watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")" || fail 'malformed watcher id missing'
    watcher_session="$(jq -er '.data.watcher_session' <<<"$begin")" || fail 'malformed watcher session missing'
    after="$(jq -er '.data.epoch' <<<"$begin")" || fail 'malformed event cursor missing'
    malformed="$(mktemp "$ROOT/tools/dev/.reflex-watch-core-malformed.XXXXXX")"
    cp -p -- "$backup" "$malformed"
    printf '\n/* ZCL_REFLEX_WATCH_CORE_MALFORMED:%s */\n' "$nonce" >>"$malformed"
    drive_candidate "$malformed" STORY_RED 0
    malformed_result="$result"
    malformed_compile="$compile_raw"
    malformed_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((after-1)),\"timeout_ms\":100}")"
    jq -e '
      .data.event=="STORY_RED" and
      .data.next_command=="z23-dev dev diagnose latest" and
      .data.why_not_live=="HOT_FORK child did not prove an isolated failed fixture check" and
      .data.candidate_bytes_executed==true and .data.story_detail==""
    ' <<<"$malformed_result" >/dev/null ||
        fail 'malformed candidate was given source-edit advice'
    jq -e '.data.resident.story_checks_run==0 and
      .data.resident.candidate_bytes_executed==true' \
      <<<"$malformed_raw" >/dev/null ||
        fail 'malformed candidate result was not preserved as a RED receipt'
    "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" >/dev/null ||
        fail 'could not stop malformed watcher before restoring story'
    watcher_id=0
    watcher_session=''
    cp -p -- "$story_backup" "$STORY_INPUT"
fi

mkdir -p "$(dirname "$OUTPUT")"
jq -n --arg owner "$CAPSULE_OWNER" --arg edited "$EDITED_PATH" \
  --argjson green "$green_result" --argjson red "$red_result" \
  --argjson green_raw "$green_raw" --argjson red_raw "$red_raw" \
  --argjson green_impact "$green_impact" --argjson red_impact "$red_impact" \
  --argjson unrelated "$unrelated_result" --argjson unrelated_raw "$unrelated_raw" \
  --argjson revert "$revert_result" --argjson revert_raw "$revert_raw" \
  --argjson malformed "$malformed_result" --argjson malformed_raw "$malformed_raw" \
  --argjson green_compile "$green_compile" --argjson red_compile "$red_compile" \
  --argjson unrelated_compile "$unrelated_compile" \
  --argjson revert_compile "$revert_compile" \
  --argjson malformed_compile "$malformed_compile" \
  --arg malformed_story_sha256 "$malformed_story_sha256" '
  {schema:"zcl.reflex_owner_acceptance.v1",owner:$owner,
   edited_path:$edited,
   claims:{compiled_new_bytes:true,executed_exact_new_bytes:true,
     externally_checked_behavior:true,independent_proof:false,
     scope:"frozen mutation vector; candidate story is feedback"},
   exact_roots:{green:{edit_epoch:$green_raw.data.edit_epoch,
       source_blob:$green_impact.data.blobs[0].new_blob_sha3,
       object:$green_raw.data.candidate_object_root,
       module:$green_raw.data.candidate_module_root,
       loaded:$green_raw.data.loaded_mapping_root,
       observation:$green_raw.data.observation_root},
     born_red:{edit_epoch:$red_raw.data.edit_epoch,
       source_blob:$red_impact.data.blobs[0].new_blob_sha3,
       object:$red_raw.data.candidate_object_root,
       module:$red_raw.data.candidate_module_root,
       loaded:$red_raw.data.loaded_mapping_root,
       observation:$red_raw.data.observation_root}},
   resources:{scope:"green, RED, unrelated, revert, and optional malformed results",
     green_wall_us:$green_raw.data.elapsed_us,
     born_red_wall_us:$red_raw.data.elapsed_us,
     revert_wall_us:$revert_raw.data.elapsed_us,
     compiler_launches:([$green_raw,$red_raw,$unrelated_raw,$revert_raw,$malformed_raw] |
       map(.data.build_receipt.compiler_processes//0)|add),
     linker_launches:([$green_raw,$red_raw,$unrelated_raw,$revert_raw,$malformed_raw] |
       map(.data.build_receipt.linker_processes//0)|add),
     story_forks:([$green_raw,$red_raw,$unrelated_raw,$revert_raw,$malformed_raw] |
       map(if .data.resident.forked then 1 else 0 end)|add), cpu_us:null,
     cpu_note:"per-story CPU is not present in the sealed event"},
   build_stages:{green:$green_compile.data.build_stages,
     born_red:$red_compile.data.build_stages,
     unrelated:$unrelated_compile.data.build_stages,
     revert:$revert_compile.data.build_stages,
     malformed:$malformed_compile.data.build_stages},
   key_cost_us:{green:$green_compile.data.build_receipt.artifact_cache_key_us,
     born_red:$red_compile.data.build_receipt.artifact_cache_key_us,
     unrelated:$unrelated_compile.data.build_receipt.artifact_cache_key_us,
     revert:$revert_compile.data.build_receipt.artifact_cache_key_us,
     malformed:$malformed_compile.data.build_receipt.artifact_cache_key_us},
   green:{event:$green.data.event,feedback_us:$green.data.feedback_us,
     candidate_object_root:$green.data.candidate_object_root,
     candidate_module_root:$green.data.candidate_module_root,
     loaded_mapping_root:$green.data.loaded_mapping_root,
     observation_root:$green.data.observation_root},
   born_red:{event:$red.data.event,feedback_us:$red.data.feedback_us,
     compile_valid:true,candidate_bytes_executed:true,
     story_detail:$red.data.story_detail,observation_root:$red.data.observation_root},
   unrelated_change:{false_owner_attribution:false,
     artifact_cache_hit:$unrelated_raw.data.build_receipt.artifact_cache_hit,
     compiler_processes:$unrelated_raw.data.build_receipt.compiler_processes,
     linker_processes:$unrelated_raw.data.build_receipt.linker_processes,
     same_object:($green.data.candidate_object_root==$unrelated.data.candidate_object_root),
     same_module:($green.data.candidate_module_root==$unrelated.data.candidate_module_root)},
   exact_revert:{event:$revert.data.event,feedback_us:$revert.data.feedback_us,
     artifact_cache_hit:$revert_raw.data.build_receipt.artifact_cache_hit,
     compiler_processes:$revert_raw.data.build_receipt.compiler_processes,
     linker_processes:$revert_raw.data.build_receipt.linker_processes,
     same_object:($green.data.candidate_object_root==$revert.data.candidate_object_root),
     same_module:($green.data.candidate_module_root==$revert.data.candidate_module_root)},
   malformed_candidate:(if $malformed==null then null else
     {event:$malformed.data.event,feedback_us:$malformed.data.feedback_us,
      story_source_sha256:$malformed_story_sha256,
      object:$malformed.data.candidate_object_root,
      module:$malformed.data.candidate_module_root,
      loaded:$malformed.data.loaded_mapping_root,
      observation:$malformed.data.observation_root,
      checks_run:$malformed_raw.data.resident.story_checks_run,
      next_command:$malformed.data.next_command,
      why_not_live:$malformed.data.why_not_live} end),
   runtime_published:false}' >"$OUTPUT"

if [[ "$watcher_id" -gt 0 ]]; then
    "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id,\"watcher_session\":\"$watcher_session\"}" >/dev/null
fi
watcher_id=0
watcher_session=""
cp -p -- "$backup" "$SOURCE"
cp -p -- "$unrelated_backup" "$UNRELATED"
printf 'reflex-hotfork-%s-core-acceptance: PASS receipt=%s\n' "$OWNER_KIND" "$OUTPUT"
