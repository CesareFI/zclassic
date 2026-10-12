#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Build a detached, filtered stack using signed picks and canonical projections.
set -Eeuo pipefail
ROOT="$(CDPATH= cd -P -- "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
# Refuse ambient Git routing/configuration before any checkout or index access.
# Names only: values may contain private paths or configuration.
for git_env in ${!GIT_@}; do
    case "$git_env" in
        GIT_PAGER|GIT_TERMINAL_PROMPT) continue ;;
        *) ;;
    esac
    printf 'stack tool: refusing inherited Git environment: %s\n' "$git_env" >&2
    exit 2
done
if [ "$(git rev-parse --show-toplevel)" != "$ROOT" ]; then
    echo 'stack tool: Git worktree does not match the script root' >&2
    exit 2
fi
fail() { printf 'stack-build: %s\n' "$*" >&2; exit 2; }

selftest() (
    bash "$ROOT/tools/scripts/stack_git_environment_test.sh"
    local tmp script="$ROOT/tools/scripts/stack_build.sh" key value path
    local -a settings=()
    # Reuse public configuration, never create signing keys or trust settings.
    for key in user.name user.email user.signingkey gpg.format gpg.ssh.program gpg.ssh.allowedSignersFile; do
        value="$(git config --get "$key" || true)"
        [ -z "$value" ] || settings+=("$key" "$value")
    done
    [ -x "$ROOT/build/bin/z23-lint" ] || fail 'build build/bin/z23-lint before --selftest'
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-stack-build.XXXXXX")"
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "SELFTEST FAIL exit=$rc" >&2; [ ! -f "$tmp/err" ] || cat "$tmp/err" >&2; fi; rm -rf "$tmp"' EXIT
    unset GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
    mkdir -p "$tmp/tools/scripts" "$tmp/tools/dev" "$tmp/build/bin" "$tmp/tools/lint" "$tmp/contexts/commons/packages/fixture"
    cp "$script" "$tmp/tools/scripts/stack_build.sh"
    cp "$ROOT/tools/dev/checkout-lock.sh" "$tmp/tools/dev/checkout-lock.sh"
    cp "$ROOT/build/bin/z23-lint" "$tmp/build/bin/z23-lint"
    git -C "$tmp" init -q
    while [ "${#settings[@]}" -gt 0 ]; do
        git -C "$tmp" config "${settings[0]}" "${settings[1]}"
        settings=("${settings[@]:2}")
    done
    printf '/build/\n/out\n/err\n/trace\n/refresh-fail\n' > "$tmp/.gitignore"
    printf 'base\n' > "$tmp/shared"
    printf 'int fixture(int x) { return x; }\n' > "$tmp/fixture.c"
    : > "$tmp/tools/lint/cyclomatic_complexity_baseline.txt"
    cat > "$tmp/Makefile" <<'FIXTURE'
.PHONY: build/bin/z23-lint
build/bin/z23-lint:
	@test -x build/bin/z23-lint
	@echo build >> trace
FIXTURE
    cat > "$tmp/tools/scripts/stack_tip_refresh.sh" <<'FIXTURE'
set -eu
echo refresh >> trace
[ ! -f refresh-fail ] || exit 9
FIXTURE
    git -C "$tmp" add .
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture base'
    local base good empty conflict complex later merge branch refs before after rc
    base="$(git -C "$tmp" rev-parse HEAD)"
    branch="$(git -C "$tmp" symbolic-ref HEAD)"
    printf 'accepted\n' > "$tmp/shared"
    git -C "$tmp" add shared
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture accepted'
    good="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" -c commit.gpgSign=false commit --allow-empty -qm 'Fixture empty'
    empty="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" checkout -q --detach "$base"
    printf 'conflicting\n' > "$tmp/shared"
    git -C "$tmp" add shared
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture conflict'
    conflict="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" checkout -q --detach "$good"
    { printf 'int fixture(int x) {\n'; for path in {1..16}; do printf 'if (x == %s) x++;\n' "$path"; done; printf 'return x; }\n'; } > "$tmp/fixture.c"
    git -C "$tmp" add fixture.c
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture over cap'
    complex="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" checkout -q --detach "$good"
    printf 'later\n' > "$tmp/later"
    git -C "$tmp" add later
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture later'
    later="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" -c commit.gpgSign=false merge -q --no-ff -s ours "$conflict" -m 'Fixture merge'
    merge="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" checkout -q "${branch#refs/heads/}"
    refs="$(git -C "$tmp" show-ref)"
    local -a cli=(bash "$tmp/tools/scripts/stack_build.sh")
    fixture_state() {
        local file
        git -C "$tmp" status --porcelain=v1
        git -C "$tmp" ls-files --stage
        git -C "$tmp" show-ref
        git -C "$tmp" rev-parse HEAD
        git -C "$tmp" hash-object --no-filters -- "$tmp/trace"
        for file in shared new contexts/commons/packages/fixture/zcode-package.json; do
            if [ -f "$tmp/$file" ]; then git -C "$tmp" hash-object --no-filters -- "$tmp/$file"
            else printf 'missing:%s\n' "$file"; fi
        done
    }
    "${cli[@]}" "$base" "$good" "$empty" "$conflict" "$complex" "$merge" "$later" > "$tmp/out" 2> "$tmp/err"
    [ "$(wc -l < "$tmp/out")" -eq 7 ]
    [ "$(grep -c '^PICKED ' "$tmp/out")" -eq 2 ]
    for path in empty conflict complexity merge; do grep -q "^SKIPPED $path input=" "$tmp/out"; done
    grep -q "^PICKED .* input=$good$" "$tmp/out"
    grep -q "^PICKED .* input=$later$" "$tmp/out"
    after="$(git -C "$tmp" rev-parse HEAD)"
    grep -qx "TIP $after" "$tmp/out"
    [ "$(git -C "$tmp" show-ref)" = "$refs" ]
    [ "$(git -C "$tmp" rev-list --count "$base..HEAD")" -eq 2 ]
    [ "$(git -C "$tmp" log --format=%G? "$base..HEAD" | sort -u)" = G ]
    grep -qx accepted "$tmp/shared"
    grep -qx later "$tmp/later"
    grep -qx 'int fixture(int x) { return x; }' "$tmp/fixture.c"
    [ "$(grep -c '^refresh$' "$tmp/trace")" -eq 1 ]
    [ -z "$(git -C "$tmp" status --porcelain=v1)" ]
    echo 'SELFTEST PASS: signed picks, empty/conflict/merge/real-complexity skips, later continuation, refs, refresh'
    # All refusal inputs preserve state and do not call the helper or refresh.
    for path in staged unstaged deleted untracked ignored-manifest; do
        case "$path" in
            staged) printf 'dirty\n' > "$tmp/shared"; git -C "$tmp" add shared ;;
            unstaged) printf 'dirty\n' > "$tmp/shared" ;;
            deleted) rm "$tmp/shared" ;;
            untracked) printf 'dirty\n' > "$tmp/new" ;;
            ignored-manifest) printf 'contexts/commons/packages/*/zcode-package.json\n' >> "$tmp/.git/info/exclude"; printf 'ignored\n' > "$tmp/contexts/commons/packages/fixture/zcode-package.json" ;;
        esac
        before="$(fixture_state)"
        rc=0
        "${cli[@]}" "$base" "$later" > "$tmp/out" 2> "$tmp/err" || rc=$?
        [ "$rc" -eq 2 ]
        [ ! -s "$tmp/out" ]
        [ "$before" = "$(fixture_state)" ]
        git -C "$tmp" restore --source=HEAD --staged --worktree -- shared
        rm -f "$tmp/new" "$tmp/contexts/commons/packages/fixture/zcode-package.json"
    done
    : > "$tmp/.git/info/exclude"
    echo 'SELFTEST PASS: dirty inputs refuse before effects'
    # A clean-index interrupted empty cherry-pick is still an owned operation.
    git -C "$tmp" -c commit.gpgSign=false cherry-pick "$empty" > "$tmp/err" 2>&1 || true
    git -C "$tmp" rev-parse --verify CHERRY_PICK_HEAD >/dev/null
    before="$(git -C "$tmp" rev-parse HEAD; git -C "$tmp" hash-object --no-filters -- "$tmp/trace")"
    rc=0
    "${cli[@]}" "$base" "$good" > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 2 ]
        [ ! -s "$tmp/out" ]
    [ "$before" = "$(git -C "$tmp" rev-parse HEAD; git -C "$tmp" hash-object --no-filters -- "$tmp/trace")" ]
    git -C "$tmp" rev-parse --verify CHERRY_PICK_HEAD >/dev/null
    git -C "$tmp" cherry-pick --abort
    echo 'SELFTEST PASS: existing Git operation preserved'
    before="$(git -C "$tmp" rev-parse HEAD)"
    rc=0
    "${cli[@]}" "$base" nonexistent-commit > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 2 ]
    [ ! -s "$tmp/out" ]
    [ "$before" = "$(git -C "$tmp" rev-parse HEAD)" ]
    touch "$tmp/refresh-fail"
    rc=0
    "${cli[@]}" "$base" "$good" > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 9 ]
    if grep -q '^TIP ' "$tmp/out"; then return 1; fi
    [ "$(git -C "$tmp" show-ref)" = "$refs" ]
    echo 'SELFTEST PASS: invalid input zero effects, refresh failure preserved without success tip'
    rm "$tmp/refresh-fail"
    before="$(grep -c '^refresh$' "$tmp/trace")"
    rc=0
    "${cli[@]}" "$complex" "$merge" > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 2 ]
    if grep -q '^TIP ' "$tmp/out"; then return 1; fi
    [ "$before" = "$(grep -c '^refresh$' "$tmp/trace")" ]
    "${cli[@]}" "$base" "$merge" > "$tmp/out" 2> "$tmp/err"
    grep -qx "TIP $base" "$tmp/out"
    [ "$(wc -l < "$tmp/out")" -eq 2 ]
    echo 'SELFTEST PASS: all-skipped base must pass complexity before refresh/TIP'
    "${cli[@]}" "$base" "$good" "$good" > "$tmp/out" 2> "$tmp/err"
    grep -qx "SKIPPED empty input=$good" "$tmp/out"
    [ "$(wc -l < "$tmp/out")" -eq 3 ]
    [ "$(git -C "$tmp" rev-list --count "$base..HEAD")" -eq 1 ]
    [ "$(git -C "$tmp" show-ref)" = "$refs" ]
    echo 'SELFTEST PASS: duplicate nonempty pick becomes empty without replay'
    # Fixture-only checker overrides must never qualify the selected tree.
    local override
    override="$(mktemp -d "$tmp/build/override.XXXXXX")"
    printf 'int unrelated(int x) { return x; }\n' > "$override/fixture.c"
    : > "$override/baseline"
    ZCL_CYCLOMATIC_ROOT="$override" ZCL_CYCLOMATIC_BASELINE="$override/baseline" \
        "${cli[@]}" "$base" "$complex" > "$tmp/out" 2> "$tmp/err"
    grep -qx "SKIPPED complexity input=$complex" "$tmp/out"
    grep -qx "TIP $base" "$tmp/out"
    grep -qx 'int fixture(int x) { return x; }' "$tmp/fixture.c"
    [ "$(git -C "$tmp" rev-parse HEAD)" = "$base" ]
    before="$(grep -c '^refresh$' "$tmp/trace")"
    rc=0
    ZCL_CYCLOMATIC_ROOT="$override" ZCL_CYCLOMATIC_BASELINE="$override/baseline" \
        "${cli[@]}" "$complex" "$merge" > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 2 ]
    if grep -q '^TIP ' "$tmp/out"; then return 1; fi
    [ "$before" = "$(grep -c '^refresh$' "$tmp/trace")" ]
    echo 'SELFTEST PASS: inherited checker overrides cannot admit pick or failing base'
    # The refresh implementation belongs to the starting tool, not BASE.
    git -C "$tmp" checkout -q --detach "$base"
    git -C "$tmp" rm -q tools/scripts/stack_tip_refresh.sh
    git -C "$tmp" -c commit.gpgSign=false commit -qm 'Fixture base without refresh'
    local nohelper
    nohelper="$(git -C "$tmp" rev-parse HEAD)"
    git -C "$tmp" checkout -q --detach "$base"
    before="$(grep -c '^refresh$' "$tmp/trace")"
    "${cli[@]}" "$nohelper" "$merge" > "$tmp/out" 2> "$tmp/err"
    grep -qx "TIP $nohelper" "$tmp/out"
    [ "$(grep -c '^refresh$' "$tmp/trace")" -eq "$((before + 1))" ]
    [ ! -e "$tmp/tools/scripts/stack_tip_refresh.sh" ]
    [ -z "$(git -C "$tmp" status --porcelain=v1)" ]
    git -C "$tmp" checkout -q --detach "$base"
    echo 'SELFTEST PASS: retained refresh runs after selecting base without helper'
    # Fixture-only broken signer: preserve staged input, never label it empty.
    git -C "$tmp" config gpg.ssh.program false
    git -C "$tmp" config gpg.program false
    rc=0
    "${cli[@]}" "$base" "$good" > "$tmp/out" 2> "$tmp/err" || rc=$?
    [ "$rc" -eq 2 ]
        [ ! -s "$tmp/out" ]
    if git -C "$tmp" diff --cached --quiet; then return 1; fi
    [ "$(git -C "$tmp" show-ref)" = "$refs" ]
    echo 'SELFTEST PASS: signing failure stops with staged state, no skip/fallback'
)

if [ "${1:-}" = --selftest ]; then
    [ "$#" -eq 1 ] || fail 'usage: stack_build.sh --selftest'
    selftest
    exit 0
fi
build_stack() {
    [ "$#" -ge 2 ] || fail 'usage: stack_build.sh BASE COMMIT...'
    git rev-parse --is-inside-work-tree >/dev/null || fail 'a Git checkout is required'
    if [ "${ZCL_CHECKOUT_LOCK_HELD:-0}" != 1 ]; then
        exec bash tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
            bash "$ROOT/tools/scripts/stack_build.sh" "$@"
    fi
    local dirty state manifest base c before rc log scratch refresh_source
    local -a commits=() parents=()
    dirty="$(git status --porcelain=v1 --untracked-files=all)" || fail 'cannot inspect cleanliness'
    [ -z "$dirty" ] || fail 'refusing dirty checkout; preserve and resolve owned work first'
    for manifest in contexts/commons/packages/*/zcode-package.json; do
        [ -f "$manifest" ] || continue
        git ls-files --error-unmatch -- "$manifest" >/dev/null 2>&1 || fail 'refusing ignored untracked package manifest'
    done
    for state in CHERRY_PICK_HEAD MERGE_HEAD REVERT_HEAD rebase-apply rebase-merge sequencer; do
        [ ! -e "$(git rev-parse --git-path "$state")" ] || fail "refusing existing Git operation: $state"
    done
    [ "${ZCL_LINT_MODE:-RATCHET}" = RATCHET ] || fail 'complexity filtering requires RATCHET mode'
    # Fixture overrides must not change the source or pins being qualified.
    unset ZCL_CYCLOMATIC_ROOT ZCL_CYCLOMATIC_BASELINE
    base="$(git rev-parse --verify --end-of-options "$1^{commit}" 2>/dev/null)" || fail 'invalid base commit'
    shift
    for c in "$@"; do
        c="$(git rev-parse --verify --end-of-options "$c^{commit}" 2>/dev/null)" || fail 'invalid input commit'
        commits+=("$c")
    done
    # Keep the starting tool's helper even when BASE removes its pathname.
    refresh_source="$(cat "$ROOT/tools/scripts/stack_tip_refresh.sh")" || fail 'cannot retain refresh implementation'
    [ -n "$refresh_source" ] || fail 'empty refresh implementation'
    mkdir -p build/handoff/stack-build
    scratch="$(mktemp -d build/handoff/stack-build/run.XXXXXX)"
    printf 'stack-build: receipts %s\n' "$scratch" >&2
    # Only HEAD is detached/moved; existing branch and published refs stay put.
    git checkout --quiet --no-overwrite-ignore --detach "$base" >&2
    make --no-print-directory -j"$(getconf _NPROCESSORS_ONLN)" build/bin/z23-lint > "$scratch/build.log" 2>&1 || {
        cat "$scratch/build.log" >&2; fail 'cannot build base complexity checker';
    }
    [ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || fail 'checker build changed source; inspect its outputs before continuing'
    build/bin/z23-lint check-cyclomatic-complexity --selftest > "$scratch/checker-selftest.log" 2>&1 || {
        cat "$scratch/checker-selftest.log" >&2; fail 'base complexity checker selftest failed';
    }
    for c in "${commits[@]}"; do
        read -r -a parents <<< "$(git rev-list --parents -n 1 "$c")"
        if [ "${#parents[@]}" -gt 2 ]; then
            printf 'SKIPPED merge input=%s\n' "$c"
            continue
        fi
        before="$(git rev-parse HEAD)"
        log="$scratch/$c.pick.log"
        rc=0
        git cherry-pick -S "$c" > "$log" 2>&1 || rc=$?
        if [ "$rc" -ne 0 ]; then
            if [ -n "$(git ls-files --unmerged)" ]; then
                cat "$log" >&2
                git cherry-pick --abort >&2
                printf 'SKIPPED conflict input=%s\n' "$c"
                continue
            fi
            if git rev-parse --verify -q CHERRY_PICK_HEAD >/dev/null &&
                git diff --quiet && git diff --cached --quiet &&
                [ "$(git rev-parse HEAD)" = "$before" ]; then
                git cherry-pick --abort >&2
                printf 'SKIPPED empty input=%s\n' "$c"
                continue
            fi
            cat "$log" >&2
            fail 'cherry-pick failed outside conflict/empty cases; preserve its state'
        fi
        rc=0
        build/bin/z23-lint check-cyclomatic-complexity > "$scratch/$c.complexity.log" 2>&1 || rc=$?
        [ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || fail 'complexity checker changed source; preserve its outputs'
        if [ "$rc" -eq 1 ]; then
            cat "$scratch/$c.complexity.log" >&2
            git checkout --quiet --no-overwrite-ignore --detach "$before" >&2
            printf 'SKIPPED complexity input=%s\n' "$c"
        elif [ "$rc" -ne 0 ]; then
            cat "$scratch/$c.complexity.log" >&2
            fail 'complexity checker unavailable; cannot classify pick'
        else
            printf 'PICKED %s input=%s\n' "$(git rev-parse HEAD)" "$c"
        fi
    done
    # Even a stack with no accepted inputs must not claim a failing base tip.
    if ! build/bin/z23-lint check-cyclomatic-complexity > "$scratch/final-complexity.log" 2>&1; then
        cat "$scratch/final-complexity.log" >&2
        fail 'assembled tip fails complexity; refresh not started'
    fi
    # Refresh owns numeric correction signing and leaves other generated changes
    # for ownership/diff review. Its content display is never a staging list.
    bash -c "$refresh_source" "$ROOT/tools/scripts/stack_tip_refresh.sh" >&2
    printf 'TIP %s\n' "$(git rev-parse HEAD)"
}
build_stack "$@"
