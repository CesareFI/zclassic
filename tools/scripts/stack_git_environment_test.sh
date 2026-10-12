#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Isolated pre-effect refusal and retained refresh root witnesses.
set -Eeuo pipefail
ROOT="$(CDPATH= cd -P -- "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
for git_env in ${!GIT_@}; do unset "$git_env"; done
tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-stack-git-env.XXXXXX")"
tmp="$(CDPATH= cd -P -- "$tmp" && pwd -P)"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "Git environment test FAILED exit=$rc" >&2; cat "$tmp/output" >&2 2>/dev/null || true; fi; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/a/tools/scripts" "$tmp/a/tools/dev" "$tmp/a/tools/lint"
cp "$ROOT/tools/scripts/stack_build.sh" "$ROOT/tools/scripts/stack_tip_refresh.sh" "$tmp/a/tools/scripts/"
cp "$ROOT/tools/dev/checkout-lock.sh" "$tmp/a/tools/dev/"
printf '/build/\n' > "$tmp/a/.gitignore"
printf 'int fixture(int x) { return x; }\n' > "$tmp/a/fixture.c"
: > "$tmp/a/tools/lint/cyclomatic_complexity_baseline.txt"
cat > "$tmp/a/tools/scripts/zcode_registry_rederive.sh" <<'FIXTURE'
set -eu
printf 'registry-root=%s\n' "$PWD"
exit 7
FIXTURE
git -C "$tmp/a" init -q
git -C "$tmp/a" -c user.name=Fixture -c user.email=fixture@invalid add .
git -C "$tmp/a" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit -qm base
base="$(git -C "$tmp/a" rev-parse HEAD)"
git clone -q --no-hardlinks "$tmp/a" "$tmp/b"
{ printf 'int fixture(int x) {\n'; for i in {1..20}; do printf 'if(x==%s) x++;\n' "$i"; done; printf 'return x; }\n'; } > "$tmp/b/fixture.c"
printf 'fixture.c:fixture:21\n' > "$tmp/b/tools/lint/cyclomatic_complexity_baseline.txt"
git -C "$tmp/b" add .
git -C "$tmp/b" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit -qm 'different source and pins'
pick="$(git -C "$tmp/b" rev-parse HEAD)"
git -C "$tmp/a" fetch -q "$tmp/b" HEAD
cp "$tmp/b/.git/index" "$tmp/alternate-index"
state() {
    local repo
    for repo in "$tmp/a" "$tmp/b"; do
        git -C "$repo" rev-parse HEAD
        git -C "$repo" status --porcelain=v1 --untracked-files=all
        git -C "$repo" ls-files --stage
        git -C "$repo" show-ref
        sha256sum "$repo/.git/HEAD" "$repo/.git/index" "$repo/fixture.c" "$repo/tools/lint/cyclomatic_complexity_baseline.txt"
    done
    sha256sum "$tmp/alternate-index"
}
retained="$(cat "$tmp/a/tools/scripts/stack_tip_refresh.sh")"
for entry in stack refresh retained; do
    case "$entry" in
        stack) cli=(bash "$tmp/a/tools/scripts/stack_build.sh" "$base" "$pick");;
        refresh) cli=(bash "$tmp/a/tools/scripts/stack_tip_refresh.sh" --check);;
        retained) cli=(bash -c "$retained" "$tmp/a/tools/scripts/stack_tip_refresh.sh" --check);;
    esac
    for selector in GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG GIT_CEILING_DIRECTORIES GIT_LITERAL_PATHSPECS; do
        case "$selector" in
            GIT_DIR|GIT_COMMON_DIR) value="$tmp/b/.git";;
            GIT_WORK_TREE) value="$tmp/b";;
            GIT_INDEX_FILE) value="$tmp/alternate-index";;
            GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES) value="$tmp/b/.git/objects";;
            GIT_CONFIG_COUNT) value=1;;
            GIT_CONFIG_PARAMETERS) value="'core.worktree'='$tmp/b'";;
            GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG) value="$tmp/b/.git/config";;
            GIT_CEILING_DIRECTORIES) value="$tmp";;
            GIT_LITERAL_PATHSPECS) value=1;;
        esac
        before="$(state)"
        rc=0
        # Include a complete valid redirection for routing/config-count cases.
        case "$selector" in
            GIT_DIR) env GIT_DIR="$value" GIT_WORK_TREE="$tmp/b" "${cli[@]}" > "$tmp/output" 2>&1 || rc=$?;;
            GIT_CONFIG_COUNT) env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.worktree GIT_CONFIG_VALUE_0="$tmp/b" "${cli[@]}" > "$tmp/output" 2>&1 || rc=$?;;
            *) env "$selector=$value" "${cli[@]}" > "$tmp/output" 2>&1 || rc=$?;;
        esac
        [ "$rc" -eq 2 ]
        grep -Fxq "stack tool: refusing inherited Git environment: $selector" "$tmp/output"
        [ "$before" = "$(state)" ]
        printf 'PASS %s %s: exit=2, exact refusal, A/B HEAD/index/refs/source/pins unchanged\n' "$entry" "$selector"
    done
done
# On-disk core.worktree can redirect Git too; refuse the physical-root mismatch.
git -C "$tmp/a" config core.worktree "$tmp/b"
for entry in stack refresh; do
    before="$(state)"
    rc=0
    if [ "$entry" = stack ]; then
        bash "$tmp/a/tools/scripts/stack_build.sh" "$base" "$pick" > "$tmp/output" 2>&1 || rc=$?
    else
        bash "$tmp/a/tools/scripts/stack_tip_refresh.sh" --check > "$tmp/output" 2>&1 || rc=$?
    fi
    [ "$rc" -eq 2 ]
    grep -Fxq 'stack tool: Git worktree does not match the script root' "$tmp/output"
    [ "$before" = "$(state)" ]
    printf 'PASS %s on-disk worktree mismatch: exit=2\n' "$entry"
done
git --git-dir="$tmp/a/.git" config --unset core.worktree
# A checkout alias is the same physical tree, for absolute and relative entry
# paths. Exercise every entry independently so either root fix is necessary.
ln -s "$tmp/a" "$tmp/link"
alias_failed=0
for entry in stack refresh retained; do
    for spelling in absolute relative; do
        if [ "$spelling" = absolute ]; then entry_root="$tmp/link"; else entry_root=link; fi
        case "$entry" in
            stack) cli=(bash "$entry_root/tools/scripts/stack_build.sh"); expected_rc=2; expected='stack-build: usage: stack_build.sh BASE COMMIT...' ;;
            refresh) cli=(bash "$entry_root/tools/scripts/stack_tip_refresh.sh" --check); expected_rc=7; expected="registry-root=$tmp/a" ;;
            retained) cli=(bash -c "$retained" "$entry_root/tools/scripts/stack_tip_refresh.sh" --check); expected_rc=7; expected="registry-root=$tmp/a" ;;
        esac
        before="$(state)"
        rc=0
        (cd "$tmp"; ZCL_CHECKOUT_LOCK_HELD=1 "${cli[@]}") > "$tmp/output" 2>&1 || rc=$?
        if [ "$rc" -eq "$expected_rc" ] && grep -Fxq "$expected" "$tmp/output" && [ "$before" = "$(state)" ]; then
            printf 'PASS %s %s alias: physical root accepted, no recorded state changes\n' "$entry" "$spelling"
        else
            printf 'FAIL %s %s alias: expected exit=%s and %s, got exit=%s\n' "$entry" "$spelling" "$expected_rc" "$expected" "$rc" >&2
            alias_failed=1
        fi
    done
done
[ "$alias_failed" -eq 0 ]
# Real retained source must resolve argv[0] back to A and reach A's generator.
before="$(state)"
rc=0
ZCL_CHECKOUT_LOCK_HELD=1 bash -c "$retained" "$tmp/a/tools/scripts/stack_tip_refresh.sh" --check > "$tmp/output" 2>&1 || rc=$?
[ "$rc" -eq 7 ]
grep -Fxq "registry-root=$tmp/a" "$tmp/output"
[ "$before" = "$(state)" ]
printf 'PASS real retained refresh: argv[0] root=A, fixture generator exit=7, no state changes\n'
echo 'stack Git environment: SELFTEST PASS'
