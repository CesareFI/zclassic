#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Keep an armed checkout's installed hooks in step with a rebuilt hook binary.
#
# Runs after the z23-git-hook rule rebuilds the binary. When THIS worktree's
# own scope already sets core.hooksPath to build/githooks, the installer is
# re-run so the gate's byte comparison keeps holding. An unarmed checkout, a
# checkout armed through the shared config, or a non-Git tree is left alone:
# this script never arms anything and never writes another worktree's config.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="${ZCL_GIT_HOOK_SOURCE_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ROOT="${ZCL_GIT_HOOK_ROOT:-$SOURCE_ROOT}"
NATIVE_BIN="${ZCL_GIT_HOOK_NATIVE_BIN:-$ROOT/build/bin/z23-git-hook}"
INSTALLED="$ROOT/build/githooks/z23-git-hook"

git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || exit 0
[[ "$(git -C "$ROOT" config --get extensions.worktreeConfig 2>/dev/null)" \
    == "true" ]] || exit 0
[[ "$(git -C "$ROOT" config --worktree --get core.hooksPath 2>/dev/null)" \
    == "build/githooks" ]] || exit 0
[[ -x "$NATIVE_BIN" && -f "$INSTALLED" ]] || exit 0
cmp -s "$NATIVE_BIN" "$INSTALLED" && exit 0

if ! out="$(ZCL_GIT_HOOK_SOURCE_ROOT="$SOURCE_ROOT" ZCL_GIT_HOOK_ROOT="$ROOT" \
        ZCL_GIT_HOOK_NATIVE_BIN="$NATIVE_BIN" \
        "$SCRIPT_DIR/install_git_hooks.sh" 2>&1)"; then
    printf '%s\n' "refresh_git_hooks_if_armed: install failed (non-fatal):" "$out" >&2
    exit 0
fi
printf '%s\n' "refreshed installed git hooks (armed checkout, rebuilt hook binary)"
