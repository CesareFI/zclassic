#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
#
# Exercises platform/deploy/devbuild (the reference mirror of the installed
# host scheduler, NOT the installed copy) with HOME pointed at a scratch
# directory, so it never touches this host's real locks, queues or
# accounting file. Covers: Z23 lane overlap up to DEVBUILD_Z23_LANES, FIFO
# ordering of --wait waiters, landing priority jumping the queue, QEDC
# lane overlap up to DEVBUILD_QEDC_LANES, per-job JSON accounting, and
# ticket cleanup.
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/devbuild-mirror-test.XXXXXX")
export HOME="$scratch/home"
mkdir -p "$HOME"
state="$HOME/.local/state/development"

pids=()
cleanup() {
    for pid in "${pids[@]}"; do
        [[ -z $pid ]] || wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$scratch"
}
trap cleanup EXIT

now_ns() { date +%s%N; }

# --- 1. Z23 lane overlap: three concurrent lanes, a fourth waits -----------
# Uses interval overlap (not a fixed wall-clock budget) so the assertion
# holds even when the shared host is heavily loaded and systemd-run/cgroup
# setup is slow: what matters is that the three admitted jobs' [start,end)
# intervals share a common instant, and the fourth only starts once one of
# them has ended, not how many wall-clock milliseconds any of that took.
export DEVBUILD_Z23_LANES=3
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 5; date +%s%N > "$1.end"' _ "$scratch/lane1" \
    >"$scratch/lane1.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 5; date +%s%N > "$1.end"' _ "$scratch/lane2" \
    >"$scratch/lane2.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 5; date +%s%N > "$1.end"' _ "$scratch/lane3" \
    >"$scratch/lane3.log" 2>&1 & pids+=("$!")
sleep 0.5
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 0.1; date +%s%N > "$1.end"' _ "$scratch/lane4" \
    >"$scratch/lane4.log" 2>&1 & pids+=("$!")
wait "${pids[@]}"
pids=()
s1=$(<"$scratch/lane1"); s2=$(<"$scratch/lane2"); s3=$(<"$scratch/lane3")
s4=$(<"$scratch/lane4")
e1=$(<"$scratch/lane1.end"); e2=$(<"$scratch/lane2.end"); e3=$(<"$scratch/lane3.end")
max_start=$s1; [[ $s2 -gt $max_start ]] && max_start=$s2; [[ $s3 -gt $max_start ]] && max_start=$s3
min_end=$e1; [[ $e2 -lt $min_end ]] && min_end=$e2; [[ $e3 -lt $min_end ]] && min_end=$e3
(( max_start < min_end )) || {
    printf 'three z23 lanes did not overlap (latest start=%d earliest end=%d)\n' \
        "$max_start" "$min_end" >&2
    exit 1
}
(( s4 >= min_end )) || {
    printf 'fourth z23 job started before any lane freed (s4=%d earliest end=%d)\n' \
        "$s4" "$min_end" >&2
    exit 1
}
printf 'devbuild mirror: three z23 lanes overlap, fourth waits for a lane PASS\n'

# --- 2. FIFO ordering of ordinary waiters on the last free lane ------------
"$root/devbuild" --wait --project z23 sleep 4 >"$scratch/hold1.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 sleep 4 >"$scratch/hold2.log" 2>&1 & pids+=("$!")
sleep 0.5
for tag in A B C D E; do
    "$root/devbuild" --wait --project z23 \
        bash -c 'date +%s%N > "$1"; sleep 0.2' _ "$scratch/fifo-$tag" \
        >"$scratch/fifo-$tag.log" 2>&1 & pids+=("$!")
    sleep 0.3
done
wait "${pids[@]}"
pids=()
prev=0
order_ok=1
for tag in A B C D E; do
    ts=$(<"$scratch/fifo-$tag")
    (( ts > prev )) || order_ok=0
    prev=$ts
done
(( order_ok )) || { printf 'FIFO waiters did not start in enqueue order\n' >&2; exit 1; }
printf 'devbuild mirror: FIFO waiter order PASS\n'

# --- 3. Landing priority jumps ordinary --wait waiters ----------------------
"$root/devbuild" --wait --project z23 sleep 4 >"$scratch/prio-hold1.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 sleep 4 >"$scratch/prio-hold2.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 sleep 4 >"$scratch/prio-hold3.log" 2>&1 & pids+=("$!")
sleep 0.5
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 0.1' _ "$scratch/prio-F" \
    >"$scratch/prio-F.log" 2>&1 & pids+=("$!")
sleep 0.3
"$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 0.1' _ "$scratch/prio-G" \
    >"$scratch/prio-G.log" 2>&1 & pids+=("$!")
sleep 0.3
DEVBUILD_PRIORITY=land "$root/devbuild" --wait --project z23 \
    bash -c 'date +%s%N > "$1"; sleep 0.1' _ "$scratch/prio-land" \
    >"$scratch/prio-land.log" 2>&1 & pids+=("$!")
wait "${pids[@]}"
pids=()
land_ts=$(<"$scratch/prio-land")
f_ts=$(<"$scratch/prio-F")
g_ts=$(<"$scratch/prio-G")
(( land_ts < f_ts && land_ts < g_ts )) || {
    printf 'landing priority job did not jump ordinary waiters (land=%d F=%d G=%d)\n' \
        "$land_ts" "$f_ts" "$g_ts" >&2
    exit 1
}
printf 'devbuild mirror: landing priority jumps queue PASS\n'

# --- 4. QEDC runs DEVBUILD_QEDC_LANES concurrent lanes ----------------------
# Two QEDC jobs launched together should overlap (up to the default 2
# lanes), unlike Z23-style single-slot serialization from before this lane
# count existed. A third job started after should wait for a lane.
"$root/devbuild" --wait --project qedc \
    bash -c 'date +%s%N > "$1"; sleep 1; date +%s%N > "$1.end"' _ "$scratch/qedc1" \
    >"$scratch/qedc1.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project qedc \
    bash -c 'date +%s%N > "$1"; sleep 1; date +%s%N > "$1.end"' _ "$scratch/qedc2" \
    >"$scratch/qedc2.log" 2>&1 & pids+=("$!")
wait "${pids[@]}"
pids=()
qs1=$(<"$scratch/qedc1")
qs2=$(<"$scratch/qedc2")
qe1=$(<"$scratch/qedc1.end")
qe2=$(<"$scratch/qedc2.end")
(( qs2 < qe1 && qs1 < qe2 )) || {
    printf 'qedc jobs did not overlap (start1=%d end1=%d start2=%d end2=%d)\n' \
        "$qs1" "$qe1" "$qs2" "$qe2" >&2
    exit 1
}
printf 'devbuild mirror: QEDC two-lane overlap PASS\n'

# --- 5. Per-job JSON accounting, including rc propagation ------------------
jobs_file="$state/devbuild.jobs.jsonl"
[[ -f $jobs_file ]] || { printf 'accounting file missing: %s\n' "$jobs_file" >&2; exit 1; }
rc=0
"$root/devbuild" --wait --project z23 bash -c 'exit 3' >"$scratch/rc.log" 2>&1 || rc=$?
(( rc == 3 )) || { printf 'devbuild did not propagate rc=3 (got %d)\n' "$rc" >&2; exit 1; }
last_line=$(grep '"pid"' "$jobs_file" | tail -1)
[[ -n $last_line ]] || { printf 'no accounting line found\n' >&2; exit 1; }
[[ $last_line == *'"rc":3'* ]] || { printf 'accounting line missing rc:3: %s\n' "$last_line" >&2; exit 1; }
[[ $last_line == *'"project":"z23"'* ]] || { printf 'accounting line missing project z23: %s\n' "$last_line" >&2; exit 1; }
lane_val=$(printf '%s' "$last_line" | sed -n 's/.*"lane":\([0-9]*\).*/\1/p')
[[ $lane_val =~ ^[0-9]+$ ]] && (( lane_val >= 1 )) || {
    printf 'accounting line has non-positive z23 lane: %s\n' "$last_line" >&2; exit 1;
}
wait_s=$(printf '%s' "$last_line" | sed -n 's/.*"wait_s":\([0-9]*\).*/\1/p')
run_s=$(printf '%s' "$last_line" | sed -n 's/.*"run_s":\([0-9]*\).*/\1/p')
[[ $wait_s =~ ^[0-9]+$ ]] || { printf 'wait_s not an integer: %s\n' "$last_line" >&2; exit 1; }
[[ $run_s =~ ^[0-9]+$ ]] || { printf 'run_s not an integer: %s\n' "$last_line" >&2; exit 1; }
line_count=$(grep -c '"pid"' "$jobs_file")
(( line_count >= 12 )) || {
    printf 'expected at least 12 accounting lines, got %d\n' "$line_count" >&2; exit 1;
}
printf 'devbuild mirror: JSON accounting (rc, lane, wait_s, run_s) PASS\n'

# --- 6. No leftover ticket/priority markers ---------------------------------
leftover=0
for f in "$state/z23.queue"/* "$state/z23.priority"/* "$state/qedc.queue"/*; do
    [[ -e $f ]] && leftover=1
done
(( leftover == 0 )) || { printf 'leftover queue/priority marker files remain\n' >&2; exit 1; }
printf 'devbuild mirror: no leftover ticket or priority files PASS\n'

# --- 7. Killing a running wrapper does not leak its lane lock ---------------
# The memory/CPU sampler is a backgrounded subshell that used to inherit
# copies of the wrapper's lane/heavy-lock file descriptors and loop forever;
# if the wrapper itself was killed (not just its child command), the sampler
# kept those descriptors open and the lane stayed locked. The sampler now
# exits with the wrapper (polls `kill -0` on the wrapper's own pid) and
# explicitly closes fds 4/5/6/8/9, so a killed wrapper's lane frees up.
"$root/devbuild" --wait --project z23 sleep 8 >"$scratch/term1.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 sleep 8 >"$scratch/term2.log" 2>&1 & pids+=("$!")
"$root/devbuild" --wait --project z23 sleep 8 >"$scratch/term3.log" 2>&1 & term3=$!
pids+=("$term3")
for _ in {1..100}; do
    running=0
    for log in "$scratch/term1.log" "$scratch/term2.log" "$scratch/term3.log"; do
        grep -q 'devbuild: z23 lane' "$log" 2>/dev/null && running=$((running + 1))
    done
    (( running == 3 )) && break
    sleep 0.1
done
(( running == 3 )) || { printf 'not all three z23 lane jobs reached running state\n' >&2; exit 1; }
sleep 0.5
kill -TERM "$term3"
lock_freed=0
for _ in {1..100}; do
    grep -qw "$term3" /proc/locks || { lock_freed=1; break; }
    sleep 0.1
done
(( lock_freed )) || {
    printf 'killed wrapper pid %s still holds a lock entry in /proc/locks\n' "$term3" >&2
    exit 1
}
new_rc=0
"$root/devbuild" --project z23 true >"$scratch/term-new.log" 2>&1 || new_rc=$?
(( new_rc == 0 )) || {
    printf 'a new z23 job (no --wait) could not get a lane after the kill (rc=%d): %s\n' \
        "$new_rc" "$(cat "$scratch/term-new.log")" >&2
    exit 1
}
printf 'devbuild mirror: killed wrapper releases its lane, no lock leak PASS\n'

# --- 8. Checkout fingerprint ("tree") accounting ----------------------------
# The wrapper is invoked with cwd inside this git worktree (the repo this
# script lives in), so every job below picks up a real tree_key.
tree_line=$(grep '"pid"' "$jobs_file" | tail -1)
tree_val=$(printf '%s' "$tree_line" | sed -n 's/.*"tree":"\([0-9a-f]*\)".*/\1/p')
[[ $tree_val =~ ^[0-9a-f]{16}$ ]] || {
    printf 'accounting line missing a 16-hex tree key: %s\n' "$tree_line" >&2; exit 1;
}
printf 'devbuild mirror: accounting line carries a 16-hex tree key PASS\n'

# --- 8a. Rerunning the identical command on an unchanged tree notes it -----
same_marker="identical checkout"
"$root/devbuild" --project z23 true tree-fingerprint-probe-marker >"$scratch/tree-first.log" 2>&1
"$root/devbuild" --project z23 true tree-fingerprint-probe-marker >"$scratch/tree-second.log" 2>&1
grep -qF "$same_marker" "$scratch/tree-first.log" && {
    printf 'first run of a never-before-seen command unexpectedly noted a repeat: %s\n' \
        "$(cat "$scratch/tree-first.log")" >&2
    exit 1
}
grep -qF "$same_marker" "$scratch/tree-second.log" || {
    printf 'rerun on an identical checkout did not print the repeat note: %s\n' \
        "$(cat "$scratch/tree-second.log")" >&2
    exit 1
}
printf 'devbuild mirror: identical rerun prints already-PASSED note PASS\n'

# --- 8b. Editing a tracked file changes the tree key and clears the note ---
edited_file="$root/README.md"
[[ -f $edited_file ]] || edited_file="$root/devbuild"
orig_line=$(grep '"tree"' "$jobs_file" | tail -1)
orig_tree=$(printf '%s' "$orig_line" | sed -n 's/.*"tree":"\([0-9a-f]*\)".*/\1/p')
printf '\n# devbuild-mirror-test scratch edit\n' >> "$edited_file"
restore_edit() { git -C "$root" checkout -- "$(basename "$edited_file")" 2>/dev/null || true; }
"$root/devbuild" --project z23 true >"$scratch/tree-edited.log" 2>&1
restore_edit
grep -qF "$same_marker" "$scratch/tree-edited.log" && {
    printf 'edited tree still reported an identical-checkout repeat: %s\n' \
        "$(cat "$scratch/tree-edited.log")" >&2
    exit 1
}
edited_line=$(grep '"tree"' "$jobs_file" | tail -1)
edited_tree=$(printf '%s' "$edited_line" | sed -n 's/.*"tree":"\([0-9a-f]*\)".*/\1/p')
[[ $edited_tree =~ ^[0-9a-f]{16}$ ]] || {
    printf 'accounting line after edit missing a 16-hex tree key: %s\n' "$edited_line" >&2; exit 1;
}
[[ $edited_tree != "$orig_tree" ]] || {
    printf 'tree key did not change after editing a tracked file (still %s)\n' "$orig_tree" >&2
    exit 1
}
printf 'devbuild mirror: editing a tracked file changes the tree key, no stale note PASS\n'

# --- 8c. Per-project CPUWeight: QEDC = 20 * DEVBUILD_Z23_LANES / DEVBUILD_QEDC_LANES, Z23 = 20 ----
weight_probe='cg=$(sed "s#.*/##" /proc/self/cgroup | tail -1); systemctl --user show -p CPUWeight "$cg"'
export DEVBUILD_Z23_LANES=3
export DEVBUILD_QEDC_LANES=2
"$root/devbuild" --wait --project qedc bash -c "$weight_probe" >"$scratch/weight-qedc.log" 2>&1
"$root/devbuild" --wait --project z23 bash -c "$weight_probe" >"$scratch/weight-z23.log" 2>&1
qedc_weight=$(sed -n 's/^CPUWeight=\([0-9]*\)$/\1/p' "$scratch/weight-qedc.log")
z23_weight=$(sed -n 's/^CPUWeight=\([0-9]*\)$/\1/p' "$scratch/weight-z23.log")
[[ $qedc_weight == 30 ]] || {
    printf 'qedc CPUWeight expected 30, got %s: %s\n' "$qedc_weight" "$(cat "$scratch/weight-qedc.log")" >&2
    exit 1
}
[[ $z23_weight == 20 ]] || {
    printf 'z23 CPUWeight expected 20, got %s: %s\n' "$z23_weight" "$(cat "$scratch/weight-z23.log")" >&2
    exit 1
}
printf 'devbuild mirror: per-project CPUWeight (qedc=30, z23=20) PASS\n'
