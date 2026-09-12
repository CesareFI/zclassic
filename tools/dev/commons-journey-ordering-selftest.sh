#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Executable regression for tools/dev/commons_journey_acceptance.sh ordering.
#
# A peer-dependent wait must never run before the peers it depends on have
# been started and their connections attempted. A node with no peer cannot
# leave finding_peers and its build worker cannot admit work, so asking
# before then is waiting on work the harness itself has not done yet: the
# wait burns its whole budget and dies, every run, for a reason that has
# nothing to do with the product.
#
# This is a STATIC check of the script's control flow. It starts no nodes and
# proves no runtime behaviour: a fixture may test harness ordering, it cannot
# substitute for real acceptance.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOURNEY="$SELF_DIR/commons_journey_acceptance.sh"
FAIL=0

fail() { printf 'commons-journey-ordering: FAIL: %s\n' "$*" >&2; FAIL=1; }
pass() { printf 'commons-journey-ordering: ok: %s\n' "$*"; }

[ -r "$JOURNEY" ] || { fail "cannot read $JOURNEY"; exit 2; }

# The function body under test, from `cj_overlay() {` to its closing brace.
overlay="$(awk '/^cj_overlay\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
[ -n "$overlay" ] || { fail "cj_overlay() not found"; exit 2; }

# Guard the guard: a body that no longer contains the steps this reasons
# about means the check has stopped checking, not that ordering is fine.
for needle in 'dht_spawn DHT_PGID_B' 'dht_spawn DHT_PGID_A' \
              'cj_connect_authenticated'; do
    grep -qF -- "$needle" <<<"$overlay" ||
        { fail "cj_overlay no longer contains '$needle'; this selftest is blind"; exit 2; }
done

line_of() { printf '%s\n' "$overlay" | grep -nF -- "$1" | head -1 | cut -d: -f1; }

spawn_b="$(line_of 'dht_spawn DHT_PGID_B')"
spawn_a="$(line_of 'dht_spawn DHT_PGID_A')"
connect="$(line_of 'cj_connect_authenticated')"

# Every wait that can only be satisfied by a peer.
peer_dependent_waits='cj_wait_worker_admits dht_wait_sync_live dht_wait_connected'

for w in $peer_dependent_waits; do
    at="$(printf '%s\n' "$overlay" | grep -nF -- "$w" | head -1 | cut -d: -f1 || true)"
    [ -n "$at" ] || continue
    if [ "$at" -lt "$spawn_b" ] || [ "$at" -lt "$spawn_a" ]; then
        fail "$w at body line $at runs before a node is started (B=$spawn_b A=$spawn_a)"
    elif [ "$at" -lt "$connect" ]; then
        fail "$w at body line $at runs before cj_connect_authenticated ($connect)"
    else
        pass "$w waits only after both nodes are up and connected"
    fi
done

# The readiness assertion must still exist and still fail closed. Deleting it
# would "fix" the ordering by removing the check.
grep -qF 'cj_wait_worker_admits' <<<"$overlay" ||
    fail "the build-worker readiness assertion was removed, not reordered"
grep -qF 'cj_die' <<<"$overlay" ||
    fail "cj_overlay no longer fails closed on a readiness timeout"

# The shared catch-up helper must not be retargeted at node B: its other
# callers deliberately accept blocks_download for the dialing node.
if grep -q 'dht_wait_sync_live[^|]*DHT_DD_B' <<<"$overlay"; then
    fail "dht_wait_sync_live was pointed at node B; it accepts catch-up states"
fi
pass "shared catch-up helper not repurposed for the build-worker node"
for mapping in 'peer_a="$CJ_PEER_ADDR_B:$B_PORT"' \
               'peer_b="$CJ_PEER_ADDR_A:$A_PORT"' \
               '"$A_HTTPS" "$peer_a"' '"$B_HTTPS" "$peer_b"'; do
    grep -qF "$mapping" <<<"$overlay" ||
        fail "two-host overlay lost a valid static launch target: $mapping"
done
pass "two-host overlay declares both static peer targets"

# Two-host latecomer C shares the requester's IP. Preserve the native
# same-IP rule by making the bootstrap peer and later route switch explicit.
# These are control-flow assertions only; the actual two-host run must still
# prove synchronization, publisher exit, and exact survivor-only delivery.
boot_c="$(awk '/^cj_boot_c\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
survival="$(awk '/^cj_journey_publisher_disappears\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
stop_a="$(awk '/^cj_stop_publisher\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
grep -qF 'bootstrap="127.0.0.1:$A_PORT"' <<<"$boot_c" ||
    fail "two-host latecomer lost its explicit requester bootstrap"
grep -qF '"$C_HTTPS" "$bootstrap"' <<<"$boot_c" ||
    fail "latecomer spawn ignores its declared bootstrap route"
grep -qF 'intervention=latecomer-bootstrap-via-requester' <<<"$boot_c" ||
    fail "latecomer bootstrap intervention is no longer recorded"
grep -qF 'node A still answers RPC after its disappearance' <<<"$stop_a" ||
    fail "publisher exit lost its RPC-down assertion"

survival_line() { printf '%s\n' "$survival" | grep -nF -- "$1" | head -1 | cut -d: -f1; }
delegate_c="$(survival_line 'del_c="$(cj_c zcode network delegate' || true)"
empty_c="$(survival_line '    cj_require_latecomer_empty' || true)"
stop_publisher="$(survival_line '        cj_stop_publisher' || true)"
restart_c="$(survival_line 'dht_spawn DHT_PGID_C' || true)"
if [ -z "$delegate_c" ] || [ -z "$empty_c" ] || [ -z "$stop_publisher" ] || [ -z "$restart_c" ]; then
    fail "latecomer phase ordering check lost a required operation"
elif [ "$delegate_c" -ge "$empty_c" ] || [ "$empty_c" -ge "$stop_publisher" ] || [ "$stop_publisher" -ge "$restart_c" ]; then
    fail "two-host publisher must exit after delegation and before survivor redial"
else
    pass "two-host latecomer changes peer only after anchored delegation and publisher exit"
fi
grep -qF 'intervention=latecomer-restart-toward-survivor-after-requester-exit' <<<"$survival" ||
    fail "latecomer route-switch intervention is no longer recorded"
grep -qF '[ "$CJ_TWOHOST" = 1 ] || cj_stop_publisher' <<<"$survival" ||
    fail "other topologies lost their publisher-stop operation"

[ "$FAIL" -eq 0 ] || exit 1
printf 'commons-journey-ordering: OK\n'
