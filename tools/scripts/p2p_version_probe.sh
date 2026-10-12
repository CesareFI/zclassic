#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# p2p_version_probe.sh — one bounded P2P version handshake against a named
# peer, reporting the start_height it advertises.
#
# Used by tools/scripts/cold_start_to_tip_stopwatch.sh as the PRE-FLIGHT peer
# gate. The measured defect: a silent or stale named peer let the C3 stopwatch
# run its full 600 s budget and label the result "stalled-named", which reads
# as a node sync regression when no node code ran against a serving peer at
# all. A TCP connect (the old precheck) proves only that something listens.
#
# Wire exchange (client side only, read-only against the peer): send one
# `version` message, then read framed messages until the peer's `version`
# arrives (a peer may send other messages first, bounded at 8). No verack,
# no further traffic; the socket is closed on exit.
#
# Usage: p2p_version_probe.sh HOST PORT [BUDGET_SECS]      (default budget 12)
#   env ZCL_CS_PEER_MAGIC  4-byte network magic as 8 hex chars (default 24e92764,
#                      ZClassic mainnet — core/chainparams/src/chainparams.c)
# stdout (one line) and exit code:
#   ok START_HEIGHT        rc 0  peer completed the version exchange
#   peer_unreachable       rc 3  TCP connect refused/failed/timed out
#   peer_no_handshake      rc 4  connected, but no valid version came back
#                                (closed at once, silent, wrong magic, junk)
#   usage                  rc 2
set -u

host="${1:-}"; port="${2:-}"; budget="${3:-12}"
magic="${ZCL_CS_PEER_MAGIC:-24e92764}"
[ -n "$host" ] && [ -n "$port" ] || { echo usage; exit 2; }
case "$port$budget" in *[!0-9]*|'') echo usage; exit 2 ;; esac
case "$magic" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) echo usage; exit 2 ;; esac

command -v sha256sum >/dev/null 2>&1 || { echo peer_no_handshake; exit 4; }

# Re-exec under timeout so the whole probe (connect, write, every read) is
# hard-bounded; 124 means the peer never produced a version in the window.
if [ -z "${P2P_PROBE_INNER:-}" ]; then
    P2P_PROBE_INNER=1 timeout "$budget" bash "${BASH_SOURCE[0]}" "$host" "$port" "$budget"
    rc=$?
    [ "$rc" -eq 124 ] && { echo peer_no_handshake; exit 4; }
    exit "$rc"
fi

le() {  # le <value> <bytes> -> little-endian hex
    local v="$1" n="$2" out="" i
    for ((i = 0; i < n; i++)); do
        out+="$(printf '%02x' $((v & 255)))"
        v=$((v >> 8))
    done
    printf '%s' "$out"
}
tobin() {  # hex -> raw bytes on stdout
    local h="$1" i
    for ((i = 0; i < ${#h}; i += 2)); do
        printf "\\x${h:i:2}"
    done
}
rd() {  # rd <n> -> up to n bytes from fd 3 as hex
    head -c "$1" <&3 | od -An -tx1 -v | tr -d ' \n'
}

zeros26="0000000000000000""00000000000000000000ffff7f000001""0000"
ua="2f7a32332d70656572707265636865636b2f"      # /z23-peerprecheck/
payload="$(le 170011 4)$(le 0 8)$(le "$(date +%s)" 8)${zeros26}${zeros26}"
payload+="$(le $((RANDOM * 32768 + RANDOM)) 8)$(printf '%02x' $((${#ua} / 2)))${ua}$(le 0 4)00"
sum="$(tobin "$payload" | sha256sum | cut -d' ' -f1)"
sum="$(tobin "$sum" | sha256sum | cut -d' ' -f1)"
cmd="76657273696f6e0000000000"                  # "version" padded to 12
msg="${magic}${cmd}$(le $((${#payload} / 2)) 4)${sum:0:8}${payload}"

{ exec 3<>"/dev/tcp/$host/$port"; } 2>/dev/null || { echo peer_unreachable; exit 3; }
trap '' PIPE
tobin "$msg" >&3 2>/dev/null

for _ in 1 2 3 4 5 6 7 8; do
    hdr="$(rd 24)"
    [ "${#hdr}" -eq 48 ] || break
    [ "${hdr:0:8}" = "$magic" ] || break
    len=$((16#${hdr:38:2}${hdr:36:2}${hdr:34:2}${hdr:32:2}))
    [ "$len" -le 65536 ] || break
    body=""
    [ "$len" -eq 0 ] || body="$(rd "$len")"
    [ "${#body}" -eq $((len * 2)) ] || break
    [ "${hdr:8:24}" = "$cmd" ] || continue
    # version(4) services(8) time(8) addr_recv(26) addr_from(26) nonce(8) =
    # 80 bytes, then user_agent varstr (one-byte length below 253), then
    # start_height(4).
    [ "$len" -ge 85 ] || break
    ualen=$((16#${body:160:2}))
    [ "$ualen" -lt 253 ] && [ "$len" -ge $((85 + ualen)) ] || break
    o=$((162 + ualen * 2))
    h="${body:o+6:2}${body:o+4:2}${body:o+2:2}${body:o:2}"
    echo "ok $((16#$h))"
    exit 0
done
echo peer_no_handshake
exit 4
