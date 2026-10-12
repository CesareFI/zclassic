#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# C5 acceptance: "List + sell file via store" OVER TOR. Two isolated regtest
# daemons, BOTH booted with -tor and NEITHER with -externalip, run the full
# store trade with EVERY store leg routed over real Tor circuits:
#
#   A (seller) mints the ZSLP access token on-chain (app.tokens.create plan
#   → commit, buried TOKEN_CONFS blocks so the mint baton confirms), then
#   lists a product with a small file payload (< 64 KiB, inside
#   the dynhost webserver's 65536-byte response cap) via app.store.list-
#   product. B (buyer) runs the new REMOTE buy against A's .onion: the
#   product detail JSON twin, the product page (CSRF + live proof-of-work,
#   solved in-process), and the /store/orders POST all ride the embedded-Tor
#   dynhost client (dynhost_client_fetch_ex — the POST path this slice
#   adds). B pays shielded with the ZCL23ORDER:<id> memo; A's payment
#   processor reconciles the memo, mints the access tokens; B's status poll
#   and /store/access collect ride the onion again, and the collected bytes
#   are SHA3-verified in-process and byte-compared against the fixture here.
#
# The proof that no clearnet store path was used: the store has no clearnet
# listener at all in this topology (the ONLY way B reaches A's /store is the
# onion service), and both tor.log files name the /store traffic — A's log
# the served HTTP POST /store/orders + GET /store/access, B's log the
# dynhost client fetches.
#
# Modelled on tools/dev/market_onion_acceptance.sh: same setsid isolation,
# port refuse-set discipline, wallet-custody recipe, mining cadence, pgid
# cleanup, phase banners, fail-never-skip posture. Public Tor network
# reachability is REQUIRED: if neither node can bootstrap, the script FAILS
# with a named reason — it never silently passes.
#
# Knobs: STO_WAIT (chain/sync gate budget, s), ONI_TOR_WAIT (Tor bootstrap
# + onion address budget, s), ONI_CREDIT_WAIT (seller reconcile + collect
# budget, s), STO_KEEP=1 preserves the scratch tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"

STO_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# Fresh block vs the siblings (market onion: 20040/20041 + 3961x/3962x,
# market: 395xx, dht: 29211-29273, science: 39111-39123, p2p 20022-20027 +
# 18033) and vs this host's zclassic23-live instance (39311/39312). The
# +11966 Tor bootstrap SocksPorts land at 32016/32017 and are asserted too.
A_PORT=20050; A_RPC=39711; A_FS=39712; A_HTTPS=39713
B_PORT=20051; B_RPC=39721; B_FS=39722; B_HTTPS=39723
DEAD_SINK=39997
STO_WAIT="${STO_WAIT:-90}"
ONI_TOR_WAIT="${ONI_TOR_WAIT:-900}"
# The seller's payment processor scans on its own cadence, needs 3
# confirmations, and a first-time ZSLP mint can sit behind projection lag;
# the buyer's polls are real Tor round trips. Generous on purpose.
ONI_CREDIT_WAIT="${ONI_CREDIT_WAIT:-900}"
STO_WORK=""; STO_DD_A=""; STO_DD_B=""; STO_PGID_A=""; STO_PGID_B=""
STO_CLEANED=0
STO_KEEP="${STO_KEEP:-0}"
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
STO_WALLET_PASS="store-onion-acceptance-wallet-pass"
STO_BACKUP_PASS="store-onion-acceptance-backup-pass"

# Trade terms: one 4 KiB deterministic payload — comfortably under the
# dynhost webserver's 65536-byte response cap (file delivery beyond it is
# the named chunked-collect follow-up, not this slice).
PRICE_ZAT=40000
FIXTURE_BYTES=4096
# The store's access token gate settles in ZSLP: zslp_mint only accepts the
# 64-hex genesis token_id, never a ticker (store_sell_operator_proof.sh
# stage 3). The seller mints it live below and the id is buried TOKEN_CONFS
# blocks so the mint baton is confirmed-valid before any order.
TOKEN_TICKER="C5FILE"
TOKEN_CONFS=4
WALLET_SCOPE=dev
TOKEN_IDEMPOTENCY_KEY="store-onion-acceptance-genesis-1"

sto_die() {
    echo "store-onion-acceptance: FATAL: $*" >&2
    if [ -n "$STO_WORK" ] && [ -d "$STO_WORK" ]; then
        printf '%s\n' "$*" >"$STO_WORK/FAILURE"
    fi
    exit 2
}
sto_note() { echo "store-onion-acceptance: $*"; }

sto_assert_port() {
    local p="$1" live
    for live in $STO_LIVE_PORTS; do
        [ "$p" = "$live" ] && sto_die "port $p is in the live refuse-set"
    done
    [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ] &&
        sto_die "port $p is already listening"
    return 0
}

sto_kill_group() {
    local pgid="$1" sig="${2:-TERM}" i
    [ -n "$pgid" ] || return 0
    kill -"$sig" "-$pgid" 2>/dev/null || true
    for i in $(seq 1 50); do
        kill -0 "-$pgid" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}

sto_cleanup() {
    [ "$STO_CLEANED" = 1 ] && return 0
    STO_CLEANED=1
    sto_kill_group "$STO_PGID_A"
    sto_kill_group "$STO_PGID_B"
    if [ "$STO_KEEP" = 1 ] && [ -n "$STO_WORK" ]; then
        sto_note "preserved acceptance artifacts: $STO_WORK"
    elif [ -n "$STO_WORK" ] && [ -d "$STO_WORK" ]; then
        case "$STO_WORK" in
            "$REPO_ROOT"/test-tmp/zcl23-stooni-*) rm -rf "$STO_WORK" ;;
            *) sto_note "WARN refusing to remove non-scratch $STO_WORK" ;;
        esac
    fi
}
trap sto_cleanup EXIT INT TERM

sto_rpc() {
    local dd="$1" port="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$RPC_BIN" "$@" 2>/dev/null
}
a_rpc() { sto_rpc "$STO_DD_A" "$A_RPC" "$@"; }
b_rpc() { sto_rpc "$STO_DD_B" "$B_RPC" "$@"; }
sto_result() {
    "$JSONQ" unwrap
}
sto_jget() {
    "$JSONQ" get "$1"
}
sto_native() {
    local dd="$1" rpc="$2"; shift 2
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1
}
a_native() { sto_native "$STO_DD_A" "$A_RPC" "$@"; }
b_native() { sto_native "$STO_DD_B" "$B_RPC" "$@"; }

sto_spawn() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5"; shift 5
    local args=() connect
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    # Same custody/tor recipe as market_onion_acceptance.sh: the
    # wallet-passphrase credential encrypts key writes at rest,
    # -operator-lane=dev arms the dev wallet scope the storebuy pay leaves
    # require, -regtestshielded activates Overwinter+Sapling from genesis on
    # BOTH nodes, and -tor runs the real embedded Tor (vendor/tor/libtor.a
    # is linked in this build; its bootstrap SocksPort is p2p_port+11966 so
    # the two nodes never collide). -externalip is DELIBERATELY ABSENT on
    # both: there is no clearnet endpoint for the store at all.
    setsid "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" -packagehost=0 -regtestshielded \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >>"$dd/node.log" 2>&1 &
    echo "$!"
}

sto_height() {
    sto_rpc "$1" "$2" getblockcount | sto_result
}
sto_wait_rpc() {
    local dd="$1" rpc="$2" pid="$3" deadline
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        [ -f "$dd/.cookie" ] && sto_height "$dd" "$rpc" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
sto_wait_height() {
    local dd="$1" rpc="$2" target="$3" deadline h
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        h="$(sto_height "$dd" "$rpc" 2>/dev/null || true)"
        [ "$h" -ge "$target" ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

# Tor bootstrap to the PUBLIC network takes ~10-60 s per node (warm
# tor_data is faster) and can be impossible on a host without Tor
# reachability. The seller's onion address is read from the same explorer
# health projection market_onion_acceptance.sh uses; the buyer only needs
# OUTBOUND Tor, so its gate is the Bootstrapped 100% log line. On timeout,
# FAIL with the last bootstrap line — never silently skip the onion proof.
oni_onion_address() {
    local json addr
    json="$(sto_native "$1" "$2" ops state --subsystem=explorer 2>/dev/null || true)"
    addr="$(printf '%s' "$json" | "$JSONQ" get data.state.onion_address 2>/dev/null || true)"
    [ -n "$addr" ] ||
        addr="$(printf '%s' "$json" | "$JSONQ" get state.onion_address 2>/dev/null || true)"
    [ -n "$addr" ] ||
        addr="$(printf '%s' "$json" | "$JSONQ" get data.onion_address 2>/dev/null || true)"
    printf '%s\n' "$addr"
}
oni_bootstrap_tail() {
    grep -a "Bootstrapped" "$1/tor.log" 2>/dev/null | tail -1
}
oni_wait_onion_address() {
    local dd="$1" rpc="$2" label="$3" deadline addr
    deadline=$(( $(date +%s) + ONI_TOR_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        addr="$(oni_onion_address "$dd" "$rpc" || true)"
        case "$addr" in
            *.onion) printf '%s\n' "$addr"; return 0 ;;
        esac
        sleep 2
    done
    sto_die "$label never published an onion address within ${ONI_TOR_WAIT}s \
— host may lack public Tor network reachability (last bootstrap line: \
$(oni_bootstrap_tail "$dd" || echo none))"
}
oni_wait_bootstrap() {
    local dd="$1" label="$2" deadline
    deadline=$(( $(date +%s) + ONI_TOR_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        case "$(oni_bootstrap_tail "$dd")" in
            *"Bootstrapped 100%"*) return 0 ;;
        esac
        sleep 2
    done
    sto_die "$label never finished Tor bootstrap within ${ONI_TOR_WAIT}s \
— host may lack public Tor network reachability (last bootstrap line: \
$(oni_bootstrap_tail "$dd" || echo none))"
}

# The regtest miner stamps blocks from whole-second wall time. More than six
# consecutive blocks with one timestamp becomes <= the peer's 11-block MTP
# even though the local submission path accepted the batch. Mine in groups
# of five with a wall-clock step so the second node validates the same chain.
sto_mine_to_address() {
    local rpc_fn="$1" count="$2" address="$3" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        "$rpc_fn" generatetoaddress "$chunk" "\"$address\"" | sto_result >/dev/null
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}

sto_wait_connected() {
    local dd="$1" rpc="$2" deadline n
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(sto_rpc "$dd" "$rpc" getconnectioncount 2>/dev/null | sto_result 2>/dev/null || true)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
# The money freshness classifier fails closed on finding_peers; the sync
# FSM only leaves it behind a peer it can sync FROM (outbound).
sto_wait_sync_live() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(sto_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | sto_jget result.sync_state 2>/dev/null || true)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 0.5
    done
    return 1
}
sto_wait_at_tip() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(sto_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | sto_jget result.sync_state 2>/dev/null || true)"
        [ "$state" = "at_tip" ] && return 0
        sleep 0.5
    done
    return 1
}
# The buyer's spendable custody reads the vault read model, which lags the
# reducer fold while the wallet re-derives its spendable coins.
sto_wait_spendable() {
    local dd="$1" rpc="$2" deadline spend
    deadline=$(( $(date +%s) + STO_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        spend="$(sto_native "$dd" "$rpc" dumpstate vault 2>/dev/null \
            | sto_jget state.zcl.spendable 2>/dev/null || true)"
        case "$spend" in
            ''|*[!0-9]*) ;;
            *) [ "$spend" -gt 0 ] && return 0 ;;
        esac
        sleep 1
    done
    return 1
}
sto_unlock_wallet() {
    local dd="$1" rpc="$2" status unlock
    status="$(sto_native "$dd" "$rpc" core wallet security status || true)"
    [ "$(printf '%s' "$status" | sto_jget ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$status" >&2; return 1; }
    if [ "$(printf '%s' "$status" | sto_jget data.unlocked 2>/dev/null || true)" != "true" ]; then
        unlock="$(printf '%s' "{\"passphrase\":\"$STO_WALLET_PASS\",\"timeout_seconds\":3600}" \
            | sto_native "$dd" "$rpc" core wallet security unlock --input=- || true)"
        [ "$(printf '%s' "$unlock" | sto_jget data.unlocked 2>/dev/null || true)" = "true" ] || {
            printf '%s\n' "$unlock" >&2; return 1; }
    fi
    return 0
}
sto_backup_wallet() {
    local dd="$1" rpc="$2" out
    out="$(printf '%s' "{\"confirm\":true,\"password\":\"$STO_BACKUP_PASS\"}" \
        | sto_native "$dd" "$rpc" core wallet backup now --input=- || true)"
    [ "$(printf '%s' "$out" | sto_jget ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$out" >&2; return 1; }
}

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS \
    $((A_PORT + 11966)) $((B_PORT + 11966)); do
    sto_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] || sto_die "build node and RPC binaries first"
[ -x "$JSONQ" ] || sto_die "build/bin/jsonq is missing — run make jsonq"
mkdir -p "$REPO_ROOT/test-tmp"
STO_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-stooni-XXXXXX")"
STO_DD_A="$STO_WORK/a"; STO_DD_B="$STO_WORK/b"
STO_CONTENT="$STO_WORK/content"
STO_DOWNLOADS="$STO_WORK/downloads"
mkdir -p "$STO_DD_A" "$STO_DD_B" "$STO_CONTENT" "$STO_DOWNLOADS"
FIXTURE="$STO_CONTENT/seller-payload.txt"
COLLECTED="$STO_DOWNLOADS/bought-copy.txt"

# Deterministic 4 KiB payload (no /dev/urandom: the artifact is the same on
# every host, so a mismatch can never be blamed on entropy). Built through a
# shell buffer, not `yes | head`: yes dies by SIGPIPE when head closes the
# pipe, and under this script's pipefail that 141 would kill the run.
FIXTURE_LINE='Z23 C5 onion store acceptance payload line — buyer collects these exact bytes over Tor.'
FIXTURE_BUF=""
while [ "${#FIXTURE_BUF}" -lt "$FIXTURE_BYTES" ]; do
    FIXTURE_BUF="$FIXTURE_BUF$FIXTURE_LINE"
done
printf '%s' "$FIXTURE_BUF" | head -c "$FIXTURE_BYTES" >"$FIXTURE"
[ "$(wc -c <"$FIXTURE")" = "$FIXTURE_BYTES" ] || sto_die "fixture build failed"

# The remote buy runs blocking onion fetches INSIDE the node's RPC handler
# (first fetch to a fresh onion service can wait out a full rendezvous
# build). The loopback RPC client's 10 s default deadline would cut those
# off; 600 s bounds the whole typed-call surface generously instead.
export ZCL_RPC_DEADLINE_MS=600000

# Wallet custody: boot both nodes with a passphrase credential so key writes
# encrypt at rest (WKS1). The seller's z-address mint and the buyer's money
# gate both refuse a locked or plaintext wallet.
STO_CRED_DIR="$STO_WORK/cred"
install -d -m 700 "$STO_CRED_DIR"
install -m 600 /dev/null "$STO_CRED_DIR/wallet-passphrase"
printf '%s\n' "$STO_WALLET_PASS" >"$STO_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$STO_CRED_DIR"

sto_note "booting seller A and buyer B (both -tor, neither -externalip)"
STO_PGID_A="$(sto_spawn "$STO_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
sto_wait_rpc "$STO_DD_A" "$A_RPC" "$STO_PGID_A" || sto_die "seller A RPC warmup failed"
STO_PGID_B="$(sto_spawn "$STO_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
sto_wait_rpc "$STO_DD_B" "$B_RPC" "$STO_PGID_B" || sto_die "buyer B RPC warmup failed"
! grep -qaF "unrecognized flag" "$STO_DD_A/node.log" "$STO_DD_B/node.log" ||
    sto_die "a boot flag was not recognized"

# Both nodes need their own spendable coins: the buyer pays the order, the
# seller pays the token GENESIS fee. Fund the seller first, then restart it
# so its forward-folded coins set stamps its authority (the same boot-time
# gate the buyer's restart below answers). The restart must land BEFORE the
# onion-address capture: this node's onion service key is ephemeral per
# boot (observed: the address changes across a restart), so the identity
# the buyer dials must be the post-restart one.
sto_note "mining 101 spendable regtest blocks to the seller"
SELLER_ADDR="$(a_rpc getnewaddress | sto_result)"
sto_mine_to_address a_rpc 101 "$SELLER_ADDR"
sto_wait_height "$STO_DD_B" "$B_RPC" 101 || sto_die "B did not sync the seller funding chain"

sto_note "restarting A so the forward-folded coins set stamps its authority"
sto_kill_group "$STO_PGID_A"; STO_PGID_A=""
STO_PGID_A="$(sto_spawn "$STO_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
sto_wait_rpc "$STO_DD_A" "$A_RPC" "$STO_PGID_A" || sto_die "A custody restart failed"
sto_wait_height "$STO_DD_A" "$A_RPC" 101 || sto_die "A did not resync after its restart"
b_rpc addnode "\"127.0.0.1:$A_PORT\"" "\"onetry\"" >/dev/null || true
sto_wait_connected "$STO_DD_B" "$B_RPC" || sto_die "B never reconnected to the restarted A"

# ── Phase 0: Tor — A publishes, B bootstraps for outbound ─────────────
# No reachability is a named FAIL, never a silent pass.
sto_note "waiting for A's onion service and B's outbound Tor bootstrap"
A_ONION="$(oni_wait_onion_address "$STO_DD_A" "$A_RPC" "seller A")"
sto_note "seller A onion service: $A_ONION"
oni_wait_bootstrap "$STO_DD_B" "buyer B"
sto_note "buyer B Tor bootstrap complete (outbound client only)"

sto_note "mining 101 spendable regtest blocks to the buyer"
BUYER_ADDR="$(b_rpc getnewaddress | sto_result)"
sto_mine_to_address b_rpc 101 "$BUYER_ADDR"
sto_wait_height "$STO_DD_A" "$A_RPC" 202 || sto_die "A did not sync the buyer funding chain"

# The buyer's spend gate and z_sendmany read the forward-folded wallet
# projections, whose authority stamps land only at boot: restart B (the
# funded node) so they stamp, then re-link with an operator-directed onetry
# so B owns the OUTBOUND peer the money-freshness classifier demands (it
# fails closed on finding_peers). B's tor_data is warm, so this bootstrap is
# the fast one.
sto_note "restarting B so the forward-folded coins set stamps its authority"
sto_kill_group "$STO_PGID_B"; STO_PGID_B=""
STO_PGID_B="$(sto_spawn "$STO_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
sto_wait_rpc "$STO_DD_B" "$B_RPC" "$STO_PGID_B" || sto_die "B custody restart failed"
oni_wait_bootstrap "$STO_DD_B" "buyer B (custody restart)"
sto_wait_height "$STO_DD_B" "$B_RPC" 202 || sto_die "B did not resync the funding chain"
b_rpc addnode "\"127.0.0.1:$A_PORT\"" "\"onetry\"" >/dev/null || true
sto_wait_connected "$STO_DD_B" "$B_RPC" || sto_die "B never connected outbound to A"
sto_wait_sync_live "$STO_DD_B" "$B_RPC" || sto_die "B sync never left finding_peers"

# Symmetric one-shot link: the seller's payment gate reads
# sync_get_state()==SYNC_AT_TIP, which a listen-only node never reaches.
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
sto_wait_connected "$STO_DD_A" "$A_RPC" || sto_die "A never connected outbound to B"
sto_wait_at_tip "$STO_DD_A" "$A_RPC" || sto_die "A sync never reached at_tip"

# The restart re-locks the encrypted-at-rest wallet (and A booted locked):
# unlock both (passphrase via --input=- only), re-top the RAM-only keypool
# bookkeeping, seed the Sapling keystores, take the current-key encrypted
# backups, then wait for the buyer's spendable custody to turn positive.
sto_note "unlocking both wallets and taking current-key encrypted backups"
sto_unlock_wallet "$STO_DD_A" "$A_RPC" || sto_die "A wallet unlock failed"
sto_unlock_wallet "$STO_DD_B" "$B_RPC" || sto_die "B wallet unlock failed"
a_rpc getnewaddress | sto_result >/dev/null || sto_die "A keypool top-up failed"
b_rpc getnewaddress | sto_result >/dev/null || sto_die "B keypool top-up failed"
# The order-create z-address mint and the buyer's shielded send both need a
# seeded Sapling keystore; minting each node's first z-address generates +
# persists the seed.
a_rpc z_getnewaddress | sto_result >/dev/null || sto_die "A sapling keystore seeding failed"
b_rpc z_getnewaddress | sto_result >/dev/null || sto_die "B sapling keystore seeding failed"
sto_backup_wallet "$STO_DD_A" "$A_RPC" || sto_die "A custody backup failed"
sto_backup_wallet "$STO_DD_B" "$B_RPC" || sto_die "B custody backup failed"
sto_wait_spendable "$STO_DD_B" "$B_RPC" || sto_die "B vault spendable never became positive"
sto_wait_spendable "$STO_DD_A" "$A_RPC" || sto_die "A vault spendable never became positive"

# ── Phase 1: seller mints the access token ON-CHAIN ──────────────────────
# The order reconcile mints access tokens with zslp_mint, which only accepts
# the 64-hex genesis token_id and only builds against a CONFIRMED mint
# baton (store_sell_operator_proof.sh stage 3 — run 3 of this acceptance
# stranded at exactly "wallet does not control the confirmed mint baton"
# when the product was listed with a bare ticker). plan → commit by plan_id
# → bury the genesis TOKEN_CONFS deep. A mines the burial itself: the
# genesis tx is in A's own mempool, so A's blocks certainly carry it.
sto_note "seller creates the $TOKEN_TICKER access token on-chain (plan → commit)"
TOKEN_PLAN="$(printf '%s' "{\"wallet_scope\":\"$WALLET_SCOPE\",\"ticker\":\"$TOKEN_TICKER\",\"name\":\"C5 onion access token\",\"decimals\":0,\"supply\":1000,\"idempotency_key\":\"$TOKEN_IDEMPOTENCY_KEY\"}" \
    | a_native app tokens create --input=- || true)"
printf '%s' "$TOKEN_PLAN" | "$JSONQ" eq ok true ||
    sto_die "token genesis plan refused: $TOKEN_PLAN"
TOKEN_PLAN_ID="$(printf '%s' "$TOKEN_PLAN" | "$JSONQ" get data.plan_id 2>/dev/null || true)"
[ "${#TOKEN_PLAN_ID}" = 64 ] ||
    sto_die "token genesis plan returned no 64-char plan_id: $TOKEN_PLAN"
TOKEN_COMMIT="$(printf '%s' "{\"wallet_scope\":\"$WALLET_SCOPE\",\"plan_id\":\"$TOKEN_PLAN_ID\",\"confirm\":true}" \
    | a_native app tokens create --input=- || true)"
printf '%s' "$TOKEN_COMMIT" | "$JSONQ" eq ok true ||
    sto_die "token genesis commit refused: $TOKEN_COMMIT"
printf '%s' "$TOKEN_COMMIT" | "$JSONQ" eq data.committed true ||
    sto_die "token genesis commit did not commit: $TOKEN_COMMIT"
TOKEN_ID="$(printf '%s' "$TOKEN_COMMIT" | "$JSONQ" get data.token_id 2>/dev/null || true)"
[ "${#TOKEN_ID}" = 64 ] ||
    sto_die "token genesis commit returned no 64-char token_id: $TOKEN_COMMIT"
GENESIS_TIP="$(sto_height "$STO_DD_A" "$A_RPC")"
sto_mine_to_address a_rpc "$TOKEN_CONFS" "$SELLER_ADDR"
sto_wait_height "$STO_DD_B" "$B_RPC" "$((GENESIS_TIP + TOKEN_CONFS))" ||
    sto_die "B did not sync the token genesis burial"
sto_note "access token live: token_id=$TOKEN_ID (buried $TOKEN_CONFS blocks)"

# ── Phase 2: seller lists the file product ─────────────────────────────
sto_note "seller lists the file product (${FIXTURE_BYTES} bytes, token $TOKEN_ID)"
LIST_OUT="$(printf '%s' "{\"name\":\"C5 onion payload\",\"description\":\"C5 onion acceptance file\",\"price_zatoshi\":$PRICE_ZAT,\"token_id\":\"$TOKEN_ID\",\"tokens_per_purchase\":1,\"content_path\":\"$FIXTURE\",\"content_filename\":\"seller-payload.txt\"}" \
    | a_native app store list-product --input=- || true)"
printf '%s' "$LIST_OUT" | "$JSONQ" eq ok true ||
    sto_die "seller list-product refused: $LIST_OUT"
PRODUCT_ID="$(printf '%s' "$LIST_OUT" | "$JSONQ" get data.id 2>/dev/null || true)"
case "$PRODUCT_ID" in
    ''|*[!0-9]*) sto_die "seller list-product returned no product id: $LIST_OUT" ;;
esac
LIST_HASH="$(printf '%s' "$LIST_OUT" | "$JSONQ" get data.content_hash 2>/dev/null || true)"
[ "${#LIST_HASH}" = 64 ] || sto_die "seller list-product stored no content hash: $LIST_OUT"
sto_note "seller product live: id=$PRODUCT_ID content_hash=$LIST_HASH"

# ── Phase 3: buyer places the order OVER TOR ────────────────────────────
# The whole point of the slice: product JSON, product page (CSRF + PoW) and
# the /store/orders POST ride the dynhost client through real circuits to
# A's onion service. Retried: a first fetch to a freshly published onion
# can miss the circuit window, and a refused attempt costs nothing but a
# pending order row on the seller (pruned unpaid within the hour).
sto_note "buyer places the order over Tor (app.store.remotebuy)"
CUSTOMER_ADDR="$(b_rpc getnewaddress | sto_result)"
ORDER_OUT=""
ORDER_DEADLINE=$(( $(date +%s) + ONI_CREDIT_WAIT ))
while :; do
    ORDER_OUT="$(printf '%s' "{\"seller_onion\":\"$A_ONION\",\"product_id\":$PRODUCT_ID,\"customer_address\":\"$CUSTOMER_ADDR\",\"output_path\":\"$COLLECTED\"}" \
        | b_native app store remotebuy --input=- || true)"
    [ "$(printf '%s' "$ORDER_OUT" | sto_jget ok 2>/dev/null || true)" = "true" ] && break
    [ "$(date +%s)" -lt "$ORDER_DEADLINE" ] ||
        sto_die "remotebuy never succeeded: $ORDER_OUT"
    sto_note "remotebuy attempt refused (retrying): $(printf '%s' "$ORDER_OUT" | sto_jget error.message 2>/dev/null || printf '%s' "$ORDER_OUT")"
    sleep 10
done
PURCHASE_ID="$(printf '%s' "$ORDER_OUT" | "$JSONQ" get data.purchase_id)" ||
    sto_die "remotebuy mismatch: $ORDER_OUT"
MERCHANT_ORDER_ID="$(printf '%s' "$ORDER_OUT" | "$JSONQ" get data.order_id)" ||
    sto_die "remotebuy mismatch: $ORDER_OUT"
PAY_ADDR="$(printf '%s' "$ORDER_OUT" | "$JSONQ" get data.payment_address)" ||
    sto_die "remotebuy mismatch: $ORDER_OUT"
PAY_MEMO="$(printf '%s' "$ORDER_OUT" | "$JSONQ" get data.memo)" ||
    sto_die "remotebuy mismatch: $ORDER_OUT"
[ "$PAY_MEMO" = "ZCL23ORDER:$MERCHANT_ORDER_ID" ] ||
    sto_die "remotebuy memo mismatch: $ORDER_OUT"
printf '%s' "$ORDER_OUT" | "$JSONQ" eq data.amount_zatoshi "$PRICE_ZAT" ||
    sto_die "remotebuy amount mismatch: $ORDER_OUT"
printf '%s' "$ORDER_OUT" | "$JSONQ" eq data.seller_onion "$A_ONION" ||
    sto_die "remotebuy seller mismatch: $ORDER_OUT"
sto_note "order placed over Tor: purchase=$PURCHASE_ID merchant_order=$MERCHANT_ORDER_ID pay_addr=$PAY_ADDR"

# The seller's tor.log must name the POST — the wire evidence that the
# order arrived through the onion service, not a clearnet shortcut.
grep -aq "HTTP POST /store/orders" "$STO_DD_A/tor.log" ||
    sto_die "seller tor.log shows no HTTP POST /store/orders — the order did not arrive over the onion wire"
grep -aq "POST fetch for .*\.onion/store/orders\|initiated fetch to .*\.onion/store/orders\|store/orders" "$STO_DD_B/tor.log" ||
    sto_die "buyer tor.log shows no dynhost fetch to the seller's /store/orders"

# ── Phase 4: buyer pays shielded with the order memo ───────────────────
sto_note "buyer pays the order shielded (t->z sendmany, memo $PAY_MEMO)"
PAY_OUT="$(printf '%s' "{\"purchase_id\":$PURCHASE_ID,\"from_address\":\"$BUYER_ADDR\",\"confirm\":true}" \
    | b_native app store pay --input=- || true)"
printf '%s' "$PAY_OUT" | "$JSONQ" eq ok true ||
    sto_die "storebuy pay refused: $PAY_OUT"
printf '%s' "$PAY_OUT" | "$JSONQ" eq data.committed true ||
    sto_die "storebuy pay mismatch: $PAY_OUT"
OP_ID="$(printf '%s' "$PAY_OUT" | "$JSONQ" get data.operation_id 2>/dev/null || true)"
[ -n "$OP_ID" ] || sto_die "storebuy pay returned no operation id: $PAY_OUT"
sto_note "payment submitted: operation=$OP_ID"

# ── Phase 5: confirmations + the seller's memo reconcile ───────────────
# The merchant credits the order only for a payment BOUND by the
# ZCL23ORDER:<id> memo at 3 confirmations, then mints the access tokens.
# Mine past the depth and poll the buyer's REMOTE status — itself an onion
# fetch of the seller's order page — until the merchant's own page says
# Tokens Sent.
sto_note "mining 4 confirmation blocks; waiting for the seller's memo reconcile"
sto_mine_to_address b_rpc 4 "$BUYER_ADDR"
PAY_TIP="$(sto_height "$STO_DD_B" "$B_RPC")"
sto_wait_height "$STO_DD_A" "$A_RPC" "$PAY_TIP" || sto_die "A did not sync the payment chain"

CREDIT_DEADLINE=$(( $(date +%s) + ONI_CREDIT_WAIT ))
CREDITED=0
while [ "$(date +%s)" -lt "$CREDIT_DEADLINE" ]; do
    POLL_OUT="$(printf '%s' "{\"purchase_id\":$PURCHASE_ID}" \
        | b_native app store purchases --input=- || true)"
    if [ "$(printf '%s' "$POLL_OUT" | sto_jget ok 2>/dev/null || true)" = "true" ] &&
       [ "$(printf '%s' "$POLL_OUT" | sto_jget data.ready_to_collect 2>/dev/null || true)" = "true" ]; then
        CREDITED=1
        break
    fi
    sleep 15
done
[ "$CREDITED" = 1 ] ||
    sto_die "seller never credited the order (last poll: $POLL_OUT)"
printf '%s' "$POLL_OUT" | "$JSONQ" eq data.seller_onion "$A_ONION" ||
    sto_die "purchase lost its seller scope: $POLL_OUT"
sto_note "merchant credited order $MERCHANT_ORDER_ID (buyer poll over Tor says Tokens Sent)"

# The seller's own row proves the memo reconcile: status SENT plus the
# paid_at stamp db_store_order_mark_paid writes — reached only after the
# ZCL23ORDER memo bind credited 3-confirmed funds and zslp_mint succeeded.
# (payment_txid is NOT asserted: the reconcile path records the settle with
# status + paid_at only; the column belongs to a different flow.)
A_ORDER_ROW="$(a_native core storage query \
    --input="{\"sql\":\"SELECT status, paid_at FROM orders WHERE id=$MERCHANT_ORDER_ID\"}" || true)"
printf '%s' "$A_ORDER_ROW" | "$JSONQ" eq ok true ||
    sto_die "seller order row unreadable: $A_ORDER_ROW"
A_ORDER_STATUS="$(printf '%s' "$A_ORDER_ROW" | "$JSONQ" get data.rows[0][0] 2>/dev/null || true)"
A_ORDER_PAID_AT="$(printf '%s' "$A_ORDER_ROW" | "$JSONQ" get data.rows[0][1] 2>/dev/null || true)"
[ "$A_ORDER_STATUS" = "2" ] ||
    sto_die "seller order row not SENT (status=$A_ORDER_STATUS): $A_ORDER_ROW"
case "$A_ORDER_PAID_AT" in
    ''|*[!0-9]*) sto_die "seller order row carries no paid_at stamp: $A_ORDER_ROW" ;;
esac
grep -aq "Store: order #$MERCHANT_ORDER_ID paid, minted" "$STO_DD_A/node.log" ||
    sto_die "seller node.log shows no paid+minted line for order $MERCHANT_ORDER_ID"
sto_note "seller reconciled the ZCL23ORDER memo: status=SENT paid_at=$A_ORDER_PAID_AT (mint logged)"

# ── Phase 6: mint confirmation ───────────────────────────────────────────
# The token gate reads the chain-derived zslp_ledger, which only counts the
# access-token mint once its block is connected (operator-proof stage 9.5).
# SENT means the mint is already broadcast into A's own mempool, so A mines
# the confirmation blocks itself. B needs no sync here — the gate lives on
# A — but B must not fork the chain it keeps paying on, so it re-syncs too.
sto_note "mining 3 blocks so the access-token mint confirms on-chain"
sto_mine_to_address a_rpc 3 "$SELLER_ADDR"
MINT_TIP="$(sto_height "$STO_DD_A" "$A_RPC")"
sto_wait_height "$STO_DD_B" "$B_RPC" "$MINT_TIP" || sto_die "B did not sync the mint-confirm chain"

# ── Phase 7: buyer collects over Tor and the bytes verify ──────────────
# Bounded retry while the seller's ledger projection folds the mint block;
# a 403 from the gate in that window is transient, anything else is not.
sto_note "buyer collects the file over Tor (/store/access token gate)"
COLLECT_OUT=""
COLLECT_DEADLINE=$(( $(date +%s) + 300 ))
while :; do
    COLLECT_OUT="$(printf '%s' "{\"purchase_id\":$PURCHASE_ID,\"output_path\":\"$COLLECTED\"}" \
        | b_native app store collect --input=- || true)"
    [ "$(printf '%s' "$COLLECT_OUT" | sto_jget ok 2>/dev/null || true)" = "true" ] && break
    [ "$(date +%s)" -lt "$COLLECT_DEADLINE" ] ||
        sto_die "collect never succeeded: $COLLECT_OUT"
    sleep 10
done
printf '%s' "$COLLECT_OUT" | "$JSONQ" eq data.hash_verified true ||
    sto_die "collect did not verify the content hash: $COLLECT_OUT"
printf '%s' "$COLLECT_OUT" | "$JSONQ" eq data.content_hash "$LIST_HASH" ||
    sto_die "collected hash differs from the listed content hash: $COLLECT_OUT"
printf '%s' "$COLLECT_OUT" | "$JSONQ" eq data.bytes "$FIXTURE_BYTES" ||
    sto_die "collected byte count mismatch: $COLLECT_OUT"
cmp -s "$FIXTURE" "$COLLECTED" ||
    sto_die "collected bytes differ from the seller's fixture"
sto_note "buyer collected $FIXTURE_BYTES bytes; SHA3 verified in-process and byte-identical to the fixture"

# The collect must have ridden the wire too: the seller's tor.log names the
# gated GET.
grep -aq "HTTP GET /store/access" "$STO_DD_A/tor.log" ||
    sto_die "seller tor.log shows no HTTP GET /store/access — the collect did not arrive over the onion wire"

sto_note "PASS: listed, ordered (POST over Tor), paid shielded, reconciled by memo, collected + hash-verified over Tor"
sto_note "  seller onion:  $A_ONION"
sto_note "  product:       id=$PRODUCT_ID token=$TOKEN_ID price=${PRICE_ZAT}zat hash=$LIST_HASH"
sto_note "  order:         purchase=$PURCHASE_ID merchant_order=$MERCHANT_ORDER_ID paid_at=$A_ORDER_PAID_AT"
sto_note "  tor evidence:  $STO_DD_A/tor.log (served POST + GET), $STO_DD_B/tor.log (dynhost client fetches)"
