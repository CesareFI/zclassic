# Commons journey across three physical hosts (2026-09-29)

`make commons-multihost-acceptance` drives the twelve-step Commons journey
across three consenting hosts. Each host runs its own isolated regtest
datadir, and every node reaches the others over its own P2P port. No tunnel
carries node traffic.

## Topology

| Role | Host | Node | Duty |
|------|------|------|------|
| A | driver host | requester and publisher | asks, writes the missing behavior, accepts, publishes; killed in step 12 |
| B | second host | build worker | proves remotely, reproduces the source, signs receipts, exports the object carrier |
| C | third host | latecomer | joins after A exits and learns only from B |

The driver copies one set of binaries to B and C and checks each copy by
sha3 before any node boots. The production nodes on B and C were not
touched: their service main PIDs were recorded before the runs and were the
same afterwards.

## Source

- Base: `6636fe270f`
- Run 3 (PASS): `a7fd5574f5`
- Runs 5 and 6: `9d1a5cd587`. The `z23` sha256 was
  `103aeef7027d09b0a391cbe77d60d668c44f59241bafd8ebe309f594c368183d`, and it
  matched on all three hosts.
- Runs 8 and 9: `ce0a212fa3` (configured-inbound sync). The `z23` sha256 was
  `900d69a14200ed25041573bd8af1c24ee81a5882e8a24d2164690b1ed738de87` on all
  three hosts. Toolchain capsule roots:
  - A and B: `5c82d3bc9d023caaf15a93b0db74f97aa0430f0c6458ae87b5d20aea6b3fcc8a`
  - C: `b0a1234afb88c1cbfb507b3d41c0f4b4422a428de33637b272818d33ce67d732`
- Tie-break runs 11-14: `5de24cac1f`. The `z23` sha256 was
  `edff14d4c9e92af8ec5d386e1406e1dda11200093acb66eab17b165c3f141650`,
  identical on all three hosts.
- Post-fix runs 15 and 16: `d3aded7383` (batched staged-drain durability).
  The `z23` sha256 was
  `80a99142e910ad011fe8816aea1f12edd28b37e930ac77c7962fb267b7173d34`,
  identical on all three hosts.

## Runs

| Run | Source | Result | Stopped at |
|-----|--------|--------|------------|
| 1 | base | FAIL | step 12: carrier rebuild judged by the `cc --version` banner |
| 2 | + carrier fix | FAIL | step 8: the remote proof result was lost when the session dropped |
| 3 | + session fix | **PASS 12/12**, 479 s | none |
| 4 | same | FAIL | bring-up: node A anchor funding reported `Insufficient funds` |
| 5 | + wallet fix | FAIL | overlay: node B stuck in `finding_peers` (two-node dial deadlock) |
| 6 | same | FAIL | overlay: same as run 5 |
| 7 | + configured-inbound sync, probe socket non-blocking | FAIL | overlay: B's identity probe returned at once, so B stayed in `finding_peers` |
| 8 | `ce0a212fa3` | **PASS 12/12**, 617 s | none |
| 9 | same | FAIL | step 11: the remote proof session was lost to connection churn |
| 10 | `d0216b92bb` (scratch tree) | PASS verdict 12/12; driver TERM'd after the verdict, rc unrecorded | none |
| 11 | `5de24cac1f` | FAIL | step 12: node C's initial sync crawled past its budget (fault 5) |
| 12 | `5de24cac1f` | **PASS 12/12**, 470 s | none |
| 13 | `5de24cac1f` | **PASS 12/12**, 450 s | none |
| 14 | `5de24cac1f` | **PASS 12/12**, 492 s | none |
| 15 | `d3aded7383` | **PASS 12/12**, 469 s | none |
| 16 | `d3aded7383` | **PASS 12/12**, 504 s | none |
| 17 | `c4e7857b51` | **PASS 13/13**, 455 s | none — first physical publisher-return pass (step 13, fault 6) |
| 18 | `c4e7857b51` | **PASS 13/13**, 469 s | none |

Wall times are the driver's own run time; queue time for the shared build
slot is excluded.

### Run 3 (PASS) step results

Every step verdict was PASS, and the verdict line reported
`"steps_proven":12,"steps_total":12,"complete":true`. The whole run took
479 s. Durations reported inside the run:

| Step | Result |
|------|--------|
| 1 guide | PASS |
| 2 commons package present | PASS |
| 3 B fetches peer-to-peer, bytes stay inert | PASS (15481 bytes from A, no registry) |
| 4 work start, reuse searched first | PASS |
| 5 use: explicit local admission | PASS |
| 6 work run: only the missing behavior | PASS (built and tested on A 67 s after the ask) |
| 7 work show | PASS |
| 8 work accept: exact bytes travel | PASS (B re-derived the source root in 7 s and signed it) |
| 9 use on the second node | PASS (ask to running program: 91 s) |
| 10 object-set carrier | PASS (2 objects, B to C, as one package) |
| 11 change existing software | PASS (143 deg/s before, 239 deg/s after, as its own root) |
| 12 publisher gone | PASS |

- **Publisher kill:** node A was killed. Node C held none of the survival
  objects and had executed no work before A exited.
- **C from B:** node C fetched the accepted application from B alone (22074
  bytes) and reproduced and ran it. It measured the same 239 deg/s that B
  measured. The carrier moved 2 objects from B to C.
- **Receipts:** 2 signed source-reproduction receipts were consumed. The
  tamper refusals fired by name: `LANE_NOT_ACCEPTED`, `TARGET_UNRESOLVED`,
  `CONFIRMATION_IDENTITY_STALE` and `SOURCE_PACKAGE_CHECKOUT_REFUSED`.
- **Central services contacted:** 0.
- **Toolchain:** hosts B and C have different toolchain capsule roots, so the
  verdict reports `carrier_toolchain=different_capsule`. It also reports
  `cross_capsule_objects_reused=0` and `zero_compiler_rebuild=false`: C
  rebuilt under its own capsule and reused none of B's objects.

### Runs 5 and 6: wall times on `9d1a5cd587`

| Phase | Run 6 wall time |
|-------|-----------------|
| bring-up (three datadirs, binaries copied and verified) | 19 s |
| mining, custody restart, backup | 48 s |
| identity anchors and delegations | 8 s |
| steps 1-2 and staging | 2 s |
| overlay: authenticated session A <-> B | 27 s |
| overlay: wait for B's build worker to admit work | 91 s, then refused |

## Faults found and fixed

1. **The carrier verdict compared compiler banners.**
   - **Cause:** Hosts with the same `cc --version` but a different
     binutils patch have different toolchain capsule roots. The capsule root
     is bound into the fastobj cache key and the build receipt.
   - **Fix:** The driver now reads `zcode work toolchain` on B and C. With
     the same capsule, it still demands full reuse, zero misses and an
     identical receipt. With a different capsule, it demands zero reuse, a
     full rebuild and a different receipt.
   - **Regression test:** `tools/dev/commons-journey-ordering-selftest.sh`.
2. **A remote proof result was stranded when its session dropped.**
   - **Cause:** Work-session ids are connection-scoped and never return.
     A worker that finished while its session churned queued the RESULT to a
     dead session, and the requester kept waiting until its deadline.
   - **Fix:** A lost session now makes the requester re-dispatch the same
     binding to the worker's new session, keeping the original deadline, and
     supersedes the lost track.
   - **Regression test:** `zcode_dev: a dropped session moves the exact
     binding to the worker's new session` in `test_zcode_dev_objects`.
3. **The boot wallet catch-up read block bodies from the wrong directory.**
   - **Cause:** On regtest and testnet, block writers store bodies under
     `<datadir>/<network>/blocks`, but the boot catch-up rescan read
     `<datadir>/blocks`. After an unclean stop the rescan failed every body
     and still moved the wallet to the tip. Each coinbase then kept the depth
     it had at the last flush, so the wallet refused to spend coins its own
     vault reported as mature.
   - **Fix:** The catch-up now reads the network-specific directory.
   - **Regression test:** scenario E in `test_wallet_rescan_coverage`.

4. **The node left holding only the peer's inbound session never synced.**
   - **Cause:** The sealed core evicts a same-IP inbound once its own
     outbound to that IP completes, and header sync began only from outbound
     peers. Two nodes told to dial each other could end with one connection,
     and the inbound-only side stayed in `finding_peers`.
   - **Fix:** An inbound session may serve headers when its own Noise
     session authenticated the static key that this node learned by
     completing Noise XX as initiator to an operator-named `-addnode`,
     `-connect`, `-addnode-file` or `addnode` RPC target at the same IP.
     The key comes from an outbound session to the exact target, or from a
     bounded identity probe that completes the handshake and closes before
     `VERSION`. The source IP, `addr_from` and gossip grant nothing, and
     plaintext, loopback and onion sources never qualify. Every session is
     checked against its own handshake. The rule and its argument are in
     `engine/services/include/services/configured_sync_peers.h`.
   - **Same limits as an outbound peer:** the peer goes through the same
     header and block validation, download windows and misbehaviour scoring.
     The core applies body-stall rules C and D only to outbound peers, so
     the stale-header predicate applies them to a configured inbound sync
     peer. The one difference left is rule B, the core's outbound-slot
     rotation, which has no inbound equivalent.
   - **Regression test:** `test_sync_service_configured_inbound.c` in
     `sync_service`. It drives real connection managers, real Noise XX
     pairs and the core eviction through all 24 A/B handshake interleavings,
     a reconnect, an impostor key at the configured IP, a plaintext session
     and publisher loss, with an injected prober and clock. On the old gate,
     16 of the 24 interleavings leave a node without a header source. One
     further case runs the real prober against a loopback listener; run 7's
     non-blocking socket fails it.
   - **Observed in run 8, node B:**
     `configured sync peer identity probe completed Noise XX with target=<A>:20028`,
     then
     `configured-inbound header sync: peer=<A>:49584 id=2 proved over its own Noise session the identity this node authenticated at an operator-named -addnode/-connect target; ...`.

5. **A fresh latecomer's staged sync intermittently crawled past its budget.**
   - **Symptom:** run 11 died at "node C (initial sync) did not reach height
     124" while C's peer session stayed handshaked and B advertised 124. C's
     staged pipeline then finished all 124 blocks roughly 45 s after the
     driver's 90 s wait expired.
   - **Cause:** C's own debug bundle names the wait:
     `event_log_barrier_appends:227` and
     `event_log_barrier_us_total:69105790` — `event_log_append`'s two
     per-append fsync barriers (about 300 ms each on node C's HDD host)
     executed on the shared supervisor tick runner, stretching staged ticks
     to ~10 s. Every SQLite timing in the same bundle stayed in microseconds,
     so node.db was not the wait. The reducer's crash-ordered
     batched-durability scope existed but armed only above the 500-block
     accelerated-cadence threshold, which a 124-block latecomer never
     reaches. When the net intake worker happened to hold the same scope
     open, appends deferred and the run passed (runs 12-14); when intake went
     idle, staged ticks paid the barriers (run 11).
   - **Fix:** `catchup_cadence_deferred_sync_active()` arms the same
     batched-durability scope around each staged drain for any backlog past
     one block (default threshold 2, `d3aded7383`). The flush still runs at
     every stage-batch commit and at scope exit, and at tip (gap <= 1)
     per-operation durability is unchanged.
   - **Regression:** `case_small_backlog_defer_sync_gate` in
     `test_catchup_cadence` and `spt_case_small_chain_durability` in
     `test_supervisor_production_tree`, red on the old wiring and green
     after.

6. **The returned publisher's wallet under-reported spendable after the
   hard kill.**
   - **Symptom:** step 13's balance check. One killed datadir gave three
     views: boot getbalance 312.49999700; live after `generate 2`
     337.49999700; after a manual `rescanblockchain` 574.99999700 — the
     pre-kill number. `listunspent 0` snapshots taken before and after the
     balance-changing rescan were byte-identical (10424 bytes), so the UTXO
     set never changed: only the maturity view did.
   - **Cause:** `wallet_rescan_report` moved the wallet's depth baseline to
     the scan's stop height without re-basing the stored confirmation
     counts of rows below the scan start. After the kill the last flush had
     measured every stored depth from height 124 while the chain stood at
     145, and the boot catch-up scanned only the 125..145 gap: pre-existing
     rows kept depths 21 short. `getbalance` gates each coinbase on
     `COINBASE_MATURITY − confirms`, so exactly the 21 coinbases in the
     maturity boundary band (heights 26..46 at tip 145) read immature:
     21 × 12.5 = 262.5 missing. The "+25 after generate 2" was two more
     real coinbases crossing the boundary under the same stale baseline —
     `generate`'s empty-script coinbase pays nobody and no view ever
     credited it. `listunspent` reads confirmations from the chain, which
     is why it was correct all along.
   - **Fix:** when a rescan starts above the wallet's current baseline,
     `wallet_rescan_rebase_depths` raises pre-existing depths by the
     distance the baseline moves — the same adjustment a later connected
     tip applies through `wallet_advance_confirmations`.
   - **Regression:** scenario G in `test_wallet_rescan_coverage` (kill at
     baseline 60, empty-coinbase gap to 160, coin maturing exactly at the
     tip): red on the old wiring — the boundary coin stayed immature and
     getbalance returned 0 — green after, including across flush and
     reboot.

## Open blocker: reconnects between two configured peers destroy both sessions (closed below)

Note: the following mechanism record was written against run 9, before the
tie-break landed; the closure section follows it.

Run 9 reached step 11 and then lost its remote proof. B's log shows the
cycle every 30 s:

1. A dials B. B holds only that inbound session, which is bound and serves
   headers.
2. B's `-connect` loop dials A again. It waits only while its outbound
   count covers every connect target
   (`core/modules/net/src/connman_dialer.c:740`), and an inbound session
   never satisfies a target (`connman_node_conflicts_with_target`,
   `core/modules/net/src/connman.c:692`).
3. A processes B's `VERSION`, answers `VERACK`, and evicts B's inbound,
   because A holds an outbound to B's IP.
4. B receives that `VERACK`, completes its outbound, and evicts A's inbound
   (`core/modules/net/src/connman_zcl23_dial.c:154`).
5. Both sessions are gone. A redials within a second, and the cycle repeats.

Whether step 4 happens depends on whether B processes the `VERACK` before
the close. Run 8 passed on that timing, and run 9 did not. The regression
test shows the same thing without timing: 8 of the 24 handshake
interleavings leave no surviving session. The configured-inbound rule cannot
help when no session survives.

The fix belongs in the sealed core. Either rule would do:

- A connect or addnode target counts as connected while an inbound session
  from its IP carries the target's authenticated Noise identity.
- Both nodes apply one deterministic tie-break when both directions exist,
  such as keeping the connection dialed by the lower static key. Each side
  knows both keys after Noise, so both evict the same connection.

The engine cannot suppress a core dial or eviction, so this change needs an
owner decision.

## Closed: the owner-authorized tie-break holds both mutual-dial edges

The owner authorized the sealed-core change on 2026-09-29 and it landed
(75e8efc199, pinned by 309aa1872a, driven by 48baac36a5): when a handshaked
outbound and an inbound from the same IP authenticated the same Noise static
key, both nodes keep the session dialed by the lower key and drop the other,
and the losing side's connect target counts as connected while the kept
inbound carries that key. Run 12's node B log shows both rules working on
the physical hosts:

- `configured-inbound header sync: peer=<A>:36854 id=3 proved over its own
  Noise session the identity this node authenticated at an operator-named
  -addnode/-connect target; ...` (engine/services/src/peer_sync_gate.c:96)
- `mutual-dial tie-break: peer=<C>:20026 kept=outbound local=65b9bd15 ...`
  (core/modules/net/src/connman_zcl23_dial.c:250). After node C synced, B
  dialed the latecomer and C's outbound to B completed its handshake — a
  fresh mutual dial on the B<->C edge. The tie-break settled it with one
  surviving session, the same rule that holds A<->B, and the run passed.

Runs 15 and 16 are two consecutive physical 12/12 passes on the fix's
landed SHA `d3aded7383` (469 s and 504 s), the repeatable-green bar
for that acceptance's twelve steps. Runs 17 and 18 raise the bar to the
full thirteen: two consecutive physical 13/13 passes on `c4e7857b51`
(455 s and 469 s), the first physical proof that the publisher returns
from its own killed datadir with a provable tip, complete body history,
and an unchanged spendable balance (fault 6). The same-host journey
passes 13/13 on the same SHA.

Separately, in run 4 node A's own shutdown hit `database is locked` on
node.db while the wallet flush was retrying. The harness's TERM grace then
expired, which caused the unclean stop. Fault 3 makes the node recover from
that stop. The driver now gives each stop the node's own shutdown grace
before escalating to KILL. The lock contention itself remains open, tracked
separately from fault 5: during run 11's crawl every SQLite timing in node
C's debug bundle stayed in microseconds.
