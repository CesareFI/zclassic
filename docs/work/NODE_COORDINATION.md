<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Node engineering coordination

This note records validated public-node findings that another development
branch should check before duplicating work. It does not set priorities or
describe live production state.

## Block-swarm peer manifest reach

Block-swarm assignment previously used the swarm-wide manifest range when a
peer supplied no piece bitmap. A peer advertising a shorter, independently
anchored manifest could therefore be assigned pieces beyond that peer's own
advertised end. Those out-of-range requests were invalid for that peer, could
increase the requester's misbehavior score and lead to a ban, and degraded IBD
reliability.

Assignment now caps each peer's reach at that peer's anchored manifest end.
Peers advertising the full range retain full reach, and peers without a
manifest retain the prior scheduling behavior. Block validity, header
admission, peer-side request validation, and consensus rules are unchanged.

The focused regression completes the first five of eight pieces, proves a
five-piece peer receives no later assignment, and proves full-range and
unknown-range peers still receive later work. The block-swarm loopback group
also passed, transferring 2,560 blocks (3,962,880 bytes) at approximately
22,888 blocks/s and 33.8 MiB/s while retaining disconnect reassignment and
stall recovery behavior.

Validation at commit `0caeed6d1`:

- `test_utxo_commitment`: passed, including the peer-manifest cap regression.
- `test_block_swarm_loopback`: passed.
- core seal, consensus-parity, complexity, generated capability inventory,
  and diff-whitespace gates: passed.
- The cold canonical suite ran 1,160 of 1,169 groups in 1,183.7 seconds:
  1,139 passed, 21 unrelated infrastructure/environment groups failed, nine
  parameter-heavy groups were gated, and 22 groups self-skipped. The host ran
  out of disk during the 500,000-file code-index scale case; later storage,
  database, resident, and development-tool failures occurred in that exhausted
  environment. Neither changed group failed.

Follow-up: block-swarm stall and restart timing still needs an audit for
wall-clock rollback behavior. Any change must preserve the legacy-download
ownership window after abandonment and must not change validation semantics.

## Block-swarm restart cooldown clock

The 300-second post-abandonment cooldown was process-local but stored the last
abandonment as Unix wall time. A backward civil-clock correction made elapsed
time negative and could leave legacy download holding ownership far beyond the
intended interval; a forward jump could expire it early.

The abandonment stamp and restart comparison now use monotonic seconds. Zero
explicitly means no prior abandonment, a reversed monotonic sample fails
closed without subtraction, and every later abandonment starts a fresh full
cooldown. The state remains non-persistent, so process restart continues to
clear the cooldown as before. Regression coverage pins immediate retry,
299/300-second boundaries, backward and large forward wall-clock changes,
defensive monotonic reversal, reset, and repeated abandonment cycles. The
block-swarm loopback remained green, moving 2,560 blocks at approximately
32,017 blocks/s and 47.3 MiB/s in the measured focused run.

The silent-stall age was subsequently corrected as described below. The
progress-report cadence remains diagnostic wall-time state and does not own
requests or control swarm abandonment/restart.

## Block-swarm silent-stall clock

The 90-second silent-stall watchdog stored piece-completion wall time. A
backward clock correction could therefore leave block-piece ownership active
and legacy download paused too long; a forward jump could abandon a healthy
swarm early.

Piece-completion stamps and the watchdog comparison now use process-local
monotonic seconds. Zero remains the explicit uninitialized value, reversed
samples fail closed before subtraction, each verified completion starts a
fresh interval, and no cooldown state is persisted across restart. Deterministic
coverage pins the 89/90-second boundary, backward and forward wall-clock
steps, repeated completion cycles, zero state, and ownership before and after
abandonment. The focused loopback passed with immediate disconnect requeue of
40 pieces and transferred 2,560 blocks (3,962,880 bytes) at 31,009 blocks/s
and 45.8 MiB/s.

Consensus impact: none. Block/header/message validation, serialization,
cryptography, PoW, activation, and monetary rules are untouched. Next inspect
per-peer request ages and timeout/reassignment behavior before changing any
timeout constant; diagnostic progress-report wall time remains a separate,
non-authoritative cleanup candidate.

## Block-swarm stale timeout ownership

The global timeout sweep could make peer A's piece assignable and peer B could
claim it before A's stale pipeline slot was cleared. A's later per-peer cleanup
then requeued the piece solely because it was in flight, revoking B's valid
ownership and enabling duplicate work.

Per-peer cleanup now requeues only when the named peer is still the recorded
owner. A deterministic A-to-B reassignment regression proves stale A cannot
revoke B, while B retains normal requeue authority. Disconnect cleanup uses
the same ownership-checked primitive. The loopback retained immediate requeue
of 40 disconnected-peer pieces and moved 2,560 blocks (3,962,880 bytes) at
30,001 blocks/s and 44.3 MiB/s.

Consensus impact: none; only request ownership bookkeeping changed. Next
measure timeout/reassignment counts and useful delivery per peer before
considering adaptive scheduling or any timeout change.

## Block-swarm first-peer fairness

The global contiguous-work window and each peer pipeline were both 256 pieces,
so the first peer receiving a send tick could claim the entire window. A
production-path regression measured the resulting split as 256/0 across two
ready peers with 320 pieces available.

New assignments are now limited to 64 per peer per send tick. Existing
in-flight work remains untouched, the global window and per-peer pipeline stay
at 256, and a lone peer reaches all 256 slots over four ticks. The regression
measures a 64/64 first-round split, proves the peers' piece sets are disjoint,
and proves the single-peer steady-state capacity remains 256. Disconnect
requeue still reclaimed all 40 outstanding pieces immediately. The real-wire
loopback moved 2,560 blocks (3,962,880 bytes) at 31,486 blocks/s and 46.5 MiB/s.

Consensus impact: none. This changes only the rate at which already-eligible
requests are assigned to peers; every response retains the existing manifest,
block, and consensus validation.

A follow-up profile scanned a 50,000-piece manifest 2,000 times: 100 million
state checks took 28,638 microseconds, about 14.3 microseconds per sweep on the
measured host. That does not justify a more complex timeout data structure.
Next measure block-swarm delivery and timeout outcomes per peer; the legacy
download manager already has bounded delivery-rate scoring, but block-piece
responses do not currently feed equivalent scheduler evidence.

That delivery/timeout audit found a narrower scheduling leak before adaptive
scoring was justified. When a piece timed out at peer A, was reassigned to peer
B, and A's late valid response completed it, B retained its now-stale pipeline
slot until B's own eight-second timeout. Repeated late responses could therefore
reduce useful parallelism despite continued valid delivery. Each peer send tick
now reconciles its local slots with authoritative swarm ownership: completed or
reassigned slots are reclaimed immediately, while timeout requeue remains
ownership-checked. A deterministic regression reproduces the A-to-B handoff and
proves B recovers the slot at zero elapsed seconds.

Consensus impact: none. Piece completion remains manifest-hash verified and all
block payloads still traverse the existing canonical reducer and consensus
validation; this changes only request-slot bookkeeping after verification.

Validation: the focused real-wire loopback moved 2,560 blocks (3,962,880
bytes) at 31,687 blocks/s (46.8 MB/s), and the ASan/UBSan profile moved the
same fixture at 8,968 blocks/s (13.2 MB/s) with no sanitizer finding. Core
seal/root-mirror, consensus parity, generated capability inventory, complexity,
and whitespace gates passed. Before the fix, B retained the stale slot for up
to eight seconds; after reconciliation it is recovered on B's next send tick
with zero elapsed seconds in the deterministic clock fixture.

Remaining risk: reconciliation is intentionally per-peer send-tick work and
still scans the fixed 256-slot pipeline. The measured 50,000-piece global scan
above remains cheap, but useful-delivery and timeout outcome telemetry per peer
is still absent, so adaptive peer ranking is not yet evidence-backed.

Worldstream interaction: Worldstream's current branch owns fresh-sync startup
observers, interruption gates, and telemetry overhead. It does not modify the
block-swarm scheduler surface in this slice. Recommended next investigation:
measure block-piece useful delivery, late delivery, and timeout outcomes by peer
before changing ranking or timeout policy.

## Block-swarm timeout-owner yield

The production send-tick ordering let the peer whose piece had just exceeded
the eight-second deadline reclaim that same piece immediately: the global
timeout sweep requeued it, peer-local reconciliation emptied the slot, and the
following fill loop assigned the first available piece back to the same peer.
A deterministic baseline reproduced peer A receiving piece 0 again before
healthy peer B could run.

Peer-local reconciliation now runs before the global sweep and reports whether
it expired work still owned by that peer. Such a peer receives no new pieces for
that send tick; the global sweep still releases other expired work, and the next
healthy peer can claim piece 0 immediately. This is a one-tick scheduling yield,
not a ban, score, disconnect, or timeout change. Stale slots caused by completed
or independently reassigned work remain immediately reclaimable without
triggering the yield.

After measurement: the deterministic sequence changed from A immediately
reclaiming piece 0 to A receiving no assignment and B receiving piece 0. The
real-wire loopback remained at 31,041 blocks/s (45.8 MB/s) for 2,560 blocks;
ASan/UBSan moved the same fixture at 9,146 blocks/s (13.5 MB/s) with no finding.
The broader UTXO/fast-sync group, core seal/root mirror, consensus parity,
generated capability inventory, complexity, and whitespace gates passed.

Consensus impact: none. The existing manifest hash, payload parsing, reducer,
block validation, transaction validation, PoW, and chain-selection paths are
unchanged. Remaining risk: a timed-out peer may receive unrelated work on a
later network-loop pass after healthy peers have had their turn; persistent or
adaptive deprioritization still requires per-peer delivery evidence.

Worldstream interaction: the latest Worldstream branch remains confined to
fresh-sync observers, startup interruption, and telemetry overhead, with no
block-swarm scheduler overlap. Recommended next investigation: add bounded
per-peer block-piece outcome counters and use measured useful/late/timeout
ratios before considering longer-lived scheduling weights.

## Overflow-safe swarm timeout accounting

Both snapshot-chunk and block-piece timeout sweeps subtracted signed monotonic
timestamps before comparing the result with their timeout. A future request
stamp could spuriously expire after a clock anomaly, while the full
`INT64_MIN` to `INT64_MAX` span invoked signed-overflow undefined behavior.
The legacy block downloader had already hardened the same boundary, but the
two fast-sync owners had not.

A shared elapsed predicate now rejects future timestamps and computes an
ordered elapsed distance in unsigned arithmetic. Production wrappers still
sample the same monotonic clock and retain the exact `age > timeout` threshold;
deterministic at-time entry points make both owners testable without sleeps or
wall-clock dependence.

Regression proof covers a future timestamp remaining in flight and the full
signed range expiring safely for both snapshot chunks and block pieces. The
four-group focused fast-sync suite passed, as did its ASan/UBSan run. Core
seal/root mirror, consensus parity, generated capability inventory,
cyclomatic complexity (55,551 functions), and whitespace gates passed.

Consensus impact: none. This changes only timeout arithmetic for in-memory
request scheduling; manifest verification, payload parsing, block/transaction
validation, PoW, chain selection, and reducer behavior are unchanged.

Worldstream interaction: refreshed Worldstream commit `0b29bec27` remains on
fresh-sync observers, startup interruption, and telemetry overhead, with no
overlap in swarm timeout ownership. Remaining risk: endgame comments promise
duplicate tail requests, but the current single-owner accounting cannot model
them safely and the duplicate-selection branch is unreachable. Recommended
next investigation: measure tail latency and design explicit bounded duplicate
ownership before changing that behavior.

## Idempotent block availability replacement

Every accepted `zblkbitmap` previously incremented the global per-piece
availability counters, then replaced the peer-local bitmap without removing
that peer's prior contribution. Replaying one valid advertisement could grow
selected counts without bound, and changing to a shorter bitmap left withdrawn
pieces artificially common. Because rarest-first scheduling trusts these
counters for ordering, one untrusted peer could bias work selection.

Bitmap replacement now subtracts the peer's previous set bits (with a zero
floor) and adds its new set bits (with a `UINT32_MAX` ceiling) while holding the
block-swarm mutex. The original add-only entry point delegates to the same
bounded implementation. A deterministic regression proves an identical replay
leaves every advertised count at one and a replacement withdraws all old bits
not present in the new bitmap.

The four-group fast-sync suite and the production-path real-wire block-swarm
loopback passed, as did the four-group ASan/UBSan fast-sync run; the loopback
transferred 2,560 blocks / 3,962,880 bytes at 29,748 blocks/s (43.9 MB/s).
Core seal/root mirror, consensus parity, generated capability inventory,
cyclomatic complexity (55,553 functions), and whitespace gates passed.

Consensus impact: none. Availability is only a request-order hint; every piece
still requires its manifest hash and every block follows canonical validation.
Worldstream commit `0b29bec27` remains confined to observer/startup work and
does not overlap this ownership.

Remaining risk and next investigation: disconnect currently requeues owned
pieces by peer ID but does not receive the departing peer's bitmap, so its
availability contribution persists until the swarm ends. Extend disconnect
cleanup with bounded bitmap withdrawal and a reconnect regression.

## Disconnect-safe availability ownership

Disconnect cleanup reclaimed a peer's in-flight pieces but could not withdraw
its bitmap because the API accepted only a numeric peer ID. Availability from
departed sessions therefore survived for the rest of the swarm and repeated
reconnects accumulated stale rarity evidence.

Each peer now records the exact block-swarm generation to which its bitmap was
counted. A successful swarm initialization advances a nonzero generation.
Bitmap replacement subtracts an old contribution only when generations match,
and terminal disconnect cleanup withdraws that contribution and clears the
generation in the same swarm-locked transaction that requeues owned pieces.
Repeated cleanup is idempotent; a stale peer from an earlier swarm cannot
subtract a current peer's count.

Regression proof extends bitmap replacement through complete withdrawal and
keeps the real-wire disconnect/failover test's repeated cleanup assertion. The
four-group fast-sync suite and block-swarm loopback passed; loopback transferred
2,560 blocks / 3,962,880 bytes at 31,872 blocks/s (47.1 MB/s). Core seal/root
mirror, consensus parity, generated capability inventory, cyclomatic
complexity (55,555 functions), and whitespace gates passed.

The ASan/UBSan block-swarm loopback also passed without a sanitizer finding,
moving the same fixture at 8,920 blocks/s (13.2 MB/s).

Consensus impact: none. This is bounded peer-local request-order accounting;
all manifest, payload, block, transaction, PoW, and chain validation remains
unchanged. Worldstream commit `0b29bec27` still has no scheduler overlap.

Remaining risk: bitmaps received before a swarm starts are intentionally not
retroactively counted, so their pieces tie at the neutral availability value
until a fresh advertisement. Next investigate whether manifest acceptance
should seed already-connected peer bitmaps for better rarest-first ordering.

## Overflow-safe block-manifest shape validation

The untrusted `zblkmanfst` parser bounded `num_pieces`, but calculated its
expected value with `end_h - start_h + BLOCKS_PER_PIECE` in signed 32-bit
arithmetic. A peer-supplied end height near `INT32_MAX` could overflow before
the count mismatch rejected the manifest, invoking undefined behavior in the
network receive path.

Manifest shape validation now widens both heights before subtraction, computes
the inclusive block span in `int64_t`, derives the expected piece count in
`uint64_t`, and rejects any mismatch before allocating the piece-hash array.
The existing 100,000-piece resource cap remains unchanged.

A deterministic regression covers valid one- and two-piece ranges, negative
and reversed heights, ordinary count mismatches, `INT32_MAX`, and a boundary
range whose supplied count is wrong. The production-path block-swarm loopback
passed and moved 2,560 blocks / 3,962,880 bytes at 30,268 blocks/s (44.7 MB/s).
Core seal/root mirror, consensus parity, generated capability inventory,
cyclomatic complexity (55,557 functions), and whitespace gates passed.

The ASan/UBSan block-swarm loopback passed the same overflow regression with
no sanitizer finding and moved 2,560 blocks at 8,939 blocks/s (13.2 MB/s).

Consensus impact: none. This only rejects malformed fast-sync peer metadata
before allocation; accepted manifests, hashes, payloads, blocks, transactions,
PoW, and chain selection are unchanged. Worldstream commit `0b29bec27` remains
on observer/startup work with no overlap.

Remaining risk and next investigation: other peer-controlled range calculations
in snapshot/chunk messages should receive the same explicit-width audit.

## Immediate malformed snapshot-chunk reassignment

A truncated `zchunkdata` header/body or an oversized entry count was scored but
left the advertised chunk globally `CHUNK_INFLIGHT` and in the peer-local slot.
Healthy peers could not claim it until the fixed 30-second timeout. Local
allocation failure had the same unnecessary delay.

Snapshot swarm state now has an ownership-checked requeue primitive. Malformed
responses with a decoded chunk index and local allocation failures invoke it
under the swarm mutex, clearing the peer-local slot only when that peer still
owns the chunk. A stale or malicious peer cannot revoke work reassigned to a
different source. The recovery decision was factored into small helpers so the
large wire dispatcher stayed at its existing complexity pin rather than raising
the ratchet.

The deterministic regression proves peer B cannot revoke peer A's chunk, peer
A's malformed response immediately restores `CHUNK_NEEDED`, repeated cleanup
is inert, and peer B can claim the work without elapsed time. The four-group
fast-sync suite, core seal/root mirror, consensus parity, generated capability
inventory, cyclomatic complexity (55,561 functions), and whitespace gates
passed. The same four fast-sync groups also passed under ASan/UBSan.

Consensus impact: none. Malformed or locally unbufferable data is still never
applied; valid chunks retain the existing hash, Merkle, and final UTXO
commitment checks. Worldstream commit `0b29bec27` remains on observer/startup
work with no overlap.

Remaining risk and next investigation: add a direct wire fixture for truncated
`zchunkdata`, then audit snapshot peer disconnect for immediate owned-chunk
requeue rather than timeout-only recovery.
