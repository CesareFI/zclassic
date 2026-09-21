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

## Event-driven snapshot-swarm disconnect recovery

Connman's terminal peer cleanup reclaimed legacy block-download requests and
block-swarm pieces, but not UTXO snapshot-swarm chunks. A disconnected peer's
chunk therefore remained globally `CHUNK_INFLIGHT` and unavailable to healthy
peers until the 30-second timeout sweep.

The snapshot coordinator now requeues every chunk still owned by the departing
peer during connman's existing disconnect cleanup. The operation is bounded by
the manifest chunk count, ownership checked, idempotent, and clears the dead
peer's local request slot. Other peers' in-flight chunks remain untouched.

The deterministic regression assigns three chunks across two peers, disconnects
one without advancing time, proves exactly its two chunks become immediately
available, proves repeat cleanup is inert, and proves a third peer can claim
both while the surviving peer retains its work. The four-group fast-sync suite,
the block-swarm loopback integration group, the same fast-sync groups under
ASan/UBSan, core seal/root mirror, consensus parity, generated capability
inventory, cyclomatic complexity (55,564 functions), and whitespace gates
passed.

Consensus impact: none. This changes only failed-peer scheduling state; chunk
hash, Merkle proof, snapshot commitment, block, and transaction validation are
unchanged. Worldstream remains at `0b29bec27` on startup/observer work, and its
fetched tree contains no `docs/work/NODE_COORDINATION.md`; there is no overlap.

Remaining risk and next investigation: build a direct wire-level truncated
`zchunkdata` fixture, then inspect snapshot manifest competition for peer
diversity and prompt failover when the single manifest source disappears.

## Preserve reassigned snapshot work during stale timeout cleanup

The global snapshot timeout sweep can requeue peer A's chunk and a healthy peer
B can claim it before A's next send tick. A's stale peer-local slot then saw
only `CHUNK_INFLIGHT` and unconditionally reset the chunk, revoking B's live
request and decrementing shared accounting.

Peer-local timeout cleanup now uses the same ownership-checked requeue primitive
as malformed-response and disconnect recovery. A stale slot is cleared locally,
but shared state changes only while that peer remains the recorded owner.

The deterministic regression times out A, immediately assigns the chunk to B,
then runs A's ownership cleanup without advancing time and proves B retains the
in-flight chunk and accounting. The four-group fast-sync suite passed normally
and under ASan/UBSan. Core seal/root mirror, consensus parity, generated
capability inventory, whitespace, and cyclomatic complexity passed; the latter
ratcheted `mp_snapshot_send_tick` downward from M=29 to M=27 (55,565 functions
scanned).

Consensus impact: none. Only snapshot request ownership/accounting changes;
all chunk, snapshot, block, transaction, and cryptographic validation is
unchanged. Worldstream remains at `0b29bec27` with no overlap.

Remaining risk and next investigation: add the direct truncated-wire fixture,
then audit invalid chunk-hash retry accounting for the same ownership invariant.

## Reject unowned and duplicate snapshot chunk delivery

`swarm_sync_receive_chunk` previously verified content but not request ownership.
A peer could submit a valid chunk assigned to another peer, or replay a completed
chunk, causing duplicate completion credit and incorrect in-flight accounting.
The wire handler also cleared the sender's unrelated peer-local slot after such
an unsolicited response.

Snapshot receive now requires the chunk to be `CHUNK_INFLIGHT` and owned by the
sender before hashing, applying, or changing counters. The handler clears its
peer-local request only when the delivered index matches that slot. Unsolicited,
late, and duplicate deliveries fail without modifying the legitimate owner's
work.

The deterministic regression proves a non-owner cannot alter state or counters,
the owner can complete exactly once, and a duplicate cannot increment completion
or decrement in-flight state again. The four-group fast-sync suite, the broader
13-group networking selection, and fast-sync under ASan/UBSan passed. Core
seal/root mirror, consensus parity, generated capability inventory, cyclomatic
complexity (55,568 functions), and whitespace gates passed after factoring the
checks into bounded helpers.

Consensus impact: none. The accepted snapshot content rules are unchanged; this
only enforces request ownership before existing verification and application.
Worldstream remains at `0b29bec27` with no overlap.

Remaining risk and next investigation: add a direct wire fixture covering
unsolicited and truncated `zchunkdata`, including preservation of the sender's
unrelated legitimate request slot.

## Overflow-safe peer-local snapshot timeout

The global snapshot timeout sweep used the shared bounded monotonic-elapsed
helper, but the peer-local cleanup immediately after it still subtracted two
signed 64-bit timestamps directly. Extreme clock values could overflow that
expression even though the global decision was safe.

The peer-local scheduler now uses `fast_sync_timeout_elapsed_at` as well. Its
existing deterministic boundary regression covers rollback and both `INT64`
extremes, and that regression passed under ASan/UBSan in the immediately prior
snapshot ownership slice. The four-group fast-sync suite, core seal/root mirror,
consensus parity, generated capability inventory, cyclomatic complexity (55,568
functions), and whitespace gates passed after wiring the scheduler to it.

Consensus impact: none. This is timeout arithmetic for failed-request cleanup;
validation and chain semantics are unchanged. Worldstream remains at
`0b29bec27` with no overlap.

Remaining risk and next investigation: direct wire regressions remain the next
gap, followed by snapshot manifest-source diversity under reconnect churn.

## Direct adversarial `zchunkdata` wire regression

The snapshot ownership fixes had algorithm-level coverage, but no regression
sent framed `zchunkdata` through the real P2P receiver and message dispatcher.
That left parsing, peer-local slot cleanup, reassignment, and shared accounting
untested as one system.

A deterministic two-peer loopback now activates an isolated two-chunk snapshot
swarm through test-only state seams and transports real framed messages through
`p2p_node_receive_bytes` and `msg_process_messages`. It proves an owned truncated
response becomes immediately assignable to another peer; the original peer can
hold different legitimate work; its late response cannot revoke the new owner
or clear that unrelated slot; valid delivery completes once; duplicate replay
cannot drift counters; a second owned truncation requeues immediately; and an
unsolicited response cannot claim needed work.

The block-swarm loopback group passed normally and under ASan/UBSan. The
four-group fast-sync suite and 13-group networking selection passed, as did
core seal/root mirror, consensus parity, generated capability inventory,
cyclomatic complexity (55,574 functions), and whitespace gates.

Consensus impact: none. The production parsing and validation behavior is
unchanged; the only core additions are `ZCL_TESTING` seams for isolated state
setup and observation. Worldstream remains at `0b29bec27` on complementary
startup/observer work, with no coordination file in its fetched tree.

Remaining risk and next investigation: snapshot manifest-source diversity and
reconnect churn now become the next active slice, including whether a surviving
compatible source can continue immediately after the manifest origin leaves.

## Exact snapshot manifest-source diversity under reconnect churn

Every Merkle-valid `zmanifest` peer was previously marked as a usable source
while a snapshot swarm was active, even when its height, anchor, commitment, or
chunk hashes described a different snapshot. The scheduler could consequently
request active-swarm chunks from an incompatible peer. Manifest initialization
also claimed the global active flag before taking the swarm mutex, leaving
partially initialized state observable during a competing arrival.

Manifest-source admission now runs under the swarm mutex. The first eligible
manifest initializes and activates the swarm atomically; later peers are
admitted only when every manifest identity field and chunk hash exactly matches
the active snapshot. Incompatible peers remain ineligible for chunk assignment.

The deterministic regression admits two exact-match peers, refuses a third
peer whose chunk-hash list differs, assigns work to the first peer, disconnects
it without advancing time, and proves the surviving compatible source
immediately acquires the requeued chunk with unchanged accounting. The manifest
identity unit regression, four fast-sync groups, block-swarm loopback, and the
broader 13-group networking selection passed. Block-swarm loopback also passed
under ASan/UBSan. Core seal/root mirror, consensus parity, generated capability
inventory, cyclomatic complexity (55,581 functions), and whitespace gates
passed.

Consensus impact: none. This changes only snapshot-source scheduling after the
existing manifest Merkle verification; snapshot commitments, chunk hashes,
block and transaction validity, PoW, and chain selection are unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work, and
its fetched tree contains no `docs/work/NODE_COORDINATION.md`.

Remaining risk and next investigation: direct `zmanifest` wire coverage should
exercise competing compatible and incompatible advertisements through the
parser, then the snapshot scheduler should be inspected for whether repeated
manifest churn can monopolize send ticks or retain stale source eligibility.

## Direct competing `zmanifest` wire regression

Manifest-source diversity initially had scheduler-level regression coverage,
but the wire parser, optional commitment field, Merkle reconstruction, active
swarm initialization, and source eligibility were not exercised together.

The loopback regression now sends three fully framed `zmanifest` messages
through `p2p_node_receive_bytes` and `msg_process_messages`. Two peers advertise
the same snapshot and are admitted; a third advertises a different but
internally Merkle-valid snapshot and remains ineligible. The originating peer
then disconnects, its owned chunk is immediately requeued, and the surviving
compatible peer acquires it without timeout or accounting drift. The temporary
admission test seam was removed because the regression now drives production
parsing and dispatch directly.

The block-swarm loopback passed normally and under ASan/UBSan, including the
new framed-manifest path. The 13-group networking selection, core seal/root
mirror, consensus parity, generated capability inventory, cyclomatic
complexity, and whitespace gates passed.

Consensus impact: none. This slice adds regression coverage and removes a
test-only seam; production manifest admission remains the validated scheduling
change from the preceding commit. Worldstream remains at `0b29bec27` on
complementary startup/observer work with no coordination-file overlap.

Remaining risk and next investigation: inspect repeated compatible and
incompatible manifest advertisements for CPU amplification, stale eligibility,
or send-tick monopolization, then select the next measured networking/IBD
bottleneck.

## Bound repeated snapshot-manifest work per peer

A single peer could repeatedly advertise a `zmanifest` with as many as 65,000
chunk hashes. Each message could force roughly 2 MiB of allocation, hash-array
parsing, and Merkle reconstruction even after that peer had already advertised
for the current swarm. Both compatible duplicates and internally valid but
incompatible alternatives were unbounded.

Each peer now receives two manifest parse attempts per snapshot-swarm
generation: the initial advertisement plus one corrective retry. Later messages
in that generation are discarded before allocation or Merkle work. The bounded
generation advances when a new swarm starts, including wrap-safe rollover, so a
peer becomes eligible again after completion/restart. No peer identity,
implementation version, or inbound/outbound class receives special treatment.

The framed-wire regression proves two incompatible attempts are processed, a
third compatible advertisement cannot bypass the cap, disconnect failover still
works, and the same peer can start the next generation. Block-swarm loopback
passed normally and under ASan/UBSan; the 13-group networking selection,
core seal/root mirror, consensus parity, generated capability inventory,
cyclomatic complexity (55,585 functions), and whitespace gates passed.

Consensus impact: none. The cap applies only to optional snapshot-manifest
scheduling and does not alter accepted blocks, transactions, PoW, chain rules,
or snapshot content verification. Worldstream remains at `0b29bec27` on
complementary startup/observer work.

Remaining risk and next investigation: inspect whether block-swarm manifest
advertisements have an equivalent repeated-parse amplification path, then
continue with measured peer-scheduler and IBD recovery bottlenecks.

## Bound repeated block-manifest work per peer

`zblkmanfst` had the same repeated-work exposure as snapshot manifests: each
advertisement could allocate a peer-controlled piece-hash array and rebuild its
Merkle root, with no per-peer limit after the swarm was already selected.

Block-manifest parsing now allows two attempts per peer per block-swarm
generation. Further advertisements are discarded before allocation and Merkle
work. The prospective generation is used while inactive, so flooding cannot
avoid the cap before swarm activation; ordinary new peers and the next swarm
generation retain independent budgets.

The direct framed loopback sends the same validated manifest three times,
proves only two attempts are admitted, and then completes all 2,560 blocks at
31,585 blocks/s (46.6 MB/s). The regression passed under ASan/UBSan at 9,333
blocks/s (13.8 MB/s). The 13-group networking selection, core seal/root mirror,
consensus parity, generated capability inventory, cyclomatic complexity
(55,588 functions), and whitespace gates passed.

Consensus impact: none. This bounds optional block-download metadata parsing;
header anchoring, piece hashes, block validation, transaction validation, PoW,
and chain selection remain unchanged. Worldstream remains at `0b29bec27` on
complementary startup/observer work.

Remaining risk and next investigation: profile manifest hashing at the maximum
wire-reachable piece count, then inspect block-swarm source identity and stale
eligibility across abandonment/restart generations.

## Exact block-swarm manifest source identity

Any internally valid, header-anchored `zblkmanfst` previously set
`blk_manifest_received`, even while its range, tip, Merkle root, or piece hashes
differed from the active swarm. The scheduler could then request active-swarm
piece indexes from a peer advertising different content. Swarm initialization
also checked inactivity before taking the block-swarm mutex, allowing competing
initializations to race.

Block-manifest admission is now serialized under the block-swarm mutex. The
first eligible manifest initializes and activates the swarm atomically; later
sources are eligible only when every manifest field and piece hash exactly
matches the active manifest. A new manifest attempt clears stale eligibility
before validation. Header anchoring, restart cooldown, and completed-height
seeding remain mandatory.

The unit regression covers exact manifest identity. The framed loopback starts
a 40-piece swarm, sends a different but internally Merkle-valid and
header-anchored manifest from another peer, proves that peer remains
ineligible, and then completes all 2,560 blocks from the compatible source at
31,659 blocks/s (46.7 MB/s). The same path passed ASan/UBSan at 9,373 blocks/s
(13.8 MB/s). Four fast-sync groups, the 13-group networking selection, core
seal/root mirror, consensus parity, generated capability inventory, cyclomatic
complexity (55,592 functions, dispatcher ratcheted M=170 to M=169), and
whitespace gates passed.

Consensus impact: none. This changes only optional source scheduling after
existing manifest and header-anchor validation. Block, transaction, PoW,
chain-selection, and cryptographic validation semantics are unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: verify that stale block-manifest
eligibility and availability bitmaps cannot cross abandonment and restart
generations, especially when the same TCP peer remains connected.

## Isolate block-swarm eligibility and bitmaps by generation

Connected peers retained `blk_manifest_received` and their availability bitmap
across swarm abandonment and restart. The scheduler checked neither value's
generation before assignment. A stale source flag could therefore authorize a
peer that had not advertised the new manifest, while an old all-zero or partial
bitmap could suppress useful requests in the new swarm.

Manifest admission now records the exact active generation, and send ticks
require that generation before assigning any piece. Availability bitmaps are
passed to rarest-first selection only when their recorded generation matches;
otherwise the peer is conservatively treated as having the exact admitted
manifest's full piece set until it advertises a current bitmap. A new manifest
attempt clears prior admission under the block-swarm mutex.

The framed throughput regression plants an old all-zero bitmap and proves the
new 40-piece swarm still assigns and completes all 2,560 blocks at 31,857
blocks/s (47.0 MB/s). It also forges a stale received flag with generation zero
on an incompatible peer and proves that peer receives no request. The fairness
fixture now uses a generation-aware test admission seam and retains 64/64 work
sharing. Block-swarm loopback passed under ASan/UBSan. The 13-group networking
selection, core seal/root mirror, consensus parity, generated capability
inventory, cyclomatic complexity (55,596 functions), and whitespace gates
passed.

Consensus impact: none. This changes only optional request-source and
availability scheduling. Block, transaction, PoW, chain-selection, and
cryptographic validation semantics are unchanged. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: audit bitmap message length against the
active manifest span and ensure excess/truncated bitmap bytes cannot distort
rarest-first availability accounting or consume unnecessary memory.

## Bind block availability to admitted manifest shape

Baseline: the wire handler accepted any `zblkbitmap` length from 1 through
65,536 bytes whenever a block swarm happened to be active. It did not require
the sending peer to have supplied the active manifest. A framed regression
confirmed that an unsolicited one-byte advertisement was stored and credited
against a 40-piece swarm, whose only valid bitmap length is five bytes.

Root cause: bitmap framing was bounded by a protocol-wide constant rather than
the active manifest, and source admission was not consulted. The handler now
requires the sender's manifest admission generation to equal the active swarm
generation and requires exactly `ceil(num_pieces / 8)` bytes. Admission and
shape are checked before allocation and rechecked under the swarm mutex at
installation, so a concurrent restart cannot inherit the payload. Truncated,
oversized, unsolicited, and generation-racing payloads preserve the peer's
previous valid contribution; repeated valid advertisements still replace it.

After-result and regression proof: the direct framed-wire regression rejects
an unsolicited bitmap, a declared-five-byte/truncated-four-byte payload, and a
six-byte payload; it accepts two repeated exact five-byte advertisements and
then completes all 2,560 fixture blocks at 31,463 blocks/s (46.4 MB/s). The
focused block-swarm loopback group passes normally and under ASan/UBSan; all
13 selected networking groups pass.

Consensus impact: none. The change only constrains optional peer availability
metadata used for request ordering. Every delivered block still traverses the
unchanged canonical validation path. Worldstream remains at `0b29bec27` on
complementary fresh-sync startup and observer gates, with no bitmap overlap.

Remaining risk and next investigation: inspect whether block-manifest and
bitmap peer admission is cleared consistently on every disconnect/reconnect
lifecycle, then profile the next block-swarm scheduling bottleneck.

## Bound disconnect cleanup and revoke detached peers

Baseline: block-swarm disconnect cleanup scanned all manifest pieces while
holding the global swarm mutex, even though a peer can own only its fixed
256-slot pipeline. At the accepted 100,000-piece manifest bound, each churned
connection could therefore inspect 100,000 entries. Cleanup also left the
detached node's manifest admission and pipeline slots intact; the wire fixture
proved that the same deferred node could immediately reacquire work.

Root cause: cleanup rediscovered ownership from the global piece table rather
than consuming the authoritative per-peer assignment slots, and treated node
freeing as implicit state revocation. It now visits exactly 256 slots, requeues
only entries still owned by that peer, clears every slot and request timestamp,
withdraws the current bitmap contribution, and revokes manifest admission in
the same swarm-mutex critical section. Work at the protocol maximum falls from
100,000 piece inspections to 256 bounded slot inspections (about 391x fewer).

After-result and regression proof: the real-wire disconnect regression first
assigns 40 pieces, then proves all 40 are immediately requeued, all 256 local
slots are cleared, admission generation is zero, a post-disconnect send tick
queues no work, repeated cleanup is idempotent, and the healthy peer completes
all 2,560 blocks. The focused group completes at 31,676 blocks/s (46.8 MB/s),
passes under ASan/UBSan, and all 13 selected networking groups pass.

Consensus impact: none. This changes only request ownership cleanup after a
transport disconnect; block validation and chain state are untouched.
Worldstream remains at `0b29bec27` on complementary fresh-sync observer work.

Remaining risk and next investigation: apply the same explicit admission
revocation audit to snapshot-swarm disconnects, then inspect scheduler lock
hold time and request emission under high peer counts.

## Isolate snapshot generations and make disconnect cleanup constant-time

Baseline: snapshot disconnect cleanup scanned as many as 65,000 global chunks
although each peer owns at most one, and left manifest admission metadata on
the detached node. Separately, the scheduler checked only the received flag,
not the manifest generation. Direct wire tests reproduced both consequences:
a detached node could reacquire work, and a still-connected source admitted to
an earlier swarm could receive work after another peer started a new swarm.

Root cause: the node's authoritative `swarm_inflight_chunk` and recorded
manifest generation were maintained but not used at these two ownership
boundaries. Disconnect cleanup now requeues that one exact chunk, clears its
request time, and revokes the received flag, generation, and attempt budget.
The scheduler atomically locks and admits a peer only when its recorded
generation equals the active swarm generation. Progress counts use the same
captured generation. Worst-case disconnect inspection falls from 65,000
chunks to one known owner slot.

After-result and regression proof: the framed reconnect test proves immediate
requeue, zeroed admission and request state, no detached-peer reassignment,
healthy-peer failover, and refusal to schedule an old-generation connected
peer after restart. The full block-swarm loopback group passes, including the
2,560-block transfer at 31,394 blocks/s (46.3 MB/s).

Consensus impact: none. This is snapshot request-source ownership and cleanup
only; snapshot content verification and canonical chain validation are
unchanged. Worldstream remains at `0b29bec27` on complementary startup and
observer work.

Remaining risk and next investigation: profile scheduler mutex hold time and
the full-manifest timeout sweeps under high peer counts, then bound avoidable
global scans without weakening timeout recovery.

## Refuse unsolicited block pieces before body intake

Worldstream's measured timeout profile (`f261d245d`) found a 50,000-piece
global sweep costs about 14.3 microseconds and explicitly did not justify a
more complex timeout structure, so Hetzner left that path unchanged and moved
to block-piece outcomes as recommended.

Baseline: the `zblkdata` handler checked swarm activity and cryptographic piece
identity but never checked whether the sending peer owned the request. A direct
wire regression used the production serve path to return a valid 64-block
piece before any scheduler assignment; all 64 bodies entered block intake and
the piece was credited. Duplicate responses were likewise submitted again
before only the completion counter was deduplicated.

Root cause: request ownership lived in the peer's bounded pipeline but was not
consulted at the receive boundary. The handler now requires the peer to be an
admitted source for the exact active generation and the piece index to exist in
that peer's pipeline before allocating hash storage or parsing/submitting block
bodies. A timed-out late response is refused without peer punishment because
lateness alone is not proof of malicious behavior. A later ownership-hardening
slice also requires the global piece owner to remain the sender before intake.

After-result and regression proof: the framed unsolicited response contributes
zero submitted blocks and leaves the swarm active. The duplicate regression
now proves only the two unique 64-block pieces enter intake, rather than three
submissions, while completion accounting remains exact. The final refactored
2,560-block loopback passes at 31,790 blocks/s (46.9 MB/s).
The focused group also passes under ASan/UBSan, and all 13 selected networking
groups pass.

Consensus impact: none. The gate changes only whether an unrequested transport
response is admitted to the existing canonical block-validation path; all
requested blocks retain identical validation. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: add per-peer block-swarm delivery and
timeout observations, then use measured outcomes to decide whether scheduling
should adapt without allowing peer starvation.

## Bind post-submit piece credit to the swarm generation

Baseline: block-piece handling deliberately releases the swarm mutex while up
to 64 canonical block bodies enter the bounded reducer intake. On reacquiring
the mutex it checked only swarm activity, start height, and piece count. A new
swarm with the same shape could therefore receive completion credit from the
old response. The exact-manifest source admission fix did not cover this
unlocked submission window.

Root cause: the receive path captured manifest shape but not the monotonic
swarm generation. It now captures the generation under the mutex and requires
it to remain identical before crediting the piece. The existing fail-safe path
leaves the new generation's piece needed for retry; already submitted bodies
remain subject to canonical validation and are not claimed as swarm progress.

After-result and regression proof: the block-submit fixture synchronously
restarts an exact same-manifest swarm during the unlocked callback. The old
response is logged as stale, receives no completion credit, and the subsequent
send tick requests both pieces of the new generation. The full framed suite
passes, including 2,560 blocks at 31,961 blocks/s (47.2 MB/s).

Consensus impact: none. This tightens transport completion accounting only;
the reducer and all block validity predicates remain unchanged. Worldstream
remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: expose bounded per-peer piece delivery
and timeout observations before considering any adaptive scheduling policy.

## Observe block-swarm outcomes and preserve ownership after unlocked submit

Baseline: the parallel block-swarm scheduler owned exact request slots and
timeouts but exposed no per-peer request, delivery, timeout, or latency
evidence. Inspection of the unlocked body-submit window also found that its
post-submit call ignored piece ownership: if disconnect or timeout requeued a
piece while up to 64 bodies entered the reducer, the late original response
could still be marked complete and refresh the global completion watchdog.

Root cause: `block_swarm_receive_piece` is a general state helper whose legacy
test contract permits marking a needed piece complete; it intentionally did
not enforce its peer argument. The untrusted wire boundary incorrectly used
that permissive helper after releasing its mutex. The wire path now uses a
new ownership-enforcing receive helper and updates progress only when the
same peer still owns the inflight piece. Each peer also carries atomic,
observation-only counts for requested, delivered, and timed-out pieces plus
cumulative delivery microseconds; `getpeerinfo` reports those counts and the
derived average without feeding them back into scheduling.

After-result and regression proof: a framed `zblkdata` response now invokes a
synchronous disconnect/requeue during body submission and proves that the old
owner receives no delivery credit, does not consume the needed piece, and can
request it again after readmission. Separate deterministic checks distinguish
stale-slot cleanup from a real timeout, attribute competing-peer requests,
and verify the exact `getpeerinfo` values. `block_swarm_loopback`,
`syncdiag_rpc`, all 13 focused `test_net*` groups, and the block-swarm
ASan/UBSan run pass; the final normal 2,560-block loopback measured 31,104
blocks/s (45.9 MB/s).

Consensus impact: NONE. This changes transport ownership accounting and
read-only diagnostics only. Every body still enters the canonical reducer and
all block, transaction, PoW, and cryptographic validation remain unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: gather these counters during an
isolated multi-peer sync before changing scheduler policy. Next inspect
whether one timed-out peer's zero-assignment tick and fixed global send order
provide sufficient opportunity to healthy later peers under reconnect churn.

## Reserve urgent block work from inbound-first peer ordering

Baseline: connman's message-cycle snapshot preserves peer array order and
invokes every send callback in that order. The block swarm assigned a fixed
64-piece batch per callback inside a 256-piece contiguous forward window, so
four inbound peers encountered first could own the entire urgent window before
a healthy outbound source ran. The existing timeout-owner yield protected the
next peer only after eight seconds; it did not prevent this initial starvation.

Root cause: per-peer batching bounded one peer but placed no bound on aggregate
inbound ownership. The scheduler now allows inbound peers to own at most half
of the 256-piece urgent window. It computes the allowance from the existing
mutex-protected inflight count, with no peer scan, allocation, new lock, or
implementation/version discrimination. Outbound peers retain the original
64-piece batch and one-peer 256-slot capacity; inbound-only nodes still receive
128 concurrent pieces and continue progressing.

After-result and regression proof: an ordered regression gives two inbound
peers repeated send ticks before one outbound peer. Inbound ownership stops at
128 pieces and the later outbound peer immediately receives 64; the original
multi-peer sharing, disjoint ownership, timeout yield, and outbound one-peer
capacity checks remain green. The full block-swarm loopback group passes at
31,755 blocks/s (46.9 MB/s).

Consensus impact: NONE. This changes only which compatible peer temporarily
owns a validated transport request. Wire format, piece integrity, canonical
block validation, and every consensus predicate are unchanged. Worldstream
remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: use the new per-peer counters during an
isolated multi-peer sync to measure whether the fixed 50% inbound allowance is
well utilized, then inspect block-swarm timeout ownership under repeated peer
reconnect and endpoint replacement.

## Refuse globally stale block responses before body intake

Baseline: a global timeout sweep can requeue or reassign a piece before the
old peer's own send tick reconciles its local pipeline. The response gate saw
that stale local slot and admitted the response, parsing and submitting as many
as 64 bodies before the post-submit ownership check correctly refused swarm
credit. A slow peer could therefore consume reducer and parsing capacity after
its work had already moved to a healthy source.

Root cause: pre-intake authorization required exact swarm generation and a
local pipeline slot but did not require the global piece state to remain
`CHUNK_INFLIGHT` with the same peer ID. The gate now checks all three under the
existing swarm mutex. Revoked ownership clears the stale slot and refuses the
payload without scoring the peer, allowing immediate reassignment while
avoiding untrusted body work.

After-result and regression proof: the framed wire fixture requeues piece zero
globally while deliberately retaining the old peer's local slot, then delivers
its valid response. Submitted block count remains unchanged, the stale slot is
reused on the next tick, and the distinct during-submit ownership race remains
covered. `block_swarm_loopback` passes at 31,412 blocks/s (46.4 MB/s).

Consensus impact: NONE. The change refuses a response whose transport request
ownership has already expired; every admitted block still traverses canonical
validation. Wire format, chain history, PoW, transaction validity, and
cryptographic checks are unchanged. Worldstream remains at `0b29bec27` on
complementary startup/observer work.

Remaining risk and next investigation: inspect repeated reconnect and endpoint
replacement for stale manifest admission or bitmap contributions, then use an
isolated multi-peer sync to collect the new delivery/timeout counters.

## Reclaim orphaned block ownership across reconnect churn

Baseline: disconnect cleanup removed a source's availability bitmap and
requeued only pieces still represented in its bounded local pipeline. Global
piece ownership is authoritative, however, so an interrupted accounting
transition could leave an in-flight piece owned by a removed peer but absent
from those slots. That piece remained unavailable to healthy sources until
the eight-second timeout sweep.

Root cause and fix: the terminal disconnect boundary assumed local and global
ownership could never diverge. After clearing the normal pipeline, it now
performs one bounded scan of the active manifest and requeues any remaining
piece whose exact owner is the disconnected peer. This work occurs only on
disconnect, never on the send/receive hot path; manifest shape validation caps
the scan at 100,000 pieces.

After-result and regression proof: the wire fixture assigns 64 normal pieces
to a peer, creates one global-only orphan, and advertises all 65 pieces in its
availability bitmap. Disconnect immediately requeues all 65 and reduces
availability from one source to zero. A replacement session is admitted over
the wire, restores availability to exactly one, and its disconnect returns it
to zero before the surviving peer downloads all 4,160 bodies. The focused
`block_swarm_loopback` group passes.

Consensus impact: NONE. This changes only transport ownership cleanup after a
peer session ends. Block parsing, hashes, canonical reducer validation, chain
history, PoW, transaction rules, and cryptographic semantics are unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: validate that per-peer timeout
telemetry remains attributed to the actual owner when another peer's send tick
runs the global orphan-timeout sweep first, then collect counters in an
isolated multi-peer sync.

## Keep block timeout attribution with the owning peer

Baseline: every peer send tick first reconciled that peer's local pipeline and
then ran a global timeout sweep. In fixed connection order, an earlier healthy
peer could therefore expire a later slow peer's pieces. Reassignment worked,
but the slow owner's timeout counter remained zero and its intended one-tick
yield was bypassed, obscuring the peer responsible for repeated stalls.

Root cause and fix: the global sweep duplicated owner-local timeout recovery
at the same deadline without access to the owning peer's accounting. Exact
owners retain the eight-second deadline; the global sweep is now a second-
window, 16-second backstop for a connected global-only orphan. Terminal
disconnect cleanup separately scans authoritative ownership immediately, and
the completion-silent watchdog remains the whole-swarm fallback.

After-result and regression proof: two peers first receive disjoint 64-piece
batches. The first owner's pieces are deterministically aged; the second peer's
tick leaves its counter and ownership intact. The first peer's own tick then
records all 64 timeouts and yields rather than immediately retaking them.
`block_swarm_loopback` passes, including disconnect-orphan, wire-response,
fairness, and healthy-peer reassignment coverage.

Consensus impact: NONE. This changes only transport timeout scheduling and
observation. Validation and serialization paths are untouched. Worldstream is
still `0b29bec27`, focused on complementary startup/observer acceptance.

Remaining risk and next investigation: run the broader networking gates, then
measure the exposed requested/delivered/timeout counters during an isolated
multi-peer synchronization or, if no consenting fast-sync peer is available,
extend the deterministic scheduler fixture to quantify sustained slow-peer
rotation without live-network dependence.

## Make timed-out snapshot owners yield to healthy sources

Baseline: the UTXO snapshot scheduler ran its global 30-second timeout sweep
before examining the current peer. On the slow owner's tick, the sweep changed
its chunk to needed, owner-local requeue no longer matched, and the same peer
immediately assigned itself that chunk again. A lone slow peer encountered
first could repeat this cycle and starve an already-admitted healthy source.

Root cause and fix: global orphan recovery and exact-owner timeout recovery
shared a deadline and assignment path. The scheduler now requeues the exact
owner first, records that it timed out, and suppresses assignment to it for
that tick. The global orphan sweep remains bounded at a separate 60-second
backstop, while disconnect still requeues immediately.

After-result and regression proof: the direct manifest-wire reconnect fixture
admits two sources, deterministically ages the current owner's chunk, and runs
that owner's production send tick. The owner releases the chunk and emits no
new request; the healthy replacement source then owns and requests it on its
next tick. The full `block_swarm_loopback` group passes, including malformed,
duplicate, late, disconnect, generation, and ownership cases.

Consensus impact: NONE. Snapshot object verification, roots, install policy,
block/transaction validity, and all cryptography are unchanged. This is only
peer scheduling after a monotonic transport timeout. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: add explicit UTXO-swarm timeout and
delivery counters for operator visibility only if live or fixture evidence
shows snapshot stalls remain hard to attribute; otherwise inspect header
source rotation after repeated empty partial responses.

## Restore validated header-range rotation on the current branch

Baseline: inspection of the current Hetzner branch found that the validated
header-range recovery series remained preserved only on
`fix/bootstrap-after-peer-discovery-current`; neither this branch nor current
`origin/main` contained it. Consequently an empty, terminal, or disconnected
range source could retain its span until timeout, partial continuations could
lose their stop boundary, progress did not renew the deadline, and a lower-tip
peer tick could shrink the shared target.

Root cause and fix: branch development had diverged after those six commits.
Their final combined behavior was applied onto the current networking branch
after a three-way applicability audit. The only overlap was connman's newer
snapshot/block-swarm disconnect cleanup; it was preserved and the header-span
release was added alongside it. Empty/terminal replies and disconnect now
release ownership immediately, partial batches preserve the assigned stop,
accepted progress renews the monotonic deadline, and planning retains the
highest connected fast-peer target regardless of tick order.

After-result and regression proof: `header_range_sched` passes its direct
empty-response, disconnect, continuation-stop, progress-renewal, stable-target,
timeout-reassignment, and cross-peer-sweep cases. `sync_service` and
`snapshot_sync_service` pass, including the terminal-batch decision contract.
The direct `process_headers_adversarial`, both header-sync groups, all three
getheaders serve groups, and all 13 networking groups also pass.
The original six commits remain preserved on their source branch; this slice
integrates their audited net effect without merging unrelated history.

Consensus impact: NONE. Header acceptance, PoW, checkpoints, chain selection,
serialization, block/transaction validity, and cryptography are unchanged.
This changes only request ownership and source rotation. Worldstream remains
at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: add a production-wiring regression that
binds a range span to a peer, drives a malformed/truncated headers response
through the dispatcher and terminal disconnect cleanup, and proves another
source can claim the span without waiting for its deadline.

## Pin malformed-header terminal ownership cleanup

Baseline: the adversarial wire fixture proved that a truncated `headers`
payload was rejected without block-tree mutation, while the range scheduler
fixture separately proved that disconnect released a peer's span. Nothing
joined those behaviors around the production-global scheduler, leaving the
ownership boundary at the parser/connman handoff unpinned.

Root cause and fix: this was a regression-coverage gap, not a runtime defect.
The wire fixture now assigns a real global range span before delivering a
truncated two-header response. It proves the parser preserves attribution,
the terminal disconnect hook releases exactly once, and a healthy peer
immediately reclaims the identical span without waiting for its deadline.

After-result and regression proof: `process_headers_adversarial` passes the
new source-assignment, malformed-wire rejection, ownership-preservation,
single-release, and immediate-reassignment assertions together with its
existing block-tree and peer-penalty checks.

Consensus impact: NONE. This slice changes tests and coordination evidence
only. Worldstream remains at `0b29bec27` on complementary fresh-sync observer
and startup-interrupt acceptance work.

Remaining risk and next investigation: inspect snapshot manifest-source
diversity under reconnect churn, especially whether session replacement can
leave an admitted source slot attributed to a dead endpoint generation.

## Reclaim authoritative snapshot ownership across reconnect churn

Baseline: snapshot terminal cleanup requeued only the chunk named by the
disconnecting peer's local `swarm_inflight_chunk`. A deterministic real-wire
manifest fixture cleared that local field while retaining the global owner;
disconnect then returned zero and left the chunk in flight until timeout.

Root cause and fix: cleanup trusted a lossy peer-local cache instead of the
bounded global scheduler table. It now calls the existing
`swarm_sync_peer_disconnected` primitive, scanning the authoritative manifest
chunk table and reclaiming every chunk owned by that peer before clearing its
admission state.

After-result and regression proof: the pre-fix `block_swarm_loopback` fixture
failed at the disconnect assertion. It now passes with local ownership erased,
global ownership reclaimed immediately, and the already-admitted healthy
manifest source taking the same chunk on its next send tick. The fixture also
retains incompatible-manifest refusal and timeout-yield coverage.

Consensus impact: NONE. Snapshot content hashes, Merkle/root checks, install
policy, chain validation, serialization, PoW, and cryptography are unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: test a genuinely new peer object after
reconnect (not only a reset existing object), then inspect whether bounded
manifest-attempt state can incorrectly exclude a valid replacement source.

## Keep snapshot manifest attempt limits session-local

Baseline and root cause: manifest attempts are intentionally capped at two
per peer object and swarm generation. The reconnect fixture previously reused
a reset object, so it did not prove that an endpoint whose old session spent
both attempts on incompatible manifests could return in a fresh session as a
valid source. Code inspection showed the counters live on `p2p_node`, but the
session boundary lacked direct wire-level proof.

Fix and after-result: the real-wire fixture now creates a second peer object
for the same endpoint, exhausts the predecessor's attempt budget, and sends
the exact active manifest on the new session. The replacement is admitted on
attempt one and its terminal cleanup is independent. `block_swarm_loopback`
passes together with the existing incompatible-source and generation gates.

Consensus impact: NONE. This is deterministic transport regression coverage
only. Worldstream remains at `0b29bec27` on complementary startup/observer
work.

Remaining risk and next investigation: inspect snapshot chunk assignment
fairness when many admitted sources compete, especially whether fixed node
iteration order lets one fast source repeatedly monopolize newly needed
chunks after completions or timeouts.

## Bound snapshot chunk assignment scans

Baseline: `swarm_sync_assign_chunk` restarted at chunk zero for every request.
Assigning N fresh chunks therefore inspected N(N+1)/2 states—about 2.1
billion probes at the 65,000-chunk manifest cap—and every peer tick rescanned
the whole table when all chunks were already complete, failed, or in flight.

Root cause and fix: the scheduler retained no next-needed position. It now
keeps a bounded cursor, returns in O(1) when counters prove every chunk is
accounted for, and moves the cursor directly to a lone retry. Batched timeout
or disconnect requeues retain the lowest reclaimed index, preserving existing
deterministic assignment order.

After-result and regression proof: the ten-chunk direct fixture now measures
exactly ten probes for ten sequential assignments instead of 55, zero extra
probes for a fully-accounted request, and one probe to reclaim a directly
requeued chunk. The first implementation exposed and then preserved the
existing lowest-index disconnect ordering. All four `fast_sync` groups and
the real-wire `block_swarm_loopback` group pass.

Consensus impact: NONE. This changes only selection among already-needed
snapshot transport chunks. Content hashes, Merkle verification, snapshot
application, chain rules, serialization, PoW, and cryptography are unchanged.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: expose the bounded probe count in sync
observability only if field measurements need it; otherwise inspect failed-
chunk terminal handling, because five verification failures currently leave
the swarm active but permanently unable to satisfy its completion predicate.

## Prevent bad sources from exhausting snapshot chunks

Baseline: a chunk accumulated one global retry for every hash-mismatching
source. The fifth malicious delivery changed it to `CHUNK_FAILED`; no peer
could request it afterward, while the active swarm could never satisfy its
completion predicate. The deterministic regression reproduced this with five
distinct bad owners followed by one healthy owner.

Root cause and fix: remote integrity failures and local database-apply failures
shared one terminal retry budget. Hash mismatches now remain strictly
untrusted-peer events: the observation counter saturates, peer scoring still
penalizes each sender, and the exact manifest-bound chunk remains needed for
another source. A subsequently hash-valid delivery resets the independent
local apply budget before any database write.

After-result and regression proof: the pre-fix `fast_sync` group failed when
the fifth bad source terminalized the chunk. It now proves all five deliveries
fail verification, none increments `chunks_failed`, source six owns the same
chunk and completes it, and the full four-group fast-sync plus real-wire
`block_swarm_loopback` suites pass.

Consensus impact: NONE. No received bytes bypass SHA3 verification, peer
penalties remain, and snapshot application and final-root verification are
unchanged. Worldstream remains at `0b29bec27` on complementary startup and
observer work.

Remaining risk and next investigation: coordinate terminal local apply-error
recovery with Worldstream's storage ownership; a safe fallback must explicitly
handle partially applied derived UTXO rows before releasing the active swarm.

## Release malformed block-piece ownership immediately

Baseline: after confirming that a peer owned an in-flight `zblkdata` piece,
truncated hash arrays, malformed payload bodies, and invalid headers were
scored but left both global ownership and the peer-local pipeline slot intact.
The deterministic framed-wire regression showed the next send tick emitted no
replacement request, forcing historical-body backfill to wait for timeout.

Root cause and fix: early parser exits bypassed the ordinary piece completion
and timeout cleanup paths. A single bounded helper now requeues the piece only
when that peer remains its authoritative owner and clears every matching local
pipeline slot. Header, hash-array, and payload truncation paths call it before
returning; unsolicited or already-reassigned responses cannot revoke another
peer's ownership.

After-result and regression proof: the pre-fix `block_swarm_loopback` group
failed because no request followed a complete but truncated `zblkdata` frame.
It now observes one immediate replacement request, then delivers the retained
valid response and completes normally. Duplicate, late-owner, disconnect,
integrity-abandonment, timeout-yield, manifest-anchor, and throughput cases
remain green.

Consensus impact: NONE. Malformed data is still rejected and scored; valid
block bodies still traverse normal parsing and the canonical reducer.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: exercise the malformed block-payload
branch (valid hash list but truncated serialized body) with the same immediate
reassignment assertion, then inspect whether request-send failures similarly
leave authoritative ownership waiting for timeout.

## Pin malformed block-body ownership recovery on the wire

Baseline and root cause: the ownership-release fix covered payload parser
failure, but its regression stopped before the advertised hash array. A future
change could preserve hash-truncation recovery while regressing the distinct
serialized-body branch without a direct wire failure.

Fix and after-result: the loopback fixture now sends an owned `zblkdata` with
a complete header and hash list, followed by a CompactSize body length whose
advertised byte is absent. The parser rejects and scores it, the owner is
released, and the next send tick emits exactly one replacement request before
the retained valid response completes the swarm.

Regression proof: `make -j2 t-fast ONLY=block_swarm_loopback` passes all wire,
duplicate, late-owner, disconnect, integrity, timeout, anchoring, and
throughput cases. Consensus impact: NONE; this adds test coverage only.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: inspect request construction and queue
failure paths for assignments that acquire authoritative ownership before the
request is durably queued, forcing avoidable timeout recovery.

## Roll back block ownership when request enqueue fails

Baseline: with a peer send queue at its enforced 64 MiB hard ceiling, one
scheduler tick attempted and refused 64 `zblkreq` frames, yet recorded all 64
pieces as requested and authoritatively owned by the disconnecting peer. No
request reached the wire, so healthy sources could not claim the pieces until
timeout or disconnect teardown.

Root cause and fix: `push_block_piece_request` discarded the bounded queue's
failure result, while the caller committed its pipeline and request metric
before enqueue. It now returns enqueue status. On failure the scheduler
requeues that piece only if this peer still owns it, clears the matching local
slot, leaves the successful-request metric unchanged, and stops the batch.

After-result and regression proof: the pre-fix loopback regression failed with
64 false request credits and occupied slots. It now observes one refused send,
zero credits, an empty failed-peer pipeline, and immediate assignment of the
released work to a healthy peer. The complete block-swarm loopback group,
including throughput, peer fairness, timeout, disconnect, duplicate, late,
malformed, integrity, and anchoring cases, passes.

Consensus impact: NONE. This changes transport request ownership only; block
bodies still traverse the canonical parser and reducer. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: the analogous snapshot chunk request
helper also discards bounded send-queue failure after claiming its single
global chunk; reproduce and close that ownership gap without conflating the
two scheduler lifecycles.

## Requeue snapshot chunks after request enqueue failure

Baseline: a snapshot peer at the 64 MiB send-queue ceiling claimed chunk zero
globally and locally even though its `zchunkreq` was refused. The framed-wire
regression observed one in-flight chunk and no outbound request, leaving other
manifest-compatible peers blocked until timeout or disconnect teardown.

Root cause and fix: both initial manifest admission and ordinary snapshot send
ticks ignored `p2p_node_end_message` failure. Chunk request construction now
returns queue status; refusal requeues only the exact current owner's chunk and
clears its local request timestamp/index. The locked scheduler wrapper drops
the swarm mutex during queue work and reacquires it before continuing.

After-result and regression proof: the pre-fix loopback case failed with
`swarm_inflight_chunk == 0` and global `CHUNK_INFLIGHT`. It now observes no
queued frame, no peer-local owner, and global `CHUNK_NEEDED`, after which the
healthy peer immediately claims the same chunk. All existing truncated,
unsolicited, duplicate, late, reconnect, timeout, and source-diversity wire
cases pass.

Consensus impact: NONE. This is transport ownership cleanup; snapshot content
and proofs retain their existing validation. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: audit other request helpers that ignore
the common bounded-queue result, prioritizing header/body IBD requests whose
accounting is committed before enqueue and can starve healthy peers.

## Release unsent parallel header ranges

Baseline and root cause: `msg_try_range_parallel_getheaders` assigned a
checkpoint-bounded span before calling `push_getheaders_span`, whose void API
discarded serialization and bounded send-queue failure. A non-draining peer
could therefore own a range for the full deadline even though no request was
queued, delaying another healthy header source.

Fix: `push_getheaders_span` now reports whether the framed request entered the
peer queue. The range driver releases only that peer's assigned span on failure
and returns to the ordinary header path. A small helper contains send/release
and observability together, preserving the existing complexity ratchet.

After-result and regression proof: the adversarial header regression fills the
peer queue to its hard cap and observes a false result for the refused span
request. `process_headers_adversarial` and all 14 pure header-range scheduler
cases pass, including empty, truncated, disconnect, timeout, cross-peer sweep,
continuation, and reassignment behavior.

Consensus impact: NONE. Header parsing, PoW, chain selection, and validity are
unchanged; this only frees transport ownership for an unsent request.
Worldstream remains at `0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: checkpoint-header fetch and
header-serve repair use the same now-observable send result but still consume
their retry throttle when enqueue fails; make those isolated retry gates
failure-aware without changing range scheduling.

## Preserve header-repair retry eligibility after enqueue failure

Baseline and root cause: checkpoint-header fetch and missing-solution repair
claimed their global retry timestamp before enqueue. Even after span sends
became failure-aware, a refused request consumed the full retry interval and
prevented another healthy peer from trying immediately.

Fix: each sender conditionally restores the timestamp it claimed when
`push_getheaders_span` reports failure. The compare-and-swap rollback cannot
overwrite a newer claimant. Header-repair send/rollback/logging lives in a
small helper so the existing complexity ratchet does not grow.

After-result and regression proof: the serve-fallback regression first drives
a repair request into a full 64 MiB peer queue, then invokes a healthy peer at
the identical monotonic timestamp. Pre-fix the healthy request was throttled;
it now queues immediately while retaining the immutable three-header span and
partial-progress behavior. `getheaders_serve_fallback` passes.

Consensus impact: NONE. This changes retry timing for unsent header requests;
all header reconstruction, hash binding, Equihash, PoW, and persistence checks
remain unchanged. Worldstream remains at `0b29bec27` on complementary
startup/observer work.

Remaining risk and next investigation: add the same direct failure/retry proof
for compiled-checkpoint header capture, then inspect ordinary `getheaders` and
legacy block-request accounting for discarded queue failures.

## Pin checkpoint-header enqueue failover directly

Baseline and risk: checkpoint-header throttle rollback shared the repaired
implementation but lacked a direct test with its required parent/target index
shape. A future change could preserve missing-solution repair while regressing
the one hash-pinned checkpoint request needed by a fresh seeded node.

Fix and after-result: the checkpoint repair fixture now builds the real
parent-linked target, arms the exact target hash, refuses the first request at
the 64 MiB queue ceiling, and invokes a second eligible peer at the identical
monotonic timestamp. The healthy peer immediately queues the bounded
parent-to-checkpoint `getheaders` request.

Regression proof: `checkpoint_header_solution_repair` passes the new enqueue
failover plus wrong-hash refusal, frozen Equihash/PoW refusal, hash-pinned
persistence, PASS-record creation, capture, consume, and compiled-arm cases.
Consensus impact: NONE; test coverage only. Worldstream remains at
`0b29bec27` on complementary startup/observer work.

Remaining risk and next investigation: inspect ordinary `getheaders` and
legacy `getdata` block-request accounting for discarded bounded-queue failures,
starting from sites that mark peer/request state before message finalization.

## Legacy getdata enqueue-failure reassignment

The legacy body scheduler assigned queued blocks in the download manager
before serializing and enqueuing `getdata`, but ignored
`p2p_node_end_message()` failure.  A peer whose bounded send queue had reached
the hard ceiling therefore owned blocks it was never asked for, suppressing
healthy sources until disconnect cleanup or timeout.  The deterministic
two-peer baseline reproduced one stale in-flight owner and an empty queue
after the wire enqueue was refused.

Serialization or send-queue failure now immediately settles that disconnect
in the download manager.  Requested telemetry is emitted only after the frame
is actually queued.  The direct message-loop regression fills peer A's send
queue, proves A retains no ownership, then proves peer B owns the exact block
on its immediately following send tick.  No timeout or wall-clock wait is
involved.

Consensus impact: NONE.  This changes only volatile P2P request ownership
after a request failed to reach the wire; block parsing, validation, PoW,
chain selection, transaction semantics, and serialization are unchanged.

Worldstream interaction: refreshed Worldstream head `5297c58f4` remains on
download timeout arithmetic and complementary observer/startup work; it does
not change this legacy message-queue ownership boundary.  Remaining risk:
other assign-before-send paths should continue to be audited for ignored
enqueue results.  Recommended next investigation: snapshot manifest-source
diversity and ownership under reconnect churn.

## Snapshot negotiation followup failover

The real-wire reconnect/diversity fixture already proved exact-manifest
multi-source admission, incompatible-source attempt bounds, same-endpoint new
sessions, authoritative disconnect cleanup, timeout-owner yield, and swarm
generation isolation.  Its missing boundary was earlier: accepting a snapshot
offer committed `serving_peer_id` and entered `SNAPSYNC_NEGOTIATING` before
the FlyClient challenge or snapshot request was queued.  A non-draining peer
could refuse that bounded enqueue while leaving every replacement offer busy
until the negotiation watchdog fired.

All requester followups now share one checked enqueue path.  Encoding or queue
failure resets the unserviceable negotiation, clears its serving-peer owner,
returns ordinary sync to header download, and avoids claiming a challenge was
sent.  The deterministic two-node wire regression fills the selected source's
send queue, delivers a valid `zsnapshot`, observes the real challenge refusal,
and proves source selection is immediately IDLE with no serving owner.

Consensus impact: NONE.  Snapshot offer validation, FlyClient verification,
UTXO commitment verification, activation containment, block/transaction
validation, PoW, and chain selection are unchanged.  The existing honest and
tampered full-transfer cases remain green.

Worldstream interaction: Worldstream `5297c58f4` owns download-timeout
arithmetic and does not overlap snapshot negotiation transport.  Remaining
risk: a source that disconnects after a followup was successfully queued can
still leave negotiation or receive state occupied until watchdog recovery.
Recommended next investigation: add ownership-checked terminal-disconnect
notification without doing database cleanup under connman's peer-list lock.

## Snapshot source disconnect ownership release

Baseline and root cause: after a snapshot followup was successfully queued,
connman could remove the serving peer without notifying the snapshot service.
The service retained `serving_peer_id` in NEGOTIATING or RECEIVING, so healthy
replacement offers remained busy until the snapshot watchdog expired.

Fix and after-result: connman's terminal-removal pass now records removed peer
IDs while holding `cs_nodes`, then invokes the message-processor lifecycle
callback only after releasing that lock.  The callback releases a snapshot
session only when the disconnected ID still owns it.  Ownership is closed
under the snapshot-service lock before rollback/discard work, preventing a
concurrent replacement session from being erased and avoiding database work
under the peer-list lock.  An active receive returns ordinary sync to header
download immediately.

Regression proof: `test_snapshot_sync_service` proves that an unrelated peer
disconnect preserves the owner, while the exact negotiating and receiving
owners reset to IDLE and the latter resumes header sync.  The full honest,
tampered, and bounded-enqueue `test_snapshot_serve_loopback` wire cases remain
green.

Consensus impact: NONE.  Only volatile source ownership and transport
lifecycle cleanup change; snapshot content verification, activation
containment, block/transaction validation, PoW, and chain selection are
unchanged.

Worldstream interaction: refreshed Worldstream head `5297c58f4` remains on
download-timeout arithmetic and does not overlap snapshot source lifecycle.
Remaining risk: concurrent disconnect and replacement-offer churn should be
exercised over the real connman socket lifecycle.  Recommended next
investigation: add a real-reactor reconnect regression, then inspect manifest
source diversity under repeated reconnects.

## Monotonic swarm progress diagnostics

Baseline and root cause: snapshot-chunk and block-piece swarm progress output
used wall-clock seconds for its five-second cadence even though ownership,
timeouts, restart cooldown, and stall recovery already use monotonic time.  A
backward civil-clock adjustment could therefore suppress the only periodic
peer/inflight diagnostic until wall time caught up, obscuring an IBD stall.

Fix and after-result: both progress cadences now initialize and compare
monotonic seconds through one bounded helper.  Backward monotonic anomalies
fail closed without signed underflow; the next completed interval re-arms the
cadence normally.  Scheduling, timeout, and request ownership are unchanged.

Regression proof: `test_block_swarm_loopback` drives the exact five-second
boundary, large backward and forward civil-clock jumps, a monotonic anomaly,
and a fresh interval after publication.  The complete snapshot `zchunkdata`,
manifest reconnect/diversity, block-swarm transfer, timeout, disconnect, and
integrity suite remains green.

Consensus impact: NONE.  This changes diagnostic emission timing only; wire
messages, validation, PoW, chain selection, and all request deadlines retain
their existing semantics.  Worldstream `5297c58f4` remains complementary on
download-timeout arithmetic.  Remaining risk and next investigation: exercise
the snapshot-owner finalization callback through the real connman reactor,
including repeated disconnect/reconnect churn and callback lock ordering.

## Empty-reactor terminal peer cleanup

Baseline and root cause: the real connman socket-handler regression initially
could not observe `finalize_node` at all.  When all remaining peers already had
invalid/closed sockets, the reactor built an empty poll set, slept, and
`continue`d before its terminal-removal pass.  On an otherwise socket-idle node
those disconnected peers—and their snapshot ownership—could therefore remain
published indefinitely rather than merely until the next 50 ms reactor tick.

Fix and after-result: the empty reactor retains its bounded 50 ms sleep but now
falls through the same timeout and terminal-cleanup phase as a nonempty poll
set.  A test-only launcher runs the production socket-handler thread without
DNS or dialer threads.  Its callback observes exactly one peer ID, successfully
acquires `cs_nodes`, and sees the peer removed, proving finalization occurs
after the peer-list lock is released.  The launcher joins and restores the
process-global stop state so later tests remain isolated.

Regression proof: `test_connman_addnode_fallback` reproduces the original
empty-poll failure using an invalid-socket disconnected peer, then proves
bounded removal, exactly-once finalization, callback lock ordering, and no
cross-test stop-state leak through the following fixed-seed case.

Consensus impact: NONE.  This changes only terminal P2P lifecycle cleanup;
wire parsing, snapshot verification, block/transaction validity, PoW, and
chain selection are unchanged.  Worldstream `5297c58f4` remains complementary
on download-timeout arithmetic.  Remaining risk and next investigation:
exercise repeated invalid-socket reconnect generations and verify each session
finalizes once without retaining peer or snapshot ownership state.

## Reconnect-generation terminal cleanup regression

Baseline and root cause: the empty-reactor regression qualified only one peer
generation, leaving repeated disconnect/reconnect lifecycle reuse unobserved.
The production node assigns each session a distinct peer ID, and all ownership
release callbacks are keyed by that ID; a missed or duplicate callback across
generations could therefore retain old snapshot ownership or release a newer
session's work.

Fix and after-result: the real socket-reactor fixture now drives three
successive invalid-socket generations through independent start/join cycles.
It proves each distinct peer ID is finalized exactly once, every callback runs
outside `cs_nodes`, and the peer table is empty after every generation.  No
production behavior changed.

Regression proof: `test_connman_addnode_fallback` passes the three-generation
reactor sequence and the later fixed-seed case, also proving that each joined
cycle restores the process-global stop state.  Consensus impact: NONE.
Worldstream `0b29bec27` remains focused on fresh-sync startup interruption and
observer coverage, with no overlap.  Remaining risk and next investigation:
measure snapshot source selection under larger compatible-source reconnect
churn, especially whether one rapidly reconnecting endpoint can crowd out
diverse stable sources without violating the bounded manifest table.

## Snapshot inbound-source reservation

Baseline and root cause: a four-chunk deterministic scheduler fixture showed
that three admitted inbound peers encountered first claimed three chunks before
the healthy outbound source ran.  Snapshot assignment had no counterpart to
the block swarm's inbound ceiling, so sufficiently many slow inbound sources
could own every needed chunk and make outbound recovery wait for the full
chunk timeout.

Fix and after-result: simultaneous inbound-owned snapshot work is now bounded
to half of the manifest's chunks (with one permitted for a one-chunk manifest).
Outbound sources retain immediate work regardless of connman's stable peer
iteration order.  The ceiling counts only current in-flight work, so delivery,
disconnect, or timeout immediately restores inbound capacity and inbound-only
sync continues rather than deadlocking.

Regression proof: `test_block_swarm_loopback` first failed with three inbound
requests in the four-chunk window.  It now proves two inbound assignments, an
immediate churn/requeue replacement by the waiting inbound source, and an
immediate outbound assignment.  Existing direct-wire truncated, unsolicited,
duplicate, late-response, disconnect, timeout, and integrity cases remain in
the same group.  Consensus impact: NONE; only request ownership changes, while
snapshot hashes, content verification, chain validation, PoW, and activation
are unchanged.  Worldstream `0b29bec27` remains focused on fresh-sync startup
interruption and observers.  Remaining risk and next investigation: measure
whether legacy block-download peer selection similarly lets inbound sources
consume the bounded in-flight window ahead of faster outbound peers.

## Legacy block-download outbound reservation

Baseline and root cause: a production-entry regression queued the complete
4,096-block IBD window and drove inbound peers through
`syncsvc_assign_peer_blocks`.  Before correction they consumed the entire
window, leaving a healthy outbound source with zero immediate work.  The
download manager tracked peer bandwidth and loopback class, but not connection
direction, so its locked global-cap calculation could not preserve peer-source
diversity.

Fix and after-result: each active download slot now records whether its owner
was inbound when assigned.  Under the manager lock, an inbound assignment is
limited to half the current dynamic global window; outbound assignments retain
the other half.  Direction changes affect new work only, preserving exact
ownership of existing slots.  Receive, timeout, and disconnect settlement free
capacity through the existing capacity generation, so inbound-only sync keeps
moving rather than deadlocking.  Slot census and cap calculation were split
into helpers, reducing `dl_assign_to_peer` complexity from 90 to 86.

Regression proof: `test_sync_service` first failed after inbound peers exceeded
2,048 assignments.  It now proves the half-window ceiling, immediate one-slot
inbound reuse after a body settles, and immediate outbound assignment.  The
download, contention, speed-contract, and always-sync restart/chaos groups
remain green.  Consensus impact: NONE; this changes only request scheduling
and records no persistent or wire-visible state.  Block parsing, validation,
PoW, chain selection, and transaction rules are unchanged.  Worldstream
`0b29bec27` remains focused on fresh-sync startup interruption and observers.
The at-tip unsolicited-announcement path now records peer direction before
`dl_mark_requested`, and that locked direct-request path enforces the same
half-window ceiling.  Its regression proves 512 inbound direct requests fill
only half the normal 1,024-slot window while an outbound request remains
immediately admissible.  Remaining risk and next investigation: quantify the
extra active-slot census cost under a saturated IBD window and, if material,
replace repeated scans with explicitly verified incremental counters.

## Getheaders enqueue-failure retry preservation

Baseline and root cause: the periodic header-sync loop recorded a peer's
`last_getheaders_time` before serializing or queueing the request.  When a
non-draining peer had filled its bounded send queue, `p2p_node_end_message`
refused the frame but the timestamp still suppressed another attempt for the
full 10--600 second sync/backoff interval.  No `getheaders` request had reached
the wire during that delay.

Fix and after-result: ordinary and anchored `getheaders` helpers now return the
actual bounded-queue result, as the range-parallel helper already did.  The
periodic loop advances the throttle only after either the range request or its
ordinary fallback was queued successfully.  Serialization, locators, request
intervals, and response handling are unchanged.

Regression proof: the production `msg_send_messages` fixture fills peer A's
send queue to the hard ceiling and proves its timestamp remains zero after the
refusal, then drives peer B through the same path and proves a real queued frame
advances the timestamp.  The existing getdata enqueue-failure reassignment case
remains adjacent and green.

Consensus impact: NONE.  This changes only volatile retry accounting after a
request failed to enter the P2P send queue.  Header validation, checkpoints,
PoW, chain selection, serialization bytes, and transaction validity are
untouched.  Worldstream `0b29bec27` remains focused on fresh-sync startup
interruption and observer coverage, with no overlap.  Remaining risk and next
investigation: audit the header-stall inbound fallback action itself; it can set
the outer send intent while the independently planned periodic action remains
empty, so prove that an inbound-only stalled node actually emits a request
before changing that path.

## Inbound-only header-stall request planning

Baseline and root cause: the header-stall fallback predicate admitted an
inbound peer and set the send loop's outer `should_sync` flag, but the ordinary
periodic planner ran afterward and reset the action to empty because inbound
peers are deliberately excluded outside a stall.  `exec_getheaders_action`
therefore received `should_send=false`; an inbound-only node could announce
fallback recovery without putting any `getheaders` request on the wire.

Fix and after-result: one pure planner now produces the ordinary periodic
action first, then explicitly creates the same tip-anchored action when the
stall fallback admits a peer.  The send loop consumes that single action and
retains queue-success timestamp accounting.  Normal inbound peers remain
ineligible, while outbound planning is unchanged.  Removing the duplicated
branch reduced `msg_send_messages` complexity from 114 to 111 and the ratchet
was lowered accordingly.

Regression proof: the header-stall group now asserts the planner—not merely
the lower-level predicate—returns a sendable action for an active inbound peer
during a stall.  Its normal-inbound refusal and outbound control cases remain
green.  Consensus impact: NONE; this changes only selection of a compatible
peer for an ordinary `getheaders` request.  Header validation, checkpoints,
PoW, chain selection, wire serialization, and transaction rules are untouched.
Worldstream `0b29bec27` remains complementary on startup interruption and
observer coverage.  Remaining risk and next investigation: drive the
inbound-only recovery through the production send loop with a real peer table,
including bounded-queue refusal followed by a second healthy inbound source.

The production-loop follow-up is now pinned directly.  Starting from
`SYNC_IDLE` with no outbound peers, the real `msg_send_messages` path promotes
header sync and attempts the inbound fallback.  A first inbound source at the
hard send-queue ceiling refuses the frame and retains a zero request timestamp;
the next healthy inbound source queues an actual `getheaders` frame and advances
its timestamp immediately.  This proves both zero-outbound recovery and
queue-failure failover without sleeps or sockets.  Consensus impact remains
NONE.  Recommended next investigation: inspect request-result accounting on
the all-rejected header recovery probe, whose rate-limit timestamp is still
stored before its `getheaders` enqueue result is known.

That probe accounting is now corrected at both trigger sites.  The immediate
receive-side bad-prevblk probe and the periodic pending-probe retry stamp
`last_reject_probe_time` only after `push_getheaders_from` reports a successful
bounded enqueue.  A production send-loop regression suppresses unrelated
periodic requests, fills peer A's queue, and proves its zero probe timestamp is
preserved; peer B then queues the exact recovery request and advances its
timestamp.  The normal all-rejected adversarial header group remains green.
Consensus impact: NONE; only volatile retry throttling after a local send-queue
refusal changed.  Recommended next investigation: audit the ordinary header
continuation calls issued directly from `process_headers`; they do not own a
separate throttle, but ignored queue refusal may still delay recovery until the
periodic planner runs.

## Outbound version enqueue-failure recovery

Baseline and root cause: the production send loop advanced an outbound peer
from `PEER_CONNECTING` to `PEER_VERSION_SENT` unconditionally after calling
`push_version`.  At the bounded per-peer send-queue ceiling,
`p2p_node_end_message` refused the frame, but the state transition suppressed
all later version attempts even though no version message existed on the wire
queue.

Fix and after-result: `push_version` now returns the actual bounded enqueue
result and records version-sent lifecycle telemetry only for a queued frame.
The outbound send loop advances handshake state only on success.  A refused
peer remains in `PEER_CONNECTING`; a healthy peer still queues exactly one
version frame and advances normally.

Regression proof: a direct production-loop `net_msg_dos` case first failed by
observing `PEER_VERSION_SENT` with no queued version frame.  It now proves the
refused peer remains retryable and the healthy control queues the frame before
transitioning.  `net_msg_dos` passes normally and under ASan/UBSan; the broader
handshake-adversarial group also passes.  The helper refactor lowered
`msg_send_messages` complexity from 111 to 109.  Consensus impact: NONE;
version serialization, network magic,
service bits, validation, PoW, chain selection, and transaction rules are
unchanged.  Worldstream `0b29bec27` remains complementary on fresh-sync startup
interruption and observer coverage.  Remaining risk and next investigation:
audit post-version one-shot negotiation flags (`getaddr`, `sendheaders`, and
mempool pull) for the same enqueue-before-state invariant.

## Keepalive deadline enqueue ownership

Baseline and root cause: the send loop wrote `ping_nonce_sent`,
`ping_usec_start`, and the monotonic pong-deadline origin before the ping frame
entered the bounded peer queue.  A non-draining peer at the hard ceiling was
therefore represented as awaiting a pong for a ping that never existed on the
wire.

Fix and after-result: keepalive construction is isolated in a bounded helper,
and all nonce/deadline state is committed only after `p2p_node_end_message`
accepts the frame.  Queue refusal leaves every ping marker clear, while the
existing resource-limit disconnect remains authoritative.

Regression proof: a production send-loop fixture supplies monotonic activity
old enough to require a ping, fills the peer queue, and first observed all
three false deadline fields.  It now proves the refused frame creates no nonce,
timer, or queued ping, while a healthy control queues a ping and starts all
three markers.  The full `net_msg_dos` group passes normally and under
ASan/UBSan.  Consensus impact:
NONE; this changes volatile peer-liveness accounting only.  Wire serialization,
validation, PoW, chain selection, and transaction rules are unchanged.
Worldstream `6c1a99c24` remains complementary on fresh-sync startup observer
coverage.  Remaining risk and next investigation: continue auditing getaddr
and mempool one-shot flags.

## Outbound getaddr enqueue ownership

Baseline and root cause: outbound version handling set the per-peer `get_addr`
one-shot guard even when the hard send-queue ceiling rejected its `getaddr`
frame.  The peer was therefore recorded as queried without any discovery
request entering the wire queue.

Fix and after-result: `get_addr` now receives the actual bounded enqueue result.
A refused frame leaves discovery retryable; a healthy control queues `getaddr`
and advances the guard.  The message bytes and ordinary handshake ordering are
unchanged.

Regression proof: a direct production `process_version` fixture first failed
with `get_addr=true` and no queued frame.  It now proves refusal and healthy
enqueue behavior through the real version handler, and `net_msg_dos` passes.
Consensus impact: NONE; this changes only volatile peer-discovery bookkeeping.
Worldstream `6c1a99c24` remains complementary on fresh-sync observer boundary
measurement.  Remaining risk and next investigation: audit the post-handshake
mempool one-shot guard, then return to measured block/header scheduling costs.

## Mempool one-shot enqueue ownership

Baseline and root cause: the post-handshake mempool pull set
`mempool_requested=true` and returned success before the empty `mempool` frame
entered the bounded send queue.  Queue refusal permanently consumed the
connection's one-shot guard despite sending no request.

Fix and after-result: `msg_tx_maybe_request_mempool` now returns the actual
enqueue result and advances its guard only after success.  Relay and deep-IBD
gates are unchanged, so historical synchronization still never competes with
mempool inventory.

Regression proof: the handshake-adversarial fixture first observed a true
return and consumed guard at the hard queue ceiling.  It now proves refusal
leaves the guard clear, then proves a subsequent healthy enqueue sets the guard
and emits the real wire command.  The complete handshake-adversarial group
passes normally and under ASan/UBSan.  Consensus impact: NONE; mempool relay policy and transaction validity
are unchanged.  Worldstream `6c1a99c24` remains complementary on fresh-sync
observer measurement.  Remaining risk and next investigation: measure the
active-slot census cost in saturated legacy block assignment before replacing
its scans with counters.

## Snapshot reconnect-source yield

Baseline and root cause: real framed `zmanifest`/`zchunkreq` coverage showed
that terminal cleanup immediately released a disconnected source's chunk, but
connman's fixed callback order allowed a new session from that same endpoint
to reclaim it before an already-admitted compatible source was called. A
rapid reconnect loop could therefore monopolize a released chunk without
invalid data or a timeout.

Fix and after-result: the active snapshot generation now retains at most 32
endpoint-scoped, one-second reconnect yields. A same-endpoint replacement
waits for one alternative-source opportunity; the yield is consumed as soon
as a different compatible source actually receives work, so it cannot delay
that endpoint through a later timeout. The state is volatile, bounded, and
generation-scoped; it is neither a ban nor a trust decision.

Regression proof: `test_block_swarm_loopback` drives a real wire manifest,
disconnects the owner, admits a distinct new peer object for the same
endpoint, and proves it emits no request before the healthy admitted source
owns the released chunk. Existing truncated, unsolicited, duplicate, late,
timeout, and disconnect ownership cases pass in the same group. Consensus
impact: NONE. Worldstream `d9f5153be` is complementary storage/startup work.
Remaining risk and next investigation: inspect snapshot timeout/reassignment
fairness under larger source churn without adding persistent peer trust state.

## Snapshot timeout-source yield

Baseline and root cause: the reconnect-source yield protected a replacement
session, but a timed-out source was deferred only for the callback that
released its chunk. In fixed peer order, that same source could reclaim the
chunk on its next tick before another admitted compatible source ran.

Fix and after-result: timeout requeue now records the existing bounded,
endpoint-scoped generation yield. The first different source that actually
receives work consumes the yield, so normal recovery and later retries are not
delayed. This remains volatile scheduling state only.

Regression proof: `test_block_swarm_loopback` expires an owner, invokes that
owner's next send tick, and proves it cannot reacquire before the healthy
admitted source owns the chunk. Consensus impact: NONE. Worldstream
`d9f5153be` remains complementary storage/startup work. Remaining risk and
next investigation: measure source fairness across repeated timeout and
disconnect churn with more than two compatible peers.

## Block-swarm timeout-source yield

Baseline and root cause: block-swarm pipeline reconciliation yielded a timed
out owner only for its current send callback. On the next fixed-order tick,
the cleared pipeline had no memory of that timeout and could reclaim work
ahead of a healthy admitted peer. A direct scheduler fixture also exposed that
such volatile state must not survive a new manifest generation.

Fix and after-result: a peer now retains a one-second monotonic timeout-yield
deadline. Assignment suppresses only new work while that bounded deadline is
active; a new block-swarm generation clears it at peer admission. This keeps
same-generation reassignment fair without contaminating restart/recovery.

Regression proof: `test_block_swarm_loopback` drives the production send loop
through an owner timeout and its next fixed-order tick, proving the old owner
emits no replacement batch before another source can run. It also proves a
later generation clears the deadline while preserving full one-peer pipeline
capacity. The complete real-wire group passes. Consensus impact: NONE.
Worldstream `d9f5153be` remains complementary storage/startup work. Remaining
risk and next investigation: measure larger repeated timeout/disconnect churn
without weakening source diversity or the bounded pipeline.

## Snapshot and block manifest enqueue ownership

Baseline and root cause: snapshot and block manifest senders advanced their
per-peer sent markers after constructing a frame, even when the bounded peer
queue rejected it. Block manifests were revisited on later send ticks, but the
snapshot manifest was handshake-only, so one saturated initial queue could
silently suppress its advertisement for the rest of that connection.

Fix and after-result: both markers now advance only after
`p2p_node_end_message` accepts the complete frame. Eligible ZCL23 peers revisit
an unsent snapshot manifest from their normal send tick, matching the existing
block-manifest publication behavior. The retry is handshake-gated, bounded by
the one sent marker, and does not alter the frame, source selection, or trust
boundary.

Regression proof: `test_block_swarm_loopback` fills a real peer queue to its
hard cap, proves refused block and snapshot advertisements leave their markers
clear and queue no frame, then proves a healthy retry queues exactly one
manifest. The real-wire `block_swarm_loopback` and
`snapshot_serve_loopback` groups pass. Consensus impact: NONE; this changes
only volatile advertisement accounting. Validation, cryptography, PoW, chain
selection, and wire payloads are unchanged. Worldstream `d9f5153be` remains
complementary storage/startup work. Remaining risk and next investigation:
measure snapshot manifest-source diversity under repeated reconnect churn with
three or more compatible endpoints.

## Independent snapshot reconnect yields

Baseline and root cause: the bounded reconnect-yield table recorded each
disconnected endpoint independently, but its consume helper cleared every
outstanding record when any alternate source received one chunk. Under a
multi-source disconnect, that single assignment could release all replacement
endpoints at once and defeat the intended source-diversity opportunity.

Fix and after-result: each successful assignment now consumes exactly one
other endpoint's active yield. Further pending endpoint yields remain in force
until another compatible source is assigned or their one-second monotonic
deadline expires. The table remains fixed at 32 entries and generation-scoped.

Regression proof: `test_block_swarm_loopback` starts a three-chunk swarm,
disconnects two owners, then proves the healthy source receives the first
recovered chunk while the other reconnecting endpoint is still deferred. The
released first endpoint then provides the next valid alternative-source
opportunity. The complete real-wire group passes. Consensus impact: NONE;
only volatile peer scheduling changed. Worldstream `5297c58f4` is
complementary classic-node timeout arithmetic work and owns no overlapping C
surface. Remaining risk and next investigation: inspect whether a rejected
`zchunkreq` has any residual owner/accounting state after a reconnect yield.

## Snapshot offer enqueue ownership

Baseline and root cause: snapshot-offer serialization recorded the advertised
snapshot identity regardless of whether the bounded peer queue accepted the
frame. Its caller also marked the peer as offered first, so a rejected offer
could suppress later advertisement of the same verified snapshot.

Fix and after-result: `send_snapshot_offer_msg` now returns the actual enqueue
result and commits offer identity only after the full frame is queued.
`mp_snapshot_maybe_offer` advances its offered marker and emits its event only
on that success. Wire bytes and all snapshot verification gates are unchanged.

Regression proof: `test_block_swarm_loopback` saturates the real peer queue,
proves a rejected offer leaves height/count identity clear and queues nothing,
then proves a healthy retry queues exactly one frame and records the identity.
The complete real-wire swarm and snapshot-serve groups pass. Consensus impact:
NONE. Worldstream `5297c58f4` remains complementary timeout arithmetic work.
Remaining risk and next investigation: audit offer refresh and serving-state
transitions under disconnect after a successful advertisement.

## Snapshot serving enqueue accounting

Baseline and root cause: `snapsync_prepare_serve_step` advances the serving
cursor before `zsyncdata` is queued. A bounded queue refusal therefore left
the sender ahead of bytes that never reached the peer; a rejected `zsyncend`
also moved the peer out of serving state without an end frame on the wire.

Fix and after-result: rejected data frames restore the exact chunk offset,
entry progress, and sent count; rejected end frames keep the peer in serving
state. This preserves retry/reconnect accounting without changing payload
bytes, snapshot validation, or acceptance policy.

Regression proof: `test_snapshot_serve_loopback` now drives the production
`mp_snapshot_send_tick`, saturates its real peer queue, and proves cursor and
serving state remain unchanged before completing the normal real-wire transfer.
Consensus impact: NONE. Worldstream `5297c58f4` remains complementary.
Remaining risk and next investigation: audit snapshot serve state after a
successful end-frame enqueue followed by immediate disconnect.

## Snapshot reconnect yield after queue refusal

Baseline and root cause: reconnect-source fairness consumed an endpoint's
yield when the scheduler assigned it a chunk, before the `zchunkreq` frame was
accepted by the bounded peer queue. A saturated alternate could therefore
release a reconnecting endpoint without having received any work.

Fix and after-result: the assignment helper now returns the enqueue result and
consumes one reconnect yield only after a `zchunkreq` frame is accepted. A
refusal still immediately releases local and authoritative chunk ownership;
the yield remains until a distinct source actually receives work. State stays
bounded, volatile, and generation-scoped.

Regression proof: `test_block_swarm_loopback` disconnects two sources, forces
the healthy alternate's real queue to its hard cap, and proves the reconnecting
endpoint remains deferred. A fresh healthy source then queues work and
consumes exactly one yield. Focused real-wire group passes. Consensus impact:
NONE; no payload, validation, or selection rule changed. Worldstream
`5297c58f4` remains complementary timeout arithmetic. Remaining risk and next
investigation: audit snapshot serving state after a successful end-frame
enqueue followed by immediate disconnect.

## Snapshot terminal-frame refusal

Baseline and root cause: data-frame refusal was covered, but `zsyncend` uses a
separate serving-state transition and lacked a direct bounded-queue regression.
An unobserved refusal there could strand a peer outside its retryable serving
state.

After-result and regression proof: the existing production path already keeps
the peer serving until `p2p_node_end_message` accepts `zsyncend`.
`test_snapshot_serve_loopback` now drives its real prepared-buffer end branch
at the queue hard cap and proves state and terminal cursor remain unchanged,
then restores the fixture cursor and completes the normal real-wire transfer.
Consensus impact: NONE. Worldstream `5297c58f4` remains complementary.
Remaining risk and next investigation: inspect snapshot requester recovery
when a served peer disconnects after data enqueue but before terminal delivery.

## Inbound block-download occupancy

Baseline and root cause: every direct block request scanned the complete
in-flight table merely to count inbound-owned slots for the outbound-reserved
window. During IBD that bounded table reaches thousands of entries while the
same count is maintained by the request lifecycle.

Fix and after-result: `download_manager` now maintains bounded
`num_inbound_active` state across assignment, receipt, timeout, disconnect,
notfound, and forced drain. Direct reservation decisions are O(1); assignment
still scans only for its necessary per-peer and history-lane counts.

Regression proof: the focused download groups pass, including direct inbound
reservation, concurrent access, timeout/disconnect/notfound recovery, and
speed contracts. Consensus impact: NONE. Worldstream `5297c58f4` remains
complementary. Remaining risk: maintain lifecycle counter coverage whenever a
new active-slot terminal path is introduced.

## Header-range anchor-resolution release

Baseline and root cause: the parallel header scheduler claimed a range for a
peer before resolving the local start anchor.  If that resolution failed, the
request path returned with the peer still owning the range until its deadline,
needlessly withholding it from other healthy sources.

Fix and after-result: the failed-resolution path now releases the peer's
range claim immediately before returning.  The scheduler can therefore assign
the same bounded range to another eligible peer without waiting for timeout.
No header bytes, validation rule, or chain-state transition changed.

Regression proof: the focused `header_range_sched` group passes its complete
release, reassignment, timeout, and disconnect coverage after the change.
Consensus impact: NONE. Worldstream `5297c58f4` remains complementary classic
download timeout work. Remaining risk and next investigation: add direct
wire-level `zchunkdata` coverage for malformed, duplicate, and late chunk
delivery accounting.

## Snapshot disconnect ownership fast path

Baseline and root cause: terminal snapshot-peer cleanup always scanned every
manifest chunk to find an owner.  Normal scheduling assigns at most one chunk
per peer, so reconnect churn repeatedly paid an O(manifest-size) scan even
when the peer's exact in-flight index was still available.

Fix and after-result: disconnect cleanup first validates and requeues the
peer-local chunk index in O(1).  A missing or stale index still takes the
former bounded authoritative scan, preserving recovery when connman has
already cleared peer-local state.  The new diagnostic probe counter makes the
normal zero-scan and stale fallback paths deterministic to test.

Regression proof: `test_fast_sync` covers both the exact-owner fast path and
the cleared-hint fallback, including owner, state, and in-flight accounting.
Consensus impact: NONE; this changes only volatile request cleanup. Worldstream
`5297c58f4` remains complementary classic download timeout work. Remaining
risk: runtime test execution awaits safe build headroom; seal, parity,
complexity, and capability-inventory gates pass. Next investigation: measure
snapshot scheduler work under large manifests and repeated reconnects.

## Snapshot global timeout-sweep coalescing

Baseline and root cause: every admitted snapshot peer tick ran the global
orphan-timeout traversal across the complete manifest. With a large manifest
and several peers this repeated identical O(chunk-count) work while the exact
owner timeout path already ran on each peer tick.

Fix and after-result: exact-owner timeout reconciliation remains per tick, but
the global orphan fallback is now admitted at most once per monotonic second.
A monotonic regression admits a sweep immediately, so clock accounting cannot
suppress recovery. This bounds repeated scheduler CPU without changing wire,
chunk verification, or validation behavior.

Regression proof: `test_fast_sync` deterministically covers first admission,
same-tick suppression, interval admission, invalid interval refusal, and
monotonic-regression recovery. Consensus impact: NONE. Worldstream `5297c58f4`
remains complementary. Remaining risk: execute the cold registered runtime
group only when disk headroom permits; source syntax, seal, parity, and
complexity gates pass. Next investigation: quantify scheduler scans under
large manifest and multi-peer churn.

## Empty snapshot timeout-sweep fast path

Baseline and root cause: even after global sweep coalescing, an admitted sweep
traversed every manifest entry when no chunks were in flight. Such a state has
no timeout candidate, so the traversal was pure scheduler overhead.

Fix and after-result: `swarm_sync_handle_timeouts_at` now returns immediately
when its authoritative in-flight count is zero. A diagnostic probe counter
shows zero manifest reads for the empty case and a complete bounded traversal
when a real stale request exists.

Regression proof: `test_fast_sync` exercises both states and proves stale
ownership is still released. Consensus impact: NONE. Worldstream remains
complementary. Remaining risk: cold runtime group awaits safe disk headroom;
syntax, seal, parity, and complexity checks pass. Next investigation: reduce
nonempty sweep work without weakening orphan recovery.

## Snapshot timeout earliest-deadline cache

Baseline and root cause: a nonempty global orphan sweep still walked every
manifest entry once per second even when every request was far from its timeout
deadline. This was avoidable scheduler work on large snapshots.

Fix and after-result: timeout scans cache the earliest future expiration for
their timeout policy and return before that deadline. Assignment, completion,
failed delivery, requeue, and disconnect transitions invalidate the cache;
policy changes and monotonic rollback force a scan. The exact-owner path is
unchanged.

Regression proof: `test_fast_sync` proves an early sweep adds no probes, while
the first eligible expiration performs the bounded scan and requeues the stale
chunk. Consensus impact: NONE. Worldstream remains complementary. Remaining
risk: cold runtime group awaits disk headroom; syntax, sealing, parity, and
complexity gates pass. Next investigation: assess block-swarm scheduling
under the same multi-peer churn profile.

## Empty block-swarm timeout-sweep fast path

Baseline and root cause: block-swarm timeout handling traversed every piece on
each eligible peer tick even when no piece was in flight. No timeout transition
is possible in that state.

Fix and after-result: the block-swarm timeout handler returns in O(1) when
the bounded authoritative in-flight count is zero. A diagnostic probe counter
proves the idle path reads no piece state; regular stale-piece recovery still
walks and requeues the timed-out owner.

Regression proof: the monotonic-boundary fast-sync regression now covers idle
zero probes and both non-expired and expired in-flight piece cases. Consensus
impact: NONE. Worldstream remains complementary. Remaining risk: cold runtime
group awaits disk headroom. Next investigation: coalesce nonempty block-swarm
orphan scans across peer ticks.

## Block-swarm global timeout-sweep coalescing

Baseline and root cause: each eligible block-swarm peer tick invoked the
global orphan timeout sweep over the piece manifest, duplicating work while
per-peer pipeline reconciliation already handled the normal owner path.

Fix and after-result: the global backstop now runs at most once per monotonic
second. Per-peer reconciliation remains immediate. A monotonic regression
admits a sweep rather than suppressing recovery.

Regression proof: `test_fast_sync` covers first admission, same-tick
suppression, interval admission, and regression admission for block-swarm
cadence. Consensus impact: NONE. Worldstream remains complementary. Remaining
risk: cold runtime groups await safe disk headroom; syntax, seal, parity, and
complexity checks pass. Next investigation: defer nonempty block-swarm scans
until the earliest possible piece expiry.

## Block-swarm timeout earliest-deadline cache

Baseline and root cause: the coalesced global block-swarm fallback still
scanned every in-flight piece once per second even when none could yet expire.

Fix and after-result: timeout handling now caches the earliest possible
expiration and skips scans before it. Assignment, receipt, and requeue clear
the cache conservatively; timeout-policy changes and monotonic rollback force
a fresh scan. Exact-owner pipeline reconciliation remains unchanged.

Regression proof: `test_fast_sync` proves an early scan is suppressed and the
existing monotonic-boundary cases still inspect and recover an in-flight piece.
Consensus impact: NONE. Worldstream remains complementary. Remaining risk:
cold runtime groups await safe disk headroom. Next investigation: measure
block-piece rarest-first scans under large, sparse peer bitmaps.

## Sparse block-swarm bitmap scheduling

Baseline and root cause: rarest-first assignment inspected every piece state
before checking whether a peer's `zblkbitmap` advertised that piece. A sparse
peer with one usable tail piece in a 4,096-piece manifest therefore touched
all 4,096 swarm states per request, even though its bounded bitmap already
proved 4,095 pieces unavailable.

Fix and after-result: assignment now iterates set bitmap bits before reading
piece state; zero bitmap bytes are skipped. Full seeders retain the prior
linear cursor path and the same rarest-first tie rule. The new bounded
diagnostic counter records actual advertised state probes. The former endgame
duplicate-request branch was unreachable behind the single-owner state filter;
it is removed rather than allowing an unsafe owner overwrite. Tail duplication
still requires an explicit bounded multi-owner design.

Regression proof: `test_fast_sync` adds a 4,096-piece fixture with only piece
4,095 advertised and proves exactly one state probe, correct ownership, and
no assignment or accounting change from an empty bitmap. Static C23 syntax,
core seal/root mirror, consensus parity, generated complexity ratchet, and
whitespace gates pass. The cold registered runtime group remains deferred to
avoid consuming the 11 GB free-disk safety floor.

Consensus impact: NONE. This only changes volatile request selection; manifest
identity and piece-hash verification, payload parsing, reducer admission,
block/transaction validation, PoW, and chain selection are unchanged.
Worldstream `5297c58f4` remains complementary classic-download timeout work.
Remaining risk and next investigation: measure real sparse-advertisement
frequency and tail latency before designing multi-owner endgame duplicates.

## Block-swarm peer timeout arithmetic

Baseline and root cause: peer-pipeline timeout reconciliation used ordered
signed subtraction, which still overflowed for an `INT64_MIN` request stamp
and an `INT64_MAX` monotonic sample. The one-second timeout-yield deadline
also added directly to a signed timestamp.

Fix and after-result: reconciliation now uses the shared overflow-safe elapsed
predicate. Yield deadlines saturate at `INT64_MAX`, and the scheduler checks
their bounded remaining interval using unsigned distance after an ordered
comparison. Normal eight-second timeout semantics are unchanged.

Regression proof: the block-swarm loopback fixture covers the full signed
timestamp range, proves the stale owner is requeued, and proves the yield
deadline saturates. Static C23 syntax and complexity gates pass; the cold
runtime/sanitizer build remains deferred to preserve the 11 GB disk floor.
Consensus impact: NONE. Only volatile peer request scheduling changes;
manifest/payload verification and all chain validation are untouched.
Worldstream `5297c58f4` remains complementary. Remaining risk: reconnect
yield records are deliberately bounded to 32 endpoints; measure real churn
before changing that policy.

## Late invalid block-piece ownership

Baseline and root cause: `zblkdata` admission precedes payload parsing outside
the block-swarm mutex. A timeout or disconnect could reassign a piece while a
former owner's invalid response was decoded; the old failure path then
requeued the replacement and abandoned its healthy swarm session.

Fix and after-result: invalid responses remain peer-scored, but only a sender
that is still the authoritative owner can release the piece, increment failure
state, or invoke the integrity fallback. A late invalid response is logged and
cannot revoke the replacement. The deterministic A-to-B reassignment
regression proves the former owner cannot requeue B's in-flight piece.

Consensus impact: NONE. This changes volatile transport ownership only; the
existing manifest hash, payload parsing, canonical reducer, and all block and
transaction validation remain unchanged. Worldstream remains complementary.
Remaining risk: runtime wire execution awaits safe disk headroom; C23 syntax,
complexity, sealing, parity, and generated-inventory gates are required before
publication.

## Superseded verified block-piece intake

Baseline and root cause: a `zblkdata` response can pass its initial ownership
admission, then lose ownership while its payload is parsed outside the swarm
mutex. The prior path still submitted that stale but hash-valid payload to the
reducer before later dropping its completion credit.

Fix and after-result: the mutex-held pre-submit check now requires current
in-flight ownership as well as a verified payload. Superseded responses are
dropped before reducer intake; current owners retain the existing submission
and canonical validation path. The existing A-to-B ownership regression covers
the authoritative reassignment predicate used by this gate.

Consensus impact: NONE. This reduces redundant transport/reducer work only;
manifest hashes, payload verification, block and transaction validity, PoW,
and chain selection are unchanged. Worldstream remains complementary.
Remaining risk: a genuine runtime wire/sanitizer execution remains deferred to
protect the 11 GB disk headroom.

## Header-range deadline saturation

Baseline and root cause: range-parallel header assignment and progress renewal
formed deadlines with signed `now_us + timeout_us`. An extreme monotonic sample
could wrap the deadline into the past, immediately releasing a live span and
making its healthy peer look stalled.

Fix and after-result: the allocation-free scheduler now saturates absolute
deadlines at `INT64_MAX`. Assignment and renewal share the helper. The
deterministic scheduler regression assigns and renews at `INT64_MAX - 1`,
proves the span remains live there, and proves it expires only at the saturated
deadline.

Consensus impact: NONE. This is volatile getheaders scheduling only; header
validation, checkpoint anchors, chain selection, and all consensus behavior
remain unchanged. Worldstream remains complementary. Runtime/sanitizer
execution remains deferred to preserve disk headroom.

## Header-range progress monotonicity

Baseline and root cause: a backwards monotonic sample in progress renewal
replaced a live header-span deadline with an earlier value. The scheduler could
then expire and reassign a healthy peer's span before its original deadline.

Fix and after-result: progress now applies the maximum of the existing and
renewed deadlines. A deterministic rollback fixture assigns at 100, reports
progress at 50, proves the span survives at 101, and proves normal expiry at
130. Consensus impact: NONE; this is volatile getheaders scheduling only.
Worldstream remains complementary. Runtime/sanitizer execution remains deferred
to preserve disk headroom.
