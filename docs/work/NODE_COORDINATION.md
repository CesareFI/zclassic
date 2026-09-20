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
