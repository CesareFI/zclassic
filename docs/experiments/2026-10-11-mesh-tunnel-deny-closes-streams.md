<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Tunnel deny and pairing revocation end live streams

## Contract

Removing a tunnel grant, or revoking the pairing behind one, must end the
streams that grant admitted, not only refuse new ones. Before this change
`mesh_tunnel_deny(peer, port)` removed the allow row and rewrote the allow
file, and pairing was consulted only when a stream opened. A stream admitted
before the removal kept carrying bytes until the session was lost or the
stream sat idle for 600 seconds. This record documents the change that closes
that gap on the acceptor side. It grants no new authority: deny and revocation
only narrow what is permitted.

## Gap on the base commit

Base: `16422c3469459397877ed7764b17283186ab22d5`. On that commit the deny
body only removes matching rows and persists the table. The open-time check
admits a stream when the peer's pairing grants status read and an exact
(peer, port) row exists. The stream pump closes streams on session loss and on
idle expiry and does not re-read pairing. The acceptor's per-stream state
recorded neither the admitted peer's pairing identifier nor the target port, so
no later code could tell which streams a given row had admitted. The existing
tunnel test never called `mesh_tunnel_deny`. These facts come from the audit
and an independent reading of the base source; the gap was not exercised at
runtime on the base, because the base lacks the new tests (see below).

## Design

Each acceptor session now records the pairing identifier and loopback port
that passed the allow check at open, and the next time its pairing is to be
re-read. Initiator sessions leave these empty. A new end token,
`tunnel_target_denied`, is distinct from the open-time refusal
`tunnel_target_not_allowed` and from `tunnel_local_closed`, so an observer of
the close frame can tell why a stream ended.

`mesh_tunnel_deny` edits and persists the table under the tunnel lock, drops
that lock, and only then visits the tunnel's streams, ending each acceptor
stream whose recorded peer and port equal the arguments. The tunnel lock is
inner to the stream lane lock, and the stream layer's visit takes the lane
lock, so the visit must never run with the tunnel lock held; close already
follows the same order and the file header comment now says deny does too.
The visit callback reaches the acceptor close path, which takes no tunnel lock,
so the order cannot invert. The table edit happens before the visit. An open
that already passed the allow check is inside the lane lock when the visit
arrives, so the visit runs after its state is set and ends it; an open that
arrives after the edit is refused by the allow check. No stream admitted by the
removed row therefore survives the call.

If the allow file rewrite fails after the row has left memory, the streams are
still ended. The row is already gone from the table that gates new opens, so
leaving old streams running under it would be the less safe choice. The
function still returns false and now logs that the live table and the file
disagree. A call that matches no row returns false and visits nothing. The
visit is bounded by the stream table size and allocates nothing.

For pairing, no push hook exists: revocation is a database write that calls
nothing in the composition layer, and adding one would make services depend on
composition. Instead, each acceptor stream rereads its pairing row from the
tunnel's stream tick when the tick time reaches its recorded next-check time,
and then schedules the next check `MESH_TUNNEL_PAIRING_RECHECK_SECONDS` (five)
later. A stream starts with a next-check time of zero, so the first tick after
open checks immediately. The stream ends with the existing token
`tunnel_peer_unpaired` when the row is missing, revoked, expired or no longer
grants status read. The check is skipped only when there is no database handle
at all. A row that cannot be read, because the database is closed, the query
fails or the row is malformed, is treated like a missing row and ends the
stream. This is the same fail-closed rule the terminal service applies to its
live sessions.

## Contract clauses

After `mesh_tunnel_deny` returns, every acceptor stream recorded for exactly
that peer and port is ended and its loopback connection to the target is shut
down, with no further tick required. Each such stream's close frame carries
the service-closed reason and the token `tunnel_target_denied`. Streams of the
same peer on another port, and streams of another peer on the same port, are
untouched and still carry bytes in both directions. Initiator streams are never
closed by deny. A deny that matches no row returns false and closes nothing.
The initiator observes the close frame, shuts its local socket, and its client
sees end of stream; the entrance stays bound, and a new connection on it is
refused with `tunnel_target_not_allowed`. The lock order is unchanged.

For pairing, a live acceptor stream whose pairing is revoked, expired, stripped
of status read, missing or unreadable is ended with `tunnel_peer_unpaired` at
the first tick at or after its next-check time. Streams whose pairing is
unchanged are not closed. Initiator streams are not rechecked.

## Test

The registered `mesh_tunnel` group gains two cases, each in its own helper
function, in the existing single-process fixture, which holds both ends in one
stream table, so each tunnelled connection counts as two live streams while
both twins are open. Each case begins by resetting the stream table, because
the per-peer limit of eight stream opens per second was already used up by the
earlier cases. That reset means these cases do not detect streams leaked by
earlier cases.

The deny case opens two entrances to two allowed ports, settles a round trip
on each, and adds an unrelated allow row for a different peer on the second
port. Labels, in order: `live_before` (four live streams);
`other_peer_row_survives_deny` (denying the other peer leaves the second
connection carrying bytes and the count at four); `deny_returns_true`;
`closed_before_return` (immediately after deny, with no beat, three live
streams remain); `target_connection_shut` (the target's accepted socket reads
end of stream, with no beat); `close_frame_token` (the acceptor's queued close
frame has the service-closed reason and the bytes `tunnel_target_denied`);
`initiator_client_sees_end`; `other_port_still_carries`;
`new_connection_refused_by_name`; and `deny_missing_row_is_false`.

The count in `closed_before_return` is three rather than two because the
initiator twin of the denied connection stays live until the close frame is
delivered to it. The live count alone does not say which side ended; that the
acceptor side did is established by the next two assertions, the target socket
at end of stream and the token read from the acceptor's queue.
`new_connection_refused_by_name` runs only the initiator half of the beat, so
the acceptor's refusal stays queued to be read; it pins that deny and the open
gate agree and is not a mutation target.

The pairing case revokes the acceptor-side pairing row, drives one tick with a
time well past the recheck interval, and asserts `revoked_stream_ended` (one
live stream left and the target socket at end of stream) and
`revoked_token_on_wire` (`tunnel_peer_unpaired`), then delivers the close and
checks that no stream remains.

## Source and environment

- Base: `16422c3469459397877ed7764b17283186ab22d5`.
- Measurement date: 2026-10-11, UTC.
- Host: a Linux x86-64 development host, AMD Ryzen 9 7950X3D, 32 logical CPUs,
  admitted through the shared build scheduler with 28 workers.
- Compiler: GCC 14.2.0.
- Final source hashes, computed after the last edit:

| File | SHA256 |
|---|---|
| `mesh_tunnel.c` | `e466aab2370ff8c894ddba5b797e804360edfe3be9e27f7d16d2080acee9c024` |
| `mesh_tunnel.h` | `ec5942d50cded0a2158655a2788dbfcea9dcb2a0ecf2492255fe6e5ab69f5682` |
| `test_mesh_tunnel.c` | `dcbd21ca4c974a77c2188760bff7d1149ea78ebe046a242ad9b5072a91946bfc` |

Two comment and log-string lines in `mesh_tunnel.c` were edited after the
writer's runs below, so the runs recorded here used `mesh_tunnel.c` with
SHA256 `9598e43d550d37496ffbb9bc9ebecce22a85a44eeb0a6c43ed869f9445e017dd`; the
header and test hashes are the same before and after. The verification trip on
the final bytes is recorded separately in the table.

## Executed observations

Commands, each through the scheduler:

    devbuild --wait make -j28 t-fast-exact ONLY=mesh_tunnel
    devbuild --wait make -j28 agent-verify ONLY=mesh_tunnel

There was no failing run of the unchanged base: the base lacks the new tests,
so a base run could only have been green. The base group was run green before
the change as a baseline. The failing-first evidence is the three mutations.
Each run executed one group; the verdict lines below are quoted from the
retained logs, and the three mutation runs show the runner's automatic
single retry alone after the first failure.

| Stage | Observation |
| --- | --- |
| Base, before the change | `SUITE VERDICT mode=cold groups_total=1283 groups_ran=1 groups_cached=0 groups_gated=1282 groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0` |
| Candidate, focused group | the same verdict line, `groups_failed=0 self_skips=0`; `ALL TESTS PASSED` |
| Mutation 1: delete the stream visit call in deny | `groups_failed=1`; failure at the `closed_before_return` assertion |
| Mutation 2: replace the port comparison in the deny visitor with `false` | `groups_failed=1`; failure at the `closed_before_return` assertion |
| Mutation 3: replace the recheck guard `now >= next_pairing_check_unix` with `false` | `groups_failed=1`; failure at the `revoked_stream_ended` assertion |
| Restoration | after each mutation the three source hashes matched their pre-mutation values and the group passed |
| Candidate, `agent-verify` trip on the pre-edit bytes | an earlier trip reported a cyclomatic-complexity failure and `lint-fast` failure; a later trip passed: complexity rc=0, `t-fast-exact` rc=0 with the same verdict line (`groups_failed=0`), inventory generation rc=0, `lint-fast` rc=0, `agent-verify: OK` |
| Candidate, `agent-verify` after the last edit | complexity rc=0, `t-fast-exact` rc=0 with one group run and none failed, cached or skipped, capability inventory rc=0, `lint-fast` rc=0 |

The expected mechanism for mutation 1 is that, with the visit deleted, no stream
ends inside deny, so the live count stays at four rather than three. For mutation 2
the log shows the same label; the visitor with its port test disabled should also
end the unrelated second connection. The retained
logs show only the first failing label for each run; a further failure in the
pairing case under mutation 2 was reported by the writer but is not visible in
the log, since the case stops at its first failure, so it is not claimed here.
Mutation 3 should leave the revoked stream alive.
Mutations of the peer comparison, the token, and the recorded peer or port
fields were not run, so the peer comparison is covered only by the
`other_peer_row_survives_deny` assertion existing, not by a demonstrated
failure. The number of assertions executed is not printed by the runner and is
not recorded here. The capability inventory regenerates with changed rows for
this source; the regenerated file is not part of this change, and the
integrator refreshes it at integration.

One non-author source review read the diff against the design card and found no
blocking issue. Its two minor notes are the database fail-closed behavior
listed under limits, and that the live-count label alone does not distinguish
which side ended, which the two following assertions cover.

## Limits

This does not establish that initiator-side streams are rechecked; they are
not, and a revoked initiator pairing is its own row's concern. Revocation of a
pairing takes effect within the recheck interval plus one tick, not
instantly; only deny is immediate. Because an unreadable pairing row ends the
stream, a transient database read failure ends live tunnel streams, which a
user may see as an unexplained disconnect with the token `tunnel_peer_unpaired`.
The evidence is a single-process fixture with both ends in one stream table, on
Linux only, so it does not establish behavior across two real nodes, across a
real session, on macOS, or under sanitizers. No live fleet run was made. The
test cases reset the stream table and so cannot detect streams leaked by
earlier cases. It does not address entrances surviving a restart, keepalive, or
health reporting; those remain as audited. The recheck adds one pairing lookup
per acceptor stream per interval under the stream lane lock; its cost was not
measured. Mutation results show that these assertions detect these specific
removals, not that no other defect exists. Publication requires the native
signed commit and base proof with full mandatory lint and affected tests; those
receipts determine admission.
