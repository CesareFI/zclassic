<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Tunnel list reports entrance health and peer session state

## Contract

A monitor reading `tunnel list` must be able to tell an idle but healthy
entrance from one whose peer has gone, and must never be told the peer is gone
when the observation could not establish that. Each row gains
`last_activity_unix`, `last_stream_end_reason`, `last_stream_end_unix`,
`streams_failed_total` and `peer_session`. `peer_session` is one of `live`,
`absent` or `unknown`; the zero value of the enumeration is `unknown`. The
change is read-only reporting and grants no authority.

## Design

`last_activity_unix` is the time of the last byte moved in either direction on
the entrance, zero when none. `last_stream_end_reason` and
`last_stream_end_unix` record the most recent stream end, empty and zero when
none. `streams_failed_total` counts failed streams and is history, not current
state. The row is built from the entrance's retired-stream totals plus the
live streams.

`peer_session` comes from `boot_mesh_observe_session_peer`, which returns one
of three results. LIVE means a ready node holds an established session naming
the peer. ABSENT means every ready node in the captured membership was read and
none held an established session naming the peer. INCOMPLETE means the
observation cannot say, and the list reports `unknown`. INCOMPLETE is the zero
value of the result type.

The function works in three steps. Under the node table lock it takes a
reference on every ready node, up to a bound of 1024 nodes held in an 8 KiB
stack array, and notes whether the table held more ready nodes than the bound.
Outside that lock it reads each captured node's session snapshot under the
node's own transport lock. A node whose transport is gone when read sets a
lost-transport flag. Finally it releases every reference under the node table
lock, because node reference counts are plain integers that the connection
manager changes only under that lock. Over the bound, or with a lost transport
and no match, the result is INCOMPLETE. A match is LIVE even when the table
exceeded the bound. The observation is not an atomic view of all sessions: the
membership is fixed at the capture, and each read reports its node at its own
later moment.

## Rejected first attempt

The first commit read the first 64 ready peers only. A live peer past that
position read as absent, a false ABSENT. Review rejected it. A test that
places the live peer beyond position 64 failed on that code, and the log of
that red run is retained in the scratch directory. An interim commit replaced
the lookup with a batched scan that reported absent only after a complete scan;
the capture-then-read design above superseded it.

A later gate also rejected test assertions on wall-clock timestamps. The test
clock is now pinned through `mesh_tunnel_test_set_now`, so timestamp
assertions compare exact values.

## Test

The registered `mesh_tunnel` group in `test_mesh_tunnel.c` gains one case
that builds a fake node table (real node objects with transports, swapped into
the net manager for the duration) and reads the row's `peer_session` at each
step. Labels, in order:

- `c_beyond_64_live`: the paired peer sits at index 70 of a 71-entry table, past the first 64, and
  reads live.
- `c_unestablished_is_absent`: a ready node whose transport holds no
  established session is a definite non-match; with nothing else matching the
  result is absent.
- `c_complete_absent`: a few readable non-matches read absent.
- `c_beyond_64_absent`: seventy ready non-matches, within the bound, read
  absent.
- `c_over_bound_unknown`: more ready non-matches than the capture bound reads
  unknown, since the surplus was never read.
- `c_over_bound_live`: the same crowd with the match captured first reads live.

## Source and environment

- Base: `857cd17b`; delta `857cd17b..d10b462b`, six commits, touching
  `mesh_tunnel.h`, `mesh_tunnel.c`, `mesh_tunnel_rpc.c`, `boot_mesh_status.c`,
  `boot_mesh_status_internal.h` and `test_mesh_tunnel.c`.
- Measurement date: 2026-10-11, UTC.
- Runs went through the shared build scheduler.

## Executed observations

The retained logs record these results. One log records the twelve impact
groups run cold: twelve ran, none failed; a second records a full lint pass.
Both were produced in the lane while its working tree was at the bytes later
committed as `21cabb77`, by the author's report; neither log carries a source
hash written at run time, so the exact source those runs executed is unknown
from the evidence. A later pair of logs records `agent-verify` OK and a full
lint pass, produced by the author's report on the comment-only successor
`d10b462b`; they also carry no run-time source hash, and their exact source is
likewise unknown from the evidence.

Three mutations were run, each red. A hash file written immediately before
those runs records the source hashes of the files under test, and they equal
the blobs of `5d54b73e`; this is the only run in this record with a
contemporaneous source binding.

| Mutation | Failing case |
| --- | --- |
| Treat a not-established snapshot as incomplete | `c_unestablished_is_absent` |
| Capture only 64 nodes | `c_beyond_64_live` |
| Treat over-bound as absent | `c_over_bound_unknown` |

The mutations were not repeated on later commits. Between `5d54b73e` and the
tip only `boot_mesh_status.c` changed: the release of references moved under
the node table lock, then comments were rewritten.

Two non-author source reviews accepted the capture bound, the overflow
handling and the locked release. They also traced that the only production
caller of the list is the RPC handler, whose workers are joined before the
connection manager is freed.

## Not shown

- There is no concurrent runtime test. Nothing exercises a node joining,
  becoming ready or being torn down while an observation runs.
- The lost-transport branch and the window between capture and read are
  untested.
- The observation is not an atomic view of all sessions; a session may end or
  change between capture and read and is reported as read.
- The runs reported for `21cabb77` and `d10b462b` have no contemporaneous
  source hash. Which exact source they executed is unknown from the retained
  evidence; file times and commit times are not a binding. Only the mutation
  runs are bound to source, and only to `5d54b73e`. No test was rerun to fill
  this gap.
- Nothing here shows guest or tunnel readiness.
- Mutation results show that these cases detect those specific changes, not
  that no other defect exists.

## Open questions

- Whether a pairing-database read failure should end live streams. Current
  behavior is fail closed.
- Whether entrances persist across restart.
- Who owns a stream-layer keepalive.
