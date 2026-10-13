<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet terminal contract inventory

Observation date: 2026-10-13 UTC (2026-10-12 America/Puerto_Rico).
Source inspected: 8f8bd63a0241b1e888d5c4a8d8184c88e0438cd5.
Scope: source and command-catalog inventory, not terminal runtime acceptance.

The operator requested consolidated development and a live keyboard-controlled
terminal to organize the fleet, including Windows without manual host SSH
configuration. The behavior contract belongs in
[AGENT_FLEET.md](../work/AGENT_FLEET.md#keyboard-controlled-fleet-terminal);
this record does not establish another queue.

## Observations

- The selected binary lists fleet membership, machine pairing, native tunnel
  allow/open/list, telemetry and wiki interfaces.
- ops.telemetry.watch documents bounded resumable batches with cursor, epoch,
  gap, dropped-record and coverage semantics. It is not itself a terminal UI
  or a fresh observation from every fleet machine.
- discover search tui returned no match. The inspected tracked terminal files
  implement shell attachment, not the requested five-view fleet dashboard.
  These bounded searches are not proof that every potential UI source is absent.
- contexts/commons/modules/zssh/README.md describes an allocation-free SSH
  engine with hybrid ML-KEM-768 plus X25519 and a require_pq policy. It explicitly
  reports no production session owner or accepted guest route; rekey is
  unsupported and sessions have a 1 GiB limit.
- Existing host SSH route qualification does not establish Z23-owned transport
  or Windows operation without host configuration.

## Qualification

Terminal rendering, keyboard controls, continuous fleet collection, action
controls, Windows runtime, native SSH integration, guest routes and measured
UI latency: NOTRUN.

The contract defines separate experiments for each missing behavior, including
offline peers, feed gaps, stable selection, restart, revocation, downgrade,
backup-route interruption and receiver-side action reconciliation. Future
receipts must name exact source, platform, policy and observed outcomes.
