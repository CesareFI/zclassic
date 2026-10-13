<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# MCP workhorse qualification

Observed 2026-10-13. Source base:
`3afa0150d973b7b872540fe9a23a3013c77e9b86`.
This records client connection, source changes and fixtures, not deployment.

## Qualified behavior

- Codex CLI 0.162.1 authenticated to the existing HTTPS gateway using the
  owner-approved OAuth mechanism. Credentials remained client-owned.
- Its temporary app-server client discovered three deployed tools and called
  `steer_brief` with `isError=false`, without model inference. The client was
  stopped afterward. No gateway, service or public listener was added.
- The brief returned 25,234 text bytes with `limit=1`: that parameter bounds
  changes, not the whole snapshot. Compact JSON selection must retain
  freshness, completeness and refusal indicators.
- The source change advertises the existing native `seq`/`attempt`
  selectors, including type, pairing and bounds. It changes no authority.
- The final registered gateway base group, six gateway shards and fleet_steer
  all passed: eight executed groups, zero failures/skips, 38,542 ms test-body
  wall time. All 36 lint-fast gates passed. Independent source review accepted
  the final gateway, fixture and README.
- Thirty pre-reset Linux, Mac and laptop seats were retired in place. Their
  controller/recovery fields and receipts remain. The coordinator then reported
  zero configured seats, not thirty idle workers. This says nothing about
  physical fleet size or independently running sessions.
- The shared workhorse wiki update was read back from a second host.

Final source SHA256:

| File | SHA256 |
|---|---|
| tools/fleet_gateway.c | 3f268986995d66b64604817e1d43adcc03796f872a71dba3af5c4036d91cbdce |
| tests/harness/src/test_fleet_gateway.c | d80c352f5fa743b7c779d1e5039d96c5cf1c0bd691b150146da129aa8768b57d |
| platform/deploy/fleet-gateway/README.md | 6d0a572bffeb1eb9788d7bd875ddb0fe4d69480f2690ede0b8e33a6211f11e21 |

Private logs, patch, hashes and receipts are retained in the operator's
`mcp-workhorse-20261013` evidence directory. Roster recovery is retained in
`mcp-roster-20261013`. Neither directory is an additional task authority.

## Workhorse observations

The initial remote subscription turn's native context confirmed
`gpt-6.1-sol` and low effort. It produced the schema and regression tests.
It made 30 shell reads returning 217,049 bytes. Five exceeded 15 KiB.
Reported cumulative usage was 2,031,637 input tokens, 1,946,240 cached input
and 8,792 output. This is not API-dollar cost or complete accepted-task cost.

Lint rejected the new test's complexity: 22 against a limit of 15. The
threshold and baseline were preserved. A resume without explicit model
selection used the host default Astra model; native context exposed the
mismatch. That turn was interrupted after it split the test. An explicitly
pinned Sol low resume inspected and retained the split. Final cumulative
session counters were 2,536,050 input, 2,341,504 cached input and 10,156 output.
Do not add cumulative totals together. This is mixed-model repair evidence;
per-model repair attribution and complete workflow cost remain unknown.

The worker sandbox made Git metadata read-only. Coordinator-owned claims and
upstream verification remained necessary. One initial test selector was
refused before compilation; another build correctly refused after docs changed
during compilation. All failures remain in the evidence, outside acceptance.

## Next measured improvements and limits

Supply exact symbol excerpts, validator and fixture references, prepared
claims and explicit sandbox responsibilities. Target 4 KiB source reads.
Do not repeat metadata operations after a read-only refusal. Pin and verify
model/effort on every start and resume. Freeze source and docs before builds.
Compare complete accepted-task cost including failures, repair, review and
machines; one trial cannot establish optimality or population reliability.

Fresh controller discovery/admission across the fleet remains unqualified.
Historical seat files must not be revived as current capacity. Exact-selector
gateway deployment remains owner-gated; the production gateway is unchanged.
Live send/evidence task round trips and fleet-wide worker execution were not
qualified by this fixture run.

## Authenticated wiki discovery acceptance

On 2026-10-13, primary Linux checkout source based on
3afa0150d973b7b872540fe9a23a3013c77e9b86 passed the focused acceptance for
authenticated wiki discovery through the existing gateway and native service.

The added MCP tool is wiki_find, mapped only to fleet.steer.wiki-find.
It requires the evidence grant scope and a nonempty query of 1 to 128 UTF-8
bytes. Discovery reuses fleet.wiki.find and returns exact revision IDs,
publishers and signed timestamps under its existing 16 KiB search-payload
budget. Additional steer and MCP envelopes are outside that payload budget.
The caller reads the pinned revision through steer_evidence with type=board
and ref=id. Latest-held selection does not establish globally latest knowledge;
wiki content remains untrusted and grants no operating authority.

All commands ran through devbuild --wait, with 28 jobs for focused tests:

| Acceptance | Result | Runner wall time |
| --- | --- | --- |
| fleet_gateway | PASS, partition check only | 0.0 s |
| fleet_gateway_shard_01 | PASS | 1.9 s |
| fleet_gateway_shard_02 | PASS | 0.6 s |
| fleet_gateway_shard_03 | PASS | 0.3 s |
| fleet_gateway_shard_04 | PASS | 0.5 s |
| fleet_gateway_shard_05 | PASS | 0.4 s |
| fleet_gateway_shard_06 | PASS | 0.7 s |
| fleet_board | PASS | 23.4 s |
| fleet_steer | PASS | 7.8 s |
| lint-fast | PASS | Not separately measured |

Each focused behavioral run selected one registered group, with zero failed,
cached, skipped or environment-unobserved groups. The gateway partition check
covers 28 sub-suites across six shards; the partition check alone is not
behavioral acceptance.

The gateway fixtures exercise missing credentials, wrong scope, revocation,
missing/wrong-type/unknown-field query inputs, a valid 128-byte query, and
129-byte ASCII and 130-byte multibyte refusals. Their private datadir has no
RPC cookie, so an authorized valid query reports WIKI_UNAVAILABLE rather than
an invented empty result. The fleet_board fixture separately executes the
native wrapper through the existing in-process RPC test hook, compares exact
signed discovery metadata, fetches that revision through steer evidence,
and checks that the reads add no database mutations.

The first gateway shard run failed two new assertions: missing q produces
handler BAD_INPUT, and the existing native normalizer rejects an empty string.
The final contract is explicitly nonempty; no normalization or grant refusal
was weakened. The first lint run refused stale generated capability inventory.
Canonical docs-api-reference and docs-capability-inventory regeneration
completed before the final lint pass. Failed-run evidence is retained.

Known limit: db_fleet_board_wiki_list currently returns zero for both an empty
store and some storage failures, including statement preparation failure.
This slice preserves that preexisting ambiguity; successful empty discovery
does not qualify storage-error detection. No deployment, live gateway refresh,
peer replication or production wiki mutation was performed.

Qualification logs, status records, before copies, source hashes and the final
patch are retained on z23-r2 under
~/.local/state/storage-plan/2026-10-12-fleet/mcp-wiki-20261013/.
The effective worker model and reasoning effort were not exposed to this
worker and remain UNKNOWN.

## Mixed backend capability and release-gate repair

A running wiki RPC returned matching entries without exact revision IDs,
publisher keys or signed timestamps. The earlier native fixture used a matching
in-process backend and did not qualify this mixed-capability deployment case.
Source acceptance therefore did not establish live wiki discovery readiness.

The wrapper now requires identity_schema equal to zcl.fleet_wiki_revision.v1,
a bounded entries array, canonical 32-byte lowercase hexadecimal revision and
publisher identities, and integer creation/expiration timestamps in order.
Missing capability, including an old backend returning an empty array, yields
WIKI_CAPABILITY_UNAVAILABLE before discovery or exact_read is advertised.
The existing server emits the marker. No latest-by-slug enrichment or second
wiki projection was introduced. The largest fixed search envelope measures
116 bytes within its existing 192-byte reserve.

The fresh source passed fleet_board, fleet_gateway_shard_01 and fleet_steer,
plus the warning-suppression, rebuild-ownership, stray-source, flag-registry and
lint-wiring runtime selftests. Admission/build/test phase wall times were
85 s, 59 s and 12 s for the three groups, respectively; these include work
outside the test body and are not application benchmarks.

The final full lint run completed 219 gates: 217 passed and two rejected the
obsolete gate remaining in the maintained documentation inventory. Removing
that exact inventory row and its obsolete explanation then passed both
check-lint-gate-wiring and check-doc-accuracy. Every retained gate has a
passing observation; this is not a claim that the final documentation ran
through one complete post-repair lint invocation. Clean release qualification
remains required before deployment.

The removed gate banned the acronym MCP in all tracked paths and text.
It had no list of actual retired interfaces; its negative witnesses were
synthetic acronym examples. The explicit current MCP product direction
supersedes that blanket policy. Only its dedicated code, registration,
Makefile/script references, obsolete environment flag and documentation were
removed. Shared helpers and every unrelated gate remain. Native grant and
capability refusal tests remain exact. The initial removal accidentally
deleted a shared git helper; it was restored byte-for-byte before the fresh
qualification. Compiling failures and stale-binary selftest output are retained
and are not qualification of the repaired source.

Evidence for this follow-up is retained on z23-r2 under
~/.local/state/storage-plan/2026-10-12-fleet/mcp-wiki-capability-20261013/.
The running backend still requires its independently qualified update; this
worker performed no deployment or production service change.
