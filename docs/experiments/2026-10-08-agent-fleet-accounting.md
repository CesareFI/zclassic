<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Passive accounting and fleet dispatch qualification

Date: 2026-10-08. Source base:
`b8be01b0e6a7886fa195100d07d2f2b0e2094d4c`.
Implementation contract: [AGENT_FLEET.md](../work/AGENT_FLEET.md).

## Scope

The outcomes importer adds bounded Codex root-session cumulative observations.
It does not establish per-task billing, model attribution, interval expenditure,
or durable ingestion checkpoints. Unsupported or ambiguous lineage is refused.
Observed counters remain distinct from pricing and subscription allocation.

Independent source review initially rejected two cases: inherited counters
counted again under another generation, and malformed metadata retaining the
previous namespace. The revised candidate refuses both and includes regression
fixtures through the outcomes caller. Review accepted this bounded scope;
installed-runtime schema qualification remains separate.

## Executed checks

On the admitted primary Linux build host:

```sh
devbuild --wait make setup
devbuild --wait make -j28 t-fast-exact ONLY=devagent_outcomes,make_lint_gates
```

Setup completed. Both registered groups passed, with zero failures and zero
skips. The runner reported a cold, exact-filtered run. These checks are functional
evidence, not a performance benchmark. Full lint initially passed 213 of 215
gates. The failures were a stale generated capability inventory and an untracked
documentation target. The inventory was regenerated through its canonical target;
new documentation was included in the candidate index. An external-adapter path
was then explicitly marked as outside this repository. Targeted reruns passed
capability freshness, inline paths, documentation claims, Markdown links and lint
gate wiring. No model calls were needed for these fixtures.

Exact checked source SHA-256:

| File | SHA-256 |
| --- | --- |
| `tools/command/native_devagent_usage.c` | `ecf932caa93d3d2817d594c746bd4586e021ce97c722379e67c29c550eac8a9b` |
| `tests/harness/src/test_devagent_outcomes.c` | `6925edb38c5eda60ab3c8fc7c6369a862d259f247a56c3764bfb43dab2855532` |

## Benchmark coverage

The existing adapter benchmark no longer substitutes zero for missing token
counters. It reports complete, partial or unavailable coverage, null incomplete
totals, and separate sums of reported counters. Exact integer parsing and checked
addition refuse malformed, negative, noninteger and overflowing values. Multiple
terminal events without deduplication identity also refuse.

The current app-server benchmark helper emits initialized zero fields even when
usage is absent. Its token coverage therefore remains unavailable until the
helper supplies independently qualified presence evidence. A syntactic zero
cannot establish a measured zero.

```sh
devbuild --wait make zcode-adapter-usage-selftest
```

All 40 offline checks passed locally and on the admitted Linux host; independent
review accepted the extraction and coverage behavior. The self-test calls the
same extraction functions as the model benchmark and is a prerequisite of
`zcode-adapter-readiness-acceptance`. No provider was contacted and no cache saving
is claimed. Compilation, provider usage coverage and model-quality qualification
remain different evidence classes.

## Existing coordinator adapter

The separate installed C23 fleet adapter had a shared snapshot temporary-file
race and could use a seat observation taken before acquiring the dispatch lock.
The corrected adapter uses separate temporary names, clears stale observations,
refreshes under the host lock, and refuses a failed lock open or acquisition.
It does not change pacing or publication policy.

The fixture includes the production source and checks active/idle/unavailable
observations, held/unavailable locks, and concurrent snapshot publication with
a two-writer barrier. Ubuntu Clang 20.1.8 compiled it with
`-std=c23 -O2 -Wall -Wextra -Werror -pedantic`; all cases passed under `devbuild`.
Restoring either the shared temporary or the stale-snapshot behavior caused the
corresponding regression assertion to fail (exit 134). These mutations ran only
in isolated scratch directories.

GCC 14 strict compilation stopped on three pre-existing unchecked-result
warnings elsewhere in the adapter; no diagnostic was suppressed. The installed
Clang-built coordinator SHA-256 is
`a8e84d34279052e03ecc571c656322434cd5f6f31c79db72ac9dccb83a3dff81`.
Its external adapter source `flow/flow.c` SHA-256 is <!-- doc-path-ok: private fleet adapter source outside this repository -->
`c3200cdeb5f06898ab178f5d0a121190039a6b20bf24c4865a2942b374fc371b`.
An old binary was preserved for rollback. A subsequent guarded dispatch returned
the existing subscription pacing hold without a snapshot rename error.

## Duplicate-work prevention qualification

On 2026-10-08, the implementation lane at base
`b8be01b0e6a7886fa195100d07d2f2b0e2094d4c` added an ActiveRecord conditional
recovery write that compares the observed lease, state, attempt, expiry,
heartbeat and worker. The production recovery caller cannot requeue a lease
renewed after its expiry scan. The deterministic two-database-handle regression
passed through `devbuild --wait make -j28 t-fast-exact ONLY=build_fabric` on
the Linux build host: one registered group, zero failures and zero skips,
91.1 seconds reported by the runner. The saved host log is
`/tmp/z23-fabric-recovery-20261008.log`.

The worker ownership regression initially failed all six new fixture setups
because the temporary CAS was not initialized. Existing cases completed; this
was not a production acceptance pass. The fixture now initializes its own
object store. The corrected `build_fabric_attach` group passed through the
same canonical runner with zero failures and zero skips in 27.4 seconds.
Its six new cases cover stale ownership before and after executor identity
probes, interruption during capture, unreadable state, named cancellation and
lease expiry. The saved host log is
`/tmp/z23-fabric-worker-fixed-20261008.log`.
The first lint-fast run passed 34 of 35 gates; only the source-derived
capability inventory was stale. After regeneration, final service error logging
and documentation ownership corrections, the full canonical `make -j28 lint`
passed. The final worker group also passed with zero failures and zero skips
in 40.7 seconds. Logs are `/tmp/z23-fabric-clean-lint-20261008.log` and
`/tmp/z23-fabric-worker-final-20261008.log` on the qualified build host.

These checks address specific duplicate-work opportunities. They do not measure
financial savings or establish atomic fencing between the final ownership check
and process creation. Provider usage and model-quality qualification were not
part of these fixture runs.

## Remaining accounting acceptance

The implementation was subsequently integrated onto
`7c57909962ce960a14d1b649693a99fd1040ad4a`, the external review's pinned main.
Renewal now also compares the observed lease snapshot, so a delayed heartbeat
cannot overwrite a newer heartbeat. The deterministic two-handle test invokes
the production heartbeat caller. The integrated `build_fabric`,
`build_fabric_attach`, `devagent_outcomes` and `make_lint_gates` groups passed
together with zero failures and zero skips (90.3 seconds). This does not claim
generation fencing for every generic lifecycle write or effect-aware recovery
for model submissions.

The benchmark's version-2 reports distinguish adapter invocations from unknown
provider-request counts and expected refusals from exact reproductions. Scope
snapshots now compare all descendant entries, including untracked files,
directories, modes and symlink targets. They do not observe transient writes or
writes outside that directory. The offline usage, scope and production report
fixtures passed 62 checks without model calls on Linux; macOS remains unrun for
these GNU-tool-dependent fixtures. Historical version-1 results remain unchanged.

The five remote Sol-medium preparatory tasks have 120000-token ceilings and
remain subject to existing admission. Their presence in the queue does not prove
execution. Full workflow costs remain incomplete until task mappings, reviewer
and child-attempt accounting, durable checkpoints and pricing provenance are
implemented. No cost saving, routing accuracy, cross-host crash recovery or
publication qualification follows from these checks.

## Duplicate usage-field refusal

On 2026-10-08, review of candidate
`871415c96ef60b408fad80479c59b36714cd69ce` found that individual JSON path
queries could select one of multiple conflicting usage fields. The follow-up
reader checks the relevant object keys before extracting counters. Duplicate
event-type, usage-object, token-object and counter fields refuse with exit 65
and no partial totals. Missing counters retain their unknown coverage.

The qualified Linux build host ran
`devbuild --wait bash tools/dev/zcode-adapter-usage-selftest.sh`: 67 checks
passed, exit 0, with no model requests. Local and receiver SHA-256 identities
matched:

| File | SHA-256 |
| --- | --- |
| `tools/dev/zcode_adapter_benchmark.sh` | `614e580d956283c0e3e8a74bc6dd35d16e9aaff1618ca2bb674806157f61bb2f` |
| `tools/dev/zcode-adapter-usage-selftest.sh` | `bf85e1c404c16737c0ba37fbdeb29b94499455de1f01b12616b356845e6f80e9` |

This is focused script acceptance for an uncommitted follow-up, not an exact
commit/base proof or a billing reconciliation. Workspace snapshots still do not
observe writes through symlinks to targets outside the snapshot directory;
executor confinement owns that boundary. macOS execution remains unverified.

## Renewal fencing across leased transitions

The follow-up requires the observed lease snapshot at every
`db_build_action_save_leased` caller. Start, verification, terminal completion
and receipt acceptance cannot overwrite a concurrently renewed lease. Seven
deterministic caller cases cover start, verification, three terminal outcomes,
and successful/failed signed receipt acceptance. Receipt cases assert rollback
of the inserted receipt and successful retry after re-reading the renewed lease.

On 2026-10-08, the Linux build host ran
`devbuild --wait make -j14 t-fast-exact ONLY=build_fabric,build_fabric_attach`.
The canonical cold verdict records 2 executed groups, 0 cached groups,
0 failed groups and 0 skips, in 109.8 seconds. The retained host log is
`/tmp/z23-lease-transition-review-20261008.log`. This validates the uncommitted
follow-up against parent `871415c96ef60b408fad80479c59b36714cd69ce`;
mutation sensitivity, final lint, exact commit/base proof and macOS execution
remain unverified for this follow-up.

## Length-preserving usage keys and snapshot modes

Independent review found that newline-delimited decoded key listings can
confuse a valid unrelated key with a duplicate counter. The reader now uses
`jsonq key-count PATH KEY`, which compares direct decoded member names by byte
length and content. The `jsonq` cold registered group passed on Linux with no
failures or skips, including 15 cases for escaped aliases, newline and NUL
distinctions, nested scope, absent paths, non-objects and malformed documents.
The log is `/tmp/z23-jsonq-key-count-20261008.log` on the build host.

Full lint refused a new GNU `stat` assumption in the workspace snapshot.
The snapshot now records the first ten type/permission characters from
`LC_ALL=C ls -ld`, including special permission bits. The revised offline
usage/scope suite passed 72 checks through `devbuild`, with no model calls.
Its exact script identities are:

| File | SHA-256 |
| --- | --- |
| `tools/dev/zcode_adapter_benchmark.sh` | `21523b982c50d02ec12d5023da603d27edaa29d9ad4238fe9bc8e6562da5a73e` |
| `tools/dev/zcode-adapter-usage-selftest.sh` | `d40eeb2f672b624935d831ee3d6a80fc1f42052ce2532625f9cf72cf6949c1b5` |

These checks supersede the earlier 67-check result for the revised scripts.
Existing GNU utility dependencies remain; macOS acceptance and final full lint
are not established by this Linux fixture result.

## Fine-grained native work-map telemetry

The follow-up adds admitted-map hierarchy counts, returned-page task coverage,
page-scoped ASCII rows, selected-action lifecycle observations and explicit
forecast evidence gaps to `zcode.work.map`. It performs no lifecycle writes and
does not infer acceptance from task resolution or action state.

The Linux host ran `devbuild --wait make -j14 t-fast-exact ONLY=build_fabric`.
The cold verdict records one executed group, zero cached/failed/skipped groups,
and 364.0 seconds. The log is `/tmp/z23-work-map-telemetry-20261008.log`.
Fixtures traverse all 204 nodes with and without selected evidence, verify
counts after response trimming, inspect expired and empty pages, compare
recorded lifecycle fields, retain unknown acceptance and enforce the existing
4096-byte response-data bound. Source identities:

| File | SHA-256 |
| --- | --- |
| `tools/command/native_zcode_work_map.c` | `7ce5da4a75b7a814f13653105bc40f8172fe7d3eb917d83ae91c45e90b2718cb` |
| `tests/harness/src/test_build_fabric.c` | `2e4ea9e1bc0f0db2cbebf7f60bf6ac11066da5f8e2963c1900f45bd7d8c3e863` |

This is fixture acceptance for the uncommitted follow-up, not a whole-project
feature census, calibrated finish forecast, final publication proof or macOS
qualification. Per-feature complete-workflow costs remain unavailable.

## Complexity and generated-artifact follow-up

The next Linux lint run rejected `test_bf_map_traversal` at complexity 18 and
`tools/jsonq.c:main` at 23 against its existing pin of 21. Page-count and text
assertions now use small helpers; command dispatch uses a fixed name/arity
table. The subsequent gate reported no over-cap traversal violation and
measured `main` at 7, requiring the shrink-only baseline to be lowered. The
capability inventory also required regeneration after these source changes.

The baseline entry has a pre-existing claim from the session-continuity
workspace. Coordination request 1237 records the proposed exact-entry change;
the isolated generated proposal does not establish claim release or landing
authority. The revised source passed the cold `build_fabric,jsonq` selection:
two groups executed, zero failures and zero skips, 76.9 seconds wall time.
The log is `/tmp/z23-accounting-focused-fix-20261008.log`. Revised SHA-256:

| File | SHA-256 |
| --- | --- |
| `tools/jsonq.c` | `d48fb24c460b49900661baf42e594c1f5a844d8b3be389be93365b8fae1d560a` |
| `tests/harness/src/test_build_fabric.c` | `b06aab327661dfd1c09e2f85ea48f05f79e89854940db3e3b3e79428c06a0334` |

Earlier passing results above apply only to their recorded source identities.

The subsequent r2 `devbuild --wait make -j14 lint` run passed all 215 gates
in 69.883 seconds. Its log is
`/tmp/z23-accounting-r2-lint-final-20261008.log`. This run used the scoped
baseline reduction and regenerated inventory; it does not release the
baseline's existing ownership claim or constitute an exact-commit push proof.

## Selected C23 procedures

Four added prompt kinds cover byte validators, native command handlers,
ActiveRecord saves and regression fixtures. The cold registered `engine` group
passed with one group executed, zero failures and zero skips in 2.1 seconds;
`check-prompt-templates` passed with 36 rows and nine complete kinds. Selection
tests check required inputs, individual exemplar selection, bounded body size
and distinct template identities. These are functional checks, not evidence
of reduced tokens or improved model accuracy.

A production preview first refused the new kinds because the standalone
runner target did not depend on the included template definitions. Adding
the template and section definition prerequisites rebuilt the runner. All four
subsequent `--dry-run` previews reported four of four required sections present
and `would dispatch`. No provider requests were made. The logs are
`/tmp/z23-c23-templates-engine-20261008.log`,
`/tmp/z23-c23-template-rebuild-20261008.log`, and
`/tmp/z23-preview-c23-*.log` on the isolated Linux validation host.

Template hashes currently identify the selected content in receipts. This
does not establish CAS persistence, complete peer-transfer closure, replication
or recovery of that content; those remain separate distributed-store work.

## Canonical template objects

The subsequent implementation serializes each selected template's existing
hash preimage, bounded to 64 KiB. Authorized dispatch writes those bytes through
the existing workspace CAS and independently checks the bounded readback hash
and bytes before a provider call. Dry-run remains read-only. Existing corrupt
objects are preserved and refused, not silently replaced.

The Linux standalone runner linked successfully with the existing bounded VCS
object-store implementation. The cold `engine` group passed with one group
executed, zero failures and zero skips in 6.0 seconds. The production-runner
fixture verifies exact object storage, repeated-write inode preservation,
missing-object recreation, and corrupt-object refusal with no new receipt.
The log is `/tmp/z23-template-cas-engine-20261008.log`. The added Windows
`shell32` linkage follows the new `os_proc.c` dependency; Windows execution is
NOTRUN. No peer replication, host-loss recovery or task-policy transport
closure is claimed by this local CAS result.

Full lint for the CAS implementation passed all 215 gates in 130.111 seconds,
exceeding the 75-second soft timing budget. The log is
`/tmp/z23-template-cas-lint-20261008.log`. Subsequent catalog review corrected
hook durability, reference-consensus assumptions, reviewer identity and
side-channel evidence requirements; catalog IDs remain 500 unique, with 100
editorial-priority entries.

On 2026-10-08T10:53:00Z, explicit owner authorization resolved the baseline
claim conflict. Only the baseline file transferred from session-continuity;
the transaction preserved every other claim field under the existing lock.
Native coordination message 1238 records the disposition. The candidate now
contains the measured `tools/jsonq.c:main` reduction from 21 to 7.

## Exact candidate proof refusal

The exact proof for candidate
`e29673089c78abce95776be099be03e67e86e360` against base
`a604b833dbebc2e56bc23cb49ccb98e91d37a409` failed. Its lint run passed 214 of
215 gates; `check-doc-inline-paths` rejected two private fleet export paths
presented as repository paths in the catalog. Those descriptions now identify
the exports as external private artifacts instead of implying checkout files.

The same attempt's cold test run executed 1,255 of 1,260 groups, with all 1,255
passing, zero failures, zero skips, and five groups gated. The recorded test
wall time was 399.2 seconds with 28 workers. These passing tests do not turn
the failed exact proof into a PASS. The attempt logs remain under the existing
development proof state; the operator capture is
`/tmp/z23-accounting-exact-proof-retry-20261008.log` on the validation host.
The documentation repair requires a new exact candidate proof.
