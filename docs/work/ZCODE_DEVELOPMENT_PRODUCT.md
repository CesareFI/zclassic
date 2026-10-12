# ZCODE C23 Development Product

Status: owner-directed v0.1 product specification. This is the active contract for turning the existing ZCODE
development-network primitives into one ordinary C23 development loop.

## Mission and product promise

> **Z23 is a metaverse where people and AI create real things together,
> and nobody owns the world they build in.**

For this product, a "real thing" is an exact C23 source change with bounded
context, an isolated candidate, reproducible build and test evidence, review,
and an explicit human decision. The developer owns that decision. An AI may
propose and repair a candidate; it cannot accept, publish, or assign authority
to its own output.

The ordinary interaction is intentionally small:

```text
z23-dev zcode project inspect --input='{"workspace":"."}'
z23-dev zcode work start -datadir=/tmp/z23-work --input='{
  "workspace":".",
  "goal":"Make the parser reject overflowing lengths",
  "profile":"standard"
}'
z23-dev zcode work run -datadir=/tmp/z23-work --input='{"work":"latest","adapter":"manual"}'
z23-dev zcode work status -datadir=/tmp/z23-work --input='{"work":"latest"}'
z23-dev zcode work accept -datadir=/tmp/z23-work --input='{"work":"latest"}'
```

The happy path accepts no raw roots, canonical wire hex, timestamps, toolchain
hashes, proof-policy wires, or action IDs. Expert commands and full roots remain
available underneath and in an `expert` result section.

## Authority and reuse audit

This is integration, not a new protocol. The following existing owners already
bind every authoritative fact required by v0.1:

| Fact | Existing authority |
|---|---|
| exact source and candidate trees | ZVCS source capture and CAS |
| bounded model context | `zcl.zcode.agent_context.v1` and code index |
| goal, limits, recipe, lock, policy | `zcl.zcode.task.v1` |
| permitted edits | `zcl.zcode.write_scope.v1` |
| source change | `zcl.zcode.patch.v1` and `candidate.v1` |
| fixed build/test/fuzz input | `package_action_input.v1` |
| execution evidence | signed ZBuild `work_receipt.v1` |
| evidence evaluation | `proof_set.v1` |
| review | `review.v1` plus signed review work receipt |
| lifecycle | FRONTIER, CANDIDATE, and PROVEN lane receipts |
| human acceptance/publication | existing `zcode work accept` and PROVEN accepted-work/lane owners |

Therefore v0.1 adds **no canonical domain**. Project summaries, proof-profile
names, adapter packets, diagnostic capsules, human work IDs, and work-session
status are display or rebuildable local projections. They are never accepted
as authority without reloading and re-verifying the full canonical objects.
No second CAS, scheduler, task authority, package format, proof system,
identity system, worker ledger, transport, or truth database is permitted.

## Baseline the product replaces

The expert workflow (`zcode package dev prepare`, `improve`, adapter handoff,
admit, worker execution, evidence, accept) needs at least seven product steps
and exposes roots or wires at every boundary. Its `improve` plan path takes
eight expert inputs (`workspace`, `dependency_lock_hex`, `write_scope_csv`,
`acceptance_recipe_hex`, `model_policy_root`, `goal`, `proof_policy_hex`,
`expires_unix`) plus an isolated datadir and an exact `context_symbol`; it
returns nine roots and points at an adapter handoff. Measured on four permissively licensed packages (`zclassic23/sha3`, `zclassic23/codec`, `zclassic23/base`, and the
standalone `fixture/tiny-lines` library), the baseline is **more than five
commands, at least eight expert fields, three manual wire/root constructions,
no adapter front door, and no human result screen**. Ordinary context selection
picks 2.6% to 64% of a package's source bytes in under a second; an inline
public API is not an exact indexed symbol, so a task naming one selects
nothing.

## Product invariants

1. The authoritative workspace is read-only until explicit human acceptance.
2. Every candidate attempt is captured in an isolated workspace and a distinct
   canonical candidate tree before execution.
3. Project and work aliases resolve to and re-verify full canonical roots.
4. Profiles only compile into exact existing proof policies; they never weaken
   explicit project requirements.
5. Context selection is deterministic, bounded, explained, and non-authoritative.
6. Fixed build, test, fuzz, and review actions create the only usable evidence.
7. Model identity is provenance, never truth or acceptance authority.
8. Read commands do not create a workspace, CAS, datadir, or projection.
9. Every blocked state names the stage, preserved evidence, retry safety, and
   next safe command.
10. A human alone accepts or rejects the exact candidate and evidence.

## Ordered implementation slices

### P1 — project inspection and initialization

Add `zcode project inspect`, `zcode project init plan|commit`, and
`zcode project status`. Inspection derives package name/layout, headers,
sources, tests, include directories, libraries, existing package metadata,
recipe, target-inclusive lock, likely write scopes, resource ceilings, and a
suggested proof profile without writing. Initialization is plan/commit,
correctable, symlink/special-file rejecting, overwrite refusing, and stores
only the existing canonical objects.

### P2 — named proof profiles

Compile `quick`, `standard`, `strong`, and `release` into exact existing
`proof_policy.v1` fields. Quick means build and declared tests. Standard adds
warning-fatal compile and sanitizers. Strong adds deterministic fuzz and local
reproduction. Release adds distinct review and approved reproduction
requirements. The response always exposes the expanded policy and root.

### P3 — bounded goal context

Tokenize the goal and search indexed symbols, signatures, paths, text, callers,
callees, include edges, and tests in a deterministic order. Exact symbol and
signature matches outrank broad text. Each excerpt says why it was selected;
dropped candidates and budget exhaustion are explicit. Report selected bytes,
total bytes, files, symbols, and generation time. The ordinary target is below
256 KiB; exact-symbol overrides remain available.

### P4 — one work front door

Add `zcode work start|run|show|status|cancel|accept` as a thin orchestration
service over existing owners. Derive state from canonical objects rather than
creating another workflow truth table: PLANNED, AWAITING_CANDIDATE,
CANDIDATE_ADMITTED, BUILDING, REPAIR_NEEDED, EVIDENCE_READY,
READY_FOR_ACCEPTANCE, CANDIDATE_PROOFS_READY, PROVEN, BLOCKED, or CANCELLED.

### P5 — model-neutral handoff

The `manual` adapter exports a bounded packet and isolated candidate workspace.
One opt-in installed adapter may run through a fixed executable registry. It
accepts no arbitrary shell, receives a scrubbed allowlisted environment, sees
no wallet/datadir/SSH/node credentials, writes only inside the candidate, has
strict output/time limits, and cannot accept or publish. Unavailable, refused,
and timed-out are typed outcomes.

### P6 — bounded repair

Permit at most three candidate attempts. Each failed fixed action produces a
bounded diagnostic capsule containing the goal, prior patch, relevant compiler
or test diagnostic, and related excerpts—not an unbounded build log. Preserve
parent candidate, changed files, supplied context, adapter identity, elapsed
time, and resources for each separately captured attempt.

### P7 — review authorship

Manual and adapter review consume only the exact candidate, patch, public API
delta, immutable non-review proof set, goal, and policy. Review cannot create
build/test evidence, edit, or accept. Independent profiles reject an
author-self-review; conflicts remain visible.

### P8 — human result

Status leads with goal, state, changed files and lines, API changes, build and
test results, sanitizer and fuzz results, reproduction grade, review verdict,
risks, scope violations, and next safe command. Roots are grouped under
`expert`.

### P9 — self-hosting and benchmark

Use this exact product path to implement and accept at least one subsequent
improvement. Run the frozen twelve-task benchmark across at least three
projects: four seeded repairs, three bounded APIs, three malformed/UB/
portability repairs, and two intentionally impossible or out-of-scope goals.
Record all failures; do not edit tasks after seeing results.

### P10 — fresh-checkout acceptance

Provide a five-minute walkthrough and a hermetic target proving workspace
immutability before acceptance, candidate isolation, scope refusal,
candidate-bound evidence, byte-identical projection rebuild, restart behavior,
exact acceptance binding, and non-reachability of wallet/token/custody/
deployment/consensus paths.

## Implementation status

Slices P1 through P10 are implemented as the ordinary five-command path from
goal through status; the ordinary caller supplies only `workspace`, `goal`,
`profile`, the display `work` alias and `adapter`, and no canonical root, wire,
timestamp, toolchain, policy field or action ID. `zcode work status` and
`work show` are the same verified read path. The manual adapter is a closed
registry entry, creates no candidate authority and does not run a model.

- **No missing canonical wire.** `candidate.v1` already binds the task,
  cumulative patch, captured source, adapter-policy root, author, sequence and
  creation time. `work_receipt.v1` binds each candidate to its fixed action,
  failed or passing output evidence, confinement, toolchain, times and signer.
  The repair adapter-policy digest additionally commits to the prior candidate
  root, while the next cumulative patch stays based on the task's immutable
  source. The rebuildable task index orders attempts by candidate sequence and
  derives `REPAIR_NEEDED` only from a verified signed receipt for the latest
  candidate. Compiler output is summarized to the canonical failure class and
  exit status; unbounded logs are neither authority nor copied into the
  adapter packet. The Codex adapter derives `adapter_policy_root` from the
  exact context, the parent candidate when repairing, and a fixed local
  adapter-policy label, and adds no wire, source store, task, candidate,
  receipt or workflow authority.
- **Installed adapter.** `RLIMIT_NPROC` is charged across the real uid, so the
  runner rebases its 128-task allowance over the measured uid task count. The
  adapter accepts exactly one documented single-run credential,
  `CODEX_API_KEY` or `CODEX_ACCESS_TOKEN`, and otherwise returns
  `ADAPTER_UNAVAILABLE`; it never copies the user's `auth.json` into the
  candidate or exposes a credential to model-run commands. A host without
  either variable cannot run the real adapter benchmark; the manual adapter
  stays operational.
- **Package roots.** Package preparation ignores only genuine root-level
  `.zvcs` and `.codeindex` directories; a symlink or special file under either
  name is rejected, so the package source and root are unaffected by local
  task/CAS and derived-index state.
- **Cancellation.** No reusable task-cancellation authority exists: the signed
  `zcl.zcode.work_cancel.v1` wire cancels one requester-owned in-flight P2P
  request ID and does not cancel or erase task/candidate history. V0.1 does not
  advertise `zcode work cancel`; a human rejects a candidate by withholding
  `work accept`. A durable `CANCELLED` task state needs an explicit authority
  decision.
- **Response budget.** The manual handoff packet is written mode-0600 inside
  the isolated candidate and the response returns only its path and byte count;
  the package-action response selects only the eight exact roots and IDs needed
  for expert audit, keeping the human result under 4 KiB.
- **Idempotent reruns.** `CANDIDATE_ADMITTED` means exactly one thing:
  candidate captured, no signed work receipt yet. A repeated run whose execution
  receipt is missing fails closed as `CANDIDATE_EXECUTION_INCOMPLETE`, keeps
  the captured candidate and names the missing receipt instead of advancing
  history. When the bound datadir holds an outstanding async proof chain for
  that candidate, a repeated run is an idempotent "waiting for independent
  reproduction" observation identical to `work status`. A repeated run on
  `EVIDENCE_READY`, `CANDIDATE_PROOFS_READY` or `PROVEN` is an idempotent
  observation of that state and never opens a fresh attempt.
- **Patch summary (P8).** Line counts are deterministic content-multiset
  deltas: identical lines are matched regardless of position, so a pure move is
  not presented as creation. Binary files and text files above the fixed
  65,536-line bound set `line_counts_complete=false` instead of inventing a
  number.
- **Package action.** One fixed execution compiles the package and runs its
  declared tests. Its one signed work receipt is one proof-set member; the
  evaluator counts the two distinct facts it carries. It reconstructs the
  chunked build artifact and rechecks candidate, recipe, lock, isolation,
  result class, `test_ran` and exit status. A standalone test receipt is still
  required when the package receipt did not run declared tests.
- **Frozen-base dependency tasks.** An accepted patch to a package with a signed
  SHA3/codec dependency DAG is evidence of the product path, not applied to the
  frozen base root, because changing that root would invalidate the signed DAG.


## Benchmark acceptance

The frozen targets are: zero ordinary raw roots or wire hex; no more than five
commands; at least 9/12 compiling candidates; at least 8/12 policy-satisfying
candidates; 2/2 impossible requests fail closed; zero writes outside candidate
workspaces; zero silent failures; zero false independence claims; every status
has a concise human summary; and honest context/time measurements.

Each slice reports expert inputs and commands removed, context reduction,
production lines added, lines deleted/consolidated, and benchmark effect.

### Frozen twelve-task result

The permanent `test_zcode_package_dev` benchmark runs twelve unchanged goals
against three freshly generated, permissively licensed C23 package workspaces.
The manual adapter harness performs the candidate edit because this host has no
supported Codex single-run credential. It therefore measures the ZCODE product
loop—context selection, isolation, capture, scope enforcement, package action,
evidence, human acceptance, status rebuild, and workspace immutability—not the
semantic coding quality of an external model.

| # | Project | Class | Frozen goal | Result |
|---:|---|---|---|---|
| 1 | benchmark-0 | seeded repair | Repair seeded parser branch A | PROVEN |
| 2 | benchmark-1 | seeded repair | Repair seeded parser branch B | PROVEN |
| 3 | benchmark-2 | seeded repair | Repair seeded parser branch C | PROVEN |
| 4 | benchmark-0 | seeded repair | Repair seeded return regression | PROVEN |
| 5 | benchmark-1 | bounded API | Add bounded API behavior A | PROVEN |
| 6 | benchmark-2 | bounded API | Add bounded API behavior B | PROVEN |
| 7 | benchmark-0 | bounded API | Add bounded API behavior C | PROVEN |
| 8 | benchmark-1 | malformed/UB | Repair malformed input handling | PROVEN |
| 9 | benchmark-2 | malformed/UB | Repair portability boundary | PROVEN |
| 10 | benchmark-0 | malformed/UB | Repair undefined behavior guard | PROVEN |
| 11 | benchmark-1 | impossible | Modify LICENSE outside the write scope | refused: `PATCH_OUTSIDE_SCOPE` |
| 12 | benchmark-2 | impossible | Replace package identity outside scope | refused: `PATCH_OUTSIDE_SCOPE` |

Measured aggregate: 12 tasks, 3 projects, 10 compiling candidates, 10 policy
satisfactions, 10 explicit human acceptances, and 2 scope refusals. Context was
312 of 816 source bytes (38.2%), selected in 70,859 us; the whole benchmark
took 14.933 seconds. Every successful path used five calls (`start`, two
`run` calls for handoff and admission, `accept`, `status`), supplied no raw
root or wire, and ended with a human summary. The impossible paths stopped at
the second `run`. Exact source roots captured before the tasks matched after
all tasks, proving zero authoritative-workspace writes. No result claims
independent reproduction or adapter authorship.

The selector performs a bounded deterministic project-entry fallback for goal
language with no literal indexed-symbol overlap, reports
`project_entry_fallback` instead of pretending the goal matched, and preserves
the exact-symbol expert override.

## Acceptance gates and remaining blockers

The safe quick- and standard-profile development loops are shipped. Proof is
`make zcode-development-acceptance` (including the twelve-task benchmark and
fresh-workspace invariants), `make lint`, `make zcode-package-asan` (ASan+UBSan
with no suppressions over isolated base/SHA3/codec and every ZCODE lifecycle
group, including `test_zcode_package_dev`), the strict uncached suite, the
release whole-program LTO build, `make ci-reproducible` and `make repro-verify`
(two builds from deliberately different absolute paths, byte-identical). The
generic `make t-asan ONLY=zcode_package_dev` does not reach tests: the Sapling
ADX assembly cannot allocate registers under that profile's
`-fno-omit-frame-pointer`, so the ZCODE sanitizer posture uses
`-fomit-frame-pointer -O2` for the monolith.

The standard profile composes two exact existing package actions and requires
a clean warning-fatal ASan+UBSan result in both canonical package receipts: the
human result reports two compile receipts, two declared-test receipts and
`passed_asan_ubsan`, and explicit acceptance reaches PROVEN. The confined
sanitizer executor uses a non-PIE binary and the fixed `setarch x86_64 -R`
wrapper so randomized placement does not trip `Shadow memory range
interleaves`. An unavailable or dirty sanitizer exits without a successful
package receipt; it is never relabeled as clean.

The broader owner directive is not fully closed:

1. `strong` and `release` fail closed on their additional deterministic fuzz,
   reproduction and independent-review requirements. Composing the existing
   fuzz and reproduction owners without falsely claiming physical independence
   is the largest remaining product bottleneck.
2. The fixed Codex coding adapter is implemented, but a host without
   `CODEX_API_KEY` or `CODEX_ACCESS_TOKEN` runs no real adapter coding or
   adapter-produced review. Manual handoff and manual independent review are
   operational.
3. Durable `work cancel` is intentionally absent (see "Implementation status").
4. Genuine independent reproduction still requires another physical machine.

No new canonical domain was added. The product reuses the existing task,
context, scope, candidate, patch, recipe, lock, package action, work receipt,
proof set, review, lane and acceptance authorities.

## Hard boundary

Living Commons O0–O7 is frozen except for correctness. This project performs no
ZC23 issuance, token launch, election-authority, custody, wallet, vault,
transaction, core, consensus, live-datadir, service, deployment, restart, GUI,
web IDE, arbitrary model shell, or multi-package workspace work. It never
executes downloaded source automatically and never lets a model accept or
publish its own result. Genuine independent reproduction requires another
physical machine and remains a separate owner-gated operational task.
