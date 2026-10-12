<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Measured fleet development contract

Status: implementation contract with partial fixture evidence; complete fleet,
cost and model-quality qualification remains **NOTRUN**.
This document supplies detail for [FORWARD_PLAN.md](FORWARD_PLAN.md), without
changing its priority order or granting execution or publication authority.

## Mission capsule

| Field | Contract |
|---|---|
| NORTH STAR | Minimize total cost per accepted development task while preserving receiver authority and public-node priority. |
| USER OUTCOME | Explain each task's measured consumption and choose a qualified, less expensive complete workflow. |
| CURRENT BASELINE | Source inspection at `b32824a5616c96e40e4bb66398a032b1973e37fa`; no cost, accuracy, route or fleet runtime qualification. |
| OWNED SURFACE | Existing engine receipts, usage importer, worker executor, Codex recovery contract, canonical task model policy and their projections. |
| INVARIANTS | Unknown is not zero; an acknowledgment is not acceptance; uncertain effects are reconciled; no authority comes from a projection. |
| ACCEPTANCE | Accounting conservation, production-caller crash tests, paired accuracy qualification, complete workflow efficiency and twenty three-host lifecycle cycles. |
| CONTINUATION QUEUE | Passive accounting; reconciliation and shadow routing; executor fixtures; budgeted model and cache qualification; granted publication. |
| ESCALATE ONLY IF | Required host admission or receiver authority is unavailable, a human budget/product decision is missing, or a repository escalation boundary is reached. |

Initial operation observes explicitly mapped, already-authorized Codex sessions.
It does not set goals, send turns, launch sessions, purchase credits or publish.
No dollar cap, model entitlement, server readiness or savings is assumed.
Automatic execution requires finite budget and deadline policies and completed
qualification. Publication additionally requires an explicit scoped owner grant.

## Source baseline and ownership

These are source observations, not runtime claims. Each link pins the inspected
revision; revalidate against the implementation candidate before changing code.

| Existing owner | Observed contract | Extension |
|---|---|---|
| [Engine receipts](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/engine/modules/engine/include/engine/engine_receipt.h) | Invocation counters, unknown usage, requested/resolved model and gates; v1 unit identity may collide within one second; local chain is unsigned. | Reference unique attempt and canonical signed observation objects. Preserve v1 readers. |
| [Usage importer](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/tools/command/native_devagent_usage.c) | Bounded, read-only Muse/Claude folding with explicit missing counters. | Codex ingestion, explicit mapping, namespaced deduplication and durable checkpointing under existing storage authority. |
| [Worker](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/tools/command/native_devagent_worker.c) | Claim before submission, bounded executor seam, crash refusal and fresh gates. | Qualified Codex executor, durable attempt fencing and budget admission. |
| [Goal recovery](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/tools/command/native_devagent_codex_goal.h) | Accepted, uncertain, applied, readback, terminal and quiescent are separate facts; callbacks retain storage/process authority. | Production controller with verified runtime identity and exclusive session ownership. |
| [Canonical task](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/contexts/commons/modules/vcs/include/vcs/zcode_dev.h) | Source, write scope, acceptance, proof and model policy roots. | Verify a versioned model-policy object at admission. |
| [Adapter benchmark](https://github.com/z23c/z23/blob/b32824a5616c96e40e4bb66398a032b1973e37fa/tools/dev/zcode_adapter_benchmark.sh) | Full, indexed, hybrid and stable-prefix arms. | Complete workflow cost, held-out accuracy and cold/warm context comparisons. |

Reuse CAS, canonical actions and receipts, build-fabric leases, authenticated
transport and ActiveRecord save lifecycles. Usage indexes, local queues and
dashboards remain rebuildable projections. Do not create a fleet ledger or shell
orchestration service. Keep imported transcripts inert and private; retain only
bounded metadata and authorized evidence references in shared objects.

## Cost-driven implementation architecture

Extend the existing ActiveRecord models and native services. Use command and
external tool responses as views and thin controllers; a browser MVC framework is not a
prerequisite. The boundaries below are implementation requirements, not claims
that task-cost accounting is complete.

| Boundary | Responsibility | Acceptance |
|---|---|---|
| ActiveRecord models | Typed observations, immutable evidence references, checked units and valid field combinations | Unknown counters remain unknown; invalid records fail without partial writes. |
| Services | Attribution, budget admission, routing, dispatch, reconciliation and settlement | Transactions and conditional writes enforce ownership and conservation under concurrent callers. |
| Provider adapters | Runtime capabilities, raw usage and external-effect acknowledgments | Duplicate and reordered fixtures preserve identity; uncertain effects are not retried blindly. |
| CLI and external tools | Bounded projections, refusal reasons, evidence and the next permitted action | Responses expose coverage and freshness without copying transcripts or inventing authority. |

Model validation cannot prevent a concurrent lease renewal or duplicate dispatch.
Test those invariants through real service callers, database reopen and
deterministic interleavings. Distinguish a prevented duplicate launch from
measured monetary savings.

Prioritize complete workflow attribution and demonstrated waste before adding
more workers or orchestration features. A fixed cohort includes rejected and
abandoned work in its numerator and accepted tasks in its denominator. Include
all attempts and independent reviewers exactly once. Compare configurations only
under the same acceptance policy and a declared accounting interpretation;
report unresolved expenditure separately and do not qualify cheaper routing
from incomplete coverage. Cache-hit percentage and worker utilization are
diagnostics, not the optimization objective.

### Template-driven production and distributed storage

Recurring C23 task types use a selected procedure, exact source exemplars,
required inputs and a registered acceptance contract. The coverage catalog is
[`C23_TASK_CATALOG.md`](./C23_TASK_CATALOG.md). Its first 100 types are editorial
priority coverage; its broader 500-type scope is not an empirical ranking or
a claim that each type has an optimized model. Keep observed sample counts,
accepted-task cost, repair cost and accuracy separate from proposed coverage.
Compile executable procedures through `engine/composition/prompt_templates.def`;
dispatch only the selected kind instead of copying the entire catalog into
every prompt. Template identity, model configuration and acceptance policy
must remain attributable when comparing outcomes.

The durable shared store must survive replacement of a worker or coordinator.
Reuse content-addressed task, candidate, action, template and receipt objects
and existing authenticated peer transport. Local SQL tables and dashboards are
indexes and projections; they must not become the only copy of shared evidence.
Immutable-object replication is separate from authority over leases or mutable
state. A transferred hash, signature or self-signed receipt alone establishes
neither qualified computation nor global ownership. Preserve conflicting
evidence and enforce receiver policy under partitions.

Selected template serialization and local CAS readback are an implementation
step, not full swarm durability. Complete the peer-transfer closure, bind it to
task/model policy, and verify replica presence and recovery independently.
Acceptance must cover loss of the originating host, unavailable replicas,
corrupt objects, concurrent claims, stale-owner writes and recovery after a
partition. No global consistency or replica count is established by local tests.

The task-facing view should offer one sequence: choose a type, preview the
selected procedure and required evidence, run under the existing authority,
then inspect the exact result and total attributable cost. Unknown cost or
accuracy remains visible. Controllers validate inputs and render service
results; models enforce valid records; services own effects and reconciliation.

## Versioned evidence and accounting

### Native work-map dashboard telemetry

The candidate implementation extends `zcode.work.map` without introducing a
second progress store. A supplied map root identifies one bounded canonical
milestone, feature and loop definition; it does not prove coverage of the
entire forward plan. Traverse `next_offset` until `-1` to inspect every row.

| Output | Meaning |
| --- | --- |
| `definition_counts` | Milestones, features, loops, explicit dependencies and parent edges across the complete admitted map |
| `task_coverage` | Verified, unobserved and expired verified task objects in the returned page, recomputed after byte-budget trimming |
| `text` | ASCII rendering of returned rows only; task-object verification does not change acceptance from `UNKNOWN` |
| `selected_evidence.lifecycle` | Recorded local action state, attempt count, claim/start/finish/update times, heartbeat and expiry |
| `forecast.missing_evidence` | Explicit missing workflow history, cost attribution and whole-map acceptance; no completion date is inferred |

Lifecycle timestamps are recorded Unix values, with zero meaning unreported.
They are neither an atomic fleet snapshot nor proof of current execution.
Selected-action proof or accepted-work qualification retains its existing
scope; neither accepted children nor one selected action qualify a parent's
integration acceptance. The command remains read-only, resolves task objects
only for the requested page, and retains the 4096-byte response-data bound.

The next measurement requirement is to bind every forward-plan feature to its
canonical task and acceptance roots, then retain comparable end-to-end task
durations, review/repair history, account-capacity holds and complete costs.
Until that history and scope are qualified, report unknown forecasts with
their missing evidence. Recorded proof runtime alone cannot predict delivery.

Introduce referenced, versioned objects without changing the interpretation of
old receipt bytes. Each observation binds the following fields, with explicit
presence indicators for unavailable values:

- Task and parent-task roots, attempt identity, host and executor identities.
- Account namespace, provider, session/thread, turn and provider-request identity.
- Requested and effective model, effort and tier; runtime version and exact
  configuration root. Requested values never fill missing effective values.
- Raw counters, counter semantics, reporting scope, source cursor, source
  generation, observation and event timestamps, coverage and evidence roots.
- Candidate, action and acceptance references when they exist.

Allocate attempt identity before external dispatch using the existing canonical
identity facilities with host/issuer namespace and collision-resistant entropy.
Neither wall-clock seconds nor a turn ID identifies every provider invocation.
Do not reinterpret historical v1 unit IDs as globally unique attempts.

An explicit mapping binds authorized account/session and source generation to a
task/attempt and configuration. A directory name, prompt text or account usage
delta cannot establish task attribution. Unmapped expenditure stays unallocated.
Child-task and reviewer usage belongs in workflow totals exactly once; parent
rollups reference child observations instead of copying their charges.

Separate incremental request observations from cumulative snapshots. A snapshot
is never added to its increments. Derive a delta only within the same namespace,
generation, counter semantics and continuous reporting interval. A reset, fork,
missing predecessor or conflicting snapshot creates a coverage gap; it does not
justify subtraction across epochs or a fabricated zero. Late events may refine
a projection without changing immutable source evidence.

Deduplicate by provider/account/session/generation/request identity and counter
scope. Exact repeats are idempotent. Conflicting bytes under the same identity
are preserved as conflicts and cannot qualify a route. Where an upstream format
lacks a stable request identity, expose a non-additive observation and the gap.
Do not count repeated last-call usage on multi-call turns as new requests.

Persist evidence references, deduplication state and source checkpoint in one
ActiveRecord transaction. A crash before commit replays safely; after commit it
resumes after the committed cursor. Bind cursors to verified source generations,
not pathname and byte offset alone. Never advance over an incomplete physical
record; reject NUL, invalid UTF-8, malformed framing and out-of-range counters
before aggregation. Bound record sizes, scan work, retained rows and responses;
return coverage and continuation information when a bound is reached.

Keep four monetary interpretations separate:

| Interpretation | Required provenance |
|---|---|
| Provider-reported charge | Exact provider record, units, currency and billing scope. |
| Invoice-reconciled charge | Invoice revision and explicit allocation references. |
| Rate-card estimate | Immutable rate revision, effective interval, model/tier and counter semantics. |
| Subscription allocation | Explicit owner-configured allocation rule and accounting period. |

Use checked integer fixed-point amounts with declared units and deterministic
rounding. Detect multiplication, addition and conversion overflow before a
projection is published. Allocation totals plus the unallocated remainder must
equal the account expenditure for each currency/unit and period. Never silently
mix credits, dollars, included subscription usage and purchased-credit charges.
Pricing adapters independently describe cache-read and cache-write treatment;
an absent rate or counter leaves that estimate unknown. Rates and model access
are versioned inputs, not constants inferred from a model name.

The [Codex app-server documentation](https://learn.chatgpt.com/docs/app-server)
is the protocol reference. Qualify the installed runtime and observed schemas;
discovery alone establishes neither account access nor billing completeness.
Retain source evidence for each adapter revision. Do not assume that account
summary fields provide per-task billing.

## Projection API changes

Extend `dev.agent.outcomes`, `fleet.usage` and `steer_brief` additively after
checking their live schemas. Names here are target behavior, not implemented
input keys. Filters select task, parent cohort, model/configuration, host and
observation interval. Responses identify schema, source generation, receiving
policy, coverage, observation age, conflicts, unresolved expenditure and evidence
references. Unsupported control versions refuse explicitly.

Report all attempts, failures, cancellations, repairs, reviews and escalations.
Task cost and cohort cost per accepted task have separate denominators. The
cohort numerator includes all work, including unsuccessful tasks; a cohort with
no accepted tasks has an undefined ratio, not zero cost. Unknown expenditure
prevents a cheaper-route qualification.

Expose uncached input, cache reads, output, compaction and missing counters.
Keep queue, model, tool, build, proof, review and publication durations distinct;
overlapping intervals cannot be summed as end-to-end wall time. Measure host
CPU, peak memory and transfer bytes separately from model charges. Each latency
summary declares sample count, interval, workload and cold/warm state.

## Durable execution and budgets

The authority remains [the canonical lifecycle](CANONICAL_LIFECYCLE.md):

```text
NEED → JOB → CANDIDATE → PROOF_SET → PUBLICATION → REMOTE_RECEIPT
```

Attempt state is a projection of durable action events:

```text
eligible → reserved → dispatch-intent → running → observed → validating
                                ↘ uncertain → reconcile
validating → accepted | repair | refused | failed | canceled
```

| Boundary | Required behavior |
|---|---|
| Reserve | Verify current task, owner epoch, lease, policy, deadline, receiver grant and finite remaining budget. |
| Dispatch | Persist immutable attempt and intent before any external effect; fence against stale owners. |
| Lost acknowledgment | Preserve uncertainty and reconcile exact request/session readback; never relaunch merely because an acknowledgment is absent. |
| Observe | Persist raw evidence; terminal, quiescent and accepted remain independent facts. |
| Validate | Run existing acceptance on the exact candidate; provider completion cannot mark PASS. |
| Settle | Release only demonstrably unspent allocation; retain unresolved possible expenditure across crashes and expired leases. |
| Publish | Require scoped owner grant, independent reproduction, expected-base publication and exact remote receipt. |

Each budget has one authoritative issuer. Its nonoverlapping allocations bind
amount, units, task, recipient, permitted stages, expiry and freshness policy.
Partitions admit only still-valid existing allocations under the receiver's
grant. A worker lease expiring does not recover money that may have been spent.
Admission checks finite deadlines, attempt limits and repair limits as well as
funds. Budget enforcement belongs at the executor boundary. If a provider cannot
enforce a strict bound, report the limitation and refuse a policy requiring it.
Disabling admission or revoking a grant preserves observation and recovery while
blocking subsequent unauthorized stages.

Warm sessions require exclusive ownership keyed by account, project,
model/configuration, tool permissions and compatible context. Verify executable
identity, confinement and task scope before admission. Capability-check the
installed protocol; unsupported goal or cache controls stay unavailable.

Before distributed dispatch, qualify bounded authenticated commands and exact
object transfers in both directions for each participating host pair. Initial
qualification covers two Linux peers and a native arm64 Mac; expansion adds
two more Linux peers under their separate resource limits. Five hosts have
ten unordered pairs and twenty directed routes, including qualified tunnels.
Record peer aliases and object roots, keeping
credentials and private endpoints local. Use existing transport and host
admission; all heavy work runs through `devbuild --wait` and native locks.

## Routing and context qualification

Freeze candidate profiles: GPT-6 Luna low for bounded extraction/navigation/
classification/triage; Luna medium for scoped routine changes; GPT-6.1 Sol medium
for baseline implementation and independent review; Sol high for diagnosis and
escalation. These are hypotheses, not proven suitability. Changed effective
configuration requires renewed qualification.

Start with shadow recommendations only. For a qualified routine class, allow
one Luna attempt then Sol escalation, with at most two repair cycles across the
workflow and all work inside its budget. Sensitive consensus, custody,
authorization and recovery changes use Sol with independent review and existing
owner gates. Model agreement and confidence cannot substitute for acceptance.

Freeze identical tasks for paired complete-workflow comparison against Sol
medium, with tuning tasks separate from held-out qualification. Predeclare the
paired confidence procedure and sample plan. Each admitted task class needs a
one-sided 95% lower confidence bound on routed-minus-baseline success of at least
−0.02. Insufficient evidence leaves it unqualified; all mandatory safety and code
gates must pass independently. Include escalation and review in both quality
outcomes and cost. Choose the least expected complete-workflow cost only among
qualified profiles that meet the task deadline and policy.

Extend the existing adapter benchmark to measure three independent reuse layers:
provider prompt reuse, exact source-bound context reuse, and receiver-qualified
build/proof reuse. Place stable instructions and tools before changing task
details. Measure history growth and compaction; neither a common prefix, resumed
session nor model switch proves cache reuse. Report cold/warm p50/p95 latency,
sample sizes, full configuration and accounting coverage. Promote only measured
cost improvements that retain quality and deadlines, not cache-hit percentage.

## Implementation specification for subsequent agents

Research refreshed on 2026-10-08 against the same freshly fetched upstream
`b32824a5616c96e40e4bb66398a032b1973e37fa`. The local checkout remains behind;
inspect these paths at that revision rather than assuming local files match.
The following details are proposed contracts, not implemented API declarations.

### Source seams and first changes

| Source at the pinned revision | Verified behavior and implementation action |
| --- | --- |
| `tools/command/native_devagent_usage.c:20` | Muse/Claude normalization is a bounded read-only fold. Add Codex decoding as a separate format, then persist observations/checkpoints through the existing model lifecycle rather than making the scanner a database authority. |
| `tools/command/native_devagent_worker.c:1911` | Production selects `zcl_devagent_worker_muse_executor`. Introduce qualified provider selection at this seam while preserving admission, fresh gates and receipts. |
| `tools/command/native_devagent_codex_goal.h:69` | `cga_record` preserves accepted, uncertain, applied, readback, terminal and quiescent separately. Implement durable callbacks through the existing action owner; never infer resend permission from matching readback. |
| `engine/services/include/services/build_fabric_async.h` | Exact actions deduplicate to REQUESTED; transitions append rooted proof events. Reuse its event/receipt pattern and timing semantics rather than adding a fleet database. |
| `engine/services/include/services/build_fabric_cache.h` | Restore rechecks accepted evidence; receipt replay explicitly does not qualify arbitrary new requests while executable tool-byte binding is incomplete. Preserve that limit. |
| `tools/dev/zcode_adapter_benchmark.sh:9` | Existing arms include full, index, hybrid, stable hybrid and app-server stable hybrid. Extend these arms with configuration and workflow accounting. |
| `tools/dev/zcode_adapter_benchmark.sh:388` | Current token extraction, also at lines 403–405, substitutes zero for missing counters. Before cost qualification, add explicit missing/coverage fields and reject incomplete financial comparisons. Historical output is not billing evidence. |

Use the built navigator and live schemas when available; otherwise `git show
<source>:<path>` supplies source-only inspection. Recheck symbols and placement
against the chosen implementation base. Preserve the adapter benchmark as test
glue; production orchestration belongs in native C23 services.

### Provider and configuration contract

A versioned adapter exposes discovery, capability qualification, passive
observation, bounded submit, readback, cancellation and reconciliation. Each
operation returns supported, unsupported or an explicit failure; an absent
capability is never synthesized. Cancellation acknowledgment does not establish
quiescence or final billing. A provider without request-id readback may leave an
attempt uncertain indefinitely; resolution then needs evidence or an owner
disposition, not an automatic replacement request.

The immutable configuration root covers provider and adapter revision, requested
model, effort, tier, runtime executable identity, account namespace, tool schemas
and permissions, instruction/context roots, sandbox policy, output limits,
compaction policy, pricing revision and capability evidence. Keep secrets outside
these objects. Record actual effective configuration per call, including reroutes;
do not silently merge it into the requested profile's qualification cohort.

Admit additional vendors or local models through this same contract. Local
inference reports measured host resources and any explicitly configured resource
allocation; it does not invent a provider bill. The operator selects the primary
optimization unit for a cohort: attributable money, credits or subscription
allocation. Report other units alongside it without silently converting them.

Current official references are [Codex pricing](https://learn.chatgpt.com/docs/pricing),
[app-server events](https://learn.chatgpt.com/docs/app-server), and
[API prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching).
Codex credit billing has no separate cache-write charge; included subscription
usage cannot be calculated from credit prices alone. The app-server documents
thread usage updates and model reroutes; qualify the installed schema and scope
before treating either as request-level accounting.

### Accounting and state-machine invariants

For each accounting interpretation and frozen cohort:

```text
workflow_cost = sum(unique attributable observations for all workflow attempts)
cost_per_accepted_task = sum(all cohort workflow costs) / accepted_task_count
account_expenditure = allocated_expenditure + unallocated_expenditure
budget_total = available + reserved + settled + unresolved
```

Budget categories are mutually exclusive in the authoritative issuer's unit.
Moving an uncertain reservation to unresolved does not restore available budget.
Unknown amounts carry coverage separately and cannot enter arithmetic as zero.
Report model-only cost first; an explicitly configured resource valuation can
add a separate total-cost view. Avoid charging a nested child or reviewer twice.

Each transition binds event version, predecessor root, task/action/attempt,
owner epoch, lease, policy/configuration, allocation, evidence and outcome.
The owning transaction verifies the expected predecessor and authority, stores
the transition and its outward-effect intent, then commits before dispatch.
Consumers deduplicate by immutable event identity. A conflicting predecessor or
payload is retained as a conflict and blocks affected admission.

After restart, reconstruct state from durable evidence before taking work.
Reconcile every persisted intent that might have reached a provider. At-least-once
transport plus deduplication is required; exactly-once external effects are not
claimed without provider support. A replacement owner cannot spend the same
allocation or inherit a warm session without fencing the old owner. A partition
may sacrifice availability to preserve expenditure and receiver authority.

Repair creates a new attempt linked to the failed candidate; escalation creates
a new attempt with the selected configuration. Neither overwrites failure
history. Validation acceptance and financial settlement advance independently:
a candidate may pass while late expenditure remains unresolved. Such incomplete
accounting does not qualify the route as cheaper.

### Swarm scheduling and latency

Twenty seats are a concurrency ceiling, not a utilization objective. Represent
work as existing task/action dependencies with disjoint write scopes. Allocate
ready work only after source, receiver grant, budget, deadline, provider capacity,
host capacity and downstream proof/review capacity pass admission. P0 contention
always wins. Reserve capacity for review and recovery rather than filling every
seat with proposal generation.

Select among qualified profiles using complete-workflow expected cost, including
failure, escalation, repair, review and context reconstruction. Unknown estimates
retain the baseline or remain shadow-only. Warm-session affinity is a tie-breaker
only when its measured savings exceed queue delay and it preserves the deadline.
No fixed Luna/Sol seat split is assumed. Respect account-wide subscription pacing
across all hosts; adding machines does not multiply the subscription allowance.

Use existing asynchronous notifications and bounded backpressure. Record queue
age and admission refusal reasons. When the proof backlog reaches its configured
limit, stop generating new candidates and drain verification. Never release a
lease on silence alone. Prevent starvation with a bounded waiting policy within
the receiver's priority classes.

Task policy declares an end-to-end deadline and stage allowances before dispatch.
Measure time-to-first-useful-result and completion p50/p95 alongside acceptance
rate and throughput. Compute local intervals with monotonic clocks; preserve UTC
timestamps for correlation, and mark cross-host clock uncertainty rather than
subtracting unsynchronized timestamps. The existing 100 ms query and one-second
telemetry targets do not establish a model-completion SLA.

### Cache experiments and quality gate

Extend the existing benchmark with a frozen experiment manifest: source/tasks,
adapter/runtime, profile, context strategy, permissions, randomization seed,
accounting interpretation and deadline. Compare cold and warm samples separately.
Interleave matched arms to limit time-of-day and provider-load confounding;
separate warm sessions to avoid accidental cross-arm history contamination.

Experiment factors are full/index/hybrid context, stable versus changing prefix,
new versus exclusively resumed session, bounded excerpt size, compaction policy,
and host-local versus peer-supplied exact objects. Change one factor first, then
test interactions that show promise. Record provider cache-read counters,
uncached input, output, reported cache writes, compaction, context transfer,
verification CPU, acceptance and latency. Prompt bytes shared are only a proxy.

For supported API adapters, qualify explicit cache breakpoints and retention
against the selected model. A matching textual prefix alone does not guarantee
cache reuse; tool schemas, effort and compaction can change the rendered prefix.
Codex adapters expose only controls their installed runtime actually supports.
Never pad with irrelevant text to manufacture cache-hit ratios. Promote a strategy
only when complete workflow cost improves and quality and deadlines still pass.

Predeclare paired success as accepted exact output within the task deadline and
all mandatory gates. Timeouts, cancellations and exhausted repairs count as
failures; exclude only predeclared invalid-task conditions symmetrically. An
independent reviewer receives the task/candidate evidence without routing labels.
Model judgment alone does not certify source correctness.

A conservative reproducible initial statistical procedure is a paired
multinomial bound: count routed-only successes and baseline-only successes over
all frozen pairs. Compute a one-sided 97.5% Clopper–Pearson lower bound for the
first proportion and upper bound for the second; subtract the latter from the
former. Bonferroni gives at least 95% coverage for this difference bound. Require
the result to be at least −0.02 separately for each task class. Predeclare sample
size and one final analysis; repeated peeking cannot justify early promotion.
Unit-test the C23 calculation against independently verified exact binomial
fixtures. More efficient paired methods require their own reviewed contract.

### Ordered implementation handoff

| Slice | Concrete deliverable | Exit evidence |
| --- | --- | --- |
| A | Codex observation decoder, explicit mappings, unique attempts and atomic checkpoints | Production importer fixtures reconcile replay, gaps, resets and malformed records exactly. |
| B | Versioned rates/allocation and configuration objects; additive outcomes and usage views | Conservation and overflow fixtures; every display identifies coverage and monetary interpretation. |
| C | Model-policy verification and shadow Luna/Sol recommendations | No dispatch effect; replayable recommendation from exact policy, cohort and cost evidence. |
| D | Codex executor callbacks and durable budget/intent transitions | Production-caller crash matrix, stale-owner fencing and uncertain-send reconciliation pass without model calls. |
| E | Frozen quality/cache experiments and account-aware admission | Budgeted paired workflows meet the accuracy bound, measured cost improvement and deadlines for each admitted class. |
| F | One-host canary, then five-host route/platform expansion | No duplicate dispatch; revocation/partition/restart tests; twenty three-host lifecycle cycles and independent Mac evidence. |
| G | Scoped publication under existing owner grant | Exact candidate reproduction, expected-base publication and remote readback; uncertain publication reconciled before retry. |

Each slice hands off source/base, native scope claim, configuration/evidence
roots, focused checks, limits and next action. Rollback disables new admission
while keeping observation and reconciliation live. No slice promotes itself from
fixture success to model, fleet or publication qualification. The next coding
task is slice A on a current owned base; installed adapter tools alone do not complete
it. No new model calls or subscription spending are required for A–D fixtures.

## Delivery and acceptance matrix

All rows below remain unqualified until exact candidate evidence is recorded.

| Slice | Production-boundary acceptance | Initial status |
|---|---|---|
| Passive accounting | Mapped-session fixtures cover duplicate/reordered/late events, cumulative snapshots, missing values, resets, forks, resumes, same-second attempts, cross-account collisions, child tasks, multi-call turns and cancellations. No session control occurs. | NOTRUN |
| Reconciliation and shadow routing | Checked overflow, immutable rate revisions, subscription conservation, unallocated expenditure, stale coverage and conflicting evidence; unknown cost refuses cheaper-route qualification. No paid dispatch. | NOTRUN |
| Codex executor | Deterministic provider fixtures verify identity, confinement, scope, limits and usage capture through the worker caller. | NOTRUN |
| Recovery | Inject crashes before/after reservation, intent, dispatch, observation, settlement, candidate and publication persistence. Cover lost acknowledgments, stale owners, restart epochs, revocation, partitions and malformed/conflicting records; prove no unauthorized duplicate effect or budget reallocation. | NOTRUN |
| Accuracy and efficiency | Explicitly budgeted held-out paired workflows satisfy the per-class confidence gate; every attempt and reviewer contributes to cost; cold/warm metrics include coverage. | NOTRUN |
| Fleet and publication | Twenty three-host lifecycle cycles including worker/publisher crashes, independent Linux/arm64 Mac verification, expected-base publication and exact remote readback under an owner grant. | NOTRUN |
| Latency | Warm local query p95 below 100 ms and telemetry acknowledgment p95 within one second under declared healthy-link conditions. | NOTRUN |

Extend registered groups `json`, `engine`, `devagent_outcomes`,
`devagent_worker`, `devagent_worker_guards`, `build_fabric`, `zcode_dev_objects`
and affected fleet groups. Use the canonical test runner, followed by applicable
lint, architecture, generated-interface and integration gates. Deterministic
fixtures precede model calls. A helper-only test does not qualify its production
caller; fault tests must observe the actual admission/effect boundary.

## Implementation evidence and next action

### Current implementation lane

Focused implementation evidence is recorded in
[the accounting and dispatch experiment](../experiments/2026-10-08-agent-fleet-accounting.md).

On 2026-10-08 the implementation lane was created at
`b8be01b0e6a7886fa195100d07d2f2b0e2094d4c`, after fetching current upstream.
The older documentation checkout was preserved. Native scope claims cover the
usage importer and outcomes fixtures. A separate remote worktree uses installed
host admission for setup and canonical focused tests; no production node changes
are part of this lane.

The first decoder proposal exposes cumulative session observations only. It is
not task attribution, durable checkpointing or cost reconciliation. Independent
review identified two required refusal cases: inherited counters across forked
generations must not be added as new expenditure, and malformed metadata must
not leave a previous identity active for subsequent observations. Qualifying
fixtures must cover both before acceptance.

Source review at this base also establishes the next durable-execution slice:

- `cga_execute` and `cga_reconcile` currently have test callers only. The
  production worker's `wkr_run_fresh` performs its pre-spend guard, then marks
  submitted and forks. Durable reservation/intent admission belongs before that
  submitted transition, not inside an already-running provider process.
- `wkr_drive_opts` and `wkr_job` need verified bindings to the existing database,
  action and lease. Do not fabricate action roots from local queue names.
- `db_build_action` owns action/lease/attempt state but does not supply a funding
  issuer. Extend the existing engine model authority with typed budget grants
  and action-linked reservations/intents; do not repurpose unrelated trimmed
  descriptor fields or create a filesystem spending ledger.
- Database schema version is 86 at this source. Locate the migration tail in
  `engine/models/src/database_migrate_features_v67_up.c` and the version in
  `engine/models/include/models/database.h`. A subsequent migration must retain
  the existing persistence-floor and migration-stamp rules. Recheck the version
  before implementation; this is a source observation, not a reserved number.
- Pattern conditional writes on `db_build_action_save_leased` and transactional
  claim/job saves in `build_fabric_service.c`. Check current lease, owner epoch,
  immutable command binding and remaining allocation in the same transaction
  that persists intent. Preserve historical attempts through existing evidence.
- Sender grants establish send authority, not model expenditure authority.
  Private-object receive grants explicitly deny execution and cannot substitute
  for a funding grant. A budget policy must name its issuer, unit, account/model
  scope, deadline and uncertain-reservation disposition before real dispatch.

Acceptance crosses the actual database reopen and worker launch boundaries:
registered build-fabric fixtures cover transactions, concurrent handles and hook
rollback; worker/guard fixtures prove refused reservations launch zero executors.
Goal-helper fixtures alone cannot close this slice. No provider-quality claim
follows from these deterministic tests.

Five preparatory Sol-medium tasks are queued through the existing coordinator,
each with a 120000-token ceiling. Their scopes are delivery verification,
accounting, recovery, cache experiments and capacity. Queue admission remains
subject to subscription pacing and downstream test capacity; queued is not
running. Their reports are proposals requiring integration and verification.

### Earlier contract evidence

Contract prepared at local `2026-10-08T02:58:23-04:00`, UTC
`2026-10-08T06:58:23Z`. Fresh fetch matched `origin/main` to
`b32824a5616c96e40e4bb66398a032b1973e37fa`. The inspected local checkout remains
at `3a93e60ebf922af3d119b9facc1d95803f42844b`, 666 commits behind; it was clean
before this documentation slice. Native `dev.agent.start` reported a standalone
checkout and `dev.agent.claim` accepted the bounded documentation/importer scope.
Those observations establish neither a current-source build nor fleet authority.

Local laptop preflight found neither `devworker` nor `devbuild` on PATH; the expected
`~/.local/bin/` files were also absent. The repository's `platform/deploy/devbuild`
is explicitly a reference mirror, not the installed host authority. Build,
runtime, sanitizer, mutation, integration, model and fleet tests are **NOTRUN**.
No executable implementation or cost saving is claimed by this documentation
slice. No session mapping, budget policy or publication grant has been supplied.

Static verification: the documentation patch passes whitespace checks and
`git apply --cached --check` against an isolated index loaded from the pinned
upstream commit. Referenced local lifecycle documentation exists in both source
revisions. These checks establish documentation applicability only.

Subsequent remote inspection found installed development admission on the two
primary Linux hosts and the arm64 Mac. The local absence is not a fleet-wide
blocker. Codex CLI integration is recorded below; it does not qualify the
accounting, routing or executor changes in the acceptance matrix.

Next action: continue in an existing sanctioned development workspace,
acquire current native ownership, and safely
prepare the pinned current source. Implement passive accounting first, using
synthetic mapped-session fixtures until real session mappings are explicitly
provided. Record exact source/base, focused checks, canonical evidence roots,
remaining gaps and next action for every subsequent slice.

## External Codex adapter evidence

On 2026-10-08, the four Linux worker hosts and native arm64 Mac reported
Codex CLI 0.161.0 and existing ChatGPT login. Private receiver configuration,
protocol-specific installation commands and artifact hashes belong in the
external adapter package's receiver evidence, outside the native node tree.
The node continues to expose its typed native command and service contracts.

The worker adapter passed 799 fixture checks on each host. Task-contract
fixtures passed 459 checks on Linux and arm64 macOS. These are adapter tests,
not model-quality, complete accounting or fleet publication acceptance.
Installed capacity is twenty Linux seats; subscription pacing and test-backlog
holds remain in force. Capacity does not establish active execution.
