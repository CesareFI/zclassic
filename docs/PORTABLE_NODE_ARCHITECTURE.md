# Portable Node Architecture

Status: incremental migration contract, 2026-09-17.

This document defines how the existing Zclassic full node becomes a portable,
embeddable node without changing the Zclassic chain, consensus rules, monetary
policy, proof of work, transaction rules, upgrade heights, or historical block
acceptance. It is an implementation roadmap, not permission for a rewrite.

## Language and compatibility decision

The authoritative node in this repository is C23. `make check-c23-only`, the
sealed-core manifest, and the current build graph make that an enforced source
property. Translating consensus code into C++ would create a second semantics
implementation and a large historical-compatibility risk.

Therefore the portable engine remains the existing C23 engine. It exposes a
small C ABI that can be consumed directly by C++, JNI, or a native Android
service. A future C++ convenience wrapper may live in the Android adapter, but
it must not duplicate validation or own consensus state. Changing the core
language is a separate repository-policy decision and would require
differential validation against every historical consensus vector; it is not a
precondition for Android embedding.

The architectural shape is still the intended one:

```text
Kotlin UI / Android service
            |
       narrow JNI adapter
            |
    versioned C lifecycle ABI
            |
 portable authoritative node engine
   | consensus | sync | P2P | storage ports |
            |
 Linux / Android platform adapters
```

## Non-negotiable invariants

1. There is one authoritative implementation of consensus and transaction
   validation.
2. A platform adapter may provide time, files, sockets, entropy, thread, and
   lifecycle services. It may not decide whether a block or transaction is
   valid.
3. Pruning changes retention, never validation. Every accepted block is fully
   validated before data becomes eligible for pruning.
4. Peer-controlled counts, lengths, queues, and allocations are bounded before
   allocation or iteration.
5. A disconnected or stalled peer releases every request it owns. Another
   usable peer can acquire the work without deleting or rebuilding chainstate.
6. Shutdown retains ownership of every worker until it exits or the host makes
   an explicit process-level failure decision. No detached worker may retain a
   pointer into a destroyed node.
7. The C/JNI boundary exposes values and opaque handles, not mutable internal
   pointers or C object graphs.
8. No exception, signal jump, or platform-specific error representation crosses
   the C ABI.

## Current architecture

The repository already contains useful boundaries, but the full node is still
assembled as a process rather than as an owned library instance.

| Area | Current authority | Important property | Remaining coupling |
| --- | --- | --- | --- |
| Consensus predicates and parameters | `core/consensus`, `core/params`, `core/chainparams`, validation and script modules under `core/` | Covered by `core/MANIFEST.sha3` and parity gates | Some orchestration and networking code is in the same sealed source tree |
| Chainstate mutation | `engine/reducer`, validation jobs, coins and storage modules | Intended one-writer reducer model | Process-wide state and boot ordering still expose implicit lifetime |
| P2P and hostile-input parsing | `core/modules/net` | 2 MiB frame bound, bounded queues, peer scoring, disconnect cleanup | Socket creation, global managers, and service lifecycle are not instance-owned |
| Sync planning | `core/modules/sync`, `engine/services` | Planner/service split; bounded block and header scheduling | Several schedulers use process-global instances |
| Platform services | `platform/modules/platform` and `platform/modules/util` | Existing Linux, Darwin, and Windows seams | POSIX/Linux feature tests still appear in consumers; Android is not a published target |
| Storage contracts | `platform/ports/include/ports` | Opaque `self` plus function-table ports | Coverage is partial; many node stores still depend directly on SQLite/filesystem policy |
| Storage implementations | `platform/adapters/outbound/persistence` | SQLite, file, legacy, and in-memory adapters are physically separate | No Android storage policy or pruning policy is composed yet |
| External app ABI | `engine/modules/framework/include/zclassic23/app.h` | Versioned C ABI, fixed-size values, opaque handles, `extern "C"` compatibility | This is an app capability ABI, not a node lifecycle ABI |
| Process entry/lifecycle | `engine/entry`, `engine/composition`, signal and supervisor utilities | Central thread registry and shutdown flag exist | Startup, shutdown, signals, daemon policy, and singleton state remain intertwined |

### Existing sync safety baseline

The current branch adds and tests these behavior-preserving reliability rules:

- block request expiry uses monotonic elapsed time and survives wall-clock
  rollback;
- disconnect cleanup releases block-swarm pieces and header-range ownership;
- received-block deduplication is bounded and survives table growth;
- header spans are released on empty and terminal replies;
- actual progress renews a span deadline;
- continuation requests keep the assigned stop hash;
- all eligible peers contribute to a stable shared header target;
- a fresh-node bootstrap can retry after peer discovery without replacing live
  reducer state.

The header-range integration now lives in
`core/modules/net/src/msg_header_range.c`; parsing remains in
`msg_headers.c`. This is an orchestration split only. Header acceptance, PoW,
checkpoint data, contextual validation, and chain selection are unchanged.

## Target boundaries

### Portable node engine

The portable engine owns:

- block, header, transaction, script, transparent, and shielded validation;
- chainstate state transitions and recovery journals;
- peer protocol parsing and serialization;
- peer discovery policy and peer reputation;
- header and block request ownership, scheduling, retry, and cancellation;
- mempool admission and transaction relay policy;
- bounded resource accounting;
- lifecycle state and cooperative cancellation;
- storage policy expressed only through ports; and
- immutable status snapshots for host-facing consumers.

It may depend on standard C23, project primitives, and declared platform/storage
ports. It may not call Android framework APIs, JNI, systemd, `fork`, `exec`, or
process-global signal installation.

### Platform adapters

Platform adapters implement explicit capabilities:

| Capability | Linux adapter | Future Android adapter |
| --- | --- | --- |
| Files and directories | POSIX paths, permissions, atomic replacement, disk-space probes | app-private/files directory, scoped permissions, atomic replacement supported by the NDK/filesystem |
| Sockets and name resolution | POSIX sockets, resolver, proxy/Tor composition | bionic sockets and resolver; network changes reported as lifecycle events |
| Time | wall and monotonic clocks | bionic wall and monotonic clocks |
| Entropy | OS RNG adapter | Android/bionic secure OS RNG |
| Threads | pthread creation, naming, bounded join | pthread creation/naming plus cooperative completion; no glibc timed join assumption |
| Process integration | signals, service manager, CLI and daemon policy | service-owned start/stop, foreground/background policy, no Unix daemonization |
| Diagnostics | stderr/files/operator telemetry | bounded host callback or polled status; never secrets |

Adapters translate platform errors into stable project errors and retain no
borrowed engine pointer beyond the documented lifetime of a call or owned
operation.

### Dependency direction

```text
consensus/domain  --> pure primitives
application/sync --> consensus + storage/network/time ports
platform adapters --> port contracts + operating system
Linux host/JNI host --> node lifecycle C ABI
```

An inward layer never includes an outward adapter. `platform/ports` remains
pure C structs and function pointers with opaque `self` ownership. New ports
must be small enough to fake deterministically in tests.

## Consensus boundary

The following are frozen network behavior:

- block/header and transaction serialization;
- PoW/Equihash verification and difficulty calculation;
- subsidy, fees, supply rules, and upgrade heights;
- transparent and shielded validity rules;
- script behavior and signature hashing;
- checkpoint values and historical exception behavior;
- chain-selection and contextual block acceptance rules.

Platform work may move a call behind a port or split orchestration into another
translation unit only when the same inputs reach the same predicate and the
same result drives the same state transition. A change near this boundary
requires, at minimum:

1. a written statement of why validity is unchanged;
2. `make check-core-seal` and the repository consensus-parity gates;
3. focused regression tests for the moved path; and
4. the full registered suite before publication.

The Android adapter must never contain a fallback validator. If a required
cryptographic dependency cannot be built for an Android target, the Android
build fails closed.

## Threading, cancellation, and lifetime

### Current model

`thread_registry` centralizes spawn tracking and the process-wide shutdown
request. It records join ownership and has a fixed safety capacity of 256.
Its spawn trampoline is the sole authority that publishes completion, and a
registry condition variable now provides deadline-bounded waits before the
final pthread reap. Production registry consumers no longer depend on a native
timed-join or try-join extension. The boot-background and catchup lifecycle
owners now retain their started/owned state when a bounded join times out, so a
caller can cancel cooperatively and retry without detaching or destroying live
state. Aggregate registry drains now use portable completion publication under
one fixed deadline and retain every worker/dependency owner on timeout; the
former unlimited `join_all_owned` fallback has been removed. Several subsystem
stop routines still use direct blocking joins. The four long-running P2P
worker handles now belong to their `connman` instance instead of process-global
pthread variables. Their join uses one aggregate registry deadline; a failed
worker keeps both its instance ownership bit and liveness record, and process
shutdown exits unclean before releasing any network dependency. Process
shutdown still escalates failures through a signal/`_exit` adapter. Those are
the next bounded-shutdown and error-propagation inventory; they are not
acceptable as the final Android lifecycle. The node also has process-global
managers and scheduler instances, so a second in-process node is not presently
supported.

Android bionic does not provide glibc's `pthread_timedjoin_np`, and it also does
not provide the cancellation mechanism used by the current Darwin emulation.
`platform_thread_join_until` now selects Android before Linux and returns
`ENOTSUP` explicitly. The host-side
`test-android-thread-join-acceptance` target proves the preprocessing branch,
while `test-android-thread-registry-acceptance` compiles and executes the
portable completion/timeout/retry path under `__ANDROID__`. These are host
proofs, not NDK or arm64 proofs. See the official
[bionic pthread interface](https://android.googlesource.com/platform/bionic/+/master/libc/include/pthread.h).

### Target model

One future `node_instance` owns, in destruction order:

1. immutable configuration copied at creation;
2. cancellation state and lifecycle mutex/condition;
3. storage adapter handles;
4. chainstate/reducer authority;
5. P2P manager and peer connections;
6. sync schedulers and request ownership tables; and
7. registered worker handles.

The lifecycle is explicit:

```text
CREATED -> STARTING -> RUNNING -> STOP_REQUESTED -> DRAINING -> STOPPED
                         |              |
                         +---- ERROR <--+
```

- `request_stop` is idempotent and non-blocking.
- workers poll an instance cancellation token as well as any narrower job
  token;
- blocking I/O has a wakeup/close path owned by the adapter;
- `join` waits for published worker completion, not a non-portable timed-join
  syscall;
- the owner destroys storage and chainstate only after all consumers drain;
- restart creates new transient network state while reopening the validated
  chainstate; and
- Android activity recreation never owns the node. A service-level host owns
  it and exposes status values to UI instances.

No new detached threads are permitted. Existing bare `pthread_create` and
direct `pthread_timedjoin_np` call sites are migration inventory, not examples
for new code.

## Networking and mobility

The P2P manager must distinguish durable node state from replaceable network
sessions. A network epoch change cancels socket operations, disconnects peers,
and releases their requests. It does not invalidate chainstate.

Required recovery behavior:

- Wi-Fi/cellular changes start a new network epoch and redial discovery inputs;
- DNS, Tor, or proxy failure yields a typed transient state with bounded retry;
- temporary offline state drains sockets and keeps validated storage open;
- resume re-evaluates wall-clock-dependent peer policy while scheduling
  deadlines use monotonic time;
- every disconnect releases block requests, block pieces, header spans, and
  per-peer queue accounting immediately; and
- a healthy peer appearing later can acquire all unfinished work.

Peer protocol parsers continue to treat zero, truncation, overflow, duplicate
messages, invalid enums, sequencing violations, partial reads, and oversized
lengths as normal hostile inputs. Refusal may disconnect or score a peer but
must not crash, leak a queue charge, or allocate from an unchecked declaration.

## Storage boundary and pruning

Storage policy is composed outside consensus. The engine asks ports for atomic
read/write/commit/recovery operations and receives typed results. Adapters own
paths, SQLite settings, file permissions, durability calls, and platform error
translation.

Supported policies are staged, not assumed:

- archival: retain every validated block and index required today;
- reduced indexes: omit optional query accelerators while preserving validation
  and restart facts;
- constrained caches: explicit caps with observable eviction;
- pruned: validate every block, retain enough undo/reorg and chainstate data,
  and delete old bodies only after a durable prune boundary is committed.

Pruning is not ready merely because a file can be deleted. It requires crash
recovery tests, reorg-depth rules, bootstrap/reindex behavior, disk-full tests,
and proof that no consensus or wallet path assumes an old body remains local.
All destructive storage tests use freshly created temporary datadirs. Production
datadirs, wallet files, parameters, and keys are never fixtures.

## Future node C ABI (not frozen)

Android needs lifecycle and immutable observations, not direct access to node
objects. The first ABI design review should cover only these concepts:

- create/destroy an opaque host-registered handle;
- start;
- request stop;
- join with a host deadline/cancellation token;
- copy a versioned status snapshot;
- obtain sync progress, peer count, and tip height from that snapshot; and
- submit bounded serialized transaction bytes and copy a structured result.

Provisional ABI rules:

- every struct starts with `struct_size` and `abi_version`;
- lengths use `size_t` internally and are checked before fixed-width conversion;
- configuration strings and byte arrays are copied during the call;
- output uses caller-owned buffers or fixed-size value structs;
- handles are opaque integers backed by a generation-checked registry, not raw
  pointers cast through JNI;
- destroy is rejected while operations or leases remain outstanding;
- status is a snapshot and contains no borrowed string;
- errors have a stable enum plus a bounded diagnostic message;
- no C++ exception or signal crosses the ABI; and
- no wallet seed, private key, viewing key, or raw secret appears in status or
  diagnostics.

The ABI will be frozen only after the instance lifecycle exists and Linux tests
exercise create/start/stop/restart/error races.

## Resource accounting and budgets

The existing enforced ceilings are evidence, not yet Android tuning targets:

| Resource | Current enforced/default ceiling | Source |
| --- | ---: | --- |
| P2P message payload | 2 MiB | `MAX_PROTOCOL_MESSAGE_LENGTH` |
| Default peers | 125 | `DEFAULT_MAX_PEER_CONNECTIONS` |
| Process receive buffers | 256 MiB, configurable | `net.c` receive budget |
| Process send buffers | 512 MiB, configurable | `net.c` send budget |
| Send buffer per peer | 32 MiB advisory, 64 MiB hard default | `net.c` send budget |
| Header solution cache | 64 MiB | `msg_headers.c` |
| Block download queue | 65,536 entries | `DL_QUEUE_MAX_CAP` |
| IBD blocks in flight | 4,096 total, 256 per WAN peer | `download.h` |
| Header ownership spans | 128, allocation-free | `HRS_MAX_SPANS` |
| Block intake queue | 1,024 entries | `MSG_BLOCK_INTAKE_CAP` |
| Registered threads | 256 safety cap | `ZCL_THREAD_REGISTRY_CAP` |
| Mutable node.db page cache | 16 MiB on effective RAM <=4 GiB; otherwise 64 MiB ceiling | `node_db_recommended_cache_kib` |

These desktop defaults are too large to declare a mobile budget. Before setting
Android defaults, a reproducible benchmark must record peak/steady RSS, thread
count, file descriptors, database/cache bytes, startup, shutdown, restart,
idle CPU, sync CPU, bandwidth, and write amplification on an arm64 device or
emulator profile. Initial Android acceptance requires:

- every variable-size queue has a hard configurable or compile-time ceiling;
- configured budgets are validated before startup and cannot overflow when
  converted;
- thread count is observable and no worker is detached;
- cache reduction changes performance only, never validation; and
- disk-space refusal occurs before an atomic commit can strand partial state.

Numeric Android RSS, CPU, and disk targets remain explicitly `TBD-MEASURED`;
inventing them from a two-core Linux build host would not be evidence.

## Validation matrix

Every migration stage selects deterministic tests from this matrix:

| State/event | Required assertion |
| --- | --- |
| Fresh, partial, and fully synced startup | same validated tip and durable restart facts |
| Stop during header/block sync | bounded stop, no owner leak, restart resumes |
| Abrupt process termination | journal/DB recovery reaches last durable state |
| Peer disconnect or stall | all ownership released and reassigned |
| Healthy peer appears later | progress resumes without chainstate deletion |
| Malformed/partial/oversized peer message | bounded refusal; no crash or unbounded allocation |
| Corrupt temporary download/bootstrap | content refused; authoritative state unchanged |
| Low disk or limited memory | typed failure and bounded cleanup |
| Network loss/DNS/Tor failure | transient state; reconnect does not rebuild chainstate |
| Repeated network epochs | no stale callback, fd, request, or thread survives its owner |

Relevant fast regression groups already include `download`,
`header_range_sched`, `process_headers_adversarial`, `sync_service`,
`boot_bundle_fetch`, and platform tests. Full publication still requires the
repository's complete registered suite and seal/parity gates.

## Benchmarks and fuzzing

Performance claims require before/after receipts with identical compiler,
dataset, cache state, CPU affinity, and configuration. Priority benchmark
families are header deserialization/validation, block deserialization and
validation, chainstate lookup, startup/restart/shutdown, sync memory peak, and
durable bytes written per accepted block.

Fuzzing priority is the P2P frame and CompactSize boundary, transaction/block
decode, bootstrap metadata, address parsing, RPC input, and eventually every C
ABI entry. Corpus inputs must be public/synthetic and contain no wallet or
production data. ASan/UBSan findings are fixed at the source; sanitizer
suppression is not an acceptance result.

## Migration stages

### Stage 0 — preserve and prove the current chain engine

- Keep consensus sealed and document every authorized change.
- Run consensus parity plus focused hostile-input/sync tests.
- Keep production chainstate outside all experiments.
- Restore file-size and capability-inventory gates after integration work.

Exit: reviewed sync baseline is sealed, focused tests pass, and publication
evidence names any upstream/environmental gate failures separately.

### Stage 1 — publish the platform capability inventory

- Separate Android from generic `__linux__` feature tests.
- Inventory direct signals, `/proc`, daemonization, process globals, raw thread
  creation, direct timed joins, sockets, paths, and filesystem calls.
- Add host-side compile fixtures for feature-selection branches.

Current progress: Android timed join is explicit and compile-tested. Registered
production workers wait on portable completion publication; direct
`pthread_timedjoin_np` and `pthread_tryjoin_np` consumers have been removed
outside the platform capability shim and its tests. The former detached onion
bridge pump is registry-owned, and completed registry-owned jobs are reaped
opportunistically so a long-running node cannot exhaust the fixed table. Boot
background and catchup-service timeout paths retain ownership and permit a
bounded retry instead of falling through to an unlimited join.
The process-level aggregate drain now has the same bounded ownership-retaining
contract. The NAT/reachability probe owner also returns a bounded join failure
while retaining its lifecycle bit and registry row, so shutdown refuses to
release runtime dependencies rather than falling through to `pthread_join`.
The same contract now covers all four `connman` workers under one aggregate
deadline, with pthread handles moved into the owning instance. A deterministic
closed-gate regression proves timeout retention followed by a successful
bounded retry. The dialer cancellation token remains process-global, so this is
an ownership milestone rather than a complete multi-instance P2P lifecycle.
Signal/backtrace paths, unregistered raw thread creation, and other direct
blocking subsystem joins remain known blockers.

Exit: portable headers do not select glibc-only APIs under Android macros, and
the unsupported-runtime inventory is explicit.

### Stage 2 — instance-owned lifecycle and cooperative completion

- Introduce node-scoped cancellation and worker completion publication.
- Route all node workers through one ownership registry.
- Replace direct timed joins with a portable wait-for-completion plus final
  owned join.
- Make start/stop/restart race tests deterministic.

Exit: Linux can repeatedly create/start/stop/destroy an isolated instance with
zero live/unreaped workers and no process exit.

### Stage 3 — filesystem, network, and storage ports

- Move path policy, disk-space probes, DNS/socket creation, and network epoch
  notifications behind ports.
- Complete storage ports for chainstate-critical authorities.
- Add in-memory/fault-injection adapters for disk-full, corruption, and
  cancellation tests.

Exit: portable engine sources contain no platform service-manager or Android
framework dependency.

### Stage 4 — bounded mobile configuration

- Measure desktop and arm64 resource profiles.
- Make peer, cache, inflight, and optional-index budgets explicit in immutable
  startup configuration.
- Prove low-budget configurations without weakening validation.

Exit: measured budgets and regression thresholds are checked in repeatable
benchmarks.

### Stage 5 — lifecycle C ABI

- Implement the smallest versioned handle API after the instance model is
  stable.
- Fuzz every ABI input and exercise concurrent stop/status/submit races.
- Keep Kotlin/JNI mapping mechanical and auditable.

Exit: a native Linux harness uses only the public C ABI to run the lifecycle
matrix.

### Stage 6 — Android NDK arm64 proof

- Pin a supported NDK/toolchain and dependency recipe.
- Compile the same portable engine source for Linux x86-64 and Android
  arm64-v8a.
- Link a headless Android native harness without consensus-source forks.

Exit: reproducible build receipts prove both targets from one source identity.

### Stage 7 — Android service integration

- Add the small JNI adapter and service-owned lifecycle.
- Treat foreground/background and network changes as host events.
- Keep UI recreation independent from node ownership.

Exit: Android lifecycle stress tests show bounded stop/restart, intact
chainstate, and no worker/socket use-after-free.

## Known blockers

- No pinned Android NDK or arm64 dependency build is present in this checkout.
- Android lacks native timed-join/cancel mechanisms. Registry-owned workers now
  publish cooperative completion portably, and bounded service owners retain
  ownership on timeout. Aggregate drains no longer have an unlimited fallback;
  stop-error propagation must still replace the process-level signal/`_exit`
  boundary and remaining direct blocking joins.
- signal installation, backtrace/syscall diagnostics, daemon policy, and some
  `/proc` assumptions are still process/platform coupled.
- the full node is not an independently owned `node_instance`; several global
  managers and the P2P cancellation token prevent safe multiple create/destroy
  cycles, although `connman` now owns its four pthread handles directly.
- storage ports do not yet cover every chainstate-critical store.
- Tor, SQLite, cryptographic dependencies, and all generated artifacts need a
  pinned Android build profile.
- a pruning retention/recovery contract has not been implemented or proved.
- final mobile resource budgets await arm64 measurements.

## Definition of portable-core success

The mission is complete only when the same authoritative validation and sync
sources build for Linux x86-64 and Android arm64-v8a, a narrow C ABI owns a
repeatable lifecycle, hostile inputs and lifecycle races are fuzzed/tested,
resource ceilings are measured and enforced, restart/reconnect preserve
validated chainstate, and no Android or Kotlin code duplicates consensus.
