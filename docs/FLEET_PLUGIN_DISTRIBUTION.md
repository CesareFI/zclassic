<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Distributing signed plugin generations

Status: design proposal. No remote installation or execution is implemented
or authorized by this document. Implementation requires reviewer acknowledgment.
Source baseline: `16f864d87ec5701a28a296407649ac24c638ecb8`.
The opt-in plugin status view is present in this published source. Deployment
and fleet runtime qualification remain separate.

## Outcome and existing authority

An owner selects an exact signed plugin generation for one consenting peer.
That peer fetches inert bytes, verifies them under its own publisher policy,
installs locally, explicitly selects the generation, and reports its exact
observed state. Starting a confined process remains a separate local action.
The sender receives evidence of each completed stage, rather than assuming
that delivered bytes mean a running plugin.

The existing [plugin store](PLUGINS.md) and its
[local API](../contexts/commons/modules/plugin/include/plugin/plugin_store.h)
are the authority for strict manifest
parsing, publisher verification, executable hashing, generations and selection.
A generation is the domain-separated SHA3-512 digest of the exact signed
manifest bytes, represented by 128 lowercase hex characters. It binds the
executable hash and declared capabilities. A version label, executable digest
alone, or abbreviated generation is not interchangeable with that identity.

Local install verifies the source and staged copy; installation leaves the
current selection unchanged. Switch re-verifies the generation and updates
current and last-good. Rollback re-verifies its target. These are local owner
commands today, not operations a mesh peer can invoke.

Reuse those boundaries and the existing task, action, CAS and receipt
authorities. Add no parallel plugin registry, trust database, signature
scheme, orchestration daemon or shell command executor.

## Transfer without new execution trust

Use an ordinary content.v2 package and the existing three-step receiver chain:

1. `zcode.package.fetch` fetches by exact root, verifies chunks and supports
   idempotent resumption. Its `maximum_bytes` input supplies a
   receiver-controlled bound. A complete fetch is inert. A one-shot CLI may
   only persist a download request; require verified completion from a hosting
   node before checkout.
2. `zcode.package.checkout` reconstructs that exact ordinary package root into
   an absent destination. It rederives the root and verifies every chunk at
   its coordinate, restoring executable files as mode 0755. Its response
   explicitly reports `executed:false`.
3. `plugin.install` accepts the checked-out plugin manifest, re-verifies the
   plugin publisher and executable, and installs without selecting or running.

These existing commands need no new transport or receiver leaf. Source
boundaries are [checkout](../tools/command/native_zcode_add_command.c) and
[the plugin API](../contexts/commons/modules/plugin/include/plugin/plugin_store.h).
Their composition still needs the proposed hermetic two-store acceptance;
the existence of each command is not an executed integration result.

Keep the ordinary package root distinct from a signed transport-carrier root.
`zcode.package.admit` is the separate importer for complete signed carriers;
it is not an interchangeable substitute for ordinary content checkout.
Package release signatures and plugin publisher signatures have separate
trust roots. Package acceptance never imports a plugin key into trusted keys.

Publisher preparation uses a normal C23 package directory, including
`zcode-package.json`, license and source, with the three `plugin_pack`
outputs carried unchanged. Reuse the existing prepare/export, sign, seal and
create lifecycle. Freeze and test the exact invocation against the current
catalog before calling this a qualified publishing recipe.

For already verified receiver-held ordinary package bytes, the local steps are:

```sh
z23 zcode package checkout --input='{"root":"<64-hex-package-root>","destination":"./plugin-received"}'
z23 plugin install --manifest=./plugin-received/NAME.plugin.json
```

The destination must be absent and beneath an owner-private parent.
Replace the root and NAME with the exact approved values; do not execute
downloaded build or startup scripts. Install is still a separate owner action.

Do not describe a generic `ops.mesh.package` command as available.
`ops.mesh.device.host.package.run` is a fixed tunnel runtime and cannot
serve as an arbitrary plugin installer.

The current `steer_deliver` endpoint accepts one C source file, not a
plugin executable set. Its source-only contract must remain intact. Renaming
an executable to a C filename or encoding it as source is not an admissible
distribution path. A future binary-quarantine adapter would need separate
schema and admission review while reusing the existing quarantine authority;
it is not the initial route proposed here.

The selected plugin consists of the three exact objects produced by
`plugin_pack`, alongside ordinary package metadata and source. Native checkout
uses canonical paths and descriptor-relative no-follow creation. Qualify its
refusals for traversal, links, special files, duplicate members and undeclared
data; do not introduce a generic archive extractor. Install only the selected
manifest with its fixed executable and signature names in the verified tree. Preserve exact manifest bytes; rewriting whitespace breaks
the signature. Never transfer a publisher private key.

## Receiver authorization and bounded requests

The publisher signature authenticates content. It does not authorize another
machine's installation, capability grant, process start or trust-file change.
A paired peer or a status-read grant likewise has no such authority.

The receiver's owner approves the source peer, exact plugin name and generation,
permitted capabilities, platform, lifetime and resource limits. An owner may
approve bounded automation through the existing native task/action policy;
the sender cannot manufacture that approval. The initial integration invokes
the existing local owner operations only after receiver approval. It exposes
no new remote mutation endpoint and never turns `status-read` into execution.

A proposed receiver action binds the peer identity, plugin name, full
generation, ordinary package root, publisher key, requested stage, expected current
generation or explicit absence, policy identity, expiry and idempotency key.
This is a proposed action contract, not an implemented plugin CLI schema.
Receiver policy is checked at admission and before every mutation.

Initial proposed limits for the selected plugin are: exactly three members;
manifest and signature
each at most the existing 65,536-byte parser bound; executable at most 64 MiB;
plugin aggregate at most 64 MiB plus both metadata limits; ordinary package
aggregate at most 128 MiB including its metadata and source; one active mutation per
plugin; at most two concurrent transfers per approving peer. These are proposed
admission ceilings, not measured capacity or current executable limits.
Use the smaller of these limits and native transport/storage admission.
Reject declared overflow before allocation; count actual bytes while receiving.
No additional compression layer in the initial package transfer. Apply native transfer deadlines,
bounded retries and cancellation, and retain only lifecycle-owned scratch.

Platform compatibility is independently checked before activation and start.
The current plugin runner requires Linux confinement and a static ELF image.
A received object on another platform may remain inert; successful transfer
does not qualify execution or authorize weakening isolation.

## State transitions and retry behavior

1. Receiver admits the exact request under its own current policy.
2. Fetch or attach to the exact ordinary package, wait for verified completion,
   then perform inert checkout into an absent owner-private destination.
3. Recompute the manifest generation and executable digest; verify the detached
   signature against the receiver's current trusted publisher keys.
4. Install using `plugin_store_install`; record its exact generation and
   `already_present` result. Do not change current.
5. Under the receiver's serialized mutation authority, compare the expected
   current generation, revalidate policy and switch using the existing store.
6. Start or reload only if separately approved. Observe the exact launched
   generation and existing confinement result; selection alone is not running.
7. Report the stage-specific receiver receipt through existing evidence.
   On failure, retain the refusal and reconcile actual local state.

The native action receipt binds the idempotency key to the complete immutable
request. A matching retry returns retained evidence or resumes its unfinished
stage after fresh authorization. A changed request under that key refuses.
A retry never silently replaces expected-current with the latest value.
Cancellation or expiry stops further stages; completed effects remain reported.
Unknown outcomes are reconciled from receipts and exact store state before retry.

Store-level `already_present` and switching to the already-current generation
provide useful idempotency, but are not a durable cross-stage request journal.
Existing native action/receipt machinery must supply that journal. Checkout
requires an absent destination and is not itself an idempotent replay: on an
uncertain result, verify the retained exact destination and receipt or allocate
new lifecycle-owned scratch without deleting unowned files. The current
plugin switch API has no expected-current argument, so serialized comparison
and mutation require a qualified receiver adapter before concurrent automation.
Do not claim atomic compare-and-switch from a check followed by an unlocked call.

A crash between last-good and current updates may leave an intermediate state:
the two links are individually replaced, not a multi-link transaction. Recovery
records and reconciles both exact values before proceeding. A previous current
generation is a rollback target, not proof of healthy execution.

## Rollback and publisher revocation

Rollback targets must remain exact, locally retained, compatible, and currently
authorized. Reverify the publisher signature and executable at rollback.
A revoked publisher cannot be restored merely because its generation is called
last-good. If no permitted rollback target remains, stop and report the refusal.
Do not erase retained unique evidence or the owner's source during recovery.

Publisher trust changes remain local owner actions. Removal of a trusted key
must prevent new installs, switches and starts under it, including retries.
Rechecking trust before each stage does not itself revoke an already running
process. Immediate revocation requires an explicit local stop/reload policy
with observed completion; post-start revocation and crash-loop fallback need
dedicated qualification. The design must not silently inherit an old grant for
a newly selected generation with different declared capabilities.

Signer-only migration also needs explicit policy: the current generation digest
binds the manifest, not the detached signer identity. Bind the publisher key
separately in the action and receipt. A different signer for identical manifest
bytes does not establish a new generation or authorize replacing retained
signature evidence implicitly.

## Reporting which generation is where

Reuse the signed `ops.mesh.status` capsule, not a second fleet view.
The published source exposes `plugins.available`, `reason`, `count`,
`listed`, `truncated` and rows with `name`, `current`, `last_good`.
Rows contain 16-hex prefixes, with at most eight rows; space pressure can omit
the entire plugin block while preserving the identity capsule.

The published source makes this view opt-in through `-meshstatusplugins`,
default off, and serves a cached snapshot. Its supervised refresh is throttled
to once per 60 seconds; that interval is not a freshness guarantee if refresh
stops. Before the first read it reports `not_yet_read`. A newly signed status
capsule does not prove that the cached plugin store observation is equally new.

That is bounded discovery. A missing block, truncated list or unavailable
store is UNKNOWN, not evidence that no plugin is present. Prefix equality
cannot prove exact generation equality. Store selection also does not establish
a running process or healthy behavior.

Use existing action receipts for the full 128-hex current and previous
generations, exact executable and ordinary package roots, publisher key, receiver
identity, policy identity, stage, result and observation time. Verify the
receiver's receipt identity and freshness. Fetch exact evidence on demand
rather than enlarging every status capsule. Stale receipts remain historical.

## Acceptance plan

All distribution integration below is NOTRUN. Existing local tests establish
only their stated local behavior.

| Obligation | Required witness |
| --- | --- |
| Exact bytes | Sender pack, consenting peer fetch, independent manifest-generation and executable rehash, receiver signature verification. |
| Authority | Wrong peer, missing approval, status-read-only request, expiry, revoked capability and changed policy all refuse before their protected effect. |
| Bounded storage | Oversized declarations and actual streams, overflow, undeclared members, path traversal, links, interrupted transfer and full storage admission. |
| Retry safety | Lost acknowledgment after every stage, same-key replay, changed payload under the same key, process restart and receipt reconciliation. |
| Concurrent selection | Two requests with the same expected current: one wins, one conflicts; no unlocked check/use window. |
| Trust lifecycle | Key removed before install, switch, start, rollback and crash fallback; same manifest signed by a different key; no automatic trust import. |
| Generation lifecycle | Same executable with changed capabilities, install without switch, switch without run, exact launch, failed start and independently verified rollback. |
| Platform limits | Native Linux confinement acceptance; unsupported platform refuses execution while preserving inert verified bytes. |
| Status limits | More than eight plugins, omitted block, prefix collision, stale signed observation and current differing from running generation. |
| Efficiency | At least ten paired cold/warm trials on consenting peers; retained failures, transferred bytes, reused chunks, CPU, memory, queue wait and wall time per accepted generation. |

Run existing registered plugin and mesh-status groups plus focused adapter
tests selected from the actual command catalog. Record exact source/base,
compiler, CPU, timestamps, commands, object hashes and independent review.
No fleet-wide activation follows from a unit test or a signed receipt alone.

