# C3 duplicate-forward lock handoff

## BASE

`a898cf77913f786e69c2e85b357004972d796976`, tree
`c14880c871c6f79116c1e0cef158f8be9a7a6af4`.

The protected production patch has not been applied. `origin/main` remains at
this last qualified commit until the owner unseals Core and the successor is
independently qualified.

## READY PACKET

The tracked packet consists of:

- `tests/harness/src/test_download_contention.c`, B's registered contention
  regression;
- its catalog and exact affected-proof mapping;
- `docs/work/c3-lock-assets/production.patch`, the reviewed inert protected
  proposal;
- the owner decision, benchmark recipe, landing checklist, and evidence digest
  manifest under `docs/work/c3-lock-assets/`.

The pre-token archive delivered byte-for-byte to B and C had SHA-256
`665f8abf4d9687b0261060067f2131b2b45b98987c64ebcbfd1ba6feba31852e`.
Both receiving hosts returned that digest after transfer.

## OWNER COMMAND

Run from the root of the checkout that will apply the protected patch:

```bash
make core-unseal REASON="C3: eliminate O(batch*queue) duplicate-forward scan while preserving exact download policy and accounting"
```

Never create or bypass the token manually. After it appears, apply only the
tracked proposal and immediately run `devbuild --wait make core-seal`.

## PATCH SHA

`docs/work/c3-lock-assets/production.patch` has SHA-256
`a6af0343c0109c46c284bcf80107d868baa2e6147cc1728048a8d6c55cd58985`.
It caches the existing work class in the bounded queue-membership entry so an
already-forward duplicate avoids the full promotion scan. The existing
history-to-forward remove/reinsert path remains intact.

## TEST COMMANDS

Freeze the tree throughout each command and route every build/test through the
shared scheduler:

```bash
devbuild --wait make core-seal
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY=download_contention
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY=download
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY='syncdiag_rpc,api,block_swarm_loopback'
devbuild --wait make lint
devbuild --wait make z23
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY=download_enqueue_profile
```

Then run the loaded recipe in `c3-lock-assets/BENCHMARK.md` against one
declared immutable fixture and topology. The native lander's mandatory
publication proof is `ZCL_STRESS_TESTS=1 make pre-push-ci`.

## EXPECTED RED

On unchanged `a898cf77`, A's 20-round registered fixture measured duplicate
lock p95 `151314 us` and first useful history enqueue p95 `151562 us`; all 20
rounds exceeded 100 ms. B independently measured `150320 us` and `150609 us`.
C measured a 65,536-entry duplicate-forward no-op at `2022314 us`, versus
`10421 us` for its paired history control. Every duplicate added zero entries.

## SUCCESS METRICS

- duplicate-forward lock p95 collapses toward the paired control;
- useful history refill rises materially above the preserved `12.7207
  bodies/s` baseline under the same fixture;
- foreground command p95 improves under load with no new timeouts;
- queue/in-flight caps, exact accounting, forward priority, avoidance,
  settlement, and one-time history-to-forward promotion remain green;
- coverage advances monotonically and C3 reaches a farther durable H* in the
  unchanged 600-second window.

## B/C EVIDENCE

B owns independent correctness/concurrency qualification. Its registered test
uses 32,768 queued forward items, 2,048 duplicate forwards, and 20 rounds; it
also verifies fresh history admission, zero duplicate inserts, exact membership,
the 65,536 cap, promotion, and receipt accounting.

C owns independent performance reproduction. Its source bundle root is
`e2755da6c709625fc945ff9f6471df71fcc5700d3682a98b0bc21f8c9edc95fa`
and wire SHA-256 is
`610b4aae55b023862d98b7d90b5d1104831cac3eb3094374a6b7727291bc575a`.
The successor is qualified only when both reports name the same frozen commit,
source root, recipe, closure, artifacts, and topology.

## NEXT 3 BOTTLENECKS

1. Current slice: remove the proven O(batch×queue) duplicate-forward scan that
   holds the shared download mutex and serializes useful refill.
2. Prove whether a durable history completion arriving during a refill pass is
   lost before the worker's timed wait. Existing evidence shows 64-body
   enqueues near a five-second cadence and `12.7207 bodies/s`; use the existing
   condition/scheduler and an event latch, without polling sleeps or cap changes.
3. Address the separate intake saturation only after its independent slice is
   selected: 1,025 duplicate bodies can fill the 1,024-slot intake queue and
   refuse a first-seen body. Preserve bounded backpressure and fail-closed
   admission.

## LAND STEPS

Follow `c3-lock-assets/LANDING.md`. In particular: fetch `origin/main`,
requalify after any rebase, verify rollout HOLD, submit the exact frozen SHA to
the native lander, observe its GREEN ready receipt, publish only through the
authorized path, fetch remote main, and compare both commit and tree. A push
must not deploy or restart production.
