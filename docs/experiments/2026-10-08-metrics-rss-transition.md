<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# RSS availability diagnostics

The metrics worker samples process memory every tick. An unavailable sample
continues to publish `zcl_rss_mb -1.00`; it never reuses a previous measurement.
The diagnostic is emitted on entry to an unavailable episode. A valid sample,
including zero resident bytes, ends that episode. The latch belongs to the
worker invocation, so a restarted worker reports its first unavailable sample.

The regression drives the production worker loop through six ticks: negative
resident bytes, reader failure, repeated negative bytes, recovery, reader
failure, repeated negative bytes. It checks each tick's published gauge and
cumulative diagnostic count. Repeating the sequence in a second worker
invocation checks session reset. The fixture uses a fixed local clock and
restores the prior clock before assertions; no live node is involved.

Base: `0ca3f0c258efcfa87ec95a6ff1d164b9ffd1e8a9`.

Focused validation command:

```sh
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact \
  ONLY=metric_alerts T_FAST_EXACT_ARGS=--no-cache
```

On 2026-10-08T12:34:47Z, the focused command completed with exit 0:
1 group ran, 0 failed, 0 cached, 0 skipped, and 41 ms test-body time.
The unavailable-episode fixture passed. The host compiler was GCC 14.2.0
on an AMD Ryzen 9 7950X3D. The build used C23 and native devbuild admission.
This is precommit source feedback; exact committed-source proof and lint
remain pending. This source proposal does not establish
sandbox availability, node acceptance, deployment qualification, or a change
to the process-memory reader's API.

## Mutation sensitivity

The intended mutation removes only the unavailable-transition guard, restoring
per-tick diagnostics. Both executions used the focused command above under
native r1 admission, with no cached group results.

- Mutated: command exit 2; 1 group failed, 0 skipped. The new worker-episode
  fixture failed at `test_metric_alerts.c:648`, whose boolean includes the
  per-tick diagnostic-count assertions. The existing single-tick RSS test
  remained green. Test-body time was 308 ms.
- Restored: command exit 0; 1 group passed, 0 failed, 0 skipped. Test-body time
  was 444 ms. The production source was restored byte-for-byte to SHA-256
  `c117ca80ab781e907e065f4f14a38470490aaa7f947b5992528bcee17dd3ec79`.

Evidence objects (SHA-256):

| Object | SHA-256 |
| --- | --- |
| Guard-only mutation patch | `fef848796491545bb084631cc3bacdfd7a9f69730338760a6349aecbba04feaa` |
| Mutated run log | `459dd0c8cea33f7acbbbbe797aa9527c00b95bbbe7447ef3e39d7d5b86996018` |
| Restored run log | `4cfc487c80e53a71545301e0664d7f94c07b50590a24b80c111cfa80c694b5a1` |

The mutation did not change the RSS gauge sentinel or reader API. This proves
that the worker fixture detects the per-tick diagnostic regression; it does
not establish live-node acceptance or sandbox readability.

## Current-main integration feedback

The complete RSS reader and episode-diagnostic changes were isolated onto
`cc40bab787ea1d3e43ed1fce91a008db8404bd47`. Production and test bytes match
the reviewed source hashes above. The capability declaration now includes
stderr writes without changing runtime authority.

A resumed, admitted 28-job Linux run passed the cold `metric_alerts` group:
1 group, 0 cached, 0 failed, 0 skipped, and 41 ms test-body time. Its combined
command exited 2 because the separate capability-closure check reported
UNPROVEN: this fresh checkout had no developer object epoch. This is not a
capability-closure pass; exact native qualification must supply that evidence.
The earlier two-job compile was deliberately terminated before completion;
its output supplies no acceptance result. Completed build objects were reused
by the resumed run.

Combined log SHA-256:
`484472c37e768cf8cc227b406b18b8e13be6df5c813217d69f8a71166fefe040`.
