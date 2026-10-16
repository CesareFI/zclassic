<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Latest fleet vitals provenance

Date: 2026-10-16.
Base: `75e4f9d72b3459ed1bf6c64171030fa91c7ffa30`.
Integration baseline: `146061d3387a8f5c7e7ada8b97d10dae185bd083`.

## Claim

The latest recorded vitals API preserves the exact signed row sequence,
timestamp and explicit value presence. A later absent sample replaces an
earlier measurement. Clock reversal does not change chain order.
Historical aggregates and the signed wire format are unchanged.

The projection uses a checked allocation bounded by admitted box slots and
catalog size, currently 32 by 41. Queries scan these slots without disk reads.
No latency or memory benchmark is claimed. No native command, remote access,
fleet sampling coverage or freshness policy is qualified by this experiment.

## Acceptance

Remote admission command:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact ONLY=fleet_ledger
```

Cases cover absence versus zero, reversed timestamps across UTC days, latest
sample versus sum, invalid arguments, unknown subjects and boxes, output
truncation, read-only replay and replication of both measured and absent rows.

A timestamp-order replacement mutant failed the sequence assertion:
`rows[0].seq = 3`, expected `7`. The runner also failed its isolated rerun.
The exact source was restored and the group passed with zero failures/skips.
After a complexity-only helper refactor, the group passed again:
one group run, zero failures, zero skips. These timings are test observations,
not performance comparisons.

Evidence is retained in the sanctioned r1 lane under
`build/scratch/fleet-vitals-latest/`: `gate-mutant.log`,
`gate-restored.log`, `gate-refactor.log`, `fixed.sha256` and
`mutant.sha256`. The earlier mutation hashes identify the pre-refactor source;
they do not identify the final refactor.

Independent source review accepted the initial behavior. Landing additionally
requires review of the final refactor and a clean `lint-land` result.
