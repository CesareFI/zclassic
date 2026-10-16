<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger authorization at deferred effects

Source base: `54245e2b7dcba363af3ee146442bd2c41dbb556e`. Qualification checkout parent: `4b5597954ed77f7e09ad1d0453b481603bc4cd27`; that commit adds separate gateway-test diagnostics. The ledger composition baseline is identical to main `146061d3387a8f5c7e7ada8b97d10dae185bd083`. Existing latest-vitals tests are preserved.

The ledger service now carries the authorized pairing identifier, revocation generation, Noise static, master and online signer across callbacks. It invokes the existing full pairing authorizer before serving DATA and before deferred replica ingestion. Outbound opening reuses the already-authorized binding. Signature, continuity and receiver-local role checks remain required. No standing-only authorization or chain-failure fallback is introduced.

This qualifies revocation and expiry between callbacks. It does not make authorization and the subsequent send or append atomic against a concurrent revocation. That stronger claim requires a native authority-generation guard coordinated with the revocation writer across the effect.

## Environment and source identity

Observed on 2026-10-16, AMD Ryzen 9 7950X3D 16-Core Processor, GCC (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0. Recorded environment timestamp: `2026-10-16T02:44:52+00:00`. Builds used the installed admission rail and the canonical focused runner, whose inner make selected 28 jobs.

SHA-256 identities:

- Production `engine/composition/src/boot_fleet_ledger.c`: `02ce1afc89a59149842fcd13deb05b711c618d20604b19e33a0d1d5b07d2bb23`.
- Test `tests/harness/src/test_fleet_ledger.c`: `a72e9e92becad01866bb92973d14a3d664015e78b0826d1f4b6e09859e39d0e9`.
- Reviewed unapplied proposal `C4-v2.patch`: `d915dcc1c79518f9164b1964570ada0545969fc3b1ec1622a0e4dbf869c3efe0`.

## Executed evidence

All four new cases passed initially and after exact source restoration: expiry after OPEN sends no DATA; expiry after receipt prevents ingestion; pairing revocation after OPEN sends no DATA; pairing revocation after receipt prevents ingestion. Both green executions ran one registered group with zero skips and zero failures. Initial body duration was 170147 ms; restored body duration was 174424 ms. These durations are execution observations, not a performance comparison.

Two isolated production mutations retained full initial authorization and evaluated the effect authorizer, but ignored its refusal:

| Mutation | Required observed failure | Result |
| --- | --- | --- |
| Bypass send and drain refusal | Expired OPEN produces DATA instead of CLOSE, test line 2007: `2 != 4` | REJECT, one failed group, zero skips |
| Bypass drain refusal only | Expired received batch advances replica, test line 2035: `4 != 3` | REJECT, one failed group, zero skips |

Each failure repeated under the runner's automatic isolated retry. Neither was a compilation, setup or timeout failure. The first mutation aborts at the send assertion; it provides no independent drain claim. Separate mutation RED evidence for the two revocation cases was not collected. Their coverage is executed GREEN plus source review.

Mutation source hashes were `938a5da9daaf58be092ec53733a578a50a1bc32486ba9a398070588c67cae303` and `b28a21993540c1de40f3a5a955ecdb551f0ec0ccb843702226997af167dbfe82`. Exact production bytes were restored after each run and verified against the green identity above. Mutants are not part of the proposed source.

## Reproduction and retained receipts

From the qualification checkout:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact ONLY=fleet_ledger
env VENDOR_CC=gcc devbuild --wait make -j28 docs-capability-inventory
env VENDOR_CC=gcc devbuild --wait make -j28 lint-land
```

Receipts are retained under `build/scratch/c4-auth-review/`: `fleet-ledger-v2.log`, `fleet-ledger-mutant.log`, `fleet-ledger-drain-mutant.log`, `fleet-ledger-restored.log`, mutation diffs, source manifests and `environment.txt`. The initial `lint-land.log` records one stale generated-capability-inventory failure; canonical regeneration uses `docs-capability-inventory`. Final lint acceptance is recorded separately in `lint-land-final.log`. `qualification.sha256` binds the retained final receipts.
