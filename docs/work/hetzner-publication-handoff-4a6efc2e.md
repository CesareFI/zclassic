# Maintainer handoff: local-header recovery latch

- Candidate commit: `4a6efc2e44c63f6668e062e80c9cea6a3a50ea3d`
- Candidate base: `3a93e60ebf922af3d119b9facc1d95803f42844b`
- Signature: valid SSH signature for `236205415+CesareFI@users.noreply.github.com`
- Changed files:
  - `engine/conditions/src/local_header_refill_needed.c`
  - `engine/services/include/services/sync_monitor.h`
  - `engine/services/src/sync_monitor.c`
  - `tests/harness/src/test_sync_watchdog_conditions.c`

## Purpose

Keep a newer local-header recovery episode armed when a stale, wrong-height
witness arrives. A matching successful witness clears the episode, retry
count, and mirror gate exactly once.

## Evidence

- Strict C23/Werror syntax passed for all four changed translation units.
- An ASan/UBSan production-helper probe, with leak detection, passed.
- The real condition-engine witness-success fixture covers matching-height
  reset; a wrong-height witness preserves the newer episode.
- `git diff --check` and the isolated complexity ratchet passed.
- The focused registered watchdog harness was **not run**: its supported Make
  selector starts a vendored OpenSSL build whose footprint cannot fit while
  retaining the mandatory 10 GiB root reserve.

Consensus, PoW, monetary policy, upgrade activation, transaction/block
validation, peer selection, and sealed networking code are untouched.

## Publication boundary

The local pre-push policy refused non-main publication with:

```
pre-push: REFUSED status=remote-ref-not-main
```

The documented hook implementation admits only `refs/heads/main`. The
documented sanctioned route is native `z23-dev dev land`, which prepares a
main landing and requires an exact proof receipt; it is not a feature-branch
or pull-request publication route. This host cannot run that proof scheduler
(it has 4 CPUs and about 2.6 GiB available RAM; the supported lane requires
8 CPUs and 24 GiB). No hook or configuration was modified and no bypass was
attempted. Publication therefore needs a repository-owner/maintainer action
through `dev land` on a proof-capable host.
