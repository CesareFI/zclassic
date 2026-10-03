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

The documented hook implementation admits only `refs/heads/main`; the
contribution guide provides no alternate contributor branch, submit helper,
patch/bundle, or maintainer-assisted command that avoids this policy. No hook
or configuration was modified and no bypass was attempted. Publication needs
repository-owner/maintainer action through the approved main admission path.
