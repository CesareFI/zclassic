<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Explicit operating-system entropy provider

The new `rng_host_fill` interface obtains host randomness without using the
mutable simulation defaults. Existing RNG interfaces retain their behavior.
The interface rejects invalid spans, limits requests to 4096 bytes, and clears
the valid output span on provider failure. Linux permits at most eight
nonblocking `getrandom` attempts. This bounds attempts, not kernel latency.

## Source and environment

- Original qualification base: `4f0c504cb1b6dd219ebe53e50d0530e8f56dc25c`.
- Integrated base: `eb8a043692f05c0d763cdaa9408932ac23ae28d3`.
- Host: Linux, AMD Ryzen 9 7950X3D, GCC 14.2.0.
- Observation: `2026-10-11T06:30:52+00:00` local and UTC.
- Production source SHA-256:
  `29f9f2face71b742591fed231c047528ce0625a8ac029e017054939ddd6c9f0e`.

## Executed focused evidence

`devbuild --wait make -j28 t-fast-exact ONLY=rng` passed with one cold
registered group, no cached groups, skips, or unobserved environment cases.
The syscall seam compiles the actual provider source and checks invalid spans,
eight interrupted calls, partial output followed by failure, hard errors,
output clearing, and independence from both injected RNG interfaces.

A mutation routed valid requests through the mutable default when installed.
The same registered group failed specifically at the injected-default bypass
assertion, with one failure. The automatic isolated rerun reproduced it.
Reversing the mutation restored the exact production source digest above.
The unchanged parent lacks the new API; parent execution is not claimed.

The initial test function exceeded the complexity limit. Splitting it into
three focused helpers preserved all 21 assertion labels and strengthened the
partial-output clearing witness by initializing its buffer to nonzero bytes.
The revised test SHA-256 is
`47a6aa2af580161bd57a2f516199c27ff54caa6b106abc461bd3322132a0b55d`.
The same mutable-provider mutation failed the revised test at the same
assertion; restoration passed the same cold registered group with no skips
or unobserved cases.

`devbuild --wait make -j28 agent-verify ONLY=rng` passed complexity, focused
tests, generated capability inventory, and fast lint after the split.
`devbuild --wait make -j28 t-asan ONLY=rng` passed the two selected groups:
`rng` and `sapling_prover_rng_determinism`, with ASan/UBSan, no cache reuse,
skips, or unobserved cases. Focused and sanitizer profiles remove `-Werror`;
their success alone is not warning-clean compilation evidence.
After fast-forward integration of the checkout-discovery changes, the same
`agent-verify ONLY=rng` command passed all four checks again. The capability
inventory was regenerated against the integrated tree; its earlier aggregate
row was not copied over upstream changes. Production and test source hashes
remained unchanged. Exact integration proof and publication remain pending.
This evidence does not qualify FreeBSD entropy ingestion, persistent
guest identities, SSH, post-quantum negotiation, or failover. No guest keys
were generated. Apple and Windows provider qualification remains separate.

## Reviewer correction

An independent source review asked for three changes, applied after the
evidence above. The failure path now clears the output span with the existing
`memory_cleanse` from `base/cleanse.h` instead of `memset`, so the cleanup
cannot be removed by optimization. The syscall seam gained an `ENOSYS` case:
the provider refuses after one call, uses no fallback source, and clears only
the output span. The bypass test now calls the injected default after the host
fill and checks that its state advances, which shows the default stays
installed. The 4096-byte limit and the eight nonblocking attempts are
unchanged.

- Corrected production source SHA-256:
  `8da94bf2b8359a3ed23564d3d9efee41e37b68d420c90830b5e11379e7fa12e9`.
- Corrected test source SHA-256:
  `55b95cd687c2073ca2754e714027aad033ac985f64c43d126535bb9d56885687`.
- Applied review patch SHA-256:
  `dce570b0c43ce0e1aad2f04987d356aac618256f8d89c5135af2c50e7a913cad`.
  Its serialization differs from `git diff`; compare the source hashes.

The corrected-source focused job at `2026-10-11T08:32Z` has a verified
scheduler record: exit zero, 9 s run and 645 MiB peak memory. Its raw
assertion log was not independently located; the fresh assertion and group
counts below belong to the later retained gate log.
`devbuild --wait make -j28 agent-verify ONLY=rng` then passed
complexity, the focused group, the generated capability inventory, and fast
lint on the same sources. The inventory changed in one row: the
production-use count of `base/cleanse.h` rose by one.

The uncorrected provider already refused `ENOSYS` and already cleared its
output, so the new assertions widen coverage; no failing run of the earlier
commit is claimed. The mutation, sanitizer, and exact-proof results above
belong to the earlier 21-assertion sources and were not repeated. Both source
files are byte-identical to the copies in the separately signed guest machine
series, so either can be integrated first without a conflict in these files.

The correction gate's native job `1348648` completed on 2026-10-11 with exit
zero, 47 seconds run time, 92 CPU seconds and 915 MiB peak memory. Its retained
`build/handoff/host-entropy-provider-20261011/agent-verify-correction.log`
has SHA-256 `eb1d538ad3330943d7703457076b6785d6403e168a52613cde6fdfc0db7c2fff`.
The separate retained `correction-focused-retained.log` in that directory has
SHA-256 `640d9d29534ded9b9643587923e30469b84ab77c5e0e961193a715652302c000`;
it records the 24 assertion labels, a 22 ms test body and one cold group with
zero failures, cached groups, skips, unobserved cases or load-flaky cases.
These are fresh gate observations, distinct from the earlier nine-second job,
whose scheduler record was verified but whose raw assertion log was not
independently located during handoff. The correction does not inherit the
previous source's sanitizer, mutation or exact-proof qualification.
