<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Non-inheritable Linux running-image descriptor

Base: `0fc9a2c3d6be0c4d53dacacf3fdac22a6df579db`.
Status: focused runtime matrix and required repaired-scope gates passed.

The Linux `os_proc_open_self_exe` previously used `fopen` on the kernel's
running-image reference. Its descriptor was inheritable by an exec'd child.
A future process-lifetime builder-image cache would retain that descriptor
while launching compilers, unnecessarily exposing the executing builder bytes
to those children. Setting a descriptor flag after opening leaves a concurrent
fork/exec window.

The existing platform authority now opens its same running-image reference
with `O_RDONLY | O_CLOEXEC`, then transfers ownership to `fdopen`. The flag is
installed atomically by the kernel. A failed `fdopen` closes the acquired
descriptor and preserves the original error. Caller ownership and `fclose`
remain unchanged. Darwin, Windows and unavailable-platform branches and their
identity classifications are unchanged; no stronger inheritance guarantee is
claimed for them. No cache or development-layer process opener is added.

The registered `os_proc` group calls the actual platform API. Temporary
close-on-exec padding descriptors keep its returned descriptor above a shell's
low internal descriptor range; the API descriptor is never duplicated or
replaced. The fixture separately obtains an explicitly inheritable control
descriptor. A real fork followed by `/bin/sh` exec must observe the image
descriptor closed and the unrelated control descriptor still present. This
avoids treating a child that closes every descriptor as positive evidence.
All formatting occurs before fork; the child calls only exec and `_exit`.
The parent waits and closes every fixture descriptor without assertion jumps.
Existing image-byte and identity tests remain intact.

The unchanged parent must fail both the immediate close-on-exec flag check and
the real exec observation. The corrected source must pass. Restoring the old
Linux `fopen` opener is the mutation; exact restoration must pass again. These
runtime legs do not alone demonstrate the absence of the concurrent opening
race: the reviewed atomic kernel flag is the mechanism for that property.
Failed `fdopen` cleanup is source-reviewed unless separately fault-qualified.
No general post-fork multithreaded execution safety is claimed; this fixture
execs immediately and does not hash or operate a cache in the child.

## Focused execution

The corrected source SHA256 is
`1e4f4ea76215e1278aaf57b0e3fad8e283923c30ddfc286f63012c8cc5c01a82`;
the test SHA256 is
`a78cf291b6f0bbc01b0589b10c314f867a6e8638089015ac06cfa0dab6e98714`.
All four legs used the canonical `t-fast-exact` target with `ONLY=os_proc`
and `T_FAST_EXACT_ARGS=--no-cache`, through native `devbuild --wait` admission.
The receiver was an AMD Ryzen 9 7950X3D with GCC 14.2.0 on 2026-10-11.
The canonical C23 `test-fast-v2` profile is unsanitized and omits `-Werror`;
these results are not sanitizer or strict-warning qualification.

| Leg | Make exit | Test body ms | Observation |
| --- | ---: | ---: | --- |
| Original Linux opener | 2 | 535 | Flag and real exec assertions failed |
| Atomic opener | 0 | 71 | Both assertions and existing group checks passed |
| Original Linux opener restored | 2 | 150 | Same two runtime assertions failed |
| Exact atomic opener restored | 0 | 162 | Both assertions and existing group checks passed |

Each leg ran one cold registered group with zero cache hits, self-skips,
environment-unobserved cases or load-flaky cases. The canonical runner retried
the failed legs alone. The matrix stopped unless both expected failure
assertions were observed; build or fixture failures were not substituted.
The mutation restores the original production source, whose only difference
from the corrected source is the Linux opener. Header and test bytes remain
constant. Exact corrected production bytes were restored afterward.

Raw logs and source/compiler/CPU/time metadata are retained under
`build/handoff/self-image-cloexec/` in the isolated receiver lane.

| Log | SHA256 |
| --- | --- |
| parent.log | `50b4e1fe36f6279ecf0c93b3f91f421dc2215767aea84d35199fb16a303513c3` |
| fix.log | `d794fc03e52b7e14a8494b2c47f65b14fcd8c323a438d1f145a5992235c94d0a` |
| mutation.log | `9481cd396a1db06aac4036903f962c97fd0b363d309dd63297c7de9228510283` |
| restoration.log | `3bb36d53add16891539120b66e3980df85471faa1915bc854d631d2a006100c6` |

The canonical cheap complexity check passed without a baseline change before
the matrix. Its log SHA256 is
`547340a86c18a2c4861fac5ea2d2ec3d1018517b1729e3ed2f3b9be55e60f40f`.
Two independent source reviews and an independent complete raw-matrix review
accepted these exact claims. Image caching,
cache performance, full proof and native publication remain NOTRUN.

## Canonical package projection

The first mandatory `agent-verify` invocation exited 2: complexity, two cold
focused groups and inventory passed, while `lint-fast` refused solely because
the edited platform package's registry row was stale. Preflight did not run.
This failed invocation remains failed; its log SHA256 is
`bf8bc0c0e0142785908d99072f743e00e422a6bc9258055c887a82a7b81a80cb`.

After obtaining the exact native registry scope, the canonical
`docs-zcode-package-registry` target rederived the platform row in one fixpoint
round, covered 96 manifests and updated no dependency pins. It changed only
the platform row's content, release, lock, capsule and signature fields;
package identity, directory, ID, recipe and publisher remained unchanged.
Production/header/test bytes remain identical to the accepted runtime matrix.
The derived registry SHA256 is
`af78bf9c5eb4020024d4e8d4e044808116ce445674a0d8d96cfa0dfef6178419`.
The generator log SHA256 is
`9df2303ab96e9f1638bade7974d0f5e9fe9d2c88fa7f95b8346cef722fcc1bdb`;
its exact diff SHA256 is
`033d4046d986169a45c06a696626a902a93bfcc9598fcceac054faf7a459a6ac`.
Two independent reviews accepted that narrow canonical projection.

The generator requires a rebuilt runner for the three groups embedding this
row: `zcode_package_registry,zcode_swarm_net,zcode_score_receipt`. Their targeted
qualification passed on the rebuilt runner: three cold groups, zero cache
hits, failures, self-skips, environment-unobserved cases or load-flaky cases.
The retained phase receipt reports 165775 ms of test body time. The swarm
umbrella ran all 22 sub-suites, with none failed.
The rerun of `lint-fast` passed all 35 gates in 11854 ms, and `lint-preflight`
passed all five gates in 17290 ms. Each command exited zero. These receipts
repair the failed scope; they do not relabel the earlier invocation as passed.
The unchanged platform runtime matrix is retained separately; no repeated
matrix or successful relabeling of the failed invocation is claimed.

| Repaired-scope log | SHA256 |
| --- | --- |
| final-gates-v2/targeted-tests.log | `ea34280fed0270e4694fd7a1995487a6d17966dac1d42b71dce483a223d22d19` |
| final-gates-v2/lint-fast.log | `d567ebb2c50c2e5a79b09e8c9ab9dd29f26c74917b98a9e6f65280125f3c9975` |
| final-gates-v2/lint-preflight.log | `b03139d3cc7e24ae5dcb816c3da72421bbdf4a05751ab8233853cc41e650aa15` |

The inventory was clean before each correctly scoped native generated lease.
It remained byte-identical throughout:
`fa0ed4762b679666c56d0da73337a29dd0201444f4aac343db593f91165f932b`.
Both generated-scope releases passed without expired-lease reclamation. The
candidate contains only platform source/header, the regression, this evidence
and the canonical platform registry row; no inventory change is included.
The final evidence reconciliation changes documentation only after gate
execution. Independent final raw receipt review accepted the exact repaired
scope. Full proof, publication, image caching and cache performance remain
NOTRUN; no other-platform inheritance or generic post-fork guarantee is added.
