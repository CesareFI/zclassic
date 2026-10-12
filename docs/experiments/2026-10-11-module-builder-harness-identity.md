<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Executing module-builder input identity

## Intended behavior

Module action preimages bind the exact executing builder bytes in their
optional harness field. On platforms reporting `RUNNING_IMAGE`, the producer
retains the kernel-pinned executable descriptor through derivation, streams
SHA3-256 over `zcl.module_builder.running_image.v1` including its terminating
NUL and the image bytes, and checks descriptor metadata before and after the
read. Capture failures refuse the action root with contextual diagnostics.
Pathname-only platforms keep this evidence absent.

This is input identity, not a statement that the builder matches the edited
module checkout, is safe, or satisfies receiver policy. It does not produce
BUILD tickets, complete the proof-key adapter, transfer a module, or authorize
loading. Source admission and existing loader authority remain separate.

## Acceptance design

The registered `action_root` group invokes the production hot-swap hook,
loads its stored canonical preimage, decodes it, and compares the harness
field with an independent streamed hash of the running image. The unchanged
parent must fail this assertion on a running-image platform. The fixed source
must pass. Removing the actual harness-present assignment must fail; exact
restoration must pass. Weak-platform coverage requires absent evidence.

## Focused execution

Base: `16422c3469459397877ed7764b17283186ab22d5`.
Fixed production SHA256:
`483aca57b03426badbf4f9469609b4dca3b7845e3c6c840b5062b7e186d4cbba`.
Test SHA256:
`4ee59c641c9aa87119746b4cb0ee71172a91aa09823e8a467ed35e84a1ad6da7`.

Canonical `t-fast-exact ONLY=action_root` ran through `devbuild --wait` on
2026-10-11 with GCC 14.2.0 and an AMD Ryzen 9 7950X3D. This C23 test-fast
profile is unsanitized and does not enable `-Werror`.

| Leg | Make exit | Test body ms | Actual emitted-harness assertion |
| --- | ---: | ---: | --- |
| Original production with new test | 2 | 6226 | FAIL |
| Fixed production | 0 | 29218 | PASS |
| Actual harness-present assignment omitted | 2 | 57859 | FAIL |
| Exact fixed source restored | 0 | 37483 | PASS |

Each leg ran one cold registered group, zero cache hits, self-skips,
environment-unobserved cases, or load-flaky cases. The failed group received
the canonical isolated retry. The registered catalog had 1283 groups; the
historical receipts record `groups_gated=1282` for this exact selection. This fixture exercises the
production action emitter, not an executed module compiler/linker pipeline.

The fixed-source complexity gate and its selftest passed at the unchanged
cap of 15. Its admission wait was 113.504 seconds. The parent run preceded
that check because it was already admitted when check ordering was refined.
The parent also built missing prerequisites in this fresh lane; that cost is
retained in its log.

The fixed leg's original command checked both source hashes before recording
its start at `2026-10-11T09:20:25Z`; it did not print a separate pre-run
hash file. Its command was retained retrospectively with that limitation.
Restoration has a pre-run printed hash record at `2026-10-11T09:25:00Z`,
and its terminal source hashes match the exact fixed tuple.

Raw receipts remain under `build/handoff/module-harness/` in the isolated lane.

| Log | SHA256 |
| --- | --- |
| parent.log | `8eb4cfe22a89a5b1dd85ee4a067bfc6f8cae341d2b4d606b8d7c50b0460a5f96` |
| fix.log | `b880baac53ff3b2ff90ce11d2c83c338ec8a1f4874fae7d280b11f5b398e43d2` |
| mutation.log | `d1ad908ef9d882b4d45267601be421676448b038ea7d304497e12db271afab41` |
| restoration.log | `fda3e701d571ccece546ff8f653681843124d2f5a54419e4a5de76d23815c82d` |

## Cost and acceptance limits

The first slice deliberately adds no memoization. The executing test image
was 224075192 bytes. The existing 24-call warm key-cost sample recorded:

| Source | Wall median / p95, microseconds | CPU median / p95, microseconds |
| --- | ---: | ---: |
| Original production | 2591 / 13368 | 2577 / 3922 |
| Fixed production | 422975 / 463947 | 398596 / 431634 |
| Exact restoration | 382602 / 399626 | 382399 / 388353 |

These are observed timings, not a controlled speed ratio. Concurrent host
load and cache state differed. Linux2 full I/O pressure averaged 37.60 percent
over 60 seconds in the coordinator's `2026-10-11T09:25:13Z` observation.
The producer streams the complete image per successful derivation; physical
disk bytes and total hash-launch counts were not independently instrumented.
Performance acceptance is NOT_ACCEPTED. No fleet-speed saving is claimed.

Weak-platform execution, sanitizers, strict-warning qualification, mandatory
integration gates, complete BUILD-key adaptation, module delivery, exact full
proof, and publication remain NOTRUN. A proposed persistent digest cache needs
atomic close-on-exec image opening, exact descriptor identity checks,
concurrent safety, fork handling, and its own real-emitter regression before
it can replace this recorded correctness slice.

## Process-local cache successor

The successor retains one kernel-pinned, atomically close-on-exec image
descriptor for process lifetime. A short mutex protects stable capture,
publication and copying the digest and metadata. Derivation runs unlocked;
its final check compares the retained descriptor with the borrowed metadata.
Changed metadata triggers rewind and a complete new capture. Failed capture
invalidates publication without closing the descriptor. Actual read-byte,
hash-launch and cache-hit counters are observations, excluded from identity.

Linux caching additionally requires lock-free integer atomics. Other strong
image platforms retain the uncached path; pathname evidence remains absent.
An initialized inherited child refuses before touching the cache lock or
stdio. The tested fork occurs after fixture workers join. Busy-capture fork
and arbitrary multithreaded post-fork use remain NOTRUN.

The composed base is `3ac2dd2c693dea69da74b71edeace2b5271b56ee`, including
signed atomic-CLOEXEC prerequisite `664748b1e2ee6134f01221afe8a0f247a0d727c8`.
Cache production SHA256 is
`ea47d7964333a6f2aa694029ec36d8ec9317cba59de990e6ca7c4d9ff195d44f`;
final action-root test SHA256 is
`852bf4fa2ea2647b2a0eb087add84da2818b236f2d4e4e5306741554b27348df`.

The actual emitter regression concurrently captures a private copied runner,
checks stored preimages, changes image metadata, exercises initialized-child
refusal, closes the uniquely new cache descriptor, restores the exact slot,
and verifies full recapture. It renames and replaces only the private copied
image, independently checks the newly executed image, and restores the
original locator on every moved cleanup path. Descriptor ownership uses a
pre-capture census of all occupied slots and a unique new matching CLOEXEC
descriptor after workers join. The bounded 0–1023 census is a fixture limit,
not a general descriptor-ownership interface.

| Successor leg | Make exit | Body ms | Observation |
| --- | ---: | ---: | --- |
| Instrumented uncached predecessor | 2 | 118432 | Warm request reads 224168848 bytes and launches one hash |
| Final fixed lifecycle controls | 0 | 87952 | Warm request reads zero bytes, launches zero hashes and records one hit |
| Cached-hit metadata equality removed | 2 | 30247 | Actual metadata recapture assertion fails |
| Exact cache source restored | 0 | 14303 | All lifecycle controls pass |

The predecessor instruments real uncached work without changing its successful
identity predicate. Its test predates fixture-only cleanup and descriptor
repairs; the unchanged warm-work assertion provides the causal witness.
The mutation preserves the final freshness check: refusal and failure to
recapture are observed, not acceptance of a stale root. Other mutation
assertions also fail. Failed groups receive canonical isolated retries.
Every final fixed/mutation/restored outer run executes one cold group with
zero cached groups, self-skips, environment-unobserved or load-flaky cases.

Final fixed execution captured 224186712 image bytes once. The fault control
identified descriptor 6, allocated backup 7, closed 6 successfully, observed
an empty root with contextual retained-image metadata refusal, restored slot
6 and recaptured all 224186712 bytes with one hash and zero hits. The soft
descriptor limit was 1024. All concurrency, metadata, child, replacement,
new-exec and locator-restoration controls passed.

The fixed warm 24-call sample recorded wall median/p95 4271/13338 microseconds
and CPU median/p95 2605/4416 microseconds. Initial capture took 558429
microseconds. These are workload observations, not a controlled speed ratio
or fleet-wide performance result. Own admitted-scope memory peaks observed
in the original command output were
1423872000 bytes for final fixed execution and 1145151488 bytes for the
mutation/restoration wrapper, with a 24 GiB limit and zero reported OOM
events. The original tool outputs contain these observations; no separate
contemporaneous peak file was written. These peaks do not qualify a smaller
admission class.

Failed attempts remain part of cost: initial complexity refusals, the removed
C23 `ATOMIC_VAR_INIT` compile error, copied-image cleanup failure and an
arbitrary descriptor-backup minimum all preceded final qualification. The
canonical runner deleted an original primary-failure log on retry; that
primary failure remains UNKNOWN. The observed retry locator mismatch was
repaired by restoring the private image, without weakening its ownership
guard. The descriptor backup now requests the next available slot above the
selected descriptor and verifies exact restoration.

Strict-warning qualification initially failed before the runner because an
unchanged exec-tier fixture omitted `exec_confirm_hint` under
`-Werror=missing-field-initializers`. A separately claimed, reviewed
designated initializer makes its existing false value explicit. Assertions
and compiler flags remain unchanged. The corrected C23 test-strict-v2
profile retained `-Werror` and `-pedantic`: three exact groups passed cold in
15399 ms with no cached groups, failures, self-skips, environment-unobserved
or load-flaky cases. Separate canonical ASan+UBSan execution passed:
`os_proc` ran one group in 99 ms, `action_root` ran one group in 46147 ms
including copied-image controls, and the `os_sandbox` prefix selected two
groups in 1754 ms. These were cold, without cached groups, failures or skips.
The sanitizer profile excludes alignment checking and removes `-Werror`;
its compilation emitted warnings. It does not establish warning-free
compilation or replace the strict profile. Final performance acceptance,
full proof, publication and actual module delivery remain pending.

Mandatory integration first executed 19 exact groups cold: all passed in
326616 ms, with no cached groups, failures, self-skips, environment-unobserved
or load-flaky cases. The aggregate gate failed because three private fixture
environment names were unregistered and `clearerr` and `fseeko` lacked
capability classifications. Complexity and inventory generation passed.
The failed aggregate receipt remains retained; it is not a passing lint claim.

The declaration repair registers only the three test flags and classifies
the libc calls consistently with existing stream operations. After independent
review, its two affected exact groups passed cold, with zero cached groups,
failures or skips. All four agent verification steps and all five preflight
checks passed; preflight wall time was 18158 ms. The original 19-group runtime
was not repeated for declaration-only changes. These qualifications bind to
the composed `3ac2dd2c693dea69da74b71edeace2b5271b56ee` baseline and the
recorded source hashes, not a later upstream tree.

Both generated-inventory windows retained initial and derived bytes, restored
the initial inventory with a checked byte comparison, and explicitly released
its native claim. Derived inventory remains a retained integration input,
not a current committed generated file. The final declaration wrapper persisted an admitted-scope
memory peak of 1611612160 bytes under a 24 GiB limit, with zero OOM events.
The earlier 19-group wrapper persisted 6256168960 bytes with zero OOM events.
These are workload observations, not admission-class qualifications.

Successor receipts are retained under
`build/handoff/module-harness/cache-v2/`.

| Receipt | SHA256 |
| --- | --- |
| fixed5/fixed.log | `22fb46bc879697752cad7f7610ce27e43941d2d4a20b77cbd89d1e854a71f494` |
| invalidation/mutation.log | `20e10d39702df95c3018440536011ac4452471a3c36397d414810ee7a8a1181e` |
| invalidation/restored.log | `885b52d4cab0b9791c892fc1e44a1f07d4c7fac034ca70656c4d5a9488f3d076` |
| profiles/strict.log, failed before runner | `3a2aae15a74bcf3d62adac4ff34b09b58192f0917b9b23d130758267ed45cc3b` |
| profiles-v2/strict.log | `9326641f9b8724916239eb3a359d0c48ea57db1058de0f3b4ff3736e575e4620` |
| profiles-v2/sanitizer.log | `1f0e90af397597022cfa549385852cd67b199ada3a2a4d047ba493563a33ec0c` |
| final-gates/agent-verify.log, aggregate failed | `12843f42ef479c511a51715a2f6bf1e4a9207ecfbea1d72cf12cf65eccabe867` |
| registration-gates/agent-verify.log | `bf3395d8e66c490471964086be0c2210267fffebd5ebaf893c6589d39563816e` |
| registration-gates/lint-preflight.log | `ec88b7670b5da7115b206f627c04d7b3aaacd26831c327eff281a4032212de52` |
| registration-gates/scope-memory.txt | `ac8a5029ebba041d5443be4649f1cdbcd593f834a172a7c98dd65d077b08aefe` |

## Composed proof accounting correction

The exact `9d59f9b1b1a5ddd04f429d054581b4b696422ac5` candidate on
`4d5ba08a7a952f2d09472ef995f69d1c18de1fd1` failed full proof with
`test_accounting_incomplete`. Its executed test selection and full lint passed,
but the image fixture copied two nested runner verdicts into the outer log.
The proof reader correctly requires exactly one suite verdict; those passing
substeps do not qualify the failed proof or publication.

The correction prefixes every captured child line, preserving diagnostics,
child exit checks, the completion marker and environment restoration. The
proof reader and accounting requirements are unchanged. Canonical
`t-fast-exact ONLY=action_root` then passed cold with no cached, skipped,
unobserved or flaky groups in 9.6 seconds. The actual output contains one
outer verdict and visibly prefixed nested verdicts. Its retained log is
`build/handoff/action-root-nested-verdict-focused.log`, SHA256
`f93ed689e2d3388785662a40292b6c19f4b6755df2e4c4a5ac419dc6a0dcd169`.
A new composed full proof is still required.
