<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Current canary observation boundary

Base: `a604b833dbebc2e56bc23cb49ccb98e91d37a409`.
Before candidate preparation, current `origin/main`
`e0aa31975b9fcd30c11125ab50f3fadf6fafa931` was fetched and integrated by
fast-forward. Its changes do not overlap the four owned files; the reviewed
service and test bytes remain unchanged by integration.
The canary watcher retains verdicts after file removal or a corrupt replacement.
Consumers previously could not distinguish retained PASS display from a current
observation. The existing state dump now adds per-kind boolean `present`,
`parsed`, and `current_pass` without changing sentinel input or FAIL authority.

`present` means the filename was observed in the latest scan attempt; `parsed`
means that attempt read a JSON object. `current_pass` uses the existing exact
source, exact executable, PASS, and process-start clear predicate. Each attempt
resets only these observations before resolving its directory. An unavailable
directory and removed or corrupt files cannot retain positive current evidence.
Historical verdict and FAIL details remain available; removal never clears FAIL.
Filename kind remains authoritative and the sentinel's `from` stays display-only.
Concurrent dumps may observe a partial scan. File changes after a scan are learned
at the next scan; these flags do not claim continuous filesystem presence.

The existing clear predicate does not reject future `started_ts`, enforce
`ts >= started_ts`, or apply a maximum age. Therefore `current_pass` cannot
establish fresh genesis acceptance or the required retained 168-hour C8 window.
Reporter binding, explicit timestamp qualification, live coarse matching, and
retained exact source/artifact window evidence remain separate continuations.
No consensus, FAIL predicate, receipt acceptance, or production operation changes.

Registered acceptance: `canary_sentinel_watch`. New production-dump assertions
require boolean field existence and cover exact PASS, empty and inaccessible
scans, removal, atomic corrupt replacement, UNKNOWN, exact replacement, retained
FAIL, inclusive process-start boundary, stale/zero start, source/artifact mismatch
and invalid/missing identities, and filename genesis versus display-only anchor.
Source checks and behavioral execution evidence are recorded separately.

Designed mutations: remove the observation reset in
`canary_sentinel_watch_tick_once` while retaining dump fields; removal and
inaccessible-directory assertions must fail. Replace `slot->current_pass =
authoritative_clear` with `slot->current_pass = parsed && is_pass` in
`process_sentinel`; identity and run-boundary assertions must fail. Restore each
production mutation before accepting the fixed result. These are proposed
mutation witnesses; no mutation execution or runtime acceptance is claimed here.

Source-only checks on 2026-10-08: `git diff --check` passed. The existing
native complexity gate passed with cap 15 and all 3,929 baseline pins exact;
no complexity baseline was changed. Compilation, registered acceptance and
fixed/mutated/restored execution remain NOTRUN for this candidate.

The filename observation is recorded before any concatenated read-path refusal.
The Linux boundary fixture creates private nested directories with `mkdirat` and
`openat`, enumerates a 4070-byte directory path, and creates its sentinel through
the retained descriptor. Its full read locator exceeds the watcher's 4096-byte
buffer: the dump must still report present=true, parsed=false, current_pass=false.
The fixture does not change process cwd and removes its descriptor-relative tree.
This exact Linux pathname witness is not a macOS or Windows runtime claim.
Restoring observation assignment after the path-size refusal must fail it.

## Linux production-boundary qualification

On 2026-10-08, isolated development peer r1 ran candidate
`70a173e0a5f244b92265648507e908289b5bd427`, parent
`e0aa31975b9fcd30c11125ab50f3fadf6fafa931`, through installed
`devbuild --wait`. Toolchain: Ubuntu GCC 14.2.0; CPU: AMD Ryzen 9 7950X3D.
Admission granted 28 jobs and 24 GiB. The registered cold
`canary_sentinel_watch` group passed: one group executed, zero cached,
zero failures, zero skips, 6.2 seconds test wall time.

The intended production mutation moved `slot->present = true` after the
concatenated path-size refusal. The cold group then failed precisely at
`observed filename survives full-path read refusal`: one group executed,
one failed, zero skips, 13.3 seconds test wall time, make status 2.
Mutation patch SHA-256:
`ed00cd5b3b6ced10ea8ffef281b8b85c6b64ed465c30a01d5b7293ca68b88d33`.

Restoration recovered the exact service SHA-256
`2ef55c5be00b9d5ef3f631fb4e5c4102a8d996fa9b50c21a0fc828de75cbf0b8`
and clean candidate checkout. The restored cold group passed: one executed,
zero cached, zero failures, zero skips, 20.8 seconds test wall time. All three
runs reported zero environment-unobserved and load-flaky groups. The earlier
C8 reporter worktree remained clean and unchanged. No production node or
consensus operation ran.

Retained r1 stage logs and their matching transferred local copies reside in
the external private proof directory named
z23-canary-proof-70a173e0a-20261008. SHA-256 identities:

| Stage | Log SHA-256 |
| --- | --- |
| Fixed | `d7a2600f74f3baa55b3cc200b1c58d8c0088b1ff85d6264d173523073f38ddb6` |
| Mutated | `b6dc1553766ebd98ee599f6290bd9afe4ab62a5f4f71cc72285b466e05a4b0d9` |
| Restored | `4e69af72ee6223a04402346b1357a079316ec871fbba6a82daa4298b3d0240d7` |

This evidence supersedes initial NOTRUN entries only for the named Linux group
and presence-boundary mutation on candidate 70a173e0a. Reset-removal and
PASS-authority mutations, macOS and Windows execution, whole integration
proof, fresh canary timestamp policy, and C8's retained 168-hour window remain
unqualified. Subsequent documentation or source changes receive new identities.
