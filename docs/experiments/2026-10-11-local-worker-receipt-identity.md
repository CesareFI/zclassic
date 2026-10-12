<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Local worker receipt identity

Receiver base: c313201495aa12dee1ee9e56790209749c0c4679. The edited parent files are byte-identical to proposal base a557d1ed0b5acd86770842f45f11660acfd797b0. Source and public-boundary matrix were independently accepted. The original required verification aggregate failed; its passing test, complexity and inventory steps are retained separately. A selective canonical generation, lint and preflight repair subsequently passed. Sanitizers, full proof and publication are NOTRUN.

The receipt adds name, attempt, seq and kind directly from the carried queue job. Strings use the existing bounded JSON escape helper. The checked 8192-byte receipt limit and atomic write remain fail closed. Existing readers select named members and tolerate these additive fields.

The regression reads receipt.json and actual claim.json from the same isolated attempt directory, requiring exact string name/worker/session and integer attempt/seq agreement. Kind is checked against the posted leaf job because claim.json does not carry kind. The real rate-limited queue retry and a distinct job check both attempts and preservation of the first receipt. The existing lifecycle entry also checks the join. Cleanup precedes the new assertions.

## Executed matrix

Host: Linux x86_64, AMD Ryzen 9 7950X3D 16-Core Processor. Compiler: GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1). Execution metadata starts at 2026-10-11T13:16:11Z (local host +00:00). Each leg retains its exact compiler, CPU, date and source hashes.

The canonical t-fast profile is unsanitized. These executions do not establish strict `-Werror` or Debug sanitizer qualification.

Production fixed SHA-256: c017a53d8e1121c379a8260b27b39e06b098513af83af30a8c5739bd978cee1a. Regression test: bc7e9d440c53fcdcfbf24a0d88dae37a9459e593bc50f56b521cfe7181cef958. Parent and mutation production: 06bf859264a779aa4b36cf7ed06b55cab771d2ccc92196f64b047c1c16b7dcb4. Mutation restores the full original production bytes, removing precisely this receipt-field addition. Restoration returns to the fixed hashes.

Canonical command, inside one admitted devbuild wrapper:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact ONLY=devagent_worker T_FAST_EXACT_ARGS=--no-cache
```

| Leg | Exit | Recorded group body | Result | Log SHA-256 |
| --- | --- | --- | --- | --- |
| Parent | 2 | 1775 ms | Actual lifecycle `joined` assertion fails | 981377d783b176793c16c0b53bde36f80a7beec198c454d38bcd0b1820a0496f |
| Fixed | 0 | 23776 ms | Lifecycle and retry/distinct-job control pass | d760eba6afb28cb700cc5b950d67c68b5bcb849cf144d56036f6ac3fa4447b61 |
| Mutation | 2 | 1400 ms | Same actual `joined` assertion fails | 8dd0402752776a6040fc1ea10bbd9df0b4986811ef9959d95a54d7d5a55bb7e9 |
| Restored | 0 | 23745 ms | Lifecycle and retry/distinct-job control pass | 6eea6d0869b6a74aec1f88514660d06ee287c44c7906d95bee54c3b137bd021c |

Each suite reports one cold group, zero cached groups, self-skips, environmental omissions and flaky loads. RED legs retain the canonical rerun-alone attempt; recorded group bodies are not complete failed-attempt cost. Fail-fast RED stops at lifecycle identity and does not establish execution of the later retry control. Fixed and restored actually reach that control. Cheap complexity passes without baseline changes; log SHA-256 492bde5c437f6f8c2ba14c7a0938b56c1b9f13ac4e279d6e1afe25aca60d6b5b.

Evidence locator: `build/handoff/local-receipt-join/matrix-v2/`, with each leg's log, metadata and exit. The guarded capsule is the `build/handoff/local-receipt-join/packet-v2/qualify-v2.sh` member of the retained author evidence packet, SHA-256 5347bfadafee8aba2c85d1609dd3c413bcd3f47386f27ad4d7ceb13c66426b27.

## Retained attempts and cost

The initial admitted qualification stopped before runtime at the cheap complexity gate: test_devagent_worker M=22 exceeded cap 15. The added retry body was extracted unchanged into a helper. Thresholds and production behavior were unchanged. Initial packet, matrix/complexity.log and wrapper.log remain retained; no runtime RED is claimed for that attempt.

Native broker observations distinguish reservation from consumption:

| Native job | Purpose | Queue wait | Admitted-to-release interval | Recorded scope CPU |
| --- | --- | --- | --- | --- |
| 2742136-88609802-1791724142754563352 | Lane preparation | 30.412994723 s | 49.693565352 s | 38.613 s |
| 2812626-88625502-1791724299746284518 | Initial cheap refusal | 0.212309260 s | 94.404947135 s | 225.379 s |
| 2941342-88652259-1791724567320026216 | Complete matrix | 0.018656846 s | 177.232696378 s | 1237.753 s |
| 3399971-88739073-1791725435466183028 | Selected tests pass; documentation lint fails | 0.033851152 s | 152.907905511 s | 723.905 s |
| 3825241-88807327-1791726117997400154 | First selective lint repair fails | 0.015299215 s | 17.318745435 s | 79.844 s |
| 300789-88893085-1791726975577441813 | Canonical generation, lint and preflight repair | 0.016437556 s | 59.108245502 s | 151.921 s |

All reserve 8 CPU tokens, 24 GiB RAM and 2 I/O tokens. These are reservations, not measured consumption. Intervals include wrapper bookkeeping and builds, not just group runtime. Complete memory/host-minute cost and provider request/token attribution remain unknown. Native event and journal evidence is retained in native-job-observation.txt. The matrix job's native release records rc=0 and scope Result=success/inactive; wrapper-v2.exit is 0. A local client-tool terminal reported exit 1 without an explanatory SSH diagnostic. Its cause remains unknown and separate from the native job result; no rerun was made to erase it.

## Remaining acceptance

Canonical impact reports include_dimension=closure-truncated. The conservative union of reported groups and tracked rules 2639, 2642 and 2643 selects the following 15 exact test selectors: make_lint_gates, command_registry_catalog, native_api_contract, command_handler_snapshot, hotswap_module, dev_platform, devagent_worker_guards, devagent_worker, devagent_muse_run, devagent_queue, devagent_queue_order, devagent_queue_guard, devagent_liveness, devagent_receive and command_input_bounds. This is a conservative scoped selection, not a complete include-closure claim. The admitted required agent-verify ran these 15 selectors cold with zero cached groups, failures, self-skips, environmental omissions or flaky loads; recorded test body 56899 ms. Complexity and inventory steps returned 0. The aggregate returned 2 because lint interpreted the prior scoped population wording as a global catalog-count claim. The unchanged source/test suite passed; this does not turn the failed aggregate into PASS. Preflight was not run. The wording is corrected to describe exact test selectors, with the original failure retained. At that stage failed lint and preflight qualification remained pending; successful test steps did not need repetition.

Failure evidence: `final-gates/agent-verify.log` SHA-256 5fde87054f3da77b85fb6bfeeb63482176cd0fca167d3bb0990f2355b4bc765a; `agent-steps/agent-verify.t-fast-exact.log` 08b3a8d4a0204e449ad5ab2bdbdd9256715f63ea9c84f563f0f799985d845319; `agent-steps/agent-verify.lint-fast.log` ae24873564761f149058a5107dec6a6d6229e91e01f05b00fba3535a9f6bf461. Initial capability inventory b75573030bcbef55ff9caf1bf0457590dc91d9a967a26a4e2f3b5f796cc4587e was restored exactly. Derived inventory 44f144d542b0e1f76c1473b73c4ac5575cc2c92a14246aaae10b3864eee87667 remains separate from the source proposal. Native release c25b0fab36674d7e7f091ecdab877016511ce82b0fbbd18160dc0777af058aae retains only the three source/evidence paths, no inventory scope, zero reclaimed leases; cleanup returns 0.

A first selective lint repair also returned 2; preflight remained NOTRUN. The historical quotation repeated the obsolete count wording, and the generated inventory freshness gate correctly refused the restored initial inventory. The quotation is removed; its exact text remains in the preserved original raw log. The reviewed subsequent qualification canonically generated the inventory, then ran lint and preflight before restoring the initial bytes. No successful tests need repetition for these documentation/generation fixes. Repair log SHA-256: 77d8964a051e6f042799f8456d4cd9ccab834b36a892a23ab2b78d4a9b85d4e1. Checked cleanup returned 0; native three-source-path release SHA-256 6df1bc505f09390e04a0fbd09653c9440210ffc7f1b92533f2c2bb5dc822be9c, with zero reclaimed leases. Initial and derived bytes for this failed repair both equal the restored b755 inventory.

These are local queue values, not globally validated task identities. The fill path can default attempt to 1 and seq to 0. Cross-host interpretation also requires the queue namespace and existing worker/session fields; those labels do not prove provider response lineage. Canonical task/action/candidate roots, complete token cost and a verified publication denominator remain unavailable from this receipt. No complete D1/D2/D5 accounting claim follows from it.

## Selective repair acceptance

The final selective wrapper ran the read-only doc-count check, canonical capability inventory generation, lint-fast and lint-preflight in that order. Each phase returned 0. Lint reports 35 gates passing, wall 12501 ms; preflight reports five gates passing, wall 17694 ms. No passing tests were repeated. The earlier failed aggregates remain failed evidence; their actual passing substeps plus this successful repair establish the required scoped checks for the unchanged production/test tuple.

Evidence: `build/handoff/local-receipt-join/lint-preflight-repair-v2/`.

| File | SHA-256 |
| --- | --- |
| provenance.txt | 1ebc5cff3103a4128faa181ac5d749f5301aa4421a9644c2739ce8fad362abc0 |
| doc-counts.log | 63051452b4ad892e78db9e6027eeedd996a5bdcde3568f5c40bbfd14ee52b292 |
| inventory.log | 04fb5c0850e229c4a67b7d6c43c435dd31787f2106d40156484c348a89de088f |
| lint-fast.log | 4c3a94f324bdc61c1b720e9870a5eef96c289a2679c4f84e16c3d31ce84a11bc |
| lint-preflight.log | 1251d00a26d081acae1e1ae1070f2c4f7a069482ad480398654a715df2c4d23a |
| release-CAP.json | e1ab6e2ec6a226024d5ef808ced889494f9943bdaa43ef934d23b71e75a0a9a9 |

Native broker release records rc=0; scope Result=success/inactive. Checked cleanup returns 0. Initial b755 inventory is restored exactly; derived 44f inventory is preserved separately and equals the first successful canonical derivation. Actual native replacement retains only the three source/evidence paths, no inventory scope, and zero reclaimed leases. The guarded repair wrapper SHA-256 is 07995f72a21469e8e3767128ea323e9cd4fad892c3431ce345adc3138af57239.

The executed repair binds experiment af765d45c40375a2ab15925a496705d34459aace9aa3d12cc3ad4c8fcf5fcb5d. This final reconciliation is a subsequent documentation-only edit; it does not relabel the source/test evidence or imply that its own wording was part of the earlier gate input. Independent final review and any standalone document validation remain separate from the executed repair. Signing, integration, new-pair full proof, publication and operational adoption remain unestablished here.
