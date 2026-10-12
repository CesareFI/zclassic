<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bounded C23 procedures and unambiguous selection

## Intention and exact scope

Extend template-driven C23 production using the existing compiled prompt
selector, template identity and receipt path. The source base is
`ed3b192029bbe4fc9df534a26fb021cc84993f6d`. The change adds
`c23-wire-codec`, `c23-cas-operation`, `c23-service-operation` and
`c23-resource-owner` to
`engine/composition/prompt_templates.def`, extends the registered `engine`
selection fixture, and updates `docs/work/C23_TASK_CATALOG.md`.
The canonical generator also refreshes the source-root identity in
`docs/CAPABILITY_INVENTORY.jsonl`.

Each procedure specifies required task inputs, a real source exemplar,
implementation order, ownership/refusal behavior and production-caller
acceptance. Only the selected procedure enters a prompt. The existing
1800-byte per-procedure test applies to all four additions. Template identities
continue through the existing canonical serialization and CAS path; this
change creates no scheduler, task authority or evidence store.

The compiled-template lint gate now rejects duplicate `(kind, section)` rows.
Previously the lookup selected one body while template identity included all
rows. The new production scanner reports the conflicting kind and section;
self-tests cover identical and different duplicate bodies and valid distinct
pairs. The change preserves existing result codes and bounded diagnostics.

The catalog supplies a compact task card and maps only matching wire and
content-store rows. Signature admission, transfer scheduling, eviction and
index recovery still require their own procedures. Examples guide reuse;
they do not establish that every possible C23 function has a template.

## Verification

The following observations cover the initial wire-codec and CAS stage;
later sections record the service and resource-owner follow-ups.

- Source inspection verified the two initial exemplar symbols at the exact base.
- The existing local `z23-lint check-prompt-templates` passed: 44 rows,
  11 complete kinds. This is a source gate, not a rebuilt-runner claim.
- `git diff --check` passed before remote qualification.
- The source/test patch transferred to an isolated development-host worktree
  at the exact base with SHA-256
  `ef3e1967d6d0f96f39f1e68b6c0342f32e065c9a702173e34d1e1fabce04d7b9`.
- Host-admitted `make setup` completed. With GCC 14.2.0,
  `devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact ONLY=engine`
  passed: one cold group, zero failures, zero skips, 4.7 seconds test wall
  time. This excludes dependency preparation and compilation time.
- Both rebuilt production-runner `--dry-run` previews selected the requested
  kind and reported four of four required sections present. No provider call
  was made. Preview checks prompt composition, not whether a worker obeys it
  or whether task-specific input fields are complete.
- At 2026-10-08T18:24:04Z, source hashes matched between local and remote:
  template definition
  `4e05203986970b1b058056168afbb92f4734135b38188fb1614c54d1933a3b33`;
  test source
  `613a293c322eba7bdde83774d4034d18005bf2a55a7a58256c02807d005c3b59`.
- Catalog checks retain 500 unique IDs, with 24 wire and 10 CAS rows selecting
  the new procedures. These are coverage counts, not productivity results.
- The first `lint-fast` run passed 34 of 35 gates and refused the stale
  capability inventory. After host-admitted `make docs-capability-inventory`,
  `devbuild --wait make lint-fast` passed all 35 gates. The generated diff
  changes only the inventory source-root record.
- Logs are retained under `build/handoff/c23-function-recipes/` in the local
  candidate checkout: setup, registered group, both previews, generation,
  initial lint refusal and final lint pass. Full publication proof is NOTRUN.

## Fleet follow-up qualification

Two remote proposals received independent source review before integration:
the service-operation recipe and duplicate-pair lint refusal. Their original
patch SHA-256 identities are respectively
`4e5305c3573619a4549f4c25e032b94e5dfc8872c7400b37f7e2d96bf2de418b`
and `b73a292c130ab4f17f63624a15ec4dd18338aa931af485056106db156f05011e`.
The service recipe was combined with the earlier additions at their shared
insertion points; the original patch is not the combined candidate identity.

On 2026-10-08 the host-admitted rebuilt prompt gate passed with 48 rows and
12 complete kinds. Its self-test passed. The registered `engine` group passed
with zero failures and zero skips in 35.1 seconds test wall time. These checks
qualify selection and fixtures, not measured provider savings or publication.
The duplicate-check mutation compiled; the unchanged self-test exited 1.
After reverse application, the rebuilt gate and self-test passed. Restored
`gate_def_parsers.c` SHA-256 was
`a1898c6b645530071cb6a4b26d4984ff094e076e94d7c68b6df2d378eee3a5c0`.
After canonical inventory regeneration, host-admitted `lint-fast` passed for
the combined candidate. Follow-up logs are retained with the earlier evidence.
Exact publication proof and publication remain NOTRUN.

## Follow-up corrections and resource ownership

Independent source reviews identified an overstatement in the service recipe:
its exemplar rolls back paired database writes, but the transition caller
advances memory and discards persistence status. The procedure now distinguishes
those outcomes instead of promising caller-visible refusal or memory rollback.
The resource-owner procedure binds the QR renderer's borrowed extent, cleared
outputs, success transfer and caller release. Its selection fixture uses the
existing bounded template-identity path. No provider cost improvement is claimed.

The lint scanner now propagates oversized-field status 2 from both collectors.
Its prior positive-status skip path could print an overflow diagnostic and
still accept a valid seed. Four 96-byte-field fixtures exercise the production
scanner. Valid skipped rows and duplicate-pair checks remain covered.
The new procedure exposed the former 48-row storage capacity. Checked call
storage now admits 64 rows, with the prompt-row bound derived from that same
capacity; full-capacity acceptance and capacity-plus-one refusal are tested.
This increases bounded static storage and the maximum pair-comparison work;
it is a capacity change, not a measured performance improvement.

On 2026-10-08, using GCC 14.2.0 on an AMD Ryzen 9 7950X3D,
host-admitted focused engine acceptance passed with zero failures and zero
skips (10.5 seconds test wall time). The rebuilt prompt gate passed with 52
rows and 13 kinds; its self-test passed. Reverting both collector predicates
to the prior positive-status skip defect compiled and made that self-test exit
1. Restoring the exact source rebuilt and passed. Restored parser SHA-256:
`e87801a196717e2ddf0a1aa9747ce2280123362325d97acd607f56aaae56ed66`.
Canonical inventory regeneration and `lint-fast` passed. Exact post-commit
publication proof is not established by these focused checks. Evidence is retained in
`build/handoff/sol-followup-collected/` and the isolated development-host
checkout's `build/followup-*` logs.

## Efficiency experiment still required

Freeze a matched cohort of real root tasks and acceptance policies. Compare
the existing workflow with the selected procedure while retaining identical
source context, model configuration and independent review obligations.
Include discovery, generation, tests, review, repair, rejected attempts and
integration in total usage. Bind observations to exact task, candidate,
template and policy identities through existing authorities. Missing usage
remains unknown; splitting tasks cannot increase the accepted-output count.

Report complete tokens per accepted task, first-attempt acceptance,
end-to-end latency, escaped defects and accounting coverage. Functional
selection and bounded text do not demonstrate savings. Provider-token
comparison, fleet recovery and publication are NOTRUN for this efficiency
experiment. The source reviews below do not qualify workflow cost savings.

## Exact-candidate source review

Independent Linux and macOS reviews inspected candidate
`0b605966df26636dd8cdf13c8637fa2e86a9b4f3` against the stated base without
executing its code. The scanner review accepted its bounded source obligations.
The template review found no blocking source defect, but rejected this
document's stale addition count and ambiguous independent-review status.
An independent source review accepted the correction of those two
documentation findings; the earlier source verdicts do not bind a later
candidate automatically. Neither review establishes execution or publication
acceptance.
