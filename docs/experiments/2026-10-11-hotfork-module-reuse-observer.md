<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# HOT_FORK module reuse observations

The existing package-policy fixture executes native module production and
confined sealed loading in a private test root. Its unchanged second save
must reuse the exact module; a compile-valid policy mutation must fail the
frozen story, and restoring the policy must restore the original module.

This slice adds typed observations and acceptance predicates for the existing
module producer's compiler and linker process counters, action and object
roots, artifact and loaded-image equality, seals, execution, confinement and
W^X. Cold and mutated stages require new module production. Warm and restored
stages require an artifact cache hit and zero reported module compiler and
linker processes. These counters do not include every process-wide tool or
action-key probe invocation. Existing stage timings are recorded without a
speed threshold or controlled performance claim.

Source proposal baseline:
`f23031bde0b4936e0f51be76954d79e9ae6858a9`.
The registered group is `dev_platform_shard_06`; the fixture is
`test_hotfork_story_file_green_and_red` in `test_dev_platform.c`.
It retains private fixture roots, copied input trees, environment restoration,
behavioral mutation order and cleanup.

Canonical complexity passed at the unchanged cap of 15. The first runtime
selected shard 05 incorrectly: the fixture table uses zero-based ownership,
and owner 5 is registered shard 06. That passing 21224 ms group did not
execute this fixture and remains wrong-selection cost, not acceptance.

The corrected shard 06 ran cold with one executed group, zero cached groups,
failures, self-skips, environment-unobserved or load-flaky cases in 40801 ms.
The named module fixture passed in 14651 ms. Cold production reported three
module compiler processes and one linker; unchanged warm reuse reported zero
of each. The behavioral mutation reported two module compiler processes and
one linker, changed its roots, and reached the existing 14/15 failed story.
Restoration reported a cache hit, zero module compiler/linker processes,
the original roots and a green 15/15 story. All four stages bound the built
artifact, candidate module and loaded mapping to identical digest bytes and
observed seals, candidate execution, confinement and W^X.

Observed build times were 311520 microseconds cold, 67147 warm and 8346
restored. These include the existing producer's recorded stages and are not
a controlled latency comparison. The exact qualified source SHA256 is
`35f55119039f42f1378390375a96c1aa424cb91fa0035f1d663dd2c30b07a656`.
GCC 14.2 and CPU/date metadata are retained with the raw receipts under
`build/handoff/hotfork-module-reuse/`: `corrected-runtime.log` SHA256
`99ba57b36bcd94904b6ab0689d99e344ab36bae2083df1a3988e688b7ab6a374`,
and `corrected-provenance.txt` SHA256
`b434dcc70d1f4539afe076981aeb7c77b928eea2230bc368926287fef413bb0b`.

After reviewed upstream integration, the unchanged test bytes passed the
12-group native impact selection and all four `agent-verify` steps on
`a557d1ed0b5acd86770842f45f11660acfd797b0`, followed by five preflight gates.
The same required acceptance passed on
`c313201495aa12dee1ee9e56790209749c0c4679`: 12 cold groups, zero cached groups,
failures, self-skips, environment-unobserved or load-flaky cases; all four
agent-verification steps returned zero. Five preflight gates passed in
17407 ms. The current source navigator retained the same 12 selectors but
reported a truncated include-closure dimension; no complete graph claim is
made. No additional unchanged upstream resource suite or full proof was run.

The final gate metadata records 2026-10-11T13:26:12Z, GCC
14.2.0-4ubuntu2~24.04.1 and AMD Ryzen 9 7950X3D. Receipts under
`build/handoff/hotfork-module-reuse/current-gates/` are `agent-verify.log`
SHA256 `3a52572132388474e963da425a0ec5b4ad8694e5edb0d2d638e2a31d99046508`,
`lint-preflight.log` SHA256
`755d4a2ef94444e161debf59d061cc49f2394c7faf150d535d0a7d86e8f790a1`,
and `provenance.txt` SHA256
`49889dc0a5ea4332087e44b093a84e95192b187da617e08ef81f0c4a29b785ef`.
The capability inventory before and after generation was byte-identical,
SHA256 `b75573030bcbef55ff9caf1bf0457590dc91d9a967a26a4e2f3b5f796cc4587e`.
Checked restoration and a native two-source-path claim replacement released
the generated scope with zero expired claims reclaimed; `release-CAP.json`
SHA256 is `d8791a3c46d06dc28ac3407d1538b6547ff6a3da238f7fac9b465f8318d8a0ec`.

The original mistaken selection, queue waits and diagnostic refusals remain
retained costs. The final experiment update is documentation-only after those
gates. A subsequent fetch observed
`295f376f744ca546401475bf4ed8cd1c4ae9075a`; its native ELF and private guest
changes were source-reviewed, but this candidate remains bound to the tested
`c313201495aa12dee1ee9e56790209749c0c4679` parent. Its integration owner must
qualify any composed final source; these receipts do not qualify that later tip.

No full candidate proof or publication is established. No HOT_SHADOW
service, distributed transfer, module delivery, activation, complete BUILD
proof reuse or cross-platform acceptance is established by this slice.
