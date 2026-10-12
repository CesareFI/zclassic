<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shipping refuses unpublished commits

## Invariant

Shipping must not publish source before its landing proof. The shell ship
entry point now refuses a checkout ahead of `origin/main`, including dry-run
and skip-gate invocations. Publication remains the native landing service's
responsibility. This change grants no deployment authority.

## Source and environment

- Base: `4f0c504cb1b6dd219ebe53e50d0530e8f56dc25c`.
- Measurement date: 2026-10-11, UTC.
- Host: x86-64 Linux, AMD Ryzen 9 7950X3D, 32 logical CPUs.
- Admission: `devbuild --wait`, 28 admitted CPUs, 24 GiB memory limit.
- Compilers: GCC 14.2.0 and Clang 20.1.8.
- Test-only diff SHA-256: `e1d10352caea23049e7d846584f9bc26cacc7b9b77f3d32c375c5a3a4922ffc7`.
- Tested candidate diff SHA-256: `94f3c3a81f939c8b90e15ebecf31179427bf273e9d2c78bd2869538c5e08195d`.

Diff hashes cover `git diff --binary` at the stated stage. The candidate hash
precedes this evidence note. Captures and the exact patches are retained under
`build/handoff/ship-publication-20261011/` in the isolated test lane.

## Executed observations

| Stage | Observation | Capture |
| --- | --- | --- |
| Unchanged production plus new test | Expected RED: the actual non-dry ship entry point changed the fixture's bare remote from `5bae184fa2b569f762728f3120d86142645c689b` to `32483e12f0f47de2564abbff58707414b0c4d3e4`; assertion at `test_dev_ship.c:847` failed | `parent-test.log` |
| Parent publication checker | PASS: 857 tracked inputs, nine allowlisted paths; the old ship exemption admits the defect | `parent-publish-gate.log` |
| Repaired candidate | PASS: exact `dev_ship` group, ship transaction checks and publication checker; the checker has eight allowlisted paths | `candidate-focused.log` |
| Restored production defect | Expected RED: restoring only the removed push block changed the fixture remote and failed the same assertion; publication checker rejected `tools/ship.sh:1188` | `mutation-test.log`, `mutation-gate.log` |
| Mutation restoration | Exact repaired shell SHA-256 restored: `6a0a80c2b38a1842e3013a3d7a63833355282015625cc019ebcac654dc2d2163` | `mutation-before.sha256`, `restoration-check.log` |
| Restored candidate verification | PASS: `agent-verify ONLY=dev_ship`, one cold group, zero failures, cache hits, skips or unobserved environments; generated capability inventory and fast lint passed | `restored-agent-verify-admitted.log` |
| Restored preflight | PASS: five preflight gates and publication checker | `restored-lint-preflight.log` |

Each group run executed one group with zero cache hits, skips or unobserved
environments. Parent and mutation failures reproduced on the runner's automatic
isolated retry. Candidate group wall time was 7.1 seconds; this is not a
delivery-to-verdict latency measurement or a Development MVP qualification.

The regression copies the production script into a disposable Git repository
with a writable local bare remote. It invokes the real non-dry entry point and
compares remote commit identities. Fixture preparation uses existing seams;
a refusing `make` stand-in prevents downstream builds and deployment after a
restored push. No production remote, node or service is targeted.

## Remaining qualification

Initial verification attempts were not admitted: `devbuild` exited 75 because
available storage was below the receiver's configured 466 GiB floor. After
ordinary native compiler-cache eviction recovered capacity, the same admission
policy accepted the restored verification and preflight commands above. No
limit was overridden. Generated capability inventory remained unchanged.
The full signed candidate/base proof and publication remain unqualified.
Focused tests, source review and preflight do not replace those gates. No
Development MVP status changes follow from this slice.
