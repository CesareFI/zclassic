<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Restart input closure and engine-unit run stamps

Recorded at 2026-10-12T02:22:00Z (local 2026-10-11T22:22:00-04:00) on the
Linux lane `include-closure-20261011`.

A restart overlay marker now seals the compiler id, the cflags, and each
dependency path with that file's hash. The source hash remains the second
field. A missing dependency list fails closed. `base_generation` stays in
the link cache key and is not an object input.

Registered `test_dev_platform_shard_05` passed, including
`test_resident_restart_builder` with zero failures. A header edit rebuilt
the one object that lists it and left the other overlay in place. A test
cflags edit left the old overlay unresolved, so the proof did not complete.
Registered `test_proof_ticket_reuse` passed: an unchanged closure hits, and
a one-byte change of source, dependencies, compiler, flags, harness, or
policy misses.

A warm rerun of `make t-fast-exact ONLY=test_proof_ticket_reuse` after an
mtime-only touch of that test measured 160.487 seconds and passed. The
ten-second warm-proof bar is not met. The runner reported `mode=cold` for
that rerun; the lane objects were already built.

The engine-unit snapshot receipt records provider requests, input, cached
input, and output tokens, the prompt template, and the tool source,
mutation, and content stamps. An omitted cache counter is null, not zero.
A content stamp that was not baked in stays the literal `unknown`.
Registered `test_engine` passed. The host that still has no fleet record
is not named in the tree, so no host record was added.

The receipt-gated landing of that measurement stopped in prebuild at
`check-cyclomatic-complexity`. The over-cap helpers were split. Unpinned
functions stay at or under 15. `run_resident_restart_fixture` stays at
its pin of 187 and `write_receipt` stays at its pin of 67. A header edit
still rebuilds only the object that lists it, a flag edit still leaves
the old overlay unresolved, and an omitted counter stays null. On the
same Linux lane, `test_dev_platform_shard_05` and `test_engine` passed
again after the split. The run was admitted at 2026-10-12T03:06:39Z and
finished at 2026-10-12T03:07:32Z.

A later proof of the same stack failed `test_devloop_early` because
`cc -MD` lists `/usr/include/stdc-predef.h` and the dependency parser
accepted only tree-relative paths. An absolute compiler-listed path is
now part of the object key when it names a regular file. The bytes are
hashed at that path. A missing file, a non-regular path, traversal, an
empty path, or a backslash still fails closed. The overlay marker stays
130 bytes. The ten-second warm-proof measurement above is unchanged.
