<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Soak runner path arguments

The runner validates the final value of each fixed-buffer path argument before
opening its log or starting a node (`tools/soak/main.c:398`,
`tools/soak/main.c:586`). Values are measured in bytes, excluding the terminal
NUL: `--log` permits 255, `--node-datadir` permits 511 and `--connect` permits
127. A value exceeding its capacity returns exit 2 with the flag name
(`tools/soak/main.c:382`).

Repeated flags use the last supplied value. Help exits from argument parsing
before deferred validation (`tools/soak/main.c:490`). Default log naming reads
the wall clock only after validation (`tools/soak/main.c:593`).

## Acceptance design and evidence limits

The registered `soak_runner` group executes the real CLI through bounded merged
output capture (`tests/harness/src/test_soak_runner.c:28`). The host-needs table
requires `build/bin/soak_runner` on POSIX. Non-help path probes specify a zero
interval, so both the corrected and unchecked-copy implementations exit before
log opening, process discovery, RPC or node startup.

Numeric-refusal probes put an empty numeric flag before help and require exit 2,
a flag-specific diagnostic and no created log. Duration-precedence probes use
nonzero intervals: a final duration of 3 with interval 2 reaches log opening
against an existing directory and requires the open failure; a final duration
of 1 with interval 2 requires the interval refusal. Help before an empty numeric
flag still requires exit 0. These are assertions in the proposed regression,
not execution evidence.

The refusal cases require exit 2, no timeout, and a flag-specific `too long`
diagnostic. A downstream interval refusal cannot satisfy those assertions.
The capacity matrix also checks the last fitting byte count, the first
non-fitting count and duplicate flags in both orders
(`tests/harness/src/test_soak_runner.c:125`). Help and fitting values are
compatibility controls, not evidence of overflow refusal.

Compilation, focused execution, mutation execution and canonical source gates
are NOTRUN in the patch-only preparation. Qualification requires the focused
group to pass on the corrected source, fail on unchecked production copies
because the expected diagnostic is absent, and pass again after restoration.
The registration and build-need closure changes additionally require the
`impact_composition` group. Static applicability does not establish these
behavioral results.
