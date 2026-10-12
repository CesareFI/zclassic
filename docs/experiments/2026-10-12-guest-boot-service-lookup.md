<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Guest boot does not spawn the user-unit lookup

Recorded 2026-10-12T10:47:58Z (local 2026-10-12T06:47:58-04:00). Host: clang 22.1.6. CPU: AMD Ryzen 7 PRO 8840U.
Binary: `build/bin/z23-dev`. Fixture: `tests/fixtures/rvmachine/tiny.bin`,
`max_instr` 100000.

The boot command's own timer stays under 1 ms (`elapsed_us` 872 on the
build that still spawned the helper). Guest work is unchanged: retired 279,
firmware calls 62, device work 0, console 60 bytes, the same marker text.

Before this change, process start exec'd `systemctl --user show zcl23-dev
-p ExecStart --value` even though guest boot does not read that unit.
`strace -f -e execve` after the change shows one exec, the `z23-dev` binary
itself. `status` with no cookie still execs `systemctl`. The registered
group `test_cli_argv_strict` covers both, and reported `groups_failed=0`.

Wall-clock samples at 2026-10-12T10:43:35Z did not move by a stable amount
(one run before, 0.110 s; two runs after, 0.169 s and 0.119 s; a third
`perf stat` after-run, 0.156 s). A 90-sample cycle profile of one after-run
spends its samples in the dynamic linker and in `secp256k1_fe_mul_inner`
during process init. That init is outside this slice. Cyclomatic ratchet
at 2026-10-12T10:49:20Z: 76318 functions, 3923 pins exact.
`engine/entry/main_cli_modes.c` stays at its recorded ceiling of 4275 lines.
The lookup predicate is the header inline `zcl_cli_service_lookup_blocked`.
