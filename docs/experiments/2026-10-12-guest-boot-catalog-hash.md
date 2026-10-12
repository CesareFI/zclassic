<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Command catalog validation records each name once

Recorded 2026-10-12T13:18:27Z (local 2026-10-12T09:18:27-0400).
Host `t14`, clang 22.1.6, AMD Ryzen 7 PRO 8840U.
Fixture `tests/fixtures/rvmachine/tiny.bin`, `max_instr` 100000.

`zcl_command_registry_validate` compared every command path and alias with
every earlier command before dispatch. Guest boot always takes the success
path. That path now inserts each name into an open-addressed table. A
collision, a full table, or a failed allocation still uses the pairwise scan,
which keeps the refusal text. The sealed ECDSA registry constructor is
unchanged. The SSH launcher option string and the onion fail-closed dial are
unchanged.

The published `0fc4633b` binary on this host, sha256
`50b54f83443b014cb2a5f2acd6cbbb7b0f701eb9565ef6fb15d20b4008c8ae4e`,
took 0.043–0.048 s across eight boots. One `perf stat` of that binary
reported task-clock 45.59 ms, 191,776,480 cycles, 278,738,127 instructions,
666,490 cache-misses, and wall 0.0485 s.

The measured binary was built from `4ef795e67` plus this catalog change.
Published inverse-delta commits through that tip, and the later sticky
resnapshot commit `ef5dee42c`, are not on this boot path. Eight boots after
the change, binary sha256
`2df37915ae7759599054219a88b032f0f1baa601b480243e15fd24ce079384ac`:

| run | wall s | elapsed_us | guest_work | pins |
| --- | --- | --- | --- | --- |
| 1 | 0.044 | 289 | 341 | held |
| 2 | 0.044 | 256 | 341 | held |
| 3 | 0.044 | 261 | 341 | held |
| 4 | 0.043 | 263 | 341 | held |
| 5 | 0.045 | 253 | 341 | held |
| 6 | 0.045 | 284 | 341 | held |
| 7 | 0.046 | 298 | 341 | held |
| 8 | 0.043 | 258 | 341 | held |

Pins held means retired 279, firmware calls 62, device work 0, skip 999,
fetch 274/67, console 60 bytes, and transcript
`3cbce45f847a34606550eca184e332ce43b5370b3b597ef7f5a6aebf48e9cd4c`.
Two `perf stat` runs reported task-clock 39.41 ms and 37.55 ms, about
236.5–236.9 million instructions, and wall 0.0427 s and 0.0405 s.
`test_command_registry_catalog` and `test_dev_machine_boot` reported
`groups_failed=0`. Cyclomatic ratchet: 76373 functions, 3923 pins exact.
