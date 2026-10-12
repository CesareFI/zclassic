<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Package secp256k1 contexts are built on first use

Recorded 2026-10-12T12:31:04Z (local 2026-10-12T08:31:04-0400).
Host `t14`, clang 22.1.6, AMD Ryzen 7 PRO 8840U.
Binary `build/bin/z23-dev`, sha256
`9e255c9ccddb7b1c8f7a934e00a398a6e62e3c79ed58ba216cb8ef5679a17e5d`.
Fixture `tests/fixtures/rvmachine/tiny.bin`, `max_instr` 100000.

Six unsealed package modules each called `secp256k1_context_create` from a
load-time constructor: seed, contributor binding, verify policy, release,
badge, and attest. A standalone probe of one `SIGN|VERIFY` create on this
host took 6703–8514 µs across eight calls. Guest boot never uses those
modules. The sealed ECDSA registry constructor in
`core/modules/crypto_registry/src/scheme_secp256k1_ecdsa.c` still runs.
The vendored archive does not export `secp256k1_context_static`, so each
module keeps its own context and builds it on first seal or verify through
`pthread_once`.

The published binary before this change, same host and fixture, took
0.081–0.088 s of wall time across eight boots. One `perf stat` of that
binary reported task-clock 81.68 ms, 353,910,551 cycles, 916,168
cache-misses, user 0.068 s, sys 0.017 s, wall 0.085 s. Eight boots after
the change:

| run | wall s | elapsed_us | retired | fw_calls | device_work | fetch_hits | fetch_misses | console_bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.044 | 235 | 279 | 62 | 0 | 274 | 67 | 60 |
| 2 | 0.042 | 223 | 279 | 62 | 0 | 274 | 67 | 60 |
| 3 | 0.042 | 215 | 279 | 62 | 0 | 274 | 67 | 60 |
| 4 | 0.045 | 231 | 279 | 62 | 0 | 274 | 67 | 60 |
| 5 | 0.043 | 225 | 279 | 62 | 0 | 274 | 67 | 60 |
| 6 | 0.043 | 215 | 279 | 62 | 0 | 274 | 67 | 60 |
| 7 | 0.045 | 267 | 279 | 62 | 0 | 274 | 67 | 60 |
| 8 | 0.047 | 251 | 279 | 62 | 0 | 274 | 67 | 60 |

`skip` stayed 999. The console marker stayed
`tiny: hello from S-mode`, `probe putchar=1`, `tiny: timer fired`, `U`.
`elapsed_us` is the command handler after process start, so it stays in
the same band. One `perf stat` after the change reported task-clock
44.13 ms, 193,578,940 cycles, 278,973,042 instructions, 650,993
cache-misses, user 0.030 s, sys 0.017 s, wall 0.048 s.

`make -j8 t-fast-exact` on `test_dev_machine_boot`,
`test_guest_ssh_fixture`, `test_rom_fetch_onion`, `test_tor`,
`test_onion_stream`, `test_zcode_verify`, `test_vcs_release`,
`test_zcode_badge`, `test_zcode_contributor`, and
`test_zcode_seed_election` reported `groups_failed=0`, `groups_ran=10`,
`groups_total=1292`. Cyclomatic ratchet: 76335 functions, 3923 pins exact.
File-size policy passed. The SSH launcher option string and the onion
fail-closed dial were not edited.
