<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue previous-wire upload isolation

Date: 2026-09-28T15:44:58Z (2026-09-28T11:44:58-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6.

## Question

Can a callback change a caller-owned previous transaction after Blue fee and
digest verification while the host reports a successful bound-input review?

## Method

The in-process Blue APDU model changes the last byte of a previous
transaction after the device replies to its final verification command.
Before the fix, `blue_payment_live_run_bound` returned success; the red
assertion is recorded in `/tmp/z23-blue-previous-red-run.log` on this host.
The tests also change the caller's previous wire during chunk upload and its
length descriptor after verification. They check that the driver fails and
requests review abort after BEGIN.

The host now copies one complete previous wire immediately before streaming
it, subject to the existing 2,097,152-byte limit. It sends only that private
copy. After device verification, it compares the caller's descriptor and all
original bytes with the copy. Any change, failed allocation, or failed device
response returns failure. The enclosing bound review requests abort.

Commands from the repository root:

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH=/tmp/z23-blue-previous-wag make lint-fast
make check-core-seal
```

## Measured cost and limits

Serial Release and sanitized Debug suites passed 57/57 cases each. The new
mutation tests reject mid-upload byte changes, post-verification byte
changes, and post-verification descriptor changes while the unchanged bound
review still succeeds. All 33 fast lint gates passed at the existing
cyclomatic cap of 15; the lint wall time was 121.578 seconds against a
75-second soft budget under concurrent testing. The core seal matched 554
files and 80 sections. Markdown links and inline paths passed with no new
errors. LeakSanitizer was disabled because the container blocks its ptrace
setup; AddressSanitizer and UndefinedBehaviorSanitizer remained active.

One extra host allocation holds at most 2,097,152 previous-wire bytes and
is freed before the next previous wire. It does not coexist with the unsigned
wire snapshot, whose allocation is released after output review. The
`blue_payment_live_run_bound` frame measured 3,480 bytes before this change
and 3,496 bytes after it with Clang `-std=c23 -O3 -fstack-usage`. The host
object `.text` grew from 5,772 to 5,916 bytes. These are host measurements;
the device image is unchanged.

The model tests sequential callback mutation. The caller must keep the
previous descriptors and wires alive and prevent concurrent writes for the
whole call. Each wire is copied when its turn begins, so the host does not
freeze all previous wires at entry. The Blue's device-side txid, digest, and
fee checks bind supplied previous wires to the transaction, but the Blue
cannot prove that a previous output is unspent or part of the accepted chain.
The Wallet image remains uninstalled and this driver is not verified on
physical Blue firmware.
