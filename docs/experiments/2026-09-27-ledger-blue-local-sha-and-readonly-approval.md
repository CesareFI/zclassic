<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue local SHA-256 and read-only approval

Local time: 2026-09-27T06:41:59-04:00

UTC: 2026-09-27T10:41:59Z

## Question

Can the read-only Blue wallet reviewer build without OpenSSL, and can its
REVIEW CONFIRMED action be prevented from authorizing a future signer?

## Result

The C23 wallet reviewer uses Z23's self-contained `zsha256` package for
transaction replay, wire comparison, CLI preflight, and UTXO script hashes.
`ZCL_LEDGER_REVIEW_ONLY=ON` builds that executable without discovering
OpenSSL or PNG. The GCC 16.1.1 Release executable's dynamic dependency list
contains only `libc.so.6`. The existing wallet CLI fixture passed against
that exact executable, including the mismatched-script and changed-tip
rejections. The `zsha256` package's vectors, HMAC, incremental, comparison,
and fuzz groups passed under Clang 22.1.6 with AddressSanitizer and
UndefinedBehaviorSanitizer and under GCC 16.1.1 Release.
The replay SHA callbacks reject invalid pointers explicitly before calling
the `void` SHA API. After that guard, both compilers passed the three focused
payment-review, wallet-CLI, and chain-tip tests. The standalone reviewer
again passed the wallet CLI fixture with only `libc.so.6` linked.

Wallet 0.2.15 has separate read-only confirmation and signing-approval
flags. The Blue touchscreen's CONFIRM callback sets only the read-only flag.
That state refuses signing approval and refuses digest consumption. The
host UI test exercised that exact callback. The signer command test passed
the confirmed state to a valid signing frame and verified that the signer
callback was never called and the response buffer was cleared. Both focused
signer tests passed after this addition. The fee, totals, and
confirmed PNG hashes identical to the previously inspected 320×480 pages:
`2609788f7ff98111bd8aaef24d482e30a62774a3dad84f52b7540e2b4f5137cd`,
`ba2a66c7e0d9309305cba9a0306e5de4e9c82a30441f86281a0f94358867e6d3`,
and `c10414e339543e9f31db6217937a10af656d8e35d799be5ace705b819d41e049`.

Both complete Ledger host suites passed 30/30 tests. The repository
cyclomatic-complexity ratchet passed across 60,767 functions in 4,430 files.
Two clean ARM builds using separately patched copies of Ledger Blue SDK
revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` produced identical
33,792-byte `.text` SHA-256
`7cefe528eeee5407edd40306951bb604f467ef526619828f246a2fe519ebf3e6`.
The image has 5,472 bytes of `.bss`, zero `.data`, and a largest named C
stack path of 752 bytes against a 2,048-byte reserve and 512-byte margin.
The SDK copies were compared byte-for-byte before the final builds. An
initial mismatch exposed a stale USB-reset hunk in one patched SDK tree;
after both trees matched the repository's C23 SDK patch, the images matched.
The Makefile now rejects a stale SDK diff before compilation. A copied SDK
with the USB-reset hunk removed failed even under `make -n` with the expected
patch-mismatch error; the canonical patched SDK passed the same build gate.
CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Test date:
2026-09-27.

## Additional verification

The wallet CLI fixture test now uses the in-tree C23 SHA-256 implementation
for previous-transaction identifiers. On 2026-09-27T06:55:23-04:00
(2026-09-27T10:55:23Z), its unchanged fixture assertions passed with Clang
22.1.6 Debug/ASan/UBSan and GCC 16.1.1 Release, each against the standalone
reviewer. `readelf -d` on the GCC fixture test listed only `libc.so.6` as a
runtime dependency. CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics.

The CLI now queries the local node tip again after the read-only Blue review
and rejects the result if the tip changed or the RPC failed. The shared
comparison function passed matching-tip, changed-block-hash, missing-RPC,
and null-initial-tip cases in the chain-tip test. The wallet CLI fixture and
chain-tip tests passed 2/2 in Clang 22.1.6 Debug/ASan/UBSan and GCC 16.1.1
Release at 2026-09-27T06:56:59-04:00 (2026-09-27T10:56:59Z). The final
post-USB branch remains unexercised on physical Blue hardware.

Wallet 0.2.16 uses DONE on the totals page and REVIEW COMPLETE on the final
read-only page. A single-line 22-pixel chain/branch warning failed the
viewport-fit assertion, so the final layout uses two 22-pixel lines. The
actual wallet UI test passed with Clang 22.1.6 Debug/ASan/UBSan and GCC
16.1.1 Release. Both complete Ledger host suites passed 30/30, and the
cyclomatic-complexity gate passed 60,769 functions in 4,430 files. The
320×480 totals and completion PNG SHA-256 values are
`4bd3ea009b00183e889315bacaa42fab5a65169dc52ce39a505eca116ca9c28a`
and `ae189901222483118f1b98b2b70278695e979ef4551975da04c69f67b7a4f422`;
the fee PNG remained
`2609788f7ff98111bd8aaef24d482e30a62774a3dad84f52b7540e2b4f5137cd`.
The PNGs were visually inspected at their native 320×480 resolution. Two
clean ARM builds from separately patched, byte-identical SDK checkouts
produced the same 33,792-byte `.text` SHA-256
`2c6000584ccd6826c5ea92133bad0ab0dd3926afbc3015c9f8ab868a77f38fb6`.
Both had zero `.data`, 5,472 bytes of `.bss`, and a largest named C stack
path of 752 bytes against the 2,048-byte reserve and 512-byte margin.
Observed 2026-09-27T07:02:25-04:00 (2026-09-27T11:02:25Z) on an AMD
Ryzen 7 PRO 8840U with Radeon 780M Graphics.

The simulator now exposes its raw 320×480 RGB buffer to C23 tests. The
wallet UI test pins SHA-256 of the fee, totals, and completion pixels to
`017b0ce094d47ea140e141d25ec9a7fbff9268b5d067ac0b3dc7513eeac617b0`,
`c41dcdb1fcb60de63a9fef60ebeff08ce88e47f9e1da3cdceacbc0a863861e84`,
and `67b249ef1989c05d6251fb54e9d895d56c2f600723a525e02f9a4b27565ba9bf`.
The canvas test compared raw RGB byte-for-byte with decoded PNG pixels. Both
tests passed 2/2 with Clang 22.1.6 Debug/ASan/UBSan and GCC 16.1.1 Release;
the complexity gate passed 60,771 functions in 4,430 files. These hashes
pin the host simulator output, not the Blue's physical display.

A fresh GCC 16.1.1 Release build with
`ZCL_LEDGER_REVIEW_ONLY=ON`, `CMAKE_DISABLE_FIND_PACKAGE_OpenSSL=ON`, and
`CMAKE_DISABLE_FIND_PACKAGE_PNG=ON` configured and built successfully. CMake
reported both disable variables unused because this mode never searches for
those packages. Its executable passed the wallet CLI fixture and `readelf -d`
listed only `libc.so.6` as a runtime dependency.

The Blue Makefile now verifies the SDK revision and exact diff before loading
the SDK's make definitions for build or clean. A copied SDK with an added
`$(error SDK_INCLUDED_BEFORE_GATE)` at the start of `Makefile.defines`
was rejected by the patch-hash gate under both `make -n` and
`make -n clean`; the sentinel was never parsed. Both dry runs accepted the
canonical patched SDK. This closes the makefile-include ordering gap; it
does not attest to the SDK's runtime behavior.

A separate SDK copy with a staged-only change to `Makefile.rules` retained
the expected unstaged patch hash but was rejected by the new staged-change
gate under `make -n`. The canonical patched SDK passed the same dry run.
The patch check uses `git diff --no-ext-diff --binary`; the canonical diff
kept SHA-256 `4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
A copied SDK with `diff.external=/bin/false` in its local Git config still
passed the dry run, showing that external diff commands are ignored.

The reviewer now uses the same uncertainty wording for a failed pre-USB
tip query as for a failed post-USB query. The wallet CLI fixture passed with
Clang 22.1.6 Debug/ASan/UBSan and GCC 16.1.1 Release, including the
changed-tip case. The standalone no-OpenSSL reviewer passed the same fixture
with the updated GCC harness; the complexity gate remained green.

## Limit

The complete Ledger host toolset still requires OpenSSL 3 for secure-channel
key exchange, custom-CA signing, public-key validation, and signing-test
verification. Wallet 0.2.16 is uninstalled and read-only. Host UI tests do
not prove physical Blue USB, touchscreen timing, EXIT, or restart behavior.
No Blue payment signature was requested or produced.
