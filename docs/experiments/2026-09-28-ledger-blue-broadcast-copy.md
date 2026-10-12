<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue signing and broadcast copy

Date: 2026-09-28T19:16:21Z (2026-09-28T15:16:21-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Does the Blue claim a transaction cannot be broadcast after it releases a
valid signature, even though broadcast is controlled by the host?

## Finding and change

The signing-approved and signature-ready pages said NO BROADCAST. That was
true of the synthetic fixture command, which has no broadcast path, but the
device cannot enforce it once it releases a signature. The final payment
page and both later screens now say HOST MAY BROADCAST. The fee and totals
pages retain CHAIN UNCHECKED and BRANCH UNCHECKED. The final page still
shows amounts, fee, derivation path, branch ID, expiry height, and lock time.
The signing action and touch targets are unchanged.

The host UI test checks the new wording on all three screens and absence of
NO BROADCAST. Its 320 × 480 final-page bitmap was visually inspected and
has decoded RGB pixel SHA-256
`6a2cd65024b34da2138814d5f895b44581029bbffc2229ffab425c4d1697bfb1`.

## Image and reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-wallet BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Wallet 0.3.27 links 48,384 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. The largest named app path uses 1,088 bytes plus a 512-byte
margin inside its 2,048-byte stack reserve; BOLOS frames are excluded.
Its `.text` SHA-256 is
`f666c315509bb7430d100b098f10f2800dc9b8656ddafc3019caa86fcb267307`;
Intel HEX SHA-256 is
`edfc053bc48445765718281190070ee966c334cf18dcfdff08820276bba10422`.
A copied source tree built against a separate pinned SDK copy produced
byte-identical `.text` and Intel HEX using the same ARM toolchain.

The serial Release and sanitized Debug suites each passed 57/57 tests.
Concurrent full-suite runs initially timed out in `blue-m0-sapling-qemu`
and `blue-cm-m3-qemu` under shared-host load; both passed alone in 6.30
seconds and the complete suites then passed serially. The unchanged
cyclomatic cap of 15 passed, as did the core seal of 554 files and 80
sections. `lint-fast` passed all 33 gates. Markdown link validation scanned
526 documents and 954 local targets; inline path validation scanned 526
documents with zero new findings.

## Limit

The device copy warns about broadcast risk; it does not establish whether
the host has a valid chain UTXO or intends to broadcast. Wallet 0.3.27
remains uninstalled after the earlier physical startup freeze. No physical
payment was signed.
