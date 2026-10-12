<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue reported APDU receive length

Date: 2026-09-28T20:13:49Z (2026-09-28T16:13:49-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Does the Blue parse a request if its USB exchange reports more bytes than
the 260-byte shared APDU buffer can contain?

## Finding and change

The startup-shell test copied a valid five-byte payment request into the
bounded buffer but forged the returned receive count as 261 and 65,535.
The prior loop dispatched the payment instruction and returned its success
status. The test failed on the expected `0x6700` status. Wallet 0.3.30
checks the reported count before inspecting the instruction or passing the
request to either handler. An oversized count aborts the current payment,
clears the shared buffer, and returns `0x6700`; it cannot be treated as an
identity request while the device is locked. The existing lock handling
remains after this check, so a locked session can still return `0x6985`.

The test checks that the payment handler was not called, no review remains
visible, and the reply tail is zero for both forged counts. The source
keeps the complexity cap at 15 by moving the test's forged-count selection
into a small helper.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-wallet BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Wallet 0.3.30 links 48,648 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. Its largest named app path uses 1,112 bytes plus a 512-byte
margin inside the 2,048-byte stack reservation; BOLOS frames are excluded.
Its `.text` SHA-256 is
`c7a6b617c215e7c48545abcf52ef191164238b7ef7db06fb2504c34f79f7fc64`;
Intel HEX SHA-256 is
`e065334b3d83f6dd41507060a3f0c55937e323c4edfa2e011973f067ba4f9ef6`.
A forced rebuild from a copied source tree and separate pinned SDK copy
produced byte-identical `.text` and Intel HEX files with the same toolchain.

Serial Release and sanitized Debug suites each passed 57/57 tests. All 33
fast lint gates, the unchanged cyclomatic cap of 15, and the consensus-core
seal of 554 files and 80 sections passed. Markdown link validation scanned
529 documents and 957 local targets; inline path validation scanned 529
documents with zero new findings.

## Limit

The test forges a host SDK-shell return value. It does not establish that
physical BOLOS can report a count beyond the supplied buffer, and it does
not verify physical USB timing. Wallet 0.3.30 remains uninstalled after
the earlier startup freeze; the installer block remains active.
