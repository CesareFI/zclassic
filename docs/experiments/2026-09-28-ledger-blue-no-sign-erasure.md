<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue NO SIGN erasure

Date: 2026-09-28T19:37:10Z (2026-09-28T15:37:10-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Does declining the final transparent signing approval immediately erase the
reviewed transaction, per-input ZIP-243 digests, and temporary hash and
display buffers while preserving an unambiguous completion screen?

## Finding

Wallet 0.3.27 set a `review_confirmed` flag on NO SIGN and kept the whole
review in RAM until EXIT. The new tests failed on that build in both the
device-screen simulator and integrated app loop. Wallet 0.3.28 calls the
existing volatile erasure path as soon as the NO SIGN callback succeeds,
then shows REVIEW COMPLETE using a separate flag. A repeated NO SIGN tap,
stale SIGN ZCL tap, or stale page-navigation tap cannot restore signing.

The screen test poisons the hash contexts and amount/path text before the
touch and confirms they are zero afterward. It compares the entire payment
state with the expected aborted state and checks that a digest cannot be
taken. The integrated app-loop test checks that the reviewed transaction is
gone before sending the next APDU; the following signing request is denied.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-wallet BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Wallet 0.3.28 links 48,392 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. Its largest named app path uses 1,088 bytes plus a 512-byte
margin within the 2,048-byte stack reserve; BOLOS frames are excluded.
Its `.text` SHA-256 is
`4822fe3e134ae5cd91897ea577010e02ba64d69ea3ca21dd950493da331884b1`;
Intel HEX SHA-256 is
`20210efb759dfb0555b87456aaa8f0e501fbd951f18c8582a2859a3e226689a4`.
A forced rebuild from a copied source tree and a separate pinned SDK copy
produced byte-identical `.text` and Intel HEX files with the same toolchain.

Serial Release and sanitized Debug suites each passed 57/57 cases. The
affected device-screen and integrated-loop cases passed again under
sanitizers after their final assertions were added. All 33 fast lint gates,
the unchanged cyclomatic cap of 15, and the consensus-core seal of 554 files
and 80 sections passed. Markdown link validation scanned 527 documents and
955 local targets; inline path validation scanned 527 documents with zero
new findings.

## Limit

The tests use a host SDK shim and simulated touches. They do not establish
physical BOLOS startup behavior. Wallet 0.3.28 remains uninstalled after
the earlier physical startup freeze; the installer block remains active.
