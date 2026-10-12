<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shielded Review device-loop redraw and reconnect

## Intent

Ensure that the Ledger Blue's read-only Shielded Review displays the
transaction facts returned over USB, redraws after progress and errors, and
erases review state across a USB reset. The existing controller tests did not
execute the actual app's APDU loop with real hashing.

## Finding and change

The APDU loop updated `review_app.lines` but called `display_review()` only
at startup, after touch, or on USB reset. A complete transaction could return
the correct digest while the screen had not been redrawn. Version 0.5.8
redraws at review begin, completion of each upload pass, advance, finish,
abort, and command rejection. Upload chunks within a pass do not force a
redraw. A caught exchange failure erases state and redraws `CONNECT Z23`.
The instruction byte is saved before the shared request/reply buffer is
overwritten.

## Reproduction

The `blue-shielded-review-device` host test includes the actual C23 Blue
app loop and substitutes only BOLOS transport, display, and touch calls. It
uses the project's BLAKE2b implementation. A scripted USB exchange uploads
the 1-spend/1-output synthetic v4 wire six times, checks every `9000` reply,
compares the 76-byte facts/digest reply with a separate ZIP-243 computation,
checks summary and branch/digest screen text, taps NEXT, LARGER TEXT, DARK,
and EXIT, sends a USB reset, checks erasure and `CONNECT Z23`, then completes
the same flow again and verifies that large/dark settings survived reset.
It asserts redraws after begin, each completed upload pass, advance, finish,
cancel, and malformed input, while partial upload chunks avoid repeated
redraws. A second device-loop sequence sends begin, a partial upload, cancel,
a fresh begin, a malformed upload, and another clean begin. It checks returned
status words, the ready screen, and erased state. Existing device-loop tests
also inject transport failures, oversized receive counts, and reset during
send. Controller tests cover additional invalid commands and rejected uploads.

```sh
cmake --build /tmp/z23-blue-standalone-release -j4
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j4
ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-sdk-repro-20260927 \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Release: 62/62 passed. Sanitized Debug: 62/62 passed. The pinned Blue SDK
revision was `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, with reviewed
C23 patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
An isolated copy of the source inputs and a separate SDK copy produced the
same Intel HEX SHA-256
`97e60cad053ac82ab41f75ed9aa73bac3c8a8306247def610e5a1a478bfbcbd6`.
The `.text` SHA-256 was
`6466837f121cfb3bc874adc599ff41518367734af43c658c8cfed482a8e8cd42`.
The image has 33,536 bytes of `.text`, zero `.data`, 4,320 bytes of `.bss`,
and a modeled worst stack path of 848/1,536 bytes. The sealed consensus core
matched all 554 files and 80 sections.

## Limits

This is a host BOLOS shim plus a pinned cross-compiled image. No physical
Ledger Blue was visible to this environment, so install, touch response,
USB timing, and BOLOS redraw behavior on hardware remain unverified. This
read-only app has no signing instruction or key access. The synthetic wire is
structurally valid for review but is not a spendable network transaction.
