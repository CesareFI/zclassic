<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue exception reply erasure

Date: 2026-09-28T13:12:26Z (2026-09-28T09:12:26-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can a Blue app-loop exception leave a partly prepared transparent signature
in the shared USB APDU buffer after payment state is aborted?

## Method

The host SDK shell writes eight mock signature bytes, then throws from the
signing command. It checks that the error reply contains only status `6814`
and that the rest of the 260-byte shared APDU buffer is zero. A second case
throws while sending a prepared signature reply and checks the complete
buffer after app teardown. The EXIT test fills the buffer first and checks
that its touch callback erases it.

Before the cleanup change, the first case failed at the buffer-erasure
assertion in `test_sign_exception_cleanup`. The app now wipes the APDU buffer
in the command exception handler, the explicit EXIT path, and final app
teardown. The command handler appends the status only after the wipe.

## Result and limit

The focused startup shell passed in Release and AddressSanitizer plus
UndefinedBehaviorSanitizer Debug. The full CMake suite passed 57/57 in
Release (13.83 seconds) and 57/57 in sanitized Debug (17.12 seconds).
Leak detection was disabled for this ptrace-constrained runner.

The pinned Blue SDK build passed its image and stack gates: `.text` is
44,288 bytes, `.data` is zero, and `.bss` is 5,120 bytes including the
2,048-byte stack reservation. The largest named payment path uses 1,064
bytes of the 1,536-byte usable stack budget. The `.text` SHA-256 is
`b5824ee5f0801bc4c147ec2584bb38e0495b8cc3e20173a6c8de92fba0e9edc2`;
the Intel HEX SHA-256 is
`d9f0429807303f5fcad5ba48204dbe95bc2edad74337b27e1647379fd6cd8be9`.

A second source checkout at `cf9559c886e4171aa03b65bf5590aa05872b2d0a`
and a separate Blue SDK copy at
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with reviewed patch
SHA-256 `4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`
produced identical extracted `.text` bytes and the same Intel HEX hash.
Its named stack paths and `.data`/`.bss` measurements also matched. All 33
fast lint gates, the 554-file/80-section core seal, Markdown links for 509
documents, and the inline-path scan with zero new issues passed.

The shell models the app loop and injected exceptions, not BOLOS exception
timing or physical USB. The image has not been installed on a Blue and has
not signed a real transaction.
