<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue payment touch binding

Date: 2026-09-29T04:45:37Z (2026-09-29T00:45:37-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compilers: Clang 22.1.6, ARM GCC 16.2.0; ISO C23.

## Question

Can a finger that goes down on NO SIGN and releases on SIGN ZCL approve
the reviewed payment? Can a release without a preceding touch, or one after
a page redraw, approve it?

## Reproduction and correction

The pinned Blue SDK dispatches a tap from the release coordinates. A new
integrated Wallet app-loop test placed a finger on NO SIGN and released it
on SIGN ZCL. Against the previous source, the test failed because the app
entered its signing-approved view. The corrected event path admits a payment
release only when its initial touch, any intervening touch events, and its
release remain on the same button and review page. The test also rejects a
release without an initial touch and a release after the signing page is
redrawn. Ordinary CONTINUE, EXIT, NO SIGN, and SIGN ZCL taps still pass
through the same app loop.

The review generation and touch state share the existing 32-bit payment
epoch. A page change invalidates an in-progress gesture. The low 26 bits
count page changes; the upper bits record whether a gesture began, remained
valid, and which of at most 15 touch targets it began on. The current pages
have no more than two targets. Packing this state avoids increasing static
RAM. The amount text buffer was tightened from 24 to its exact 22-byte
maximum, including the terminator; the maximum-money formatting test checks
its adjacent guard byte.

The SDK shim models touch and release events and the actual Wallet callback
path. It cannot prove the physical Blue's event timing. This image remains
uninstalled until the real device can confirm ordinary taps, drags, EXIT,
and the 30-second timeout.

## Image and local verification

Two clean source-copy builds against separately patched copies of Blue SDK
revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`
produced identical Wallet 0.3.37 bytes. `.text` is 49,408 bytes, `.data`
is zero, and `.bss` is 5,120 bytes including the 2,048-byte stack reserve.
The 6,144-byte Blue app SRAM budget leaves 1,024 bytes after `.bss`. The
largest modeled payment path uses 1,120 bytes plus the required 512-byte
margin. The largest modeled signing subpath is 1,080 bytes. BOLOS firmware
frames are excluded.

The `.text` SHA-256 is
`3e889f26e72153ceae6b9717041cd39962f2057d6d7c23175c3730befa4f0392`.
The Intel HEX SHA-256 is
`bc27eccc3e77dda8d74421bef3b36f4d6dde57d179cd81c8e58cf7df9435c474`.
The installer does not admit this image.

The final Release source passed 60/60 tests in 92.89 seconds. Sanitized
Debug passed 60/60 in 99.56 seconds with LeakSanitizer disabled for this
runner's ptrace
environment; address and undefined-behavior sanitizers remained enabled.
Both suites include the consensus-accepted Sapling review fixture, pinned
shielded screen content, and Cortex-M0/M3 arithmetic tests. They do not
establish Sapling signing or physical Blue behavior.
All 33 fast lint gates passed. The 554-file and 80-section core seal passed,
the complexity gate scanned 63,534 functions at the unchanged cap of 15,
and both Markdown gates passed with zero new inline-path failures across
557 documents. No consensus-core source changed.
