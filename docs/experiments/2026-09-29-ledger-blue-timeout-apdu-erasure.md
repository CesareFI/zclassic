<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue approval-timeout APDU erasure

Date: 2026-09-29T04:14:51Z (2026-09-29T00:14:51-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compilers: Clang 22.1.6, ARM GCC 16.2.0; ISO C23.

## Question

After the Blue returns the first signature of a two-input transparent
payment, does a USB reset or approval timeout erase the remaining approval,
shared APDU bytes, and signer workspace before a second signing request?

## Reproduction and correction

The integrated app-loop test reviews two synthetic owned inputs and two
outputs, approves signing, and receives the first fixed test signature. It
then fills the shared APDU buffer with a nonzero sentinel and dispatches
either a USB reset or ticker timeout. Both routes must erase the approval
and full APDU buffer, stop the approval timer, return to the receive screen,
and reject input one's signing request without another signer call.

Against the previous source, the ticker case failed the APDU erasure
assertion: the buffer retained the sentinel. USB reset already erased it.
The ticker event now erases the full shared APDU buffer and signer workspace
when approval expires or the idle session locks. The startup shell separately
checks ticker erasure and the additional signer wipe. Both focused tests pass
after the correction.

The signature in the app-loop test is a fixed DER-shaped fixture. These tests
cover state transitions and cleanup, not a broadcastable transaction or
ECDSA validity. The corrected timeout has not been exercised on a physical
Blue.

## Device budget and image identity

Clean builds from two source copies against separately patched copies of the
pinned Blue SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
and patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`
produced identical Wallet 0.3.36 bytes. `.text` is 48,896 bytes, `.data`
is zero, and `.bss` is 5,120 bytes, including the 2,048-byte stack reserve.
The Blue app SRAM budget is 6,144 bytes, leaving 1,024 bytes after `.bss`.
The largest modeled payment upload path uses 1,120 bytes plus the required
512-byte margin; the signing public-hash path uses 1,080 bytes. BOLOS frames
are excluded from those stack measurements.

The `.text` SHA-256 is
`2697dd041804b927d70a18d2c575197bf1170d7d85692cad4facc70f862f769e`.
The Intel HEX SHA-256 is
`d00a18c2f24ffd9704000fc1fb6c3a329997cc2e4fceae96b8dd78d0f1d898e9`.
The installer does not admit this image, and it has not run on a physical
Blue.

## Local verification

Release passed 60/60 tests in 32.58 seconds. Sanitized Debug passed 60/60 in
34.18 seconds with LeakSanitizer disabled for this runner's ptrace
environment; address and undefined-behavior sanitizers remained enabled.
All 33 fast lint gates passed. The 554-file and 80-section core seal passed,
the complexity gate scanned 63,522 functions at its unchanged cap of 15,
and both Markdown gates passed with zero new inline-path failures across
556 documents. No consensus-core source changed.
