<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shielded Review USB generation and stale reply

## Intent

Prevent a completed read-only review from returning a success reply after
USB reset or suspend erases its on-screen and in-memory state.

## Reproduction and correction

The host test runs the C23 Blue device APDU loop with the project's BLAKE2b
implementation. It streams the complete synthetic six-pass Sapling wire,
then injects a USB reset or suspend from the BAGL display callback on the
final summary redraw. Before correction, the reset case failed because the
loop attempted to
transmit the old `9000` reply after reset. The corrected loop increments a
USB generation on reset or suspend, compares it with the generation at the
start of each APDU iteration, erases a superseded result, and receives a new
request without sending the old reply. The test checks that review state,
hash workspace, and shared APDU buffer are erased and that the screen returns
to `CONNECT Z23`.

An existing two-review reconnect test was updated so a reset during receive
discards the interrupted APDU and sends a fresh begin request. The completed
result still matches a separate ZIP-243 digest computation. The app remains
read-only, with no key or signing authority.

## Build evidence

The pinned Blue SDK revision is `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
with reviewed C23 patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Two isolated source and SDK builds of 0.5.9 produced identical Intel HEX
SHA-256
`8c796353659ae4582bae5e5dea5fe336ab6dacd28df032048c8ee3687a798ad8`
and `.text` SHA-256
`c2471f696f92cbc50853d0efdbff41253a110090227b734d1f33e04ced42245a`.
The image has 33,536 bytes of `.text`, zero `.data`, 4,328 bytes of `.bss`,
and a largest modeled stack path of 856/1,536 bytes. The
`zcl-blue-install --image-check` command recognized the pinned `.text`
binary as Shielded Review 0.5.9 with no declared signing path and
installation blocked pending physical validation.
Release and sanitized Debug each passed 62/62 tests. All 33 fast lint gates,
the 554-file/80-section consensus-core seal, inline documentation paths,
bound documentation claims, and local Markdown links passed.

The host BOLOS shim and cross-compiled image do not establish physical Blue
USB timing, touch response, or recovery behavior. No device was exposed to
this environment, so no 0.5.9 installation was attempted.
