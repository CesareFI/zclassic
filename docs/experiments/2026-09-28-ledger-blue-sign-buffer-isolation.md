<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue signing buffer isolation

Date: 2026-09-28T13:31:06Z (2026-09-28T09:31:06-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can an approved transparent signing call report success after its
reply-length output overwrites bytes of the signature reply?

## Method

The host test places a real `size_t` reply-length object at offset eight
inside the same storage used for the APDU reply. It begins with a valid,
touchscreen-approved digest and calls both the direct signing function and
the signing APDU command. Before the change, the direct call returned
success and consumed approval; its length write corrupted reply bytes.

The signing boundary now rejects an output length overlapping request,
reply, review state, or owned hashes before any signer call. Request and
reply may still share the external APDU buffer. Rejection aborts the review;
it clears the external reply when that does not overwrite protected state.
Additional tests place the request or reply inside review state and place
the reply over account hashes. They require rejection before signer use and
preservation of the account hashes.

## Result and limit

The focused signing test passed in Release and AddressSanitizer plus
UndefinedBehaviorSanitizer Debug. The complete sanitized Debug CMake suite
passed 57/57 tests (107.20 seconds) with LeakSanitizer disabled for this
ptrace-constrained runner. The final serial Release suite passed 57/57
(53.60 seconds). An earlier concurrent Release run had one `BAD_COMMAND`
because a targeted build relinked the signing test executable during CTest.
A second serial run timed out in the unrelated M0 Sapling emulator after
30.29 seconds under shared-host load; that case passed alone in 14.90
seconds before the clean full run. No test or timeout gate was changed.

The pinned Blue SDK build passed its image and stack gates: `.text` is
45,568 bytes, `.data` is zero, and `.bss` is 5,120 bytes including the
2,048-byte stack reservation. Its largest named payment path uses 1,064
bytes and largest signing path uses 1,056 bytes of the 1,536-byte usable
stack budget. The `.text` SHA-256 is
`d04e9accb8c94443b20d4f81f8ac722318294c926cf094c5f4623b5bf77d3442`;
the Intel HEX SHA-256 is
`522241c3b2c6ae5eb7ef9a09ac35d9e06f90526e0fb6956632a3d6ecdaecfdeb`.

The device app passes separate stack and static-memory gates, but the
modeled paths exclude BOLOS frames. The image remains uninstalled and its
behavior on physical Blue firmware is unverified.

## Independent build and final gates

A second source checkout at signed commit
`d22b472da0beb5f8e9be125ca1e541ecf714222b` built against a separate
copy of the pinned Blue SDK at
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`. The SDK patch SHA-256 was
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
`cmp` found identical `.text` bytes across the two source and SDK copies;
the second Intel HEX SHA-256 also matched the value above. Both linked
images report 45,568 bytes of `.text`, zero `.data`, and 5,120 bytes of
`.bss`.

The final source passed all 33 `make lint-fast` gates, the unchanged core
seal (554 files, 80 sections), Markdown links (510 documents, 938 local
targets), and inline-path validation (510 documents, 12 baselined and zero
new findings). The Clang AddressSanitizer and UndefinedBehaviorSanitizer
signing fuzzer completed 100,000 generated inputs without a finding. These
tests do not establish physical-device timing, secure-element behavior, or
ZCL consensus acceptance of a transaction signed by this app.
