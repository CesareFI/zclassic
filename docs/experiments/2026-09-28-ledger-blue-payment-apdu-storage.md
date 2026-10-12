<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue payment APDU storage boundary

Date: 2026-09-28T13:54:46Z (2026-09-28T09:54:46-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can the read-only payment APDU handler accept an apparently successful
response after its reply-length write overlaps another command buffer?

## Method

A host test places an aligned `size_t` at offset eight of the reply storage
for a valid status request. Before the change, the direct handler returned
`9000`; the assertion requiring rejection failed. The fixed handler checks
request, reply, reply length, review state, and device-derived account hash
storage before its first write or dispatch. Rejected layouts abort the review
and erase safe external reply storage. Additional cases put the request or
reply inside review state, put reply length inside request bytes, and put the
reply over account hashes. They check rejection, request preservation when
reply storage is separate, and account hash preservation. A valid request
and reply sharing the external Blue APDU buffer still succeeds.

## Result and limits

The focused payment review test passed in Release and AddressSanitizer plus
UndefinedBehaviorSanitizer Debug. The complete serial Release suite passed
57/57 tests in 30.99 seconds. The sanitized Debug suite passed 57/57 tests
in 27.05 seconds with LeakSanitizer disabled for this ptrace-constrained
runner. The pinned Blue SDK build passed its image and stack gates: `.text`
is 46,592 bytes, `.data` is zero, and `.bss` is 5,120 bytes including the
2,048-byte stack reservation. The largest named payment path uses 1,064
bytes of the 1,536-byte usable stack, retaining the required 512-byte
margin. The largest signing path uses 1,056 bytes. The `.text` SHA-256 is
`fd00ff055f0a2f7f6a714d1098af5e2ba687407a9ae77eb375590a7186e0a539`;
the Intel HEX SHA-256 is
`4614155309e1128269311a9bcc14c3d8ef191fe66a7d6f9ddde1459c7834136b`.
The Clang AddressSanitizer and UndefinedBehaviorSanitizer payment APDU
fuzzer completed 100,000 inputs in 48 seconds with no finding. An earlier
run stopped after more than 90,000 inputs because LeakSanitizer cannot run
under this runner's ptrace environment; the complete run used
`ASAN_OPTIONS=detect_leaks=0`, the same setting as the Debug suite.

The Blue's real command loop supplies these pointers itself; the host cannot
choose them through APDU bytes. These direct-call tests protect that internal
contract and prevent a later caller from reporting success after buffer
corruption. The image is uninstalled and has not run on physical Blue
firmware. The stack model excludes BOLOS frames, and the test does not
establish chain provenance or shielded signing.

## Independent build

A second source checkout at signed commit
`fbb9e05dc455a92a06d630b46c961a07628ee9f9` built against a separate
copy of the pinned Blue SDK at
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`. The SDK patch SHA-256
was `4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
`cmp` found identical `.text` bytes across the two source and SDK copies;
the second Intel HEX SHA-256 also matched the value above. Both linked
images report 46,592 bytes of `.text`, zero `.data`, and 5,120 bytes of
`.bss`. The copies used the same host and ARM toolchain; byte equality does
not establish cross-toolchain reproducibility.

All 33 `make lint-fast` gates passed at the unchanged complexity cap with
the Windows guard self-test fixture rooted in writable `/tmp`. The run took
171.789 seconds on this shared host, above its 75-second soft budget. The
unchanged core seal passed for 554 files and 80 sections. Markdown links
passed for 511 documents and 939 local targets; the inline-path scan found
12 baselined and zero new issues.
