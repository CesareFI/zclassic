<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue shielded upload isolation

Date: 2026-09-28T12:12:46Z (2026-09-28T08:12:46-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can a shielded review read transaction bytes from storage that its replay or
APDU controller modifies during the same six-pass upload?

## Method

The replay rejects feed bytes overlapping its state, selected spend `rk`, or
selected output capture before parsing or hashing. On rejection it erases
the replay and both provisional captures. The APDU and screen controllers
reject request, reply, or reply-length buffers overlapping their state.
Request and reply may share the Blue's APDU buffer. Rejected commands and
failed screen formatting erase the review and up to 76 bytes of reply
storage, the largest defined response.

Host tests inject valid-looking header bytes from each replay-owned buffer,
including a two-byte span across captured fields. APDU tests place request,
reply, and an aligned reply-length pointer inside controller state. The
screen test forces a formatting failure after a successful feed. They check
rejection, erasure, and a fresh valid replay. Existing tests keep the
in-place APDU request/reply path and the consensus Sapling fixture covered.

The read-only Shielded Review build now requires the pinned Blue SDK revision
and reviewed patch. It rejects staged or untracked SDK files, initialized
`.data`, static `.bss` above 5,120 bytes, and modeled stack paths leaving
less than 512 bytes of its 2,048-byte reserve.

Commands from the repository root:

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-sdk-repro-20260927 \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

## Result and limit

The complete CMake suite passed 57/57 tests in Release (42.06 seconds) and
57/57 in AddressSanitizer and UndefinedBehaviorSanitizer Debug (19.31 seconds).
Leak detection was disabled for this ptrace-constrained runner. The unchanged
cyclomatic-complexity gate passed at cap 15. The sealed consensus-core check
passed all 554 files and 80 sections. The pinned SDK build rejected an
unrelated Git checkout as the SDK. The linked image has 32,512 bytes of
`.text`, zero `.data`, and 4,320 bytes of `.bss`, including its 2,048-byte
stack reservation. The largest modeled stack path uses 832 bytes of the
1,536-byte budget. The `.text` SHA-256 is
`3cdebe1b1ba684f237f9d2f2ee33327e2f703da4daf51320bb2d74ad6e6baa35`;
the Intel HEX SHA-256 is
`6079c0055c91d3b0634566fc319ff586476a296954b7d84217afa6e3a6dcab70`.

A separate source checkout at `80479fe9841dd12b41a3f51a9b75021314a6cdb5`
and separate SDK copy at `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
with reviewed patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`
rebuilt the image. Binary comparison of extracted `.text` sections passed;
the second Intel HEX has the same SHA-256. The independent build passed the
same stack-path gate, including the 832-byte finish path.

## Shared APDU fuzz regression

The sanitized APDU fuzzer now sends its complete valid six-pass fixture
through one shared request/reply buffer. Random commands also choose shared
or separate buffers and vary the declared reply capacity from 0 to 78 bytes.
It checks that rejected replies are erased within capacity, that bytes past
capacity retain their original request value when buffers are shared, and
that bytes outside both request and reply remain unchanged. It also checks
transaction erasure and screen reset after rejection.

The earlier harness change completed 100,000 generated inputs in 120 seconds
without a sanitizer finding. The final harness, which adds the
past-capacity assertion and valid shared-buffer seed, completed 10,000
generated inputs in 155 seconds without a sanitizer finding. After splitting
the oracle into smaller functions to meet the unchanged complexity cap of
15, the final harness completed another 10,000 inputs in 267 seconds without
a sanitizer finding. The fixed complete-transaction seed passed separately
on the final harness. All campaigns used Clang
22.1.6 with AddressSanitizer and UndefinedBehaviorSanitizer; LeakSanitizer
was disabled for this runner. The final command was:

```sh
ASAN_OPTIONS=detect_leaks=0 \
  /tmp/z23-blue-shielded-fuzz-20260928/fuzz-blue-shielded-review-apdu \
  -runs=10000 -max_len=4096 -timeout=15 \
  -artifact_prefix=/tmp/z23-blue-shielded-final-artifact-
```

This extends the host test oracle; it does not alter the device image or
prove USB timing and physical display behavior.

This tests memory separation and failure erasure in host code and measures
the pinned SDK image. The hash context remains caller-owned; the replay API
requires it to be disjoint from upload bytes and mutable review storage.
The read-only app is not installed on a Blue, and it cannot establish
shielded recipients, memo ownership, fee, proof validity, or signing authority.
