<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue output screen binding

## Question

Does a CONTINUE tap acknowledge exactly the transparent output that the Blue
displayed, including its amount, address, index, and account relation?

## Experiment

The host device UI test displays a 1.23456789 ZCL P2PKH output, changes the
pending output amount to 2.23456789 ZCL after the screen has been drawn, and
taps CONTINUE. Before the correction, the callback accepted the changed
amount and the test failed at its abort assertion. After the correction, the
callback recomputes the screen from the pending parser output and device
account hashes, compares every screen byte, and aborts on mismatch. The test
uses Z23's SHA-256 implementation for the Blue SDK hash shim.

The production comparison covers the displayed title, amount, complete
address and its three lines, and the device-derived account label. It occurs
before `blue_payment_apdu_touch_continue` updates owned output totals. The
test injects an internal state fault; normal APDU uploads are already blocked
while an output is pending. This is a defense against stale or corrupted
review state, not evidence that a USB host can cause that state change.

## Reproduction and results

Run from the repository root with Clang 22.1.6 on an AMD Ryzen 7 PRO 8840U,
2026-09-29T02:16:00-04:00 (2026-09-29T06:16:00+00:00):

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug --output-on-failure
ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH=/tmp/z23-blue-wag-scratch make lint-fast check-core-seal check-cyclomatic-complexity check-markdown-links check-doc-inline-paths
```

Both test suites passed 60/60. The first concurrent run timed out one QEMU
case under host load. That case passed alone, and the complete Release and
Debug suites passed when run separately. Fast lint passed 33 gates. The core
seal matched 554 files and 80 sections. Complexity stayed at cap 15. The
Markdown link and inline path gates passed before this experiment was added;
they were rerun after it was added.

Two clean builds against separately patched copies of pinned Blue SDK
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` matched byte for byte:

| Measure | Result |
| --- | ---: |
| `.text` | 50,176 bytes |
| `.data` | 0 bytes |
| `.bss`, including reserved stack | 5,120 bytes |
| Modeled output touch path | 888 bytes |
| Stack reservation | 2,048 bytes |
| Required free margin within reservation | 512 bytes |
| `.text` SHA-256 | `a299fb189939f0ca06b3aaf29bcd3fadb0f1f21df69f283f84fa798b70f0381e` |
| Intel HEX SHA-256 | `52c8e5869bbdd6de72e3793a30f95d9a2c414adfc8f94c3ad0f32111829ff80b` |

The stack model excludes BOLOS frames. No physical Blue was available to
test this image, and it is not installer-whitelisted. Transaction signing,
Sapling proof generation, and shielded signing are not established by this
screen-binding test.
