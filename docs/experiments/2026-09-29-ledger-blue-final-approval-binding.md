<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue final approval binding

## Question

Can a final SIGN ZCL tap approve payment facts that differ from the Blue's
final screen while the payment state still passes its internal total checks?

## Experiment

The device UI test first drew a one-input final payment screen with a
1.00000000 ZCL fee. It then increased both the input total and fee by
1.00000000 ZCL, preserving `fee = inputs - outputs`, and tapped SIGN ZCL.
Before the correction, the callback approved the changed payment and the
test failed at its abort assertion. The callback now derives the amount to
others, amount matching the device keys, fee, input path label, branch ID,
lock time, and expiry height from current payment state and compares those
values to the text shown on the final page before granting approval.
The final page also copies those facts into its unused address slot during
rendering and checks that copy at SIGN ZCL. It uses existing payment memory,
so the app's static RAM allocation does not grow.

The passing regression injects six changes after display: coordinated
input and fee totals, the amount matching the device keys, branch ID, lock
time, expiry height, and a coordinated change to both fee state and the
label's text buffer. Each SIGN ZCL tap aborts, erases review state, and
produces no signature. The coordinated text-buffer case was accepted by the
first correction before the displayed-facts snapshot was added. Normal
signing remains covered by the device UI and
integrated app-loop tests. These injections model internal state faults;
they do not establish that a USB host can modify that state directly.

The stack checker previously required the NO SIGN callback but did not
measure SIGN ZCL. It now requires the approval callback frame and includes
it in a modeled path. Removing that frame from a copy of the compiler's
stack-usage file makes the checker fail with
`Missing stack frame: approve_sign`.

## Reproduction and results

Run from the repository root with Clang 22.1.6 on an AMD Ryzen 7 PRO 8840U,
2026-09-29T02:29:14-04:00 (2026-09-29T06:29:14+00:00):

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug --output-on-failure
ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH=/tmp/z23-blue-wag-scratch make lint-fast check-core-seal check-cyclomatic-complexity check-markdown-links check-doc-inline-paths
```

Release and sanitized Debug each passed 60/60 tests. Two clean builds
against separately patched copies of pinned Blue SDK
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` matched byte for byte:

| Measure | Result |
| --- | ---: |
| `.text` | 51,712 bytes |
| `.data` | 0 bytes |
| `.bss`, including reserved stack | 5,120 bytes |
| Modeled approval touch path | 872 bytes |
| Stack reservation | 2,048 bytes |
| Required free margin within reservation | 512 bytes |
| `.text` SHA-256 | `6b4eed2f4c8c2f61206de3e269c26c9eb6ee00a4939200768694f27c761dc94b` |
| Intel HEX SHA-256 | `23d9d029473dc8faf4b656cfc2023696e1f2b21e82c76b92821bfb882cf593b8` |

The stack model excludes BOLOS frames. The image has not been tested on a
physical Blue and is not installer-whitelisted. The test does not establish
end-to-end shielded signing, Sapling proof generation, or a verified chain
tip. The final page explicitly labels the chain and owner as unverified.
