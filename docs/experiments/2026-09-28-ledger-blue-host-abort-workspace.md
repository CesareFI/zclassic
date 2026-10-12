<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue host abort workspace erasure

Local time: 2026-09-28T20:32:08-04:00. UTC: 2026-09-29T00:32:08Z.
Host: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics. Compiler: Clang
22.1.6. ARM linker: arm-none-eabi-gcc 16.2.0.

## Question

Does an acknowledged host payment-abort command erase the entire device
controller workspace, including temporary hash contexts, amount text, and
one-use signing approval?

## Finding

The payment APDU erased the transaction record but returned success while
the controller retained its hash contexts and display text. A new device UI
assertion failed against Wallet 0.3.33 because the final approval and timer
were also still active in the controller. Wallet 0.3.34 calls the controller
erasure path after the APDU validates and acknowledges the host abort.

The device UI test poisons both hash contexts and all amount and input-path
text, then sends the real abort command through the controller. It verifies
the temporary buffers are zero, the approval and timer are cleared, and the
ended screen is shown. The integrated app-loop test aborts after a simulated
SIGN ZCL touch, checks the full payment state against the erased
state, and confirms a later signing APDU is denied.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release --parallel 4
ctest --test-dir /tmp/z23-blue-standalone-release --output-on-failure --parallel 1
cmake --build /tmp/z23-blue-standalone-debug --parallel 4
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug --output-on-failure --parallel 1
make -C apps/zcl-ledger/device-blue-wallet \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
make check-core-seal check-cyclomatic-complexity
ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH=/tmp/z23-blue-034-wag make lint-fast
make check-markdown-links check-doc-inline-paths
```

The pinned Blue SDK revision is
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, with the reviewed C23
patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
The ARM image has 48,640 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`; the largest modeled payment upload path uses 1,120 bytes plus a
512-byte margin within the 2,048-byte stack reserve. BOLOS frames are
excluded. The `.text` SHA-256 is
`f5d365676398970e03dc30215cdd2089a300a11752e0883d4e1389eaa9d94b01`;
Intel HEX SHA-256 is
`6d52dca9a2a73857d39f6864ffe6c6defbca974059bbf213edfc0ac445bfac24`.

A clean source copy from `git archive` of parent
`2d744eb0e95ea8804e4258496ab0688f95e5e1f4` with the modified
Makefile and controller overlaid was built against a separate copy of the
pinned SDK. Its `.text` and Intel HEX bytes matched exactly. This checks
same-host, same-toolchain repeatability.

Serial Release and sanitized Debug each passed all 59 Blue CTest cases on
the final source. The consensus-core seal matched 554 files and 80 sections;
the cyclomatic complexity cap of 15 passed without a new pin.

## Limit

The host SDK shim and ARM build do not establish physical BOLOS timing or
RAM erasure on a real Blue. Wallet 0.3.34 is uninstalled after the earlier
physical startup freeze. This change does not authorize a physical install
or a live payment.
