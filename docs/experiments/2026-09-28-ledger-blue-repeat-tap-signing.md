<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue repeated touch at final signing page

Date: 2026-09-28T18:51:59Z (2026-09-28T14:51:59-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can a repeated touch at the totals page's NEXT button also hit SIGN ZCL on
the following page before the owner has read its final facts?

## Result

The old pages placed both buttons at x=165..299 and y=386..443. The final
page now places SIGN ZCL at x=20..154 and NO SIGN at x=165..299. A device UI
test checks that NEXT and SIGN ZCL have disjoint touch rectangles, then
repeats the center touch of NEXT after the final page appears. It reaches
REVIEW COMPLETE without setting signing approval or its 30-second timer.
The normal SIGN ZCL route still reaches the signing page. The 320 × 480
simulator image was inspected and its decoded RGB pixel digest was updated to
`7a61219f22c38353221e31e984fba8106728a6d98ffcbe5ed355d8424d4a3318`.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2 --target test-blue-wallet-device-ui test-blue-wallet-integrated-loop blue-wallet-m0-qemu-image
ctest --test-dir /tmp/z23-blue-standalone-release -R '^(blue-wallet-device-ui|blue-wallet-integrated-loop|blue-wallet-m0-qemu)$' --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2 --target test-blue-wallet-device-ui test-blue-wallet-integrated-loop blue-wallet-m0-qemu-image
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -R '^(blue-wallet-device-ui|blue-wallet-integrated-loop|blue-wallet-m0-qemu)$' --output-on-failure
make -C apps/zcl-ledger/device-blue-wallet BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

The three focused tests and all 57 local tests passed in both Release and
sanitized Debug. The C23 complexity gate passed at its unchanged cap of 15.
All 33 fast lint gates passed. The Markdown gates scanned 524 documents,
with zero new inline-path findings. The consensus-core seal matched 554
files and 80 sections. Wallet
0.3.26 links 48,384 bytes of `.text`, zero `.data`, and 5,120 bytes of
`.bss`; the largest named app path uses 1,088 bytes plus a 512-byte margin
inside the 2,048-byte stack reservation. Its `.text` SHA-256 is
`9dcc85cb0e6d845e34b2e75f7c9132af73852c5f36c0483b1dc7b0702293a00c`;
Intel HEX SHA-256 is
`410bda25b689daef31e759110bf0b9d798087159bbe19cee1fab4e28b3709d63`.
A copied source tree built against a separate pinned SDK copy produced
byte-identical `.text` and Intel HEX using the same ARM toolchain.

## Limit

The simulator dispatches synthetic finger releases by geometry. It does not
model BOLOS touch debouncing or prove the actual Blue's screen timing. The
image remains uninstalled after the earlier physical startup freeze. The
installer block remains. No payment or signature ran on the physical Blue.
