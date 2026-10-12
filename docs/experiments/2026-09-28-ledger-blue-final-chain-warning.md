<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue final signing chain warning

Date: 2026-09-28T18:18:55-04:00; UTC: 2026-09-28T22:18:55+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with its pinned
C23 patch.

The Blue checks that the host's branch ID is among known mainnet branch IDs.
It does not verify a live chain tip. The fee and totals screens warned
CHAIN UNCHECKED, but the final SIGN ZCL screen showed only the branch ID.
An assertion requiring the warning on the final screen failed on the prior
image. Version 0.3.33 shows the warning in the 22-pixel font under a smaller
FINAL PAYMENT CHECK heading. It keeps both payment amount categories, fee,
input path, branch ID, expiry height, lock time, HOST MAY BROADCAST text,
and separate SIGN ZCL and NO SIGN touch targets.

The 320 × 480 final-screen PNG was inspected. The title and warning do not
clip or overlap. The decoded RGB SHA-256 is
`1c8f0e3a5202fdc66e37d86967e256cd480703dcabb1fdd04841b26b7ee3e9fb`.
The UI test pins these pixels and asserts all final-screen facts. Release
passed 59/59 tests. AddressSanitizer and UndefinedBehaviorSanitizer Debug
passed 59/59 with `ASAN_OPTIONS=detect_leaks=0`.

The pinned C23 ARM image passed the static RAM and modeled stack gates.
`.text` is 48,640 bytes, `.data` is zero, and `.bss` is 5,120 bytes,
including the 2,048-byte stack reserve. The largest modeled app path is
1,112 bytes, leaving the required 512-byte margin; BOLOS frames are outside
this model. The `.text` SHA-256 is
`d8fffe2ffff7594c4696c365120afa25f40ca540f76a430f581ca64984c7d9cc`;
Intel HEX SHA-256 is
`4ae6b754a8e01204fd45f96a19f1f316535c1c4183d66e055d04b142e05799f0`.
A separate source copy from `git archive` with the two modified device
files and a separate pinned SDK copy produced byte-identical `.text` and
Intel HEX bytes.

```sh
make -B -C apps/zcl-ledger/device-blue-wallet \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

The image has not run on a physical Blue. This warning does not turn the
device into a chain verifier and does not authorize physical installation.
The Wallet install block remains after version 0.3.4 froze on opening.
