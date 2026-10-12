<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue review USB reset

Date: 2026-09-28T17:03:36-04:00; UTC: 2026-09-28T21:03:36+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with the
pinned C23 patch.

The previous device loop ignored USB reset and suspend events. A normal or
shielded review could remain active after a disconnect. The host SDK shell
injects both events with nonzero transaction, hash workspace, and APDU
buffers. Its initial regression failed because the display did not return
to `CONNECT Z23`. The normal Review test also found that a screen reset
alone left the transaction intact; an explicit abort corrected that path.
After the correction, both configurations erase their review state, hash
workspace, and full 260-byte APDU buffer, and show the ready screen while
preserving the text size and color theme.
The complete Release suite passed 59/59; the AddressSanitizer and
UndefinedBehaviorSanitizer Debug suite passed 59/59 with
`ASAN_OPTIONS=detect_leaks=0`.

The pinned C23 device image passes its image and stack gates. `.text` is
33,024 bytes, `.data` is zero, and `.bss` is 4,320 bytes, including the
2,048-byte stack reservation. The modeled USB reset path uses 64 bytes;
the largest modeled path remains the 824-byte finish path, within a
1,536-byte budget. BOLOS frames are outside this model. The `.text`
SHA-256 is
`0d87bbfd380c2b2c315ace66d8d60c2c9243bc15a6726c40f109dffdcabcc2af`;
the Intel HEX SHA-256 is
`b6ab943a1c803d77beb4817017cd54653e2132767cff4ec9d57cde94e645c77d`.
A separate source copy and separately pinned SDK copy produced identical
`.text` and Intel HEX bytes.

The normal Review 0.4.6 image has 33,792 bytes of `.text`, zero `.data`,
and 6,000 bytes of `.bss`, leaving 144 bytes of linker SRAM headroom. Its
modeled APDU, screen, and USB reset paths use 776, 888, and 176 bytes of
the 2,048-byte stack reservation. Its `.text` SHA-256 is
`a1eff6f4b6186b0d4be4d5fa206ab956f3aa8c3ee520e6da92596a34a6c384fc`;
Intel HEX SHA-256 is
`9cdf1782ea257efce28f4fb644feb777f8a301f16a9ce6d03adcf886fa799aa5`.
The separate source and SDK build reproduced both normal Review hashes.

```sh
make -B -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Both read-only images remain uninstalled. The host shell exercises the
device event function but cannot establish physical USB timing or
touchscreen behavior. A reset during an in-flight response needs a
separate race test before either image can be considered ready for a user.
