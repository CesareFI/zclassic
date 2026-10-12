<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue private-key initialization result

Date: 2026-09-28T16:37:01-04:00; UTC: 2026-09-28T20:37:01+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with its pinned
C23 patch.

The SDK's `cx_ecfp_init_private_key` syscall returns an integer. The wallet
previously ignored it and checked only the output structure's curve and
key length. Fault-injection stubs returned `-1` while filling those fields
with plausible values. Before the correction, the signer test produced a
signature and the startup test displayed a receive address. After the
correction, both tests reject the negative result, clear key material,
and do not expose a signature or address. A nonnegative result still
requires the existing curve and length checks. The SDK header does not
specify a unique nonnegative success value; host and ARM test stubs use
both zero and 32.

The Release suite passed 57/57; the AddressSanitizer and
UndefinedBehaviorSanitizer Debug suite passed 57/57 with
`ASAN_OPTIONS=detect_leaks=0`. The pinned C23 device image passed the
static RAM and modeled-stack gates. `.text` is 48,640 bytes, `.data` is
zero, and `.bss` is 5,120 bytes, including the 2,048-byte stack reserve.
The largest modeled app path is 1,112 bytes, leaving the required
512-byte margin. BOLOS syscall frames are outside this model. The `.text`
SHA-256 is
`7a209cd2f7cddd002f03e88e3771896d9bb439b061e3dcefcb94b929b7281659`;
the Intel HEX SHA-256 is
`199ca087bd62d4e6d336cdc287e5bd2d922ced474bd6480764e8e16932fdd7f3`.
A separate source copy and separately pinned SDK copy produced identical
`.text` and Intel HEX bytes.

```sh
make -B -C apps/zcl-ledger/device-blue-wallet \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

The Wallet candidate remains blocked from physical installation. This
result does not establish BOLOS runtime stack depth, USB behavior, or
touchscreen safety on a physical Blue.
