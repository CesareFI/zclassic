<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue review exchange failure

Date: 2026-09-28T17:38:09-04:00; UTC: 2026-09-28T21:38:09+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with the
pinned C23 patch.

The previous device loop called `io_exchange` with both a pending reply
length and a request for the next APDU. If BOLOS threw while transmitting
the reply, the catch retained that length and appended a new status word
after the old reply. The fault-injection regression aborted against that
loop. The corrected loop transmits with `IO_RETURN_AFTER_TX`, clears the
pending length, then receives the next APDU. It erases the transaction,
hash workspace, and full 260-byte APDU buffer before propagating a send
or receive exception. An exception after a received command instead queues
a two-byte status response from an erased buffer.

The shared host device-loop test injects failures at both exchange calls,
a forged 261-byte receive count, and a USB reset callback during a pending
send. It checks that the subsequent receive has no pending reply length,
the transaction and APDU buffer are erased, and the oversized report cannot
reach the parser. Both normal and shielded configurations pass the focused
test. The complete Release suite passed 59/59; the AddressSanitizer and
UndefinedBehaviorSanitizer Debug suite passed 59/59 with
`ASAN_OPTIONS=detect_leaks=0`.

Normal Review 0.4.7 has 34,048 bytes of `.text`, zero `.data`, and 6,000
bytes of `.bss`, leaving 144 bytes of linker SRAM headroom. Its modeled
APDU, screen, and USB reset paths use 792, 904, and 192 bytes of its
2,048-byte stack reservation. `.text` SHA-256 is
`0d719924ca08128834d2713b6efd92a95f126fa748a458d954902a35e6f38c60`;
Intel HEX SHA-256 is
`7e78e32fe85e11887f21feec1569a02847dbcec45642ce09121b08a049f287e4`.

Shielded Review 0.5.6 has 33,280 bytes of `.text`, zero `.data`, and 4,320
bytes of `.bss`. Its largest modeled path uses 840 bytes of its 1,536-byte
stack budget; the USB reset path uses 64 bytes. `.text` SHA-256 is
`15ae381322ef88fb4bc773c2c13e6e6151bf83282bdfd3d6bf6a17c7719c84de`;
Intel HEX SHA-256 is
`a5556d24d91701abfe8c3ecb3131a12a584aa8e239cdd04c6f66563888c22eaf`.
Both Intel HEX files match byte for byte when built from a separate source
copy and separately pinned SDK copy. The stack model excludes BOLOS frames.

```sh
make -B -C apps/zcl-ledger/device-blue-review \
  BOLOS_SDK=/tmp/z23-blue-account-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
make -B -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-account-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Both images remain uninstalled. The host shell confirms app-level erasure
and control flow. It cannot prove whether the physical USB transport sends
a partial response when reset overlaps transmission; that behavior needs a
device-level timing test before either image is ready for a user.
