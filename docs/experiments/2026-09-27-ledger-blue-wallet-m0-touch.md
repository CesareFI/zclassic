<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue Wallet Cortex-M0 EXIT packet test

Local time: 2026-09-27T23:20:22-04:00.
UTC: 2026-09-28T03:20:22Z.

The ARM startup harness previously ran on a Cortex-M3 board and treated any
finger packet as an EXIT tap. It now decodes the finger-release coordinates,
checks the displayed touchable element's bounds, and invokes the callback
only for a hit. During
the Wallet's APDU receive wait, the harness first releases at `(0, 0)` and
checks that the app has not exited. It then releases at the center of the
displayed EXIT button and checks that the app exits. It also requires the
hit element to be labeled `EXIT`.

ARM GCC 16.2.0 compiled the C23 harness for Cortex-M0, matching the Blue
SDK's `-mcpu=cortex-m0` target and the ST31G480's SC000 core. QEMU 11.0.1
ran it on `microbit`; `blue-wallet-m0-qemu` passed and reported a 992-byte
stack watermark for startup, two read-only APDUs, and EXIT. The test uses the real
Wallet `main.c`, address protocol, Base58, and Z23 SHA-256 and RIPEMD-160
source. Its BOLOS calls, touch forwarding, BIP32 derivation, and EC point
generation are deterministic test shims. The pass does not establish that
the linked Wallet image boots or that the physical Blue touchscreen works.
The Wallet image remains blocked from installation.

The complete Clang Debug suite, including the Cortex-M0 test and the separate
Sapling arithmetic Cortex-M3 test, passed 52/52 cases with host ASan/UBSan.
The staged C23 complexity gate passed 63,077 functions at cap 15.

## USB interruption after a visible payment reply

Local time: 2026-09-27T23:29:40-04:00.
UTC: 2026-09-28T03:29:40Z.

The Cortex-M0 harness now scripts two payment-begin APDUs after the read-only
receive commands. For each request it checks the one-reply `9000` status and
the subsequent payment-screen transition. It injects a USB reset after the
first visible reply and a USB suspend after the second. Both events must abort
the pending payment and restore the receive screen before the outside touch
and EXIT packets. The test uses the real Wallet startup, APDU loop, USB event
handler, and receive screen. The payment handler and display remain explicit
test stubs, so this result does not qualify the transaction parser, signing
flow, linked BOLOS image, or physical USB behavior.

ARM GCC 16.2.0 and QEMU 11.0.1 on an AMD Ryzen 7 PRO 8840U produced `M0
WALLET PASS` with a 992-byte stack watermark. The complete Clang Debug CTest
suite passed 52/52 cases. The Wallet image remains blocked from installation.
