<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue Wallet 0.3.6 Cortex-M3 startup test

Local time: 2026-09-27T22:43:37-04:00.
UTC: 2026-09-28T02:43:37Z.

An ARM GCC 16.2.0 C23 test image now compiles the Wallet's `main.c`, receive
layout, APDU protocol, Base58, and Z23 SHA-256 and RIPEMD-160 code. QEMU's
Cortex-M3 MPS2 board gives the test 6 KiB of RAM and a 2 KiB reserved stack.
The test supplies deterministic BOLOS BIP32 and EC results. It executes
startup, checks the 35-character receive address and its three displayed
lines, receives exact identity and compressed-public-key replies, triggers
the displayed EXIT callback, and checks exception cleanup and erased boot
key workspace.

The final stack watermark was `0x03d0`, or 976 bytes, on that route. The
test linker reported 1,360 bytes of `.data` and 1,256 bytes of `.bss`;
these include test and C library state and are not the Wallet app's BOLOS
allocation. The same linker script still passed the existing Sapling
arithmetic Cortex-M3 test after its exception-table boundary symbols were
added. Both QEMU tests completed with exit status zero and their expected
pass markers. The full Ledger build passed 52/52 CTests: 50 host tests in a
Clang Debug build with ASan/UBSan enabled and two ARM QEMU tests. The rebuilt
final ARM harness passed its focused QEMU test.
The staged cyclomatic selftest and repository gate passed at cap 15, scanning
63,071 functions in 4,543 files with 4,112 exact baseline pins.

The test does not emulate BOLOS, its real BIP32 or EC operations, its USB
state machine, its touchscreen, or the device app's linker layout. The fake
public points test control flow and address formatting; they do not prove a
real wallet address. The measured stack route covers startup, two read-only
APDUs, and EXIT, not payment upload or signing. Wallet 0.3.6 remains blocked
from physical installation.
