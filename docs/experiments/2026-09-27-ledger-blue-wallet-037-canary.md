<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue Wallet 0.3.7 SDK stack canary

Local time: 2026-09-27T22:54:22-04:00.
UTC: 2026-09-28T02:54:22Z.

Wallet 0.3.7 enables the pinned Blue SDK's
`HAVE_BOLOS_APP_STACK_CANARY` option. Its `io_seproxyhal_init` writes
`0xdead0031` to `app_stack_canary`; `io_exchange` checks that value before
handling an APDU and invokes the SDK's secure-element reset path on mismatch.
The Wallet source now refuses to compile without the flag. A C23 Clang
syntax check without it failed at that requirement; the same check with the
flag passed. The linked ARM disassembly contains the marker write and the
comparison at the start of `io_exchange`. The linker places the canary at
`0x200023fc`, four bytes below `_stack` at `0x20002400`.

Two clean ARM GCC 16.2.0 builds from separate checkouts of Blue SDK commit
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, each with the reviewed
C23 patch, produced byte-identical 41,216-byte `.text` images with SHA-256
`64839dd399415af205fcf0c02a9ca4f5283c45d0e6103df3747759847c4bc0fd`.
The image has zero `.data` and 5,120 bytes of `.bss`, including the 2,048-byte
reserved stack. The stricter named-frame check still passes with a maximum
1,056-byte payment path and a required 512-byte margin. The version change
does not alter the APDU protocol or authorize a new signing route.

The C23 installer rejected the exact candidate image hash before opening a
nonexistent HID path. The canary is checked at `io_exchange`, so corruption
between checks or a fault that prevents reaching the next exchange may remain
undetected. The ARM image has not run under BOLOS or on the physical Blue;
Wallet 0.3.7 remains an offline candidate and is absent from the installer's
allowlist.

The complete Ledger CTest suite passed 52/52 in Clang Debug with host
ASan/UBSan and two ARM QEMU cases. The focused Wallet startup shell also
passed under GCC 16.1.1 Release after the compile-time flag requirement was
added. The QEMU shell does not execute the SDK canary code.
The staged C23 cyclomatic selftest passed; the repository gate accepted
63,071 functions in 4,543 files at cap 15 with 4,112 exact baseline pins.
