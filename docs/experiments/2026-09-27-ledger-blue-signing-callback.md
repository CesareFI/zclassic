<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue fixed-path signing callback

Local time: 2026-09-27T05:51:37-04:00

UTC: 2026-09-27T09:51:37Z

## Question

Can a C23 callback for the Ledger Blue derive only the two supported ZCL
transparent keys, sign a supplied digest through the Blue SDK, and erase its
private buffers without enabling transaction signing over USB?

## Result

The callback selects only `m/44'/147'/0'/0/0` or `m/44'/147'/0'/1/0` after
PIN validation. It clears signature and public-key outputs before rejecting
invalid input, initializes the SDK private key from the device-derived scalar,
clears the raw scalar and chain code, derives the compressed public key, calls
RFC6979 secp256k1 ECDSA on the 32-byte digest, and erases static private and
public material on normal return. App command, USB interruption, exit, and
outer exception cleanup paths also erase that material.

A C23 host SDK shim passed fixed-path, PIN, invalid-path, keypair-failure,
malformed-public-key, signer-failure, oversized-signature, output-clearing,
and state-erasure tests. Clang 22.1.6 Debug
with AddressSanitizer and UndefinedBehaviorSanitizer and GCC 16.1.1 Release
each passed 30/30 local tests. Two independently patched Blue SDK trees at
revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` built with Clang
22.1.6 and ARM GCC 16.2.0 and produced identical `.text` SHA-256
`067744e45fbad645850dd7a8cf8cdfb1f1b4b8ede585d4c57c61fa5f962788b7`.
The linked app has 33,792 bytes of `.text`, 5,472 bytes of `.bss`, and no
`.data`; 672 bytes remain after `.bss` in the 6,144-byte app SRAM region.
The read-only stack gate's largest named C path is 752 bytes against a
2,048-byte reserve and a 512-byte margin. CPU: AMD Ryzen 7 PRO 8840U with
Radeon 780M Graphics. Test date: 2026-09-27.

## Limit

The SDK callback compiles for ARM but is not linked into the app because
there is no signing APDU caller. Its 120-byte standalone frame is not an
active signing stack measurement. The linked image contains only the cleanup
function and its private buffer. The SDK shim cannot prove the device's
derive or ECDSA syscalls behave correctly. Before signing is enabled, the
callback must be wired only to the confirmed-digest boundary, the returned
signature must be independently verified, active signing stack use must be
measured, and physical USB, touchscreen, EXIT, and recovery tests must pass.
