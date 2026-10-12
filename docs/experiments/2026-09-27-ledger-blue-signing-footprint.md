<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue signing footprint

Local time: 2026-09-27T06:06:28-04:00

UTC: 2026-09-27T10:06:28Z

## Question

Do the compiled transparent signing boundary and Blue SDK signer fit the
device image and app stack budgets before a signing APDU is introduced?

## Method

The ordinary read-only Wallet 0.2.14 image was compared with a build that
appended `-Wl,-u,blue_wallet_sign_digest` and
`-Wl,-u,blue_payment_sign_command` to the SDK's existing linker flags. The
forced symbols make the strict command parser, signer, and dependencies
appear in the ELF without creating a USB command. The build ran
`check-image` and `check-stack`
against two independently patched Blue SDK trees at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`.

The C23 stack checker now requires the compiled frame data for the signing
command parser, signing boundary, digest extraction, DER normalization, and
public-key hash. It adds each possible callee to the current `answer_command` →
`wallet_payment_command` → `blue_payment_sign_command` →
`blue_payment_sign_next` prefix. A negative check replaced the measured
signer frame of 112 bytes with 1,600 bytes in
a temporary copy of its `.su` file; the gate had to refuse the image.

## Result

The ordinary image has 33,792 bytes of `.text`, 5,472 bytes of `.bss`, and
zero `.data`. The forced-link image has 37,376 bytes of `.text`, 5,472 bytes
of `.bss`, and zero `.data`. Its `.text` SHA-256 is
`49c132761a7aecd7838470774e2ba942338d6bbc07414b3a8c9b8abeb0e059ab`
in both SDK builds. The four candidate named C paths sum to 688 bytes
(device signer), 600 bytes (digest extraction), 672 bytes (DER), and 728
bytes (public hash). The existing read-only maximum is 752 bytes. The
reserve is 2,048 bytes, and the gate retains a 512-byte margin. With the
temporary 1,600-byte signer frame, its candidate path became 2,176 bytes
and the gate rejected it.

The candidate CLA `A5` / INS `29` parser requires an exact six-byte APDU
with one input index. A host test passes an OpenSSL secp256k1 signature
through the parser with the APDU and reply sharing a buffer, then verifies
the signature independently. Unapproved review state, every other input index,
wrong CLA/INS/P1/P2/Lc, short and long frames, and insufficient reply
capacity return no signature and abort the review. A deterministic 10,000
malformed-frame sequence ran under Clang AddressSanitizer and
UndefinedBehaviorSanitizer. Clang 22.1.6 Debug and GCC 16.1.1 Release each
passed 30/30 local tests.

Compiler: Clang 22.1.6 for ARM app C, ARM GCC 16.2.0 for linking, and
Clang 22.1.6 for the C23 stack checker. CPU: AMD Ryzen 7 PRO 8840U with
Radeon 780M Graphics. Test date: 2026-09-27.

## Limit

The forced-link build is a size experiment, not an installable payment
signer. The callback is unreachable over USB. These stack sums exclude
BOLOS syscall and event-handler frames, and the current wallet command
frame may change when signing dispatch is connected. Physical device signing
and signature verification, active-path stack use, interruption recovery,
and chain-backed input status remain untested.
