<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue APDU tail erasure

Date: 2026-09-29T07:05:55-04:00 (2026-09-29T11:05:55Z).

## Question

Does the device loop leave request bytes in the two APDU buffer positions
reserved for a status word after a successful response?

## Method and result

The shared Review device loop calls its protocol controller with a
258-byte response capacity in a 260-byte APDU buffer. The controller
clears unused bytes within that capacity. The device loop now clears from
the response length to the end of the full buffer before appending the
two-byte status word. Its host device-loop test poisons the last two bytes
of each synthetic shielded review and fault request, then verifies that
every transmitted response leaves all bytes beyond the response zero.
This covers complete six-pass review, cancellation, malformed upload,
USB reconnect, and a reset during final redraw through the C23 BOLOS shim.
It does not establish behavior on a physical Blue.

The updated read-only image is version 0.5.11. Two clean builds using
separate copies of the pinned `blue-r21.1` SDK at commit
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, each with SDK patch
SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`,
produced the same 34,048-byte `.text` SHA-256
`671d323a0d9720bdd79af3cbb53166481da04952d7101917ced5192dba1fa4ff`
and Intel HEX SHA-256
`9434836d43c109bcc7d42ef7af2046f59239e34cadba7ce656d538be6b61e384`.
The image has zero `.data` and 4,360 bytes of `.bss`; its largest modeled
stack path is 888/1,536 bytes. The model excludes BOLOS frames.

Release passed 62/62 tests in 32.02 seconds; address- and
undefined-behavior-sanitized Debug passed 62/62 in 35.86 seconds with leak
detection disabled for this traced environment. The 33 fast lint gates,
554-file/80-section consensus-core seal, cyclomatic cap 15, 585-document
Markdown link check, and inline-path check passed. The offline installer
reported `ZCL Shielded Review 0.5.11`, no signing path, and installation
blocked pending physical validation.

Build toolchain: Clang 22.1.6, ARM GCC 16.2.0. Host CPU: AMD Ryzen 7 PRO
8840U with Radeon 780M Graphics. The image is pinned for offline
recognition; installation remains disabled pending physical validation.
