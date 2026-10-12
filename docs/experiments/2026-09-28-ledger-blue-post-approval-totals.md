<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue totals after transparent approval

Date: 2026-09-29T03:31:33Z (2026-09-28T23:31:33-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compiler: Clang 22.1.6.

## Question

If the Blue's internal payment totals change after the owner taps SIGN ZCL,
will a later signing APDU still consume the reviewed input digest?

## Reproduction and correction

The new test approves a one-input review, then separately changes the input
total, output total, fee, or own-output total. Against the previous source,
the first changed-total case returned a signature instead of `6985`; the
test failed. The test also signs the first input of a two-input review,
changes the fee, and requests the second signature. The corrected code
rechecks `own_output <= output`, `input >= output`, and
`fee == input - output` before each digest is taken. Each changed-total
signing command now returns `6985` without another signer call, zeroes its
reply, and erases the review state. The existing approval-time check uses
the same helper, so the two decisions cannot diverge on these totals.

The external host cannot directly write this app state through the defined
APDU protocol. The test covers internal state corruption or unexpected
interleaving between approval and signing; it does not establish a reachable
remote exploit. Other approval facts, including account ownership and
current-chain validity, retain their separate checks and limits.

## Device budget and image identity

Clean C23 ARM builds from a source snapshot and two separate SDK copies at
revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, each carrying the
reviewed patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`,
produced identical Wallet 0.3.35 bytes. `.text` is 48,896 bytes, `.data`
is zero, and `.bss` is 5,120 bytes, including the 2,048-byte stack reserve.
Of the 6,144-byte Blue app SRAM budget, 1,024 bytes remain after `.bss`.
The largest modeled payment upload path is 1,120 bytes, plus the required
512-byte margin, below the 2,048-byte reserve. The largest modeled signing
subpath is the public-hash path at 1,080 bytes. BOLOS frames are excluded.

The `.text` SHA-256 is
`9a36ffba3476445777541db37630a98b4211ae8d27324c17841b837c9c845767`.
The Intel HEX SHA-256 is
`d570ee8d22b410882e723a0032ed5b6e31eff8973d7d7d0a930f2edbe9498d49`.
Both builds match each value. The prior Wallet 0.3.34 `.text` size recorded
in the device README was 48,640 bytes, so this build is 256 bytes larger.
The image is not installer-whitelisted or physically tested.

## Local verification

The focused signing test passed in Release and sanitized Debug after the
correction. The final Release suite passed 60/60 in 135.10 seconds under
shared-host load. The final sanitized Debug suite passed 60/60 in 103.64
seconds with LeakSanitizer disabled for this runner's ptrace environment;
address and undefined-behavior sanitizers remained enabled. Repository-gate
results: all 33 fast lint gates passed, the complexity gate scanned 63,517
functions at the unchanged cap of 15, the 554-file and 80-section core seal
passed, and both Markdown gates passed with zero new inline-path failures
across 554 documents. No consensus-core source changed.
