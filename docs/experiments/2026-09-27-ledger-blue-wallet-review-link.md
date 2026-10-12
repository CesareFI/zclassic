<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Linked Blue Wallet read-only review candidate

Local time: 2026-09-27T01:45:39-04:00

UTC: 2026-09-27T05:45:39Z

## Question

Can the Wallet retain its fixed-path transparent receive function while
linking an output-by-output, read-only ZCL transaction review within the
Blue's app SRAM and stack limits, using reproducible C23 build inputs?

## Method and evidence

Wallet 0.2.1 links the bounded unsigned v4 parser, three-pass ZIP-243 replay,
payment APDU state machine, output formatter, and BAGL touch screens. USB
commands can begin, feed, advance passes, finish, cancel, and query a review.
The sole acknowledgement call is in the touchscreen CONTINUE callback. Each
output screen shows its exact amount, all 35 mainnet address characters,
position, type, DRAFT; NO SIGNING, CONTINUE, and EXIT. A nonpayment APDU
aborts an active review before the receive command runs. The host accepts
both the pinned v8 receive-only and new v9 receive/review app identities.

The build used Clang 22.1.6 and ARM GCC 16.2.0 on AMD Ryzen 7 PRO 8840U.
The SDK base revision is `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`.
The repository SDK patch has SHA-256
`ada31b494c9a58dd74536cc90ab90eee81e5b26790a886aad7aaa8bad289e8c3`.
That patch sets the linker stack reserve to 2,048 bytes and contains the
reviewed C23 and USB transport adaptations. A fresh SDK worktree at the
base revision accepted the patch and produced the same SDK diff hash as the
original patched checkout. Clean builds against both SDK directories
produced identical 24,832-byte `.text` images with SHA-256
`97db7a9ab725b03fd55365a057a552488f88f106ab8cd957bbda0faad1875113`.
The installer accepts that hash and rejects a one-byte changed image before
opening USB. No install occurred during this experiment.
Wallet 0.2.1 identifies the USB-interruption build in app metadata. The SDK
uses `APPVERSION` in its load parameters, outside the extracted `.text`
image; correcting that version did not change the image hash. The earlier
0.2.0 image remains pinned separately.

The linked ELF has zero `.data` and 4,236 bytes of `.bss`. The SDK app SRAM
region is 6,144 bytes; `.bss` includes the 2,048-byte linker stack reserve.
The image leaves 1,908 bytes after `.bss`, above its 512-byte headroom guard.
The named C stack-path gate sums 608 bytes for output upload, 648 for screen
formatting, 632 for replay finish, 472 for pass advance, and 80 for touch,
all within the 2,048-byte reserve with a 512-byte margin. These path sums
exclude BOLOS firmware frames. Clang Debug address/undefined-behavior and
GCC Release host suites each passed 22/22 tests. The payment test includes
10,000 deterministic malformed/interleaved APDUs and a simulated USB abort.
The SDK forwards reset and suspend events to the app while no APDU is active;
the app aborts any visible review and displays the receive screen. The
compiled ARM event path and reproducible image are verified, but USB reset
and suspend behavior has not been observed on the physical Blue.
The cyclomatic gate passed at cap 15. The host 320 × 480 dark preview was
visually checked with the linked app's dark colors and CONTINUE/EXIT layout.

## Physical follow-up

Local time: 2026-09-27T02:06:09-04:00

UTC: 2026-09-27T06:06:09Z

The subsequent signed install command was accepted by the dedicated Blue,
and a CA-authenticated app catalog query listed ZCL Wallet. The owner then
opened ZCL Wallet, observed a steady receive screen, and confirmed EXIT
returned home. A read-only app-info query returned ZCL Wallet 0.2.1 and a
receive-address query returned `t1RAmKL4KFauUXGswvMvk66aS5UL33ck1Uz`.
The owner confirmed that all 35 characters match the Blue screen.

## Limits

Host APDU tests and SDK linking do not prove review USB timing, output touch
behavior, screen pixels, or recovery after interrupted USB. The local Blue
Speculos checkout supports SDK 1.5 and blue-2.2.5, not this app's Blue 2.1.x
SDK; it cannot be used as exact firmware evidence. The device does not
authenticate a prevout's chain status, fee, change, account, or active
consensus branch. The final replay digest is discarded. No payment signing
or Sapling spend command exists. Physical testing must confirm this exact
image hash before any claim of device readiness.
