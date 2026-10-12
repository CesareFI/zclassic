<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Shielded Review for Ledger Blue

Version 0.5.11 clears the unused tail of the 260-byte APDU buffer before
returning a status word. The device-loop test poisons the two reserved tail
bytes before every synthetic review and fault request, then checks that no
stale request bytes remain after the response. Two builds with separate
pinned SDK copies produced the same 34,048-byte `.text` SHA-256
`671d323a0d9720bdd79af3cbb53166481da04952d7101917ced5192dba1fa4ff`
and Intel HEX SHA-256
`9434836d43c109bcc7d42ef7af2046f59239e34cadba7ce656d538be6b61e384`.
The image has zero `.data`, 4,360 bytes of `.bss`, and a largest modeled
stack path of 888/1,536 bytes. Offline image recognition remains separate
from installation permission; this image has no physical Blue validation.
The [APDU-tail experiment](../../../docs/experiments/2026-09-29-ledger-blue-apdu-tail-erasure.md)
records the test and build inputs.

Version 0.5.10 returns and displays the SHA-256 commitment to the exact
transaction wire reviewed on the Blue. Protocol v8 returns public facts,
the ZIP-243 signing digest, and the full-wire commitment as a 108-byte
reply. Z23 independently checks all three before reporting success and
prints the commitment for comparison with the Blue's third review page.
The full-wire commitment includes proof and binding-signature bytes that
ZIP-243 does not hash. A changed proof keeps the ZIP-243 digest but changes
the commitment in the host and device-loop tests. This app remains read-only;
the commitment is not payment approval or a signature. The pinned image is
recognized for offline inspection but installation is blocked pending
physical open, page, and EXIT validation. The
[full-wire commitment experiment](../../../docs/experiments/2026-09-29-ledger-blue-full-wire-commitment.md)
records reproducible tests, image bytes, RAM and stack measurements.

Version 0.5.9 revokes a pending APDU reply when USB resets or suspends during
screen redraw. The app erases the superseded review and waits for a fresh
request without transmitting its old success status. A host device-loop
regression forced reset on the final summary redraw: it observed a stale
success reply before the fix and no stale reply afterward. The existing
complete review, cancel, malformed upload, reconnect, touch, and erasure tests
still pass. Two isolated builds with the pinned SDK matched Intel HEX SHA-256
`8c796353659ae4582bae5e5dea5fe336ab6dacd28df032048c8ee3687a798ad8`
and `.text` SHA-256
`c2471f696f92cbc50853d0efdbff41253a110090227b734d1f33e04ced42245a`.
The image has 33,536 bytes of `.text`, zero `.data`, 4,328 bytes of `.bss`,
and a largest modeled stack path of 856/1,536 bytes. Offline
`--image-check` recognizes this read-only image with no declared signing
path; installation remains blocked pending a physical open and EXIT check.
Release and sanitized Debug each passed 62/62 tests. All 33 fast lint gates,
the unchanged consensus-core seal, and the documentation gates passed.
The [USB-generation experiment](../../../docs/experiments/2026-09-29-ledger-blue-review-usb-generation.md)
records the test and build evidence. The image has not been installed or
tested on a physical Blue.

Version 0.5.8 requests a screen redraw after beginning a review, completing
each upload pass, advancing a pass, finishing, aborting, or rejecting a
command. The shared Blue APDU loop previously changed review text without
requesting a BAGL redraw. A host test now executes the actual device loop
with the C23 BLAKE2b implementation: it sends the complete six-pass
synthetic Sapling fixture twice, compares the returned digest with an
independent ZIP-243 computation, checks displayed summary and digest pages,
exercises large text, dark mode, and EXIT, then resets USB between reviews
and verifies state erasure. This tests a BOLOS shim, not a physical Blue.
The same loop test checks begin, partial upload, cancel, malformed upload,
fresh begin, and transport failure. It asserts that a screen redraw occurs
after each state transition and not after every partial upload chunk.
Release and sanitized Debug each passed 62 of 62 tests. Two isolated builds
with the pinned SDK matched Intel HEX SHA-256
`97e60cad053ac82ab41f75ed9aa73bac3c8a8306247def610e5a1a478bfbcbd6`.
The image has 33,536 bytes of `.text`, zero `.data`, and 4,320 bytes of
`.bss`; the largest modeled stack path is 848 of 1,536 bytes. The
[device-loop experiment](../../../docs/experiments/2026-09-29-ledger-blue-shielded-device-loop.md)
records the complete test. This read-only image remains uninstalled and
provides no keys or signing.
Its 33,536-byte `.text` file can be checked offline with
`zcl-blue-install --image-check app.bin` after extracting it with
`arm-none-eabi-objcopy -O binary --only-section=.text bin/app.elf app.bin`.
The installer recognizes SHA-256
`6466837f121cfb3bc874adc599ff41518367734af43c658c8cfed482a8e8cd42`
for verification only and reports installation blocked pending a physical
open and EXIT check.

Version 0.5.7 retains the requested, known mainnet branch ID through the
six-pass Sapling review and displays it beside the full ZIP-243 digest.
The digest page says `CHAIN UNCHECKED; NO SIGNING`: a known branch ID does
not prove that branch is active at the current tip. The consensus Sapling
fixture and an alternate known-branch run verify distinct digests and the
exact branch text. The screen simulator checks 123 light, dark, standard,
and large-text PNGs. The image has 33,280 bytes of `.text`, zero `.data`, and
4,320 bytes of `.bss`. Its largest modeled stack path is 840 bytes of the
1,536-byte budget. Two clean pinned-SDK builds matched `.text` SHA-256
`542f9d5e95e1160c56ddcb45207f31a9381f54d14d0dc2daa2e331a60e54a728`
and Intel HEX SHA-256
`e6f7b4a90063342d41d9807c2339a6432257c361e17638d581a8e90e74ac92c2`.
Release and sanitized Debug each passed 60 of 60 tests. The
[branch-screen experiment](../../../docs/experiments/2026-09-29-ledger-blue-shielded-branch-screen.md)
records the vectors and rendered-page checks. This read-only image remains
uninstalled.

Version 0.5.6 separates reply transmission from the next APDU receive in
the shared device loop. A transport exception erases the shielded review,
hash workspace, and APDU buffer without reusing a pending reply length. A
reported receive count beyond 260 bytes is rejected before parsing. Host
device-loop tests inject both exchange failures, an oversized count, and
USB reset during a pending send. The read-only image remains uninstalled.
Its `.text` is 33,280 bytes, `.data` is zero, and `.bss` is 4,320 bytes.
The largest modeled stack path uses 840 bytes of the 1,536-byte budget;
the USB reset path uses 64 bytes. The `.text` SHA-256 is
`15ae381322ef88fb4bc773c2c13e6e6151bf83282bdfd3d6bf6a17c7719c84de`;
Intel HEX SHA-256 is
`a5556d24d91701abfe8c3ecb3131a12a584aa8e239cdd04c6f66563888c22eaf`.
The [exchange-failure experiment](../../../docs/experiments/2026-09-28-ledger-blue-review-exchange-failure.md)
records the fault tests and independent build.

Version 0.5.5 clears the in-progress or completed review, SHA-256/BLAKE2b
workspace, and shared APDU buffer on a Blue USB reset or suspend event. The
device-loop test injects both events, checks complete erasure, and verifies
the `CONNECT Z23` screen returns. The pinned image has 33,024 bytes of
`.text`, no initialized `.data`, and 4,320 bytes of `.bss`. Its largest
modeled stack path remains 824 bytes; the new USB reset path uses 64 bytes
of the 1,536-byte budget. The `.text` SHA-256 is
`0d87bbfd380c2b2c315ace66d8d60c2c9243bc15a6726c40f109dffdcabcc2af`;
Intel HEX SHA-256 is
`b6ab943a1c803d77beb4817017cd54653e2132767cff4ec9d57cde94e645c77d`.
The [USB reset experiment](../../../docs/experiments/2026-09-28-ledger-blue-shielded-usb-reset.md)
records the tests and independent build. This read-only image remains
uninstalled.

Version 0.5.4 erases the full declared APDU reply capacity on rejection and
unused reply capacity on success, including when the Blue shares its request
and reply buffer. This prevents later commands from reading stale request or
review bytes. The [reproduction record](../../../docs/experiments/2026-09-28-ledger-blue-shielded-reply-erasure.md)
includes the failing regression, passing tests, and independently rebuilt
image. The app remains read-only and uninstalled. The pinned image has 32,768
bytes of `.text`, no initialized `.data`, and 4,320 bytes of `.bss`. Its
largest modeled stack path is 824 bytes of the 1,536-byte budget. Its `.text`
SHA-256 is
`4166f7b217f1368ee82bf6b397300dc59b2b6ce53e11fa0b77d74155d55aa6b7`;
Intel HEX SHA-256 is
`67e6504dad14b00b2295a2722b3bfe363217c5f0bdf63dc313d18f094c0bed11`.

Version 0.5.3 rejects transaction bytes that overlap replay state or
provisional Sapling captures before parsing or hashing. Its APDU controller
and screen controller reject request, reply, or reply-length storage inside
their state, while allowing the Blue's shared request/reply buffer. Rejected
commands and failed screen formatting erase the review and up to 76 bytes of
reply data. The build pins the reviewed SDK
revision and patch and caps static RAM use at 5,120 bytes. It remains
read-only and uninstalled.
The pinned image has 32,512 bytes of `.text`, no initialized `.data`, and
4,320 bytes of `.bss`. Its largest modeled stack path is 832 bytes of the
1,536-byte budget. Its `.text` SHA-256 is
`3cdebe1b1ba684f237f9d2f2ee33327e2f703da4daf51320bb2d74ad6e6baa35`;
Intel HEX SHA-256 is
`6079c0055c91d3b0634566fc319ff586476a296954b7d84217afa6e3a6dcab70`.
The `.text` bytes and Intel HEX hash match a build from a separate source
checkout and SDK copy. The [reproduction record](../../../docs/experiments/2026-09-28-ledger-blue-shielded-upload-isolation.md)
includes the commands, test results, and limits.

Version 0.5.2 of this ISO C23 app is a read-only offline candidate for
Ledger Blue firmware 2.1.x. It accepts a complete Sapling-v4 transaction
in chunks of at most 220 bytes, uploaded six times. Each pass parses the wire independently and
derives one ZIP-243 section hash. A SHA-256 commitment to the first pass
rejects changed bytes in later passes. Only after all passes match does the
app return the ZIP-243 SIGHASH_ALL digest and public counts.

Tap NEXT / REFRESH during upload to redraw the current pass and byte count.
After finish, the screen shows public input/output and
Sapling spend/output counts, `PUB OUT` public output total, Sprout JoinSplit count,
and a digest prefix. NEXT / REFRESH shows the requested branch ID and full
digest in four rows. LARGER
TEXT and DARK are available; EXIT requests the Blue home screen. The screen
says `FEE UNKNOWN`, `SHIELDED HIDDEN; NO SIGNING`, and `CHAIN UNCHECKED; NO
SIGNING`. Neither the screen nor the digest is authorization to pay.

The protocol uses CLA `A5`, P1/P2 zero, and one-byte `Lc`:

| INS | Request | Response before `9000` |
| --- | --- | --- |
| `01` | Empty | `ZCL`, version `07`, review-only capability `40` |
| `20` | Four-byte wire length and four-byte branch ID, little endian | Empty |
| `21` | 1–220 wire bytes | Pass byte and four-byte received count |
| `22` | Empty, after a complete pass | Next pass byte |
| `23` | Empty, after pass six | 44-byte public summary and 32-byte ZIP-243 digest |
| `24` | Empty | Empty; erases the review |

Every rejected command erases pending or completed review state. The branch
ID is checked against known ZCL mainnet IDs but is not bound to a trusted
chain tip. Shielded recipients, amounts, memo contents, proofs, transparent
input values, change, and fee are not independently established by this
app. It has no key derivation, approval, or signing command.

Build with the reviewed C23 Blue SDK, its 2 KiB stack patch, Clang 22.1.6,
and ARM GCC 16.2.0:

```sh
make -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
```

The build rejects initialized `.data`, `.bss` above 5,120 bytes, a non-Blue
target, an SDK that differs from the reviewed revision and patch, or a modeled
stack path that leaves less than 512 bytes of its 2,048-byte reserve. The
largest modeled path is the six-pass finish path. SDK and BOLOS frames are
outside this local stack model; physical USB and touchscreen behavior remain
unverified. The app is not installed on a Blue. The
[experiment record](../../../docs/experiments/2026-09-27-ledger-blue-signing-route.md)
contains measured image size, stack paths, and the image hash. A new build
must be independently checked before installation.

The host command can exercise the exact six-pass protocol against the C23
screen and APDU simulator, or against an open Ledger Blue HID device. Both
modes compare every progress reply, the final public facts, and the complete
ZIP-243 digest with Z23's independent host implementation. The simulator
does not reproduce BOLOS, USB timing, or the physical display. For a binary
Sapling-v4 transaction and a verified ZCL branch ID:

```sh
cmake -S apps/zcl-ledger -B build/blue-review \
  -DCMAKE_C_STANDARD=23 -DZCL_LEDGER_REVIEW_ONLY=ON
cmake --build build/blue-review --target zcl-blue-shielded-review
build/blue-review/zcl-blue-shielded-review \
  --simulate unsigned-v4.bin 0x76b809bb
```

Use `--blue /dev/hidrawN` in place of `--simulate` only after the exact
read-only image has been installed and the device app is open. Neither mode
signs, broadcasts, verifies shielded recipients or proofs, or establishes a
fee. The host command and review-only build do not require OpenSSL.

For visual inspection, the separate C23 screen simulator writes 41
320×480 PNG files: ready, start and end of each upload pass, summary and
digest in both themes, and every large-text detail in both themes. It uses
the same screen controller and layout constants as the device image, but
its host font renderer is an approximation of Blue BAGL glyphs.

```sh
cmake -S apps/zcl-ledger -B build/blue-visual
cmake --build build/blue-visual --target zcl-blue-shielded-screen-sim
build/blue-visual/zcl-blue-shielded-screen-sim \
  unsigned-v4.bin 0x76b809bb /tmp/zcl-blue-review
```

The PNGs are review artifacts, not evidence that the physical display or
touch events work. The command does not connect to the Blue.

## Sapling key compatibility

This review app has no Sapling keys. Z23's current software Sapling wallet
uses an independent 32-byte seed and ZIP-32 path `m/32'/147'/account'`.
ZIP-32 starts from the wallet seed with personalized BLAKE2b-512. The Blue
2.1.x app API exposes BIP-32 derivation, including a custom HMAC seed-key
variant, but no raw wallet seed or ZIP-32 derivation call. A Blue-derived
Sapling account therefore cannot be presented as the same account as Z23's
existing software wallet. A separate derivation scheme would need a
domain-separated seed source, a public recovery specification, independent
C23 recovery tests, and explicit account identity in the wallet UI before
receiving funds or enabling signing. The
[ZIP-32 specification](https://zips.z.cash/zip-0032),
[Blue SDK interface](https://github.com/LedgerHQ/blue-secure-sdk/blob/master/include/os.h),
and [Zcash Ledger security audit](https://zecsec.com/audits/zcash-ledger-audit-report-v2.pdf)
document the compatibility and recovery risks.
