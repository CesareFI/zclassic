<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# C23 development for Ledger Blue

Z23 builds Blue device apps from C23 source with Ledger's open-source
Blue SDK and open-source ARM tools. The host transport, tests, and installer
are C23. No Ledger Live service is part of the build or runtime path.

## Reproduce the toolchain

Use Ledger's `blue-secure-sdk` tag `blue-r21.1`, commit
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, and apply the reviewed
[`blue-sdk-c23.patch`](device-blue/blue-sdk-c23.patch). The patch sets the
SDK's C dialect and ARM include path. The build used Clang 22.1.6,
`arm-none-eabi-gcc` 16.2.0, and ARM Newlib headers. Set `BOLOS_SDK` to the
patched SDK, `ARM_INCLUDE_DIR` to the Newlib include directory, and
`GCCPATH` and `CLANGPATH` to the compiler bin directories, each ending in
`/`. The Review app additionally requires its
[`blue-review-stack.patch`](device-blue-review/blue-review-stack.patch)
on a separate copy of the patched SDK. This reserves 2 KiB for the app
stack. The build rejects the base SDK's 1 KiB stack reserve.

```sh
cmake -S apps/zcl-ledger -B build/zcl-ledger-debug \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
cmake --build build/zcl-ledger-debug
ctest --test-dir build/zcl-ledger-debug --output-on-failure
build/zcl-ledger-debug/test-blue-review-simulator \
  apps/zcl-ledger/tests/fixtures/zip243-transparent-vector3.hex
build/zcl-ledger-debug/zcl-tx-review --json --simulate-app \
  transaction.bin
build/zcl-ledger-debug/zcl-blue-screen-sim \
  transaction.bin /tmp/zcl-blue-preview
build/zcl-ledger-debug/zcl-blue-screen-sim \
  transaction.bin /tmp/zcl-blue-accessible --large-text --dark

make -C apps/zcl-ledger/device-blue-review \
  BOLOS_SDK=/path/to/patched/blue-secure-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/arm-toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
```

The device Makefiles require `-std=c23 -Wall -Wextra -Werror -pedantic`.
The Blue linker rejects an SRAM overflow, and the Makefile rejects a
nonempty initialized `.data` section. It also compiles with
`-fstack-usage` and runs a C23 stack-budget check across the deepest
known APDU and screen call paths with a 512-byte reserve for intermediate
frames. The Wallet receive candidate uses the same checker for its
derivation, address formatting, APDU, and event paths. This is a conservative
build gate, not a complete firmware stack proof. The code image is the ELF's `.text`
section, extracted with `arm-none-eabi-objcopy -O binary
--only-section=.text`. Record its byte count and SHA-256. The C23 installer
accepts only explicitly pinned hashes; source changes require a new app
version and pin. An exact image hash identifies the built bytes, not their
security.

## Separate evidence gates

Host unit tests exercise protocol bounds, transaction parsing, screen text,
address derivation, and cryptographic vectors. The C23 Review simulator
uses the same app controller source as the Blue image and prints each page
for the published 245-byte ZIP-243 transparent fixture. It exercises the
USB command sequence and page transitions through host hash callbacks.
The C23 renderer writes one 320 × 480 PNG for the waiting screen, each
transaction page, and the wraparound page. `--large-text` previews each
nonempty detail on a separate screen in the SDK's 22-pixel full-alphabet
font; `--dark` previews a high-contrast dark palette. The uninstalled
Review 0.4.4 ARM candidate exposes the matching controls. The renderer
shares layout constants with the ARM app and decodes an Apache-2.0 Ledger
Open Sans BAGL font table. The
table is the closest available open-source match; its identity with the
font inside the dedicated Blue's BOLOS 2.1.1 is unverified. Rounded button
edges and the antialias palette are approximations. These PNGs test layout
and clipping, not physical pixel equality. It does not emulate BOLOS, the
Blue USB transport, or touch.
The host CLI exposes the same controller exercise through `--simulate-app`;
its JSON keeps simulated and physical Blue evidence in separate fields.

## Reusable Blue screen preview

[`blue_bagl_canvas.h`](include/blue_bagl_canvas.h) provides a C23 host
canvas for the Blue's 320 × 480 screen. It draws clipped rectangles,
rounded rectangles, and ASCII text with the two reviewed BAGL font tables;
it writes RGB PNGs through libpng. The nominal 14-pixel font table has a
16-pixel bitmap height; the larger table has a 22-pixel bitmap height.
`blue_bagl_text` rejects unsupported bytes, overlong labels, and text boxes
outside the screen instead of silently truncating them. Future app preview
renderers can link `blue_bagl_canvas` and keep their app-specific layout in a
separate source file. Review now uses this API; its 68 fixture PNGs across
regular, large-text, dark, and large-text dark modes are byte-identical to
the previous renderer.
`blue_bagl_wrap_ascii` uses actual glyph advances and explicit input length,
output capacity, line width, and line count. It wraps at spaces where
possible, breaks long words when needed, and rejects unsupported bytes or
content that cannot fit. Its output is only valid when it returns true.

[`zcl_tx_stream.h`](include/zcl_tx_stream.h) provides a reusable C23 component
for bounded transaction intake. It accepts arbitrary USB-sized chunks of an
unsigned, all-transparent Sapling-v4 transaction, with up to 16 inputs and
2 MiB of wire bytes. It accepts standard P2PKH/P2SH outputs and rejects
shielded components, nonempty input scripts, noncanonical lengths, trailing
bytes, and out-of-range public values. Its callbacks run before the
transaction is complete; callers must discard staged facts on any error.
It returns aggregate facts only after `finish` validates the declared total.
The state is capped at 160 bytes by an ARM C23 compile-time assertion. The
parser does not authenticate prevouts, calculate a ZIP-243 digest, prove
chain state, derive change, or permit signing. The
[streaming experiment](../../docs/experiments/2026-09-27-ledger-blue-tx-stream.md)
records its measured tests and limits.
[`zcl_tx_stream_zip243.h`](include/zcl_tx_stream_zip243.h) adds an exact
transparent input SIGHASH_ALL calculation over this bounded parser. It
reconstructs standard output bytes independently from parsed amounts and
hash160 values, hashes input outpoints and sequences in separate personalized
BLAKE2b contexts, and matches the complete-transaction ZIP-243 implementation
on an unsigned variant of the published transparent fixture. Its final
scriptCode, spent amount, and branch ID are caller supplied; they are not
authenticated by this component. The
[streaming digest experiment](../../docs/experiments/2026-09-27-ledger-blue-streaming-zip243.md)
records ARM memory costs. The two SDK hash contexts plus wrapper state exceed
the earlier conservative accounting for receive app growth. The linker
includes its stack reservation in `.bss`, so the corrected SRAM guard admits
this state as an isolated addition. The code remains offline and is not linked
into either Blue image; payment UI and protocol state need a linked measurement.
[`zcl_tx_replay_zip243.h`](include/zcl_tx_replay_zip243.h) trades two extra
complete uploads for one BLAKE2b context. It checks a SHA-256 commitment to
the entire first upload before accepting either replay's ZIP-243 subhash.
The [replay memory experiment](../../docs/experiments/2026-09-27-ledger-blue-replay-zip243.md)
measures 684 bytes of wrapper and SDK hash state on ARM, 116 bytes below the
two-context method. The corrected Wallet guard admits this state as an
isolated addition. Wallet 0.2.1 now links replay, transport, and output UI;
its full image measurements are recorded in the
[linked Wallet experiment](../../docs/experiments/2026-09-27-ledger-blue-wallet-review-link.md).
Wallet 0.2.1 receive display and EXIT worked on the Blue, but a later
read-only payment review stopped USB replies and made EXIT unresponsive.
Version 0.2.1 was deleted; 0.2.4 remains uninstalled.
[`blue_payment_review.h`](include/blue_payment_review.h) adds a C23,
read-only review controller. It retains one standard transparent output,
halts upload until that output is acknowledged, and limits a session to 16
outputs. A chunk must end exactly when an output completes; a chunk with
trailing bytes invalidates the session. Every output is provisional until
the final replay commitment validates. Its acknowledgement function must be
bound to a touchscreen callback; a USB command must never call it. Wallet
0.2.1 contains that binding. The
[output review experiment](../../docs/experiments/2026-09-27-ledger-blue-output-review.md)
records host tests and the isolated ARM state measurement. The linked
candidate has no signing operation or verified fee.
The [exact-stop follow-up](../../docs/experiments/2026-09-27-ledger-blue-exact-output-stop.md)
records the rejected trailing-byte case and unchanged ARM state size.
[`blue_payment_screen.h`](include/blue_payment_screen.h) formats a pending
controller output with the complete 35-character P2PKH or P2SH address,
amount to eight decimals, position, and output type. On a hash failure it
clears the formatted screen. The C23 host renderer previews light and dark
320 × 480 screens with the Blue SDK's 22-pixel address font and a separate
"DRAFT; NO SIGNING" label. The
[screen experiment](../../docs/experiments/2026-09-27-ledger-blue-payment-screen.md)
records the host and ARM measurements. This is an offline preview; its
touchscreen action is not wired to a device or signing command.
The [`blue_payment_simulate.h`](include/blue_payment_simulate.h) host harness
feeds complete transaction bytes through the same three-pass controller,
simulates a touch at each pending output, and returns screens only after the
final replay commitment passes. `zcl-blue-payment-sim` renders those screens
as PNGs from a binary unsigned v4 transaction. Its consensus branch ID is
caller supplied and not authenticated. The
[transaction-driven simulator experiment](../../docs/experiments/2026-09-27-ledger-blue-payment-simulator.md)
records the reproducible fixture and failure checks. This harness does not
emulate BOLOS USB or hardware touch timing.
[`blue_payment_apdu.h`](include/blue_payment_apdu.h) defines the C23,
read-only Wallet command state machine. USB can start, feed, advance passes,
finish, cancel, and query the review. Only a separate touchscreen function
acknowledges a pending output. The
[APDU experiment](../../docs/experiments/2026-09-27-ledger-blue-payment-apdu.md)
records malformed-command and memory tests. The handler is host-tested and
linked into the withdrawn Blue Wallet 0.2.1 candidate. Its app catalog entry
is verified; the owner saw a steady receive screen and working EXIT, then
matched all 35 address characters with the host's read-only result. Review
USB behavior failed on a synthetic physical test. The
[failure experiment](../../docs/experiments/2026-09-27-ledger-blue-wallet-review-failure.md)
records the observed fault and the offline-only 0.2.2 response. Version 0.2.3
also prevents a post-reply display exception or an incomplete receive from
creating an APDU response without a request. Version 0.2.4 adds a label
derived from the device's fixed P2PKH hash for an exact self-address match.

The canvas is host-only and does not access the Blue framebuffer. Its PNGs
show intended layout using SDK font data; physical font pixels, touch
regions, contrast, and responsiveness require a dedicated-device check for
the exact ARM image hash. Future memo displays must classify UTF-8 and
opaque bytes before using this ASCII-only canvas. A payment app must show
and bind every material transaction field before any key operation.

An ARM build measures code,
initialized data, and SRAM use. Neither proves a Blue screen renders or
responds to touch. Test a new image on the dedicated Blue only after those
checks, then record install, open, page navigation, EXIT, USB replies, and
recovery observations for that exact image hash. Never promote a synthetic
transaction review to payment authorization.

The intended everyday app is one [ZCL Wallet](ROADMAP.md). The existing
Probe, Fixture, Review, and Sign Test apps are narrow development tools.
The 0.1.0 Wallet receive image used 3,348 bytes of `.bss`, including a
2,048-byte stack reservation and four-byte canary, in the Blue's 6,144-byte
app SRAM region. It left 2,796 bytes after `.bss`. The uninstalled 0.2.4 candidate
uses 4,276 bytes of `.bss` and leaves 1,868 bytes after `.bss`, with the same
512-byte guard. It uses bounded streaming instead of Review's 2,304-byte
transaction buffer. Output and interrupted USB behavior still require
physical and emulator checks.
The Review app has no key permission; Sign Test can sign only its fixed
self-test message. The host must establish ZCL consensus branch, input
provenance, shielded output details, and token validity before asking a
future payment app to approve a transaction. A device approval must bind
the displayed recipient, amount, fee, account, and network to the exact
transaction bytes and the resulting signature.

## Transparent input provenance gate

[`zcl_tx_prevout.h`](include/zcl_tx_prevout.h) is a C23 host preflight for
unsigned, all-transparent v4 transactions with up to 16 P2PKH inputs and
standard P2PKH/P2SH outputs. The caller supplies each complete previous v1-v4
transaction in input order. Preflight parses those transactions, computes
each SHA-256d txid, compares the exact outpoint bytes, selects the indexed
P2PKH output, rejects duplicate outpoints, and calculates input total,
output total, and fee. Its hash-bound ZIP-243 digest takes script and amount
from that selected output. The tests compare the double hash of ZIP 243's
published vector 3 with its published txid, check a synthetic fee and input
digest, and reject mismatches and truncated encodings. Separate fixtures
exercise v1, v2, Overwinter v3, and Sapling v4 previous wires, including
JoinSplit and Sapling tails; the spending wire remains restricted to v4.

A previous transaction matching an outpoint does not prove the output is
unspent, mature, on the accepted ZCL chain, or controlled by the selected
Ledger account. The caller-provided branch ID also needs consensus-height
validation. The Review app cannot verify previous transactions and cannot
sign. This preflight must not set `signing_ready` or supply approval text to
a signer. The next device design must stream authenticated prevout evidence,
derive change scripts from its own key path, independently display every
output and fee, and bind final approval to its own digest computation.

For parser fuzzing with the published transparent fixture as the initial
corpus, build `fuzz-zcl-tx` with Clang Debug and `ZCL_LEDGER_FUZZ=ON`, then
run it locally with a fixed seed. The fuzzer checks that complete-transaction
parsing, input/output visitors, script classification, and ZIP-243 hashing
agree on accepted v4 bytes. It does not fuzz BOLOS or prove consensus parity.
The same build includes `fuzz-zcl-previous-output` for v1-v4 previous-output
selection. Its first input byte selects the output index; remaining bytes are
the complete previous transaction. It checks failure atomicity and bounds of
every accepted script and value. Seed all four versions with valid wires so
mutations reach each parser tail. This checks memory safety and API invariants,
not signatures, proofs, chain inclusion, or consensus acceptance.

Review 0.4.0 passed local tests but stopped answering USB and EXIT on the
dedicated Blue. It was deleted after a restart and its installer hash was
removed. Version 0.4.4 retains the font-size and palette controls and uses
the common C23 Base58 encoder for output addresses. Host tests check
navigation, wrapping, and screenshots; they do
not establish BOLOS touch or USB responsiveness. It is not pinned for
installation.

The ST31G480 silicon supports up to 28 MHz, 12 KiB user RAM, and 480 KiB
secure user flash. Those are silicon limits, not measured app throughput or
free install capacity. The patched Blue linker grants this app 6 KiB SRAM
and a 400 KiB code address range. Review 0.4.4 uses 6,000 SRAM bytes
(including a 2,048-byte stack reserve) and 32,256 code bytes, leaving 144
bytes in the SRAM region. Its APDU review limit is 2,304 bytes. No on-device
latency measurement has been made.
