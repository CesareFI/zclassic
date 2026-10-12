<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Read-only transparent payment APDU boundary

Local time: 2026-09-27T01:30:45-04:00

UTC: 2026-09-27T05:30:45Z

## Question

Can USB upload and inspect a transparent transaction without a USB command
that acknowledges an output or produces a signature?

## Result

The C23 Wallet command candidate uses CLA `A5`, zero P1/P2, and an exact
single-byte payload length. INS `20` begins a replay with declared byte
length, selected input index, and caller-supplied branch ID. INS `21` feeds
one bounded chunk and reports when an output is waiting. INS `22` advances
to the next replay pass. INS `23` validates the complete third pass and
returns only the transparent output count. INS `24` cancels; INS `25`
reports nonsecret state. There is no USB output-acknowledgement command.
The separate `blue_payment_apdu_touch_continue` function is intended only
for a physical touch callback. Any malformed or unsupported command aborts
the review and clears the screen model.

The synthetic two-output test sends a full APDU sequence, checks both output
screens, queries status while pending, simulates one physical touch per
output, completes the replay, and checks the verified status. Separate tests
reject an unsupported instruction, a feed before touch, a chunk one byte
past an output boundary, and an APDU length mismatch. A deterministic
10,000-case malformed/interleaved APDU campaign checks bounded replies and
session invalidation under Clang sanitizers.

ARM GCC 16.2.0 compiled the handler as ISO C23 with `-Os -Wall -Wextra
-Werror -pedantic -fstack-usage`. The isolated object has 538 bytes of
`.text`, zero `.data`, and zero `.bss`; its largest reported local frame is
104 bytes. The APDU state including controller and screen measures 520 bytes
on ARM. It excludes SHA-256 and BLAKE2b contexts, linked UI, USB stack,
and SDK globals.

## Limit

This is a host-tested state machine, not a Blue-installed application. The
caller-supplied branch ID and prior-output details are not authenticated.
The final digest is discarded because no key operation or signing approval
exists. Physical touch binding, cancellation during USB failure, BOLOS
timing, and full linked SRAM and stack costs still need device integration
and emulator testing before an installable candidate is considered.
