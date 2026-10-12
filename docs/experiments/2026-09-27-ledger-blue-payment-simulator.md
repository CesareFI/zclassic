<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Transaction-driven transparent payment simulator

Local time: 2026-09-27T01:23:24-04:00

UTC: 2026-09-27T05:23:24Z

## Question

Can the host preview derive its output pages from unsigned transaction bytes,
exercise each output pause and acknowledgement, and withhold all pages if
the final transaction replay is invalid?

## Result

The C23 host simulator runs the same bounded review controller used by the
unit test. It uploads the unsigned transaction for all three passes and
simulates an acknowledgement each time an output becomes pending in pass
three. It retains at most 16 formatted output screens. Only after the
complete third pass matches the first pass's SHA-256 commitment does it
return screens to the PNG renderer. This is a simulated touch; no hardware
approval occurs.

The one-input/two-output test fixture produces two 320 × 480 PNGs with full
P2PKH and P2SH addresses and exact one- and two-ZCL amounts. Both rendered
pages were inspected at original size. A malformed P2SH script and a
truncated transaction return zero pages. An invalid branch ID argument is
rejected before reading the file. Reproduce the preview with:

```sh
build/zcl-ledger/test-blue-payment-review /tmp/zcl-unsigned-fixture.bin
build/zcl-ledger/zcl-blue-payment-sim 76b809bb /tmp/zcl-unsigned-fixture.bin /tmp/zcl-payment
build/zcl-ledger/zcl-blue-payment-sim --dark 76b809bb /tmp/zcl-unsigned-fixture.bin /tmp/zcl-payment-dark
```

At 2026-09-27T11:00:08-04:00 (2026-09-27T15:00:08Z), the standalone fee and
totals previews were aligned with the current Wallet 0.2.17 screen labels,
font sizes, warnings, and controls. The fee preview now shows TOTALS and
EXIT; the totals preview shows BACK and DONE. Both show CHAIN UNCHECKED and
BRANCH UNCHECKED separately. Dark previews were rendered at 320 × 480 and
visually inspected beside the actual device UI source rendered through its
SDK shim. The focused payment-screen test passed 1/1 under Clang 22.1.6
Debug/ASan/UBSan and 1/1 under GCC 16.1.1 Release on an AMD Ryzen 7 PRO
8840U. The SDK shim now renders the device source's button fills, button
text alignment, and labels. For matching fee, path, and totals inputs, the
standalone renderer and SDK-shim renderer produce byte-identical 320 × 480
RGB buffers. At 2026-09-27T11:05:28-04:00 (2026-09-27T15:05:28Z), the
focused pixel comparison passed 2/2 under Clang 22.1.6 Debug/ASan/UBSan
and 2/2 under GCC 16.1.1 Release. Neither renderer proves
pixel identity with the physical BOLOS framebuffer.

At 2026-09-27T11:29:09-04:00 (2026-09-27T15:29:09Z), the standalone
transparent-output preview's CONTINUE and EXIT labels were changed to the
22-pixel font used by Wallet 0.2.18. For a device-formatted account output,
the standalone preview and the actual wallet screen source rendered through
the SDK shim produced byte-identical 320 × 480 RGB buffers. The output page
was saved as a 320 × 480 PNG and visually inspected. The focused touchscreen
test passed 1/1 under Clang 22.1.6 Debug/ASan/UBSan and 1/1 under GCC
16.1.1 Release. Physical framebuffer and touch timing remain unverified.

Clang 22.1.6 Debug with address and undefined behavior sanitizers and GCC
16.1.1 Release each passed 22/22 host tests on AMD Ryzen 7 PRO 8840U. The
repository cyclomatic gate passed at cap 15.

## Limit

The caller supplies the consensus branch ID; the simulator does not verify
it against a ZCL node. The empty scriptCode and zero spent amount passed
to the final replay check create an unused diagnostic digest, never a
payment signature. The harness does not emulate BOLOS USB, touchscreen
timing, the Blue framebuffer, key derivation, or Sapling proof validation.
Screens show transparent outputs only and explicitly state no signing.
