<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Review for Ledger Blue

Version 0.4.7 separates reply transmission from the next APDU receive. If
either exchange throws, it erases review state and the shared buffer instead
of reusing a pending reply length. It also rejects a receive count beyond
the 260-byte APDU buffer before parsing. Host device-loop tests inject send
and receive failures, an oversized count, and USB reset during a pending
send. The read-only image remains uninstalled. Its `.text` is 34,048 bytes,
`.data` is zero, and `.bss` is 6,000 bytes. The modeled APDU, screen, and
USB reset stack paths use 792, 904, and 192 bytes of the 2,048-byte
reservation; BOLOS frames are excluded. The `.text` SHA-256 is
`0d719924ca08128834d2713b6efd92a95f126fa748a458d954902a35e6f38c60`;
Intel HEX SHA-256 is
`7e78e32fe85e11887f21feec1569a02847dbcec45642ce09121b08a049f287e4`.
The [exchange-failure experiment](../../../docs/experiments/2026-09-28-ledger-blue-review-exchange-failure.md)
records the fault tests and independent build.

Version 0.4.6 erases the transaction, hash workspace, and complete shared
APDU buffer when the Blue reports USB reset or suspend. It returns to
`CONNECT Z23` while keeping the chosen text size and color theme. The
device-loop regression injects both events and checks erasure and display
state. The read-only image remains uninstalled. Its `.text` is 33,792 bytes,
`.data` is zero, and `.bss` is 6,000 bytes, leaving 144 bytes of linker
SRAM headroom. The modeled APDU, screen, and USB reset stack paths use
776, 888, and 176 bytes of the 2,048-byte reservation; BOLOS frames are
excluded. The `.text` SHA-256 is
`a1eff6f4b6186b0d4be4d5fa206ab956f3aa8c3ee520e6da92596a34a6c384fc`;
Intel HEX SHA-256 is
`9cdf1782ea257efce28f4fb644feb777f8a301f16a9ce6d03adcf886fa799aa5`.
The [USB reset experiment](../../../docs/experiments/2026-09-28-ledger-blue-shielded-usb-reset.md)
records the reproducible test and build results.

This C23 app accepts up to 2,304 bytes of a raw ZCL Sapling-v4 transaction
over USB and returns a structural summary and SHA-256 digest of the exact
transaction bytes. It counts transparent inputs and
outputs, Sapling spends and outputs, and Sprout JoinSplits. It also reports
the public output total, value balance, lock time, and expiry height. The
touchscreen starts with `CONNECT Z23`, `SEND A TRANSACTION`, and `THEN TAP
NEXT PAGE`. After a successful review, tap
`NEXT PAGE` to see the public output total, Sapling counts, the Sprout
JoinSplit count, an explicit unverified-fee warning, and
the first eight bytes of the transaction SHA-256 digest. Further taps show
each transparent output's amount in ZCL and, for P2PKH or P2SH, its independently
derived ZCL mainnet address. Other script pages show the script length and
the first ten bytes of its SHA-256 digest. OP_RETURN pages say `TOKEN STATUS
UNVERIFIED`; a token marker alone is not token validation. After the final
output, NEXT PAGE returns to the summary. LARGER TEXT presents one detail
at a time in the Blue SDK's 22-pixel alphabet font; STANDARD TEXT returns
to the six-line screen. DARK and LIGHT select the display palette. The
`EXIT` callback requests
the Blue home screen. The app has no key derivation, approval, or signing
command. Given an explicit consensus branch ID, it also computes the ZIP-243
shielded SIGHASH_ALL digest. Its screen does not display recipients,
shielded recipients, shielded amounts, or a verified fee. Its response is not user
authorization of a payment.

Build with the reviewed Blue SDK, the additional
[`blue-review-stack.patch`](blue-review-stack.patch), and an ISO C23
compiler. Apply the stack patch to a separate copy of the SDK after the
base C23 SDK patch; the Review build rejects the base 1 KiB stack reserve:

```sh
make -C apps/zcl-ledger/device-blue-review \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
```

The build checks for an empty `.data` section and a bounded ARM stack
path. Extract the code image and check its SHA-256 before installing:

```sh
llvm-objcopy -O binary --only-section=.text \
  apps/zcl-ledger/device-blue-review/bin/app.elf /tmp/zcl-review.bin
sha256sum /tmp/zcl-review.bin
```

Version 0.4.0's former image hash was
`f442caa2e21e3b2f830f48f71ba23531ba6cfdf51bd4d888ee59bfd0e0e72dae`.
It is no longer accepted by the installer after a live USB lockup.
Review 0.4.5 is an offline UX candidate that has not been installed. It uses
the common C23 Base58 encoder for output addresses. Its
2,304-byte transaction limit reserves 2 KiB of Blue SRAM for the stack
and 144 bytes of linker SRAM headroom. The build checks the known call paths
against the 2 KiB stack reserve and keeps 512 bytes of headroom. The
same C23 app controller runs in the host simulator, including the published
transparent fixture and public P2SH and OP_RETURN output pages. The simulator
also sends 10,000 deterministic malformed APDUs. Rejected commands erase the
transaction buffer and reset the display state to `CONNECT Z23`; beginning a new
review and clearing a completed review also erase the previous buffer. The
device result remains unverified; the candidate is not pinned for
installation. The 0.4.5 `.text` SHA-256 is
`c23c78c978245da12af43dd44b44e63f8a695857be8a2c9ca632804d2c00d37c`;
this records the offline build and does not authorize installation.
After a new image hash is pinned, install only on the dedicated test Blue at
its home screen using
`zcl-blue-install /dev/hidrawN --ca-install CA_KEY_FILE /tmp/zcl-review.bin`.
Delete an older ZCL Review app first; the Blue rejected installation over
an existing icon with status `6a80` at commit.
If a signed install is rejected, diagnose its exact status before another
install attempt. Remove a signed Review app from home using
`zcl-blue-install /dev/hidrawN --ca-delete-review CA_KEY_FILE`.

The host's `zcl-tx-review`
command can compare the app's reply to its own parser using
`--blue /dev/hidrawN`, once a separately reviewed image is installed and
open. The earlier version 0.1.0 signed image installed on the dedicated Blue running BOLOS 2.1.1,
and a synthetic one-spend, one-output Sapling fixture returned a matching
summary and exact-byte digest. The owner confirmed the signed app opened
without BOLOS's non-genuine warning and exited normally. Version 0.2.0
received a successful install response after the previous Review icon was
deleted, but its icon is absent from the owner's home screen. Installation,
touchscreen operation, and live ZIP-243 behavior remain unverified. Version 0.4.0
installed and opened, but a 245-byte test-vector review stopped USB replies
and EXIT did not respond. The owner restarted the Blue and Z23 deleted the
app. Do not install version 0.4.0. Running
the host command without `--blue` only parses a local file.

Protocol commands use CLA `A5`, P1/P2 zero, and one-byte `Lc`:

| INS | Request | Successful response before `9000` |
| --- | --- | --- |
| `01` | Empty | `ZCL`, protocol version `06`, review-only capability `40` |
| `10` | Two-byte little-endian transaction length | Empty |
| `11` | Transaction chunk | Empty |
| `12` | Empty | 44-byte little-endian structural summary, then 32-byte SHA-256 digest |
| `13` | Empty | Empty; clears pending review |
| `14` | Four-byte little-endian consensus branch ID | 32-byte ZIP-243 shielded SIGHASH_ALL digest |

Each chunk is at most 220 bytes from the host CLI. An invalid size or
truncated transaction fails. Any rejected command erases the pending or
completed review. `12` consumes the pending review even if the transaction is
invalid. `14` requires a complete transaction and leaves it
pending for `12`; the caller must supply a branch ID valid for the transaction's
height. The app does not check that relationship. Neither digest is a device
approval. The summary fields and limitations are documented in
the [host guide](../README.md).
