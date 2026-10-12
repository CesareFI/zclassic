<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Laptop payment facts beside the Ledger Blue

Date: 2026-09-29. Compiler: Clang 22.1.6, x86_64-pc-linux-gnu.
Scope: the C23 host companion `zcl-blue-host-gui` and the wallet app-loop
simulator. Wallet 0.3.46 image bytes are unchanged.

## What the laptop shows

One representative transparent payment prints a stable log and four
320×480 PNG views: light, dark, large text, and large text on dark.
Both launches wrote the same log and the same PNGs. The log was:

```
connection: Blue linked
app_name: ZCL Wallet
app_version: 12
receive: t1ZjZs2V82PuoqGfwRvFDLtGMhe5DokMrya
recipient: t3Mg6o2UpMFVtrzqGs7f2VTS6DaiPnFT5rL
amount: 2.00000000 ZCL
fee: 1.00000000 ZCL
network: BRANCH 0x76B809BB
memo: NO MEMO
approval: SIGN ZCL
digest: bc49ff238fbb4a7467fd9c4e30ad85a25c80545ea7ccf8c44d27e418b813284b
bind: match
```

`app_version` is protocol identity 12 from the device reply, not the
installer version 0.3.46. The receive address is the simulator review
address. The recipient and amount are the second transparent output.
The fee is 1.00000000 ZCL from 100000000 zatoshis. The branch is
`0x76b809bb`. The device draws no memo line; `NO MEMO` is that absence.
`SIGN ZCL` is the final approval label. The digest is the ZIP-243 value
the review would sign. A mismatched amount, recipient, fee, network,
memo, or digest releases no signature.

Large text is 22px. The branch line wraps after `Network`, and each
35-character address is drawn as three spans. Dark mode uses the dark
body and light text. None of the nine facts is dropped. `--window`
opens that same payment in a dark window. `--window-shot` saves the
window as a PNG. Both exit 3 when the window system cannot start.
The window does not sign and does not install.

## Authorities and the pinned image

Review, keys, signing, and installation are exact separate values.
A read-only review result cannot release a signature or permit an
install. The installer recognizes `.text` SHA-256
`d005d4fa9d4a77cf1781c6cf566d7932e2468d32d0b8f6f11acb60110ffe28fb`
as ZCL Wallet 0.3.46, reports installation blocked, and refuses a
physical install before opening a device. The image file is 54,272
bytes. These host changes do not rebuild that image.

Boot now calls `wallet_payment_boot_reset`, which revokes any earlier
approval before derivation reuses the payment workspace. The startup
harness counts that wipe and leaves its scripted visibility in place
so a later command can still redraw. Touch approval, touch rejection,
USB reset, cancel, the approval ticker, reboot, and a non-ZCL APDU
each leave no signature and no install.

## Tests

`ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build/zcl-ledger-host
--output-on-failure` passed 60/60 under Debug with AddressSanitizer and
UndefinedBehaviorSanitizer. LeakSanitizer cannot initialize in this
environment; disabling it is not a leak-freedom result. The focused
install, laptop GUI, device UI, startup, and integrated-loop tests
passed in that suite. These tests drive the shipped app loop and GUI
binding. They do not establish physical touch timing, USB identity, or
on-device signing.
