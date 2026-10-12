<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue payment interruption inside device callbacks

Date: 2026-09-29. Scope: ZCL Wallet 0.3.46, C23 host harness and
Cortex-M3 image. No payment or signing command was sent to a physical Blue.

## Failure reproduced

The integrated app-loop harness injected a USB reset from the SDK BLAKE2b
initialization callback during the first payment APDU. The previous code
used `visible` as its reset guard; visibility was still false. It returned
`0x9000` and retained the payment after the reset. Immediate abort inside
the hash callback then caused an AddressSanitizer failure because it erased
the hash workspace while the active hash function still used it.

## Correction and tests

The app marks payment handling as in flight before entering a hash or signer
callback. USB reset, suspend, PIN lock, or approval timeout advances the
review epoch during an active command. The outer command boundary rejects
the result with `0x6985`, wipes the reply, and erases the review after the
callback returns. The shared APDU buffer is erased at the interrupt. The
signer workspace is erased after the callback. Reset during the first
payment command and reset or timeout inside the signer return no signature.

`ctest --test-dir /tmp/z23-blue-tail-release --output-on-failure -j1`
passed 63/63. `ASAN_OPTIONS=detect_leaks=0 ctest --test-dir
/tmp/z23-blue-tail-debug --output-on-failure -j1` passed 63/63 with
AddressSanitizer and UndefinedBehaviorSanitizer. LeakSanitizer was disabled
because it cannot initialize in this environment. The integrated-loop
tests assert the rejected status, no signature reply, erased review, and
deferred signer erasure. These tests simulate BOLOS callbacks; they do not
establish device timing or touchscreen behavior.

The ARM app built cleanly with the pinned Ledger Blue SDK in two separate
SDK directories. Both produced 54,272 bytes of `.text`, zero `.data`, and
5,120 bytes of `.bss`. SHA-256 of `.text` was
`d005d4fa9d4a77cf1781c6cf566d7932e2468d32d0b8f6f11acb60110ffe28fb`;
SHA-256 of `app.hex` was
`dbc29199ed92ba88144ff0d130bc7da6c062634b76929a44989089e0c5270a46`.
The stack gate measured a largest modeled payment frame of 1,128 bytes
plus a 512-byte margin in the 2,048-byte reserve. BOLOS frames are excluded.

## Physical boundary

The connected Ledger Blue enumerated as USB vendor `2c97`, product `0000`
on `/dev/hidraw1` and `/dev/hidraw2`. `/dev/hidraw1` answered the read-only
app-info query as `BOLOS` version `2.1.1`. A development secure channel
opened and its authenticated app catalog listed zero applications. No app
was installed, removed, opened, or tested on the Blue for this experiment.
The installer profile identifies the exact 0.3.46 image but continues to
reject its installation. Physical install, opening, touch, USB interruption,
and recovery remain separate tests.
