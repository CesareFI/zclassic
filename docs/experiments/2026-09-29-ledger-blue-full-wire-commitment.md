<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue shielded review full-wire commitment

## Purpose

ZIP-243 does not include every transaction byte in its signing digest. A
read-only review that returns only that digest cannot show whether the Blue
processed the same proof and binding-signature bytes as the host. This
experiment adds a separate SHA-256 commitment over the complete uploaded
wire, including those bytes, without granting signing or key access.

## Protocol and screen

Shielded Review 0.5.10 identifies as read-only protocol v8. Its 108-byte
finish body contains 44 public-fact bytes, 32 ZIP-243 digest bytes, and 32
full-wire SHA-256 bytes. The Blue derives the commitment on the first pass
and rejects each later pass whose complete-wire hash differs. The host
snapshots the caller's wire, independently parses the facts, computes both
digests, checks the exact finish body, and verifies the caller did not mutate
the original wire during upload. Any mismatch fails closed and sends a
best-effort erase command.

The summary page continues to state `SHIELDED HIDDEN; NO SIGNING`; the
second page displays the requested branch and full ZIP-243 digest. The new
third page displays `FULL WIRE SHA-256` and all 64 hex characters. The CLI
prints the same commitment after a verified result. A known branch and a
full-wire match do not establish current chain state, shielded recipients,
amounts, fee, proof validity, ownership, or payment authorization.

## Tests and limits

The synthetic one-spend/one-output fixture passes host client, APDU, app,
device-loop, and screen simulator tests. Mutating a spend-proof byte leaves
the ZIP-243 digest unchanged while changing the full-wire commitment. A
forged device commitment is rejected and clears host outputs. The device
loop drives the actual app APDU and touch code under a BOLOS host shim; it
compares every displayed hex character on the ZIP-243 and full-wire pages
against the independently computed digests and checks USB reset, cancel,
malformed upload, recovery, and
EXIT. The PNG simulator checks 165 valid 320x480 pages across three wires,
two themes, and standard and large text. These are host and shim results,
not physical-device observations.

The controller test also changes the final binding-signature byte in each
of passes two through six. The independent ZIP-243 computation gives the
same signing digest for the changed wire, while every substituted pass is
rejected with `6a80`, a zero-length reply, and erased review state. The
focused APDU test passed in Release and sanitized Debug.

After running the suites without competing lint jobs, Release passed 62/62
and sanitized Debug passed 62/62. The fast lint set passed 33/33; the
consensus-core seal matched 554 files and 80 sections, and the inline-path,
document-claim, and Markdown-link checks passed. The CLI simulation of the
simnet Sapling-spend fixture printed ZIP-243 digest
`d4967a8269007709fd063a592f7359b864fa390c76f4609dc9f9b96069c27c8b`
and full-wire SHA-256
`683cec314305410a0d90146856ea503dffc1c74a8e01d6fa89eff79403cd2216`.

The pinned Blue SDK is revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with C23 patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Clang 22.1.6 and ARM GCC 16.2.0 built the C23 image on an AMD Ryzen 7 PRO
8840U on 2026-09-29T09:02:34Z. A clean build from a separate source and
SDK copy reproduced Intel HEX SHA-256
`b3a61ad5d2f74f1fe53c0b5ce6feb37dc75a7fd89b41424ba89fe25f26af2b94`
and `.text` SHA-256
`08284dd4fdd7f22fe3483c760ac80dee9e3c690ac3e1f1b43b2f0008866456d3`.
The image has 34,056 bytes of `.text`, zero `.data`, 4,360 bytes of `.bss`,
and a modeled maximum stack path of 888/1,536 bytes. The installer
recognizes these `.text` bytes with no signing path and blocks installation
until physical validation. A Blue USB interface was unavailable in this
workspace, so the app has not been installed or exercised on hardware.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j4
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j4
ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-sdk-repro-20260927 \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```
